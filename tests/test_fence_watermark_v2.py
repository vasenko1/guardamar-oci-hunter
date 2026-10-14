"""Offline adversarial tests: v2 strictly monotone spent-run watermark only."""
from __future__ import annotations

import ast
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from automation import durable_fence as v1
from automation import fence_watermark_v2 as v2
from automation.launch_contract import Preview


def env(run="111"):
    return {
        "GITHUB_REPOSITORY": "vasenko1/guardamar-oci-hunter",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ID": run,
    }


class SharedStore:
    """Exact-CAS fake under one lock; no GitHub network or OCI calls."""
    def __init__(self, data=None):
        self.lock = threading.Lock()
        self.rev = 1
        self.data = data if data is not None else v2.plan_v1_open_upgrade(
            v1.initial_record_bytes()
        )
        self.calls = 0
        self.timeout_after_write = False
        self.reject = False
        self.unavailable = False

    def read(self):
        if self.unavailable:
            raise OSError("never print details")
        with self.lock:
            return str(self.rev), self.data

    def cas(self, expected, new):
        with self.lock:
            self.calls += 1
            if self.reject:
                return False
            if str(self.rev) != expected:
                return False
            self.data = new
            self.rev += 1
            if self.timeout_after_write:
                raise TimeoutError("lost acknowledgement")
            return True

    def state(self):
        return v2.decode(self.data)


class WatermarkTests(unittest.TestCase):
    def test_genesis_is_a_pure_upgrade_preview_not_a_write(self):
        raw = v1.initial_record_bytes()
        self.assertEqual(json.loads(raw)["version"], 1)
        v2_bytes = v2.plan_v1_open_upgrade(raw)
        self.assertEqual(json.loads(v2_bytes), {
            "version": 2, "phase": "OPEN", "reason": "INITIAL",
            "highest_spent_run_id": None, "claims_committed": 0,
            "active_run_id": None, "active_memory_gb": None,
        })
        self.assertEqual(raw, v1.initial_record_bytes())
        self.assertLess(len(v2_bytes), v2.MAX_WIRE_BYTES)
        self.assertEqual(v2.decode(v2_bytes), v2.WatermarkRecord(
            "OPEN", "INITIAL", None, 0))

    def test_v1_history_conversion_uses_numeric_not_lexical_max(self):
        for n in (2, 100, 9999):
            old = v1.FenceRecord(
                "OPEN", "CAPACITY_MISS", tuple(str(x) for x in range(n, 0, -1))
            )
            migrated = v2.decode(v2.plan_v1_open_upgrade(v1.encode(old)))
            self.assertEqual(migrated.highest_spent_run_id, str(n))
            self.assertEqual(migrated.claims_committed, n)
            self.assertLess(len(v2.encode(migrated)), 220)
            cell = SharedStore(v2.encode(migrated))
            with self.assertRaisesRegex(v2.FenceBlocked, "run_id_not_above"):
                v2.claim(cell, env(str(n)), Preview("PREVIEW_ONLY", 6.0))
            v2.claim(cell, env(str(n + 1)), Preview("PREVIEW_ONLY", 6.0))
            self.assertEqual(cell.state().highest_spent_run_id, str(n + 1))

    def test_claim_requires_durable_ack_and_is_blocked_while_claimed(self):
        cell = SharedStore()
        ticket = v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.state().phase, "CLAIMED")
        self.assertEqual(cell.state().highest_spent_run_id, "111")
        self.assertEqual(cell.state().claims_committed, 1)
        self.assertEqual(ticket.run_id, "111")
        self.assertEqual(cell.calls, 1)
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(cell, env("999"), Preview("PREVIEW_ONLY", 2.0))
        self.assertEqual(cell.calls, 1)

    def test_rearmed_larger_id_succeeds_smaller_and_same_fails(self):
        cell = SharedStore()
        first = v2.claim(cell, env("123"), Preview("PREVIEW_ONLY", 6.0))
        v2.settle(cell, first, "CAPACITY_MISS")
        for late in ("100", "122", "123"):
            with self.subTest(late=late), self.assertRaisesRegex(
                v2.FenceBlocked, "run_id_not_above_watermark"
            ):
                v2.claim(cell, env(late), Preview("PREVIEW_ONLY", 6.0))
        newer = v2.claim(cell, env("200"), Preview("PREVIEW_ONLY", 2.0))
        self.assertEqual(cell.state().highest_spent_run_id, "200")
        self.assertEqual(cell.state().claims_committed, 2)
        v2.settle(cell, newer, "CAPACITY_MISS")
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(cell, env("123"), Preview("PREVIEW_ONLY", 2.0))

    def test_over_ten_thousand_sequential_attempts_are_constant_size(self):
        cell = SharedStore()
        for n in range(1, 12002):
            ticket = v2.claim(cell, env(str(n)), Preview("PREVIEW_ONLY", 6.0))
            v2.settle(cell, ticket, "CAPACITY_MISS")
        obj = cell.state()
        self.assertEqual(obj.claims_committed, 12001)
        self.assertEqual(obj.highest_spent_run_id, "12001")
        self.assertLess(len(cell.data), 220)
        self.assertEqual(obj.phase, "OPEN")
        with self.assertRaisesRegex(v2.FenceBlocked, "run_id_not_above"):
            v2.claim(cell, env("1"), Preview("PREVIEW_ONLY", 6.0))

    def test_parallel_claims_only_one_accepted_no_retry(self):
        cell = SharedStore()
        def contestant(i):
            try:
                return v2.claim(cell, env(str(i + 1000)), Preview("PREVIEW_ONLY", 6.0))
            except v2.FenceBlocked:
                return None
        with ThreadPoolExecutor(max_workers=20) as pool:
            successes = [x for x in pool.map(contestant, range(100)) if x]
        self.assertEqual(len(successes), 1)
        self.assertEqual(cell.calls, 1)
        self.assertEqual(cell.state().active_run_id, successes[0].run_id)

    def test_halt_is_sticky_and_settlement_not_reopened(self):
        for reason in ("AMBIGUOUS", "ACCEPTED", "BLOCKED", "RATE_LIMITED"):
            cell = SharedStore()
            ticket = v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
            v2.settle(cell, ticket, reason)
            self.assertEqual(cell.state().phase, "HALTED")
            self.assertEqual(cell.state().reason, reason)
            with self.assertRaises(v2.FenceBlocked):
                v2.claim(cell, env("222"), Preview("PREVIEW_ONLY", 6.0))

    def test_429_before_and_during_claim_and_idempotent_stop(self):
        cell = SharedStore()
        v2.stop_on_preflight_429(cell)
        self.assertEqual(cell.state().phase, "HALTED")
        self.assertEqual(cell.state().reason, "RATE_LIMITED")
        self.assertIsNone(cell.state().highest_spent_run_id)
        n = cell.calls
        v2.stop_on_preflight_429(cell)
        self.assertEqual(cell.calls, n)
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        cell = SharedStore()
        ticket = v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        v2.stop_on_preflight_429(cell)
        with self.assertRaises(v2.FenceBlocked):
            v2.settle(cell, ticket, "CAPACITY_MISS")
        self.assertEqual(cell.state().highest_spent_run_id, "111")

    def test_false_ack_and_lost_ack_never_grant_and_no_auto_retry(self):
        cell = SharedStore()
        cell.reject = True
        with self.assertRaisesRegex(v2.FenceBlocked, "commit_unconfirmed"):
            v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.state().phase, "OPEN")
        self.assertEqual(cell.calls, 1)
        cell = SharedStore()
        cell.timeout_after_write = True
        with self.assertRaisesRegex(v2.FenceBlocked, "commit_unconfirmed"):
            v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.calls, 1)
        self.assertEqual(cell.state().phase, "CLAIMED")
        cell.timeout_after_write = False
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(cell, env("112"), Preview("PREVIEW_ONLY", 6.0))

    def test_settlement_mismatch_repeat_and_unconfirmed_are_blocked(self):
        cell = SharedStore()
        ticket = v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 2.0))
        wrong = v2.ClaimTicket("111", 6.0, ticket.revision)
        with self.assertRaises(v2.FenceBlocked):
            v2.settle(cell, wrong, "CAPACITY_MISS")
        cell.reject = True
        with self.assertRaisesRegex(v2.FenceBlocked, "commit_unconfirmed"):
            v2.settle(cell, ticket, "CAPACITY_MISS")
        self.assertEqual(cell.state().phase, "CLAIMED")
        cell.reject = False
        v2.settle(cell, ticket, "CAPACITY_MISS")
        with self.assertRaises(v2.FenceBlocked):
            v2.settle(cell, ticket, "CAPACITY_MISS")

    def test_v1_state_is_rejected_by_v2_claim_not_auto_migrated(self):
        cell = SharedStore(v1.initial_record_bytes())
        with self.assertRaisesRegex(v2.FenceBlocked, "invalid_watermark_document"):
            v2.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.calls, 0)
        self.assertEqual(cell.data, v1.initial_record_bytes())
        with self.assertRaisesRegex(v2.FenceBlocked, "invalid_watermark_document"):
            v2.stop_on_preflight_429(cell)

    def test_migration_requires_canonical_open_never_rearms_halt_or_claim(self):
        for phase,reason,spent,run,mem in [
            ("CLAIMED", "INITIAL", ("111",), "111", 6.0),
            ("HALTED", "RATE_LIMITED", (), None, None),
            ("HALTED", "AMBIGUOUS", ("111",), "111", 6.0),
            ("OPEN", "INITIAL", ("111",), None, None),
            ("OPEN", "CAPACITY_MISS", (), None, None),
        ]:
            record = v1.FenceRecord(phase, reason, spent, run, mem)
            with self.subTest(phase=phase,reason=reason):
                with self.assertRaises(v2.FenceBlocked):
                    v2.plan_v1_open_upgrade(v1.encode(record))
        with self.assertRaises(v2.FenceBlocked):
            v2.plan_v1_open_upgrade(v1.initial_record_bytes() + b"\n")

    def test_schema_duplicate_missing_extra_noncanonical_and_bool_fail(self):
        good = json.loads(v2.plan_v1_open_upgrade(v1.initial_record_bytes()))
        bad = [
            b'{}',
            b'{"version":2,"version":2}',
            b'not json',
            v1.initial_record_bytes(),
            json.dumps({**good, "version": True}).encode(),
            json.dumps({**good, "claims_committed": True}).encode(),
            json.dumps({**good, "claims_committed": -1}).encode(),
            json.dumps({**good, "claims_committed": 1}).encode(),
            json.dumps({**good, "highest_spent_run_id": "01", "claims_committed": 1}).encode(),
            json.dumps({**good, "highest_spent_run_id": "99", "claims_committed": 0}).encode(),
            json.dumps({**good, "unknown": "malicious"}).encode(),
            b" " + v2.encode(v2.WatermarkRecord("OPEN", "INITIAL", None, 0)),
            b"x" * (v2.MAX_WIRE_BYTES + 1),
        ]
        for blob in bad:
            with self.subTest(example=blob[:40]):
                with self.assertRaises(v2.FenceBlocked):
                    v2.decode(blob)

    def test_claim_count_never_exceeds_positive_highest_id(self):
        # Two distinct increasing positive integers cannot have maximum 1.
        impossible = v2.WatermarkRecord(
            "OPEN", "CAPACITY_MISS", "1", 2,
        )
        with self.assertRaisesRegex(
            v2.FenceBlocked, "watermark_count_exceeds_highest_id"
        ):
            v2.encode(impossible)
        canonical = json.loads(v2.plan_v1_open_upgrade(v1.initial_record_bytes()))
        canonical.update({
            "reason": "CAPACITY_MISS", "highest_spent_run_id": "1",
            "claims_committed": 2,
        })
        with self.assertRaises(v2.FenceBlocked):
            v2.decode(json.dumps(
                canonical, sort_keys=True, separators=(",", ":")
            ).encode("ascii"))
        # Count equals maximum is possible only for claims 1,2,...,N.
        possible = v2.WatermarkRecord(
            "OPEN", "CAPACITY_MISS", "2", 2,
        )
        self.assertEqual(v2.decode(v2.encode(possible)), possible)

    def test_claim_counter_exhaustion_is_a_safe_halt(self):
        # A reachable bound needs max ID >= number of distinct claims.
        # Use a strictly higher admissible ID to reach the counter gate.
        high = str(v2.MAX_CLAIM_COUNT)
        obj = v2.WatermarkRecord("OPEN", "CAPACITY_MISS", high,
                                 v2.MAX_CLAIM_COUNT)
        cell = SharedStore(v2.encode(obj))
        with self.assertRaisesRegex(v2.FenceBlocked, "counter_exhausted"):
            v2.claim(cell, env(str(v2.MAX_CLAIM_COUNT + 1)),
                     Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.calls, 0)

    def test_bad_untrusted_context_and_preview_have_no_cas(self):
        for key, value in [
            ("GITHUB_REF", "refs/heads/oci-fence-state"),
            ("GITHUB_REPOSITORY", "wrong/repo"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_REF_PROTECTED", "false"),
            ("GITHUB_EVENT_NAME", "schedule"),
            ("GITHUB_RUN_ID", "001"),
        ]:
            cell = SharedStore()
            data = env()
            data[key] = value
            with self.subTest(key=key):
                with self.assertRaises(v2.FenceBlocked):
                    v2.claim(cell, data, Preview("PREVIEW_ONLY", 6.0))
                self.assertEqual(cell.calls, 0)
        for p in (
            Preview("PREVIEW_ONLY", True),
            Preview("PREVIEW_ONLY", 1.0),
            Preview("RATE_LIMITED", None),
            Preview("RESOURCE_GATES_CLEAR", 6.0),
        ):
            cell = SharedStore()
            with self.assertRaises(v2.FenceBlocked):
                v2.claim(cell, env(), p)
            self.assertEqual(cell.calls, 0)

    def test_v2_module_is_pure_and_no_oci_or_github_io(self):
        from pathlib import Path
        mod = ast.parse((Path(__file__).resolve().parents[1]
                         / "automation/fence_watermark_v2.py").read_text())
        imports = [n.module.split(".")[0] for n in ast.walk(mod)
                   if isinstance(n, ast.ImportFrom) and n.module]
        imports += [alias.name.split(".")[0] for n in ast.walk(mod)
                    if isinstance(n, ast.Import) for alias in n.names]
        self.assertFalse(set(imports) & {
            "oci", "requests", "urllib", "socket", "subprocess", "httpx"
        })
        attrs = {node.attr for node in ast.walk(mod)
                 if isinstance(node, ast.Attribute)}
        self.assertFalse(attrs & {
            "launch_instance", "create_compute_capacity_report", "request",
            "open", "put", "delete", "post",
        })


if __name__ == "__main__":
    unittest.main()
