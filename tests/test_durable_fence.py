"""Completely offline, shared-backing fake CAS tests. NO GitHub/OCI credentials."""
from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from automation import durable_fence as fence
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


class SharedCAS:
    """Single durable-in-test record, with compare-and-swap serialization."""

    def __init__(self):
        self.lock = threading.Lock()
        self.revision = 1
        self.data = fence.initial_record_bytes()
        self.fail_read = False
        self.fail_before_commit = False
        self.timeout_after_commit = False
        self.cas_calls = 0

    def read(self):
        if self.fail_read:
            raise OSError("secret storage error")
        with self.lock:
            return str(self.revision), self.data

    def cas(self, expected_revision, new_record):
        with self.lock:
            self.cas_calls += 1
            if self.fail_before_commit:
                raise TimeoutError("backend failed before writing")
            if str(self.revision) != expected_revision:
                return False
            self.data = new_record
            self.revision += 1
            if self.timeout_after_commit:
                raise TimeoutError("backend committed but response lost")
            return True

    def record(self):
        return fence.decode(self.data)


class FenceOfflineTests(unittest.TestCase):
    def test_wire_format_round_trip_and_minimal_public_fields(self):
        raw = fence.initial_record_bytes()
        data = json.loads(raw)
        self.assertEqual(set(data), {
            "version", "phase", "reason", "spent_run_ids",
            "active_run_id", "active_memory_gb",
        })
        self.assertNotIn("ssh-", raw.decode())
        self.assertNotIn("ocid1.", raw.decode())
        self.assertNotIn("pem", raw.decode())
        self.assertEqual(fence.decode(raw), fence.FenceRecord("OPEN", "INITIAL", ()))

    def test_one_claim_is_committed_before_any_hypothetical_write(self):
        cell = SharedCAS()
        ticket = fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        self.assertIsInstance(ticket, fence.ClaimTicket)
        self.assertEqual(cell.record().phase, "CLAIMED")
        self.assertEqual(cell.record().active_run_id, "111")
        self.assertEqual(cell.record().spent_run_ids, ("111",))
        self.assertEqual(cell.cas_calls, 1)
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env("222"), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.cas_calls, 1)

    def test_concurrent_claims_have_exactly_one_winner(self):
        cell = SharedCAS()
        def attempt(i):
            try:
                ticket = fence.claim(
                    cell, env(str(i + 1000)), Preview("PREVIEW_ONLY", 2.0)
                )
                return (ticket.run_id, True)
            except fence.FenceBlocked:
                return (str(i + 1000), False)
        with ThreadPoolExecutor(max_workers=20) as pool:
            result = list(pool.map(attempt, range(100)))
        self.assertEqual(sum(1 for _, ok in result if ok), 1)
        self.assertEqual(cell.record().phase, "CLAIMED")
        self.assertEqual(len(cell.record().spent_run_ids), 1)

    def test_crash_after_claim_before_cloud_call_blocks_next_run(self):
        cell = SharedCAS()
        fence.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        # Simulated destroyed process: a newly constructed reader gets only
        # the durable record, no in-memory RunState or ClaimTicket.
        recovered = SharedCAS()
        recovered.data = cell.data
        recovered.revision = cell.revision
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(recovered, env("222"), Preview("PREVIEW_ONLY", 6.0))

    def test_backend_committed_but_acknowledgment_lost_must_not_grant(self):
        cell = SharedCAS()
        cell.timeout_after_commit = True
        with self.assertRaisesRegex(fence.FenceBlocked, "fence_commit_unconfirmed"):
            fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.record().phase, "CLAIMED")
        cell.timeout_after_commit = False
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env("222"), Preview("PREVIEW_ONLY", 2.0))

    def test_failed_reservation_and_read_never_grant(self):
        cell = SharedCAS()
        cell.fail_before_commit = True
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(cell.record().phase, "OPEN")
        self.assertEqual(cell.record().spent_run_ids, ())
        cell.fail_read = True
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))

    def test_confirmed_capacity_miss_allows_only_distinct_new_run(self):
        cell = SharedCAS()
        old = fence.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        fence.settle(cell, old, "CAPACITY_MISS")
        self.assertEqual(cell.record().phase, "OPEN")
        self.assertEqual(cell.record().reason, "CAPACITY_MISS")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env("111"), Preview("PREVIEW_ONLY", 6.0))
        new = fence.claim(cell, env("222"), Preview("PREVIEW_ONLY", 2.0))
        self.assertNotEqual(new.run_id, old.run_id)
        self.assertEqual(cell.record().spent_run_ids, ("111", "222"))

    def test_outcome_missing_or_ambiguous_does_not_reopen_fence(self):
        for result in ("RATE_LIMITED", "AMBIGUOUS", "BLOCKED", "ACCEPTED"):
            with self.subTest(result=result):
                cell = SharedCAS()
                old = fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
                fence.settle(cell, old, result)
                self.assertEqual(cell.record().phase, "HALTED")
                self.assertEqual(cell.record().reason, result)
                with self.assertRaises(fence.FenceBlocked):
                    fence.claim(cell, env("222"), Preview("PREVIEW_ONLY", 2.0))

    def test_429_before_claim_globally_halts_without_run(self):
        cell = SharedCAS()
        fence.stop_on_preflight_429(cell)
        self.assertEqual(cell.record().phase, "HALTED")
        self.assertEqual(cell.record().reason, "RATE_LIMITED")
        self.assertEqual(cell.record().spent_run_ids, ())
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        fence.stop_on_preflight_429(cell)
        self.assertEqual(cell.cas_calls, 1)

    def test_429_during_pending_claim_also_globally_halts(self):
        cell = SharedCAS()
        old = fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        fence.stop_on_preflight_429(cell)
        self.assertEqual(cell.record().phase, "HALTED")
        self.assertEqual(cell.record().reason, "RATE_LIMITED")
        with self.assertRaises(fence.FenceBlocked):
            fence.settle(cell, old, "CAPACITY_MISS")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env("222"), Preview("PREVIEW_ONLY", 6.0))

    def test_stale_cas_and_double_settlement_are_blocked(self):
        cell = SharedCAS()
        revision, state = cell.read()
        fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        self.assertIs(cell.cas(revision, state), False)
        old = fence.ClaimTicket("111", 6.0, revision)
        fence.settle(cell, old, "CAPACITY_MISS")
        with self.assertRaises(fence.FenceBlocked):
            fence.settle(cell, old, "CAPACITY_MISS")
        with self.assertRaises(fence.FenceBlocked):
            fence.settle(cell, fence.ClaimTicket("333", 6.0, revision), "BLOCKED")

    def test_no_automatic_rearm_if_settlement_write_is_unconfirmed(self):
        cell = SharedCAS()
        old = fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        cell.fail_before_commit = True
        with self.assertRaises(fence.FenceBlocked):
            fence.settle(cell, old, "CAPACITY_MISS")
        self.assertEqual(cell.record().phase, "CLAIMED")

    def test_false_or_ambiguous_cas_never_grants(self):
        cell = SharedCAS()
        original = cell.cas
        cell.cas = lambda rev, record: False
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        cell.cas = lambda rev, record: None
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))
        cell.cas = original

    def test_untrusted_github_runs_and_probes_fail_before_cas(self):
        for key, bad in (
            ("GITHUB_REPOSITORY", "owner/another"),
            ("GITHUB_REF", "refs/pull/6/merge"),
            ("GITHUB_REF_PROTECTED", "false"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_EVENT_NAME", "schedule"),
            ("GITHUB_RUN_ID", "0"),
        ):
            with self.subTest(key=key):
                cell = SharedCAS()
                fields = env()
                fields[key] = bad
                with self.assertRaises(fence.FenceBlocked):
                    fence.claim(cell, fields, Preview("PREVIEW_ONLY", 6.0))
                self.assertEqual(cell.cas_calls, 0)
        for preview in (
            Preview("RATE_LIMITED", None),
            Preview("RESOURCE_GATES_CLEAR", 6.0),
            Preview("PREVIEW_ONLY", 1.0),
            Preview("PREVIEW_ONLY", True),
        ):
            cell = SharedCAS()
            with self.assertRaises(fence.FenceBlocked):
                fence.claim(cell, env(), preview)
            self.assertEqual(cell.cas_calls, 0)

    def test_schema_corruption_unknown_fields_and_duplicates_fail_closed(self):
        cell = SharedCAS()
        examples = [
            b'not json',
            b'{}',
            b'{"version":2,"phase":"OPEN","reason":"INITIAL","spent_run_ids":[],"active_run_id":null,"active_memory_gb":null}',
            b'{"version":1,"phase":"OPEN","reason":"INITIAL","spent_run_ids":[],"active_run_id":null,"active_memory_gb":null,"extra":1}',
            b'{"version":1,"phase":"OPEN","reason":"INITIAL","spent_run_ids":["123","123"],"active_run_id":null,"active_memory_gb":null}',
            b'{"version":1,"phase":"CLAIMED","reason":"INITIAL","spent_run_ids":[],"active_run_id":"111","active_memory_gb":6.0}',
            b'{"version":1,"phase":"HALTED","reason":"INITIAL","spent_run_ids":[],"active_run_id":null,"active_memory_gb":null}',
        ]
        for raw in examples:
            with self.subTest(raw=raw[:30]):
                cell.data = raw
                with self.assertRaises(fence.FenceBlocked):
                    fence.claim(cell, env(), Preview("PREVIEW_ONLY", 6.0))

    def test_journal_full_fails_without_reinitializing(self):
        record = fence.FenceRecord(
            "OPEN", "CAPACITY_MISS",
            tuple(str(i + 1) for i in range(fence.MAX_JOURNAL_SIZE)),
        )
        cell = SharedCAS()
        cell.data = fence.encode(record)
        with self.assertRaisesRegex(fence.FenceBlocked, "fence_journal_full"):
            fence.claim(
                cell, env(str(fence.MAX_JOURNAL_SIZE + 1)),
                Preview("PREVIEW_ONLY", 6.0),
            )

    def test_only_safe_ledger_metadata_is_serialized(self):
        cell = SharedCAS()
        old = fence.claim(cell, env(), Preview("PREVIEW_ONLY", 2.0))
        raw = cell.data
        self.assertNotIn(b"ocid1.", raw)
        self.assertNotIn(b"PRIVATE KEY", raw)
        self.assertNotIn(b"ssh-", raw)
        self.assertNotIn(b"opc_retry_token", raw)
        self.assertNotIn(b"GITHUB_TOKEN", raw)
        self.assertEqual(old.memory_in_gbs, 2.0)


if __name__ == "__main__":
    unittest.main()
