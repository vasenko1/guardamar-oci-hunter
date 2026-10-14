"""Offline transition tests: at most one simulated OCI write per state."""
import ast
import inspect
import unittest

from automation.launch_contract import Preview
from automation import launch_state as fsm


def ready(memory=6.0):
    return fsm.begin(Preview("PREVIEW_ONLY", memory))


def waiting(memory=6.0):
    return fsm.consume_once(ready(memory))


class OneWriteReducerTests(unittest.TestCase):
    def test_never_claim_host_capacity_from_quota_alone(self):
        preflight = ready()
        self.assertEqual(preflight.phase, "PREPARED")
        self.assertEqual(preflight.outcome, "NO_WRITE")
        self.assertFalse(preflight.write_budget_consumed)

    def test_no_second_physical_write_in_same_run_state(self):
        before = ready()
        after = fsm.consume_once(before)
        self.assertTrue(after.write_budget_consumed)
        self.assertEqual(after.phase, "WAIT_RESPONSE")
        self.assertEqual(fsm.consume_once(before).phase, "WAIT_RESPONSE")
        # The immutable state returned by the reducer must replace the old
        # state. Reusing a stale before-state is a future integration risk,
        # not an authorization: a persistent writer gate is still required.
        with self.assertRaises(fsm.InvalidTransition):
            fsm.consume_once(after)
        with self.assertRaises(fsm.InvalidTransition):
            fsm.consume_once(fsm.submitted(after, "CAPACITY_MISS"))

    def test_response_never_triggers_another_write(self):
        for event, outcome, phase, disable in (
            ("CAPACITY_MISS", "CAPACITY_MISS", "STOPPED", False),
            ("RATE_LIMITED", "RATE_LIMITED", "STOPPED", True),
            ("FATAL", "BLOCKED", "STOPPED", True),
            ("AMBIGUOUS", "AMBIGUOUS", "DISCOVER_ONLY", True),
            ("ACCEPTED", "PENDING", "OBSERVE_ONLY", False),
        ):
            with self.subTest(event=event):
                after = fsm.submitted(waiting(), event)
                self.assertEqual(after.outcome, outcome)
                self.assertEqual(after.phase, phase)
                self.assertEqual(after.disable_schedule, disable)
                self.assertTrue(after.write_budget_consumed)
                with self.assertRaises(fsm.InvalidTransition):
                    fsm.consume_once(after)

    def test_429_preflight_and_inflight_are_hard_stops(self):
        preflight = fsm.begin(Preview("RATE_LIMITED", None))
        self.assertTrue(preflight.disable_schedule)
        self.assertEqual(preflight.phase, "STOPPED")
        with self.assertRaises(fsm.InvalidTransition):
            fsm.consume_once(preflight)
        for initial in (ready(), waiting(), fsm.submitted(waiting(), "AMBIGUOUS")):
            with self.subTest(phase=initial.phase):
                after = fsm.throttle(initial)
                self.assertTrue(after.disable_schedule)
                self.assertEqual(after.phase, "STOPPED")
                self.assertEqual(after.outcome, "RATE_LIMITED")

    def test_fail_closed_before_write_on_all_known_blockers(self):
        for outcome in (
            "TARGET_EXISTS", "RESOURCE_BLOCKED", "FREE_TIER_BLOCKED",
            "LIMIT_BLOCKED", "AUDIT_UNAVAILABLE",
        ):
            with self.subTest(outcome=outcome):
                state = fsm.begin(Preview(outcome, None))
                self.assertTrue(state.disable_schedule)
                with self.assertRaises(fsm.InvalidTransition):
                    fsm.consume_once(state)

    def test_unapproved_profile_or_unknown_status_rejected(self):
        for preview in (
            Preview("PREVIEW_ONLY", 1.0),
            Preview("PREVIEW_ONLY", 4.0),
            Preview("PREVIEW_ONLY", True),
            Preview("RESOURCE_GATES_CLEAR", 6.0),
        ):
            with self.subTest(preview=preview), self.assertRaises(fsm.InvalidTransition):
                fsm.begin(preview)

    def test_ambiguous_response_without_discovery_is_not_retried(self):
        state = fsm.submitted(waiting(), "AMBIGUOUS")
        for n, expected in ((0, "AMBIGUOUS"), (1, "PENDING"), (2, "BLOCKED")):
            with self.subTest(count=n):
                after = fsm.discovered(state, n)
                self.assertTrue(after.disable_schedule)
                self.assertEqual(after.outcome, expected)
                self.assertTrue(after.write_budget_consumed)
                with self.assertRaises(fsm.InvalidTransition):
                    fsm.consume_once(after)

    def test_duplicate_or_corrupt_discovery_never_proceeds(self):
        state = fsm.submitted(waiting(), "AMBIGUOUS")
        for n in (-1, True, 1.5, "1"):
            with self.subTest(count=n), self.assertRaises(fsm.InvalidTransition):
                fsm.discovered(state, n)

    def test_success_only_after_readiness_and_public_ipv4(self):
        state = fsm.submitted(waiting(memory=2.0), "ACCEPTED")
        observed = fsm.observed(
            state, target_found=True, matches_approved_manifest=True,
            lifecycle_state="PROVISIONING", has_public_ipv4=False,
        )
        self.assertEqual(observed.outcome, "PENDING")
        observed = fsm.observed(
            observed, target_found=True, matches_approved_manifest=True,
            lifecycle_state="RUNNING", has_public_ipv4=True,
        )
        self.assertEqual(observed.outcome, "READY")
        self.assertTrue(observed.disable_schedule)
        self.assertEqual(observed.memory_in_gbs, 2.0)
        with self.assertRaises(fsm.InvalidTransition):
            fsm.consume_once(observed)

    def test_absent_vm_and_missing_public_ip_remain_pending(self):
        initial = fsm.submitted(waiting(), "ACCEPTED")
        absent = fsm.observed(
            initial, target_found=False, matches_approved_manifest=False,
            lifecycle_state="PROVISIONING", has_public_ipv4=False,
        )
        self.assertEqual(absent.outcome, "PENDING")
        pending = fsm.observed(
            initial, target_found=True, matches_approved_manifest=True,
            lifecycle_state="RUNNING", has_public_ipv4=False,
        )
        self.assertEqual(pending.outcome, "PENDING")

    def test_wrong_manifest_and_terminated_vm_are_hard_blockers(self):
        initial = fsm.submitted(waiting(), "ACCEPTED")
        for match, status in ((False, "RUNNING"), (True, "STOPPED"),
                              (True, "TERMINATED"), (True, "UNKNOWN")):
            with self.subTest(match=match, status=status):
                result = fsm.observed(
                    initial, target_found=True,
                    matches_approved_manifest=match,
                    lifecycle_state=status, has_public_ipv4=True,
                )
                self.assertEqual(result.outcome, "BLOCKED")
                self.assertTrue(result.disable_schedule)

    def test_invalid_transition_must_fail_not_retry(self):
        for event in ("PENDING", "SUCCESS", "UNKNOWN", "", "429"):
            with self.subTest(response=event), self.assertRaises(fsm.InvalidTransition):
                fsm.submitted(waiting(), event)
        with self.assertRaises(fsm.InvalidTransition):
            fsm.submitted(ready(), "ACCEPTED")
        with self.assertRaises(fsm.InvalidTransition):
            fsm.discovered(ready(), 0)
        with self.assertRaises(fsm.InvalidTransition):
            fsm.throttle(fsm.submitted(waiting(), "RATE_LIMITED"))

    def test_no_cloud_sdk_client_or_mutating_method_in_reducer(self):
        tree = ast.parse(inspect.getsource(fsm))
        imported = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertNotIn("oci", imported)
        self.assertFalse(any(
            node.attr in {"launch_instance", "create_compute_capacity_report",
                          "terminate_instance"}
            for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        ))


if __name__ == "__main__":
    unittest.main()
