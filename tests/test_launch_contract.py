"""Offline-only tests for the future launch *preview*, not an OCI launcher."""
import unittest

from automation.guardamar_capacity import AuditError, Snapshot, check_snapshot
from automation.launch_contract import (
    FALLBACK_MEMORY_GB, PRIMARY_MEMORY_GB, Preview, preview_candidate,
)


def snapshot(**changes):
    fields = dict(
        target_count=0, image_ok=True, subnet_ok=True, shape_ok=True,
        ocpu_used=0.0, ram_used=0.0, free_storage_used=0.0,
        ocpu_available=4.0, ram_available=24.0, storage_available=200.0,
    )
    fields.update(changes)
    return Snapshot(**fields)


def choose(rows=None, status="RECEIVED", first=None, final=None):
    return preview_candidate(
        first or snapshot(), final or snapshot(), status,
        rows if rows is not None else {
            6.0: ("AVAILABLE", 1), 2.0: ("AVAILABLE", 1),
            1.0: ("AVAILABLE", 1),
        },
    )


class OfflineLaunchContractTests(unittest.TestCase):
    def test_unchanged_primary_profile_and_no_capacity_assertion(self):
        self.assertEqual(choose(), Preview("PREVIEW_ONLY", 6.0))

    def test_report_based_two_gb_fallback_only(self):
        rows = {6.0: ("OUT_OF_HOST_CAPACITY", 0),
                2.0: ("AVAILABLE", 1), 1.0: ("AVAILABLE", 100)}
        self.assertEqual(choose(rows), Preview("PREVIEW_ONLY", 2.0))
        self.assertEqual(choose({6.0: ("OUT_OF_HOST_CAPACITY", None),
                                 2.0: ("AVAILABLE", None)}),
                         Preview("PREVIEW_ONLY", 2.0))

    def test_never_launch_1gb_even_if_only_available_shape(self):
        rows = {6.0: ("OUT_OF_HOST_CAPACITY", 0),
                2.0: ("OUT_OF_HOST_CAPACITY", 0),
                1.0: ("AVAILABLE", 100)}
        self.assertEqual(choose(rows), Preview("PREVIEW_ONLY", 6.0))
        self.assertNotIn(1.0, (PRIMARY_MEMORY_GB, FALLBACK_MEMORY_GB))

    def test_no_fallback_for_unknown_or_missing_capacity_report(self):
        self.assertEqual(choose({}, status="UNAVAILABLE"), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(choose({6.0: ("OUT_OF_HOST_CAPACITY", 0)}),
                         Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(choose({6.0: ("AVAILABLE", 0),
                                 2.0: ("AVAILABLE", 2)}),
                         Preview("PREVIEW_ONLY", 6.0))

    def test_fallback_count_zero_never_selects_two_gb(self):
        rows = {6.0: ("OUT_OF_HOST_CAPACITY", 0), 2.0: ("AVAILABLE", 0)}
        self.assertEqual(choose(rows), Preview("PREVIEW_ONLY", 6.0))

    def test_429_hard_stop_before_any_profile_selection(self):
        self.assertEqual(choose(status="RATE_LIMITED"), Preview("RATE_LIMITED"))

    def test_429_outcome_takes_precedence(self):
        self.assertEqual(choose(status="RATE_LIMITED",
                                first=snapshot(target_count=1)), Preview("RATE_LIMITED"))

    def test_both_safety_snapshots_must_be_clear(self):
        self.assertEqual(choose(first=snapshot(target_count=1)), Preview("TARGET_EXISTS"))
        self.assertEqual(choose(final=snapshot(target_count=2)), Preview("TARGET_EXISTS"))
        self.assertEqual(choose(final=snapshot(subnet_ok=False)), Preview("RESOURCE_BLOCKED"))
        self.assertEqual(choose(final=snapshot(ocpu_available=0)), Preview("LIMIT_BLOCKED"))

    def test_2gb_fallback_cannot_bypass_primary_6gb_budget_gate(self):
        rows = {6.0: ("OUT_OF_HOST_CAPACITY", 0), 2.0: ("AVAILABLE", 1)}
        # 8+6 exceeds conservative 12 GB cap, even if 8+2 would fit.
        self.assertEqual(choose(rows, first=snapshot(ram_used=8)),
                         Preview("FREE_TIER_BLOCKED"))

    def test_budget_selected_profile_is_checked_too(self):
        self.assertEqual(check_snapshot(snapshot(), memory_gb=2), "RESOURCE_GATES_CLEAR")
        with self.assertRaises(AuditError):
            check_snapshot(snapshot(), memory_gb=1)
        with self.assertRaises(AuditError):
            check_snapshot(snapshot(), memory_gb=float("nan"))

    def test_bad_availability_is_fail_closed(self):
        for bad in (float("nan"), float("inf"), -0.1):
            with self.subTest(bad=str(bad)):
                self.assertEqual(choose(first=snapshot(ocpu_used=bad)),
                                 Preview("RESOURCE_BLOCKED"))

    def test_malformed_host_rows_are_fail_closed(self):
        cases = (
            {6.0: ("AVAILABLE", -1)},
            {6.0: ("AVAILABLE", True)},
            {6.0: ("AVAILABLE", 1.2)},
            {6.0: ("UNEXPECTED", 2)},
            {4.0: ("AVAILABLE", 1)},
            {1.0: ("AVAILABLE", "1")},
            {6.0: ["AVAILABLE", 1]},
        )
        for rows in cases:
            with self.subTest(rows=str(rows)):
                self.assertEqual(choose(rows), Preview("RESOURCE_BLOCKED"))
        self.assertEqual(choose(status="NONSENSE"), Preview("RESOURCE_BLOCKED"))

    def test_pure_candidate_module_has_no_oci_sdk_mutations(self):
        import ast
        import inspect
        from automation import launch_contract
        tree = ast.parse(inspect.getsource(launch_contract))
        attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse(attributes & {
            "launch_instance", "create_compute_capacity_report", "terminate_instance",
            "create_vnic", "delete_vnic", "update_instance",
        })


if __name__ == "__main__":
    unittest.main()
