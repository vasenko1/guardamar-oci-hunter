"""Offline regression for a standalone audit-only OCI release candidate."""

import contextlib
import io
import json
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch

from automation import guardamar_capacity as audit


def sample(**changes):
    initial = dict(
        target_count=0, image_ok=True, subnet_ok=True, shape_ok=True,
        ocpu_used=0.0, ram_used=0.0, free_storage_used=0.0,
        ocpu_available=4.0, ram_available=24.0, storage_available=200.0,
    )
    initial.update(changes)
    return audit.Snapshot(**initial)


def fake_env():
    return {key: "fixture-private-value" for key in audit.CONFIG_KEYS}


class CandidateTests(unittest.TestCase):
    def test_read_only_build_has_no_launch_cli(self):
        self.assertIs(audit.LAUNCH_BUILD_ENABLED, False)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                audit.main(["launch"])
        self.assertEqual(error.exception.code, 2)

    def test_clean_resource_gates_do_not_claim_host_capacity(self):
        self.assertEqual(audit.check_snapshot(sample()), "RESOURCE_GATES_CLEAR")

    def test_existing_target_always_blocks_clear(self):
        for n in (1, 2, 9):
            with self.subTest(n=n):
                self.assertEqual(audit.check_snapshot(sample(target_count=n)), "TARGET_EXISTS")

    def test_image_subnet_and_shape_fail_closed(self):
        for key in ("image_ok", "subnet_ok", "shape_ok"):
            with self.subTest(key=key):
                self.assertEqual(audit.check_snapshot(sample(**{key: False})), "RESOURCE_BLOCKED")

    def test_never_override_strict_always_free_usage_ceiling(self):
        scenarios = (
            dict(ocpu_used=2.0),
            dict(ram_used=10.0),
            dict(free_storage_used=151.0),
        )
        for item in scenarios:
            with self.subTest(item=item):
                self.assertEqual(audit.check_snapshot(sample(**item)), "FREE_TIER_BLOCKED")

    def test_oci_service_limit_shortage_stops(self):
        scenarios = (
            dict(ocpu_available=0.0),
            dict(ram_available=5.0),
            dict(storage_available=49.0),
        )
        for item in scenarios:
            with self.subTest(item=item):
                self.assertEqual(audit.check_snapshot(sample(**item)), "LIMIT_BLOCKED")

    def test_invalid_oci_results_are_not_treated_as_clear(self):
        for num in (float("nan"), float("inf"), -1.0):
            with self.subTest(value=num):
                with self.assertRaises(audit.AuditError):
                    audit.check_snapshot(sample(ocpu_used=num))
        with self.assertRaises(audit.AuditError):
            audit.check_snapshot(sample(target_count=-1))

    def test_missing_config_never_calls_oci(self):
        reader = Mock()
        output = audit.run_audit({"OCI_USER_OCID": "exists"}, reader)
        self.assertEqual(output, {"outcome": "AUDIT_UNAVAILABLE", "launch_enabled": False})
        reader.assert_not_called()

    def test_api_errors_cannot_leak_private_data_or_sdk_details(self):
        reader = Mock(side_effect=RuntimeError("PRIVATE-KEY and SECRET-IP"))
        output = io.StringIO()
        with patch.dict(os.environ, fake_env(), clear=True):
            with contextlib.redirect_stdout(output):
                exit_status = audit.main(["audit"])
        self.assertEqual(exit_status, 2)
        self.assertEqual(json.loads(output.getvalue()), {
            "outcome": "AUDIT_UNAVAILABLE", "launch_enabled": False
        })
        self.assertNotIn("SECRET", output.getvalue())
        # Explicit injected-reader path has exactly the same privacy boundary.
        self.assertEqual(audit.run_audit(fake_env(), reader)["outcome"], "AUDIT_UNAVAILABLE")

    def test_expected_snapshot_reports_only_enumerated_status(self):
        private_marker = "SECRET-IP"
        reader = Mock(return_value=sample())
        output = audit.run_audit(fake_env(), reader)
        self.assertEqual(output, {"outcome": "RESOURCE_GATES_CLEAR", "launch_enabled": False})
        self.assertNotIn(private_marker, json.dumps(output))
        reader.assert_called_once()

    def test_sources_have_no_oci_mutation_methods(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(audit))
        forbidden = {
            "launch_instance", "create_compute_capacity_report",
            "terminate_instance", "update_instance",
            "update_subnet", "create_vnic", "delete_vnic",
        }
        attributes = {
            node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
        }
        self.assertFalse(attributes.intersection(forbidden))

    def test_sdk_snapshot_only_reads_exact_resources_and_never_mutates(self):
        # Strict fake OCI SDK: all network operations remain in-memory.
        image = types.SimpleNamespace(
            id="image-test", lifecycle_state="AVAILABLE", operating_system="Oracle Linux"
        )
        subnet = types.SimpleNamespace(
            id="subnet-test", lifecycle_state="AVAILABLE",
            availability_domain=None, prohibit_public_ip_on_vnic=False,
        )
        compute = Mock()
        compute.list_instances.return_value = types.SimpleNamespace(data=[])
        compute.get_image.return_value = types.SimpleNamespace(data=image)
        compute.list_shapes.return_value = types.SimpleNamespace(
            data=[types.SimpleNamespace(shape=audit.SHAPE)]
        )
        network = Mock()
        network.get_subnet.return_value = types.SimpleNamespace(data=subnet)
        limits = Mock()
        responses = [
            types.SimpleNamespace(used=0, available=4),
            types.SimpleNamespace(used=0, available=24),
            types.SimpleNamespace(used=0, available=200),
        ]
        limits.get_resource_availability.side_effect = [
            types.SimpleNamespace(data=row) for row in responses
        ]
        fake_sdk = types.SimpleNamespace(
            signer=types.SimpleNamespace(Signer=Mock(return_value="signer")),
            retry=types.SimpleNamespace(NoneRetryStrategy=Mock(return_value="no-retry")),
            core=types.SimpleNamespace(
                ComputeClient=Mock(return_value=compute),
                VirtualNetworkClient=Mock(return_value=network),
            ),
            limits=types.SimpleNamespace(
                LimitsClient=Mock(return_value=limits),
            ),
            pagination=types.SimpleNamespace(
                list_call_get_all_results=lambda fn, *args, **kwargs: fn(*args, **kwargs),
            ),
        )
        env = fake_env()
        env.update({
            "OCI_IMAGE_OCID": "image-test",
            "OCI_SUBNET_OCID": "subnet-test",
        })
        with patch.dict(sys.modules, {"oci": fake_sdk}):
            s = audit.read_snapshot(audit.read_config(env))
        self.assertEqual(audit.check_snapshot(s), "RESOURCE_GATES_CLEAR")
        self.assertEqual(compute.get_image.call_args.args, ("image-test",))
        self.assertEqual(network.get_subnet.call_args.args, ("subnet-test",))
        self.assertEqual(limits.get_resource_availability.call_count, 3)
        compute.launch_instance.assert_not_called()
        compute.create_compute_capacity_report.assert_not_called()


if __name__ == "__main__":
    unittest.main()
