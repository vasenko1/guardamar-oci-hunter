"""No-network tests of an exact pinned intent for the future OCI handoff."""
import ast
import base64
import hashlib
import inspect
import struct
import unittest
import uuid
from types import MappingProxyType
from unittest.mock import patch

from automation import launch_intent as intent
from automation.launch_contract import Preview


def fixture():
    key_binary = struct.pack(">I", len(b"ssh-rsa")) + b"ssh-rsa" + b"fixture-key"
    key = "ssh-rsa " + base64.b64encode(key_binary).decode("ascii") + " unit-test-key"
    values = {
        "OCI_TENANCY_OCID": "ocid1.tenancy.oc1..example123",
        "OCI_COMPARTMENT_OCID": "ocid1.tenancy.oc1..example123",
        "OCI_AVAILABILITY_DOMAIN": "Fake:EU-MADRID-3-AD-1",
        "OCI_TARGET_DISPLAY_NAME": "fixture-oci-target",
        "OCI_IMAGE_OCID": "ocid1.image.oc1.eu-madrid-3.fixture123",
        "OCI_SUBNET_OCID": "ocid1.subnet.oc1.eu-madrid-3.fixture123",
        "OCI_SSH_PUBLIC_KEY": key,
        "GITHUB_REPOSITORY": "vasenko1/guardamar-oci-hunter",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": "38551708666",
    }
    return values


def test_pins(values):
    return MappingProxyType({
        name: hashlib.sha256(values[name].encode("utf-8")).hexdigest()
        for name in intent.REQUIRED_SELECTORS
    })


def build(values=None, memory=6.0):
    values = fixture() if values is None else values
    with patch.object(intent, "APPROVED_SHA256", test_pins(fixture())):
        return intent.build_offline_intent(values, Preview("PREVIEW_ONLY", memory))


class PinnedLaunchIntentTests(unittest.TestCase):
    def test_legacy_manifest_structure_complete_and_exact(self):
        env = fixture()
        result = build(env)
        expected = {
            "availability_domain": env["OCI_AVAILABILITY_DOMAIN"],
            "compartment_id": env["OCI_COMPARTMENT_OCID"],
            "display_name": env["OCI_TARGET_DISPLAY_NAME"],
            "shape": "VM.Standard.A1.Flex",
            "shape_config": {"ocpus": 1.0, "memory_in_gbs": 6.0},
            "source_details": {
                "source_type": "image", "image_id": env["OCI_IMAGE_OCID"],
                "boot_volume_size_in_gbs": 50,
            },
            "create_vnic_details": {
                "assign_ipv6_ip": False,
                "assign_private_dns_record": True,
                "assign_public_ip": True,
                "subnet_id": env["OCI_SUBNET_OCID"],
            },
            "metadata": {"ssh_authorized_keys": env["OCI_SSH_PUBLIC_KEY"]},
            "instance_options": {"are_legacy_imds_endpoints_disabled": True},
            "availability_config": {"recovery_action": "RESTORE_INSTANCE"},
            "is_pv_encryption_in_transit_enabled": True,
            "agent_config": {
                "is_management_disabled": False,
                "is_monitoring_disabled": False,
                "plugins_config": [
                    {"name": name, "desired_state": state}
                    for name, state in intent.AGENT_PLUGINS
                ],
            },
            "freeform_tags": {
                "guardamar-capacity-managed": "true",
                "guardamar-capacity-target": env["OCI_TARGET_DISPLAY_NAME"],
            },
        }
        self.assertEqual(result.manifest, expected)
        self.assertEqual(len(result.manifest["agent_config"]["plugins_config"]), 15)
        self.assertNotIn(env["OCI_SSH_PUBLIC_KEY"], repr(result))
        self.assertNotIn(env["OCI_COMPARTMENT_OCID"], repr(result))
        self.assertEqual(result.memory_in_gbs, 6.0)

    def test_fallback_only_changes_memory_in_legacy_intent(self):
        primary = build(memory=6.0)
        fallback = build(memory=2.0)
        a, b = primary.manifest.copy(), fallback.manifest.copy()
        self.assertEqual(a.pop("shape_config")["memory_in_gbs"], 6.0)
        self.assertEqual(b.pop("shape_config")["memory_in_gbs"], 2.0)
        self.assertEqual(a, b)
        self.assertEqual(fallback.memory_in_gbs, 2.0)

    def test_idempotency_token_repeat_stable_but_differs_by_profile_and_run(self):
        x, y = build(), build()
        self.assertEqual(x.retry_token, y.retry_token)
        self.assertEqual(x.retry_token, str(uuid.uuid5(
            uuid.NAMESPACE_URL, "guardamar-capacity:38551708666:6"
        )))
        self.assertNotEqual(x.retry_token, build(memory=2.0).retry_token)
        other = fixture()
        other["GITHUB_RUN_ID"] = "38551708667"
        self.assertNotEqual(x.retry_token, build(other).retry_token)

    def test_no_unapproved_preview_can_build_intent(self):
        for preview in (
            Preview("RATE_LIMITED", 6.0),
            Preview("TARGET_EXISTS", 6.0),
            Preview("RESOURCE_GATES_CLEAR", 6.0),
            Preview("PREVIEW_ONLY", 1.0),
            Preview("PREVIEW_ONLY", 4.0),
            Preview("PREVIEW_ONLY", None),
            Preview("PREVIEW_ONLY", True),
        ):
            with self.subTest(preview=preview), self.assertRaises(intent.IntentBlocked):
                with patch.object(intent, "APPROVED_SHA256", test_pins(fixture())):
                    intent.build_offline_intent(fixture(), preview)

    def test_each_reviewed_selector_is_hard_pinned(self):
        original = fixture()
        for field_name in intent.REQUIRED_SELECTORS:
            with self.subTest(name=field_name):
                broken = original.copy()
                broken[field_name] = original[field_name] + "-changed"
                with self.assertRaises(intent.IntentBlocked):
                    build(broken)
                broken[field_name] = ""
                with self.assertRaises(intent.IntentBlocked):
                    build(broken)
                del broken[field_name]
                with self.assertRaises(intent.IntentBlocked):
                    build(broken)

    def test_root_tenancy_must_match_manifest_compartment(self):
        value = fixture()
        value["OCI_TENANCY_OCID"] = "ocid1.tenancy.oc1..another"
        with self.assertRaises(intent.IntentBlocked):
            build(value)

    def test_reject_wrong_account_types_region_even_with_test_pin(self):
        good = fixture()
        cases = (
            ("OCI_COMPARTMENT_OCID", "ocid1.compartment.oc1..example123"),
            ("OCI_IMAGE_OCID", "ocid1.image.oc1.eu-paris-1.fixture123"),
            ("OCI_SUBNET_OCID", "ocid1.subnet.oc1.eu-paris-1.fixture123"),
            ("OCI_SSH_PUBLIC_KEY", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 AAA"),
            ("OCI_SSH_PUBLIC_KEY", "ssh-rsa !!!! unit-test-key"),
        )
        for name, replacement in cases:
            with self.subTest(name=name, value_kind=replacement.split(" ")[0]):
                value = good.copy()
                value[name] = replacement
                if name == "OCI_COMPARTMENT_OCID":
                    value["OCI_TENANCY_OCID"] = replacement
                with patch.object(intent, "APPROVED_SHA256", test_pins(value)):
                    with self.assertRaises(intent.IntentBlocked):
                        intent.build_offline_intent(value, Preview("PREVIEW_ONLY", 6.0))

    def test_no_fallback_local_run_id_or_pr_ref_and_wrong_repository(self):
        for field_name, replacement in (
            ("GITHUB_RUN_ID", "local"),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_RUN_ID", "123;evil"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REF", "refs/pull/5/merge"),
            ("GITHUB_REPOSITORY", "user/other-public-repo"),
        ):
            with self.subTest(name=field_name):
                value = fixture()
                value[field_name] = replacement
                with self.assertRaises(intent.IntentBlocked):
                    build(value)

    def test_errors_and_repr_never_print_ssh_key_or_resource_ids(self):
        value = fixture()
        value["OCI_SUBNET_OCID"] += "private-marker"
        with self.assertRaises(intent.IntentBlocked) as failure:
            build(value)
        self.assertNotIn("private-marker", str(failure.exception))
        self.assertNotIn(value["OCI_SSH_PUBLIC_KEY"], str(failure.exception))

    def test_module_contains_no_oci_sdk_calls_or_mutations(self):
        tree = ast.parse(inspect.getsource(intent))
        imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any(any(a.name == "oci" for a in getattr(n, "names", ()))
                             for n in imports))
        forbidden = {
            "launch_instance", "create_compute_capacity_report",
            "terminate_instance", "create_vnic", "delete_vnic", "update_instance",
        }
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse(attrs & forbidden)


if __name__ == "__main__":
    unittest.main()
