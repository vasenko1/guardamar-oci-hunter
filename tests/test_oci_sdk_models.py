"""Credential-free SDK construction and fake-transport regression.

The pinned OCI Python package is used for MODEL CLASSES ONLY. No OCI client,
signer, API key, socket or real cloud call is instantiated in these tests.
"""
import ast
import inspect
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

import oci

from automation import launch_intent, launch_state
from automation import oci_sdk_models as adapter
from automation import oci_error_policy as error_policy
from automation.launch_contract import Preview
from test_launch_intent import fixture, test_pins


def prepared(values=None, memory=6.0):
    values = fixture() if values is None else values
    values.update({
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_SHA": "a" * 40,
    })
    state = launch_state.consume_once(launch_state.begin(Preview("PREVIEW_ONLY", memory)))
    with patch.object(launch_intent, "APPROVED_SHA256", test_pins(fixture())):
        intent = launch_intent.build_offline_intent(
            values, Preview("PREVIEW_ONLY", memory)
        )
        return values, intent, state


def compile_real(values=None, memory=6.0):
    env, intent, state = prepared(values, memory)
    with patch.object(launch_intent, "APPROVED_SHA256", test_pins(fixture())):
        return adapter.compile_sdk_models(intent, state, env, oci.core.models)


class SdkModelAdapterTests(unittest.TestCase):
    def test_exact_oci_sdk_class_and_manifest_fields(self):
        env, _, _ = prepared()
        compiled = compile_real(env)
        model = compiled.model
        types = oci.core.models
        self.assertIsInstance(model, types.LaunchInstanceDetails)
        self.assertIsInstance(model.create_vnic_details, types.CreateVnicDetails)
        self.assertIsInstance(model.source_details, types.InstanceSourceViaImageDetails)
        self.assertIsInstance(model.shape_config, types.LaunchInstanceShapeConfigDetails)
        self.assertIsInstance(model.instance_options, types.InstanceOptions)
        self.assertIsInstance(
            model.availability_config, types.LaunchInstanceAvailabilityConfigDetails
        )
        self.assertIsInstance(model.agent_config, types.LaunchInstanceAgentConfigDetails)
        self.assertEqual(model.shape, "VM.Standard.A1.Flex")
        self.assertEqual(model.shape_config.ocpus, 1.0)
        self.assertEqual(model.shape_config.memory_in_gbs, 6.0)
        self.assertEqual(model.source_details.image_id, env["OCI_IMAGE_OCID"])
        self.assertEqual(model.source_details.boot_volume_size_in_gbs, 50)
        self.assertEqual(model.compartment_id, env["OCI_COMPARTMENT_OCID"])
        self.assertEqual(model.availability_domain, env["OCI_AVAILABILITY_DOMAIN"])
        self.assertEqual(model.create_vnic_details.subnet_id, env["OCI_SUBNET_OCID"])
        self.assertIs(model.create_vnic_details.assign_public_ip, True)
        self.assertIs(model.create_vnic_details.assign_ipv6_ip, False)
        self.assertIs(
            model.instance_options.are_legacy_imds_endpoints_disabled, True
        )
        self.assertIs(model.is_pv_encryption_in_transit_enabled, True)
        self.assertEqual(
            model.metadata["ssh_authorized_keys"], env["OCI_SSH_PUBLIC_KEY"]
        )
        self.assertEqual(model.freeform_tags, {
            "guardamar-capacity-managed": "true",
            "guardamar-capacity-target": env["OCI_TARGET_DISPLAY_NAME"],
        })
        self.assertEqual(len(model.agent_config.plugins_config), 14)
        self.assertEqual(
            [(x.name, x.desired_state) for x in model.agent_config.plugins_config],
            list(launch_intent.AGENT_PLUGINS),
        )
        self.assertNotIn(env["OCI_SSH_PUBLIC_KEY"], repr(compiled))
        self.assertNotIn(env["OCI_COMPARTMENT_OCID"], repr(compiled))

    def test_2gb_has_same_oci_sdk_structure_as_primary(self):
        primary = compile_real()
        fallback = compile_real(memory=2.0)
        self.assertEqual(primary.model.shape_config.memory_in_gbs, 6.0)
        self.assertEqual(fallback.model.shape_config.memory_in_gbs, 2.0)
        self.assertEqual(primary.model.shape_config.ocpus, 1.0)
        self.assertEqual(fallback.model.shape_config.ocpus, 1.0)
        self.assertEqual(
            primary.model.source_details.boot_volume_size_in_gbs,
            fallback.model.source_details.boot_volume_size_in_gbs,
        )
        self.assertNotEqual(primary.retry_token, fallback.retry_token)

    def test_retries_of_same_github_run_are_rejected_before_models(self):
        for bad in ("2", "3", "0", "", "abc"):
            with self.subTest(attempt=bad):
                env, intent, state = prepared()
                env["GITHUB_RUN_ATTEMPT"] = bad
                models = Mock()
                with self.assertRaisesRegex(adapter.ModelBlocked, "rerun_not_eligible"):
                    adapter.compile_sdk_models(intent, state, env, models)
                models.LaunchInstanceDetails.assert_not_called()

    def test_untrusted_event_ref_commit_rejected(self):
        for key, val in (
            ("GITHUB_EVENT_NAME", "schedule"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REF_PROTECTED", "false"),
            ("GITHUB_SHA", "x" * 40),
            ("GITHUB_SHA", ""),
        ):
            with self.subTest(field=key, value=val):
                env, intent, state = prepared()
                env[key] = val
                with self.assertRaises(adapter.ModelBlocked):
                    adapter.compile_sdk_models(intent, state, env, Mock())

    def test_unconsumed_or_inconsistent_state_cannot_build_models(self):
        env, intent, state = prepared()
        for bad in (
            replace(state, phase="PREPARED"),
            replace(state, write_budget_consumed=False),
            replace(state, outcome="AMBIGUOUS"),
            replace(state, memory_in_gbs=2.0),
        ):
            with self.subTest(state=bad.phase):
                with self.assertRaises(adapter.ModelBlocked):
                    adapter.compile_sdk_models(intent, bad, env, Mock())

    def test_tampering_manifest_token_or_env_fails_closed(self):
        env, intent, state = prepared()
        for modified in (
            replace(intent, retry_token="forged-token"),
            replace(intent, manifest={**intent.manifest, "shape": "VM.DenseIO"}),
            replace(intent, manifest={
                **intent.manifest,
                "source_details": {
                    **intent.manifest["source_details"],
                    "boot_volume_size_in_gbs": 1000,
                },
            }),
        ):
            with self.subTest(condition="tamper"):
                with patch.object(
                    launch_intent, "APPROVED_SHA256", test_pins(fixture())
                ):
                    with self.assertRaises(adapter.ModelBlocked):
                        adapter.compile_sdk_models(modified, state, env, Mock())
        env["OCI_SUBNET_OCID"] += "-different"
        with patch.object(launch_intent, "APPROVED_SHA256", test_pins(fixture())):
            with self.assertRaises(adapter.ModelBlocked):
                adapter.compile_sdk_models(intent, state, env, Mock())

    def test_model_ctor_errors_cannot_print_secret_values(self):
        env, intent, state = prepared()
        fake = Mock()
        fake.CreateVnicDetails.side_effect = RuntimeError(
            "private-ssh-key-or-oci-request-material"
        )
        with patch.object(launch_intent, "APPROVED_SHA256", test_pins(fixture())):
            with self.assertRaises(adapter.ModelBlocked) as raised:
                adapter.compile_sdk_models(intent, state, env, fake)
        self.assertEqual(str(raised.exception), "sdk_model_unavailable")
        self.assertIsNone(raised.exception.__cause__)

    def test_mock_oci_launch_request_is_one_test_only_invocation(self):
        """Do not invoke any real OCI client: FakeCompute is a local Mock."""
        env, intent, state = prepared()
        with patch.object(launch_intent, "APPROVED_SHA256", test_pins(fixture())):
            preview = adapter.compile_sdk_models(
                intent, state, env, oci.core.models
            )
        fake_compute = Mock()
        fake_compute.launch_instance.return_value = SimpleNamespace(
            data=SimpleNamespace(id="fake-instance-no-oci-call")
        )
        # EXACTLY ONE simulated LaunchInstance with explicit no-retry
        # strategy; no OCI signer/network/ComputeClient exists in this test.
        response = fake_compute.launch_instance(
            preview.model,
            opc_retry_token=preview.retry_token,
            retry_strategy=oci.retry.NoneRetryStrategy(),
        )
        self.assertEqual(response.data.id, "fake-instance-no-oci-call")
        fake_compute.launch_instance.assert_called_once()
        self.assertIsInstance(
            fake_compute.launch_instance.call_args.kwargs["retry_strategy"],
            oci.retry.NoneRetryStrategy,
        )
        resolved = launch_state.submitted(state, "ACCEPTED")
        self.assertEqual(resolved.phase, "OBSERVE_ONLY")
        with self.assertRaises(launch_state.InvalidTransition):
            launch_state.consume_once(resolved)

    def test_sdk_error_status_cannot_leak_provider_text(self):
        class FakeError(Exception):
            def __init__(self, status, code, message):
                super().__init__(message)
                self.status = status
                self.code = code
                self.message = message

        examples = (
            (429, "OutOfHostCapacity", "Out of host capacity!", "RATE_LIMITED"),
            (500, "TooManyRequests", "Out of host capacity!", "RATE_LIMITED"),
            (500, "OutOfHostCapacity", "capacity", "CAPACITY_MISS"),
            (400, "NotAuthorized", "denied", "BLOCKED"),
            (401, "NotAuthorizedOrNotFound", "sensitive", "BLOCKED"),
            (503, "InternalError", "private caller details", "AMBIGUOUS"),
            (None, "", "private caller details", "AMBIGUOUS"),
        )
        for status, code, message, outcome in examples:
            with self.subTest(status=status, code=code):
                error = FakeError(status, code, message)
                result = error_policy.classify_oci_failure(error)
                self.assertEqual(result, outcome)
                self.assertNotIn("private caller", result)
                self.assertNotIn("sensitive", result)

    def test_adapter_has_no_compute_client_or_oci_mutating_methods(self):
        for module in (adapter, error_policy):
            tree = ast.parse(inspect.getsource(module))
            attrs = {
                n.attr for n in ast.walk(tree)
                if isinstance(n, ast.Attribute)
            }
            self.assertNotIn("ComputeClient", attrs)
            self.assertNotIn("launch_instance", attrs)
            self.assertNotIn("create_compute_capacity_report", attrs)
            self.assertNotIn("terminate_instance", attrs)


if __name__ == "__main__":
    unittest.main()
