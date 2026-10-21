import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from automation import oci_launch_candidate as capacity


def availability(cores=0, memory=0, storage=0):
    return {
        "a1_ocpus": capacity.ResourceAvailability(cores, 16 - cores),
        "a1_memory_gb": capacity.ResourceAvailability(memory, 96 - memory),
        "free_storage_gb": capacity.ResourceAvailability(
            storage, 200 - storage
        ),
    }


def image(identifier=capacity.IMAGE_OCID, state="AVAILABLE", os_name="Oracle Linux"):
    return capacity.ImageRecord(identifier, state, os_name, "Oracle-Linux-9.8")


def subnet(identifier=capacity.SUBNET_OCID, state="AVAILABLE", prohibit=False):
    return capacity.SubnetRecord(identifier, state, None, prohibit)


def record(
    identifier="instance-id",
    name=capacity.DISPLAY_NAME,
    state="RUNNING",
    tags=None,
):
    return capacity.InstanceRecord(identifier, name, state, tags or {})


def details(identifier="instance-id", state="RUNNING", **changes):
    values = {
        "identifier": identifier,
        "display_name": capacity.DISPLAY_NAME,
        "lifecycle_state": state,
        "shape": capacity.SHAPE,
        "ocpus": capacity.OCPUS,
        "memory_in_gbs": capacity.MEMORY_GBS,
        "image_id": capacity.IMAGE_OCID,
        "availability_domain": capacity.AVAILABILITY_DOMAIN,
        "freeform_tags": {},
    }
    values.update(changes)
    return capacity.InstanceDetails(**values)


class FakeError(Exception):
    def __init__(self, message, status=None, code=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


class FakeGateway:
    def __init__(self):
        self.instance_snapshots = [[]]
        self.instance_reads = [details()]
        self.launch_error = None
        self.launch_calls = []
        self.launch_memories = []
        self.capacity_report_calls = 0
        self.capacity_report_error = None
        self.capacity_report = {
            capacity.MEMORY_GBS: (
                capacity.CAPACITY_STATUS_OUT_OF_HOST_CAPACITY,
                None,
            ),
            capacity.FALLBACK_MEMORY_GBS: (
                capacity.CAPACITY_STATUS_OUT_OF_HOST_CAPACITY,
                None,
            ),
            1.0: (capacity.CAPACITY_STATUS_OUT_OF_HOST_CAPACITY, None),
        }
        self.vnics = [
            capacity.VnicRecord("vnic-id", capacity.SUBNET_OCID, "203.0.113.7")
        ]

    def list_instances(self):
        if len(self.instance_snapshots) > 1:
            return self.instance_snapshots.pop(0)
        return self.instance_snapshots[0]

    def get_image(self):
        return image()

    def get_subnet(self):
        return subnet()

    def list_shapes(self):
        return [capacity.SHAPE]

    def get_resource_availability(self):
        return availability()

    def get_a1_capacity_report(self):
        self.capacity_report_calls += 1
        if self.capacity_report_error is not None:
            raise self.capacity_report_error
        return self.capacity_report

    def get_instance(self, _identifier):
        if len(self.instance_reads) > 1:
            return self.instance_reads.pop(0)
        return self.instance_reads[0]

    def get_primary_vnic(self, _identifier):
        if len(self.vnics) > 1:
            value = self.vnics.pop(0)
        else:
            value = self.vnics[0]
        if isinstance(value, Exception):
            raise value
        return value

    def launch_instance(self, token, memory_in_gbs=capacity.MEMORY_GBS):
        self.launch_calls.append(token)
        self.launch_memories.append(memory_in_gbs)
        if self.launch_error:
            raise self.launch_error
        return "instance-id"


class CapacityAuditTests(unittest.TestCase):
    def test_empty_tenancy_closes_all_launch_preflight_gates(self):
        report = capacity.evaluate_audit(
            [], image(), subnet(), [capacity.SHAPE], availability()
        )

        self.assertTrue(report.launch_safe)
        self.assertTrue(report.target_subnet_available)
        self.assertEqual(report.target_instances, ())

    def test_name_or_managed_tag_blocks_every_nonterminated_state(self):
        cases = (
            record(state="PROVISIONING"),
            record(name="renamed", tags={capacity.MANAGED_TAG: "true"}),
            record(name="renamed", tags={capacity.TARGET_TAG: capacity.DISPLAY_NAME}),
            record(state="UNKNOWN_FUTURE_STATE"),
        )
        for instance in cases:
            with self.subTest(instance=instance):
                report = capacity.evaluate_audit(
                    [instance], image(), subnet(), [capacity.SHAPE], availability()
                )
                self.assertFalse(report.launch_safe)

    def test_terminated_target_does_not_block(self):
        report = capacity.evaluate_audit(
            [record(state="TERMINATED")],
            image(),
            subnet(),
            [capacity.SHAPE],
            availability(),
        )
        self.assertTrue(report.launch_safe)

    def test_subnet_must_be_exact_available_and_allow_public_ip(self):
        cases = (
            subnet(identifier="wrong"),
            subnet(state="TERMINATED"),
            subnet(prohibit=True),
            capacity.SubnetRecord(
                capacity.SUBNET_OCID, "AVAILABLE", "another-ad", False
            ),
        )
        for value in cases:
            with self.subTest(subnet=value):
                report = capacity.evaluate_audit(
                    [], image(), value, [capacity.SHAPE], availability()
                )
                self.assertFalse(report.launch_safe)

    def test_strict_free_tier_boundaries_allow_only_exact_fit(self):
        exact = capacity.evaluate_audit(
            [], image(), subnet(), [capacity.SHAPE], availability(1, 6, 150)
        )
        self.assertTrue(exact.launch_safe)
        for values in ((1.1, 6, 0), (1, 6.1, 0), (0, 0, 151)):
            with self.subTest(values=values):
                report = capacity.evaluate_audit(
                    [], image(), subnet(), [capacity.SHAPE], availability(*values)
                )
                self.assertFalse(report.launch_safe)

    def test_image_and_shape_are_exact(self):
        wrong_image = capacity.evaluate_audit(
            [], image("wrong"), subnet(), [capacity.SHAPE], availability()
        )
        wrong_os = capacity.evaluate_audit(
            [], image(os_name="Ubuntu"), subnet(), [capacity.SHAPE], availability()
        )
        wrong_shape = capacity.evaluate_audit(
            [], image(), subnet(), ["VM.Standard.E5.Flex"], availability()
        )
        self.assertFalse(wrong_image.launch_safe)
        self.assertFalse(wrong_os.launch_safe)
        self.assertFalse(wrong_shape.launch_safe)

    def test_manifest_pins_every_cost_and_launch_parameter(self):
        manifest = capacity.launch_manifest()
        self.assertEqual(manifest["availability_domain"], capacity.AVAILABILITY_DOMAIN)
        self.assertEqual(manifest["compartment_id"], capacity.COMPARTMENT_OCID)
        self.assertEqual(manifest["display_name"], "guardamar-bot")
        self.assertEqual(manifest["shape"], "VM.Standard.A1.Flex")
        self.assertEqual(
            manifest["shape_config"], {"ocpus": 1.0, "memory_in_gbs": 6.0}
        )
        fallback = capacity.launch_manifest(capacity.FALLBACK_MEMORY_GBS)
        self.assertEqual(
            fallback["shape_config"], {"ocpus": 1.0, "memory_in_gbs": 2.0}
        )
        with self.assertRaises(capacity.SafetyError):
            capacity.launch_manifest(1.0)
        self.assertEqual(manifest["source_details"]["image_id"], capacity.IMAGE_OCID)
        self.assertEqual(manifest["source_details"]["boot_volume_size_in_gbs"], 50)
        self.assertEqual(
            manifest["create_vnic_details"]["subnet_id"], capacity.SUBNET_OCID
        )
        self.assertTrue(manifest["create_vnic_details"]["assign_public_ip"])
        self.assertFalse(manifest["create_vnic_details"]["assign_ipv6_ip"])
        self.assertEqual(manifest["freeform_tags"][capacity.MANAGED_TAG], "true")

    def test_launch_still_requires_cli_and_workflow_switch(self):
        factory_called = False

        def factory(_env):
            nonlocal factory_called
            factory_called = True
            return FakeGateway()

        self.assertEqual(capacity.main(["launch"], {}, factory, lambda _: None), 2)
        self.assertEqual(
            capacity.main(
                ["launch", "--allow-launch"], {}, factory, lambda _: None
            ),
            2,
        )
        self.assertFalse(factory_called)

    def test_existing_running_target_is_verified_with_zero_launch_calls(self):
        gateway = FakeGateway()
        gateway.instance_snapshots = [[record()]]

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(result.public_ip, "203.0.113.7")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(gateway.launch_calls, [])
        self.assertEqual(gateway.capacity_report_calls, 0)

    def test_existing_2gb_target_is_verified_with_zero_launch_calls(self):
        gateway = FakeGateway()
        gateway.instance_snapshots = [[record()]]
        gateway.instance_reads = [
            details(memory_in_gbs=capacity.FALLBACK_MEMORY_GBS)
        ]

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(result.memory_in_gbs, capacity.FALLBACK_MEMORY_GBS)
        self.assertEqual(gateway.launch_calls, [])
        self.assertEqual(gateway.capacity_report_calls, 0)

    def test_existing_1gb_target_is_rejected(self):
        gateway = FakeGateway()
        gateway.instance_snapshots = [[record()]]
        gateway.instance_reads = [details(memory_in_gbs=1.0)]

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "BLOCKED")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(gateway.launch_calls, [])

    def test_existing_mismatched_target_blocks_with_zero_launch_calls(self):
        gateway = FakeGateway()
        gateway.instance_snapshots = [[record()]]
        gateway.instance_reads = [details(shape="VM.Standard.E5.Flex")]

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "BLOCKED")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(gateway.launch_calls, [])

    def test_capacity_report_sdk_request_contains_all_three_memory_profiles(self):
        class FakeShapeRequest:
            def __init__(self, instance_shape, instance_shape_config):
                self.instance_shape = instance_shape
                self.instance_shape_config = instance_shape_config

        class FakeShapeConfig:
            def __init__(self, ocpus, memory_in_gbs):
                self.ocpus = ocpus
                self.memory_in_gbs = memory_in_gbs

        class FakeReportRequest:
            def __init__(self, compartment_id, availability_domain, shape_availabilities):
                self.compartment_id = compartment_id
                self.availability_domain = availability_domain
                self.shape_availabilities = shape_availabilities

        model = SimpleNamespace(
            CreateCapacityReportShapeAvailabilityDetails=FakeShapeRequest,
            CapacityReportInstanceShapeConfig=FakeShapeConfig,
            CreateComputeCapacityReportDetails=FakeReportRequest,
        )
        fake_oci = SimpleNamespace(
            core=SimpleNamespace(models=model),
            retry=SimpleNamespace(NoneRetryStrategy=lambda: "NO_RETRY"),
        )
        fake_compute = Mock()
        returned = [
            SimpleNamespace(
                instance_shape=capacity.SHAPE,
                instance_shape_config=FakeShapeConfig(capacity.OCPUS, memory),
                availability_status=capacity.CAPACITY_STATUS_OUT_OF_HOST_CAPACITY,
                available_count=None,
            )
            for memory in (6.0, 2.0, 1.0)
        ]
        fake_compute.create_compute_capacity_report.return_value = SimpleNamespace(
            data=SimpleNamespace(shape_availabilities=returned)
        )

        gateway = object.__new__(capacity.OciGateway)
        gateway._oci = fake_oci
        gateway._compute = fake_compute
        report = gateway.get_a1_capacity_report()

        self.assertEqual(set(report), {6.0, 2.0, 1.0})
        fake_compute.create_compute_capacity_report.assert_called_once()
        args, kwargs = fake_compute.create_compute_capacity_report.call_args
        self.assertEqual(kwargs["retry_strategy"], "NO_RETRY")
        self.assertEqual(args[0].compartment_id, capacity.COMPARTMENT_OCID)
        self.assertEqual(args[0].availability_domain, capacity.AVAILABILITY_DOMAIN)
        self.assertEqual(
            [(row.instance_shape_config.ocpus, row.instance_shape_config.memory_in_gbs)
             for row in args[0].shape_availabilities],
            [(1.0, 6.0), (1.0, 2.0), (1.0, 1.0)],
        )

    def test_every_run_reports_6gb_2gb_and_read_only_1gb(self):
        gateway = FakeGateway()
        result = capacity.run_launch(
            gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None
        )
        self.assertEqual(gateway.capacity_report_calls, 1)
        self.assertEqual(set(result.capacity_report["profiles"]), {"6gb", "2gb", "1gb"})
        self.assertEqual(
            result.capacity_report["profiles"]["1gb"]["status"],
            capacity.CAPACITY_STATUS_OUT_OF_HOST_CAPACITY,
        )
        self.assertEqual(gateway.launch_memories, [capacity.MEMORY_GBS])
        with self.assertRaises(capacity.SafetyError):
            capacity.launch_manifest(1.0)

    def test_missing_1gb_report_row_is_visible(self):
        gateway = FakeGateway()
        gateway.capacity_report.pop(1.0)
        result = capacity.run_launch(
            gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None
        )
        self.assertEqual(result.capacity_report["profiles"]["1gb"]["status"], "NOT_RETURNED")
        self.assertEqual(gateway.launch_memories, [capacity.MEMORY_GBS])

    def test_selector_uses_2gb_only_when_6gb_is_out_and_2gb_is_available(self):
        gateway = FakeGateway()
        gateway.capacity_report = {
            capacity.MEMORY_GBS: (
                capacity.CAPACITY_STATUS_OUT_OF_HOST_CAPACITY,
                None,
            ),
            capacity.FALLBACK_MEMORY_GBS: (
                capacity.CAPACITY_STATUS_AVAILABLE,
                1,
            ),
        }
        gateway.instance_reads = [
            details(memory_in_gbs=capacity.FALLBACK_MEMORY_GBS)
        ]

        result = capacity.run_launch(gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(gateway.capacity_report_calls, 1)
        self.assertEqual(gateway.launch_memories, [capacity.FALLBACK_MEMORY_GBS])
        self.assertEqual(result.memory_in_gbs, capacity.FALLBACK_MEMORY_GBS)

    def test_selector_prefers_6gb_when_both_profiles_are_available(self):
        gateway = FakeGateway()
        gateway.capacity_report = {
            capacity.MEMORY_GBS: (capacity.CAPACITY_STATUS_AVAILABLE, 1),
            capacity.FALLBACK_MEMORY_GBS: (
                capacity.CAPACITY_STATUS_AVAILABLE,
                1,
            ),
        }

        result = capacity.run_launch(gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(gateway.launch_memories, [capacity.MEMORY_GBS])

    def test_selector_keeps_6gb_when_both_profiles_are_out_of_capacity(self):
        gateway = FakeGateway()

        result = capacity.run_launch(gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(gateway.launch_memories, [capacity.MEMORY_GBS])

    def test_selector_keeps_6gb_when_capacity_report_is_unavailable(self):
        gateway = FakeGateway()
        gateway.capacity_report_error = TimeoutError("report unavailable")

        result = capacity.run_launch(gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(gateway.capacity_report_calls, 1)
        self.assertEqual(result.capacity_report["status"], "UNAVAILABLE")
        self.assertIn("TimeoutError", result.capacity_report["error"])
        self.assertEqual(gateway.launch_memories, [capacity.MEMORY_GBS])

    def test_selector_does_not_use_2gb_when_available_count_is_zero(self):
        gateway = FakeGateway()
        gateway.capacity_report = {
            capacity.MEMORY_GBS: (
                capacity.CAPACITY_STATUS_OUT_OF_HOST_CAPACITY,
                None,
            ),
            capacity.FALLBACK_MEMORY_GBS: (
                capacity.CAPACITY_STATUS_AVAILABLE,
                0,
            ),
        }

        result = capacity.run_launch(gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(gateway.launch_memories, [capacity.MEMORY_GBS])

    def test_capacity_miss_makes_exactly_one_request_and_no_retry(self):
        gateway = FakeGateway()
        gateway.launch_error = FakeError(
            "Out of host capacity.", status=500, code="InternalError"
        )

        result = capacity.run_launch(
            gateway, {"GITHUB_RUN_ID": "123"}, lambda _: None
        )

        self.assertEqual(result.outcome, "CAPACITY_MISS")
        self.assertFalse(result.disable_schedule)
        self.assertEqual(len(gateway.launch_calls), 1)

    def test_rate_limit_classification_precedes_capacity_text(self):
        error = FakeError(
            "Out of host capacity; TooManyRequests",
            status=429,
            code="TooManyRequests",
        )
        self.assertEqual(capacity._error_kind(error), "rate_limit")

    def test_capacity_report_429_prevents_launch_and_stops_schedule(self):
        gateway = FakeGateway()
        gateway.capacity_report_error = FakeError(
            "Rate limit", status=429, code="TooManyRequests"
        )
        result = capacity.run_launch(gateway, {}, lambda _: None)
        self.assertEqual(result.outcome, "RATE_LIMITED")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(result.capacity_report["status"], "RATE_LIMITED")
        self.assertEqual(gateway.capacity_report_calls, 1)
        self.assertEqual(gateway.launch_calls, [])

    def test_preflight_429_stops_without_launch(self):
        gateway = FakeGateway()

        def limit_error():
            raise FakeError("Rate limit", status=429, code="TooManyRequests")

        gateway.get_resource_availability = limit_error
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            env = {
                "GUARDAMAR_LAUNCH_SWITCH": capacity.LAUNCH_SWITCH_VALUE,
                "GITHUB_OUTPUT": str(output),
            }
            self.assertEqual(
                capacity.main(
                    ["launch", "--allow-launch"],
                    env,
                    lambda _: gateway,
                    lambda _: None,
                ),
                0,
            )
            emitted = output.read_text()
            self.assertIn("outcome=RATE_LIMITED", emitted)
            self.assertIn("disable_schedule=true", emitted)
        self.assertEqual(gateway.launch_calls, [])
        self.assertEqual(gateway.capacity_report_calls, 0)

    def test_rate_limit_makes_exactly_one_request_and_no_retry(self):
        gateway = FakeGateway()
        gateway.launch_error = FakeError(
            "slow down", status=429, code="TooManyRequests"
        )

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "RATE_LIMITED")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(len(gateway.launch_calls), 1)

    def test_fatal_launch_rejection_disables_schedule(self):
        gateway = FakeGateway()
        gateway.launch_error = FakeError("forbidden", status=403, code="NotAuthorized")

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "BLOCKED")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(len(gateway.launch_calls), 1)

    def test_ambiguous_response_discovers_instance_before_any_repeat(self):
        gateway = FakeGateway()
        gateway.launch_error = TimeoutError("response lost")
        gateway.instance_snapshots = [[], [], [], [record(state="PROVISIONING")]]
        gateway.instance_reads = [
            details(state="PROVISIONING"),
            details(state="RUNNING"),
        ]

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(len(gateway.launch_calls), 1)

    def test_unresolved_ambiguous_response_never_retries_and_disables(self):
        gateway = FakeGateway()
        gateway.launch_error = TimeoutError("response lost")

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "AMBIGUOUS")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(len(gateway.launch_calls), 1)

    def test_accepted_launch_waits_for_running_and_verifies_public_ip(self):
        gateway = FakeGateway()
        gateway.instance_reads = [
            details(state="PROVISIONING"),
            details(state="STARTING"),
            details(state="RUNNING"),
        ]

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(result.instance_id, "instance-id")
        self.assertEqual(result.public_ip, "203.0.113.7")
        self.assertEqual(len(gateway.launch_calls), 1)

    def test_running_instance_waits_for_public_ip_without_another_launch(self):
        gateway = FakeGateway()
        gateway.instance_snapshots = [[record()]]
        gateway.vnics = [
            capacity.VnicRecord("vnic-id", capacity.SUBNET_OCID, None),
            capacity.VnicRecord("vnic-id", capacity.SUBNET_OCID, "203.0.113.7"),
        ]

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "READY")
        self.assertEqual(gateway.launch_calls, [])

    def test_429_during_vnic_ready_check_stops_without_retry(self):
        gateway = FakeGateway()
        gateway.instance_snapshots = [[record()]]
        vnic_reads = []

        def throttled_vnic(_identifier):
            vnic_reads.append(1)
            raise FakeError("Too many requests", status=429, code="TooManyRequests")

        gateway.get_primary_vnic = throttled_vnic
        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "RATE_LIMITED")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(len(vnic_reads), 1)
        self.assertEqual(gateway.launch_calls, [])

    def test_failed_discovery_after_ambiguous_response_disables_schedule(self):
        gateway = FakeGateway()
        gateway.launch_error = TimeoutError("response lost")
        gateway.instance_snapshots = [[], [], TimeoutError("list failed")]
        original_list = gateway.list_instances

        def list_instances():
            value = original_list()
            if isinstance(value, Exception):
                raise value
            return value

        gateway.list_instances = list_instances

        result = capacity.run_launch(gateway, {}, lambda _: None)

        self.assertEqual(result.outcome, "AMBIGUOUS")
        self.assertTrue(result.disable_schedule)
        self.assertEqual(len(gateway.launch_calls), 1)

    def test_retry_token_is_stable_for_same_profile_across_reruns(self):
        first = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        rerun = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}
        self.assertEqual(
            capacity._retry_token(first, capacity.MEMORY_GBS),
            capacity._retry_token(rerun, capacity.MEMORY_GBS),
        )
        self.assertNotEqual(
            capacity._retry_token(first, capacity.MEMORY_GBS),
            capacity._retry_token({"GITHUB_RUN_ID": "124"}, capacity.MEMORY_GBS),
        )

    def test_retry_token_differs_when_rerun_selects_other_profile(self):
        env = {"GITHUB_RUN_ID": "123"}
        self.assertNotEqual(
            capacity._retry_token(env, capacity.MEMORY_GBS),
            capacity._retry_token(env, capacity.FALLBACK_MEMORY_GBS),
        )
        with self.assertRaises(capacity.SafetyError):
            capacity._retry_token(env, 1.0)

    def test_result_writes_safe_github_outputs_and_ready_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            summary = Path(directory) / "summary"
            result = capacity.CapacityResult(
                "READY",
                "verified",
                True,
                "ocid1.instance.example",
                "203.0.113.7",
                memory_in_gbs=capacity.FALLBACK_MEMORY_GBS,
            )
            capacity._emit_result(
                result,
                {"GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary)},
            )
            self.assertIn("outcome=READY", output.read_text())
            self.assertIn("disable_schedule=true", output.read_text())
            self.assertIn("VM.Standard.A1.Flex", summary.read_text())
            self.assertIn("1 OCPU / 2 GB", summary.read_text())
            self.assertNotIn(capacity.SSH_PUBLIC_KEY, summary.read_text())

    def test_proposed_workflow_is_staged_for_break_before_make_only(self):
        """The workflow lives ONLY on an unmerged Draft until old writer off."""
        workflow = (
            Path(__file__).parents[1] / ".github" / "workflows"
            / "guardamar-capacity.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('cron: "3-58/15 * * * *"', workflow)
        self.assertIn("  schedule:", workflow)
        # Even an unmodified five-minute Termux cron cannot cause
        # off-slot OCI calls: the runner checks cadence before SDK setup.
        self.assertIn("Gate manual/backstop launches to 15-minute slots", workflow)
        self.assertIn('slot=$((10#$minute % 15))', workflow)
        self.assertIn('slot >= 5 && slot <= 9', workflow)
        self.assertEqual(
            workflow.count("if: steps.cadence.outputs.allow == 'true'"), 4
        )
        self.assertIn("  workflow_dispatch:", workflow)
        self.assertNotIn("  pull_request:", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertIn("  group: guardamar-capacity-search", workflow)
        self.assertIn("  cancel-in-progress: false", workflow)
        self.assertEqual(workflow.count(
            "python -m automation.oci_launch_candidate launch --allow-launch"
        ), 1)
        self.assertEqual(workflow.count(
            "python -m automation.oci_launch_candidate audit"
        ), 1)
        # No extra environment, IAM principal or duplicated nine secrets.
        self.assertEqual(workflow.count("environment: oci-readonly"), 2)
        self.assertNotIn("oci-launch", workflow)
        self.assertIn("github.ref_protected == true", workflow)
        self.assertIn("github.run_attempt == 1", workflow)
        self.assertIn("inputs.action == 'launch'", workflow)
        self.assertIn("inputs.action != 'launch'", workflow)
        self.assertIn("GUARDAMAR_LAUNCH_SWITCH: OWNER_AUTHORIZED_PHASE_2", workflow)
        self.assertIn("inputs.mode == 'candidate'", workflow)
        self.assertIn("  disable:", workflow)
        self.assertIn("gh api --method PUT", workflow)
        self.assertIn("needs.capacity.outputs.disable_schedule == 'true'", workflow)
        self.assertNotIn("automation.guardamar_capacity launch", workflow)
        self.assertIn("automation.guardamar_capacity audit", workflow)
        # No old read-only secret environment may be used as a writer.
        writer = workflow.split("\n  capacity:", 1)[-1].split("\n  disable:", 1)[0]
        self.assertIn("environment: oci-readonly", writer)
        self.assertIn("OCI_SSH_PUBLIC_KEY:", writer)
        self.assertIn("launch --allow-launch", writer)

    def test_existing_nine_secrets_allow_read_only_but_not_launch(self):
        # Real read-only environment deliberately has no SSH deployment key.
        fake_sdk = SimpleNamespace(
            signer=SimpleNamespace(Signer=Mock(return_value="fake-signer")),
            retry=SimpleNamespace(NoneRetryStrategy=Mock(return_value="no-retry")),
            core=SimpleNamespace(
                ComputeClient=Mock(return_value=Mock()),
                VirtualNetworkClient=Mock(return_value=Mock()),
            ),
            limits=SimpleNamespace(LimitsClient=Mock(return_value=Mock())),
        )
        tenancy = "ocid1.tenancy.oc1..testonly"
        env = {
            "OCI_TENANCY_OCID": tenancy,
            "OCI_USER_OCID": "ocid1.user.oc1..testonly",
            "OCI_FINGERPRINT": "fake",
            "OCI_PRIVATE_KEY": "fake",
            "OCI_COMPARTMENT_OCID": tenancy,
            "OCI_AVAILABILITY_DOMAIN": "TEST:EU-MADRID-3-AD-1",
            "OCI_IMAGE_OCID": "ocid1.image.oc1.eu-madrid-3.test",
            "OCI_SUBNET_OCID": "ocid1.subnet.oc1.eu-madrid-3.test",
            "OCI_TARGET_DISPLAY_NAME": capacity.DISPLAY_NAME,
        }
        fixture_hashes = {
            key: hashlib.sha256(env[key].encode("utf-8")).hexdigest()
            for key in capacity.APPROVED_SELECTOR_SHA256 if key in env
        }
        with (
            patch.dict(sys.modules, {"oci": fake_sdk}),
            patch.object(capacity, "APPROVED_SELECTOR_SHA256", {
                **capacity.APPROVED_SELECTOR_SHA256, **fixture_hashes,
            }),
            patch.object(capacity, "COMPARTMENT_OCID", tenancy),
            patch.object(capacity, "AVAILABILITY_DOMAIN",
                         env["OCI_AVAILABILITY_DOMAIN"]),
            patch.object(capacity, "IMAGE_OCID", env["OCI_IMAGE_OCID"]),
            patch.object(capacity, "SUBNET_OCID", env["OCI_SUBNET_OCID"]),
        ):
            gateway = capacity.OciGateway(env)
            self.assertIsNone(gateway._ssh_public_key)
            self.assertEqual(fake_sdk.core.ComputeClient.call_count, 1)
            with self.assertRaisesRegex(
                capacity.SafetyError, "launch requires a valid configured SSH"
            ):
                gateway.launch_instance("fake-retry-token")
            fake_sdk.core.ComputeClient.return_value.launch_instance.assert_not_called()
            # A different, syntactically valid same-region OCI image must
            # fail BEFORE constructing another OCI SDK client.
            changed = dict(env)
            changed["OCI_IMAGE_OCID"] = "ocid1.image.oc1.eu-madrid-3.other"
            with patch.object(capacity, "IMAGE_OCID", changed["OCI_IMAGE_OCID"]):
                with self.assertRaisesRegex(
                    capacity.SafetyError, "differ from the approved"
                ):
                    capacity.OciGateway(changed)
            changed = dict(env)
            changed["OCI_TARGET_DISPLAY_NAME"] = "not-the-approved-target"
            with patch.object(capacity, "DISPLAY_NAME",
                              changed["OCI_TARGET_DISPLAY_NAME"]):
                with self.assertRaisesRegex(
                    capacity.SafetyError, "differ from the approved"
                ):
                    capacity.OciGateway(changed)
            self.assertEqual(fake_sdk.core.ComputeClient.call_count, 1)

    def test_staged_runner_fails_before_oci_sdk_without_full_selectors(self):
        # The live audit job does not provide SSH public key or the candidate
        # write-path runtime config; missing items must never reach OCI.
        with self.assertRaises(capacity.SafetyError):
            capacity.OciGateway({
                "OCI_TENANCY_OCID": "fixture", "OCI_USER_OCID": "fixture",
                "OCI_FINGERPRINT": "fixture", "OCI_PRIVATE_KEY": "fixture",
            })

    def test_public_candidate_contains_no_original_infrastructure_ids(self):
        source = (
            Path(__file__).parents[1] / "automation" / "oci_launch_candidate.py"
        ).read_text(encoding="utf-8")
        for marker in (
            "aaaaaaaapdyqh", "urntbnbuaa", "nuiwwug7",
            "AAAAB3NzaC1yc2", "ssh-key-2026-09-07",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)

    def test_public_outcome_redacts_oci_identifiers(self):
        import io
        import contextlib
        result = capacity.CapacityResult(
            "READY", "completed", True,
            "ocid1.instance.secret", "192.0.2.70",
            report=capacity.AuditReport(
                "eu-madrid-3", "SENSITIVE_AVAILABILITY_DOMAIN",
                ("ocid1.instance.secret",), ("RUNNING",),
                0.0, 0.0, 0.0, "Oracle Linux",
                True, True, True, (),
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            summary = Path(tmp) / "summary"
            text = io.StringIO()
            with contextlib.redirect_stdout(text):
                capacity._emit_result(
                    result,
                    {"GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary)},
                )
            result_text = text.getvalue() + output.read_text() + summary.read_text()
            self.assertNotIn("ocid1.instance.secret", result_text)
            self.assertNotIn("192.0.2.70", result_text)
            self.assertNotIn("SENSITIVE_AVAILABILITY_DOMAIN", result_text)
            self.assertIn("disable_schedule=true", output.read_text())
            self.assertIn("outcome=READY", output.read_text())


if __name__ == "__main__":
    unittest.main()
