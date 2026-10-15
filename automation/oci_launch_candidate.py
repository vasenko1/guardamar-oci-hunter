"""Unwired candidate of the proven OCI capacity runner (no active Actions launch).

Selectors and SSH public key must be explicitly provided as job secrets; this
module contains no bot source, credentials, or real OCI infrastructure IDs.
Original behavior was derived from the existing production OCI-only module.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence


REGION = "eu-madrid-3"
AVAILABILITY_DOMAIN = os.environ.get("OCI_AVAILABILITY_DOMAIN", "UNCONFIGURED_AD")
COMPARTMENT_OCID = os.environ.get("OCI_COMPARTMENT_OCID", "UNCONFIGURED_COMPARTMENT")
DISPLAY_NAME = os.environ.get("OCI_TARGET_DISPLAY_NAME", "guardamar-bot")
SHAPE = "VM.Standard.A1.Flex"
OCPUS = 1.0
MEMORY_GBS = 6.0
FALLBACK_MEMORY_GBS = 2.0
ALLOWED_MEMORY_GBS = (MEMORY_GBS, FALLBACK_MEMORY_GBS)
# Diagnostic 1 GB is read-only: Oracle Linux 9 on ARM requires >=2 GB.
CAPACITY_REPORT_MEMORY_GBS = ALLOWED_MEMORY_GBS + (1.0,)
CAPACITY_STATUS_AVAILABLE = "AVAILABLE"
CAPACITY_STATUS_OUT_OF_HOST_CAPACITY = "OUT_OF_HOST_CAPACITY"
IMAGE_OCID = os.environ.get("OCI_IMAGE_OCID", "UNCONFIGURED_IMAGE")
SUBNET_OCID = os.environ.get("OCI_SUBNET_OCID", "UNCONFIGURED_SUBNET")
SSH_PUBLIC_KEY = os.environ.get("OCI_SSH_PUBLIC_KEY", "UNCONFIGURED_PUBLIC_KEY")

FREE_A1_OCPU_LIMIT = 2.0
FREE_A1_MEMORY_GB_LIMIT = 12.0
FREE_STORAGE_GB_LIMIT = 200.0
BOOT_VOLUME_GB = 50
MANAGED_TAG = "guardamar-capacity-managed"
MANAGED_TAG_VALUE = "true"
TARGET_TAG = "guardamar-capacity-target"

# This revision is explicitly owner-authorized for the exact manifest below.
# The independent workflow switch and all live OCI gates must also be present.
LAUNCH_BUILD_ENABLED = True
LAUNCH_SWITCH_VALUE = "OWNER_AUTHORIZED_PHASE_2"

POLL_DELAYS_SECONDS = (0, 5, 10, 15, 20, 30, 45, 60, 60, 60)
AMBIGUOUS_DISCOVERY_DELAYS_SECONDS = (0, 5, 10, 20, 30)

AGENT_PLUGINS = (
    ("WebLogic Management Service", "DISABLED"),
    ("Vulnerability Scanning", "DISABLED"),
    ("Oracle Java Management Service", "DISABLED"),
    ("OS Management Hub Agent", "DISABLED"),
    ("Management Agent", "DISABLED"),
    ("Fleet Application Management Service", "DISABLED"),
    ("Custom Logs Monitoring", "ENABLED"),
    ("Compute Instance Run Command", "ENABLED"),
    ("Compute Instance Monitoring", "ENABLED"),
    ("Compute HPC RDMA Auto-Configuration", "DISABLED"),
    ("Compute HPC RDMA Authentication", "DISABLED"),
    ("Cloud Guard Workload Protection", "ENABLED"),
    ("Block Volume Management", "DISABLED"),
    ("Bastion", "DISABLED"),
)


class SafetyError(RuntimeError):
    """Raised when the automation cannot prove a safe action."""


@dataclass(frozen=True)
class InstanceRecord:
    identifier: str
    display_name: str
    lifecycle_state: str
    freeform_tags: Mapping[str, str]


@dataclass(frozen=True)
class InstanceDetails:
    identifier: str
    display_name: str
    lifecycle_state: str
    shape: str
    ocpus: float
    memory_in_gbs: float
    image_id: str
    availability_domain: str
    freeform_tags: Mapping[str, str]


@dataclass(frozen=True)
class ImageRecord:
    identifier: str
    lifecycle_state: str
    operating_system: str
    display_name: str


@dataclass(frozen=True)
class SubnetRecord:
    identifier: str
    lifecycle_state: str
    availability_domain: Optional[str]
    prohibit_public_ip_on_vnic: bool


@dataclass(frozen=True)
class VnicRecord:
    identifier: str
    subnet_id: str
    public_ip: Optional[str]


@dataclass(frozen=True)
class ResourceAvailability:
    used: float
    available: float


@dataclass(frozen=True)
class AuditReport:
    region: str
    availability_domain: str
    target_instances: tuple[str, ...]
    target_states: tuple[str, ...]
    a1_ocpus_used: float
    a1_memory_gb_used: float
    free_storage_gb_used: float
    image_name: str
    target_shape_available: bool
    target_subnet_available: bool
    launch_safe: bool
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class CapacityResult:
    outcome: str
    message: str
    disable_schedule: bool = False
    instance_id: Optional[str] = None
    public_ip: Optional[str] = None
    report: Optional[AuditReport] = None
    memory_in_gbs: Optional[float] = None
    capacity_report: Optional[dict[str, Any]] = None

    @property
    def exit_code(self) -> int:
        return 0 if self.outcome in {
            "AUDIT",
            "CAPACITY_MISS",
            "RATE_LIMITED",
            "PENDING",
            "READY",
        } else 2


def launch_manifest(memory_in_gbs: float = MEMORY_GBS) -> dict[str, Any]:
    """Return one of the two exact owner-approved A1 launch intents."""

    if memory_in_gbs not in ALLOWED_MEMORY_GBS:
        raise SafetyError("launch memory is outside the approved A1 profiles")

    return {
        "availability_domain": AVAILABILITY_DOMAIN,
        "compartment_id": COMPARTMENT_OCID,
        "display_name": DISPLAY_NAME,
        "shape": SHAPE,
        "shape_config": {"ocpus": OCPUS, "memory_in_gbs": memory_in_gbs},
        "source_details": {
            "source_type": "image",
            "image_id": IMAGE_OCID,
            # Pin the Stack's implicit/default size so API default drift cannot
            # allocate more than the already budgeted Always Free 50 GB.
            "boot_volume_size_in_gbs": BOOT_VOLUME_GB,
        },
        "create_vnic_details": {
            "assign_ipv6_ip": False,
            "assign_private_dns_record": True,
            "assign_public_ip": True,
            "subnet_id": SUBNET_OCID,
        },
        "metadata": {"ssh_authorized_keys": SSH_PUBLIC_KEY},
        "instance_options": {"are_legacy_imds_endpoints_disabled": True},
        "availability_config": {"recovery_action": "RESTORE_INSTANCE"},
        "is_pv_encryption_in_transit_enabled": True,
        "agent_config": {
            "is_management_disabled": False,
            "is_monitoring_disabled": False,
            "plugins_config": [
                {"name": name, "desired_state": state}
                for name, state in AGENT_PLUGINS
            ],
        },
        "freeform_tags": {
            MANAGED_TAG: MANAGED_TAG_VALUE,
            TARGET_TAG: DISPLAY_NAME,
        },
    }


def _is_target(instance: InstanceRecord) -> bool:
    return (
        instance.display_name == DISPLAY_NAME
        or instance.freeform_tags.get(MANAGED_TAG) == MANAGED_TAG_VALUE
        or instance.freeform_tags.get(TARGET_TAG) == DISPLAY_NAME
    ) and instance.lifecycle_state.upper() != "TERMINATED"


def evaluate_audit(
    instances: Sequence[InstanceRecord],
    image: ImageRecord,
    subnet: SubnetRecord,
    available_shapes: Sequence[str],
    resource_availability: Mapping[str, ResourceAvailability],
) -> AuditReport:
    """Evaluate duplicate, configuration, and strict cost gates."""

    required = ("a1_ocpus", "a1_memory_gb", "free_storage_gb")
    missing = [name for name in required if name not in resource_availability]
    if missing:
        raise SafetyError("missing availability data: " + ", ".join(missing))

    targets = tuple(instance for instance in instances if _is_target(instance))
    cores = resource_availability["a1_ocpus"]
    memory = resource_availability["a1_memory_gb"]
    storage = resource_availability["free_storage_gb"]
    for name, value in resource_availability.items():
        if value.used < 0 or value.available < 0:
            raise SafetyError(f"invalid availability data for {name}")

    subnet_ok = (
        subnet.identifier == SUBNET_OCID
        and subnet.lifecycle_state == "AVAILABLE"
        and not subnet.prohibit_public_ip_on_vnic
        and subnet.availability_domain in (None, AVAILABILITY_DOMAIN)
    )
    blockers: list[str] = []
    if targets:
        blockers.append("a non-terminated target instance already exists")
    if image.identifier != IMAGE_OCID or image.lifecycle_state != "AVAILABLE":
        blockers.append("the exact configured image is not available")
    if image.operating_system != "Oracle Linux":
        blockers.append("the configured image is not Oracle Linux")
    if SHAPE not in available_shapes:
        blockers.append("the configured A1 shape is unavailable for image and AD")
    if not subnet_ok:
        blockers.append("the exact subnet cannot safely provide the public VNIC")
    if cores.used + OCPUS > FREE_A1_OCPU_LIMIT:
        blockers.append("the launch would exceed the 2 Always Free A1 OCPU cap")
    if memory.used + MEMORY_GBS > FREE_A1_MEMORY_GB_LIMIT:
        blockers.append("the launch would exceed the 12 GB Always Free A1 RAM cap")
    if storage.used + BOOT_VOLUME_GB > FREE_STORAGE_GB_LIMIT:
        blockers.append("the launch would exceed the 200 GB Always Free storage cap")
    if cores.available < OCPUS:
        blockers.append("OCI reports insufficient A1 OCPU service availability")
    if memory.available < MEMORY_GBS:
        blockers.append("OCI reports insufficient A1 RAM service availability")
    if storage.available < BOOT_VOLUME_GB:
        blockers.append("OCI reports insufficient free storage availability")

    return AuditReport(
        region=REGION,
        availability_domain=AVAILABILITY_DOMAIN,
        target_instances=tuple(instance.identifier for instance in targets),
        target_states=tuple(instance.lifecycle_state for instance in targets),
        a1_ocpus_used=cores.used,
        a1_memory_gb_used=memory.used,
        free_storage_gb_used=storage.used,
        image_name=image.display_name,
        target_shape_available=SHAPE in available_shapes,
        target_subnet_available=subnet_ok,
        launch_safe=not blockers,
        blockers=tuple(blockers),
    )


def _instance_blockers(instance: InstanceDetails) -> list[str]:
    blockers = []
    if instance.display_name != DISPLAY_NAME:
        blockers.append("display name mismatch")
    if instance.shape != SHAPE:
        blockers.append("shape mismatch")
    if instance.ocpus != OCPUS:
        blockers.append("OCPU mismatch")
    if instance.memory_in_gbs not in ALLOWED_MEMORY_GBS:
        blockers.append("RAM mismatch")
    if instance.image_id != IMAGE_OCID:
        blockers.append("image mismatch")
    if instance.availability_domain != AVAILABILITY_DOMAIN:
        blockers.append("availability domain mismatch")
    return blockers


def _ready_blockers(instance: InstanceDetails, vnic: VnicRecord) -> list[str]:
    blockers = _instance_blockers(instance)
    if instance.lifecycle_state != "RUNNING":
        blockers.append("instance is not RUNNING")
    if vnic.subnet_id != SUBNET_OCID:
        blockers.append("subnet mismatch")
    if not vnic.public_ip:
        blockers.append("public IPv4 is missing")
    return blockers


class OciGateway:
    """Small OCI adapter with SDK automatic retries disabled."""

    def __init__(self, env: Mapping[str, str]) -> None:
        try:
            tenancy = env["OCI_TENANCY_OCID"]
            user = env["OCI_USER_OCID"]
            fingerprint = env["OCI_FINGERPRINT"]
            private_key = env["OCI_PRIVATE_KEY"]
        except KeyError as exc:
            raise SafetyError(f"missing credential {exc.args[0]}") from exc

        required = (
            ("OCI_COMPARTMENT_OCID", COMPARTMENT_OCID),
            ("OCI_AVAILABILITY_DOMAIN", AVAILABILITY_DOMAIN),
            ("OCI_IMAGE_OCID", IMAGE_OCID),
            ("OCI_SUBNET_OCID", SUBNET_OCID),
            ("OCI_TARGET_DISPLAY_NAME", DISPLAY_NAME),
            ("OCI_SSH_PUBLIC_KEY", SSH_PUBLIC_KEY),
        )
        if any(not isinstance(val, str) or not val or
               val.startswith("UNCONFIGURED_") or
               env.get(key) != val for key, val in required):
            raise SafetyError("OCI runtime selectors are missing or inconsistent")
        if (COMPARTMENT_OCID != tenancy or
                not AVAILABILITY_DOMAIN.endswith(":EU-MADRID-3-AD-1") or
                not IMAGE_OCID.startswith("ocid1.image.oc1.eu-madrid-3.") or
                not SUBNET_OCID.startswith("ocid1.subnet.oc1.eu-madrid-3.") or
                not SSH_PUBLIC_KEY.startswith(("ssh-rsa ", "ssh-ed25519 ")) or
                "\n" in SSH_PUBLIC_KEY or
                len(SSH_PUBLIC_KEY) > 4096):
            raise SafetyError("OCI runtime selectors violate approved resource boundaries")

        import oci

        signer = oci.signer.Signer(
            tenancy=tenancy,
            user=user,
            fingerprint=fingerprint,
            private_key_file_location=None,
            private_key_content=private_key,
        )
        config = {
            "tenancy": tenancy,
            "user": user,
            "fingerprint": fingerprint,
            "key_file": "<private-key-is-kept-in-memory>",
            "region": REGION,
        }
        no_retry = oci.retry.NoneRetryStrategy()
        self._oci = oci
        self._compute = oci.core.ComputeClient(
            config, signer=signer, retry_strategy=no_retry
        )
        self._network = oci.core.VirtualNetworkClient(
            config, signer=signer, retry_strategy=no_retry
        )
        self._limits = oci.limits.LimitsClient(
            config, signer=signer, retry_strategy=no_retry
        )

    def list_instances(self) -> list[InstanceRecord]:
        response = self._oci.pagination.list_call_get_all_results(
            self._compute.list_instances,
            COMPARTMENT_OCID,
            retry_strategy=self._oci.retry.NoneRetryStrategy(),
        )
        return [
            InstanceRecord(
                item.id,
                item.display_name or "",
                item.lifecycle_state,
                item.freeform_tags or {},
            )
            for item in response.data
        ]

    def get_instance(self, identifier: str) -> InstanceDetails:
        item = self._compute.get_instance(
            identifier,
            retry_strategy=self._oci.retry.NoneRetryStrategy(),
        ).data
        shape_config = item.shape_config
        if shape_config is None:
            raise SafetyError("OCI omitted instance shape configuration")
        return InstanceDetails(
            item.id,
            item.display_name or "",
            item.lifecycle_state,
            item.shape,
            float(shape_config.ocpus),
            float(shape_config.memory_in_gbs),
            item.image_id,
            item.availability_domain,
            item.freeform_tags or {},
        )

    def get_image(self) -> ImageRecord:
        item = self._compute.get_image(
            IMAGE_OCID,
            retry_strategy=self._oci.retry.NoneRetryStrategy(),
        ).data
        return ImageRecord(
            item.id,
            item.lifecycle_state,
            item.operating_system,
            item.display_name,
        )

    def get_subnet(self) -> SubnetRecord:
        item = self._network.get_subnet(
            SUBNET_OCID,
            retry_strategy=self._oci.retry.NoneRetryStrategy(),
        ).data
        return SubnetRecord(
            item.id,
            item.lifecycle_state,
            item.availability_domain,
            bool(item.prohibit_public_ip_on_vnic),
        )

    def list_shapes(self) -> list[str]:
        response = self._oci.pagination.list_call_get_all_results(
            self._compute.list_shapes,
            COMPARTMENT_OCID,
            availability_domain=AVAILABILITY_DOMAIN,
            image_id=IMAGE_OCID,
            retry_strategy=self._oci.retry.NoneRetryStrategy(),
        )
        return [item.shape for item in response.data]

    def get_resource_availability(self) -> dict[str, ResourceAvailability]:
        names = {
            "a1_ocpus": ("compute", "standard-a1-core-regional-count"),
            "a1_memory_gb": (
                "compute",
                "standard-a1-memory-regional-count",
            ),
            "free_storage_gb": (
                "block-storage",
                "total-free-storage-gb-regional",
            ),
        }
        result = {}
        for key, (service, limit_name) in names.items():
            item = self._limits.get_resource_availability(
                service,
                limit_name,
                COMPARTMENT_OCID,
                retry_strategy=self._oci.retry.NoneRetryStrategy(),
            ).data
            if item.used is None or item.available is None:
                raise SafetyError(f"OCI omitted availability data for {key}")
            result[key] = ResourceAvailability(
                float(item.used), float(item.available)
            )
        return result

    def get_a1_capacity_report(
        self,
    ) -> dict[float, tuple[str, Optional[int]]]:
        """Return capacity snapshots for launchable and probe-only A1 profiles."""

        oci = self._oci
        requested = [
            oci.core.models.CreateCapacityReportShapeAvailabilityDetails(
                instance_shape=SHAPE,
                instance_shape_config=oci.core.models.CapacityReportInstanceShapeConfig(
                    ocpus=OCPUS,
                    memory_in_gbs=memory_in_gbs,
                ),
            )
            for memory_in_gbs in CAPACITY_REPORT_MEMORY_GBS
        ]
        details = oci.core.models.CreateComputeCapacityReportDetails(
            compartment_id=COMPARTMENT_OCID,
            availability_domain=AVAILABILITY_DOMAIN,
            shape_availabilities=requested,
        )
        response = self._compute.create_compute_capacity_report(
            details,
            retry_strategy=oci.retry.NoneRetryStrategy(),
        )
        result: dict[float, tuple[str, Optional[int]]] = {}
        for item in response.data.shape_availabilities:
            config = item.instance_shape_config
            if item.instance_shape != SHAPE or config is None:
                continue
            if config.ocpus is None or config.memory_in_gbs is None:
                continue
            if float(config.ocpus) != OCPUS:
                continue
            memory_in_gbs = float(config.memory_in_gbs)
            if memory_in_gbs not in CAPACITY_REPORT_MEMORY_GBS:
                continue
            if memory_in_gbs in result:
                raise SafetyError("OCI returned duplicate A1 capacity rows")
            count = (
                None
                if item.available_count is None
                else int(item.available_count)
            )
            result[memory_in_gbs] = (item.availability_status, count)
        return result

    def get_primary_vnic(self, instance_id: str) -> VnicRecord:
        response = self._oci.pagination.list_call_get_all_results(
            self._compute.list_vnic_attachments,
            COMPARTMENT_OCID,
            instance_id=instance_id,
            retry_strategy=self._oci.retry.NoneRetryStrategy(),
        )
        attachments = [
            item
            for item in response.data
            if item.lifecycle_state == "ATTACHED" and item.nic_index == 0
        ]
        if len(attachments) != 1:
            raise SafetyError("expected exactly one attached primary VNIC")
        item = self._network.get_vnic(
            attachments[0].vnic_id,
            retry_strategy=self._oci.retry.NoneRetryStrategy(),
        ).data
        return VnicRecord(item.id, item.subnet_id, item.public_ip)

    def launch_instance(
        self,
        retry_token: str,
        memory_in_gbs: float = MEMORY_GBS,
    ) -> str:
        """Submit exactly one SDK request with all automatic retries disabled."""

        oci = self._oci
        manifest = launch_manifest(memory_in_gbs)
        vnic = oci.core.models.CreateVnicDetails(
            **manifest.pop("create_vnic_details")
        )
        shape_config = oci.core.models.LaunchInstanceShapeConfigDetails(
            **manifest.pop("shape_config")
        )
        source = oci.core.models.InstanceSourceViaImageDetails(
            **manifest.pop("source_details")
        )
        options = oci.core.models.InstanceOptions(
            **manifest.pop("instance_options")
        )
        availability = oci.core.models.LaunchInstanceAvailabilityConfigDetails(
            **manifest.pop("availability_config")
        )
        plugin_values = manifest["agent_config"].pop("plugins_config")
        plugins = [
            oci.core.models.InstanceAgentPluginConfigDetails(**plugin)
            for plugin in plugin_values
        ]
        agent = oci.core.models.LaunchInstanceAgentConfigDetails(
            plugins_config=plugins,
            **manifest.pop("agent_config"),
        )
        details = oci.core.models.LaunchInstanceDetails(
            create_vnic_details=vnic,
            shape_config=shape_config,
            source_details=source,
            instance_options=options,
            availability_config=availability,
            agent_config=agent,
            **manifest,
        )
        response = self._compute.launch_instance(
            details,
            opc_retry_token=retry_token,
            retry_strategy=oci.retry.NoneRetryStrategy(),
        )
        return response.data.id


def audit(gateway: Any) -> AuditReport:
    return evaluate_audit(
        gateway.list_instances(),
        gateway.get_image(),
        gateway.get_subnet(),
        gateway.list_shapes(),
        gateway.get_resource_availability(),
    )


def _retry_token(
    env: Mapping[str, str],
    memory_in_gbs: float = MEMORY_GBS,
) -> str:
    # GITHUB_RUN_ID stays stable when a workflow run is re-run. Keep retries
    # idempotent for the same exact launch intent, while giving the 2 GB
    # fallback a distinct token if a later rerun selects a different profile.
    if memory_in_gbs not in ALLOWED_MEMORY_GBS:
        raise SafetyError("retry token memory is outside the approved A1 profiles")
    run_id = env.get("GITHUB_RUN_ID", "local")
    return str(uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"guardamar-capacity:{run_id}:{memory_in_gbs:g}",
    ))


def _error_kind(exc: BaseException) -> str:
    message = str(getattr(exc, "message", exc)).lower()
    status = getattr(exc, "status", None)
    code = str(getattr(exc, "code", "")).lower()
    # A throttle response always takes precedence over a capacity-like message.
    if status == 429 or code == "toomanyrequests":
        return "rate_limit"
    if "out of host capacity" in message or "outofhostcapacity" in code:
        return "capacity"
    if isinstance(status, int) and 400 <= status < 500:
        return "fatal"
    if isinstance(exc, (SafetyError, KeyError, TypeError, ValueError)):
        return "fatal"
    if type(exc).__name__ == "InvalidConfig":
        return "fatal"
    return "ambiguous"


def _safe_error(exc: BaseException) -> str:
    status = getattr(exc, "status", None)
    code = getattr(exc, "code", None)
    parts = [type(exc).__name__]
    if status is not None:
        parts.append(f"status={status}")
    if code:
        parts.append(f"code={code}")
    return " ".join(parts)


def _target_records(gateway: Any) -> list[InstanceRecord]:
    return [item for item in gateway.list_instances() if _is_target(item)]


def _observe_instance(
    gateway: Any,
    identifier: str,
    sleep: Callable[[float], None],
) -> CapacityResult:
    last_state = "UNKNOWN"
    last_memory_in_gbs: Optional[float] = None
    for delay in POLL_DELAYS_SECONDS:
        if delay:
            sleep(delay)
        instance = gateway.get_instance(identifier)
        last_state = instance.lifecycle_state
        last_memory_in_gbs = instance.memory_in_gbs
        blockers = _instance_blockers(instance)
        if blockers:
            return CapacityResult(
                "BLOCKED",
                "existing target configuration mismatch: " + ", ".join(blockers),
                disable_schedule=True,
                instance_id=identifier,
                memory_in_gbs=instance.memory_in_gbs,
            )
        if instance.lifecycle_state == "RUNNING":
            try:
                vnic = gateway.get_primary_vnic(identifier)
            except Exception as exc:
                kind = _error_kind(exc)
                if kind in {"fatal", "rate_limit"}:
                    return CapacityResult(
                        "RATE_LIMITED" if kind == "rate_limit" else "BLOCKED",
                        "READY verification failed: " + _safe_error(exc),
                        disable_schedule=True,
                        instance_id=identifier,
                        memory_in_gbs=instance.memory_in_gbs,
                    )
                continue
            blockers = _ready_blockers(instance, vnic)
            permanent_blockers = [
                blocker for blocker in blockers if blocker != "public IPv4 is missing"
            ]
            if permanent_blockers:
                return CapacityResult(
                    "BLOCKED",
                    "READY verification mismatch: "
                    + ", ".join(permanent_blockers),
                    disable_schedule=True,
                    instance_id=identifier,
                    public_ip=vnic.public_ip,
                    memory_in_gbs=instance.memory_in_gbs,
                )
            if vnic.public_ip:
                return CapacityResult(
                    "READY",
                    "exact target instance is RUNNING with a public IPv4",
                    disable_schedule=True,
                    instance_id=identifier,
                    public_ip=vnic.public_ip,
                    memory_in_gbs=instance.memory_in_gbs,
                )
        if instance.lifecycle_state in {
            "STOPPED",
            "STOPPING",
            "TERMINATING",
            "TERMINATED",
        }:
            return CapacityResult(
                "BLOCKED",
                f"target entered unexpected state {instance.lifecycle_state}",
                disable_schedule=True,
                instance_id=identifier,
                memory_in_gbs=instance.memory_in_gbs,
            )
    return CapacityResult(
        "PENDING",
        f"target remains in {last_state}; next run will verify it without launch",
        instance_id=identifier,
        memory_in_gbs=last_memory_in_gbs,
    )


def _discover_after_ambiguous(
    gateway: Any,
    sleep: Callable[[float], None],
) -> Optional[CapacityResult]:
    for delay in AMBIGUOUS_DISCOVERY_DELAYS_SECONDS:
        if delay:
            sleep(delay)
        try:
            targets = _target_records(gateway)
        except Exception as exc:
            return CapacityResult(
                "AMBIGUOUS",
                "instance discovery failed after ambiguous launch response: "
                + _safe_error(exc),
                disable_schedule=True,
            )
        if len(targets) > 1:
            return CapacityResult(
                "BLOCKED",
                "multiple target instances appeared after an ambiguous response",
                disable_schedule=True,
            )
        if targets:
            return _observe_instance(gateway, targets[0].identifier, sleep)
    return None


def _select_launch_memory(gateway: Any) -> tuple[float, dict[str, Any]]:
    """Check every memory profile; never allow 1 GB as a launch target."""

    try:
        availability = gateway.get_a1_capacity_report()
    except Exception as exc:
        if _error_kind(exc) == "rate_limit":
            return MEMORY_GBS, {"status": "RATE_LIMITED", "error": _safe_error(exc)}
        return MEMORY_GBS, {"status": "UNAVAILABLE", "error": _safe_error(exc)}

    snapshot = {
        "status": "RECEIVED",
        "profiles": {
            f"{memory_in_gbs:g}gb": {
                "status": (
                    availability[memory_in_gbs][0]
                    if memory_in_gbs in availability else "NOT_RETURNED"
                ),
                "available_count": (
                    availability[memory_in_gbs][1]
                    if memory_in_gbs in availability else None
                ),
            }
            for memory_in_gbs in CAPACITY_REPORT_MEMORY_GBS
        },
    }
    primary = availability.get(MEMORY_GBS)
    fallback = availability.get(FALLBACK_MEMORY_GBS)
    if primary is None or fallback is None:
        return MEMORY_GBS, snapshot

    primary_status, _ = primary
    fallback_status, fallback_count = fallback
    fallback_has_count = fallback_count is None or fallback_count > 0
    if (
        primary_status == CAPACITY_STATUS_OUT_OF_HOST_CAPACITY
        and fallback_status == CAPACITY_STATUS_AVAILABLE
        and fallback_has_count
    ):
        return FALLBACK_MEMORY_GBS, snapshot
    return MEMORY_GBS, snapshot


def run_launch(
    gateway: Any,
    env: Mapping[str, str],
    sleep: Callable[[float], None] = time.sleep,
) -> CapacityResult:
    """Run at most one logical and one physical LaunchInstance request."""

    report = audit(gateway)
    if report.target_instances:
        if len(report.target_instances) > 1:
            return CapacityResult(
                "BLOCKED",
                "multiple non-terminated target instances exist",
                disable_schedule=True,
                report=report,
            )
        result = _observe_instance(gateway, report.target_instances[0], sleep)
        return CapacityResult(**{**asdict(result), "report": report})
    if not report.launch_safe:
        return CapacityResult(
            "BLOCKED",
            "launch preflight failed: " + "; ".join(report.blockers),
            disable_schedule=True,
            report=report,
        )

    final_report = audit(gateway)
    if not final_report.launch_safe:
        return CapacityResult(
            "BLOCKED",
            "final launch preflight failed: " + "; ".join(final_report.blockers),
            disable_schedule=True,
            report=final_report,
        )

    selected_memory_gbs, capacity_snapshot = _select_launch_memory(gateway)
    if capacity_snapshot["status"] == "RATE_LIMITED":
        return CapacityResult(
            "RATE_LIMITED",
            "OCI throttled the capacity report; launch skipped and search stop requested",
            disable_schedule=True,
            report=final_report,
            capacity_report=capacity_snapshot,
        )

    try:
        identifier = gateway.launch_instance(
            _retry_token(env, selected_memory_gbs),
            selected_memory_gbs,
        )
    except Exception as exc:
        kind = _error_kind(exc)
        if kind == "capacity":
            return CapacityResult(
                "CAPACITY_MISS",
                "OCI reported Out of host capacity for "
                f"{OCPUS:g} OCPU / {selected_memory_gbs:g} GB; "
                "no retry in this run",
                report=final_report,
                memory_in_gbs=selected_memory_gbs,
                capacity_report=capacity_snapshot,
            )
        if kind == "rate_limit":
            return CapacityResult(
                "RATE_LIMITED",
                "OCI rate-limited the single request; stop search to prevent repeated 429",
                disable_schedule=True,
                report=final_report,
                memory_in_gbs=selected_memory_gbs,
                capacity_report=capacity_snapshot,
            )
        if kind == "fatal":
            return CapacityResult(
                "BLOCKED",
                "LaunchInstance rejected: " + _safe_error(exc),
                disable_schedule=True,
                report=final_report,
                memory_in_gbs=selected_memory_gbs,
                capacity_report=capacity_snapshot,
            )
        discovered = _discover_after_ambiguous(gateway, sleep)
        if discovered is not None:
            return CapacityResult(**{**asdict(discovered), "report": final_report, "capacity_report": capacity_snapshot})
        return CapacityResult(
            "AMBIGUOUS",
            "launch response was ambiguous and no target became visible; "
            "manual review required",
            disable_schedule=True,
            report=final_report,
            memory_in_gbs=selected_memory_gbs,
            capacity_report=capacity_snapshot,
        )

    result = _observe_instance(gateway, identifier, sleep)
    return CapacityResult(**{**asdict(result), "report": final_report, "capacity_report": capacity_snapshot})


def _emit_result(result: CapacityResult, env: Mapping[str, str]) -> None:
    """Public Actions logs must never expose target OCIDs, IP or selectors."""
    payload = asdict(result)
    payload["instance_id"] = None
    payload["public_ip"] = None
    if payload["report"] is not None:
        payload["report"]["target_instances"] = []
        payload["report"]["availability_domain"] = "[REDACTED]"
    print(json.dumps(payload, sort_keys=True))
    output_path = env.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as output:
            output.write(f"outcome={result.outcome}\n")
            output.write(
                "disable_schedule="
                + ("true" if result.disable_schedule else "false")
                + "\n"
            )

    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as summary:
            summary.write("## OCI capacity result\n\n")
            summary.write(f"- Outcome: **{result.outcome}**\n")
            summary.write("- Resource identifiers withheld from public logs.\n")


def main(
    argv: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
    gateway_factory: Any = OciGateway,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("audit", help="perform read-only safety checks")
    launch_parser = subparsers.add_parser("launch", help="run one bounded attempt")
    launch_parser.add_argument("--allow-launch", action="store_true")
    args = parser.parse_args(argv)
    current_env = os.environ if env is None else env

    if args.command == "launch":
        if not LAUNCH_BUILD_ENABLED:
            result = CapacityResult("BLOCKED", "launch is build-disabled", True)
            _emit_result(result, current_env)
            return result.exit_code
        if not args.allow_launch:
            result = CapacityResult("BLOCKED", "explicit CLI gate is missing", True)
            _emit_result(result, current_env)
            return result.exit_code
        if current_env.get("GUARDAMAR_LAUNCH_SWITCH") != LAUNCH_SWITCH_VALUE:
            result = CapacityResult("BLOCKED", "owner launch switch is missing", True)
            _emit_result(result, current_env)
            return result.exit_code

    try:
        gateway = gateway_factory(current_env)
        if args.command == "audit":
            report = audit(gateway)
            result = CapacityResult("AUDIT", "read-only audit completed", report=report)
        else:
            result = run_launch(gateway, current_env, sleep)
    except Exception as exc:
        kind = _error_kind(exc)
        result = CapacityResult(
            "RATE_LIMITED" if kind == "rate_limit" else
            ("BLOCKED" if kind == "fatal" else "AUDIT_UNAVAILABLE"),
            "preflight unavailable: " + _safe_error(exc),
            disable_schedule=kind in {"fatal", "rate_limit"},
        )
    _emit_result(result, current_env)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
