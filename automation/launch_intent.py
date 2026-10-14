"""Exact legacy-compatible OCI A1 launch *intent*, with no OCI writer.

This file has no OCI SDK imports or network calls and is not invoked by
GitHub Actions. It prepares a strictly pinned local value only. A future
separate, approved writer must independently validate current OCI state,
permissions, exclusive authority and safety switches before any API write.
Never print the manifest or the SSH key.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .launch_contract import PERMITTED_PROFILES_GB, Preview

REGION = "eu-madrid-3"
SHAPE = "VM.Standard.A1.Flex"
OCPUS = 1.0
BOOT_VOLUME_GB = 50
TARGET_TAG = "guardamar-capacity-target"
MANAGED_TAG = "guardamar-capacity-managed"

# Fixed digest allowlist of the reviewed original selectors and SSH *public*
# key. No OCI IDs or SSH material are stored in this public codebase. Never
# make these digests user-controlled in a production call.
APPROVED_SHA256 = MappingProxyType({
    "OCI_COMPARTMENT_OCID": "dd228be21a2eeed391c9af4e106774f2408b5f58f03e380f0b7f1e24b5f04461",
    "OCI_AVAILABILITY_DOMAIN": "e7c446b7b7b056fbb01f788fe12c1d9cd8754f0a2d63a5c2b8dff52db7001fe2",
    "OCI_TARGET_DISPLAY_NAME": "83f54c7e62278bb0247c4e1e15a00a2c3d30861f14d57cae2dd6d12b066d183a",
    "OCI_IMAGE_OCID": "6793a7188c22b272ee0f10d9261dda614474d7cf9ca7ec2bd1582b84ac3c8eb0",
    "OCI_SUBNET_OCID": "fb2d34bf5590053c72db8015dc3b4c2cba64e2ec34a248cc42d8f69ddae04dc9",
    "OCI_SSH_PUBLIC_KEY": "c35efc176aa86527822449950c682590ce8b1151d367ab101e3084dbb309b1d2",
})
REQUIRED_SELECTORS = tuple(APPROVED_SHA256)

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


class IntentBlocked(ValueError):
    """Fail closed without exposing secret or provider-derived content."""


@dataclass(frozen=True)
class LaunchIntent:
    """Sensitive in-memory data; repr intentionally hides the entire payload."""

    memory_in_gbs: float
    manifest: dict[str, Any] = field(repr=False)
    retry_token: str = field(repr=False)


def _verified_selectors(env: Mapping[str, str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for name in REQUIRED_SELECTORS:
        value = env.get(name)
        if not isinstance(value, str) or not value or len(value) > 8192:
            raise IntentBlocked("approved_selector_missing")
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, APPROVED_SHA256[name]):
            raise IntentBlocked("approved_selector_mismatch")
        values[name] = value

    tenancy = env.get("OCI_TENANCY_OCID")
    if not isinstance(tenancy, str) or tenancy != values["OCI_COMPARTMENT_OCID"]:
        raise IntentBlocked("root_compartment_mismatch")

    if not re.fullmatch(r"ocid1\.tenancy\.oc1\.\.[a-z0-9]+", tenancy):
        raise IntentBlocked("invalid_tenancy")
    for field_name, kind in (("OCI_IMAGE_OCID", "image"), ("OCI_SUBNET_OCID", "subnet")):
        if not re.fullmatch(
            rf"ocid1\.{kind}\.oc1\.eu-madrid-3\.[a-z0-9]+", values[field_name]
        ):
            raise IntentBlocked("resource_region_mismatch")

    pieces = values["OCI_SSH_PUBLIC_KEY"].split()
    if len(pieces) != 3 or pieces[0] != "ssh-rsa":
        raise IntentBlocked("invalid_ssh_public_key")
    try:
        raw_key = base64.b64decode(pieces[1], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IntentBlocked("invalid_ssh_public_key") from None
    if not raw_key.startswith(b"\x00\x00\x00\x07ssh-rsa"):
        raise IntentBlocked("invalid_ssh_public_key")
    return values


def _run_identity(env: Mapping[str, str]) -> str:
    if env.get("GITHUB_REPOSITORY") != "vasenko1/guardamar-oci-hunter":
        raise IntentBlocked("unapproved_repository")
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise IntentBlocked("unapproved_branch")
    run_id = env.get("GITHUB_RUN_ID")
    if not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise IntentBlocked("missing_real_run_identity")
    return run_id


def build_offline_intent(env: Mapping[str, str], preview: Preview) -> LaunchIntent:
    """Build manifest only after caller supplies the approved dry-run outcome.

    A Preview is NOT sufficient authorization for live OCI launch, because it
    contains no proof that observations are fresh or exclusive. The future
    executor must add independent gates. This function can never write OCI.
    """
    if (type(preview) is not Preview or preview.outcome != "PREVIEW_ONLY"
            or type(preview.memory_in_gbs) not in (int, float)
            or preview.memory_in_gbs not in PERMITTED_PROFILES_GB):
        raise IntentBlocked("launch_preview_not_approved")

    values = _verified_selectors(env)
    run_id = _run_identity(env)
    memory_in_gbs = float(preview.memory_in_gbs)
    target = values["OCI_TARGET_DISPLAY_NAME"]
    manifest = {
        "availability_domain": values["OCI_AVAILABILITY_DOMAIN"],
        "compartment_id": values["OCI_COMPARTMENT_OCID"],
        "display_name": target,
        "shape": SHAPE,
        "shape_config": {"ocpus": OCPUS, "memory_in_gbs": memory_in_gbs},
        "source_details": {
            "source_type": "image",
            "image_id": values["OCI_IMAGE_OCID"],
            "boot_volume_size_in_gbs": BOOT_VOLUME_GB,
        },
        "create_vnic_details": {
            "assign_ipv6_ip": False,
            "assign_private_dns_record": True,
            "assign_public_ip": True,
            "subnet_id": values["OCI_SUBNET_OCID"],
        },
        "metadata": {"ssh_authorized_keys": values["OCI_SSH_PUBLIC_KEY"]},
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
            MANAGED_TAG: "true",
            TARGET_TAG: target,
        },
    }
    token = str(uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"guardamar-capacity:{run_id}:{memory_in_gbs:g}",
    ))
    return LaunchIntent(memory_in_gbs, manifest, token)
