"""Standalone, READ-ONLY OCI A1 inventory for independent public release.

This module is a release candidate, not the live capacity hunter. It cannot
create an instance, reserve capacity, install a workload or modify OCI state.
All OCI resource selectors and API credentials come from GitHub Secrets at
runtime and must never appear in a public release, CLI output or exception.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

REGION = "eu-madrid-3"
SHAPE = "VM.Standard.A1.Flex"
REQUIRED_OCPU = 1.0
REQUIRED_MEMORY_GB = 6.0
REQUIRED_STORAGE_GB = 50.0
MAX_FREE_OCPU = 2.0
MAX_FREE_MEMORY_GB = 12.0
MAX_FREE_STORAGE_GB = 200.0
LAUNCH_BUILD_ENABLED = False

CONFIG_KEYS = (
    "OCI_TENANCY_OCID",
    "OCI_USER_OCID",
    "OCI_FINGERPRINT",
    "OCI_PRIVATE_KEY",
    "OCI_COMPARTMENT_OCID",
    "OCI_AVAILABILITY_DOMAIN",
    "OCI_IMAGE_OCID",
    "OCI_SUBNET_OCID",
    "OCI_TARGET_DISPLAY_NAME",
)
TAG_MANAGED = "guardamar-capacity-managed"
TAG_TARGET = "guardamar-capacity-target"


class AuditError(Exception):
    """Fail closed; never include values supplied by an external provider."""


@dataclass(frozen=True)
class Snapshot:
    target_count: int
    image_ok: bool
    subnet_ok: bool
    shape_ok: bool
    ocpu_used: float
    ram_used: float
    free_storage_used: float
    ocpu_available: float
    ram_available: float
    storage_available: float


def read_config(env: Mapping[str, str]) -> dict[str, str]:
    config: dict[str, str] = {}
    for key in CONFIG_KEYS:
        value = env.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 8192:
            raise AuditError("configuration_unavailable")
        config[key] = value
    return config


def check_snapshot(snapshot: Snapshot) -> str:
    """Do not confuse resource safety preflight with physical host capacity."""
    numbers = (
        snapshot.ocpu_used, snapshot.ram_used,
        snapshot.free_storage_used, snapshot.ocpu_available,
        snapshot.ram_available, snapshot.storage_available,
    )
    if any(
        isinstance(x, bool) or not isinstance(x, (int, float))
        or x != x or x < 0 or x == float("inf")
        for x in numbers
    ):
        raise AuditError("invalid_availability")
    if snapshot.target_count < 0:
        raise AuditError("invalid_instance_count")
    if snapshot.target_count:
        return "TARGET_EXISTS"
    if not all((snapshot.image_ok, snapshot.subnet_ok, snapshot.shape_ok)):
        return "RESOURCE_BLOCKED"
    if (
        snapshot.ocpu_used + REQUIRED_OCPU > MAX_FREE_OCPU
        or snapshot.ram_used + REQUIRED_MEMORY_GB > MAX_FREE_MEMORY_GB
        or snapshot.free_storage_used + REQUIRED_STORAGE_GB > MAX_FREE_STORAGE_GB
    ):
        return "FREE_TIER_BLOCKED"
    if (
        snapshot.ocpu_available < REQUIRED_OCPU
        or snapshot.ram_available < REQUIRED_MEMORY_GB
        or snapshot.storage_available < REQUIRED_STORAGE_GB
    ):
        return "LIMIT_BLOCKED"
    return "RESOURCE_GATES_CLEAR"


def read_snapshot(config: Mapping[str, str]) -> Snapshot:
    """OCI SDK calls: read/list operations only, SDK retries disabled."""
    import oci

    signer = oci.signer.Signer(
        tenancy=config["OCI_TENANCY_OCID"],
        user=config["OCI_USER_OCID"],
        fingerprint=config["OCI_FINGERPRINT"],
        private_key_file_location=None,
        private_key_content=config["OCI_PRIVATE_KEY"],
    )
    sdk_config = {
        "tenancy": config["OCI_TENANCY_OCID"],
        "user": config["OCI_USER_OCID"],
        "fingerprint": config["OCI_FINGERPRINT"],
        "key_file": "<in-memory-key>",
        "region": REGION,
    }
    no_retry = oci.retry.NoneRetryStrategy()
    compute = oci.core.ComputeClient(sdk_config, signer=signer, retry_strategy=no_retry)
    network = oci.core.VirtualNetworkClient(
        sdk_config, signer=signer, retry_strategy=no_retry
    )
    limits = oci.limits.LimitsClient(sdk_config, signer=signer, retry_strategy=no_retry)

    compartment = config["OCI_COMPARTMENT_OCID"]
    ad = config["OCI_AVAILABILITY_DOMAIN"]
    image = config["OCI_IMAGE_OCID"]
    subnet = config["OCI_SUBNET_OCID"]

    instances = oci.pagination.list_call_get_all_results(
        compute.list_instances,
        compartment,
        retry_strategy=no_retry,
    ).data
    target = config["OCI_TARGET_DISPLAY_NAME"]
    target_count = sum(
        item.lifecycle_state != "TERMINATED"
        and (
            item.display_name == target
            or (item.freeform_tags or {}).get(TAG_MANAGED) == "true"
            or (item.freeform_tags or {}).get(TAG_TARGET) == target
        )
        for item in instances
    )

    image_info = compute.get_image(image, retry_strategy=no_retry).data
    image_ok = (
        image_info.id == image
        and image_info.lifecycle_state == "AVAILABLE"
        and image_info.operating_system == "Oracle Linux"
    )
    subnet_info = network.get_subnet(subnet, retry_strategy=no_retry).data
    subnet_ok = (
        subnet_info.id == subnet
        and subnet_info.lifecycle_state == "AVAILABLE"
        and subnet_info.prohibit_public_ip_on_vnic is False
        and subnet_info.availability_domain in (None, ad)
    )
    shapes = oci.pagination.list_call_get_all_results(
        compute.list_shapes,
        compartment,
        availability_domain=ad,
        image_id=image,
        retry_strategy=no_retry,
    ).data
    shape_ok = any(item.shape == SHAPE for item in shapes)

    availability = {}
    for name, service, limit in (
        ("ocpu", "compute", "standard-a1-core-regional-count"),
        ("ram", "compute", "standard-a1-memory-regional-count"),
        ("storage", "block-storage", "total-free-storage-gb-regional"),
    ):
        row = limits.get_resource_availability(
            service, limit, compartment, retry_strategy=no_retry
        ).data
        if row.used is None or row.available is None:
            raise AuditError("availability_unavailable")
        availability[name] = (float(row.used), float(row.available))

    return Snapshot(
        target_count=target_count,
        image_ok=image_ok,
        subnet_ok=subnet_ok,
        shape_ok=shape_ok,
        ocpu_used=availability["ocpu"][0],
        ram_used=availability["ram"][0],
        free_storage_used=availability["storage"][0],
        ocpu_available=availability["ocpu"][1],
        ram_available=availability["ram"][1],
        storage_available=availability["storage"][1],
    )


def run_audit(
    env: Mapping[str, str], reader: Any = read_snapshot,
) -> dict[str, str | bool]:
    try:
        result = check_snapshot(reader(read_config(env)))
    except Exception:
        # Both OCI API errors and unexpected SDK failures must remain private.
        # This is read-only and cannot retry by creating another OCI resource.
        return {"outcome": "AUDIT_UNAVAILABLE", "launch_enabled": False}
    return {"outcome": result, "launch_enabled": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("audit",))
    args = parser.parse_args(argv)
    result = run_audit(os.environ)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] != "AUDIT_UNAVAILABLE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
