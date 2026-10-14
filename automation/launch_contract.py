"""Pure, offline profile-selection contract for a possible *future* OCI creator.

This module intentionally cannot contact OCI, sign requests, or launch anything.
It must not be wired into a privileged workflow until a separately approved
one-writer cutover with independent least-privilege credentials.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .guardamar_capacity import AuditError, Snapshot, check_snapshot

PRIMARY_MEMORY_GB = 6.0
FALLBACK_MEMORY_GB = 2.0
PROBE_ONLY_MEMORY_GB = 1.0
PERMITTED_PROFILES_GB = (PRIMARY_MEMORY_GB, FALLBACK_MEMORY_GB)
KNOWN_PROFILE_STATES = frozenset(("AVAILABLE", "OUT_OF_HOST_CAPACITY", "UNKNOWN"))
KNOWN_REPORT_STATES = frozenset(("RECEIVED", "UNAVAILABLE", "RATE_LIMITED"))


@dataclass(frozen=True)
class Preview:
    outcome: str
    memory_in_gbs: float | None = None


def _valid_profiles(profiles: Mapping[float, tuple[str, int | None]]) -> bool:
    """Reject corrupt/provider-surprising rows, including negative counts."""
    if not isinstance(profiles, Mapping):
        return False
    for memory, value in profiles.items():
        if (type(memory) not in (int, float)
                or float(memory) not in (*PERMITTED_PROFILES_GB, PROBE_ONLY_MEMORY_GB)):
            return False
        if not isinstance(value, tuple) or len(value) != 2:
            return False
        status, count = value
        if not isinstance(status, str) or status not in KNOWN_PROFILE_STATES:
            return False
        if count is not None and (type(count) is not int or count < 0):
            return False
    return True


def preview_candidate(
    first: Snapshot,
    final: Snapshot,
    report_status: str,
    report_profiles: Mapping[float, tuple[str, int | None]],
) -> Preview:
    """Dry-run only: two independently observed safety gates, no OCI writes.

    Conservative parity with the current live hunter: if the 6-GB preflight
    fails, do not use a cheaper profile to bypass a safety gate. The 2-GB
    fallback requires a *specific* 6-GB host-capacity miss, a 2-GB AVAILABLE
    host report and a nonzero or unspecified host count. 1 GB is probe-only.
    The status RESOURCE_GATES_CLEAR is never proof of physical capacity.
    """
    if report_status == "RATE_LIMITED":
        return Preview("RATE_LIMITED")
    try:
        initial = check_snapshot(first, memory_gb=PRIMARY_MEMORY_GB)
        if initial != "RESOURCE_GATES_CLEAR":
            return Preview(initial)
        second = check_snapshot(final, memory_gb=PRIMARY_MEMORY_GB)
        if second != "RESOURCE_GATES_CLEAR":
            return Preview(second)
        if report_status not in KNOWN_REPORT_STATES:
            return Preview("RESOURCE_BLOCKED")
        if not _valid_profiles(report_profiles):
            return Preview("RESOURCE_BLOCKED")
        memory = PRIMARY_MEMORY_GB
        if report_status == "RECEIVED":
            primary = report_profiles.get(PRIMARY_MEMORY_GB)
            fallback = report_profiles.get(FALLBACK_MEMORY_GB)
            if (primary is not None and fallback is not None
                    and primary[0] == "OUT_OF_HOST_CAPACITY"
                    and fallback[0] == "AVAILABLE"
                    and (fallback[1] is None or fallback[1] > 0)):
                memory = FALLBACK_MEMORY_GB
        # Recheck budget using the actually selected memory size. This is
        # pure validation, not a third OCI request or an authorization.
        selected = check_snapshot(final, memory_gb=memory)
        if selected != "RESOURCE_GATES_CLEAR":
            return Preview(selected)
        return Preview("PREVIEW_ONLY", memory)
    except (AuditError, TypeError, AttributeError, ValueError, OverflowError):
        return Preview("RESOURCE_BLOCKED")
