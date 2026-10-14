"""Offline-only OCI launch outcome reducer; never performs a cloud write.

This is a *simulation* of one-run behavior, not a durable lock and not a
production launcher. No SDK, subprocess, GitHub API, filesystem or network
is imported. The future real writer requires fresh OCI observations, explicit
owner authorization, external one-writer cutover, 429 gates and an audited
persisted write boundary. No workflow currently imports this module.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from .launch_contract import PERMITTED_PROFILES_GB, Preview


class InvalidTransition(ValueError):
    """Safe, context-free rejection of invalid or duplicate transitions."""


@dataclass(frozen=True)
class RunState:
    phase: str
    outcome: str
    memory_in_gbs: float | None = None
    write_budget_consumed: bool = False
    disable_schedule: bool = False


def begin(preview: Preview) -> RunState:
    """No 429 may be weakened to a different outcome."""
    if type(preview) is not Preview:
        raise InvalidTransition("invalid_preview")
    if preview.outcome == "RATE_LIMITED":
        return RunState("STOPPED", "RATE_LIMITED", disable_schedule=True)
    if (preview.outcome == "PREVIEW_ONLY"
            and type(preview.memory_in_gbs) in (int, float)
            and preview.memory_in_gbs in PERMITTED_PROFILES_GB):
        return RunState("PREPARED", "NO_WRITE", float(preview.memory_in_gbs))
    if preview.outcome in {
        "TARGET_EXISTS", "RESOURCE_BLOCKED", "FREE_TIER_BLOCKED",
        "LIMIT_BLOCKED", "AUDIT_UNAVAILABLE",
    }:
        return RunState("STOPPED", preview.outcome, disable_schedule=True)
    raise InvalidTransition("unsupported_preflight_result")


def consume_once(state: RunState) -> RunState:
    """Model *consumption before* a write; does not issue a request."""
    if (type(state) is not RunState or state.phase != "PREPARED"
            or state.write_budget_consumed):
        raise InvalidTransition("write_budget_already_consumed_or_unavailable")
    return replace(
        state, phase="WAIT_RESPONSE", outcome="WRITE_INTENT_RECORDED",
        write_budget_consumed=True,
    )


def submitted(state: RunState, response: str) -> RunState:
    """One non-retryable hypothetical response after the single write."""
    if (type(state) is not RunState or state.phase != "WAIT_RESPONSE"
            or not state.write_budget_consumed):
        raise InvalidTransition("write_outcome_without_submission")
    if response == "RATE_LIMITED":
        return replace(
            state, phase="STOPPED", outcome="RATE_LIMITED",
            disable_schedule=True,
        )
    if response == "CAPACITY_MISS":
        return replace(state, phase="STOPPED", outcome="CAPACITY_MISS")
    if response == "FATAL":
        return replace(
            state, phase="STOPPED", outcome="BLOCKED", disable_schedule=True,
        )
    if response == "AMBIGUOUS":
        return replace(
            state, phase="DISCOVER_ONLY", outcome="AMBIGUOUS",
            disable_schedule=True,
        )
    if response == "ACCEPTED":
        return replace(state, phase="OBSERVE_ONLY", outcome="PENDING")
    raise InvalidTransition("unapproved_provider_result")


def discovered(state: RunState, target_count: int) -> RunState:
    """Only read-only discovery is permitted after an ambiguous write."""
    if (type(state) is not RunState or state.phase != "DISCOVER_ONLY"
            or not state.write_budget_consumed):
        raise InvalidTransition("unexpected_discovery")
    if type(target_count) is not int or target_count < 0:
        raise InvalidTransition("invalid_target_count")
    if target_count == 1:
        return replace(state, phase="OBSERVE_ONLY", outcome="PENDING")
    if target_count > 1:
        return replace(state, phase="STOPPED", outcome="BLOCKED")
    return replace(state, phase="STOPPED", outcome="AMBIGUOUS")


def observed(
    state: RunState, *, target_found: bool,
    matches_approved_manifest: bool,
    lifecycle_state: str, has_public_ipv4: bool,
) -> RunState:
    """Read-only state reduction; caller must separately verify exact OCI ID."""
    if (type(state) is not RunState or state.phase != "OBSERVE_ONLY"
            or not state.write_budget_consumed):
        raise InvalidTransition("unexpected_observation")
    if not all(type(flag) is bool for flag in (
        target_found, matches_approved_manifest, has_public_ipv4,
    )):
        raise InvalidTransition("invalid_observation")
    if not target_found:
        return replace(state, outcome="PENDING")
    if not matches_approved_manifest:
        return replace(
            state, phase="STOPPED", outcome="BLOCKED", disable_schedule=True,
        )
    if lifecycle_state == "RUNNING" and has_public_ipv4:
        return replace(
            state, phase="STOPPED", outcome="READY", disable_schedule=True,
        )
    if lifecycle_state in {"STOPPING", "STOPPED", "TERMINATING", "TERMINATED"}:
        return replace(
            state, phase="STOPPED", outcome="BLOCKED", disable_schedule=True,
        )
    if lifecycle_state in {"PROVISIONING", "STARTING", "RUNNING"}:
        return replace(state, outcome="PENDING")
    return replace(
        state, phase="STOPPED", outcome="BLOCKED", disable_schedule=True,
    )


def throttle(state: RunState) -> RunState:
    """Every OCI HTTP 429 discovered during an active state is a hard stop."""
    if type(state) is not RunState or state.phase == "STOPPED":
        raise InvalidTransition("no_active_oci_request")
    return replace(
        state, phase="STOPPED", outcome="RATE_LIMITED",
        disable_schedule=True,
    )
