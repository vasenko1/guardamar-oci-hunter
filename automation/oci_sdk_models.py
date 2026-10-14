"""OFFLINE ONLY: build typed OCI SDK *models*; never create a client or send a request.

No OCI signing key, ComputeClient, network, SDK retry, or LaunchInstance call
is used here. This candidate must not be wired into privileged Actions jobs.
A model is not proof of fresh OCI inventory or permission for a real write.
"""
from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Mapping

from .launch_contract import Preview
from .launch_intent import (
    IntentBlocked, LaunchIntent, build_offline_intent,
)
from .launch_state import RunState


class ModelBlocked(ValueError):
    """A non-sensitive refusal, safe to return without provider details."""


@dataclass(frozen=True)
class ModelPreview:
    """Only an in-memory object graph. Neither fields nor exceptions are logged."""

    memory_in_gbs: float
    model: Any = field(repr=False)
    retry_token: str = field(repr=False)


def _first_run_only(env: Mapping[str, str]) -> None:
    """Refuse GitHub re-runs; not a cross-run or cross-repository lock."""
    if env.get("GITHUB_RUN_ATTEMPT") != "1":
        raise ModelBlocked("rerun_not_eligible")
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise ModelBlocked("event_not_eligible")
    if env.get("GITHUB_REF_PROTECTED") != "true":
        raise ModelBlocked("unprotected_ref")
    commit = env.get("GITHUB_SHA")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ModelBlocked("unverified_commit_format")


def compile_sdk_models(
    intent: LaunchIntent,
    state: RunState,
    env: Mapping[str, str],
    models: Any,
) -> ModelPreview:
    """Compile exact approved intent into nested OCI SDK model classes.

    The caller supplies SDK model classes only, not an OCI client. This
    function is intentionally unable to contact Oracle. Rebuild the approved
    manifest from pinned selectors and compare it *before* passing any input
    to the SDK constructors. A simulated consumed-write state is required,
    but does not confer durable authorization.
    """
    _first_run_only(env)
    if type(intent) is not LaunchIntent or type(state) is not RunState:
        raise ModelBlocked("unapproved_input_type")
    if (
        state.phase != "WAIT_RESPONSE"
        or state.outcome != "WRITE_INTENT_RECORDED"
        or state.write_budget_consumed is not True
        or state.memory_in_gbs != intent.memory_in_gbs
    ):
        raise ModelBlocked("write_budget_not_consumed")

    try:
        expected = build_offline_intent(
            env, Preview("PREVIEW_ONLY", intent.memory_in_gbs)
        )
    except (IntentBlocked, TypeError, AttributeError):
        raise ModelBlocked("unapproved_intent") from None
    if (
        intent.manifest != expected.manifest
        or intent.retry_token != expected.retry_token
    ):
        raise ModelBlocked("intent_does_not_match_pinned_manifest")

    # Never modify the original approved input. Match the existing live OCI
    # adapter's exact nested model classes and keyword arguments.
    payload = deepcopy(expected.manifest)
    try:
        vnic = models.CreateVnicDetails(**payload.pop("create_vnic_details"))
        shape = models.LaunchInstanceShapeConfigDetails(
            **payload.pop("shape_config")
        )
        source = models.InstanceSourceViaImageDetails(
            **payload.pop("source_details")
        )
        options = models.InstanceOptions(**payload.pop("instance_options"))
        availability = models.LaunchInstanceAvailabilityConfigDetails(
            **payload.pop("availability_config")
        )
        agent_args = payload.pop("agent_config")
        plugins = [
            models.InstanceAgentPluginConfigDetails(**entry)
            for entry in agent_args.pop("plugins_config")
        ]
        agent = models.LaunchInstanceAgentConfigDetails(
            plugins_config=plugins, **agent_args
        )
        model = models.LaunchInstanceDetails(
            create_vnic_details=vnic,
            shape_config=shape,
            source_details=source,
            instance_options=options,
            availability_config=availability,
            agent_config=agent,
            **payload,
        )
    except Exception:
        # SDK model errors may contain user-supplied values; do not expose
        # exception repr, args or chained exceptions.
        raise ModelBlocked("sdk_model_unavailable") from None
    return ModelPreview(intent.memory_in_gbs, model, expected.retry_token)
