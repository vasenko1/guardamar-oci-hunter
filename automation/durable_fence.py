"""Offline durable-CAS fencing *protocol*: no backend, OCI or GitHub IO.

No adapter in this repository can persist or authorize an actual OCI write.
A future backend MUST provide a single linearizable compare-and-swap operation
for one globally shared control record and durable reads. Not all GitHub APIs
offer this guarantee. Until that backend is independently proven and the old
writer revoked, the live Hunter must remain the only OCI creator.

Claim is stored BEFORE any hypothetical LaunchInstance; a lost acknowledgement
always causes a safe outage, never another write. A definitive host-capacity
miss may re-arm the next DISTINCT run; ambiguous results and 429 halt.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Mapping, Protocol

from .launch_contract import PERMITTED_PROFILES_GB, Preview

MAX_JOURNAL_SIZE = 10_000
_MAX_BYTES = 400_000
_PHASES = frozenset({"OPEN", "CLAIMED", "HALTED"})
_REASONS = frozenset({
    "INITIAL", "CAPACITY_MISS", "RATE_LIMITED", "AMBIGUOUS",
    "BLOCKED", "ACCEPTED",
})
_FINAL_RESULTS = frozenset({
    "CAPACITY_MISS", "RATE_LIMITED", "AMBIGUOUS", "BLOCKED", "ACCEPTED",
})


class FenceBlocked(Exception):
    """Failure without provider data or a decision to perform an OCI write."""


@dataclass(frozen=True)
class FenceRecord:
    """Only non-sensitive intent metadata, never cloud IDs or key bytes."""

    phase: str
    reason: str
    spent_run_ids: tuple[str, ...]
    active_run_id: str | None = None
    active_memory_gb: float | None = None


@dataclass(frozen=True)
class ClaimTicket:
    """Result of a *confirmed durable* claim, not permission to use OCI."""

    run_id: str
    memory_in_gbs: float
    revision: str


class AtomicRecordStore(Protocol):
    """Implementation not included. Version is an opaque backend ETag.

    read(): only durable committed data, no cached or eventually-consistent
    snapshot for the purpose of authorizing a write.
    cas(): true ONLY on an atomically committed new record; false on version
    conflict; exception on unknown/partial result. Never retry unknown CAS.
    """

    def read(self) -> tuple[str, bytes]: ...
    def cas(self, expected_revision: str, new_record: bytes) -> bool: ...


def initial_record_bytes() -> bytes:
    """Test fixture only, NOT an auto-initialization or arming endpoint."""
    return encode(FenceRecord("OPEN", "INITIAL", ()))


def _run_id(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[1-9][0-9]{0,19}", value))


def _validate(record: FenceRecord) -> None:
    if type(record) is not FenceRecord:
        raise FenceBlocked("invalid_record_type")
    if record.phase not in _PHASES or record.reason not in _REASONS:
        raise FenceBlocked("invalid_fence_state")
    spent = record.spent_run_ids
    if not isinstance(spent, tuple) or len(spent) > MAX_JOURNAL_SIZE:
        raise FenceBlocked("invalid_fence_journal")
    if any(not _run_id(v) for v in spent) or len(set(spent)) != len(spent):
        raise FenceBlocked("invalid_fence_journal")
    if record.phase == "OPEN":
        if record.reason not in {"INITIAL", "CAPACITY_MISS"}:
            raise FenceBlocked("invalid_open_state")
        if record.active_run_id is not None or record.active_memory_gb is not None:
            raise FenceBlocked("unsettled_open_state")
    elif record.phase == "CLAIMED":
        if record.reason != "INITIAL" or not _run_id(record.active_run_id):
            raise FenceBlocked("invalid_claim")
        if record.active_run_id not in spent:
            raise FenceBlocked("uncommitted_claim")
        if type(record.active_memory_gb) not in (int, float):
            raise FenceBlocked("invalid_claim_memory")
        if record.active_memory_gb not in PERMITTED_PROFILES_GB:
            raise FenceBlocked("invalid_claim_memory")
    else:
        if record.reason not in {
            "RATE_LIMITED", "AMBIGUOUS", "BLOCKED", "ACCEPTED",
        }:
            raise FenceBlocked("invalid_halt_reason")
        if record.active_run_id is not None:
            if not _run_id(record.active_run_id):
                raise FenceBlocked("invalid_halt_identity")
            if record.active_run_id not in spent:
                raise FenceBlocked("uncommitted_halt")
            if type(record.active_memory_gb) not in (int, float):
                raise FenceBlocked("invalid_halt_memory")
            if record.active_memory_gb not in PERMITTED_PROFILES_GB:
                raise FenceBlocked("invalid_halt_memory")
        elif record.active_memory_gb is not None:
            raise FenceBlocked("invalid_preflight_halt")


def encode(record: FenceRecord) -> bytes:
    """Canonical strict JSON; no instance identity, OCID, IP or credentials."""
    _validate(record)
    doc = {
        "version": 1,
        "phase": record.phase,
        "reason": record.reason,
        "spent_run_ids": list(record.spent_run_ids),
        "active_run_id": record.active_run_id,
        "active_memory_gb": record.active_memory_gb,
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), allow_nan=False)
    data = raw.encode("ascii")
    if len(data) > _MAX_BYTES:
        raise FenceBlocked("fence_store_capacity_exceeded")
    return data


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON fields rather than accepting the last value."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def decode(data: bytes) -> FenceRecord:
    """Reject malformed, stale-schema, unrecognised or ambiguous state."""
    if type(data) is not bytes or not data or len(data) > _MAX_BYTES:
        raise FenceBlocked("invalid_fence_document")
    try:
        obj = json.loads(data.decode("ascii"), object_pairs_hook=_unique_pairs)
        if type(obj) is not dict or set(obj) != {
            "version", "phase", "reason", "spent_run_ids",
            "active_run_id", "active_memory_gb",
        } or type(obj["version"]) is not int or obj["version"] != 1:
            raise ValueError("invalid schema")
        if type(obj["spent_run_ids"]) is not list:
            raise ValueError("bad journal")
        record = FenceRecord(
            phase=obj["phase"], reason=obj["reason"],
            spent_run_ids=tuple(obj["spent_run_ids"]),
            active_run_id=obj["active_run_id"],
            active_memory_gb=obj["active_memory_gb"],
        )
        _validate(record)
        return record
    except (ValueError, UnicodeError, TypeError, KeyError, FenceBlocked):
        raise FenceBlocked("invalid_fence_document") from None


def _load(store: AtomicRecordStore) -> tuple[str, FenceRecord]:
    try:
        revision, raw = store.read()
    except Exception:
        raise FenceBlocked("fence_read_unavailable") from None
    if not isinstance(revision, str) or not revision or len(revision) > 256:
        raise FenceBlocked("invalid_fence_revision")
    return revision, decode(raw)


def _commit(store: AtomicRecordStore, revision: str, update: FenceRecord) -> None:
    # A CAS that commits but times out must NEVER be treated as a grant.
    raw = encode(update)
    try:
        committed = store.cas(revision, raw)
    except Exception:
        raise FenceBlocked("fence_commit_unconfirmed") from None
    if committed is not True:
        raise FenceBlocked("fence_commit_unconfirmed")


def _trusted_run(env: Mapping[str, str]) -> str:
    """Defense in depth: environment variables alone are not authorization."""
    if env.get("GITHUB_REPOSITORY") != "vasenko1/guardamar-oci-hunter":
        raise FenceBlocked("wrong_fence_repository")
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise FenceBlocked("wrong_fence_branch")
    if env.get("GITHUB_REF_PROTECTED") != "true":
        raise FenceBlocked("unprotected_fence_ref")
    if env.get("GITHUB_RUN_ATTEMPT") != "1":
        raise FenceBlocked("fence_rerun_forbidden")
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise FenceBlocked("fence_event_forbidden")
    run_id = env.get("GITHUB_RUN_ID")
    if not _run_id(run_id):
        raise FenceBlocked("invalid_fence_run_id")
    return run_id


def claim(
    store: AtomicRecordStore, env: Mapping[str, str], preview: Preview,
) -> ClaimTicket:
    """Commit one durable claim BEFORE a caller can consider an OCI write.

    The caller must additionally check a fresh OCI audit and approved
    manifest, and the future executor must not exceed one actual SDK call.
    This function does NOT make any OCI write or guarantee cross-repo safety.
    """
    run_id = _trusted_run(env)
    if (type(preview) is not Preview or preview.outcome != "PREVIEW_ONLY"
            or type(preview.memory_in_gbs) not in (int, float)
            or preview.memory_in_gbs not in PERMITTED_PROFILES_GB):
        raise FenceBlocked("no_approved_preview")
    revision, old = _load(store)
    if old.phase != "OPEN":
        raise FenceBlocked("fence_not_armed")
    if run_id in old.spent_run_ids:
        raise FenceBlocked("run_id_already_spent")
    if len(old.spent_run_ids) >= MAX_JOURNAL_SIZE:
        raise FenceBlocked("fence_journal_full")
    new = FenceRecord(
        "CLAIMED", "INITIAL", (*old.spent_run_ids, run_id),
        run_id, float(preview.memory_in_gbs),
    )
    _commit(store, revision, new)
    return ClaimTicket(run_id, float(preview.memory_in_gbs), revision)


def settle(
    store: AtomicRecordStore, ticket: ClaimTicket, result: str,
) -> None:
    """Only definitive OutOfHostCapacity re-arms for a distinct next run.

    No automatic create is allowed after accepted, fatal, ambiguous or 429.
    A failed settlement leaves CLAIMED and blocks every future claim.
    """
    if type(ticket) is not ClaimTicket or result not in _FINAL_RESULTS:
        raise FenceBlocked("invalid_fence_settlement")
    revision, old = _load(store)
    if (old.phase != "CLAIMED" or old.active_run_id != ticket.run_id
            or old.active_memory_gb != ticket.memory_in_gbs):
        raise FenceBlocked("fence_settlement_mismatch")
    if result == "CAPACITY_MISS":
        new = FenceRecord("OPEN", "CAPACITY_MISS", old.spent_run_ids)
    else:
        new = FenceRecord(
            "HALTED", result, old.spent_run_ids,
            old.active_run_id, old.active_memory_gb,
        )
    _commit(store, revision, new)


def stop_on_preflight_429(store: AtomicRecordStore) -> None:
    """Mark the global fence HALTED even if throttle occurred before claim."""
    revision, old = _load(store)
    if old.phase == "HALTED":
        if old.reason == "RATE_LIMITED":
            return
        raise FenceBlocked("fence_already_halted")
    new = FenceRecord(
        "HALTED", "RATE_LIMITED", old.spent_run_ids,
        old.active_run_id, old.active_memory_gb,
    )
    _commit(store, revision, new)
