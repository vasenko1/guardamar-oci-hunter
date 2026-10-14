"""OFFLINE proposal: constant-size GitHub-run-ID watermark fence (schema v2).

No GitHub API, OCI SDK, workflow/credential, state-branch mutation or migration
side effect. All v1->v2 conversion is a pure calculation; owner-approved CAS
migration is a different, NOT-IMPLEMENTED operation.

Safety is based on strictly increasing *accepted* numeric run IDs, not an
assumption that GitHub schedules/executions arrive in numeric order. A late
older run must fail closed even if it is a legitimate new invocation. Every
authorized claim must be durably CAS-committed before considering any OCI write.
The append-only Git commit chain, not this compact JSON, provides history;
that Git history has its own unbounded-growth operational limitation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from . import durable_fence as legacy
from .launch_contract import PERMITTED_PROFILES_GB, Preview

FenceBlocked = legacy.FenceBlocked
AtomicRecordStore = legacy.AtomicRecordStore
ClaimTicket = legacy.ClaimTicket

VERSION = 2
MAX_WIRE_BYTES = 1024
MAX_CLAIM_COUNT = (1 << 63) - 1
_PHASES = frozenset({"OPEN", "CLAIMED", "HALTED"})
_REASONS = frozenset({
    "INITIAL", "CAPACITY_MISS", "RATE_LIMITED", "AMBIGUOUS",
    "BLOCKED", "ACCEPTED",
})
_FINAL_RESULTS = frozenset({
    "CAPACITY_MISS", "RATE_LIMITED", "AMBIGUOUS", "BLOCKED", "ACCEPTED",
})
_KEYS = frozenset({
    "version", "phase", "reason", "highest_spent_run_id", "claims_committed",
    "active_run_id", "active_memory_gb",
})


@dataclass(frozen=True)
class WatermarkRecord:
    phase: str
    reason: str
    highest_spent_run_id: str | None
    claims_committed: int
    active_run_id: str | None = None
    active_memory_gb: float | None = None


def _valid_run(value: object) -> bool:
    # Reuse the v1 format, which also refuses leading zeros, signs and floats.
    return legacy._run_id(value)


def _validate(record: WatermarkRecord) -> None:
    if type(record) is not WatermarkRecord:
        raise FenceBlocked("invalid_watermark_record")
    if record.phase not in _PHASES or record.reason not in _REASONS:
        raise FenceBlocked("invalid_watermark_phase")
    if (type(record.claims_committed) is not int
            or not 0 <= record.claims_committed <= MAX_CLAIM_COUNT):
        raise FenceBlocked("invalid_watermark_claim_count")
    high = record.highest_spent_run_id
    if (high is not None and not _valid_run(high)
            or (record.claims_committed == 0) != (high is None)):
        raise FenceBlocked("invalid_watermark_highest_run")
    # Distinct accepted positive decimal IDs are strictly increasing.
    # After N successful claims the Nth highest ID cannot be less than N.
    # This is a check of internal consistency, NOT proof that every earlier
    # commit in the Git history is genuine or that GitHub run IDs are ordered.
    if high is not None and record.claims_committed > int(high):
        raise FenceBlocked("watermark_count_exceeds_highest_id")
    if record.phase == "OPEN":
        if (record.reason not in {"INITIAL", "CAPACITY_MISS"}
                or record.active_run_id is not None
                or record.active_memory_gb is not None):
            raise FenceBlocked("invalid_watermark_open")
        if (record.reason == "INITIAL" and record.claims_committed != 0
                or record.reason == "CAPACITY_MISS" and record.claims_committed == 0):
            raise FenceBlocked("invalid_watermark_open_reason")
    elif record.phase == "CLAIMED":
        if (record.reason != "INITIAL" or high is None
                or record.active_run_id != high):
            raise FenceBlocked("invalid_watermark_claim")
        if (type(record.active_memory_gb) not in (int, float)
                or record.active_memory_gb not in PERMITTED_PROFILES_GB):
            raise FenceBlocked("invalid_watermark_memory")
    else:
        if record.reason not in {"RATE_LIMITED", "AMBIGUOUS", "BLOCKED", "ACCEPTED"}:
            raise FenceBlocked("invalid_watermark_halt")
        if record.active_run_id is None:
            if record.active_memory_gb is not None:
                raise FenceBlocked("invalid_watermark_preflight_halt")
        elif (not _valid_run(record.active_run_id)
              or record.active_run_id != high
              or type(record.active_memory_gb) not in (int, float)
              or record.active_memory_gb not in PERMITTED_PROFILES_GB):
            raise FenceBlocked("invalid_watermark_active_halt")


def encode(record: WatermarkRecord) -> bytes:
    """Canonical bounded ASCII JSON, never OCI/GitHub secrets or resource IDs."""
    _validate(record)
    raw = json.dumps({
        "version": VERSION,
        "phase": record.phase,
        "reason": record.reason,
        "highest_spent_run_id": record.highest_spent_run_id,
        "claims_committed": record.claims_committed,
        "active_run_id": record.active_run_id,
        "active_memory_gb": record.active_memory_gb,
    }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(raw) > MAX_WIRE_BYTES:
        raise FenceBlocked("watermark_record_too_large")
    return raw


def decode(data: bytes) -> WatermarkRecord:
    """Version-1, duplicate-key, noncanonical or unknown JSON fails closed."""
    if type(data) is not bytes or not data or len(data) > MAX_WIRE_BYTES:
        raise FenceBlocked("invalid_watermark_document")
    try:
        obj = json.loads(data.decode("ascii"), object_pairs_hook=legacy._unique_pairs)
        if (type(obj) is not dict or set(obj) != _KEYS
                or type(obj["version"]) is not int or obj["version"] != VERSION):
            raise ValueError("unsupported schema")
        record = WatermarkRecord(
            phase=obj["phase"],
            reason=obj["reason"],
            highest_spent_run_id=obj["highest_spent_run_id"],
            claims_committed=obj["claims_committed"],
            active_run_id=obj["active_run_id"],
            active_memory_gb=obj["active_memory_gb"],
        )
        if encode(record) != data:
            raise ValueError("noncanonical document")
        return record
    except (ValueError, UnicodeError, TypeError, KeyError, FenceBlocked):
        raise FenceBlocked("invalid_watermark_document") from None


def plan_v1_open_upgrade(v1_bytes: bytes) -> bytes:
    """Pure preview; CANNOT write/initialize/migrate any live state branch.

    Only a canonical, fully settled OPEN v1 state can be upgraded, never
    CLAIMED, HALTED, ambiguous or malformed state. All previously spent v1
    IDs remain protected by their numerical maximum. Git history retains the
    full earlier list without copying it into the new JSON.
    """
    old = legacy.decode(v1_bytes)
    if legacy.encode(old) != v1_bytes or old.phase != "OPEN":
        raise FenceBlocked("watermark_migration_requires_canonical_open_v1")
    if (old.reason == "INITIAL" and old.spent_run_ids
            or old.reason == "CAPACITY_MISS" and not old.spent_run_ids):
        raise FenceBlocked("watermark_migration_inconsistent_v1_history")
    high = max(old.spent_run_ids, key=int) if old.spent_run_ids else None
    return encode(WatermarkRecord(
        phase="OPEN", reason=old.reason, highest_spent_run_id=high,
        claims_committed=len(old.spent_run_ids),
    ))


def _load(store: AtomicRecordStore) -> tuple[str, WatermarkRecord]:
    try:
        revision, data = store.read()
    except Exception:
        raise FenceBlocked("watermark_read_unavailable") from None
    if type(revision) is not str or not revision or len(revision) > 256:
        raise FenceBlocked("invalid_watermark_revision")
    return revision, decode(data)


def _commit(store: AtomicRecordStore, revision: str, update: WatermarkRecord) -> None:
    raw = encode(update)
    try:
        committed = store.cas(revision, raw)
    except Exception:
        raise FenceBlocked("watermark_commit_unconfirmed") from None
    if committed is not True:
        raise FenceBlocked("watermark_commit_unconfirmed")


def claim(
    store: AtomicRecordStore, env: Mapping[str, str], preview: Preview,
) -> ClaimTicket:
    """No claim grant unless a single durable exact-revision CAS is confirmed."""
    run_id = legacy._trusted_run(env)
    if (type(preview) is not Preview or preview.outcome != "PREVIEW_ONLY"
            or type(preview.memory_in_gbs) not in (int, float)
            or preview.memory_in_gbs not in PERMITTED_PROFILES_GB):
        raise FenceBlocked("no_approved_watermark_preview")
    revision, old = _load(store)
    if old.phase != "OPEN":
        raise FenceBlocked("watermark_not_armed")
    # Numeric greater-than (not merely different): excludes every prior
    # accepted ID, including out-of-order arrivals and process restarts.
    if old.highest_spent_run_id is not None and int(run_id) <= int(
        old.highest_spent_run_id
    ):
        raise FenceBlocked("run_id_not_above_watermark")
    if old.claims_committed >= MAX_CLAIM_COUNT:
        raise FenceBlocked("watermark_counter_exhausted")
    _commit(store, revision, WatermarkRecord(
        phase="CLAIMED", reason="INITIAL",
        highest_spent_run_id=run_id,
        claims_committed=old.claims_committed + 1,
        active_run_id=run_id,
        active_memory_gb=float(preview.memory_in_gbs),
    ))
    return ClaimTicket(run_id, float(preview.memory_in_gbs), revision)


def settle(
    store: AtomicRecordStore, ticket: ClaimTicket, outcome: str,
) -> None:
    if type(ticket) is not ClaimTicket or outcome not in _FINAL_RESULTS:
        raise FenceBlocked("invalid_watermark_settlement")
    revision, old = _load(store)
    if (old.phase != "CLAIMED"
            or old.active_run_id != ticket.run_id
            or old.active_memory_gb != ticket.memory_in_gbs):
        raise FenceBlocked("watermark_settlement_mismatch")
    if outcome == "CAPACITY_MISS":
        updated = WatermarkRecord(
            "OPEN", "CAPACITY_MISS", old.highest_spent_run_id,
            old.claims_committed,
        )
    else:
        updated = WatermarkRecord(
            "HALTED", outcome, old.highest_spent_run_id,
            old.claims_committed, old.active_run_id, old.active_memory_gb,
        )
    _commit(store, revision, updated)


def stop_on_preflight_429(store: AtomicRecordStore) -> None:
    revision, old = _load(store)
    if old.phase == "HALTED":
        if old.reason == "RATE_LIMITED":
            return
        raise FenceBlocked("watermark_already_halted")
    _commit(store, revision, WatermarkRecord(
        "HALTED", "RATE_LIMITED", old.highest_spent_run_id,
        old.claims_committed, old.active_run_id, old.active_memory_gb,
    ))
