"""Unwired, strict-v2 GitHub CAS backend. NO OCI SDK, migration or workflows.

This is not a live launcher. It only operates on an *existing*, canonical
version-2 protected ledger after a separately reviewed one-time migration.
It refuses version-1 and all invalid state transitions before creating Git
blob/tree/commit objects. It does not initialize, upgrade or reset the ref.

The underlying GraphQL beforeOid operation was proven with a stand-alone
same-tree probe, not with THIS version-aware adapter. Actual deployment needs
new dedicated read/write permission and fault-injection testing first.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import fence_watermark_v2 as v2
from . import github_fence_readonly as inspector
from .github_fence_store import GitHubCASStore, JsonTransport, TransportUnavailable


class _RestrictedGET:
    """Allow the inspector's GET-only protocol over the existing transport."""
    def __init__(self, transport: JsonTransport):
        self.transport = transport

    def get(self, path: str) -> dict:
        return self.transport.request("GET", path)


def validate_transition(old: v2.WatermarkRecord,
                        new: v2.WatermarkRecord) -> None:
    """Whitelist only the exact v2 reducer's irreversible transitions.

    This extra writer-level gate is not a replacement for review of who holds
    a repository-wide contents:write token. It rejects accidental direct
    calls to .cas() that could reset the maximum or reopen halted state.
    """
    v2.encode(old)
    v2.encode(new)
    same_history = (
        new.highest_spent_run_id == old.highest_spent_run_id
        and new.claims_committed == old.claims_committed
    )
    if old.phase == "OPEN":
        if new.phase == "CLAIMED":
            old_high = (int(old.highest_spent_run_id)
                        if old.highest_spent_run_id is not None else 0)
            good = (
                new.reason == "INITIAL"
                and new.highest_spent_run_id is not None
                and int(new.highest_spent_run_id) > old_high
                and new.claims_committed == old.claims_committed + 1
                and new.active_run_id == new.highest_spent_run_id
            )
        elif new.phase == "HALTED":
            good = (
                same_history and new.reason == "RATE_LIMITED"
                and new.active_run_id is None and new.active_memory_gb is None
            )
        else:
            good = False
    elif old.phase == "CLAIMED":
        if new.phase == "OPEN":
            good = (
                same_history and new.reason == "CAPACITY_MISS"
                and new.active_run_id is None and new.active_memory_gb is None
            )
        elif new.phase == "HALTED":
            good = (
                same_history
                and new.reason in {
                    "RATE_LIMITED", "AMBIGUOUS", "BLOCKED", "ACCEPTED"
                }
                and new.active_run_id == old.active_run_id
                and new.active_memory_gb == old.active_memory_gb
            )
        else:
            good = False
    else:
        good = False
    if not good:
        raise TransportUnavailable("github_v2_transition_forbidden")


@dataclass(repr=False)
class GitHubV2CASStore(GitHubCASStore):
    """Explicit v2-only CAS store with fail-closed read/transition checks.

    This object is never constructed by any existing Actions workflow.
    """

    def _validate_proposed_record(self, new_record: bytes) -> None:
        v2.decode(new_record)

    def read(self) -> tuple[str, bytes]:
        try:
            snapshot, raw = inspector.read_snapshot(
                _RestrictedGET(self.transport)
            )
            if snapshot.version != 2:
                raise ValueError("v1 requires separately approved migration")
            return snapshot.revision, raw
        except Exception:
            raise TransportUnavailable("github_v2_read_unavailable") from None

    def cas(self, expected_revision: str, new_record: bytes) -> bool:
        """No POST before validating current immutable v2 + exact transition.

        After initial validation, real concurrent ref updates can still occur.
        GitHub's exact beforeOid CAS rejects the stale revision; never retry
        after ambiguous responses. No automatic rearm or v1->v2 upgrade.
        """
        try:
            expected = self._sha(expected_revision)
            proposed = v2.decode(new_record)
            current_head, original = self.read()
            if current_head != expected:
                raise ValueError("stale CAS parent")
            previous = v2.decode(original)
            validate_transition(previous, proposed)
        except Exception:
            raise TransportUnavailable("github_v2_cas_preflight_blocked") from None
        # The parent implementation validates via _validate_proposed_record,
        # creates immutable objects, then uses updateRefs(beforeOid=expected)
        # EXACTLY ONCE. No retry, even after rate-limits or timeout.
        return super().cas(expected, new_record)
