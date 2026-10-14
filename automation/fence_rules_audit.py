"""Offline verification of repository rule-policy *descriptions*.

No API client, token, OCI SDK, or mutation. GitHub's active ruleset API data
must be supplied by a separate read-only discovery step; this module alone
does NOT test the effective permission of a future GITHUB_TOKEN.

A ruleset with status 'evaluate' or 'disabled', unknown bypass principals,
wildcard branch patterns, or missing deletion/fast-forward restriction cannot
be treated as equivalent to a narrowly targeted active protection rule.
"""
from __future__ import annotations

from typing import Mapping, Sequence

SOURCE_REPO = "vasenko1/guardamar-oci-hunter"
STATE_REF = "refs/heads/oci-fence-state"
MAIN_REF = "refs/heads/main"


class ProtectionBlocked(ValueError):
    """Expected policy not evidenced. Never include GitHub payload contents."""


def _trusted_ruleset(
    entry: Mapping[str, object], ref: str,
) -> set[str]:
    if not isinstance(entry, Mapping):
        return set()
    if (entry.get("target") != "branch" or entry.get("enforcement") != "active"
            or entry.get("source") != SOURCE_REPO
            or entry.get("source_type") != "Repository"
            or entry.get("bypass_actors") != []
            or entry.get("current_user_can_bypass") not in ("never", None)):
        return set()

    conditions = entry.get("conditions")
    if not isinstance(conditions, dict):
        return set()
    names = conditions.get("ref_name")
    if not isinstance(names, dict):
        return set()
    # Narrow scope, not a wildcard or an inherited/ambiguous ref matcher.
    if names.get("include") != [ref] or names.get("exclude") != []:
        return set()

    rules = entry.get("rules")
    if not isinstance(rules, list):
        return set()
    result: set[str] = set()
    for row in rules:
        if not isinstance(row, dict) or not isinstance(row.get("type"), str):
            return set()
        result.add(row["type"])
    return result


def require_main_and_state_protected(
    rulesets: Sequence[Mapping[str, object]],
    *,
    state_exists: bool,
    main_sha: str,
    state_root_verified: bool,
) -> None:
    """Fail closed unless source/main and independently rooted state are safe.

    Intended as a preflight *part* of a future privileged runner, not
    permission to do any OCI mutation. The caller separately must prove the
    state root really has no parent, contains only the fixed ledger, and
    that the most recent state tip descends from the approved genesis.
    """
    if type(state_exists) is not bool or not state_exists:
        raise ProtectionBlocked("state_branch_missing")
    if type(state_root_verified) is not bool or not state_root_verified:
        raise ProtectionBlocked("state_root_not_verified")
    if (not isinstance(main_sha, str) or len(main_sha) != 40
            or any(c not in "0123456789abcdef" for c in main_sha)):
        raise ProtectionBlocked("main_identity_not_verified")
    if (not isinstance(rulesets, (list, tuple))
            or not rulesets or len(rulesets) > 100):
        raise ProtectionBlocked("ruleset_list_unavailable")

    def match(ref: str) -> set[str]:
        # More than one exact matching ruleset is ambiguous because GitHub
        # applies aggregate rules and a future App may need bypass to write.
        applicable = [
            rules for entry in rulesets
            if (rules := _trusted_ruleset(entry, ref))
        ]
        if len(applicable) != 1:
            raise ProtectionBlocked("expected_exact_ruleset_not_found")
        return applicable[0]

    main = match(MAIN_REF)
    if not {"deletion", "non_fast_forward", "pull_request",
            "required_status_checks"} <= main:
        raise ProtectionBlocked("main_not_safely_protected")

    state = match(STATE_REF)
    if not {"deletion", "non_fast_forward"} <= state:
        raise ProtectionBlocked("fence_ref_not_append_only")
    if {"pull_request", "required_status_checks", "update",
        "merge_queue", "creation"} & state:
        raise ProtectionBlocked("fence_ref_cannot_be_automatically_updated")
