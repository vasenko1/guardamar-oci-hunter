"""Closed-set OCI error classification with no external message disclosure.

This module neither imports OCI nor issues requests. Provider messages are
used internally only for a narrow, pre-approved status classification.
"""
from __future__ import annotations


def classify_oci_failure(exc: BaseException) -> str:
    """Return only RATE_LIMITED, CAPACITY_MISS, BLOCKED, or AMBIGUOUS."""
    try:
        status = getattr(exc, "status", None)
        code = str(getattr(exc, "code", "") or "").casefold()
        message = str(getattr(exc, "message", exc)).casefold()
    except Exception:
        return "AMBIGUOUS"

    # Always give 429 precedence even when OCI's description also includes
    # 'Out of host capacity'. Never retry a rate-limited call.
    if status == 429 or code == "toomanyrequests":
        return "RATE_LIMITED"
    # Explicit 4xx denials (including IAM 401/403) must never be mistaken
    # for a benign host-capacity miss because of provider message contents.
    if type(status) is int and 400 <= status < 500:
        return "BLOCKED"
    if "outofhostcapacity" in code or "out of host capacity" in message:
        return "CAPACITY_MISS"
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return "BLOCKED"
    return "AMBIGUOUS"
