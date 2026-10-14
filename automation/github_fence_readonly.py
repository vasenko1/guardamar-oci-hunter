"""Read-only, version-aware protected GitHub fence verifier (NO write methods).

May be used in an unprivileged PR test job with GITHUB_TOKEN contents:read.
Can recognize canonical v1 and v2 state; intentionally cannot migrate, claim,
settle, create commits or grant any OCI permission. The external Git history
and writer authorization require separate independent auditing.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import urllib.request

from . import durable_fence as v1
from . import fence_watermark_v2 as v2

REPO = "vasenko1/guardamar-oci-hunter"
ROOT = "/repos/" + REPO
REF = "refs/heads/oci-fence-state"
PATH = "fence-record.json"
GENESIS = "650c36d7a2937efc56868bacc3d3acc5c2559e69"
TEST_WINNER = "ed78b480980cdfd03841349ac0164d92c66a9add"
ORIGINAL_TREE = "5198c8cead35679615df2ec450e55263f5231fa3"
ORIGINAL_BLOB = "295d46ae14f8ebff248507e4a4465306dfd9bef6"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
MAX_RESPONSE = 1_000_000


class AuditRejected(Exception):
    """Sanitized hard failure: never infer a write permission from an audit."""


def require(test: object, code: str) -> None:
    if not test:
        raise AuditRejected(code)


def sha(value: object) -> str:
    require(isinstance(value, str) and bool(SHA_RE.fullmatch(value)), "BAD_SHA")
    return value


@dataclass(repr=False)
class ReadOnlyHttp:
    token: str = field(repr=False)
    timeout: int = 12

    def get(self, path: str) -> dict:
        require(isinstance(self.token, str) and len(self.token) >= 10, "NO_READ_TOKEN")
        # Explicit GET-only routes. No generic method, no GraphQL mutation,
        # no POST Git-object creation or permissions escalation.
        commit_read = bool(re.fullmatch(
            re.escape(ROOT) + r"/git/commits/[0-9a-f]{40}", path))
        tree_read = bool(re.fullmatch(
            re.escape(ROOT) + r"/git/trees/[0-9a-f]{40}", path))
        file_read = bool(re.fullmatch(
            re.escape(ROOT) +
            r"/contents/fence-record[.]json[?]ref=[0-9a-f]{40}", path))
        allow = (path in {
            ROOT, ROOT + "/git/ref/heads/oci-fence-state",
            ROOT + "/branches/oci-fence-state",
        } or commit_read or tree_read or file_read)
        require(allow and ".." not in path and "://" not in path
                and "//" not in path, "AUDIT_PATH_DENIED")
        request = urllib.request.Request(
            "https://api.github.com" + path,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.token,
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "oci-fence-readonly-inspector",
            })

        class DenyRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        try:
            with urllib.request.build_opener(DenyRedirect()).open(
                request, timeout=self.timeout,
            ) as response:
                require(response.status == 200, "GITHUB_GET_FAILED")
                wire = response.read(MAX_RESPONSE + 1)
            require(len(wire) <= MAX_RESPONSE, "GITHUB_RESPONSE_OVERSIZE")
            obj = json.loads(wire.decode("utf-8"))
            require(type(obj) is dict and "errors" not in obj, "GITHUB_BAD_REPLY")
            # Git commit's 'message' is legitimate, but message-only errors
            # on other endpoints must never pass for a successful response.
            if "message" in obj:
                require(commit_read and
                        isinstance(obj.get("message"), str) and
                        SHA_RE.fullmatch(str(obj.get("sha", ""))) is not None and
                        type(obj.get("tree")) is dict and
                        type(obj.get("parents")) is list, "GITHUB_BAD_REPLY")
            return obj
        except (OSError, ValueError, UnicodeError, TimeoutError):
            raise AuditRejected("GITHUB_READ_UNAVAILABLE") from None


def decode_version(raw: bytes) -> tuple[int, v1.FenceRecord | v2.WatermarkRecord]:
    """Reject noncanonical or duplicate-key JSON; explicitly choose schema."""
    require(type(raw) is bytes and 0 < len(raw) <= 400_000, "INVALID_LEDGER_BYTES")
    try:
        obj = json.loads(raw.decode("ascii"), object_pairs_hook=v1._unique_pairs)
        require(type(obj) is dict and type(obj.get("version")) is int,
                "UNSUPPORTED_LEDGER_VERSION")
        version = obj["version"]
        if version == 1:
            record = v1.decode(raw)
            require(v1.encode(record) == raw, "NONCANONICAL_V1")
        elif version == 2:
            record = v2.decode(raw)
            require(v2.encode(record) == raw, "NONCANONICAL_V2")
        else:
            raise AuditRejected("UNSUPPORTED_LEDGER_VERSION")
        return version, record
    except (ValueError, TypeError, UnicodeError, v1.FenceBlocked):
        raise AuditRejected("UNVERIFIED_LEDGER") from None


@dataclass(frozen=True)
class Inspection:
    revision: str
    version: int
    phase: str
    reason: str
    tree: str
    blob: str


def read_snapshot(api: ReadOnlyHttp, expected_head: str | None = None
                  ) -> tuple[Inspection, bytes]:
    """Verify read-only immutable content and return validated bytes.

    A caller MUST NOT interpret this read as authorization to write; a
    subsequent CAS still needs its exact original revision in beforeOid.
    """
    if expected_head is not None:
        sha(expected_head)
    repo = api.get(ROOT)
    require(repo.get("full_name") == REPO, "WRONG_REPOSITORY")
    branch = api.get(ROOT + "/branches/oci-fence-state")
    require(branch.get("name") == "oci-fence-state" and
            branch.get("protected") is True, "UNPROTECTED_FENCE")

    def head() -> str:
        result = api.get(ROOT + "/git/ref/heads/oci-fence-state")
        require(result.get("ref") == REF, "INCORRECT_FENCE_REF")
        obj = result.get("object")
        require(type(obj) is dict and obj.get("type") == "commit",
                "INCORRECT_FENCE_OBJECT")
        return sha(obj.get("sha"))

    commit_sha = head()
    if expected_head is not None:
        require(commit_sha == expected_head, "UNEXPECTED_FENCE_HEAD")
    commit = api.get(ROOT + "/git/commits/" + commit_sha)
    require(commit.get("sha") == commit_sha, "COMMIT_ID_MISMATCH")
    parents = commit.get("parents")
    require(type(parents) is list and len(parents) == (0 if commit_sha == GENESIS else 1),
            "UNEXPECTED_COMMIT_PARENT_COUNT")
    if len(parents) == 1:
        require(type(parents[0]) is dict and
                SHA_RE.fullmatch(str(parents[0].get("sha", ""))) is not None,
                "BAD_PARENT")
    t = commit.get("tree")
    require(type(t) is dict, "MISSING_TREE")
    tree_sha = sha(t.get("sha"))
    tree = api.get(ROOT + "/git/trees/" + tree_sha)
    require(tree.get("sha") == tree_sha and tree.get("truncated") is False
            and type(tree.get("tree")) is list and len(tree["tree"]) == 1,
            "UNEXPECTED_TREE")
    entry = tree["tree"][0]
    require(type(entry) is dict and entry.get("path") == PATH and
            entry.get("mode") == "100644" and entry.get("type") == "blob" and
            type(entry.get("size")) is int and 0 < entry["size"] <= 400_000,
            "UNEXPECTED_LEDGER_FILE")
    blob_sha = sha(entry.get("sha"))
    file = api.get(ROOT + "/contents/" + PATH + "?ref=" + commit_sha)
    require(file.get("type") == "file" and file.get("path") == PATH and
            file.get("encoding") == "base64" and file.get("sha") == blob_sha and
            type(file.get("content")) is str, "UNEXPECTED_LEDGER_CONTENT")
    try:
        payload = base64.b64decode(
            "".join(file["content"].split()), validate=True)
    except (ValueError, binascii.Error):
        raise AuditRejected("LEDGER_BASE64_REJECTED") from None
    require(len(payload) == entry["size"], "LEDGER_SIZE_MISMATCH")
    digest = hashlib.sha1(
        ("blob " + str(len(payload)) + "\0").encode("ascii") + payload
    ).hexdigest()
    require(digest == blob_sha, "LEDGER_BLOB_HASH_MISMATCH")
    version, record = decode_version(payload)
    require(head() == commit_sha, "STATE_MOVED_DURING_READ")
    return (Inspection(commit_sha, version, record.phase, record.reason,
                       tree_sha, blob_sha), payload)


def read(api: ReadOnlyHttp, expected_head: str | None = None) -> Inspection:
    """Preserve original non-mutating inspection interface."""
    return read_snapshot(api, expected_head)[0]


def live_smoke_current() -> None:
    """Intentionally one version-pinned no-write public state observation."""
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and
            os.environ.get("GITHUB_EVENT_NAME") == "pull_request" and
            os.environ.get("GITHUB_BASE_REF") == "main" and
            os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
            "NOT_A_READONLY_PR_PROBE")
    result = read(ReadOnlyHttp(os.environ.get("GH_TOKEN", "")), TEST_WINNER)
    require(result.version == 1 and result.phase == "OPEN" and
            result.reason == "INITIAL" and
            result.tree == ORIGINAL_TREE and
            result.blob == ORIGINAL_BLOB, "CURRENT_GENESIS_MISMATCH")
    # Data output is deliberately limited to one non-sensitive status line.
    print("READ_ONLY_OK: protected existing fence at approved v1 no-op revision")


if __name__ == "__main__":
    try:
        live_smoke_current()
    except Exception as exc:
        label = str(exc) if isinstance(exc, AuditRejected) else "UNKNOWN_READ_FAILURE"
        print("READ_ONLY_BLOCKED: " + label)
        raise SystemExit(1) from None
