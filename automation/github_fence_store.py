"""GitHub exact-before-OID CAS backend; UNWIRED from all workflows.

No OCI client or launch functionality exists in this module. Using this in
production requires a separately approved dedicated state repository, a GitHub
write principal scoped only to that repository, a protected state ref, an
initialized ledger and live authorization/cutover review.
GraphQL updateRefs(beforeOid=...) is the atomic server-side primitive.
REST git update-reference with force=false is NOT an exact compare-and-swap.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from .durable_fence import MAX_JOURNAL_SIZE, FenceBlocked, decode

REPO = "vasenko1/guardamar-oci-fence"
FENCE_REF = "refs/heads/oci-fence-state"
FENCE_PATH = "fence-record.json"
SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
MAX_REPLY_BYTES = 1_000_000
_GRAPHQL = """mutation CAS($input: UpdateRefsInput!) {
  updateRefs(input: $input) { clientMutationId }
}"""


class TransportUnavailable(Exception):
    """Provider failure or uncertain write acknowledgment; never authorize OCI."""


class JsonTransport(Protocol):
    def request(self, method: str, path: str, payload: dict | None = None) -> dict: ...


@dataclass(repr=False)
class GitHubHttpTransport:
    """Explicit-only HTTP transport; no credential in repr, logs or exceptions.

    DO NOT instantiate from an OCI audit/PR workflow. It requires a separately
    restricted token for a future protected state branch; it is not configured.
    """

    access_token: str = field(repr=False)
    timeout: int = 10

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        if not isinstance(self.access_token, str) or len(self.access_token) < 10:
            raise TransportUnavailable("github_authorization_unavailable")
        if method not in ("GET", "POST") or not path.startswith("/"):
            raise TransportUnavailable("github_operation_disallowed")
        if path.startswith("//") or "://" in path or ".." in path:
            raise TransportUnavailable("github_operation_disallowed")
        if not (path.startswith("/repos/" + REPO + "/")
                or path == "/graphql"):
            raise TransportUnavailable("github_operation_disallowed")
        wire = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None else None
        )
        request = urllib.request.Request(
            "https://api.github.com" + path,
            data=wire,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.access_token,
                "X-GitHub-Api-Version": "2026-03-10",
                "Content-Type": "application/json",
                "User-Agent": "guardamar-offline-fence-candidate",
            },
        )

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        try:
            with urllib.request.build_opener(NoRedirect()).open(
                request, timeout=self.timeout
            ) as response:
                status = response.status
                content = response.read(MAX_REPLY_BYTES + 1)
        except (OSError, ValueError, TimeoutError):
            raise TransportUnavailable("github_request_unconfirmed") from None
        if status not in (200, 201) or len(content) > MAX_REPLY_BYTES:
            raise TransportUnavailable("github_reply_unusable")
        try:
            result = json.loads(content.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise TransportUnavailable("github_reply_unusable") from None
        if type(result) is not dict:
            raise TransportUnavailable("github_reply_unusable")
        # Do not return raw GitHub error payloads: they may contain identifiers.
        if "errors" in result or "message" in result:
            raise TransportUnavailable("github_request_not_confirmed")
        return result


@dataclass(repr=False)
class GitHubCASStore:
    """Storage adapter with zero automatic retries, using exact GraphQL CAS.

    Before any call to claim() the user must have independently initialized
    the state branch and its fence-record.json. This class cannot initialize,
    repair, reset, prune or delete an existing record/ref.
    """

    transport: JsonTransport

    def _verified_repository_id(self) -> str:
        """Resolve GraphQL identity only from the fixed future state repo."""
        try:
            details = self.transport.request("GET", "/repos/" + REPO)
            if not isinstance(details, dict) or details.get("full_name") != REPO:
                raise ValueError("unexpected repository")
            node_id = details.get("node_id")
            if not isinstance(node_id, str) or not node_id:
                raise ValueError("missing GraphQL repository identity")
            return node_id
        except Exception:
            raise TransportUnavailable("github_repository_identity_unavailable") from None

    @staticmethod
    def _sha(value: Any) -> str:
        if not isinstance(value, str) or not SHA1_RE.fullmatch(value):
            raise TransportUnavailable("github_revision_invalid")
        return value

    @staticmethod
    def _field(response: Any, key: str) -> dict:
        if type(response) is not dict or type(response.get(key)) is not dict:
            raise TransportUnavailable("github_reply_unusable")
        return response[key]

    def _ref_tip(self) -> str:
        try:
            data = self.transport.request(
                "GET", "/repos/" + REPO + "/git/ref/" + FENCE_REF.removeprefix("refs/")
            )
            return self._sha(self._field(data, "object").get("sha"))
        except Exception:
            raise TransportUnavailable("github_fence_ref_unavailable") from None

    def read(self) -> tuple[str, bytes]:
        """Read immutable ledger bytes at a specific verified Git commit."""
        head = self._ref_tip()
        try:
            path = ("/repos/" + REPO + "/contents/" + FENCE_PATH
                    + "?ref=" + head)
            entry = self.transport.request("GET", path)
            if (entry.get("type") != "file"
                    or entry.get("path") != FENCE_PATH
                    or entry.get("encoding") != "base64"):
                raise ValueError("invalid file")
            encoded = entry["content"]
            if not isinstance(encoded, str):
                raise ValueError("bad content")
            raw = base64.b64decode(encoded, validate=False)
            if len(raw) > 400_000:
                raise ValueError("oversize")
            decode(raw)  # validate before any caller can ever trust the ledger
            return head, raw
        except Exception:
            raise TransportUnavailable("github_fence_read_unavailable") from None

    def cas(self, expected_revision: str, new_record: bytes) -> bool:
        """Publish a new single-parent commit with exact beforeOid compare.

        DO NOT retry on failures, not even for 429/5xx. If GitHub committed
        but the acknowledgment was lost, caller must fail closed.
        """
        parent = self._sha(expected_revision)
        try:
            decode(new_record)
            if type(new_record) is not bytes or len(new_record) > 400_000:
                raise ValueError("invalid proposed document")

            prefix = "/repos/" + REPO + "/git/"
            current = self.transport.request("GET", prefix + "commits/" + parent)
            tree_sha = self._sha(self._field(current, "tree").get("sha"))
            blob = self.transport.request("POST", prefix + "blobs", {
                "content": new_record.decode("ascii"),
                "encoding": "utf-8",
            })
            blob_sha = self._sha(blob.get("sha"))
            tree = self.transport.request("POST", prefix + "trees", {
                "base_tree": tree_sha,
                "tree": [{
                    "path": FENCE_PATH,
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_sha,
                }],
            })
            new_tree = self._sha(tree.get("sha"))
            commit = self.transport.request("POST", prefix + "commits", {
                "message": "fence: append one durable state transition",
                "tree": new_tree,
                "parents": [parent],
            })
            next_sha = self._sha(commit.get("sha"))
            # GitHub GraphQL documentation explicitly specifies beforeOid.
            # REST refs PATCH force:false only checks fast-forward ancestry.
            payload = {
                "query": _GRAPHQL,
                "variables": {
                    "input": {
                        "repositoryId": self._verified_repository_id(),
                        "clientMutationId": "oci-fence-no-retry",
                        "refUpdates": [{
                            "name": FENCE_REF,
                            "beforeOid": parent,
                            "afterOid": next_sha,
                            "force": False,
                        }],
                    },
                },
            }
            answer = self.transport.request("POST", "/graphql", payload)
            result = self._field(answer, "data")
            ack = self._field(result, "updateRefs").get("clientMutationId")
            if ack != "oci-fence-no-retry":
                raise TransportUnavailable("github_cas_ack_unconfirmed")
            return True
        except Exception:
            # Conflicts, GitHub GraphQL errors and transport outages all
            # produce a fail-closed unknown outcome, *not* a new write grant.
            raise TransportUnavailable("github_cas_commit_unconfirmed") from None
