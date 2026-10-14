"""Single-execution, OCI-FREE *candidate* migration of the known v1 fence.

NOT WIRED TO A PRODUCTION SCHEDULE. DO NOT RUN ON THE LIVE LEDGER UNTIL THE
OPERATOR REVIEWS THE UNMERGED PR, MERGES TRUSTED MAIN, AND EXPLICITLY APPROVES
ONE workflow_dispatch. One acknowledged exact-beforeOid GitHub mutation only.
No retries on errors or uncertain acknowledgement; no OCI SDK, IAM or secrets.
"""
from __future__ import annotations

import os
import re

from automation import fence_migration_preview as proposal
from automation import fence_rules_audit as rules
from automation import fence_watermark_v2 as v2
from automation import github_fence_readonly as read
from automation.github_fence_store import (
    GitHubHttpTransport, _GRAPHQL, TransportUnavailable,
)

REPO = read.REPO
ROOT = read.ROOT
CURRENT_TIP = proposal.EXPECTED_TIP
REF = read.REF
MAIN_RULE_ID = 25036918
STATE_RULE_ID = 25080078
CONFIRM = "MIGRATE-APPROVED-V1-OPEN-TO-V2-ONCE"
MESSAGE = "fence: one-time approved v1 OPEN/INITIAL to v2 schema transition"
RUN_ID_PATTERN = re.compile(r"[1-9][0-9]{0,19}\Z")


class MigrationBlocked(Exception):
    """Fail closed with a constant, non-secret reason code."""


def require(ok: object, message: str) -> None:
    if not ok:
        raise MigrationBlocked(message)


class Api:
    """Adapter without a retry facility. Mutations remain allowlisted by HTTP."""

    def __init__(self, transport):
        self.transport = transport

    def get(self, path: str) -> dict:
        return self.transport.request("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self.transport.request("POST", path, body)


def sha(value: object) -> str:
    require(isinstance(value, str) and read.SHA_RE.fullmatch(value) is not None,
            "INVALID_SHA")
    return value


def ref(api: Api, branch: str) -> str:
    obj = api.get(ROOT + "/git/ref/heads/" + branch)
    require(type(obj) is dict and obj.get("ref") == "refs/heads/" + branch,
            "WRONG_REF")
    val = obj.get("object")
    require(type(val) is dict and val.get("type") == "commit", "WRONG_REF_TYPE")
    return sha(val.get("sha"))


def validate_invocation(env: dict[str, str]) -> str:
    """Dual human confirmation + trusted first-attempt main-only run."""
    require(env.get("GITHUB_REPOSITORY") == REPO
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_REF_PROTECTED") == "true"
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("GITHUB_ACTOR") == "vasenko1"
            and env.get("MIGRATION_CONFIRM") == CONFIRM
            and env.get("MIGRATION_EXPECTED_OLD_HEAD") == CURRENT_TIP
            and RUN_ID_PATTERN.fullmatch(env.get("GITHUB_RUN_ID", "")) is not None,
            "UNTRUSTED_MIGRATION_INVOCATION")
    return sha(env.get("GITHUB_SHA"))


def verify_protection(
    api: Api, main_expected: str, expected_state: str = CURRENT_TIP,
) -> str:
    """Exact same-repository ruleset policy, not just protected=true."""
    repo = api.get(ROOT)
    require(type(repo) is dict and repo.get("full_name") == REPO
            and isinstance(repo.get("node_id"), str)
            and bool(repo["node_id"]), "REPOSITORY_IDENTITY_MISMATCH")
    for branch in ("main", "oci-fence-state"):
        info = api.get(ROOT + "/branches/" + branch)
        require(type(info) is dict and info.get("name") == branch
                and info.get("protected") is True,
                "BRANCH_PROTECTION_MISSING")
    require(ref(api, "main") == main_expected, "MAIN_COMMIT_CHANGED")
    index = api.get(ROOT + "/rulesets")
    require(type(index) is list
            and len(index) == 2
            and all(type(row) is dict and type(row.get("id")) is int
                    for row in index)
            and sorted(row["id"] for row in index)
                == sorted((MAIN_RULE_ID, STATE_RULE_ID)),
            "UNKNOWN_REPOSITORY_RULESETS")
    full = []
    for rule_id in (MAIN_RULE_ID, STATE_RULE_ID):
        row = api.get(ROOT + "/rulesets/" + str(rule_id))
        require(type(row) is dict and type(row.get("id")) is int
                and row["id"] == rule_id, "RULESET_ID_MISMATCH")
        full.append(row)
    try:
        rules.require_main_and_state_protected(
            full, state_exists=True, main_sha=main_expected,
            state_root_verified=True,
        )
    except rules.ProtectionBlocked:
        raise MigrationBlocked("REQUIRED_RULES_MISSING") from None
    by_id = {row["id"]: row for row in full}
    state_types = {v.get("type") for v in by_id[STATE_RULE_ID]["rules"]}
    require(state_types == {
        "deletion", "non_fast_forward", "required_linear_history"
    }, "STATE_RULES_CHANGED")
    main_types = {v.get("type") for v in by_id[MAIN_RULE_ID]["rules"]}
    require(main_types == {
        "deletion", "non_fast_forward", "pull_request",
        "required_status_checks",
    }, "MAIN_RULES_CHANGED")
    checks = next(
        r for r in by_id[MAIN_RULE_ID]["rules"]
        if r["type"] == "required_status_checks"
    )
    parameters = checks.get("parameters")
    require(type(parameters) is dict
            and parameters.get("strict_required_status_checks_policy") is True
            and type(parameters.get("required_status_checks")) is list
            and any(type(check) is dict
                    and check.get("context") == "public-audit-tests"
                    for check in parameters["required_status_checks"]),
            "MAIN_STATUS_POLICY_CHANGED")
    require(ref(api, "oci-fence-state") == expected_state,
            "FENCE_HEAD_CHANGED")
    return repo["node_id"]


def verify_tree(api: Api, tree_sha: str, blob_sha: str, size: int) -> None:
    tree = api.get(ROOT + "/git/trees/" + sha(tree_sha))
    require(type(tree) is dict and tree.get("sha") == tree_sha
            and tree.get("truncated") is False
            and type(tree.get("tree")) is list
            and len(tree["tree"]) == 1, "BAD_PROPOSED_TREE")
    item = tree["tree"][0]
    require(type(item) is dict and
            item.get("path") == read.PATH and
            item.get("type") == "blob" and
            item.get("mode") == "100644" and
            item.get("sha") == blob_sha and
            type(item.get("size")) is int and
            item["size"] == size, "BAD_PROPOSED_TREE")


def run_migration(api: Api, env: dict[str, str]) -> str:
    expected_main = validate_invocation(env)
    # First make the complete GET-only ancestry and byte-level v1 preview.
    # No write-capable operation is permitted before BOTH independent gates.
    item = proposal.preview(api)
    require(item.before_oid == CURRENT_TIP and
            item.before_blob_oid == read.ORIGINAL_BLOB,
            "UNEXPECTED_OLD_DOCUMENT")
    repo_id = verify_protection(api, expected_main)
    candidate = item.candidate_bytes
    converted = v2.decode(candidate)
    require(converted.phase == "OPEN" and converted.reason == "INITIAL"
            and converted.highest_spent_run_id is None
            and converted.claims_committed == 0
            and item.after_blob_oid != item.before_blob_oid,
            "WRONG_V2_MIGRATION_PROPOSAL")
    require(ref(api, "oci-fence-state") == CURRENT_TIP,
            "FENCE_MOVED_BEFORE_CREATE")

    # Create immutable objects, not a ref update. Every GitHub response is
    # untrusted until checked. Never assume a failed or lost reply is safe to
    # retry, even if only part of the sequence completed.
    blob = api.post(ROOT + "/git/blobs", {
        "content": candidate.decode("ascii"), "encoding": "utf-8",
    })
    require(type(blob) is dict and
            blob.get("sha") == item.after_blob_oid,
            "PROPOSED_BLOB_NOT_CONFIRMED")
    tree = api.post(ROOT + "/git/trees", {
        "base_tree": read.ORIGINAL_TREE,
        "tree": [{"path": read.PATH, "mode": "100644",
                  "type": "blob", "sha": item.after_blob_oid}],
    })
    require(type(tree) is dict, "TREE_CREATE_UNCONFIRMED")
    tree_oid = sha(tree.get("sha"))
    require(tree_oid != read.ORIGINAL_TREE, "TREE_NOT_UPDATED")
    verify_tree(api, tree_oid, item.after_blob_oid, len(candidate))

    creation = api.post(ROOT + "/git/commits", {
        "message": MESSAGE, "tree": tree_oid,
        "parents": [CURRENT_TIP],
    })
    require(type(creation) is dict, "COMMIT_CREATE_UNCONFIRMED")
    next_oid = sha(creation.get("sha"))
    commit = api.get(ROOT + "/git/commits/" + next_oid)
    require(type(commit) is dict and commit.get("sha") == next_oid and
            commit.get("message") == MESSAGE and
            type(commit.get("tree")) is dict and
            commit["tree"].get("sha") == tree_oid and
            type(commit.get("parents")) is list and
            len(commit["parents"]) == 1 and
            type(commit["parents"][0]) is dict and
            commit["parents"][0].get("sha") == CURRENT_TIP,
            "COMMIT_NOT_LINEAR")
    require(ref(api, "oci-fence-state") == CURRENT_TIP,
            "REF_MOVED_BEFORE_CAS")

    # EXACTLY ONE conditional GraphQL ref update. There is NO retry path.
    mutation_id = "approved-oci-fence-v1-v2-once-" + env["GITHUB_RUN_ID"]
    result = api.post("/graphql", {
        "query": _GRAPHQL,
        "variables": {"input": {
            "repositoryId": repo_id,
            "clientMutationId": mutation_id,
            "refUpdates": [{
                "name": REF, "beforeOid": CURRENT_TIP,
                "afterOid": next_oid, "force": False,
            }],
        }},
    })
    require(type(result) is dict and
            type(result.get("data")) is dict and
            type(result["data"].get("updateRefs")) is dict and
            result["data"]["updateRefs"].get("clientMutationId")
                == mutation_id, "CAS_ACK_UNCONFIRMED")

    # Postcondition checks are mandatory; a lost ACK/failed postread can mean
    # the ref has ALREADY MOVED. Never roll it back or repeat the mutation.
    require(ref(api, "oci-fence-state") == next_oid,
            "POST_CAS_HEAD_UNCONFIRMED")
    record, returned = read.read_snapshot(api, next_oid)
    require(record.revision == next_oid and
            record.version == 2 and record.phase == "OPEN" and
            record.reason == "INITIAL" and
            record.tree == tree_oid and
            record.blob == item.after_blob_oid and
            returned == candidate, "POST_CAS_DOCUMENT_UNCONFIRMED")
    require(ref(api, "main") == expected_main,
            "POST_CAS_MAIN_CHANGED")
    # Branch policy can change between checks; detect it rather than
    # pretending to undo an already committed update.
    verify_protection(api, expected_main, next_oid)
    return next_oid



def main() -> None:
    api = Api(GitHubHttpTransport(os.environ.get("GH_TOKEN", "")))
    # No tokens, HTTP payloads, traceback or input material are printed.
    try:
        new_oid = run_migration(api, dict(os.environ))
        print("MIGRATION_OK: exact one-time protected v1-to-v2 CAS confirmed.")
        print("MIGRATION_NEW_HEAD: " + new_oid)
        print("MIGRATION_NEW_SCHEMA: 2; contents: OPEN/INITIAL; no OCI calls.")
    except (MigrationBlocked, read.AuditRejected,
            TransportUnavailable, v2.FenceBlocked) as exc:
        print("MIGRATION_BLOCKED: " + exc.__class__.__name__)
        print("No retry. Independently inspect HEAD and canonical ledger.")
        raise SystemExit(1) from None
    except Exception:
        print("MIGRATION_BLOCKED: UNCLASSIFIED_FAILURE")
        print("No retry. Independently inspect HEAD and canonical ledger.")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
