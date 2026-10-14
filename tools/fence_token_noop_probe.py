"""One-shot, OCI-free, content-preserving protected-branch GITHUB_TOKEN CAS probe.

This is an experiment only. It is NOT a production fence writer. On successful
manual invocation it appends exactly one commit with the original tree to the
already protected independent oci-fence-state branch. The ledger bytes stay
unchanged. Two simultaneous contenders use exact GraphQL beforeOid CAS.
Never retry an ambiguous mutation or re-arm an existing state.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import threading
import urllib.error
import urllib.request

REPO = "vasenko1/guardamar-oci-hunter"
REF = "refs/heads/oci-fence-state"
ROOT = "650c36d7a2937efc56868bacc3d3acc5c2559e69"
ROOT_TREE = "5198c8cead35679615df2ec450e55263f5231fa3"
ROOT_BLOB = "295d46ae14f8ebff248507e4a4465306dfd9bef6"
CANONICAL = (b'{"active_memory_gb":null,"active_run_id":null,'
             b'"phase":"OPEN","reason":"INITIAL","spent_run_ids":[],"version":1}')
CONFIRM = "APPEND-ONE-NOOP-COMMIT"
API_ROOT = "/repos/" + REPO
SHA = re.compile(r"[0-9a-f]{40}\Z")
NUMERIC = re.compile(r"[1-9][0-9]{0,19}\Z")
GRAPHQL = ("mutation CAS($input:UpdateRefsInput!){"
           "updateRefs(input:$input){clientMutationId}}")
CLIENT_ID = "fence-token-noop-probe-v1"


class ProbeBlocked(Exception):
    """Never authorize a replay, a retry, or any OCI operation."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ProbeBlocked(code)


def sha(value: object) -> str:
    require(isinstance(value, str) and SHA.fullmatch(value) is not None,
            "INVALID_SHA")
    return value


class Api:
    def __init__(self, token: str):
        require(isinstance(token, str) and len(token) >= 10, "NO_JOB_TOKEN")
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        # Strictly pin the API to this repo, two source/state ref reads,
        # immutable Git objects, the one ledger and one GraphQL CAS endpoint.
        # A repository-wide write token is NOT a branch-scoped credential.
        commit_object = (
            method == "GET" and
            re.fullmatch(re.escape(API_ROOT) + r"/git/commits/[0-9a-f]{40}",
                         path) is not None
        )
        commit_create = method == "POST" and path == API_ROOT + "/git/commits"
        ledger_read = (
            method == "GET" and
            re.fullmatch(re.escape(API_ROOT) +
                         r"/contents/fence-record[.]json[?]ref=[0-9a-f]{40}",
                         path) is not None
        )
        allowed_read = method == "GET" and (
            path == API_ROOT or
            path == API_ROOT + "/branches/oci-fence-state" or
            path in {API_ROOT + "/git/ref/heads/main",
                     API_ROOT + "/git/ref/heads/oci-fence-state",
                     API_ROOT + "/git/trees/" + ROOT_TREE} or
            commit_object or ledger_read
        )
        require(allowed_read or commit_create or
                (method == "POST" and path == "/graphql"),
                "DISALLOWED_ENDPOINT")
        require(".." not in path and "://" not in path and "//" not in path,
                "DISALLOWED_ENDPOINT")
        wire = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            "https://api.github.com" + path,
            data=wire,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
                "User-Agent": "guardamar-fence-token-noop-probe",
            },
        )

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        try:
            with urllib.request.build_opener(NoRedirect()).open(req, timeout=15) as res:
                require(res.status in (200, 201), "API_HTTP_FAILURE")
                raw = res.read(1_000_001)
            require(len(raw) <= 1_000_000, "API_OVERSIZE")
            obj = json.loads(raw.decode("utf-8"))
            require(type(obj) is dict and "errors" not in obj,
                    "API_REJECTED")
            # GitHub's successful GET/POST Git commit objects contain
            # 'message' as their actual commit message. In other endpoint
            # families a top-level 'message' indicates an API error.
            # Do not let an error-only {"message": "..."} pass as success.
            if "message" in obj:
                require((commit_object or commit_create) and
                        isinstance(obj.get("message"), str) and
                        isinstance(obj.get("sha"), str) and
                        SHA.fullmatch(obj["sha"]) is not None and
                        type(obj.get("tree")) is dict and
                        isinstance(obj["tree"].get("sha"), str) and
                        SHA.fullmatch(obj["tree"]["sha"]) is not None and
                        type(obj.get("parents")) is list,
                        "API_REJECTED")
            return obj
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            # Never print GitHub error payloads or credential-derived headers.
            raise ProbeBlocked("API_RESULT_UNCONFIRMED") from None


def get_ref(api: Api, branch: str) -> str:
    obj = api.request("GET", API_ROOT + "/git/ref/heads/" + branch)
    require(obj.get("ref") == "refs/heads/" + branch, "WRONG_REF")
    return sha(obj.get("object", {}).get("sha"))


def get_commit(api: Api, commit_sha: str) -> dict:
    expected = sha(commit_sha)
    result = api.request("GET", API_ROOT + "/git/commits/" + expected)
    require(result.get("sha") == expected, "COMMIT_ID_MISMATCH")
    return result


def verify_tree_and_bytes(api: Api, commit_sha: str) -> None:
    commit = get_commit(api, commit_sha)
    require(commit.get("tree", {}).get("sha") == ROOT_TREE, "TREE_CHANGED")
    tree = api.request("GET", API_ROOT + "/git/trees/" + ROOT_TREE)
    require(tree.get("truncated") is not True and
            len(tree.get("tree", [])) == 1, "UNEXPECTED_TREE")
    entry = tree["tree"][0]
    require(entry.get("path") == "fence-record.json" and
            entry.get("mode") == "100644" and entry.get("type") == "blob" and
            entry.get("sha") == ROOT_BLOB, "UNEXPECTED_BLOB")
    item = api.request(
        "GET", API_ROOT + "/contents/fence-record.json?ref=" + commit_sha)
    require(item.get("type") == "file" and
            item.get("path") == "fence-record.json" and
            item.get("sha") == ROOT_BLOB and
            item.get("encoding") == "base64" and
            isinstance(item.get("content"), str), "UNEXPECTED_CONTENT")
    try:
        actual = base64.b64decode("".join(item["content"].split()), validate=True)
    except (ValueError, base64.binascii.Error):
        raise ProbeBlocked("BAD_LEDGER_ENCODING") from None
    require(actual == CANONICAL, "LEDGER_CONTENT_CHANGED")


def preflight(api: Api) -> str:
    env = os.environ
    require(env.get("GITHUB_REPOSITORY") == REPO and
            env.get("GITHUB_REF") == "refs/heads/main" and
            env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
            env.get("GITHUB_RUN_ATTEMPT") == "1" and
            NUMERIC.fullmatch(env.get("GITHUB_RUN_ID", "")) is not None and
            env.get("PROBE_CONFIRM") == CONFIRM, "UNTRUSTED_INVOCATION")
    expected_main = sha(env.get("GITHUB_SHA"))
    require(get_ref(api, "main") == expected_main, "MAIN_MOVED")
    # The separate exact-ref ruleset was independently inspected via the API.
    # Runtime basic branch metadata must still report protected=true.
    branch = api.request("GET", API_ROOT + "/branches/oci-fence-state")
    require(branch.get("name") == "oci-fence-state" and
            branch.get("protected") is True, "FENCE_PROTECTION_MISSING")
    require(get_ref(api, "oci-fence-state") == ROOT, "FENCE_NOT_AT_GENESIS")
    root = get_commit(api, ROOT)
    require(root.get("parents") == [], "ROOT_NOT_ORPHAN")
    verify_tree_and_bytes(api, ROOT)
    return repository_node_id(api)


def repository_node_id(api: Api) -> str:
    # Strictly require the repository identity, not an input-supplied GraphQL ID.
    repo = api.request("GET", API_ROOT)
    require(repo.get("full_name") == REPO and
            isinstance(repo.get("node_id"), str) and bool(repo["node_id"]),
            "REPOSITORY_MISMATCH")
    return repo["node_id"]


def prepare_commit(api: Api, contender: str, run_id: str) -> str:
    commit = api.request("POST", API_ROOT + "/git/commits", {
        "message": "test: fence GITHUB_TOKEN CAS no-op (" + run_id + "/" + contender + ")",
        "tree": ROOT_TREE,
        "parents": [ROOT],
    })
    result = sha(commit.get("sha"))
    check = get_commit(api, result)
    require(check.get("tree", {}).get("sha") == ROOT_TREE and
            [p.get("sha") for p in check.get("parents", [])] == [ROOT],
            "PROPOSED_COMMIT_NOT_LINEAR")
    return result


def contender(api: Api, repo_id: str, new_sha: str,
              barrier: threading.Barrier) -> bool:
    # Both transactions must race with the SAME old OID. No retries.
    try:
        barrier.wait(timeout=12)
    except threading.BrokenBarrierError:
        raise ProbeBlocked("CONTENDERS_NOT_SYNCHRONIZED") from None
    answer = api.request("POST", "/graphql", {
        "query": GRAPHQL,
        "variables": {"input": {
            "repositoryId": repo_id,
            "clientMutationId": CLIENT_ID,
            "refUpdates": [{
                "name": REF, "beforeOid": ROOT,
                "afterOid": new_sha, "force": False,
            }],
        }},
    })
    require(answer.get("data", {}).get("updateRefs", {}).get("clientMutationId")
            == CLIENT_ID, "CAS_ACK_UNCONFIRMED")
    return True


def run_probe(api: Api) -> None:
    repo_id = preflight(api)
    run_id = os.environ["GITHUB_RUN_ID"]
    first = prepare_commit(api, "A", run_id)
    second = prepare_commit(api, "B", run_id)
    require(first != second, "DUPLICATE_PROPOSALS")
    barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(contender, api, repo_id, s, barrier)
                   for s in (first, second)]
        responses = []
        for fut in futures:
            try:
                responses.append(fut.result())
            except ProbeBlocked:
                responses.append(False)
            except Exception:
                responses.append(False)  # Unknown acknowledgement: no retry.
    # Exactly one *acknowledged* winner is required.
    require(responses.count(True) == 1, "CAS_RESULT_UNCONFIRMED")
    accepted = first if responses[0] else second
    require(get_ref(api, "oci-fence-state") == accepted,
            "CAS_FINAL_HEAD_MISMATCH")
    resulting = get_commit(api, accepted)
    require([p.get("sha") for p in resulting.get("parents", [])] == [ROOT],
            "NONLINEAR_REF_UPDATE")
    verify_tree_and_bytes(api, accepted)
    print("PASS: protected GITHUB_TOKEN CAS had one acknowledged winner.")
    print("PASS: independent ledger contents and tree remain unchanged.")
    print("NOTE: state branch HEAD advanced once; run this probe only once.")


if __name__ == "__main__":
    try:
        run_probe(Api(os.environ.get("GH_TOKEN", "")))
    except Exception as exc:
        code = str(exc) if isinstance(exc, ProbeBlocked) else "UNKNOWN_FAILURE"
        print("BLOCKED: " + code)
        print("No retry: inspect protected fence HEAD before any new action.")
        raise SystemExit(1) from None
