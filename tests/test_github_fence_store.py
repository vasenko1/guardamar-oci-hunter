"""No-key end-to-end tests for GitHub exact-OID CAS backend.

Fake GitHub routes model immutable commit objects and one ref under a lock.
A separate isolated *real* GitHub ref probe is documented in the runbook.
No request in these tests leaves the Python process.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from automation import durable_fence as fence
from automation import github_fence_store as backend
from automation.launch_contract import Preview


def sha(data):
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


class LocalGitHub:
    """The mocked GraphQL compare uses exact beforeOid under a thread lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.initial = fence.initial_record_bytes()
        self.tip = "a" * 40
        self.commits = {self.tip: ("b" * 40, self.initial)}
        self.blobs = {}
        self.trees = {}
        self.last_ordinal = 0
        self.fail_graphql = False
        self.ack_lost_after_commit = False
        self.graphql_updates = 0
        self.unknown_requests = 0
        self.last_mutation = None

    def request(self, method, path, payload=None):
        prefix = "/repos/" + backend.REPO
        if method == "GET" and path == prefix + "/git/ref/heads/oci-fence-state":
            with self.lock:
                return {"object": {"sha": self.tip}}
        if method == "GET" and path.startswith(prefix + "/contents/fence-record.json?ref="):
            commit = path.rsplit("=", 1)[1]
            with self.lock:
                if commit not in self.commits:
                    raise RuntimeError("fake commit unavailable")
                raw = self.commits[commit][1]
            return {
                "type": "file", "path": backend.FENCE_PATH,
                "encoding": "base64",
                "content": base64.b64encode(raw).decode("ascii"),
            }
        if method == "GET" and path.startswith(prefix + "/git/commits/"):
            ref = path.rsplit("/", 1)[1]
            with self.lock:
                return {"tree": {"sha": self.commits[ref][0]}}
        if method == "POST" and path == prefix + "/git/blobs":
            body = payload["content"].encode("ascii")
            key = hashlib.sha1(body).hexdigest()
            with self.lock:
                self.blobs[key] = body
            return {"sha": key}
        if method == "POST" and path == prefix + "/git/trees":
            commit_tree = payload["base_tree"]
            new_blob = payload["tree"][0]["sha"]
            self.assert_tree_entry(payload)
            key = sha(commit_tree + ":" + new_blob)
            with self.lock:
                self.trees[key] = new_blob
            return {"sha": key}
        if method == "POST" and path == prefix + "/git/commits":
            parent = payload["parents"][0]
            tree = payload["tree"]
            with self.lock:
                self.last_ordinal += 1
                oid = sha(f"{parent}:{tree}:{self.last_ordinal}")
                self.commits[oid] = (tree, self.blobs[self.trees[tree]])
            return {"sha": oid}
        if method == "POST" and path == "/graphql":
            item = payload["variables"]["input"]["refUpdates"][0]
            self.last_mutation = item
            self.graphql_updates += 1
            if self.fail_graphql:
                return {"errors": [{"message": "fake github conflict"}]}
            with self.lock:
                if item["beforeOid"] != self.tip:
                    return {"errors": [{"message": "beforeOid mismatch"}]}
                self.tip = item["afterOid"]
            if self.ack_lost_after_commit:
                raise TimeoutError("fake commit ACK lost")
            return {"data": {"updateRefs": {"clientMutationId":
                payload["variables"]["input"]["clientMutationId"]}}}
        self.unknown_requests += 1
        raise AssertionError("unexpected fake GitHub request")

    @staticmethod
    def assert_tree_entry(payload):
        rows = payload["tree"]
        assert len(rows) == 1
        assert rows[0]["path"] == "fence-record.json"
        assert rows[0]["mode"] == "100644"
        assert rows[0]["type"] == "blob"


def env(run_id):
    return {
        "GITHUB_REPOSITORY": "vasenko1/guardamar-oci-hunter",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ID": run_id,
    }


class GitHubFenceBackendTests(unittest.TestCase):
    def test_read_exact_immutable_commit_and_content(self):
        fake = LocalGitHub()
        store = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        revision, data = store.read()
        self.assertEqual(revision, fake.tip)
        self.assertEqual(data, fence.initial_record_bytes())
        self.assertEqual(fake.unknown_requests, 0)

    def test_one_winner_across_simultaneous_github_cas(self):
        fake = LocalGitHub()
        store = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        def contender(i):
            try:
                fence.claim(store, env(str(100000 + i)), Preview("PREVIEW_ONLY", 6.0))
                return True
            except fence.FenceBlocked:
                return False
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(contender, range(100)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(fence.decode(store.read()[1]).phase, "CLAIMED")
        self.assertEqual(fake.unknown_requests, 0)
        self.assertEqual(fake.last_mutation["name"], backend.FENCE_REF)
        self.assertIs(fake.last_mutation["force"], False)
        self.assertEqual(fake.graphql_updates >= 1, True)

    def test_committed_claim_persists_across_new_store_instance(self):
        fake = LocalGitHub()
        prior = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        fence.claim(prior, env("111"), Preview("PREVIEW_ONLY", 2.0))
        subsequent = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(subsequent, env("222"), Preview("PREVIEW_ONLY", 6.0))

    def test_ambiguous_graphql_timeout_leaves_committed_claim(self):
        fake = LocalGitHub()
        fake.ack_lost_after_commit = True
        old_head = fake.tip
        store = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(store, env("111"), Preview("PREVIEW_ONLY", 6.0))
        self.assertNotEqual(fake.tip, old_head)
        self.assertEqual(fence.decode(store.read()[1]).phase, "CLAIMED")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(store, env("222"), Preview("PREVIEW_ONLY", 6.0))

    def test_graphql_error_leaves_branch_unchanged(self):
        fake = LocalGitHub()
        fake.fail_graphql = True
        old_head = fake.tip
        store = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(store, env("111"), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(fake.tip, old_head)
        self.assertEqual(fence.decode(store.read()[1]).phase, "OPEN")

    def test_settle_capacity_miss_allows_only_distinct_new_run(self):
        fake = LocalGitHub()
        store = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        ticket = fence.claim(store, env("111"), Preview("PREVIEW_ONLY", 6.0))
        fence.settle(store, ticket, "CAPACITY_MISS")
        self.assertEqual(fence.decode(store.read()[1]).phase, "OPEN")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(store, env("111"), Preview("PREVIEW_ONLY", 6.0))
        next_ticket = fence.claim(
            store, env("222"), Preview("PREVIEW_ONLY", 2.0)
        )
        self.assertEqual(next_ticket.run_id, "222")

    def test_global_429_stop_persists_to_new_instance(self):
        fake = LocalGitHub()
        store = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        fence.stop_on_preflight_429(store)
        fresh = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        self.assertEqual(fence.decode(fresh.read()[1]).reason, "RATE_LIMITED")
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(fresh, env("999"), Preview("PREVIEW_ONLY", 6.0))

    def test_malformed_or_missing_blob_never_allows_claim(self):
        fake = LocalGitHub()
        store = backend.GitHubCASStore(fake, "fake-graph-repo-id")
        with fake.lock:
            tree, _ = fake.commits[fake.tip]
            fake.commits[fake.tip] = (tree, b'{"phase":"OPEN"}')
        with self.assertRaises(fence.FenceBlocked):
            fence.claim(store, env("111"), Preview("PREVIEW_ONLY", 6.0))

    def test_failure_does_not_leak_transport_or_key_material(self):
        class Broken:
            def request(self, method, path, payload=None):
                raise ValueError("original OCI credential or GitHub access token")
        store = backend.GitHubCASStore(Broken(), "fake-graph-repo-id")
        with self.assertRaises(backend.TransportUnavailable) as ctx:
            store.read()
        self.assertNotIn("credential", str(ctx.exception))
        self.assertNotIn("token", str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)

    def test_http_adapter_never_accepts_wrong_host_or_path(self):
        api = backend.GitHubHttpTransport("test-token-not-an-actual-secret")
        for path in ("http://example.org", "//example.com", "/other-service",
                     "/repos/another/repo/git/commits"):
            with self.subTest(path=path), self.assertRaises(
                backend.TransportUnavailable
            ):
                api.request("GET", path)
        self.assertNotIn("test-token", repr(api))


if __name__ == "__main__":
    unittest.main()
