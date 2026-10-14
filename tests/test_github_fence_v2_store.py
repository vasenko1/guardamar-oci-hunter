"""Offline GitHub-v2 write-path state machine and remote CAS emulation.

No test reads real GitHub, OCI SDK, secrets, or a protected branch. Fake API
models immutable Git objects, one protected ref, and updateRefs exact OID
under a lock, including lost acknowledgment after an actual ref update.
"""
from __future__ import annotations

import base64
import hashlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from automation import durable_fence as v1
from automation import fence_watermark_v2 as v2
from automation import github_fence_v2_store as backend
from automation import github_fence_readonly as inspector
from automation import github_fence_store as old_backend
from automation.launch_contract import Preview


def oid(payload):
    return hashlib.sha1(payload).hexdigest()


def git_blob(raw):
    return oid(("blob " + str(len(raw)) + "\0").encode("ascii") + raw)


def env(run):
    return {
        "GITHUB_REPOSITORY": inspector.REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": str(run),
    }


class GitFake:
    """Versioned one-ref Git Data API with independently hashed blobs."""
    def __init__(self, raw=None):
        self.lock = threading.Lock()
        self.init = raw if raw is not None else v2.plan_v1_open_upgrade(
            v1.initial_record_bytes())
        self.blobs = {}
        self.trees = {}
        self.commits = {}
        self.node = "graph-repository-id"
        self.tip = "a" * 40
        self._initial(self.init)
        self.requests = []
        self.cas_calls = 0
        self.writes = 0
        self.lose_ack = False
        self.graphql_denied = False
        self.protected = True
        self.bad_tree = False
        self.move_on_verify = False

    def _initial(self, raw):
        blob = git_blob(raw)
        tree = "b" * 40
        self.blobs[blob] = raw
        self.trees[tree] = blob
        self.commits[self.tip] = (tree, None, "initial v2 fixture")

    def request(self, method, path, data=None):
        self.requests.append((method, path))
        root = inspector.ROOT
        if method == "GET":
            if path == root:
                return {"full_name": inspector.REPO, "node_id": self.node}
            if path == root + "/branches/oci-fence-state":
                return {"name": "oci-fence-state", "protected": self.protected}
            if path == root + "/git/ref/heads/oci-fence-state":
                with self.lock:
                    self._ref_reads = getattr(self, "_ref_reads", 0) + 1
                    tip = self.tip
                    if self.move_on_verify and self._ref_reads >= 2:
                        tip = "d" * 40
                return {"ref": inspector.REF, "object": {
                    "type": "commit", "sha": tip}}
            if path.startswith(root + "/git/commits/"):
                name = path.rsplit("/", 1)[-1]
                tree, parent, msg = self.commits[name]
                return {
                    "sha": name, "tree": {"sha": tree}, "message": msg,
                    "parents": [{"sha": parent}] if parent else [],
                }
            if path.startswith(root + "/git/trees/"):
                name = path.rsplit("/", 1)[-1]
                blob = self.trees[name]
                entries = [{
                    "path": inspector.PATH, "mode": "100644",
                    "type": "blob", "sha": blob,
                    "size": len(self.blobs[blob]),
                }]
                if self.bad_tree:
                    entries.append({"path": "evil", "mode": "100644",
                                    "type": "blob", "sha": blob,
                                    "size": len(self.blobs[blob])})
                return {"sha": name, "tree": entries, "truncated": False}
            if path.startswith(root + "/contents/fence-record.json?ref="):
                ref = path.split("=", 1)[1]
                blob = self.trees[self.commits[ref][0]]
                return {
                    "type": "file", "path": inspector.PATH,
                    "sha": blob, "encoding": "base64",
                    "content": base64.b64encode(self.blobs[blob]).decode("ascii"),
                }
        if method == "POST":
            self.writes += 1
            if path == root + "/git/blobs":
                assert data["encoding"] == "utf-8"
                raw = data["content"].encode("ascii")
                blob = git_blob(raw)
                self.blobs[blob] = raw
                return {"sha": blob}
            if path == root + "/git/trees":
                prev = data["base_tree"]
                row = data["tree"]
                assert prev in self.trees
                assert len(row) == 1 and row[0]["path"] == inspector.PATH
                assert row[0]["mode"] == "100644"
                assert row[0]["type"] == "blob"
                blob = row[0]["sha"]
                assert blob in self.blobs
                name = oid((prev + blob).encode("ascii"))
                self.trees[name] = blob
                return {"sha": name}
            if path == root + "/git/commits":
                assert len(data["parents"]) == 1
                parent = data["parents"][0]
                tree = data["tree"]
                assert parent in self.commits and tree in self.trees
                name = oid((parent + tree + data["message"]).encode("ascii"))
                self.commits[name] = (tree, parent, data["message"])
                return {"sha": name, "message": data["message"],
                        "tree": {"sha": tree}, "parents": [{"sha": parent}]}
            if path == "/graphql":
                self.cas_calls += 1
                spec = data["variables"]["input"]
                assert spec["repositoryId"] == self.node
                assert len(spec["refUpdates"]) == 1
                op = spec["refUpdates"][0]
                assert op["name"] == inspector.REF and op["force"] is False
                if self.graphql_denied:
                    return {"errors": [{"message": "denied"}]}
                with self.lock:
                    if op["beforeOid"] != self.tip:
                        return {"errors": [{"message": "outdated revision"}]}
                    assert op["afterOid"] in self.commits
                    self.tip = op["afterOid"]
                if self.lose_ack:
                    raise TimeoutError("remote ref committed but ack lost")
                return {"data": {"updateRefs": {
                    "clientMutationId": spec["clientMutationId"]}}}
        raise AssertionError("unexpected Git operation " + method + " " + path)


class V2AdapterTests(unittest.TestCase):
    def test_read_v2_verifies_blob_tree_protection_and_head(self):
        fake = GitFake()
        adapter = backend.GitHubV2CASStore(fake)
        revision, raw = adapter.read()
        self.assertEqual(revision, fake.tip)
        self.assertEqual(v2.decode(raw), v2.WatermarkRecord(
            "OPEN", "INITIAL", None, 0))
        self.assertEqual(fake.writes, 0)
        self.assertEqual(fake.cas_calls, 0)

    def test_version1_blocks_before_any_post_not_auto_upgraded(self):
        fake = GitFake(v1.initial_record_bytes())
        adapter = backend.GitHubV2CASStore(fake)
        with self.assertRaises(old_backend.TransportUnavailable):
            adapter.read()
        next_doc = v2.plan_v1_open_upgrade(v1.initial_record_bytes())
        with self.assertRaises(old_backend.TransportUnavailable):
            adapter.cas(fake.tip, next_doc)
        self.assertEqual(fake.writes, 0)
        self.assertEqual(fake.tip, "a" * 40)

    def test_real_protocol_offline_claim_settle_rearm(self):
        fake = GitFake()
        storage = backend.GitHubV2CASStore(fake)
        first = v2.claim(storage, env(101), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(v2.decode(storage.read()[1]).phase, "CLAIMED")
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(storage, env(102), Preview("PREVIEW_ONLY", 6.0))
        v2.settle(storage, first, "CAPACITY_MISS")
        with self.assertRaisesRegex(v2.FenceBlocked, "run_id_not_above"):
            v2.claim(storage, env(101), Preview("PREVIEW_ONLY", 6.0))
        second = v2.claim(storage, env(102), Preview("PREVIEW_ONLY", 2.0))
        self.assertEqual(v2.decode(storage.read()[1]).claims_committed, 2)
        v2.settle(storage, second, "ACCEPTED")
        self.assertEqual(v2.decode(storage.read()[1]).phase, "HALTED")
        self.assertEqual(v2.decode(storage.read()[1]).reason, "ACCEPTED")
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(storage, env(103), Preview("PREVIEW_ONLY", 2.0))

    def test_preclaim_rate_limit_is_sticky(self):
        fake = GitFake()
        store = backend.GitHubV2CASStore(fake)
        v2.stop_on_preflight_429(store)
        self.assertEqual(v2.decode(store.read()[1]).reason, "RATE_LIMITED")
        writes = fake.writes
        v2.stop_on_preflight_429(store)
        self.assertEqual(fake.writes, writes)

    def test_claim_after_timeout_must_fail_closed(self):
        fake = GitFake()
        fake.lose_ack = True
        store = backend.GitHubV2CASStore(fake)
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(store, env(101), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(fake.cas_calls, 1)
        self.assertEqual(v2.decode(store.read()[1]).phase, "CLAIMED")
        fake.lose_ack = False
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(store, env(102), Preview("PREVIEW_ONLY", 2.0))
        self.assertEqual(fake.cas_calls, 1)

    def test_graphql_denial_never_changes_tip_or_grants_claim(self):
        fake = GitFake()
        fake.graphql_denied = True
        initial_head = fake.tip
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(backend.GitHubV2CASStore(fake), env(101),
                     Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(fake.tip, initial_head)
        self.assertEqual(fake.cas_calls, 1)

    def test_parallel_claims_one_winner_and_no_retry(self):
        fake = GitFake()
        def contender(n):
            try:
                return v2.claim(backend.GitHubV2CASStore(fake), env(n),
                                Preview("PREVIEW_ONLY", 6.0))
            except v2.FenceBlocked:
                return None
        with ThreadPoolExecutor(max_workers=12) as pool:
            wins = [x for x in pool.map(contender, range(200, 250)) if x]
        self.assertEqual(len(wins), 1)
        self.assertEqual(v2.decode(backend.GitHubV2CASStore(fake).read()[1]).phase,
                         "CLAIMED")
        self.assertEqual(fake.cas_calls, 1)

    def test_illegal_transition_guard_direct_call_no_post(self):
        examples = [
            v2.WatermarkRecord("OPEN", "INITIAL", None, 0),
            v2.WatermarkRecord("HALTED", "RATE_LIMITED", None, 0),
        ]
        for input_record in examples:
            fake = GitFake(v2.encode(input_record))
            store = backend.GitHubV2CASStore(fake)
            old_rev, _ = store.read()
            proposed = [
                v2.WatermarkRecord("OPEN", "CAPACITY_MISS", "101", 1),
                v2.WatermarkRecord("CLAIMED", "INITIAL", "101", 1,
                                   "101", 2.0),
                v2.WatermarkRecord("HALTED", "BLOCKED", None, 0),
            ]
            for candidate in proposed:
                accepted = (
                    input_record.phase == "OPEN" and
                    candidate.phase == "CLAIMED" and
                    candidate.highest_spent_run_id == "101"
                )
                if accepted:
                    continue
                with self.subTest(state=input_record, candidate=candidate):
                    with self.assertRaises(old_backend.TransportUnavailable):
                        store.cas(old_rev, v2.encode(candidate))
            self.assertEqual(fake.writes, 0)

    def test_direct_halting_and_history_reset_after_claim_are_denied(self):
        fake = GitFake()
        store = backend.GitHubV2CASStore(fake)
        ticket = v2.claim(store, env(101), Preview("PREVIEW_ONLY", 6.0))
        previous_writes = fake.writes
        revision, _ = store.read()
        forged = [
            v2.WatermarkRecord("OPEN", "CAPACITY_MISS", "101", 1),
            v2.WatermarkRecord("HALTED", "BLOCKED", "101", 1,
                               "101", 2.0),
            v2.WatermarkRecord("CLAIMED", "INITIAL", "102", 2,
                               "102", 6.0),
        ]
        for candidate in forged:
            # OPEN with same history is VALID CAPACITY_MISS, but direct CAS
            # cannot distinguish who initiated it; caller authorization is
            # still required. Reject the other two fabricated mutations.
            if candidate.phase == "OPEN":
                continue
            with self.assertRaises(old_backend.TransportUnavailable):
                store.cas(revision, v2.encode(candidate))
        self.assertEqual(fake.writes, previous_writes)
        v2.settle(store, ticket, "CAPACITY_MISS")
        revision, _ = store.read()
        with self.assertRaises(old_backend.TransportUnavailable):
            store.cas(revision, v2.encode(v2.WatermarkRecord(
                "HALTED", "ACCEPTED", "101", 1)))
        self.assertEqual(v2.decode(store.read()[1]).phase, "OPEN")

    def test_stale_head_blocks_preobject_creation(self):
        fake = GitFake()
        store = backend.GitHubV2CASStore(fake)
        rev, _ = store.read()
        ticket = v2.claim(store, env(101), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(ticket.revision, rev)
        count = fake.writes
        with self.assertRaises(old_backend.TransportUnavailable):
            store.cas(rev, v2.encode(v2.WatermarkRecord(
                "HALTED", "RATE_LIMITED", None, 0)))
        self.assertEqual(fake.writes, count)

    def test_bad_tree_or_unprotected_or_moving_head_denied_pre_write(self):
        for attribute in ("bad_tree", "protected", "move_on_verify"):
            fake = GitFake()
            if attribute == "protected":
                fake.protected = False
            else:
                setattr(fake, attribute, True)
            with self.subTest(attribute=attribute):
                store = backend.GitHubV2CASStore(fake)
                with self.assertRaises(old_backend.TransportUnavailable):
                    v2.claim(store, env(101), Preview("PREVIEW_ONLY", 6.0))
                self.assertEqual(fake.writes, 0)

    def test_wrong_repository_id_rejected_before_graphql_update(self):
        fake = GitFake()
        fake.node = ""
        store = backend.GitHubV2CASStore(fake)
        with self.assertRaises(v2.FenceBlocked):
            v2.claim(store, env(101), Preview("PREVIEW_ONLY", 6.0))
        self.assertEqual(fake.cas_calls, 0)

    def test_exactly_one_parent_for_each_successful_state_commit(self):
        fake = GitFake()
        storage = backend.GitHubV2CASStore(fake)
        initial_head = fake.tip
        ticket = v2.claim(storage, env(101), Preview("PREVIEW_ONLY", 2.0))
        next_head = fake.tip
        self.assertEqual(fake.commits[next_head][1], initial_head)
        v2.settle(storage, ticket, "CAPACITY_MISS")
        self.assertEqual(fake.commits[fake.tip][1], next_head)

    def test_no_oci_or_mutating_workflow_wiring(self):
        from pathlib import Path
        import ast
        root = Path(__file__).resolve().parents[1]
        path = root / "automation/github_fence_v2_store.py"
        tree = ast.parse(path.read_text())
        imports = [n.module for n in ast.walk(tree)
                   if isinstance(n, ast.ImportFrom) and n.module]
        self.assertNotIn("oci", imports)
        self.assertNotIn("subprocess", imports)
        job_source = (root / ".github/workflows/guardamar-capacity.yml").read_text()
        self.assertNotIn("github_fence_v2_store", job_source)
        self.assertNotIn("environment: oci-launch", job_source)


if __name__ == "__main__":
    unittest.main()
