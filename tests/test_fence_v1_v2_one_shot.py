"""Offline adversarial tests of a future manually approved migration.

All GitHub REST/GraphQL writes are an in-memory fake; NO external call, OCI,
IAM, credentials, real refs or workflow dispatch. A fake lost ACK must never
be interpreted as permission to retry.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from automation import durable_fence as v1
from automation import fence_watermark_v2 as v2
from automation import fence_migration_preview as plan
from automation import github_fence_readonly as reader
from automation.github_fence_store import GitHubHttpTransport, TransportUnavailable
from tools import fence_v1_v2_one_shot as migrate

MAIN = "a4b0ce37f909f59f88aa667ea470a1e85258d33c"


def sha_blob(raw: bytes) -> str:
    return hashlib.sha1(
        ("blob " + str(len(raw)) + "\0").encode("ascii") + raw
    ).hexdigest()


def invocation(**overrides):
    return {**{
        "GITHUB_REPOSITORY": migrate.REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTOR": "vasenko1",
        "GITHUB_RUN_ID": "38688888888",
        "GITHUB_SHA": MAIN,
        "MIGRATION_CONFIRM": migrate.CONFIRM,
        "MIGRATION_EXPECTED_OLD_HEAD": plan.EXPECTED_TIP,
    }, **overrides}


def ruleset(number, ref):
    typ = (["deletion", "non_fast_forward", "required_linear_history"]
           if number == migrate.STATE_RULE_ID else
           ["deletion", "non_fast_forward", "pull_request",
            "required_status_checks"])
    data = {
        "id": number, "name": "strict fixed fixture",
        "source": migrate.REPO, "source_type": "Repository",
        "target": "branch", "enforcement": "active",
        "bypass_actors": [], "current_user_can_bypass": "never",
        "conditions": {"ref_name": {"include": [ref], "exclude": []}},
        "rules": [{"type": kind} for kind in typ],
    }
    if number == migrate.MAIN_RULE_ID:
        data["rules"][-1]["parameters"] = {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [{
                "context": "public-audit-tests", "integration_id": 15368,
            }],
        }
    return data


class MockGitHub:
    """Documented response shapes, exact single-ref CAS under one lock."""
    def __init__(self):
        self.lock = threading.Lock()
        self.current = plan.EXPECTED_TIP
        self.main = MAIN
        self.old = v1.initial_record_bytes()
        self.node = "R_repo_node"
        self.raw_blobs = {
            reader.ORIGINAL_BLOB: self.old,
        }
        self.trees = {reader.ORIGINAL_TREE: reader.ORIGINAL_BLOB}
        self.commits = {}
        self.rules = {
            migrate.MAIN_RULE_ID: ruleset(
                migrate.MAIN_RULE_ID, "refs/heads/main"),
            migrate.STATE_RULE_ID: ruleset(
                migrate.STATE_RULE_ID, reader.REF),
        }
        self.protected = True
        self.extra_ruleset = False
        self.postpolicy_tamper = False
        self.corrupt_blob_create = False
        self.lost_ack = False
        self.deny_cas = False
        self.mutating_calls = []
        self.graphql_calls = 0
        self.http_calls = []

    def get(self, path):
        with self.lock:
            self.http_calls.append(("GET", path))
            root = reader.ROOT
            if path == root:
                return {"full_name": reader.REPO, "node_id": self.node}
            if path in (root + "/branches/main",
                        root + "/branches/oci-fence-state"):
                name = path.split("/")[-1]
                return {"name": name, "protected": self.protected}
            if path in (root + "/git/ref/heads/main",
                        root + "/git/ref/heads/oci-fence-state"):
                name = path.split("/")[-1]
                tip = self.main if name == "main" else self.current
                return {"ref": "refs/heads/" + name,
                        "object": {"type": "commit", "sha": tip}}
            if path == root + "/rulesets":
                result = [{"id": i} for i in self.rules]
                if self.extra_ruleset:
                    result.append({"id": 999})
                return result
            for ident, record in self.rules.items():
                if path == root + "/rulesets/" + str(ident):
                    if self.postpolicy_tamper and self.graphql_calls:
                        return {**record, "bypass_actors": [{"actor_id": 1}]}
                    return record
            if path == root + "/git/commits/" + reader.GENESIS:
                return {"sha": reader.GENESIS,
                        "message": "Initialize OCI fence ledger",
                        "tree": {"sha": reader.ORIGINAL_TREE}, "parents": []}
            if path == root + "/git/commits/" + plan.EXPECTED_TIP:
                return {"sha": plan.EXPECTED_TIP,
                        "message": plan.KNOWN_MESSAGE,
                        "tree": {"sha": reader.ORIGINAL_TREE},
                        "parents": [{"sha": reader.GENESIS}]}
            if path.startswith(root + "/git/commits/"):
                oid = path.split("/")[-1]
                return self.commits[oid]
            if path.startswith(root + "/git/trees/"):
                oid = path.split("/")[-1]
                blob = self.trees[oid]
                return {"sha": oid, "truncated": False, "tree": [{
                    "path": reader.PATH, "mode": "100644", "type": "blob",
                    "sha": blob, "size": len(self.raw_blobs[blob]),
                }]}
            if path.startswith(root + "/contents/fence-record.json?ref="):
                oid = path.split("=")[-1]
                if oid == plan.EXPECTED_TIP:
                    blob = reader.ORIGINAL_BLOB
                else:
                    blob = self.trees[self.commits[oid]["tree"]["sha"]]
                return {"path": reader.PATH, "type": "file",
                        "encoding": "base64", "sha": blob,
                        "content": base64.b64encode(
                            self.raw_blobs[blob]).decode("ascii")}
            raise AssertionError("Unexpected GET " + path)

    def post(self, path, body):
        with self.lock:
            self.http_calls.append(("POST", path))
            self.mutating_calls.append(path)
            root = reader.ROOT
            if path == root + "/git/blobs":
                raw = body["content"].encode("ascii")
                expected = sha_blob(raw)
                self.raw_blobs[expected] = raw
                return {"sha": "f" * 40 if self.corrupt_blob_create
                        else expected}
            if path == root + "/git/trees":
                assert body["base_tree"] == reader.ORIGINAL_TREE
                assert len(body["tree"]) == 1
                assert body["tree"][0]["path"] == reader.PATH
                blob = body["tree"][0]["sha"]
                assert blob in self.raw_blobs
                tree_id = hashlib.sha1(
                    (reader.ORIGINAL_TREE + blob).encode()).hexdigest()
                self.trees[tree_id] = blob
                return {"sha": tree_id}
            if path == root + "/git/commits":
                assert body["parents"] == [plan.EXPECTED_TIP]
                tree_oid = body["tree"]
                assert tree_oid in self.trees
                commit_id = hashlib.sha1(
                    (tree_oid + body["message"] +
                     plan.EXPECTED_TIP).encode()).hexdigest()
                self.commits[commit_id] = {
                    "sha": commit_id, "message": body["message"],
                    "tree": {"sha": tree_oid},
                    "parents": [{"sha": plan.EXPECTED_TIP}],
                }
                return self.commits[commit_id]
            if path == "/graphql":
                self.graphql_calls += 1
                item = body["variables"]["input"]
                update = item["refUpdates"][0]
                assert len(item["refUpdates"]) == 1
                assert item["repositoryId"] == self.node
                assert update["name"] == reader.REF
                assert update["force"] is False
                if self.deny_cas or self.current != update["beforeOid"]:
                    return {"errors": [{"message": "CAS conflict"}]}
                self.current = update["afterOid"]
                if self.lost_ack:
                    raise TransportUnavailable("simulated lost ACK")
                return {"data": {"updateRefs": {
                    "clientMutationId": item["clientMutationId"],
                }}}
            raise AssertionError("Unexpected POST " + path)


class MigrationTests(unittest.TestCase):
    def test_exactly_one_cas_append_and_verified_v2(self):
        api = MockGitHub()
        new_head = migrate.run_migration(api, invocation())
        self.assertEqual(api.current, new_head)
        self.assertEqual(api.graphql_calls, 1)
        self.assertEqual(api.mutating_calls.count("/graphql"), 1)
        self.assertEqual(api.mutating_calls.count(
            reader.ROOT + "/git/commits"), 1)
        next_doc = api.raw_blobs[
            api.trees[api.commits[new_head]["tree"]["sha"]]]
        self.assertEqual(next_doc,
                         v2.plan_v1_open_upgrade(v1.initial_record_bytes()))
        self.assertEqual(v2.decode(next_doc).phase, "OPEN")
        self.assertEqual(v2.decode(next_doc).claims_committed, 0)
        self.assertEqual(api.old, v1.initial_record_bytes())
        self.assertEqual(api.main, MAIN)
        self.assertEqual(api.commits[new_head]["parents"],
                         [{"sha": plan.EXPECTED_TIP}])

    def test_successful_once_must_never_replay(self):
        api = MockGitHub()
        migrate.run_migration(api, invocation())
        calls = len(api.mutating_calls)
        with self.assertRaises(reader.AuditRejected):
            migrate.run_migration(api, invocation(GITHUB_RUN_ID="38688888889"))
        self.assertEqual(len(api.mutating_calls), calls)
        self.assertEqual(api.graphql_calls, 1)

    def test_all_untrusted_invocations_fail_before_any_io(self):
        for name, bad in [
            ("GITHUB_REPOSITORY", "someone/else"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REF_PROTECTED", "false"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_ACTOR", "other"),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_SHA", "not-a-sha"),
            ("MIGRATION_CONFIRM", "YES"),
            ("MIGRATION_EXPECTED_OLD_HEAD", "f" * 40),
        ]:
            with self.subTest(name=name):
                api = MockGitHub()
                with self.assertRaises(migrate.MigrationBlocked):
                    migrate.run_migration(api, invocation(**{name: bad}))
                self.assertEqual(api.http_calls, [])

    def test_rules_or_moved_main_fail_before_mutating(self):
        for fail in ("unprotected", "extra_ruleset", "main_moved",
                     "bypass", "wrong_status"):
            api = MockGitHub()
            if fail == "unprotected":
                api.protected = False
            elif fail == "extra_ruleset":
                api.extra_ruleset = True
            elif fail == "main_moved":
                api.main = "f" * 40
            elif fail == "bypass":
                api.rules[migrate.STATE_RULE_ID]["bypass_actors"] = [
                    {"actor_id": 123}]
            elif fail == "wrong_status":
                api.rules[migrate.MAIN_RULE_ID]["rules"][-1][
                    "parameters"]["strict_required_status_checks_policy"] = False
            with self.subTest(fail=fail):
                with self.assertRaises((migrate.MigrationBlocked,
                                        reader.AuditRejected)):
                    migrate.run_migration(api, invocation())
                self.assertEqual(api.mutating_calls, [])

    def test_ambiguous_graphql_applied_ack_lost_no_retry(self):
        api = MockGitHub()
        api.lost_ack = True
        with self.assertRaises(TransportUnavailable):
            migrate.run_migration(api, invocation())
        self.assertNotEqual(api.current, plan.EXPECTED_TIP)
        self.assertEqual(api.graphql_calls, 1)
        with self.assertRaises(reader.AuditRejected):
            migrate.run_migration(api, invocation())
        self.assertEqual(api.graphql_calls, 1)

    def test_graphql_rejected_and_existing_head_unchanged(self):
        api = MockGitHub()
        api.deny_cas = True
        with self.assertRaises(MigrationErrorTypes()):
            migrate.run_migration(api, invocation())
        self.assertEqual(api.current, plan.EXPECTED_TIP)
        self.assertEqual(api.graphql_calls, 1)

    def test_wrong_blob_ack_stop_before_cas(self):
        api = MockGitHub()
        api.corrupt_blob_create = True
        with self.assertRaises(migrate.MigrationBlocked):
            migrate.run_migration(api, invocation())
        self.assertEqual(api.current, plan.EXPECTED_TIP)
        self.assertEqual(api.graphql_calls, 0)
        self.assertEqual(len(api.mutating_calls), 1)

    def test_post_commit_rules_changed_blocks_after_single_cas(self):
        api = MockGitHub()
        api.postpolicy_tamper = True
        with self.assertRaises(migrate.MigrationBlocked):
            migrate.run_migration(api, invocation())
        self.assertEqual(api.graphql_calls, 1)
        self.assertNotEqual(api.current, plan.EXPECTED_TIP)

    def test_workflow_trigger_and_source_stay_oci_free(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/fence-v1-v2-migration.yml").read_text()
        self.assertIn("  workflow_dispatch:", text)
        self.assertNotIn("  schedule:", text)
        self.assertNotIn("  push:", text)
        self.assertNotIn("  pull_request:", text)
        self.assertNotIn("pull_request_target:", text)
        self.assertIn("github.run_attempt == 1", text)
        self.assertIn("github.actor == 'vasenko1'", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("      contents: write", text)
        self.assertIn("      contents: read", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("oci-launch", text)
        self.assertNotIn("  environment:", text)
        self.assertNotIn("create_instance", text)
        source = (root / "tools/fence_v1_v2_one_shot.py").read_text()
        self.assertNotIn("import oci", source)
        self.assertNotIn("launch_instance", source)


def MigrationErrorTypes():
    return (migrate.MigrationBlocked, TransportUnavailable)


if __name__ == "__main__":
    unittest.main()
