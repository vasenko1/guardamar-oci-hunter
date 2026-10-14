"""Offline hostile-transport regression tests for the isolated, one-shot fence probe."""
from __future__ import annotations

import base64
from contextlib import redirect_stdout
import io
import json
import os
import threading
import unittest
from unittest.mock import patch

from tools import fence_token_noop_probe as probe


MAIN = "d97de2cc217adab9185fc4f9b49703986c3707da"
ENV = {
    "GITHUB_REPOSITORY": probe.REPO,
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_RUN_ID": "1234567",
    "GITHUB_SHA": MAIN,
    "PROBE_CONFIRM": probe.CONFIRM,
}


class FakeApi:
    def __init__(self):
        self.lock = threading.Lock()
        self.head = probe.ROOT
        self.main = MAIN
        self.protected = True
        self.raw = probe.CANONICAL
        self.proposals = {}
        self.graphql_attempts = 0
        self.api_mutations = 0
        self.lose_ack = False

    def request(self, method, path, body=None):
        if method == "GET":
            if path == probe.API_ROOT:
                return {"full_name": probe.REPO, "node_id": "R_N"}
            if path == probe.API_ROOT + "/branches/oci-fence-state":
                return {"name": "oci-fence-state", "protected": self.protected}
            if path == probe.API_ROOT + "/git/ref/heads/main":
                return {"ref": "refs/heads/main", "object": {"sha": self.main}}
            if path == probe.API_ROOT + "/git/ref/heads/oci-fence-state":
                return {"ref": probe.REF, "object": {"sha": self.head}}
            if path == probe.API_ROOT + "/git/commits/" + probe.ROOT:
                return {"tree": {"sha": probe.ROOT_TREE}, "parents": []}
            if path.startswith(probe.API_ROOT + "/git/commits/"):
                key = path.rsplit("/", 1)[-1]
                if key in self.proposals:
                    return {"tree": {"sha": probe.ROOT_TREE},
                            "parents": [{"sha": probe.ROOT}]}
            if path == probe.API_ROOT + "/git/trees/" + probe.ROOT_TREE:
                return {"truncated": False, "tree": [{
                    "path": "fence-record.json", "mode": "100644",
                    "type": "blob", "sha": probe.ROOT_BLOB,
                }]}
            if path.startswith(probe.API_ROOT + "/contents/fence-record.json?ref="):
                return {"type": "file", "path": "fence-record.json",
                        "sha": probe.ROOT_BLOB, "encoding": "base64",
                        "content": base64.b64encode(self.raw).decode("ascii")}
        if method == "POST" and path == probe.API_ROOT + "/git/commits":
            assert body["parents"] == [probe.ROOT]
            assert body["tree"] == probe.ROOT_TREE
            assert body["message"].startswith("test: fence GITHUB_TOKEN CAS no-op")
            assert body["message"].endswith(("/A)", "/B)"))
            key = ("a" if body["message"].endswith("/A)") else "b") * 40
            self.proposals[key] = dict(body)
            self.api_mutations += 1
            return {"sha": key}
        if method == "POST" and path == "/graphql":
            with self.lock:
                self.graphql_attempts += 1
                data = body["variables"]["input"]
                update = data["refUpdates"][0]
                assert data["repositoryId"] == "R_N"
                assert update["name"] == probe.REF
                assert update["beforeOid"] == probe.ROOT
                assert update["force"] is False
                if self.head != probe.ROOT:
                    return {"errors": [{"message": "stale"}]}
                self.head = update["afterOid"]
                if self.lose_ack:
                    return {}  # Write applied, but success response lost.
                return {"data": {"updateRefs": {
                    "clientMutationId": probe.CLIENT_ID}}}
        raise AssertionError("Unexpected API call: " + method + " " + path)


class FenceProbeTests(unittest.TestCase):
    def test_exact_sha_and_run_id_grammar(self):
        self.assertEqual(probe.sha(MAIN), MAIN)
        for s in ["z" * 40, "a" * 39, "a" * 41, MAIN + "\\n"]:
            with self.assertRaises(probe.ProbeBlocked):
                probe.sha(s)
        self.assertIsNotNone(probe.NUMERIC.fullmatch("123"))
        self.assertIsNone(probe.NUMERIC.fullmatch("0"))

    def test_successful_parallel_content_preserving_cas(self):
        api = FakeApi()
        with patch.dict(os.environ, ENV, clear=True), redirect_stdout(io.StringIO()):
            probe.run_probe(api)
        self.assertIn(api.head, api.proposals)
        self.assertEqual(api.graphql_attempts, 2)
        self.assertEqual(api.api_mutations, 2)
        self.assertEqual(api.raw, probe.CANONICAL)
        self.assertNotEqual(api.head, probe.ROOT)
        # The exact genesis guard prevents automatic second use.
        with patch.dict(os.environ, ENV, clear=True):
            with self.assertRaises(probe.ProbeBlocked):
                probe.run_probe(api)
        self.assertEqual(api.graphql_attempts, 2)

    def test_lost_success_ack_fail_closed_no_retry(self):
        api = FakeApi()
        api.lose_ack = True
        with patch.dict(os.environ, ENV, clear=True):
            with self.assertRaisesRegex(probe.ProbeBlocked, "CAS_RESULT_UNCONFIRMED"):
                probe.run_probe(api)
        self.assertEqual(api.graphql_attempts, 2)
        self.assertEqual(api.raw, probe.CANONICAL)

    def test_missing_or_changed_protected_branch_fails_before_writes(self):
        for corrupt in ["unprotected", "changed", "wrongbytes", "missingroot"]:
            api = FakeApi()
            if corrupt == "unprotected":
                api.protected = False
            elif corrupt == "changed":
                api.head = "c" * 40
            elif corrupt == "wrongbytes":
                api.raw = b'{"phase":"HALTED"}'
            else:
                api.request = _no_orphan_root(api)
            with self.subTest(corrupt=corrupt):
                with patch.dict(os.environ, ENV, clear=True):
                    with self.assertRaises(probe.ProbeBlocked):
                        probe.run_probe(api)
                self.assertEqual(api.api_mutations, 0)

    def test_bad_invocation_and_main_movement_fail_before_writes(self):
        for key, value in [
            ("GITHUB_REF", "refs/heads/feature/something"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REPOSITORY", "other/repo"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_RUN_ID", "0"),
            ("PROBE_CONFIRM", "NO"),
            ("GITHUB_SHA", "f" * 40),
        ]:
            api = FakeApi()
            with self.subTest(key=key):
                with patch.dict(os.environ, {**ENV, key: value}, clear=True):
                    with self.assertRaises(probe.ProbeBlocked):
                        probe.run_probe(api)
                self.assertEqual(api.api_mutations, 0)

    def test_url_confinement_blocks_outside_repository(self):
        transport = object.__new__(probe.Api)
        transport.token = "only-a-test-token-123456"
        for method, path in [
            ("POST", "/repos/other/repo/git/commits"),
            ("POST", probe.API_ROOT + "/git/ref/heads/main"),
            ("GET", "https://attacker.example/"),
            ("GET", probe.API_ROOT + "/../../other"),
            ("POST", probe.API_ROOT + "/git/blobs"),
        ]:
            with self.subTest(path=path):
                with self.assertRaises(probe.ProbeBlocked):
                    transport.request(method, path)


def _no_orphan_root(api):
    prior = api.request
    def response(method, path, body=None):
        if method == "GET" and path == probe.API_ROOT + "/git/commits/" + probe.ROOT:
            return {"tree": {"sha": probe.ROOT_TREE},
                    "parents": [{"sha": "f" * 40}]}
        return prior(method, path, body)
    return response


if __name__ == "__main__":
    unittest.main()
