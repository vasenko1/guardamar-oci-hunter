"""No-credential offline validation of the GitHub GET-only v1/v2 verifier."""
import base64
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from automation import durable_fence as v1
from automation import fence_watermark_v2 as v2
from automation import github_fence_readonly as probe


def blob_sha(raw):
    return hashlib.sha1(
        ("blob " + str(len(raw)) + "\0").encode("ascii") + raw
    ).hexdigest()


class FakeRead:
    def __init__(self, raw=None):
        self.raw = raw if raw is not None else v1.initial_record_bytes()
        self.head = probe.TEST_WINNER
        self.parent = probe.GENESIS
        self.tree_id = "a" * 40
        self.blob_id = blob_sha(self.raw)
        self.rewind_head = False
        self.unprotected = False
        self.incorrect_blob = False
        self.extra_entry = False
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if path == probe.ROOT:
            return {"full_name": probe.REPO}
        if path == probe.ROOT + "/branches/oci-fence-state":
            return {"name": "oci-fence-state",
                    "protected": not self.unprotected}
        if path == probe.ROOT + "/git/ref/heads/oci-fence-state":
            if self.rewind_head and len([x for x in self.calls
                                         if x == path]) > 1:
                return {"ref": probe.REF, "object": {
                    "type": "commit", "sha": "d" * 40}}
            return {"ref": probe.REF, "object": {
                "type": "commit", "sha": self.head}}
        if path == probe.ROOT + "/git/commits/" + self.head:
            return {"sha": self.head, "message": "valid commit subject",
                    "tree": {"sha": self.tree_id},
                    "parents": [{"sha": self.parent}]}
        if path == probe.ROOT + "/git/trees/" + self.tree_id:
            items = [{
                "path": "fence-record.json", "type": "blob", "mode": "100644",
                "size": len(self.raw), "sha": self.blob_id,
            }]
            if self.extra_entry:
                items.append({"path": "hidden", "type": "blob",
                              "mode": "100644", "size": 1, "sha": "e" * 40})
            return {"sha": self.tree_id, "truncated": False,
                    "tree": items}
        if path == (probe.ROOT + "/contents/fence-record.json?ref=" +
                    self.head):
            return {"path": "fence-record.json", "type": "file",
                    "sha": "f" * 40 if self.incorrect_blob else self.blob_id,
                    "encoding": "base64",
                    "content": base64.b64encode(self.raw).decode()}
        raise AssertionError("unexpected GET " + path)


class ReadOnlyVerifierTests(unittest.TestCase):
    def test_realistic_git_shape_v1_strict_and_only_get(self):
        fake = FakeRead()
        view = probe.read(fake, probe.TEST_WINNER)
        self.assertEqual(view.version, 1)
        self.assertEqual(view.phase, "OPEN")
        self.assertEqual(view.reason, "INITIAL")
        self.assertEqual(view.blob, blob_sha(v1.initial_record_bytes()))
        self.assertEqual(len(fake.calls), 7)
        self.assertTrue(all(x.startswith(probe.ROOT + "/") or x == probe.ROOT
                            for x in fake.calls))

    def test_valid_v2_is_recognized_but_never_migrated(self):
        raw = v2.plan_v1_open_upgrade(v1.initial_record_bytes())
        fake = FakeRead(raw)
        result = probe.read(fake, probe.TEST_WINNER)
        self.assertEqual(result.version, 2)
        self.assertEqual(result.phase, "OPEN")
        self.assertEqual(raw, fake.raw)
        self.assertFalse(any("graphql" in x for x in fake.calls))

    def test_invalid_versions_corruption_and_noncannonical_are_refused(self):
        inputs = [
            b'not JSON',
            b'{"version":3}',
            v1.initial_record_bytes() + b"\n",
            v2.plan_v1_open_upgrade(v1.initial_record_bytes()) + b" ",
            v1.initial_record_bytes().replace(b'"version":1',
                b'"version":1,"version":1'),
            b"{}",
            b"\x80" + v1.initial_record_bytes(),
        ]
        for raw in inputs:
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(probe.AuditRejected):
                    probe.read(FakeRead(raw), probe.TEST_WINNER)

    def test_reject_wrong_head_extra_tree_wrong_blob_or_unprotected(self):
        for flag in ("rewind_head", "unprotected",
                     "incorrect_blob", "extra_entry"):
            api = FakeRead()
            setattr(api, flag, True)
            with self.subTest(flag=flag):
                with self.assertRaises(probe.AuditRejected):
                    probe.read(api, probe.TEST_WINNER)

    def test_fails_closed_on_unexpected_head_and_missing_parent(self):
        api = FakeRead()
        api.head = "c" * 40
        with self.assertRaisesRegex(probe.AuditRejected, "UNEXPECTED_FENCE_HEAD"):
            probe.read(api, probe.TEST_WINNER)
        api = FakeRead()
        api.parent = "not-a-SHA"
        with self.assertRaisesRegex(probe.AuditRejected, "BAD_PARENT"):
            probe.read(api, probe.TEST_WINNER)

    def test_readonly_http_allowlist_and_benign_git_commit_message(self):
        class Response(io.BytesIO):
            status = 200
            def __init__(self, body):
                super().__init__(json.dumps(body).encode())
        class Opener:
            def __init__(self, body):
                self.body = body
            def open(self, request, timeout=None):
                self.assert_get = (request.get_method() == "GET")
                assert self.assert_get
                return Response(self.body)

        api = probe.ReadOnlyHttp("fake-token-for-tests-only")
        path = probe.ROOT + "/git/commits/" + probe.TEST_WINNER
        valid = {"sha": probe.TEST_WINNER, "message": "test commit",
                 "tree": {"sha": probe.ORIGINAL_TREE}, "parents": []}
        with patch.object(probe.urllib.request, "build_opener",
                          return_value=Opener(valid)):
            self.assertEqual(api.get(path), valid)
        for bad, route in [
            ({"message": "Resource not accessible by integration"}, path),
            ({"errors": [{"message": "denied"}]}, path),
            ({"message": "permission denied"}, probe.ROOT),
        ]:
            with patch.object(probe.urllib.request, "build_opener",
                              return_value=Opener(bad)):
                with self.assertRaises(probe.AuditRejected):
                    api.get(route)
        for route in [
            probe.ROOT + "/git/commits",
            probe.ROOT + "/git/ref/heads/main",
            "/graphql",
            probe.ROOT + "/actions/secrets",
            "https://attacker.test/",
            probe.ROOT + "/../../repos/another",
        ]:
            with self.subTest(route=route):
                with self.assertRaisesRegex(
                    probe.AuditRejected, "AUDIT_PATH_DENIED"
                ):
                    api.get(route)

    def test_token_is_not_in_repr_or_exception_and_no_write_interface(self):
        api = probe.ReadOnlyHttp("fake-token-for-tests-only")
        self.assertNotIn("fake-token", repr(api))
        self.assertFalse(hasattr(api, "post"))
        self.assertFalse(hasattr(api, "request"))
        self.assertFalse(hasattr(api, "cas"))
        self.assertFalse(hasattr(api, "put"))

    def test_invalid_size_and_too_large_payload_fail_closed(self):
        with self.assertRaises(probe.AuditRejected):
            probe.decode_version(b"x" * 400_001)
        fake = FakeRead(b"x" * 400_001)
        with self.assertRaises(probe.AuditRejected):
            probe.read(fake)
        for entry in (b'', b'[]', b'null'):
            with self.assertRaises(probe.AuditRejected):
                probe.decode_version(entry)


if __name__ == "__main__":
    unittest.main()
