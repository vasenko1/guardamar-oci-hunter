"""Completely offline exact-tip two-commit migration preview regressions."""
import base64
import hashlib
import unittest

from automation import durable_fence as v1
from automation import fence_migration_preview as plan
from automation import fence_watermark_v2 as v2
from automation import github_fence_readonly as read


def blob(raw):
    return hashlib.sha1(("blob " + str(len(raw)) + "\0").encode() + raw).hexdigest()


class NoWriteAPI:
    def __init__(self):
        self.raw = v1.initial_record_bytes()
        self.tip = plan.EXPECTED_TIP
        self.genesis = plan.EXPECTED_GENESIS
        self.genesis_parents = []
        self.winner_parent = self.genesis
        self.winner_message = plan.KNOWN_MESSAGE
        self.protected = True
        self.change_after_first_read = False
        self.calls = []
        self.tree = read.ORIGINAL_TREE

    def get(self, path):
        self.calls.append(path)
        root = read.ROOT
        if path == root:
            return {"full_name": read.REPO}
        if path == root + "/branches/oci-fence-state":
            return {"name": "oci-fence-state", "protected": self.protected}
        if path == root + "/git/ref/heads/oci-fence-state":
            calls = self.calls.count(path)
            tip = ("c" * 40 if self.change_after_first_read and calls >= 2
                   else self.tip)
            return {"ref": read.REF, "object": {
                "type": "commit", "sha": tip}}
        if path == root + "/git/commits/" + self.tip:
            return {"sha": self.tip, "message": self.winner_message,
                    "tree": {"sha": self.tree},
                    "parents": [{"sha": self.winner_parent}]}
        if path == root + "/git/commits/" + self.genesis:
            return {"sha": self.genesis, "message": "genesis",
                    "tree": {"sha": self.tree},
                    "parents": self.genesis_parents}
        if path == root + "/git/trees/" + self.tree:
            return {"sha": self.tree, "truncated": False, "tree": [{
                "path": "fence-record.json", "mode": "100644",
                "type": "blob", "size": len(self.raw), "sha": blob(self.raw)}]}
        if path == root + "/contents/fence-record.json?ref=" + self.tip:
            return {"path": "fence-record.json", "type": "file",
                    "encoding": "base64", "sha": blob(self.raw),
                    "content": base64.b64encode(self.raw).decode()}
        raise AssertionError("unexpected GET route: " + path)


class MigrationPreviewTests(unittest.TestCase):
    def test_known_two_commit_history_yields_no_write_exact_proposal(self):
        api = NoWriteAPI()
        result = plan.preview(api)
        self.assertEqual(result.before_oid, plan.EXPECTED_TIP)
        self.assertEqual(result.before_blob_oid, read.ORIGINAL_BLOB)
        self.assertEqual(result.v1_spent_count, 0)
        self.assertEqual(result.candidate_size, len(result.candidate_bytes))
        self.assertEqual(result.candidate_bytes,
                         v2.plan_v1_open_upgrade(v1.initial_record_bytes()))
        self.assertEqual(v2.decode(result.candidate_bytes).claims_committed, 0)
        self.assertEqual(result.after_blob_oid, blob(result.candidate_bytes))
        self.assertTrue(all(path.startswith(read.ROOT) for path in api.calls))
        self.assertEqual(api.calls[-1],
                         read.ROOT + "/git/ref/heads/oci-fence-state")
        self.assertFalse(hasattr(api, "cas"))
        self.assertFalse(hasattr(plan, "migrate"))

    def test_modified_blob_or_noninitial_v1_refuses_proposal(self):
        wrong = [b"bad JSON", v1.encode(v1.FenceRecord(
            "OPEN", "CAPACITY_MISS", ("111",))), v2.plan_v1_open_upgrade(
                v1.initial_record_bytes())]
        for raw in wrong:
            api = NoWriteAPI()
            api.raw = raw
            with self.subTest(raw=raw[:20]), self.assertRaises(read.AuditRejected):
                plan.preview(api)

    def test_changes_to_history_or_rules_are_blocked(self):
        for attr,value in [
            ("winner_parent", "f" * 40),
            ("winner_message", "forged CAS"),
            ("genesis_parents", [{"sha": "f" * 40}]),
            ("protected", False),
            ("tip", "c" * 40),
            ("tree", "d" * 40),
            ("change_after_first_read", True),
        ]:
            api = NoWriteAPI()
            setattr(api, attr, value)
            with self.subTest(attr=attr), self.assertRaises(read.AuditRejected):
                plan.preview(api)

    def test_malformed_commit_fields_are_sanitized_not_leaked(self):
        cases = [
            ("winner", {"sha": plan.EXPECTED_TIP,
                        "message": plan.KNOWN_MESSAGE,
                        "tree": None, "parents": [{"sha": plan.EXPECTED_GENESIS}]}),
            ("winner", {"sha": plan.EXPECTED_TIP,
                        "message": plan.KNOWN_MESSAGE,
                        "tree": {"sha": read.ORIGINAL_TREE},
                        "parents": ["not-a-dict"]}),
            ("genesis", {"sha": plan.EXPECTED_GENESIS,
                         "tree": None, "parents": []}),
            ("genesis", None),
            ("ref", {"ref": read.REF, "object": None}),
        ]
        for target, payload in cases:
            api = NoWriteAPI()
            original_get = api.get
            lookup = {
                "winner": read.ROOT + "/git/commits/" + plan.EXPECTED_TIP,
                "genesis": read.ROOT + "/git/commits/" + plan.EXPECTED_GENESIS,
                "ref": read.ROOT + "/git/ref/heads/oci-fence-state",
            }[target]
            def wrapped(path, count=[0]):
                if path == lookup:
                    count[0] += 1
                    if target != "ref" or count[0] >= 3:
                        return payload
                return original_get(path)
            api.get = wrapped
            with self.subTest(target=target, payload=payload):
                with self.assertRaises(read.AuditRejected):
                    plan.preview(api)

    def test_never_renders_a_write_or_external_api_call(self):
        import ast
        from pathlib import Path
        source=(Path(__file__).resolve().parents[1] /
                "automation/fence_migration_preview.py").read_text()
        attrs={x.attr for x in ast.walk(ast.parse(source))
               if isinstance(x, ast.Attribute)}
        self.assertFalse(attrs & {
            "post","patch","put","request","cas","create_blob","create_tree",
            "launch_instance","create_compute_capacity_report"})
        self.assertNotIn("oci", source.split("import")[1:2])


if __name__ == "__main__":
    unittest.main()
