"""Pinned public release and workflow trust boundary checks (offline only)."""
import ast
import hashlib
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_WORKFLOW = ".github/workflows/guardamar-capacity.yml"
PR_WORKFLOW = ".github/workflows/pr-tests.yml"


class ReleaseBoundaryTests(unittest.TestCase):
    def test_release_manifest_matches_all_tracked_source_bytes(self):
        manifest = json.loads((ROOT / "release-manifest.json").read_text())
        self.assertEqual(manifest["mode"], "audit-only")
        entries = manifest["files"]
        self.assertTrue(isinstance(entries, dict) and len(entries) >= 7)
        for path, want_sha in entries.items():
            with self.subTest(path=path):
                self.assertEqual(len(want_sha), 64)
                self.assertNotIn("..", Path(path).parts)
                self.assertFalse(Path(path).is_absolute())
                self.assertTrue((ROOT / path).is_file())
                self.assertEqual(
                    hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                    want_sha,
                )
        # No unreviewed source, old Git history, infrastructure identifiers,
        # private research, or local caches can be added to this release.
        p = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True,
            capture_output=True,
        )
        tracked = {x.decode() for x in p.stdout.split(bytes((0,))) if x}
        self.assertEqual(tracked, set(entries) | {"release-manifest.json"})

    def test_audit_workflow_is_main_only_and_never_scheduled(self):
        content = (ROOT / AUDIT_WORKFLOW).read_text()
        self.assertIn("  workflow_dispatch:", content)
        self.assertNotIn("  schedule:", content)
        self.assertNotIn("  push:", content)
        self.assertNotIn("  pull_request:", content)
        self.assertNotIn("pull_request_target:", content)
        self.assertIn("github.ref == 'refs/heads/main'", content)
        self.assertIn("inputs.mode == 'audit'", content)
        self.assertIn("    environment: oci-readonly", content)
        self.assertIn("run: python -m automation.guardamar_capacity audit", content)
        self.assertNotIn("guardamar_capacity launch", content)
        self.assertNotIn("environment: oci-launch", content)
        self.assertNotIn("actions: write", content)

    def test_pr_ci_has_no_oci_environment_or_secret_access(self):
        content = (ROOT / PR_WORKFLOW).read_text()
        self.assertIn("  pull_request:", content)
        self.assertIn("permissions:\n  contents: read", content)
        self.assertIn("persist-credentials: false", content)
        self.assertNotIn("secrets.", content)
        self.assertNotIn("environment:", content)
        self.assertNotIn("  schedule:", content)
        self.assertNotIn("pull_request_target:", content)

    def test_executable_audit_has_no_mutating_oci_sdk_api(self):
        content = (ROOT / "automation/guardamar_capacity.py").read_text()
        tree = ast.parse(content)
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        forbidden = {
            "launch_instance", "create_compute_capacity_report",
            "terminate_instance", "update_instance", "create_vnic", "delete_vnic",
            "create_volume", "delete_volume",
        }
        self.assertFalse(attrs & forbidden)
        from automation import guardamar_capacity
        self.assertIs(guardamar_capacity.LAUNCH_BUILD_ENABLED, False)


if __name__ == "__main__":
    unittest.main()
