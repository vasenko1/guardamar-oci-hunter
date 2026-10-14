"""Strict offline ruleset vetting; no GitHub administrator/OCI credentials."""
from __future__ import annotations

import copy
import unittest

from automation.fence_rules_audit import (
    MAIN_REF, STATE_REF, ProtectionBlocked,
    require_main_and_state_protected,
)


def ruleset(ref, types, *, rid=1):
    return {
        "id": rid,
        "name": "offline fixture",
        "target": "branch",
        "enforcement": "active",
        "source": "vasenko1/guardamar-oci-hunter",
        "source_type": "Repository",
        "bypass_actors": [],
        "current_user_can_bypass": "never",
        "conditions": {
            "ref_name": {"include": [ref], "exclude": []},
        },
        "rules": [{"type": t} for t in types],
    }


def approved():
    return [
        ruleset(MAIN_REF, [
            "deletion", "non_fast_forward", "pull_request",
            "required_status_checks",
        ]),
        ruleset(STATE_REF, [
            "deletion", "non_fast_forward", "required_linear_history",
        ], rid=2),
    ]


def check(entries=None, *, exists=True, root=True, sha="a" * 40):
    require_main_and_state_protected(
        approved() if entries is None else entries,
        state_exists=exists,
        main_sha=sha,
        state_root_verified=root,
    )


class SameRepoFenceRulesTests(unittest.TestCase):
    def test_exact_two_protected_refs_pass(self):
        self.assertIsNone(check())

    def test_existing_repository_only_has_main_rules_and_must_stop(self):
        current = approved()[:1]
        with self.assertRaises(ProtectionBlocked):
            check(current)
        with self.assertRaisesRegex(
            ProtectionBlocked, "state_branch_missing"
        ):
            check(exists=False)

    def test_independent_root_and_main_sha_required(self):
        for value in (False, None, "yes"):
            with self.subTest(root=value), self.assertRaises(ProtectionBlocked):
                check(root=value)
        for value in ("wrong", "G" * 40, "a" * 39, None):
            with self.subTest(sha=value), self.assertRaises(ProtectionBlocked):
                check(sha=value)

    def test_active_exact_branch_name_and_no_bypass_required(self):
        attrs = (
            ("enforcement", "evaluate"),
            ("enforcement", "disabled"),
            ("source", "attacker/elsewhere"),
            ("source_type", "Organization"),
            ("bypass_actors", [{"actor_type": "OrganizationAdmin"}]),
            ("target", "tag"),
            ("current_user_can_bypass", "always"),
        )
        for field, value in attrs:
            with self.subTest(field=field):
                entries = approved()
                entries[1][field] = value
                with self.assertRaises(ProtectionBlocked):
                    check(entries)
        for value in (
            ["refs/heads/*"], ["refs/heads/other"],
            ["refs/heads/main", STATE_REF],
        ):
            with self.subTest(ref_names=value):
                entries = approved()
                entries[1]["conditions"]["ref_name"]["include"] = value
                with self.assertRaises(ProtectionBlocked):
                    check(entries)

    def test_state_needs_non_force_and_non_delete_but_must_allow_cas(self):
        for missing in ("deletion", "non_fast_forward"):
            entries = approved()
            entries[1]["rules"] = [
                row for row in entries[1]["rules"] if row["type"] != missing
            ]
            with self.subTest(missing=missing), self.assertRaises(
                ProtectionBlocked
            ):
                check(entries)
        for forbidden in (
            "pull_request", "required_status_checks", "update",
            "merge_queue", "creation",
        ):
            entries = approved()
            entries[1]["rules"].append({"type": forbidden})
            with self.subTest(forbidden=forbidden), self.assertRaises(
                ProtectionBlocked
            ):
                check(entries)

    def test_main_must_retain_strict_pr_ci_and_unrewritable_rules(self):
        for missing in (
            "deletion", "non_fast_forward", "pull_request",
            "required_status_checks",
        ):
            entries = approved()
            entries[0]["rules"] = [
                r for r in entries[0]["rules"] if r["type"] != missing
            ]
            with self.subTest(missing=missing), self.assertRaises(
                ProtectionBlocked
            ):
                check(entries)

    def test_extra_unknown_wildcard_ruleset_must_trigger_re_review(self):
        entries = approved()
        entries.append(ruleset(
            "refs/heads/*", ["deletion", "non_fast_forward"], rid=3
        ))
        with self.assertRaises(ProtectionBlocked):
            check(entries)
        entries = approved() + [dict(id=9, target="tag")]
        with self.assertRaises(ProtectionBlocked):
            check(entries)

    def test_missing_or_malformed_rulesets_always_block(self):
        for bad in (None, [], {}, [{}], [None, None], [1, 2]):
            with self.subTest(value=str(bad)), self.assertRaises(
                ProtectionBlocked
            ):
                check(bad)

    def test_original_main_ruleset_is_only_one_and_never_enough(self):
        # Derived from the actual repository ruleset read on 2026-10-14:
        # ID 25036918, exact refs/heads/main, no bypass, active, 4 rules.
        actual_main_only = ruleset(MAIN_REF, [
            "deletion", "non_fast_forward",
            "pull_request", "required_status_checks",
        ], rid=25036918)
        with self.assertRaises(ProtectionBlocked):
            check([actual_main_only])

    def test_no_network_io_or_oci_calls_in_ruleset_policy(self):
        import ast
        import inspect
        from automation import fence_rules_audit as policy
        tree = ast.parse(inspect.getsource(policy))
        module_names = {
            n.module.split(".")[0]
            for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and n.module
        }
        self.assertFalse(module_names & {
            "oci", "requests", "urllib", "socket", "subprocess",
        })


if __name__ == "__main__":
    unittest.main()
