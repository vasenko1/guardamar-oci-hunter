"""Non-mutating v1->v2 exact-head migration PREVIEW, not an upgrader.

Only confirms the known orphan-genesis->one verified no-op history, canonical
v1 OPEN/INITIAL bytes, and calculates the candidate v2 bytes and Git blob
OID. No mutating HTTP route, GitHub Action, OCI SDK, token write scope, or
automatic migration is provided. Stop if actual history deviates.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Protocol

from . import durable_fence as v1
from . import fence_watermark_v2 as v2
from . import github_fence_readonly as reader

EXPECTED_TIP = reader.TEST_WINNER
EXPECTED_GENESIS = reader.GENESIS
KNOWN_MESSAGE = "test: fence GITHUB_TOKEN CAS no-op (38622373564/A)"


class OnlyGet(Protocol):
    def get(self, path: str) -> dict: ...


@dataclass(frozen=True)
class ProposedUpgrade:
    before_oid: str
    after_blob_oid: str
    before_blob_oid: str
    candidate_size: int
    v1_spent_count: int
    candidate_bytes: bytes  # never automatically written to GitHub


def preview(api: OnlyGet) -> ProposedUpgrade:
    """Require exact known two-commit history before producing v2 proposal."""
    observed, original = reader.read_snapshot(api, EXPECTED_TIP)
    reader.require(observed.version == 1
                   and observed.phase == "OPEN"
                   and observed.reason == "INITIAL"
                   and observed.revision == EXPECTED_TIP
                   and observed.tree == reader.ORIGINAL_TREE
                   and observed.blob == reader.ORIGINAL_BLOB,
                   "UNEXPECTED_V1_SOURCE")
    reader.require(original == v1.initial_record_bytes(),
                   "SOURCE_BYTES_NOT_INITIAL")

    winner = api.get(reader.ROOT + "/git/commits/" + EXPECTED_TIP)
    reader.require(type(winner) is dict, "NOOP_ANCESTRY_INVALID")
    parents = winner.get("parents")
    tree = winner.get("tree")
    reader.require(winner.get("sha") == EXPECTED_TIP
                   and winner.get("message") == KNOWN_MESSAGE
                   and type(tree) is dict
                   and tree.get("sha") == reader.ORIGINAL_TREE
                   and type(parents) is list and len(parents) == 1
                   and type(parents[0]) is dict
                   and parents[0].get("sha") == EXPECTED_GENESIS,
                   "NOOP_ANCESTRY_INVALID")
    genesis = api.get(reader.ROOT + "/git/commits/" + EXPECTED_GENESIS)
    reader.require(type(genesis) is dict, "GENESIS_ANCESTRY_INVALID")
    genesis_tree = genesis.get("tree")
    reader.require(genesis.get("sha") == EXPECTED_GENESIS
                   and type(genesis_tree) is dict
                   and genesis_tree.get("sha") == reader.ORIGINAL_TREE
                   and genesis.get("parents") == [],
                   "GENESIS_ANCESTRY_INVALID")
    latest = api.get(reader.ROOT + "/git/ref/heads/oci-fence-state")
    reader.require(type(latest) is dict, "STATE_CHANGED_DURING_PREVIEW")
    latest_object = latest.get("object")
    reader.require(latest.get("ref") == reader.REF
                   and type(latest_object) is dict
                   and latest_object.get("sha") == EXPECTED_TIP
                   and latest_object.get("type") == "commit",
                   "STATE_CHANGED_DURING_PREVIEW")

    candidate = v2.plan_v1_open_upgrade(original)
    valid = v2.decode(candidate)
    reader.require(valid.phase == "OPEN" and valid.reason == "INITIAL"
                   and valid.claims_committed == 0
                   and valid.highest_spent_run_id is None,
                   "UNEXPECTED_V2_PROPOSAL")
    oid = hashlib.sha1(
        ("blob " + str(len(candidate)) + "\0").encode("ascii") + candidate
    ).hexdigest()
    return ProposedUpgrade(
        EXPECTED_TIP, oid, observed.blob, len(candidate), 0, candidate
    )
