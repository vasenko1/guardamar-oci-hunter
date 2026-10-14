# Unwired v2 GitHub exact-beforeOid CAS backend — release gate

Status: **DRAFT/TEST ONLY. Not merged, not a workflow, not a migration,
no OCI writes, no scheduled use and no new secrets.**

## What was built

`automation/github_fence_v2_store.py` contains `GitHubV2CASStore`
for use with the existing `v2.claim/settle` offline protocol. The class
inherits the existing exact-beforeOid CAS implementation but replaces
the prior hard-coded v1 validation hook with **strict canonical v2 only**.
The original `GitHubCASStore` remains v1 by default, preserving all
older unit tests and refusing v2. This is deliberate version selection, not
a tolerant automatic decoder that could silently upgrade a live branch.

The v2 store's `read()` first verifies the existing exact state ref via the
reviewed read-only inspector: repo identity, basic protected flag, immutable
commit/tree/single 100644 blob, real Git blob SHA-1, canonical v2 JSON and
unchanged HEAD across reads. It returns immutable commit SHA and bytes.
**If the live v1 HEAD is presented, the read fails closed**. The store
cannot perform the one-time v1→v2 migration, and no auto-initialization
method exists.

Before any POST in `cas()`, it re-reads that verified v2 document at the
current protected HEAD, requires the same exact expected revision and
validates the intended old→new state transition, including:

- OPEN→CLAIMED: the new numeric watermark must strictly increase,
  the claim count increases exactly once, the active ID equals that
  watermark, and the record is a valid preview-funded claim.
- OPEN→HALTED: only a no-claim RATE_LIMITED stop with unchanged history.
- CLAIMED→OPEN: only a confirmed CAPACITY_MISS settlement, clearing
  the active run but retaining watermark/history.
- CLAIMED→HALTED: only accepted/blocked/ambiguous/rate-limited results
  with unchanged history and the same active run and memory.
- HALTED: terminal. No writing, opening, wiping history or lowering IDs.

The v2 reducer is STILL the caller responsible for validating GitHub's
trusted workflow environment, approved OCI intent and SDK actions. An
attacker with a repository-wide contents:write token could still attempt
unauthorized allowed state changes; this state-transition whitelist
cannot establish caller legitimacy. GitHub's branch-protection rules
must be independently inspected and cannot cryptographically prove the
intentions of an authorized writer.

After the preflight, the adapter delegates to the tested Git Data POST
sequence and GraphQL `updateRefs(beforeOid=exact_previous_SHA,
force=false)` **once**. If a new writer changes the ref after preflight,
the exact beforeOid must reject. If GraphQL commits but the HTTP response
is lost or unknown, the exception blocks OCI progression. No automatic
repair, read-confirmed assumed grant, claim replay, migration, forced
push, ref cleanup or merge exists.

The write path only creates a blob, tree and linear single-parent commit
before the conditional ref update. If conflict/timeout occurs, some
unreferenced Git objects may remain; the state branch does not move on
confirmed conflict. The design depends on Github's GraphQL CAS semantics
observed in the earlier isolated real-token test; **this exact v2 adapter
has not made any real GitHub write and the v2 schema has not been migrated
live**.

## Testing and integration gates

`tests/test_github_fence_v2_store.py` is an entirely local REST/GraphQL
fake that computes real Git blob SHA-1 and models an immutable commit
chain and protected ref, with no external calls, credentials or OCI.
It tests v1 rejection without POST, claim/settle/halt logic, direct
CAS whitelist, stale revisions, concurrent claims, lost acknowledgement,
GraphQL denial, and tampered or unprotected state. The pre-existing CI
executes all tests with read-only checkout and no OCI SDK mutation.

The adapter's inherited `GitHubHttpTransport` now permits two additional
**GET** routes for branch protection and immutable trees, with no new
mutation path or token scope. Its default v1 behavior remains unchanged.

Before any production release:
1. Resolve the stacked Draft PR ancestry (#3–#7, #10, #11, this PR).
   Each must be retargeted/rebased so no unreviewed code is bundled.
2. Obtain a separate owner-approved, OCI-free, exact-head single-CAS
   upgrade from canonical v1 OPEN to v2; it is NOT coded here. Refuse
   CLAIMED, HALTED, unexpected ref, unexpected ruleset or ambiguous ACK.
3. After upgrade, test the **exact** v2 adapter with an authenticated
   Actions `GITHUB_TOKEN` under an approved no-OCI probe and observe
   the final parent, blob, tree and revision. The prior no-op CAS test
   **must never be rerun**; any new write would be a separate experiment.
4. Audit job credential isolation, OCI user/compartment minimal create
   authorization, double-writer exclusion (old Hunter must be revoked),
   Git history growth, retry/429 handling and state recovery.
5. Only an explicitly approved release may wire a scheduled LaunchInstance.
   Until then, the current Termux/GitHub OCI Hunter remains the sole
   production VM creator, and the state branch remains v1 OPEN/INITIAL.

A passing offline CI run is NOT permission to convert the live state
branch, change IAM, merge into main or activate another OCI writer.
