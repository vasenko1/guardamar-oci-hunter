# Bounded state with a monotonically increasing spent-run watermark (v2)

**Status: OFFLINE DESIGN CANDIDATE ONLY. No mutation of the existing
`oci-fence-state` branch, no migration tool, no launch permission.**

## Why this proposal exists

The v1 record lists up to 10,000 spent `GITHUB_RUN_ID` strings inside
`fence-record.json`. At one accepted claim per five minutes this caps the
record at approximately 35 days; the record must not be deleted, reset, pruned,
or arbitrarily re-created to extend the service. The already-proven
`updateRefs(beforeOid)` GitHub CAS updates a protected append-only Git
branch. The original history remains available in that branch.

The proposed v2 document replaces the list with a **strictly increasing
numeric watermark** `highest_spent_run_id`. Every accepted `GITHUB_RUN_ID`
must be greater than that number; a confirmed CAS persists the new maximum
before a hypothetical OCI create. This conservatively rejects older or
out-of-order jobs, even if never spent, rather than claiming any undocumented
GitHub run-ID ordering or sequence guarantee. No timestamp or schedule window
is used to infer safety. An ID is never allowed a second claim, including
after confirmed host-capacity miss, process restart, or an older workflow
arriving late. A counter `claims_committed` is retained for auditing; its
2^63-1 limit is practically distant but is still an explicit fail-closed cap.

## Proposed schema

```json
{"active_memory_gb":null,"active_run_id":null,"claims_committed":0,"highest_spent_run_id":null,"phase":"OPEN","reason":"INITIAL","version":2}
```

Canonical ASCII JSON only, exactly seven fields, maximum 1,024 bytes,
decimal IDs with no leading zeros/signs and <=20 digits, nonnegative
bounded integer claim counter, which must never exceed the numeric
highest spent run ID (an invariant for distinct positive increasing IDs).
This local invariant does **not** prove genuine ancestry of previous commits.
A CLAIMED state must have its active run
exactly equal to the maximum. A HALTED state never grants another claim.
A definite CAPACITY_MISS leaves OPEN but preserves the watermark and counter.
All other results and OCI 429 halt globally. An unknown/lost CAS success
remains unconfirmed and grants **no** OCI action. Calls that see a v1 record
reject it; nothing automatically initializes/migrates it.

The record's length is independent of the number of accepted attempts. A
12,001-claim offline stress test confirms the v1 10,000-ID cap is removed.

## Proof obligations and limitations

Safety invariant by induction for *correct, authorized writers*:
1. Given a durable committed watermark `H`, only ID `x > H` can be claimed.
2. Every successfully acknowledged claim commits `H := x` atomically.
3. Settlement leaves `H` unchanged; subsequent claims again require `> H`.
4. If another writer races against the same prior revision, an exact-before
   CAS permits at most one committed claim (conditional on the live GitHub
   semantics previously tested). All unsuccessful/ambiguous outcomes fail
   closed; an in-flight CLAIMED state blocks new attempts.
5. Hence no accepted ID can be accepted twice. This **does not** authorize
   an OCI request without separate manifest, quota, 429, idempotency and
   break-before-make controls.

GitHub `run_id` must be the trusted runner-supplied numeric value, not a
dispatch input. Numeric increases are intentionally a safety admission
rule, **not a claim** that GitHub will dispatch jobs in numeric order. If
a newly arrived run ID is <= the prior watermark, the system skips that run
rather than loosening the rule. A future run with a higher ID can continue.
No unattended fallback to wall-clock time, clearing the watermark, or
reconciling a previously denied run is permitted.

The public Git ref's append-only history preserves the old v1 spent IDs and
each later CAS state commit; the compact file alone does **not** contain a
full historical list. Git history has its own growth limits and possible
provider outages. At two commits (CLAIM + CAPACITY_MISS) per 5-minute window,
there could be roughly **210,240 new commits per year** in the worst
always-eligible/always-capacity-miss case. Before production, establish
conservative repository-size, object-count, latency and Actions/API-budget
telemetry, backup and an owner-reviewed operational policy. Do not assume
that an append-only public Git branch provides unlimited free storage, and
do not prune/rebase/force-push history to hide growth.

### Documented GitHub hosting constraints (must be measured on the real cadence)

GitHub's [repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits)
recommend at most **10 GB on-disk .git** and a maximum of **6 pushes/minute**
per repository for operational health; its
[large-files guidance](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
suggests ideally under 1 GB, and strongly recommends under 5 GB.
Our CAS is an API ref update, not a conventional `git push`; these numbers
are **health guidance, not a measured or guaranteed budget** for this use.
The [API rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
state **1,000 requests/hour per repository** for standard `GITHUB_TOKEN`
and general secondary limits of **500 content-generating requests/hour**.
The real CAS adapter makes multiple REST and GraphQL calls per accepted claim
and settlement. Measure total repository consumption across all workflows,
not only the successful write count; provider can reject requests earlier.
A 403/429/unknown write acknowledgment must block progression and must
never be worked around with immediate or unattended retry.

Before allowing even a small live schedule, set conservative alert thresholds
based on observed commit-history growth, compressed repository size, workflow
runtime/queue overlap, REST/GraphQL request volume and 403/429 frequency.
A growing repository or approaching limit must trigger a controlled safe
outage and owner review, never automatic commit rewriting or new infrastructure
without explicit approval.

The main/state rulesets have no bypass and prevent non-fast-forward/deletion;
neither rule alone prevents an authorized contents:write process from
appending a malicious fabricated state. The future trusted workflow,
restricted environment and source review are a mandatory trust boundary.

## One-time migration gate (not implemented)

Current protected ledger is **v1 OPEN/INITIAL** with an intentionally
appended no-op test commit at
`ed78b480980cdfd03841349ac0164d92c66a9add`. NEVER reset or rewrite
this history.

A pure `plan_v1_open_upgrade(v1_bytes)` function can construct v2 bytes
only from a canonical v1 OPEN state; CLAIMED, HALTED, ambiguous/malformed
states reject. The migration preserves `phase`, `reason`, the maximum of
all distinct spent v1 run IDs and a claim count equal to list length. Old v1
history remains accessible via prior commits. It does not open a halted
ledger, delete old runs or grant launch permission.

A separately reviewed, **OCI-free**, operator-controlled one-time migration
must:

1. Re-read effective branch protections, source `main`, state HEAD, the
   complete real v1 document and its history/parent chain.
2. Refuse any v1 CLAIMED/HALTED phase, unknown state, rule change, evidence
   mismatch, or unexpected simultaneous writer.
3. Preview exact expected old revision and proposed v2 bytes/hash without
   writing.
4. Obtain explicit owner approval and perform precisely one
   `updateRefs(beforeOid=observed_state_head)` CAS with no retry.
5. Read back exact new parent, tree, full v2 document and still-active
   rulesets; require trustworthy confirmation before any launch workflow.

The live v1 `GitHubCASStore.read()` currently decodes **only v1**. This v2
module is deliberately not connected to it and cannot affect current
operations. A later reviewed adapter version must validate exactly the
selected version and **refuse unapproved auto migration**. A dedicated
OCI-free integration run against the actual backend and protected branch
is required before considering live OCI create. There is no such job here.

## Regression scope

Unprivileged CI exercises >10,000 transitions with compact bytes, v1
history migration including lexically misleading run IDs, invalid schema,
duplicate fields, bool/int confusion, counter exhaustion, out-of-order IDs,
parallel contenders, sticky halt/429, lost CAS ACK, stale claims, and fake
read failures. No OCI SDK, HTTP request, GitHub secret or scheduled writer.
Existing v1 codec/tests remain unchanged and continue to protect the
currently deployed genesis journal.
