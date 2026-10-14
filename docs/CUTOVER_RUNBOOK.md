# OCI Hunter cutover gates — DRAFT (no production change)

## Proven state
The new public main is **audit-only** and its protected GitHub Environment
`oci-readonly` uses a distinct OCI user. The 2026-10-14 [read-only audit](https://github.com/vasenko1/guardamar-oci-hunter/actions/runs/38551708666)
passed. `RESOURCE_GATES_CLEAR` is not proof of host capacity.

Existing live hunter: 1 A1 OCPU, **6 GB primary / 2 GB fallback**,
50 GB boot; 1 GB *capacity-report probe only*. Conservative strict
limits: 2 A1 OCPU, 12 GB RAM, 200 GB shared boot/block storage.

## Trust boundaries
The audit-only identity must never be granted create rights. A future
launcher needs its **own** narrowly scoped OCI user/key and its **own**
protected GitHub Environment; neither is provisioned in this PR. A1
`LaunchInstance` requires distinct permissions for INSTANCE_CREATE,
INSTANCE_IMAGE_READ, VNIC_CREATE, VNIC_ATTACH, and SUBNET_ATTACH.
Host capacity reporting is a report-generation API that Oracle gates by
COMPUTE_CAPACITY_REPORT_CREATE, not covered by read-only inspection.

The public repo must remain an independently sanitized source export:
never mirror original Git history, hard-coded cloud resource identifiers,
or original embedded SSH authorized-key material.

## Before authorization of any future writer
1. Independently review exact launch manifest: fixed selectors,
   shape, OCPU, 6/2 GB, 50 GB boot, SSH authorized key, IMDS settings,
   security and agent configurations, deduplication tags, and cost limits.
2. Run two target and quota preflights, keep SDK automatic retries off,
   stop permanently on any 429, never issue a second physical create
   within a workflow. On ambiguous create response: stop, discover
   target with read operations only, require human decision.
3. Test the full workflow without cloud mutation. Protect new launcher
   Environment: only `main`, no bypass, separate OCI write credential;
   no PR job may access credentials. No scheduled launch until handoff.
4. Stop both **old** GitHub schedule/manual workflow and **old** Termux
   dispatch path; verify all queued/running old jobs are drained.
   Revoke old writer OCI credential before allowing a new writer.
   GitHub concurrency groups do **not** coordinate across repos.
5. Fresh OCI inventory must find no existing or ambiguous target.
   A separate owner approval may authorize one new manual attempt.
   Confirm OCI/Audit state before starting any new bounded schedule
   or changing the Termux dispatcher.
6. Rollback is break-before-make: stop/drain/revoke new authority,
   inventory OCI, then explicitly reauthorize old. A safe outage is
   better than two writers.
7. Only after the new Hunter is stable, test authenticated Mac/Termux
   Git access and backups before making source repos private.

Current PR adds only an **offline policy preview** and regression tests;
no CLI `launch`, OCI mutating SDK calls, secrets, or schedules.

Official references:
- https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/corepolicyreference_topic-Permissions_Required_for_Each_API_Operation.htm
- https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/corepolicyreference_topic-Details_for_Verb__ResourceType_Combinations.htm
- https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments

## Further offline manifest gate — stacked Draft PR #4

This additional candidate constructs an *in-memory launch intent only*. Its
`automation.launch_intent` module does not import OCI and has no create API.
It is not wired to any Actions job, and must remain absent from protected
`main` until this PR passes review. This stage adds no IAM, GitHub secret,
launch schedule, or changed Termux/Oracle behavior.

The exact reviewed live selector values and legacy RSA SSH **public** key
are verified against fixed SHA-256 digests. The values themselves are **not**
in public source or release artifacts. The new expected selector name
`OCI_SSH_PUBLIC_KEY` is a **future launcher-only** protected Environment
value: do not add it to `oci-readonly`, and do not copy the old code's key
material into public commits. An operator must independently verify the
approved SSH authorized key and host-access plan before any real cutover.
Any intentional resource/SSH-key change requires explicit digest update
and code review; callers cannot provide their own allowlist.

The offline intent asserts root compartment equals the OCI tenancy, fixed
Madrid region resource IDs, protected `main` and expected public repository,
a real decimal GitHub run ID, a `PREVIEW_ONLY` approved dry-run selection,
fixed boot 50 GB, one A1 OCPU, approved memory (6 or 2 GB), IMDSv2,
VNIC settings, plugin configuration and both legacy deduplication tags.
Its stable per-run/per-profile UUID5 retry token does not authorize retries:
the future live writer must still enforce one physical write and a
break-before-make owner-approved cutover.

This is **manifest parity only**, not safety parity for the full live
state machine, including 429 detection, run draining, readiness observation
and ambiguous OCI writes. Those remain separately gated.

## Offline state reducer — not a distributed lock

`automation.launch_state` is a deterministic pure-data model. Its tests
cover 429 at preflight/in flight, failure on unknown provider responses,
one **modelled** write-budget consumption, capacity misses, ambiguous
responses, discovery of zero/one/multiple target records, and READY only
after accepted/running/matching/public IPv4.

**Critical limitation:** an immutable `RunState` object by itself is not
a durable fence. If a caller reuses the old `PREPARED` object, the reducer
can derive a new `WAIT_RESPONSE` state; a process restart also discards the
state. The future OCI writer MUST enforce exactly one physical SDK create
call with a separately audited one-shot per-workflow guard, no SDK retry,
and stable retry token. After any uncertain response, no new creation is
allowed until explicit operator investigation. No source here currently
has a production LaunchInstance call.

## Stage 3 — unprivileged OCI SDK model compatibility (Draft PR #5)

The SDK adapter in `automation/oci_sdk_models.py` only constructs the
**real** `oci==2.185.2` typed nested models from the approved offline
intent. It cannot create `ComputeClient`, sign requests or call
`LaunchInstance`. The fake `LaunchInstance` is invoked **once in tests
only**, on a local Mock, with a `NoneRetryStrategy` marker. This must never
be presented as verification of a real cloud write.

`automation/oci_error_policy.py` classifies error responses into a
closed set without exposing exception text. A 429/TooManyRequests takes
precedence even if the same provider message says Out of Host Capacity.
Unexpected errors are ambiguous, requiring manual discovery and stop.

The offline adapter refuses `GITHUB_RUN_ATTEMPT != "1"`, unexpected
event/branch/repository, unprotected refs, invalid commit syntax,
unconsumed simulated state, mismatched retry token, and any deviation
from the fixed reviewed manifest/digests. These are **defense-in-depth,
not authorization**: GitHub environment variables can be supplied by
ordinary code, a new manual dispatch has a new `GITHUB_RUN_ID`, and
GitHub Actions jobs can be restarted. OCI retry tokens expire after
approximately **24 hours**. Therefore no claim of exactly-once cloud
creation is made by this candidate. A durable one-writer fence,
old-credential revocation, fresh live inventory, explicit owner approval,
and no automatic retry after ambiguous writes remain mandatory.

PR CI installs the pinned OCI SDK on the **unprivileged PR test job only**.
No OCI secret, protected GitHub Environment, worker implementation,
scheduled launch, or live action is added.

## Stage 4 — write-ahead CAS fence protocol (offline only; Draft PR #6)

`automation/durable_fence.py` introduces a **pure protocol and validator** for
a future globally shared, durable, compare-and-swap (CAS) state record. The
current code implements **neither** the storage backend nor any OCI request.
It cannot, by itself, prevent a second real launch. Its public document
contains only minimal nonsensitive run identifiers, approved memory profile
and state; **no tenancy, resource IDs, token, public IP or SSH material**.

The protocol is intentionally conservative:
- Every new run must be `GITHUB_RUN_ATTEMPT=1`, approved manual dispatch
  on protected `main`, with a never-before-spent numeric GitHub run ID.
  This is defense in depth, **not authenticated authorization**.
- An atomic, durable `OPEN -> CLAIMED` write must be acknowledged **before**
  a potential future physical `LaunchInstance`; a commit timeout, conflict,
  read error, crash, restart, or stale snapshot forbids the write.
- A definitive OCI `OutOfHostCapacity` reply permits an atomically recorded
  `CLAIMED -> OPEN(CAPACITY_MISS)` transition. Only a **different unused**
  run ID can try again.
- An accepted/ambiguous/error response or 429 turns the global record
  `HALTED`. If finalization fails, it stays `CLAIMED`, which also blocks
  new attempts. A 429 **before** a write also requires a sticky global halt.
  No automatic reconciliation or restart is permitted after ambiguity.
- Exhausted journal/maximum document size triggers a **safe outage**; no
  silent rotation, truncation, overwrite, or recreation of the record.
  The prototype caps the journal at 10,000 distinct runs and serialized state
  at 400,000 bytes, comfortably below GitHub's normal small-file threshold.
  At a 5-minute cadence, 10,000 attempts would be roughly 35 days; durable
  compaction and retention are **not designed yet**. This short bound is an
  operational blocker for unattended long-term deployment, not a reason
  to bypass the safety gate.

**Critical unresolved backend gate:** A real storage provider must support
a *linearizable durable compare-and-swap* across concurrent GitHub workflow
executions, with unambiguous confirmation of a successful commit, durable
reads and restricted writers. Offline mocks test the protocol but **cannot
prove any remote GitHub API's atomicity**. GitHub REST repository Contents
API accepts a previous blob SHA and may return 409 Conflict, but this is
not by itself a verified end-to-end globally shared, strongly consistent
fence. Do not write fence state to protected `main` or loosen main's
ruleset merely to obtain `contents:write`. If GitHub-backed control
state is selected, specify a dedicated least-privilege state surface,
authorization, retention strategy, single-writer owner and adversarial
live CAS tests before connecting OCI create permissions. This PR contains
**no live GitHub write implementation**.

No new public schedule is authorized. The current protocol admits
*manual protected-main first attempts* only; supporting scheduled
dispatches requires a separate reviewed change, not weakening this gate
without evidence.

OCI's `opc_retry_token` has a roughly 24-hour validity window and is
**not** a substitute for the durable claim. GitHub `concurrency` is
scoped to a repository, not a lock shared with the original Hunter.
The break-before-make cutover still requires old GitHub/Termux jobs
disabled and drained, old OCI writer key revoked, new dedicated OCI
writer principal/Environment and explicit operator approval. The
current audit-only `oci-readonly` must never receive write permission.

## Stage 5 — SAME-REPOSITORY GitHub GraphQL fence (Draft PR #7; NOT CONNECTED)

**Revision of prior external-repository design:** no third GitHub repository is
required for this candidate. `automation/github_fence_store.py` pins the
already-existing `vasenko1/guardamar-oci-hunter`, using ONLY the separately
protected, append-only `refs/heads/oci-fence-state` and
`fence-record.json`. This ref has **NOT** been created or initialized;
the source code and workflow on protected `main` are unaffected.

### Credentials and trust boundaries

A future **trusted launcher** GitHub Actions job on reviewed, protected
`main` can request its automatically provided short-lived `GITHUB_TOKEN`
with **per-job `contents: write`**. No new PAT, GitHub App, GitHub account,
repository or Oracle IAM user is required merely for this journal. All PR
tests and existing read-only OCI audit jobs must remain `contents: read`,
without any fence write access. Never expose the future launcher environment
or token to `pull_request`, `pull_request_target`, user input, untrusted
checkout or unreviewed external actions. Do not attach the write token to
`oci-readonly`. **No such privileged job/token wiring is added here.**

**Important compromise:** `contents:write` is repository-wide, NOT
restricted to `oci-fence-state` by GitHub's token scope. Source `main`
must keep its existing active PR-required, strict-CI, non-force, non-delete
ruleset. The **separate state-ref ruleset** must block deletion, force
pushes and unwanted changes without disallowing its own single-parent
forward-only CAS writes. A blanket "restrict updates" or PR-required
rule on the state branch would also block the future Actions writer unless
a separately reviewed narrow bypass is possible. No bypass is currently
approved; test the effective rules with the real future `GITHUB_TOKEN`
*before* enabling an OCI writer. Administrators/collaborators with write
access remain a separate trust consideration; an append-only rule alone
does not prove arbitrary trusted writers could not append a false OPEN
state. If this residual risk cannot be accepted, switch to a dedicated
state repo or another independently authorized storage service. Do **not**
weaken source branch protection to make the ledger work.

### Exact CAS algorithm, unconnected

The candidate uses GitHub REST Git-data GET/POST to read the state-ref tip,
read `fence-record.json` from an immutable commit SHA, create one blob,
tree and single-parent commit, then invokes GraphQL `updateRefs` with
exact `beforeOid`, `force:false`, fixed ref and a verified repository
`node_id` read from the fixed source repo. The HTTP client has an
**allowlist of only the exact Git-data endpoints** needed; it cannot
issue unrelated repository API calls through its request method. The
state ref is not auto-created/repaired/rebased/reset/deleted by this code.

A CAS success requires a complete GraphQL acknowledgement; missing responses,
HTTP errors, conflicts, unexpected content or lost acknowledgements are
**never retried**, and permit no OCI creation. There is no OCI SDK launch
call or scheduled writer in the release candidate. The GitHub experiment
`experiment/fence-cas-validation-20261014` remains a separate benign
experimental branch, NOT this ledger.

### Evidence and work still required

GitHub's `updateRefs` documents atomic updates with exact `beforeOid`
(REST `git/refs` update with `force:false` merely checks fast-forward).
Previous real *connector* experiments on the isolated test branch saw
one acknowledged winner among two and then among six simultaneous
contenders. Losing writes gave generic GraphQL errors. These do **not**
demonstrate the future in-workflow `GITHUB_TOKEN` has permission to
perform this mutation under the future branch rules, nor test this exact
Python HTTP transport against live GitHub. Fake REST/GraphQL tests cover
competition, crash, malformed responses, rate-limit persistence and token
path restriction.

Next authorized tasks: deliberate initialization of an independent-root
`oci-fence-state` ledger (not from `main` history); owner-configured
state-ref ruleset with no unsafe bypass; test actual repo-scoped ephemeral
`GITHUB_TOKEN` permission and real parallel GraphQL CAS operations on
this ref, independent of OCI; verify emergency freeze/recovery and replay
protection; examine git history growth, API limits, and the bounded
10,000-run journal. At a five-minute cadence this journal permits around
35 days of attempts; a durable history-preserving archival/rotation
strategy remains a HARD BLOCKER before unattended production launch.

Old OCI Hunter and Termux dispatcher remain sole writers, unchanged.
New OCI read-only principal and `oci-readonly` Environment retain
read-only authority. The eventual launch credential may come from a
safely rotated key of the old restricted write-capable OCI principal after
effective-IAM review, rather than an unnecessary third OCI user; separate
protected `oci-launch` deployment environment and a verified
break-before-make cutover with old credentials revoked are still mandatory.
**None of that is authorized or implemented by this PR.**

Documentation:
- https://docs.github.com/en/actions/tutorials/authenticate-with-github_token
- https://docs.github.com/en/graphql/reference/git
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
