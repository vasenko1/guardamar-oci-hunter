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

## Stage 5 — concrete GitHub GraphQL CAS store (Draft PR #7, NOT CONNECTED)

The candidate `automation/github_fence_store.py` builds the actual GitHub
REST Git-data + GraphQL `updateRefs` requests. It is deliberately not
referenced by the audit workflow, is not given any GitHub write credential
in PR CI, and has **no OCI SDK client or launch method**. Any failures,
HTTP non-2xx, ambiguous GraphQL errors, incomplete acknowledgements,
read timeouts, conflicts or partial Git object writes cause **failure
without a write grant**; no automatic retries.

GitHub's GraphQL `updateRefs` documents `beforeOid` exact-head comparison
and atomic application. REST `PATCH git/refs` with `force:false` verifies
only fast-forward ancestry; do NOT treat it as equivalent exact-head CAS.
We exercised the linked GitHub connector's `update_ref(expected_sha=...)`
against an **isolated disposable experiment branch** of the public source
repository. Two contenders built sibling commits from the same old head;
only one update was acknowledged, and a later stale attempt was rejected.
The losing calls surfaced generic GraphQL errors, not a stable 409 reason.
This is a **limited real GitHub probe**, not a proof of all network/read
or crash semantics, and not an execution of the new HTTP code. Do not infer
production read/write guarantees solely from this test.

**Separation**: use a *future separate* GitHub state repository
`vasenko1/guardamar-oci-fence` (NOT YET CREATED). The fixed state reference
will be `refs/heads/oci-fence-state` with exactly
`fence-record.json`. A standalone, tightly scoped future GitHub App/token
may write **only the dedicated state repo**. Never give that token
`contents:write` on `vasenko1/guardamar-oci-hunter`, and never expand
PR permissions or add the token to the read-only `oci-readonly` Environment.
Protect the state ref against force pushes, deletion, non-authorized writers,
recreation, manual reset and bypass, including administrators as supported.
The initial record must be provisioned only in a separately approved
operation; there is intentionally no auto-init/auto-repair. The public
experiment branch is not the real state ref and authorizes no OCI action.

The backend's `read()` fetches a branch tip, then fetches the ledger by
**immutable commit SHA**; `cas()` creates a blob, replacement tree and
single-parent commit, then asks GraphQL `updateRefs` to advance the
dedicated ref with exact `beforeOid`. Only an acknowledged mutation can
return `True`. A successful Git commit object creation alone has **no
effect** until the ref advances. Any ambiguous result blocks launches,
even if the ref may already have advanced. No automatic rollback or
retry of GitHub writes is allowed.

Before declaring this an operational backend: initialize/protect the
separate state repository with owner approval, establish restricted API
credentials, independently test a representative set of concurrent
**real GraphQL API** requests using the exact production token/ref,
verify immutable-object read consistency, app token revocation, access
scope, crash recovery, API limits and scheduled cadence, and rehearse
failure/retention behavior. The current PR verifies the HTTP request
shapes and multi-writer transitions on an in-memory GitHub simulation.
Neither credential provisioning nor these live validations are completed.

Git history growth from repeated attempts, GitHub REST/GraphQL rate limits,
and the bounded 10,000-run journal (~35 days at a 5-minute cadence) remain
**blocking issues** for unattended operation. A safe journal rotation or
long-term replacement mechanism must be designed and reviewed separately.
The old Hunter continues running and creating VM attempts as before.
