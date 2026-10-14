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
