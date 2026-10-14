# Prepared, NOT APPROVED: one-shot v1→v2 fence migration

**STATUS: DRAFT SOURCE ONLY. DO NOT MERGE OR DISPATCH.** The current
protected `oci-fence-state` branch is intentionally still canonical v1
`OPEN/INITIAL`. The previous live token CAS test is complete and must
NEVER be rerun. No OCI LaunchInstance, OCI credentials, Termux/cron changes
or production creator cutover is part of this staged migration.

## What was found during independent PR-source audit

All preexisting stacked candidate PRs were tested by GitHub's default
`pull_request` **synthetic merge checkout**. Their branch-only tree
omitted four files already merged to main while the SHA-256 release
manifest contained their hashes: the original protected token CAS probe
workflow, script, tests and instruction document. Thus a green PR CI
did not prove standalone Draft branch/file-inventory correctness.

This staging branch copies those **exact four blobs from protected main**
without editing their bytes. A new `source-head-inventory` CI job
checks the exact `github.event.pull_request.head.sha` with read-only
credentials and tests its complete `git ls-files` set and every declared
SHA-256 hash, separately from the existing synthetic merge test.
This gate must remain in any reviewed candidate release.

## Staged implementation: no live run

`.github/workflows/fence-v1-v2-migration.yml` has only manual
`workflow_dispatch`; no schedule, push, pull request or reusable
workflow trigger. It is not installed on protected main, so it cannot
run without an intentional, protected, reviewed merge. Its job always
requires exact `main`, `github.ref_protected=true`, owner actor
`vasenko1`, `run_attempt=1` and two operator-supplied values:

- **confirm**: `MIGRATE-APPROVED-V1-OPEN-TO-V2-ONCE`
- **expected_old_head**: `ed78b480980cdfd03841349ac0164d92c66a9add`

These values are not authorization to act now. The owner must first
review/approve source and separately authorize that ONE event; do not
dispatch merely because the controls become visible. A predecessor
job runs purely synthetic tests with `contents:read`. A separate
single job has repository-scoped, ephemeral `GITHUB_TOKEN` with
`contents:write`, pinned checkout/setup actions and
`persist-credentials:false`. It has no OCI environment or secrets.
GitHub does NOT offer branch-scoped GITHUB_TOKEN: the protected-main
ruleset, exact-ref ruleset, exact endpoint allowlist and reviewed code
are critical additional controls.

`tools/fence_v1_v2_one_shot.py` performs:
1. Check trustworthy GitHub event context and dual confirmation.
2. With GET only, prove exact `ed78…` current head, canonical 111-byte
   v1 `OPEN/INITIAL`, one-file original tree/blob, and exactly known
   winner-to-parentless-genesis ancestry.
3. Verify source `main` equals `GITHUB_SHA`, full live current
   main + fence branch protections, **exactly two** repository rulesets,
   IDs 25036918/25080078, active exact refs, zero bypass actors,
   state non-fast-forward/deletion/linear-history protections, strict
   source-main required-status-check policy.
4. Compute canonical v2 `OPEN/INITIAL` bytes through the reviewed pure
   converter and its independent Git blob SHA-1.
5. Create only immutable Git blob, tree and one-parent commit; verify all
   their returned OIDs, shapes and immutable data before moving any ref.
6. Perform exactly one GitHub GraphQL `updateRefs` against
   `beforeOid=ed78…`, `force:false`, with a per-run
   `clientMutationId`. There is **no retry** on 403/429/500, timeout,
   GraphQL errors, conflicts or unconfirmed acknowledgement.
7. Independently re-read resulting ref, canonical v2 bytes, Git blob,
   proposed commit and unchanged source main, and recheck the exact full
   ruleset policy. A post-CAS error means the update MAY have committed;
   do not reset, re-run, revert or auto-recover.

Do not infer from this script that all GitHub API rights are proven.
The previously successful live CAS test proved one content-preserving
commit via a short-lived Actions token. The migration requests additional
ruleset GETs and a NEW blob/tree; that precise path is tested offline
but **has not been tested on GitHub with its prospective job token**.
If any actual rights, rate limit or API-response mismatch occurs,
the migration must stop and preserve all evidence rather than retry.

## Explicit dependencies and unresolved production gates

The known ledger ref currently has only the parentless genesis and one
content-preserving child. After a future authorized v2 conversion it
should have exactly one new linear commit and its v2 `OPEN/INITIAL`
document. Its original history must remain intact, including original
blob and v1 ancestor commits.

Before adding this workflow to main:
- Reconcile and independently review the stacked Draft PRs #3–#7,
  #10–#13 and this staging PR; avoid accidentally merging the whole
  stack into main. Source inventories must be correct at **actual HEAD**.
- Perform independent owner review of workflow event gates, exact source
  main and state ruleset API data and branch policy. Confirm original
  OCI creator remains sole creator and that no second writer is active.
- Identify effective GitHub token permissions on the new ruleset-read
  paths. Read-only failure is acceptable; granting broader IAM or PAT
  by default is NOT.
- Approve a separate one-time state-ref schema transition *only*.
  This **does not** authorize a new OCI instance or flip old Hunter off.
- Following any acknowledged success, independently verify HEAD, new
  commit/parent, new tree/blob and canonical v2 JSON; failures are
  operator-stop without retry.
- Only in a separate owner-reviewed step consider a real protected v2
  CAS experiment, API/history growth budgets, OCI least-privilege
  credential issuance, and break-before-make old/new creator cutover.

No production cutover, visibility change, scheduled OCI request or actual
migration is authorized by passing a PR check.
