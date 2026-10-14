# One-shot protected-branch GITHUB_TOKEN CAS probe — DRAFT

This is an **experiment, not a launcher**, and is intentionally independent
of Draft PRs #3–#7. It has **zero** OCI SDK imports, OCI calls, OCI secrets,
PATs, external GitHub Apps, schedules, and Termux dependencies.

## Precise mutation boundary

- Existing repository: `vasenko1/guardamar-oci-hunter`.
- Trusted workflow: `.github/workflows/fence-token-probe.yml`, dispatched
  **manually on protected main only** after a separately reviewed PR merge.
- Target: independently initialized `refs/heads/oci-fence-state`.
- Pinned genesis commit: `650c36d7a2937efc56868bacc3d3acc5c2559e69`.
- Pinned tree: `5198c8cead35679615df2ec450e55263f5231fa3`.
- Pinned single ledger blob: `295d46ae14f8ebff248507e4a4465306dfd9bef6`.
- The operation **changes the state branch HEAD exactly once on success**.
  Two candidate commits use the identical original tree and parent, with
  distinct messages. One wins the exact-before-OID GraphQL CAS; the other
  must be rejected. Therefore the bytes of `fence-record.json`, its blob
  hash, its JSON fields, and its entire tree stay unchanged. The one new
  commit is a *test-only no-op append* in history, **not** a run claim.
- There is no reset, cleanup force push, journal truncation, archive,
  deletion, or automatic rerun. Once the branch no longer points at the
  pinned genesis SHA, all future invocations fail before any Git-data write.
- A rejected or ambiguous CAS response causes a failed job and must be
  investigated by reading the protected state HEAD. The script **never
  retries**, including after timeout, HTTP 429 or GraphQL errors.
- GraphQL CAS contention is tested with one real ephemeral Actions
  `GITHUB_TOKEN` used from two parallel threads in one trusted job. This
  is evidence for this permission context, not a complete proof of arbitrary
  multi-run distributed linearizability.

## Security controls

- Dispatch only, main only, first attempt only, exact typed input
  `APPEND-ONE-NOOP-COMMIT`. No `pull_request_target`, `pull_request`,
  `push`, `schedule`, `workflow_run`, or `repository_dispatch` trigger.
- First offline fake-transport test job has only `contents:read`.
  The later short-lived mutation job alone has `contents:write`.
- Checkout pins the official action by immutable SHA and
  `persist-credentials:false`. Both jobs use SHA-pinned Python setup.
- No protected environment or secret other than the automatic
  `GITHUB_TOKEN`. In particular **not** `oci-readonly` or `oci-launch`.
- Write script pins repository, branch, genesis, tree and blob; confirms
  main SHA, GitHub source/ref/event/run attempt, basic branch protection,
  genuine parentless genesis, exact file structure and canonical bytes
  before building Git commit objects or issuing GraphQL mutation.
- Creating unattached Git commit objects is not a ref update. If both
  CAS requests are rejected, the branch has not advanced even though
  orphan/unreferenced Git objects may temporarily exist.
- A repository-wide `contents:write` token is not branch-scoped. Source
  main's existing strict-PR/status-check rules and state ref's exact rules
  must remain active; this experiment does not overcome the trust risk of
  a compromised authorized writer. The released script is not a
  replacement for validated, history-preserving durable-fence architecture.

## Execution order

1. Review the self-contained new PR, its tests and workflow permissions.
   Read back exact ruleset `25080078` (state: deletion, non-fast-forward,
   linear history, zero bypass) and ruleset `25036918` (main: PR, strict
   status, no force/deletion, zero bypass); verify unchanged genesis HEAD.
2. Merge **only** this dedicated test PR after required CI passes. Do not
   merge or turn on a launcher from stacked Draft PRs #3–#7.
3. In GitHub Actions, manually choose **Protected OCI fence GITHUB_TOKEN
   CAS probe (one-shot)**, branch **main**, and type the exact confirmation.
   No other inputs, cloud credentials or manual cleanup are needed.
4. Inspect resulting run: exactly two GraphQL CAS contenders, one
   acknowledged winner, final protected branch tip one direct descendant
   of genesis with unchanged tree/blob and unchanged canonical JSON.
   Independently check no PR, schedule or OCI workflow changed.
5. If any job fails or appears ambiguous, **do not rerun**. Inspect the
   branch HEAD, commit parent and ledger bytes read-only, then record
   failure without re-arming the branch or enabling OCI.
6. Update the migration research and Draft PR #7 with observed exact run
   evidence. This test alone does **not** authorize OCI writes or
   settle the 10,000-run bounded journal-retention blocker.

This change remains inert until its PR is independently reviewed,
merged through the existing protected main rules, and manually dispatched.
