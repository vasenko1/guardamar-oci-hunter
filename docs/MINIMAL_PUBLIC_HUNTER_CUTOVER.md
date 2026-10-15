# Minimal OCI Hunter cutover — one writer, no new infrastructure

**STOP:** This is an **unmerged Draft PR**. Public `main` remains
**read-only**. The original private `guardamar-status-bot` workflow
is the **sole current OCI creator**. Never merge this PR while it is active.

## What remains unchanged

- Existing public `vasenko1/guardamar-oci-hunter` repository (GitHub
  Free: public runners do not consume the private-repo minutes budget).
- Existing OCI module derived from proven original launch code:
  one physical `LaunchInstance` request/run, no SDK retries,
  two complete OCI preflights, 6/2 GB Always Free limits,
  fail-closed 429, existing-target detection and stop on READY.
- Existing GitHub Environment **`oci-readonly`** holding **nine**
  secret values already validated by successful live `mode=candidate`
  audit [#38718139262](https://github.com/vasenko1/guardamar-oci-hunter/actions/runs/38718139262).
  Despite its legacy name, the future *writer* job uses this same
  environment; actual OCI launch privileges remain unverified.
- The original CLI safety switch `OWNER_AUTHORIZED_PHASE_2`:
  no extra GitHub secret is necessary. **Activation is the deliberate
  merge of this writer PR after the old workflow is disabled.**
- Existing Termux five-minute cron on Android; the pending private bot
  [PR #370](https://github.com/vasenko1/guardamar-status-bot/pull/370)
  only changes the GitHub workflow destination; it sends both
  `action=launch` and `mode=tests`. The phone has no OCI credential.

## One missing secret

Add just **`OCI_SSH_PUBLIC_KEY`** to the **existing `oci-readonly`
Environment secrets** in the public Hunter repository. It MUST be the
same original **public** SSH key used by the currently functioning
private `guardamar-status-bot` Hunter. The new candidate pins SHA-256
hashes of the approved original OCI resource selectors and this key:
a different value is blocked rather than launching a wrong VM.

To display the original public key locally on the production phone
(do not paste the output into chat):

```sh
cd ~/bots/guardamar-status
.venv/bin/python -c 'from automation.guardamar_capacity import SSH_PUBLIC_KEY; print(SSH_PUBLIC_KEY)'
```

Paste the single printed `ssh-rsa ...` line into GitHub's
**Settings → Environments → oci-readonly → Environment secrets** as
`OCI_SSH_PUBLIC_KEY`. No new OCI user, SSH pair, GitHub repo,
environment, CAS ledger or other secret is required.

**Important:** the successful read-only audit proves OCI connectivity,
not `LaunchInstance` authorization. If the existing OCI API identity
lacks write permission, the new workflow MUST fail closed. Never broaden
IAM or mint another principal without a separate review.

## Exact safe cutover (requires owner action/authorization)

1. Independently confirm both bot repositories are **private** and
   Git/Actions access works on Android. Check SSH public key is added.
2. Owner **disables OLD** `guardamar-status-bot` workflow in GitHub
   Actions and confirms no queued, waiting, pending or running old
   jobs remain. A small gap in OCI polling is safer than two writers.
   The existing phone continues to check the disabled old workflow and
   skips without dispatching. **Do not re-enable the old workflow.**
3. Only then explicitly authorize merging public Hunter **PR #17**
   into protected main. Its existing workflow then acquires the normal
   `3-58/5` five-minute schedule. Observe a real run before proceeding.
   On 403 or another unsafe result, leave OLD disabled; fix only the
   actual error (no redundant infrastructure).
4. Separately merge private bot **PR #370**, safely fast-forward the
   verified clean production Termux checkout, and run its
   GET-only `--check-dispatch-access`. Confirm the existing `*/5`
   crontab sends to the public Hunter; validate job IDs and outcome.
   The fine-grained PAT must grant **Actions read/write** to the
   public Hunter. This access cannot be verified by a GET alone.
5. Keep both source repositories **private**. Verify their existing
   authenticated Git remotes and bot service after the cutover.
   `guardamar-cams-data` remains public for data consumers.
6. Only after the new writer is stable, remove the original
   `guardamar-status-bot` OCI Actions secrets, **not** the shared
   OCI API key in Oracle. To roll back, first disable/drain the new
   writer; only then re-enable the old one.

GitHub's concurrency groups apply **within a repository**, not
across two repos. Do not assume they prevent cross-repo duplicate VM
creation. Do not merge stacked Draft PRs #3–#14, edit the protected
`oci-fence-state` branch or migrate CAS schemas for this cutover.
