# Minimal OCI migration to keep bot sources private on GitHub Free

**Status: dormant candidate. No workflow has permission to launch an OCI
instance from this repository. DO NOT ACTIVATE UNTIL OLD WRITER IS OFF.**

The public source repository `vasenko1/guardamar-status-bot` currently
holds the **ONLY** active VM creator, running GitHub Actions every five
minutes with an optional accurate Termux dispatch backstop. It also holds
Telegram bot source and must become private. GitHub Free gives a private
repository only 2,000 GitHub-hosted Actions minutes/month; moving these
near-288-daily-run jobs straight into a private repo is not a sustainable
free solution. The existing public `vasenko1/guardamar-oci-hunter` stays
public for a narrow OCI-only workflow, without any Telegram source.

## This small staging PR

- Carries an independent OCI-only `automation/oci_launch_candidate.py`,
  adapted directly from the already working source's one-attempt,
  two-preflight, 6 GB / 2 GB selection, 429-stop and retry-token logic.
  **No OCI VM launch workflow refers to it.**
- Removes real compartment, image, subnet, AD, display-name override and
  SSH public key from code; candidate requires consistent runtime values
  through Secrets and rejects missing selectors before OCI SDK actions.
- Includes the existing OCI launch regression tests, plus public-log
  identifier redaction and "still not wired" checks.
- Extends the existing public `.github/workflows/guardamar-capacity.yml`
  with an explicit manual **candidate** audit option, still **audit-only**:
  no schedule, no launch job, and no OCI write workflow. Once the OCI
  repository secrets are set, this provides a safe live read-only dry run
  before touching the old Hunter.
- Does NOT include Telegram bot source/history, a mutable Git database,
  a new GitHub repo, OCI IAM principal, user-managed state or a new scheduler.

## Manual prerequisites for a later cutover (do NOT paste values to chat)

A human GitHub repository administrator must set the **existing OCI API
identity credentials** as four GitHub repository secrets *in the existing
public Hunter repository*:

`OCI_TENANCY_OCID`, `OCI_USER_OCID`, `OCI_FINGERPRINT`,
`OCI_PRIVATE_KEY`.

**The nine existing `oci-readonly` environment secrets are sufficient
for the manual `mode=candidate` OCI audit. The SSH public key below is
required only for a future separately authorized VM launch; do not add
it merely to run the read-only check.**

The runtime resource-selection secrets are:

`OCI_COMPARTMENT_OCID`, `OCI_AVAILABILITY_DOMAIN`,
`OCI_IMAGE_OCID`, `OCI_SUBNET_OCID`,
`OCI_TARGET_DISPLAY_NAME` (must be the proven `guardamar-bot`),
`OCI_SSH_PUBLIC_KEY` (the **public** SSH key from the approved original
launch configuration).

Only repository Settings → Secrets and variables → Actions is appropriate.
Do not commit values, insert them in workflow inputs, logs or a discussion.
**Do not create a second OCI API key or principal just to complete this
migration.** The original OCI IAM credentials may be moved, but running
both old and new writers at once is forbidden even with separate tokens.

## Prepared activation PR — **DO NOT MERGE WHILE OLD CREATOR IS LIVE**

A separate Draft feature branch `feature/oci-break-before-make-activation`
prepares the SAME existing public Actions workflow for a **single**
periodic OCI writer. Until a separately authorized merge, the protected
public `main` retains read-only/manual OCI audits and **no schedule**.
On merge, GitHub's five-minute `schedule` will start automatically.
That is why merging this PR is the final writer-activation action, not
a harmless deployment step. Do not enable auto-merge.

The future workflow has exactly one launch step and matches the original
Termux dispatch JSON `{"action":"launch"}`, while preserving manual
`mode=candidate` (no LaunchInstance). It skips reruns, requires protected
`main`, uses a single repo-scoped concurrency group and disables its own
schedule when OCI returns READY/BLOCKED/RATE_LIMITED/AMBIGUOUS. A protected
new `oci-launch` GitHub Environment is the write-credential boundary.
It must contain validated **writer-authorized** OCI credentials, all
approved selectors, the **public** SSH key and an explicit switch
`GUARDAMAR_LAUNCH_SWITCH=OWNER_AUTHORIZED_PHASE_2`. The already-tested
`oci-readonly` environment is separate and should remain read-only;
its nine secrets alone do **not** prove OCI IAM permission to launch.

Environment secrets **cannot** be read back from GitHub. Reuse existing
owner-held credential material for the original writer; never log or
paste private keys to GitHub discussions/ChatGPT and never mint a second
OCI writer IAM identity by default. If approved writer credentials cannot
be securely recovered, stop and choose a separately reviewed approach.
The temporary presence of a second set of credentials in `oci-launch`
does not create a second writer without the actual workflow, but extra
write access should last no longer than the cutover requires.

**Before merging this Draft:** independently verify in GitHub that old
`guardamar-status-bot` workflow is `disabled_manually` or inactive;
that NO queued/in_progress/pending old runs remain, including any pending
schedule/dispatch jobs; and that old manual dispatch is refused. Allow
all in-flight original requests to settle. Ensure Termux's current
cron points to the OLD repo and therefore skips when the old workflow is
disabled. This is a short intentional check gap: do NOT leave the old
enabled as insurance. GitHub concurrency is per repository and does NOT
serialize old/new workflows across repositories.

**Then, with owner approval:** merge this one PR only into the protected
main, verify the new writer's single run, and retarget the Termux script
to this existing public repository without touching the public OCI
credentials on Android. If the public workflow fails, fix it while OLD
remains disabled; to roll back, first disable the public workflow and
wait for its jobs to finish before re-enabling the old one. Never
re-enable both.

Any old `ocr-fence-state` CAS v1→v2 migration is a different plan and
is not needed for this single-writer migration. The protected orphan
state branch is left exactly as it was.

## Cutover — separate future explicitly reviewed operation

1. Independently verify the dormant public code through **offline tests**.
   Configure the listed Secrets, then manually dispatch the existing public
   workflow with `mode=candidate`. This performs **READ-ONLY OCI audit** using
   the actual migrated OCI SDK/preflight adapter; it cannot launch an
   instance. Do not use `launch`, which is not a supported workflow input.
2. Review a *separate* **public writer activation** workflow based on the
   existing proven source schedule `3-58/5 * * * *` and concurrency
   group with `cancel-in-progress:false`, exact main/ref checks, a
   first-attempt CLI switch, one physical OCI LaunchInstance, no
   retries/429 stop, and a disable step on READY/unsafe results. It must
   not be merged or dispatched while original OCI workflow is active.
3. Disable the existing `guardamar-status-bot` VM-capacity workflow in
   GitHub settings. Wait for every queued/running job to complete, verify
   the old `launch` is disabled and cannot be redispatched. The phone
   will then see an inactive workflow and SKIP; no OCI calls from Android.
4. Only after step 3, authorize the reviewed new public workflow on
   protected main and enable a single public OCI creator. Confirm its
   first audit/capacity runs. **No second OCI writer.**
5. Update the existing Termux dispatcher endpoint and its
   repo-selected fine-grained Actions PAT from old repo to public hunter.
   The phone continues to do GET/one POST only; it holds no OCI SDK/key.
   Check real five-minute cron execution and actual GitHub run links.
6. Delete **old repository copies of the OCI Actions secrets** after
   new writer is validated; do not delete the shared OCI user's API key
   or IAM grant while the new runner needs it. Leave old workflow
   disabled. Keep emergency rollback break-before-make.
7. Now make both `guardamar-status-bot` and, after independent
   deployment-remote checks, `guardamar-digest-bot` **private** using
   their GitHub Settings. Keep `guardamar-cams-data` public.
   Validate Termux's *authenticated* Git pull and the existing
   `--check-private-access` mode after the visibility change.

**Current blockers:** secrets have not been confirmed on the public
repo, writer activation is NOT yet implemented, old writer is active,
old and new Termux dispatch destinations are not switched and the bot
repositories remain public. Do not treat this document as authorization.

The multiple Draft PRs #3–#14 implementing Git-based v1/v2 fence
CAS/migration are deliberately not prerequisites. A repository
concurrency group and break-before-make with the original existing
OCI target preflight are sufficient for this narrow single-writer
transition, pending independent fault review. GitHub cannot guarantee
scheduled event delivery: retain the existing Termux fallback.
