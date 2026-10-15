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
- Leaves the public existing `.github/workflows/guardamar-capacity.yml`
  unchanged, **audit-only**, with no schedule and no launch job.
- Does NOT include Telegram bot source/history, a mutable Git database,
  a new GitHub repo, OCI IAM principal, user-managed state or a new scheduler.

## Manual prerequisites for a later cutover (do NOT paste values to chat)

A human GitHub repository administrator must set the **existing OCI API
identity credentials** as four GitHub repository secrets *in the existing
public Hunter repository*:

`OCI_TENANCY_OCID`, `OCI_USER_OCID`, `OCI_FINGERPRINT`,
`OCI_PRIVATE_KEY`.

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

## Cutover — separate future explicitly reviewed operation

1. Independently verify the dormant new public code against original
   source hashes and run **offline tests**. Configure repository secrets
   but leave the public workflow audit-only. An OCI-free audit may be
   explicitly run in the new repository after secrets are verified.
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
