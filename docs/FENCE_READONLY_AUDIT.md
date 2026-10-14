# Version-aware GET-only OCI fence inspection (experimental PR, no writes)

**Status: review-only.** This module is not an OCI launcher, writer, migration
tool, GitHub CAS transport or authority to claim a VM. It cannot change the
protected `oci-fence-state` branch.

The v1 candidate read method in Draft PR #7 knows v1 only; the bounded v2
proposal in Draft PR #10 has a pure, strict v2 codec but no GitHub I/O.
This new `automation/github_fence_readonly.py` is an isolated audit adapter
that recognizes either canonical schema without auto-converting one into the
other. It has a *GET-only* transport with an exact route allowlist, no POST,
GraphQL mutation, Git ref updates, blob/tree/commit creation or OCI imports.

## Checks

An eligible same-repository unprivileged PR job (`contents:read` only, no
OCI secret/environment) checks the protected branch live. It pins the already
observed historical one-shot commit
`ed78b480980cdfd03841349ac0164d92c66a9add`.
Unexpected HEAD changes must fail the experimental job, rather than quietly
changing which state the test accepts. The probe currently expects exactly
v1 OPEN/INITIAL with the verified original tree/blob and does not upgrade it.

The verifier reads repository identity, branch protection flag, exact state
ref, Git commit, corresponding tree, immutable file content referenced by
the commit, and the state ref once more. It checks a single file `fence-record.json`
with mode 100644, consistent Git tree SHA, file/blob SHA, Base64 content,
size, and the independently computed Git blob SHA-1 over `blob <size>\\0<bytes>`.
Version 1 and version 2 are strictly canonical ASCII JSON with no duplicate,
unknown or reordered fields; v1 and v2 are parsed by their *exact integer*
version. The v2 numeric watermark consistency rules are inherited from
`fence_watermark_v2.py`.

Re-reading the ref confirms that it did not move **between** the two
observations. This is NOT a serializable lock or guarantee the ref will not
move later. The next actual CAS must still use the exact `beforeOid` and
fail closed on a moved ref. This inspector checks only the current commit's
immediate parent count and format; it does **not** cryptographically audit
the entire historical chain back to genesis. It cannot detect every forged
historical forward-only commit by an otherwise authorized writer.

The temporary PR-only live check was executed successfully in
[GitHub Actions #38626377904](https://github.com/vasenko1/guardamar-oci-hunter/actions/runs/38626377904):
`READ_ONLY_OK: protected existing fence at approved v1 no-op revision`.
It was gated to the same-repository test branch, used only ephemeral
`contents:read` and had no OCI environment or secrets. **After collecting
this evidence, the temporary CI network step was removed** so subsequent
pull requests cannot depend on an aging fixed historical HEAD. This Draft
PR retains the reusable GET-only module, optional explicitly invoked
read-only CLI smoke entry point, and pure offline regression tests.
Never turn this verification into a write-capable workflow.

## Acceptance evidence required

- unprivileged CI passes strict v1/v2 offline response-shape and
  replay/spoof/size/hash/ref-movement tests;
- the conditioned live probe reports one `READ_ONLY_OK` against the
  real protected branch and an ephemeral `contents:read` token;
- independently read back current main/state SHA, ledger hash, and branch
  rules, verifying they have not changed;
- keep Draft PR #7/#10/#11 unmerged, do not migrate v1 yet, and maintain the
  original Termux Hunter as the only possible OCI instance creator.

Passing this inspection does **not** confirm v2 write-path interoperability,
Git history-retention feasibility, the future OCI key or IAM scope,
settlement behavior after a provider fault, or authorization for cutover.
