# Exact-head v1→v2 migration preview: no writes

**Research only. No GitHub branch mutation, no OCI API, no workflow, no
new IAM access and no authorization to migrate.**

The existing state branch still points at the independently proven GitHub
Actions no-op commit
`ed78b480980cdfd03841349ac0164d92c66a9add`; its v1
`fence-record.json` is canonical `OPEN / INITIAL` with zero spent IDs.
Before any future upgrade, `automation/fence_migration_preview.py`
performs an exact-commit, immutable-content and known-ancestry audit.

The pure `preview(api)` function:
- Invokes the previously real-API-tested GET-only inspector, requiring
  exact known state HEAD, protected branch, one 100644 file, original
  tree/blob/contents and stable ref across the read;
- Checks the historical no-op commit has exactly the expected sole parent
  `650c36d7a2937efc56868bacc3d3acc5c2559e69`, the exact winning
  test-run message, and the original tree;
- Reads the genesis commit and demands **no parents** and that original tree;
- Rechecks the state HEAD one more time after ancestry checks;
- Requires exact bytes equal to the first approved canonical v1 OPEN
  document and passes them to pure `v2.plan_v1_open_upgrade`;
- Returns a proposal containing immutable beforeOid, old blob SHA, new
  proposed v2 bytes, new Git blob SHA-1 and byte length.

No method can POST, PATCH, PUT, mutate Git refs, create a Git object,
initialize a record, attach OCI credentials, or run automatically. The
result can be used only as **review material** for a future explicitly
approved once-only exact-beforeOid migration. It cannot be invoked by any
existing workflow and must never auto-run from a scheduled Hunter.

Known-history pins are intentionally strict: the plan must fail if the
real branch changes before approval, including any legitimate subsequent
commit. At that point a new independent review is necessary; never
silently repin to a newer HEAD or force/rewrite the protected ref.

Full ruleset enforcement still needs separate live API verification, as
basic GitHub `protected=true` cannot prove the required exact ruleset.
A successful preview checks the only known two commits, not any future
arbitrary chain. There is no approval yet for a GitHub mutation.
After a separately authorized migration (not here), the strict-v2 adapter
itself needs its own real CAS proof without OCI access. A lost success
acknowledgment is never grounds for an automatic second write.

Stacked Draft dependencies #3–#7, #10–#12 must be reconciled and explicitly
reviewed before any merge, and a measured Git-history growth/API budget,
minimal OCI IAM and old-writer break-before-make are still required.
