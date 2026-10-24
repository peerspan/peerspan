# Ordinary admission and binding catalog facts

This part of UP-06c.2 materializes ordinary signed `person_record` grants into
the verifier's private path state. It follows the accepted
[signing](machine-linking-contract.md), [transaction](machine-linking-transactions.md)
and [history](linking-history-checks.md) contracts. The current-action gate in
[PR #49](https://github.com/peerspan/peerspan-internal/pull/49) remains responsible
for new signing authority; this slice reads durable public grants back as history.
It adds no runtime route, writer, database schema or CLI command.

## Supported ordinary grants

Alongside existing catalog evidence, accept strict format-1 person envelopes
with `operation_id: "-"` for exactly:

| Kind | Authority | Effect |
| --- | --- | --- |
| `peerspan-host-bind-v1` | Original person or activated device path with bit 2; same payload person and exact host consent | Record the person/host binding, subject to sticky known restrictions. |
| `peerspan-host-admit-v1` | Original person or activated device path with bit 8 and root-issued administrator authority | Record the payload host's member label and admission. |
| `peerspan-person-admit-v1` | Same bit-8 administrator checks; payload person is the subject, not necessarily the signer | Record the subject person's member label/admission; do not grant an administrator role. |

All envelope/payload/signature/context checks from the strict reader remain.
Resolve exact `ar_` and `pf_` IDs from original signed bytes. Ordinary records
need no link-operation ID; operation-bound records still require their exact
complete activation. The network-root companion remains restricted to linking.
Other ordinary kinds remain `upgrade_required`: restrictive envelopes,
policies/groups, invitations and redemptions need subsequent catalog work.
Unknown or malformed registry entries are `invalid` under the existing reader.
This slice remains genesis-only; a supported ordinary grant's epoch/network
must match the pinned context (`invalid` on mismatch).

## Resolution and durable authority

Verify the original signature, exact structural certificate path, required scope
and complete issuer activation before any grant supplies authority. A parsed
certificate never activates itself. Resolve newly admitted signer persons from
other independently authorized ordinary person admissions when necessary.
An unknown person cannot bootstrap its own admission or role from its own
signature. Authority cycles are `invalid`. Before entering an uncached ordinary
grant, refuse with `invalid` if 24 dependency entries are already actively
resolving (including ordinary, activation and retention work). Resolved grants
do not count; this is not a 24-record catalog cap. Existing certificate/activation
depth-eight limits remain. A valid independent admission
can break an apparent dependency cycle; candidate traversal order supplies no
authority. Admission/binding facts are published only after their own checks.

For durable authority, use the existing history rules: original-person binding
authority is durable; administrator grants need current role or the root's exact
format-2 `record:ar_...` kept entry. Device-signed grants need a currently usable
activated path or an applicable checkpoint retaining that exact `ar_` ID.
The root kept list and person checkpoint are both necessary when both role and
device-path authority have been lost. No checkpoint restores a live path or
administrator role for new actions.

A cryptographically valid administrator grant excluded by an explicit root
administrator withdrawal supplies no admission. Preserve a known false subject
when it has no independent admission; an independent valid admission still works.
Format-1 withdrawals retain no ordinary grants. Malformed/bad-signature records
are errors even when an administrator was withdrawn. A structurally valid
excluded grant need not activate its unusable issuer, because it supplies no
authority. An unrecognized administrator signer remains `forbidden`.

Extend checkpoint member verification to these three ordinary grant kinds.
Check every member's exact signature, person, structural issuer, required scope
and strict-ancestor rule; self/sibling/descendant checkpoints cannot retain it.
An ordinary record ID does not require an unrelated linking transcript for the
record itself, but its device issuer still needs its own complete activation.
Missing endorsements name the exact `ar_` ID, and missing certificates or issuer
activations name their existing `dc_`/`link_` IDs.

Legacy root/person memberships, restrictions and feature evidence retain their
accepted behavior. Equal admission labels and same-person bindings are
idempotent facts; conflicting usable labels/bindings are `state_conflict`.
Person admission alone never binds a host or grants administration. A binding
alone never admits a person/host or activates a certificate. Known person/host
removal, leave, scoped unbinding and key revocations cannot be erased by grants.
All current admitted hosts still require the exact feature roster acknowledgment,
`join_ack` or a complete activation. A new ordinary admission does not assert
reader support. First feature enablement still refuses circular linking records.

Revalidate every materialized ordinary grant after all known device revocations
and historical dependencies have been resolved. A dependency visited before a
later restriction cannot keep unusable signing authority. Grant/history checking
must not reuse cached results to skip first-operation deadline/current-authority
checks. The existing action/activation/feature APIs use this same resolver.
Renewal may reference an exact supported ordinary binding/admission `pf_`; check
that selected proof's remaining authority even when another proof establishes
the same current fact. An excluded proof is `forbidden` for such a reference.

## State-only catalog projection

Expose a reusable `VerifyCatalogFacts` / `verify_catalog_facts` entry point with
the same pinned descriptor, epoch, optional known feature ID and current time.
It returns derived path state only after successful catalog and final history
checks. A supplied complete feature can be verified historically with known ID
`-`; this does not durably enable it. First action authorization still needs a
previously persisted feature pin.

The projection includes all accepted legacy and ordinary facts, known false
subjects, and ancestor activations needed to verify them. Unused activation and
certificate candidates remain lazy; their presence does not establish facts.
This is a bounded fact projection, not a general complete-v1 catalog verifier,
persisted state or proof of coordinator freshness. Future storage must preserve
known restrictive/high-water state and recheck transaction-time authority.

The state-free probes additionally accept exactly:

```text
kind: "catalog_facts"
network_base64: exact pinned descriptor JSON
catalog_base64: exact catalog JSON
epoch: 0
known_feature_id: "-" | lf_...
now: exact UTC-second timestamp
```

All fields are required. Decoded descriptor/catalog total is at most 512 KiB;
existing object/catalog limits and 2 MiB framing apply. Success is exactly:

```text
ok: true
network_id: net_...
feature_id: lf_...
persons: [{person_public_key, member, admitted, administrator}]
hosts: [{host_public_key, member, admitted}]
bindings: [{host_public_key, person_public_key}]
activated_certificate_ids: [dc_...]
revoked_devices: [{person_public_key, device_public_key}]
```

Arrays sort by their public key/ID, and revoked devices sort by person then
device. Member is the verified admission label, or `-` if no usable admission
established one. It may remain with `admitted: false` after a sticky removal;
the label alone supplies no authority. Known unbound bindings use person `-`.
Person administrator is the verified role flag in path state; current usability
also requires admission. Empty arrays are `[]`, never null. Errors retain the
existing exact path envelope. No state is exposed on failure.
Arrays contain subjects present in derived path state: a binding to an unknown
host adds only a binding row, and administrator delegation alone adds no person
row without a separate admission or known restrictive/false-subject fact.

## Verification

A separate author works only from these contracts/public fixtures and independent
signers, without either implementation:

- Ordinary root-person/device host admission, person admission and binding;
  exact host consent, original/subject distinction, labels, new person without
  implied host binding or administrator role, and mandatory feature join proof.
- New-person dependency chains with independently authorized admissions, missing
  signer admission, cycles, independent proof breaking a cycle, no self-created
  person/role/activation, bounded resolution and catalog ordering/aliases.
- Exact scope, current/historical issuer distinction, missing activation and
  certificate proofs, expired/revoked/unbound paths, exact/partial/wrong
  checkpoints, original-person and unaffected strict-ancestor endorsements.
- Administrator withdrawals with exact kept/omitted/v1 entries, independent
  admission, both retention dimensions, and new actions still requiring live role.
- Sticky removals/leave/unbinding and final known revocations; traversal order
  cannot preserve an earlier result's lost authority. Exact ordinary renewal
  references cannot substitute another current proof or bypass first checks.
- Strict contexts/payloads/signatures/byte IDs, conflicts, state projection,
  lazy unused candidates, unsupported ordinary kinds, size/framing/recovery.
- Existing reader/path/activation/history/feature/action regressions; update only
  expectations whose documented support boundary changes.

```sh
python3 conformance/linking_records.py \
  --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```

Recorded checks and the supported scope are in the
[implementation results](results/linking-records.json).
