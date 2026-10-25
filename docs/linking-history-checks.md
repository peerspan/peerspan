# Genesis membership, removals and retained link history

This extends the [catalog/activation verifier](linking-activation-checks.md)
accepted in [PR #46](https://github.com/peerspan/peerspan-internal/pull/46).
It remains stateless, with verified epochs from the [root-chain extension](linking-root-checks.md), without runtime routes, mutation,
persistence, freshness or writer-readiness claims. The existing activation
probe request/success shapes and 512 KiB decoded bound remain unchanged.

## Additional catalog evidence

The verifier additionally supports the existing public shapes for
`host_membership`, `person_membership`, `host_unbinding`, `host_leave`,
`host_revocation`, `invite_revocation`, `person_removal`, `admin_removal`,
`join_ack`, `checkpoint` and delegated `device_revocation`.
Legacy statements follow the [coordination contract](coordination-contract.md)
and strict signing encodings. All supplied legacy facts are signature-checked;
candidate certificates/checkpoints confer no authority merely by being indexed.

Legacy host/person memberships verify both the actual root/person-administrator
invite signature and invite-key member signature, network, keys, label, epoch,
and `joined_at <= invite_expires_at`. A previously redeemed legacy invite need
not still be unexpired now. This rule does not apply to new delegated-invite
envelopes. Invite revocation removes only memberships derived from that invite;
independent valid admissions remain valid. Conflicting consumption of one invite
half by different subjects is `state_conflict`. Host and person halves are
separate. Every currently admitted legacy host must be in the feature roster or
have a valid `join_ack` or complete activation acknowledging that exact host and
feature. Removed/departed hosts
do not require a new acknowledgment. Renewal may name a `host_membership` proof
in place of a legacy `host_admission` proof.

Verified person removal, host revocation/leave, and same-person host unbinding
are sticky. They override otherwise valid admissions/bindings, including facts
recovered from historical activations. An unbinding is scoped to its person and
host; it cannot erase another person's valid binding. Removed people cannot act
or be readmitted. Device-key revocation remains scoped to network and person.
A first activation for a known removed/departed host or permanently unbound
person/host returns `forbidden`; conflicting existing live membership/binding
returns `state_conflict`. Historical verification can preserve the complete
transcript as evidence while deriving removed/unbound state; it never restores
an unusable host or person. All durable-record authority must still verify: if
the removed person also signed an admission as administrator, that record needs
the root's exact kept-record authorization. An unaffected administrator or
network-root admission can instead remain independently valid.
Historical activation may coexist with current independent membership of the
same host/label and same-person binding; verifying history does not reapply
the first-admission precondition. First new admissions still conflict with
existing live membership. Historical eligibility cached during roster/join-proof,
checkpoint or revocation resolution cannot satisfy a first-operation request.
First verification must always enforce its request interval, present owner/admin
authority, target validity/revocation and current admission/binding preconditions,
even when the same complete transcript was already verified as historical data.
Renewal checks the exact selected proof's remaining
authority even when another proof establishes the same current membership.
Missing admission proof is still `proof_required`.

Root-signed administrator removals accept the exact legacy shape or format 2.
Each signature is pinned to the genesis root. Conflicting nonidentical removals
for one person are `state_conflict`, except irreversible escalation to
`revoke_admitted: true`. Equivalent byte aliases are allowed. A removed role
never becomes current again, even with another delegation or checkpoint.
`revoke_admitted: false` preserves only exact listed durable history:

- Legacy statement digests use the v1 `kept` list or v2 `legacy:` entries.
- Person-enveloped link admissions need the exact v2 `record:ar_...` entry.
- `revoke_admitted: true` preserves none. V1 retains no new envelopes.

Cryptographically valid facts whose administrator authority was withdrawn
confer no current membership; an independent valid admission may still do so.
Unknown/unrecognized administrator signatures are `forbidden`, malformed or bad
signatures are `invalid`. New administrator actions always need a current role.

Complete catalog projections retain fully signed completed activations after a
recognized root withdrawal makes their administrator admission unusable. Those
transcripts remain structural provenance, contributing no membership through the
withdrawn admission. Their binding contributes no current binding when its owner
path is unusable and no exact checkpoint retains that binding. Every original
signature, structural certificate path and complete consent still verifies;
malformed or incomplete transcripts are not ignored. This permits irreversible
`revoke_admitted: true` to remove the affected grants while retaining policies'
and groups' monotonic high-water evidence without granting a fallback policy.
An independent usable admission and binding may still establish current facts.

Selecting an exact activation or renewal membership proof for historical
verification still requires its precise administrator keep authorization and
checkpoint dimensions. Aggregate inert provenance cannot satisfy that selected
proof, a first operation, signing authority or live membership.
Records and certificates embedded in an already retained complete activation
are existing evidence for fresh-merge classification. Re-index their exact
original bytes from that prior activation; a virtual catalog expansion cannot
turn them into newly submitted grants when a later restriction makes them inert.
The direct `access_state` and `action_authorization` catalog interfaces apply
the same structural-provenance rule. Independent current-root admission and
current original-person binding of the old host do not activate the inert
certificate, or its inert descendants. A selected policy signed by that
certificate remains a retained inactive maximum with code `forbidden`; a new
scope-1 policy action under it is also `forbidden`, independently of the lost
administrator role. The projected activated-certificate IDs exclude these
certificates. Exact selected historical activation remains `forbidden` without
its precise retained authority. Malformed transcripts and missing structural
dependencies still fail strictly rather than becoming inert evidence.

## Checkpoints and completed activations

Supported checkpoints retain exact `ar_` binding/admission records from a
complete activation or supported [ordinary grants](linking-record-checks.md),
or `dr_` device revocations. Operation-bound records still require that exact
activation; a checkpoint alone cannot activate a pending certificate or turn an
offer into an admission. Ordinary host/person admission and binding with
operation `-` follow the record checks; ordinary unbinding, person removal and
host/invite revocation follow the [restriction checks](linking-restriction-checks.md).
Completed invitation history and paired invite-`ar_`/redemption-`pf_` retention
follow the [redemption checks](linking-redemption-checks.md). Other ordinary kinds
and other `pf_` retention fail closed with `upgrade_required`. Policies, groups, live
invites, certificates, activations and administrator roles are not retainable.

Every retained record's original signature, payload, signer certificate and
structural chain must verify. Resolve its semantic ID from original signed
bytes; retain no other record by resemblance. The checkpoint names the same
network and original *signer* person. Its signature is by that original person
or a currently usable, unaffected strict ancestor of the record's signing
certificate. A delegated checkpoint needs each record's required bits (2 for
binding/unbinding, 8 for administrator admissions/restrictions, 4 for device
revocation), including the current administrator
role for bit 8. A sibling, descendant or the record's own signing certificate
cannot retain it. The root-person checkpoint is durable, may endorse records
after the original device expired, and does not rely on asserted receipt/signing
time. Checkpoints are additive; an omitted ID deletes nothing. Missing referenced
objects use `proof_required` with their exact ID. Authority dependency cycles
fail closed and resolution is bounded.
Checkpoint shapes are strict even when unused. Signature/authority evaluation
is lazy: an otherwise well-formed checkpoint for another network/person or
unneeded record remains inert. A valid applicable endorsement suffices despite
another unusable candidate. A matching checkpoint with a bad signature is
`invalid`; a self/sibling/descendant signer or missing required scope/current
admin role is `forbidden`; expiry/revocation of the checkpoint signer leaves
`proof_required` for the record. A missing referenced member names its own ID.

For a historical complete activation, verify all packet/certificate signatures
and structural delegation, locked references, consent and member labels.
Its durable admission/binding must independently retain usable authority:
original-person binding authority remains durable, administrator admissions
need current role or the root's exact kept-record list, and a device-signed
record needs a currently live path or an applicable checkpoint. A missing
endorsement returns `proof_required` with the affected `ar_` ID. Both the root
kept-record list and person checkpoint are necessary when both role and device
authority were lost. Neither replaces the other.

Historical structural packet checks never make expired/revoked paths live.
Checkpoints do not preserve certificate issuance or activation *authority* for
new operations. First verification still requires currently admitted/live owner
and administrator paths, with all known removals/revocations applied. Root
renewal of C can use C's retained membership/binding after its issuer B expires;
B cannot approve a fresh operation using that checkpoint.

Delegated device revocation requires an activated, currently live strict ancestor
with bit 4, or a valid applicable checkpoint retaining that exact `dr_` record.
Verify its target certificate/key/person/network and strict ancestry before any
retention check. Root-signed revocations are applied before delegated checks;
one revoked issuer cannot authorize another unchecked restriction. A supplied
valid restriction whose historical authority is incomplete produces
`proof_required` with its `dr_` ID; it is never silently discarded. Known
restrictions apply during checkpoint/path evaluation, so a self-supporting cycle
cannot restore an affected path.
Missing issuer certificates/activations name their `dc_`/`link_` dependencies;
retention never replaces that activation prerequisite. Revalidate every derived
historical record and delegated revocation against the final known restrictive
state, including restrictions discovered later in dependency traversal.

## Remaining support boundary

Policies/groups and high-water handling,
other ordinary person envelopes, standalone live invitation tokens and durable feature activation/
durable freshness remain required before writers. These known unsupported
formats return `upgrade_required`; unknown kinds remain `invalid`.

## Verification

Build the probes as in the [reader checks](linking-reader-checks.md), then run:

```sh
python3 conformance/linking_history.py \
  --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```

The [recorded results](results/linking-history.json) include this suite, the
activation/path/reader regressions and language gates. The activation regression
accepts either affected `ar_` ID when two records simultaneously need retention;
partial-checkpoint cases isolate each exact missing ID.

A separate author derives cases from this contract and the accepted signing,
transaction and coordination contracts, without reading either implementation:

- Existing activation, signed-object and exact-path regressions.
- Legacy invite host/person membership, signatures, expiry-at-redemption,
  revoked invites, separate invite halves, same-invite conflicting subjects,
  roster versus exact `join_ack`, and renewal proof resolution.
- Person/host removal, leave and scoped unbinding; unrelated target isolation,
  known removed versus unknown proof, and historical evidence never restoring
  current membership or signing authority.
- V1/v2 admin removals, exact retained legacy/envelope IDs, role withdrawal,
  conflicting removals and irreversible escalation.
- Delegated B to C history after expiry, exact root checkpoint restoring only
  durable records, root renewal of C, missing/wrong/partial endorsements,
  sibling/self/descendant checkpoint signers and conditional administration.
- Sticky delegated revocation, missing issuer activation, nonancestor targets,
  expiry/withdrawal/known root revocation of the issuer and exact `dr_` retention.
- Strict fields/types/encodings/limits, semantic conflicts, dependency cycles,
  unrelated inert candidate isolation, and stream recovery.
- A current independent admission of the requested host, with no roster entry or
  separate `join_ack`, obtains its feature acknowledgment from that same complete
  activation. Historical evidence can verify, but first verification must still
  reject existing live membership, an elapsed request interval, or unusable
  owner/admin authority. Reusing historical work must never return first-operation
  success; pair historical success controls with first-operation rejections.

Verified root rotation and nonzero-epoch catalogs now follow the
[root-chain checks](linking-root-checks.md), including current attestations
and historical transcript preservation.
