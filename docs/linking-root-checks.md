# Root chains and current epochs for linking verification

This extends the catalog, activation, feature and action verifiers with the
existing signed root-rotation protocol. It is stateless: callers supply the
selected current epoch and persist the longest verified chain separately.
The network descriptor remains pinned to its genesis root and coordinator.
Neither a rotation nor a coordinator assertion changes those descriptor pins.

## Chain and selected epoch

`rotation` catalog entries contain exactly the existing coordination shape:
`network_id`, `epoch`, `previous_root_public_key`, `root_public_key`,
`rotated_at`, `signature`. Their message is
`L("peerspan-root-rotate-v1", network_id, epoch, previous_root_public_key,
root_public_key, rotated_at)`, signed raw Ed25519 or SSHSIG by the previous root.
Epochs are unsigned integers and must form a contiguous chain starting at one;
the descriptor's genesis key is epoch zero. Root keys must be canonical. A different rotation at
the same epoch is `state_conflict`; equivalent byte aliases are allowed. Bad
shape, signature, predecessor or epoch zero is `invalid`.
Here a byte alias retains every parsed field, including the exact signature;
JSON whitespace or field ordering may differ. A different parsed signature is
a different rotation object even when it signs the same rotation message.
A missing intermediate rotation is `proof_required` with an empty required-ID
list, since its exact transport ID cannot be derived from the missing bytes.

Every catalog consumer first verifies this chain. Its supplied `epoch` must
equal the chain tip. A greater selected epoch is `proof_required` with an empty
list; a smaller selected epoch is `state_conflict`. The existing decoded and
framing bounds apply. This check does not provide durable fork or rollback
protection: the caller must compare every signed rotation against its persisted
prefix before committing any state.

## Current and historical authority

All signed epoch fields refer to a root in the verified chain; a future epoch
without that root is `proof_required`, never a trusted assertion. Local signed
envelope/payload epoch disagreement is self-inconsistent and remains `invalid`
before resolving a missing future root; unavailable lineage cannot hide that
strict record error. Legacy
person and host admissions verify their exact signed epoch. Current root
admissions confer membership only at the chain tip. Legacy person invite
`invite_epoch` follows the same rule. Legacy host invites have no signed epoch:
their root signature must be by the current root. Older root signatures are
cryptographically checked but confer no admission on their own. Administrator
signed durable statements need no re-signing at rotation: a verified historical
delegation still recognizes their signer, subject to the exact kept-record
authorization required after removal and the existing record/path rules.

An administrator delegation is verified under the root of its signed epoch;
only a delegation at the current epoch establishes a current role. An old
delegation still identifies a historical administrator for structural signature
and exact kept-record checks. Administrator removals, person removals, host and
invite revocations signed by any verified root remain sticky. Original-person
signatures remain distinct from network-root signatures even when the key
bytes happen to match: authority follows the signed envelope and selected role.

The existing coordination `attestation` shape is additionally accepted as a
catalog kind: `network_id`, `epoch`, `host_public_key`, `member`, `attested_at`,
`signature`. Its message is `L("peerspan-attest-v1", network_id, epoch,
host_public_key, member, attested_at)`, signed by the root of that epoch. An
attestation at the current epoch establishes current host membership and its
label; an older attestation is verified but inert. Conflicting currently usable
labels remain `state_conflict`. An attested host still needs the existing exact
feature roster, join acknowledgment or complete activation acknowledgment.
Attestation never binds a person, admits a person, or activates a certificate.

Historical complete activations and their exact original records remain
verifiable across rotation. Verified historical person labels are private identity-consistency evidence keyed
by person, original admission epoch and label. A transcript may use a matching
verified admission from its own or an earlier epoch; a later admission cannot
justify a backdated transcript. A current label cannot overwrite the original
label merely because the root rotated. These labels confer no current
membership or role and are not projected as current labels.
Completed `invite_redemption` person-admit halves supply the same private
historical label evidence as ordinary person admissions. Use the original
signed invitation epoch (the person envelope's epoch or legacy `invite_epoch`),
after verifying the invitation, target-member signature, administrator authority,
paired retention/checkpoints and applicable invite restrictions. Never assign
the selected current epoch to that evidence. A skip half supplies no admission;
an excluded administrator grant supplies none. As with a legacy person
membership, an otherwise verified invitation signed by its historical epoch's
root can retain private label evidence after rotation while its current person
membership remains false. Later-epoch invitations cannot establish an earlier
operation's label. None of this evidence restores current authority.
Every epoch in their owner, selection, commit and
admission/binding envelope must agree. A network-root administrator packet and
root companion record verify under that historical epoch's root. An old-root
admission alone cannot establish current host membership: it needs current
attestation or independent current admission. A historical old-root admission
that is no longer usable may coexist as evidence with an independently current
host admission under a different label; it must not overwrite that current
label or membership. Two currently usable different-label admissions still
conflict, including retained administrator admissions. First finalization
keeps every existing conflict check. A historical transcript may still
activate its certificate as evidence, but present path evaluation requires
current admitted persons/hosts, bindings and every existing revocation rule.
Person-enveloped historical admissions retain their existing delegated-signer,
kept-record and checkpoint rules; rotation alone does not erase them. Binding
is original-person authority and remains durable subject to sticky restrictions.
Renewal rechecks the exact selected membership proof: stale-root evidence needs
the matching current attestation even if another proof separately admits a host.
A current attestation can make an exact selected stale root-signed legacy host
admission or host invitation membership usable. This fallback requires a verified
chain-root signature on that original grant, with its signed epoch checked where
the legacy shape carries one. It cannot revive an administrator-signed admission
or invitation excluded by administrator removal or its kept list. An independent
attestation may still admit that host on its own, but renewal selecting the
excluded administrator proof remains `forbidden`; the exact selected reference
cannot be replaced by that independent admission. This applies equally to
ordinary legacy membership and complete public redemption evidence.

Current action envelopes and first activations must use the selected current
epoch. Historical ordinary person envelopes may use any verified chain epoch;
this never reinstates an old role or overrides a removal. Different transcript
epochs and stale first-operation epochs are `invalid`. A historical feature
continues to verify under its proposal epoch's root and keeps the exact same
feature ID after rotation. A first feature activation requires the proposal's
epoch to equal the current selected epoch as well as the existing lifetime and
roster checks. A second feature remains `state_conflict`. An `already_enabled` feature result
reports the selected current epoch while keeping the original feature ID. A
known person without a matching historical admission label makes the transcript
`invalid`; a person entirely unknown still needs its ordinary admission proof.

Fully signed historical coordinator descriptors follow the separate
[original-pin checks](linking-coordinator-history-checks.md); first operations
retain their exact actual coordinator pin.

## Public interface and support boundary

Existing probe request and success shapes are unchanged. `catalog_facts`,
`activation`, `feature_activation` and `action_authorization` accept nonzero selected epochs
with the exact verified chain in their catalog. No new route, writer, storage,
freshness, propagation, signing provider or root-rotation command is introduced.
Existing reader/path APIs continue to check their own signed-object/path
contracts without a catalog. Policies/groups are covered by their own slice.

### Policy/group integration

The access-state selector recognizes a legacy group signature by any verified
chain root as historical structural evidence. A selection by an older root is
inactive with `forbidden`; its version and exact message hash still participate
in the existing maximum selection. It cannot cause fallback to a lower current
root group. A newer usable current-root definition can supersede it normally.
Historical original-person policy observations require independently verified
person admission evidence, including a valid old-root admission that no longer
confers current membership. A bare removal, delegation or excluded grant is not
that evidence. Missing admission fails the whole result with `proof_required`.
An admitted historical person may therefore retain an inactive policy maximum
after rotation while its present signing path remains unusable. None of these
observations restore current person, administrator or device authority.

## Verification

An independent author derives `conformance/linking_roots.py` from this contract
and the accepted coordination/signing/transaction contracts without reading
either implementation. Cases cover:

- One and multiple rotations, arbitrary catalog order, raw and SSH roots,
  equivalent aliases, exact predecessor/epoch/signature/key/field encodings,
  forks, gaps, selected-epoch mismatch, and stream recovery.
- Current root admissions, stale-root admissions and memberships, current
  attestations, person admission and current administrator delegation,
  old-root sticky restrictions/removal and withdrawn-administrator retention.
- Historical complete transcripts/certificates and features surviving rotation;
  old-root transcript injection failing to create current host authority;
  current first activations/actions, stale/mixed epochs, exact renewal proof
  authority, original-person versus root roles, and descriptor pin mismatch.
- Historical transcripts whose only person admission is a completed invitation
  redemption, with original epoch retained across rotation, and controls for
  later-epoch invitation, skip and excluded administrator admission evidence.
- Renewal selecting a removed administrator's excluded legacy admission or host
  invitation stays forbidden despite matching current attestation; stale-root
  signed alternatives remain usable only with their exact matching attestation.
- All prior linking suites and required Go/Rust language gates and host builds.

The [recorded results](results/linking-root-chains.json) include all 3,062 checks
per implementation, builds and completed lightweight language gates. The initial
full Go run failed only at the existing discovery packet-routing assertion; its
unchanged-source baseline evidence and full Rust success are recorded separately.
The retargeted pre-review-fix full language gates both passed. After both review
fixes, full Rust passed; full Go failed only at the unchanged discovery
packet-routing assertion at line 157. The exact final result, prior passing run,
unchanged-source evidence and baseline flake record are retained. Sandbox-only
socket denials are recorded separately from these permitted final runs.
