# Completed invitation history

This extends the genesis catalog verifier after
[PR #52](https://github.com/peerspan/peerspan-internal/pull/52), following the
accepted [invitation/redemption contract](machine-linking-transactions.md#invites-from-delegated-administrators).
Go and Rust materialize completed public redemptions into the existing
`catalog_facts` projection and use them as person/host admission proofs. This is
stateless historical verification, with no routes, mutation, token decoding,
first-redemption authorization, persistence or writer readiness.

## Exact public evidence

Support catalog kind `invite_redemption`, whose ID is its exact byte-derived
`pf_` ID. Require exactly the format-1 public fields from the transaction
contract. Support all four explicit mode/action pairs: `host/none`,
`person/admit`, `member/admit`, `member/skip`. Missing actions, other pairs,
inconsistent absent fields, unknowns, duplicate keys and seeds are `invalid`.
Verify each consumed invite's signature and the invite-key raw signature over
the exact existing host/person-member statement. A skipped person half is `-`
and supplies no signature, grant, consumption or admission.

Consumed invites are inline ordinary person envelopes of the exact matching
host/person-invite kind, or the exact legacy public invite shapes. Envelopes
must name the pinned network, a verified chain epoch and operation `-`, have scope 8, and
verify their strict original-person/device signature. Legacy signatures retain
their actual root/person-administrator domain; a device cannot impersonate a
legacy person signer. Both halves in `member/admit` must agree on invite key,
label, expiry, network and exact issuer person/certificate (network root is a
distinct authority). `joined_at <= invite_expires_at`; an asserted earlier
timestamp never establishes past issuer authority. Nonzero invite epochs follow the [root-chain checks](linking-root-checks.md);
network and operation context mismatches are `invalid`.

Only invites inline in a completed public redemption are supported here.
Standalone ordinary invite envelopes and private authorized-invite tokens remain
outside this slice. Register inline envelope `ar_` IDs from exact signed bytes
for checkpoint/root-kept references; indexing them supplies no live authority.
All supplied redemptions are verified, including ones whose authority was
withdrawn. Malformed/signature failures cannot be hidden by an inert grant.

## Derived facts and dependencies

Each usable host half supplies host admission with the signed label. Each
usable `admit` person half supplies person admission with the signed label.
Neither creates a binding or administrator role. Conflicting usable labels are
`state_conflict`. A half made inert by root withdrawal or invite-key revocation
supplies a false subject with member `-` unless another usable admission
established a label. A fully authorized half's label can remain after a sticky
person/host removal, just as for ordinary admissions. Sticky removals/unbindings and invite revocation
apply; invite revocation affects only admission derived from that invite.
Independent valid admissions remain usable.

`member/skip` resolves the exact already-admitted person from independent catalog
evidence and checks its label against the host invite: missing admission is
`proof_required`, known removed/unusable person is `forbidden`, label mismatch
is `invalid`. It supplies no person admission. Ordinary grants and other
redemptions can provide the person's proof, including when catalog order differs.
No redemption can bootstrap its issuer, skipped person or certificate activation.
Cycles are `invalid`. Before entering an uncached redemption, refuse if 24
dependency entries are already busy, sharing the ordinary/activation/retention
bound. An independent valid admission can break an apparent cycle.

Track known host/person invite-half use alongside legacy memberships. Different
subjects consuming the same half are `state_conflict`; host/person halves are
separate. Equivalent aliases/same-subject evidence confer no additional facts.
This stateless projection does not implement first-use consumption transactions
or committed retry semantics.

Every resulting admitted host needs the exact feature roster, join acknowledgment
or complete activation proof under existing rules. Removed hosts need no new
acknowledgment. `catalog_facts` retains its exact shape, array sorting and decoded
512 KiB bound. Unused certificates/activations remain lazy. The first-feature
activation gate still refuses redemption evidence as circular linking authority.

## Live authority and retained membership

Legacy invite halves retain existing legacy history rules: verify current or
root-kept legacy administrator authority and signed redemption time within the
invite window; an expired legacy invite need not still be live now. Its root
withdrawal entries remain exact legacy message digests.

For a new enveloped half, recognize root-issued administrator delegation. An
explicit withdrawal excluding its exact `record:ar_...` or the redemption's
exact `redemption:pf_...` makes that half inert. Format 1 retains no enveloped
halves. An inert half supplies only a known false subject; its structural
certificate/scope/signature still verify, but its unusable issuer need not be
activated. Each half is independently retained by the root; preserving one
does not implicitly preserve the other.

Otherwise verify the exact issuer's complete activation. Current admitted
administrator role or the root's exact kept entries are required. If the invite
is still unexpired (`now < invite_expires_at`) and that exact issuer path is
currently usable, the half establishes historical membership. Invite expiry
must not exceed a device path's expiry. The historical verifier does not infer
the original issue time or reapply a fresh issue's 30-day bound.

After invite expiry or loss of device-path authority, require an applicable
checkpoint containing **both** that consumed invitation's exact `ar_` ID and
this completed redemption's exact `pf_` ID. Missing retention requests the `pf_`
ID; a missing referenced checkpoint member names its own ID. Another redemption,
invite half, record or byte alias is not a substitute. The root's kept entries
and person checkpoint are both necessary when both role and path/expiry
authority were lost. No root kept list extends invite expiry by itself.

For this purpose, checkpoint members additionally accept `pf_` only for a
strict, signature-valid completed `invite_redemption`. Derive its original
issuer person/certificate from the consumed signed invitations; both halves must
agree. Checkpoint signer is that original person or a currently usable,
unaffected strict ancestor with scope 8 and administrator role. A checkpoint may
retain an invitation `ar_` only with a supplied completed redemption naming it;
retention never makes a live invite redeemable. All other existing checkpoint
member/ancestor rules remain. Other `pf_` kinds remain `upgrade_required`.

After known device revocations and all dependencies settle, recheck every
materialized redemption against final authority. Current action/activation APIs
share these catalog facts. Renewal may name an exact redemption `pf_` as its
host membership proof; revalidate its selected host half even when independent
membership also exists. An inert/revoked selected half is `forbidden`.

## Boundary and verification

A historical public redemption contains no authenticated TLS-caller identity.
It cannot prove a first route's caller, prior consumption, freshness, receipt
time or committed outcome. The future writer must enforce current issuer and
invite time bounds, host-key caller/feature proof or person-only current member,
explicit admit/skip conflicts, single-use transactions and stored retries. No
historical result authorizes a fresh redemption. Policy/group selection follows
the [access-state checks](linking-policy-checks.md). durable high-water/feature/freshness, storage/maps/propagation and ceremony remain.

A separate author uses contracts/public vectors and independent signers, without
either implementation:

- All four valid public forms and strict invalid combinations; exact inline
  envelope/legacy signatures, scopes, roles, issuer agreement and member proofs.
- Host/person facts, no binding/role creation, skip proofs/labels and dependency
  cycles/independent resolution; known invite-half conflicts and catalog aliases.
- Feature coverage, sticky restrictions, invite revocation and independent
  admission; exact selected redemption renewal proofs and existing API consumers.
- Live, expired, revoked and unactivated issuers; exact paired checkpoint IDs,
  wrong members/persons, self/sibling/descendant versus root/unaffected ancestors;
  root withdrawals/kept halves and both retention dimensions. Never retain live
  invitations or unrelated `pf_` kinds.
- Existing limits/framing/strictness and all linking regressions; narrowly update
  the previous unsupported expectation for `invite_redemption` only.

```sh
python3 conformance/linking_redemptions.py \
  --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```

Recorded commands, results and limitations are in the
[implementation results](results/linking-redemptions.json).

Verified root rotation and nonzero-epoch catalogs now follow the
[root-chain checks](linking-root-checks.md), including current attestations
and historical transcript preservation.
