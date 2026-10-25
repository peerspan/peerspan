# Linking feature activation checks

This part of UP-06c.2c checks the upgrade gate from the
[transaction contract](machine-linking-transactions.md#2-feature-activation-and-upgraded-readers).
It verifies a complete feature against signed catalog evidence before a future
caller persists activation. Both Go and Rust use verified
root-chain epochs under the [root checks](linking-root-checks.md). No daemon/coordinator
route, acknowledgment writer, storage migration, or `enable-linking` CLI ships
in this slice. A valid host signature asserts reader support; this checker
cannot inspect a remote binary or prove its migration actually ran.

## Context and outcomes

The caller pins the exact network descriptor, current epoch, current time and
previously persisted feature ID (`-` if no feature is enabled). These pins must
come from locally verified state, never the submitted catalog. The descriptor
and all encodings, catalog limits and strict signed-object checks follow the
[activation checks](linking-activation-checks.md).

The input is a catalog plus a separate complete `{proposal, acknowledgments}`
feature object. Recompute the `lf_` identity, verify the proposal epoch's root raw or
SSHSIG proposal signature and every roster host's raw acknowledgment. The
proposal's network must match the pins; first activation must use the current epoch; all roster keys and
acknowledgments are sorted, distinct, nonempty and exact. A claimed protocol
version, a `join_ack`, or a pending link supplies no missing acknowledgment.

With no previously persisted feature:

- Require `issued_at <= now < issued_at + 24 hours`. Both endpoints are exact
  UTC seconds; a future proposal or the exclusive deadline returns `expired`.
- Derive current admitted hosts from signed legacy direct/invite memberships,
  administrator delegation/removal, host revocation and host leave. Verify
  signatures and apply all known restrictions and exact kept-statement rules.
  Person removal or unbinding alone does not remove host membership.
- Require the proposal roster to equal that full set, after restrictions.
  Missing or extra hosts return `state_conflict`; even a removed host's valid
  acknowledgment cannot excuse an old roster. All hosts, including ones without
  a person binding, must be covered. A proposal host with no supplied signed
  membership is an extra host (`state_conflict`). No host is automatically removed.
- Linking operation records, activations, certificates, device revocations and
  checkpoints cannot establish the roster for the first enablement: those
  formats require the enabled reader gate. Supplying them on this path returns
  `forbidden` after normal shape/index checks. This avoids bootstrapping the
  feature from a link that itself depends on that feature.
- A feature already present in the submitted catalog does not bypass these
  checks. Catalog presence is not evidence of prior durable activation.

With a previously persisted feature ID:

- A different submitted feature returns `state_conflict`. Linking is monotonic;
  a second proposal cannot replace the known feature.
- The same complete feature is an `already_enabled` result. Recheck its
  signatures, context and supplied catalog authority, but do not apply the
  initial deadline or frozen-roster equality to this historical object. Hosts
  can depart and later hosts must prove the same feature through a `join_ack`
  or a complete activation under the existing history rules. Even departure of
  every original roster host does not disable the feature. A current later host
  missing that proof returns `proof_required` with an empty ID list; a supplied
  `join_ack` for a different feature is `invalid`. Activation/certificate
  candidates remain lazy under the existing catalog contract: a complete link
  used for a current host's feature acknowledgment must match the pinned owner
  descriptor; an unused candidate supplies no facts and need not be evaluated.
- Unsupported catalog history remains `upgrade_required`. A caller must retain
  its durable feature when verification fails; this function performs no writes.

Success returns only `{network_id, feature_id, epoch, disposition}`, where
`disposition` is `activate` or `already_enabled`. `activate` means eligible under
the supplied verified snapshot. The future transactional writer must recheck
epoch/roster and the existing feature immediately before its atomic commit.
It must persist the feature monotonically, enforce reader-version mutation/map
gates and preserve it through restart/rotation. This checker does not establish
snapshot freshness or enable writers.

Errors use the activation checker's `invalid`, `expired`, `state_conflict`,
`forbidden`, `proof_required` (with exact dependency IDs where available), and
`upgrade_required` shapes. Multiple simultaneous faults have no precedence.
Unknown kinds are `invalid`. Selected and signed epochs follow the
[root-chain checks](linking-root-checks.md), including historical features surviving
rotation. Policy/group high-water handling and durable freshness remain subsequent work.

## Conformance transport

The state-free probes additionally accept exactly:

```text
kind: "feature_activation"
network_base64: exact pinned descriptor JSON
catalog_base64: exact catalog JSON
feature_base64: exact complete feature JSON
epoch: 0
known_feature_id: "-" | lf_...
now: exact UTC-second timestamp
```

All fields are required. The sum of the three decoded JSON inputs is at most
512 KiB; the existing 2 MiB line limit and stream recovery apply. Success is
exactly `{ok: true, network_id, feature_id, epoch: 0, disposition}`. Failure
uses the activation probe's exact error envelope. The raw signed-object reader
with `kind: "feature"` retains its cryptographic-only behavior.

## Verification

The [recorded results](results/linking-features.json) include 172 feature cases,
the existing reader/path/activation/history regressions and both language gates.

A separate author works only from these contracts and public fixtures, without
reading either implementation. Use independent signing, rather than accepting
one implementation's result as the other's oracle. Cover:

- Complete root/raw and root/SSHSIG proposals, one/multiple hosts, exact roster,
  inclusive issue time, last valid second and exclusive 24-hour deadline.
- Missing/extra/stale roster, omitted/duplicate/unsorted/wrong-host/wrong-feature
  acknowledgments, invalid signatures and absent admitted-host proofs. A
  non-roster `join_ack` never repairs first enablement's frozen roster.
- Legacy direct and invite membership, administrator signatures, valid removal
  with exact kept/omitted statements, host revocation and host leave, and
  unbound hosts. Invalid or conflicting authority remains rejected.
- Old feature in the catalog with unknown durable pin still enforces first
  checks. A known matching feature survives expiry, roster departure and a
  separately acknowledged later join; conflicting known/catalog features fail.
- First enablement refuses circular linking evidence; known-feature verification
  can use independently complete linked-host history.
- Pinned descriptor/epoch mismatch, malformed fields/types/JSON/Base64,
  transport IDs, catalog ordering/aliases, size/framing and recovery.
- Existing reader, path, activation and history conformance regressions.

Build the probes as in the reader checks, then run:

```sh
python3 conformance/linking_features.py \
  --go-probe /absolute/go-probe --rust-probe /absolute/rust-probe
```
