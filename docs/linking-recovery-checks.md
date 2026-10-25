# Linking feature transfer and coordinator repair

An existing active coordinator can merge complete historical public evidence
without treating its old signatures as a new issuance. A coordinator that lacks
the durable feature pin cannot infer prior activation from a host assertion,
expired proposal, administrator move, or coordinator receipt. This extension
requires an explicit fresh authorization by the current network root to import
that exact feature and snapshot at the actual target. It preserves the feature
ID and never copies a private key.

## Exact authorization

The authorization is exactly `{format: 1, network_id, network_name, epoch,
feature_id, coordinator_address, coordinator_public_key, catalog_sha256,
issued_at, expires_at, signature}`. Keys/IDs/labels use the existing strict
encodings. The name matches the immutable network descriptor; `catalog_sha256`
is lowercase SHA-256 hex of the exact submitted catalog JSON bytes. Times are
whole UTC seconds and `expires_at = issued_at + 300 seconds`. The current root
signs with the existing raw Ed25519 or root SSHSIG convention over:

```
L("peerspan-link-feature-import-v1", network_id, network_name, decimal(epoch),
  feature_id, coordinator_address, coordinator_public_key, catalog_sha256,
  issued_at, expires_at)
```

First use requires `issued_at <= now < expires_at`, the verified root-chain tip
and epoch, and the actual pinned destination address/key. An administrator or
old root cannot replace that root signature. A move signature alone lacks the
feature/snapshot binding and is insufficient. The complete historical feature,
catalog, signed membership, capabilities, restrictions and current caller still
verify independently. Root import authorization grants no host/person/device
authority and does not authorize a host to follow a coordinator pin.

This is a typed current-root signing operation with a fixed template. The local
review names the network, existing feature ID, target address/key, snapshot hash
and deadline before signing. Root material stays on its existing machine or SSH
agent; callers may carry only the public completed authorization. The exact
template is persisted before an external signing step. There is no arbitrary
message-signing route.

Future `issued_at`, invalid signatures and mismatched signed descriptor/hash
fields return 400 `invalid`; the exclusive expiry edge returns 410 `expired`.
A well-formed feature ID differing from the catalog or durable pin returns 409
`state_conflict`; malformed identifier syntax returns 400 `invalid`.

## Coordinator import

`POST /coord/v2/networks/import` is exactly
`{network, catalog, feature_authorization}`. `network` is the existing exact
five-field descriptor naming the actual destination connection. The total
mutation body is at most 1 MiB. The existing public-object/count/response limits
still apply. `feature_authorization` is `"-"` when the coordinator already has
the exact active feature, otherwise the complete authorization above is
required. Its hash binds the original submitted bytes before the coordinator
merges any prior restrictive evidence. A different known feature conflicts.

For a new network, apply the existing registration limit. Verify the immutable
network identity/name and complete catalog. For an active network, independently
verified prior current membership admits the TLS caller before applying the
incoming union, allowing that host to propagate its own signed withdrawal. A
caller unknown in an older backup must instead establish current membership
from the complete verified union. No asserted member row supplies entry. Existing known restrictions and root-chain
prefixes cannot disappear. A known forbidden caller remains forbidden; missing
dependencies may be repaired from the verified union. Historical replication
keeps signed observations and exact access maxima without requiring an expired
issuer to sign a fresh action. Operation-specific drafts still need their
complete activation. No missing feature or membership is inferred from a
pending candidate, unsigned row or local tool label.

Atomically retain the public proofs, exact active feature, reachability member
indexes and exact public import authorization/outcome. The authorization is an
internal durable operation record, not a new public catalog kind. New network
or feature import returns 201 with the exact format-2 map; an exact authorization
retry returns its original stored map with 200 before expiry checks. Existing
active historical repair returns the current verified format-2 map with 200.
The internal outcome stores exactly `{authorization_base64, catalog_base64,
map_base64}`, preserving the original submitted catalog bytes as well as the
merged result. Reusing the same authorization with different catalog bytes
returns 409 `state_conflict`; it never changes the saved outcome.
The coordinator atomically retains a private provenance reference in its
existing statements category, kind `link_feature_import`, subject equal to the
internal `feature-import:` operation ID, and exact original authorization JSON
as its statement. This reference is not exported as a catalog object or used as
authority. Backup/restore requires the reference and matching exact durable
outcome in both directions, detecting accidental deletion of either category.
Deleting both consistently cannot be distinguished from otherwise complete
history rollback; the durable host pin and explicit repair rules still apply.
Stored snapshots are public evidence, never fresh authority. The private import
operation index cannot be queried through the link-request retrieval route.

Without root authorization, a missing durable pin fails closed with
`proof_required` for the exact feature ID. A partial schema-7 backup is refused;
an older complete backup can be explicitly repaired with the same fresh root
authorization. This records new root intent rather than claiming an unproven
past activation. A live linking request never changes coordinator pin: complete
or retire it at its original pin before starting another ceremony.

## Private root review and recovery commands

The Unix-only local route
`POST /v1/networks/{id}/feature-import` takes exactly
`{coordinator_address, coordinator_public_key, import_id, approve}`. A new preview
uses `import_id: "-"`; approval requires the exact previously reviewed `lfi_` ID
and matching frozen target pins. A preview (`false`)
freezes a strict target descriptor, sufficient complete public catalog, current
root and the authorization template above, with signature `"-"`. It signs,
publishes and switches no pin. Explicit approval rechecks the same root, feature,
snapshot, target and deadline before any signature; it never replaces a reviewed
intent with another snapshot. At most eight retained intents per network.

Response is exactly `{import_id, review, signing_requests, committed}`. Review
is exactly `{network_id, network_name, epoch, feature_id, coordinator_address,
coordinator_public_key, catalog_sha256, expires_at, signer_public_key}`.
`import_id` is `lfi_` plus lowercase SHA-256 of
`L("peerspan-link-feature-import-intent-v1", network_id, coordinator_address,
coordinator_public_key, catalog_sha256, issued_at)`.
Signing requests use the existing exact four-field shape, with object type
`feature_import`, the fixed message above, current-root public key, and its
existing `ed25519`/`sshsig` format. They appear only after explicit approval.
The daemon never imports an original/SSH root seed. The CLI's existing original
root provider or SSH agent signs only this persisted typed request.

`POST /v1/networks/{id}/feature-import/{import_id}/signed` takes exactly
`{object_type: "feature_import", signature}` and verifies the persisted message.
`POST /v1/networks/{id}/feature-import/{import_id}/resume` takes `{}`. Both return
the same response. Resume does not imply approval or replace any signature;
after approval and a valid signature it submits the exact persisted import body.
`committed` becomes true only after independently verifying and durably recording
the target's outcome. Lost responses retry the identical authorization; expiry
never silently changes the target/template or creates a new signature.

The private intent is stored in the existing `network_statements` table under
kind `link_feature_import_intent`, subject `import_id`. This private bookkeeping
kind never enters a public catalog or establishes authority. Its strict record
is exactly `{format: 1, import_id, approved, state, network_base64,
catalog_base64, authorization_template_base64, signature, submitted,
result_map_base64}`. States are `review`, `awaiting_signature`, `ready`,
`submitted`, `complete`, `expired`; boolean fields are actual JSON booleans.
Unknown signature/result is `"-"`. Exact public bytes use canonical Base64; no
secret/key is stored here. Preserve the row across Go/Rust restart and ordinary
network projection writes. Expired unsubmitted and completed intents may be
removed after deadline plus 24 hours. Unknown submitted outcomes keep their
public intent until resolved and count toward the eight-intent limit.

`network repair [NETWORK] --coordinator HOST:PORT --coordinator-key KEY` previews
the root import; both target flags are required together. `--approve` approves
the exact printed target/snapshot and drives the fixed root signing step.
`--import-id ID` resumes that exact intent without changing its fields.
Noninteractive `--approve` requires this exact reviewed intent ID. Human
review is on stderr, strict JSON on stdout; noninteractive preview requires the
explicit approval invocation, never a generic `--yes`. An interactive invocation
uses a distinct default-no confirmation. Existing `network move` uses this
root-bound import when the destination lacks the active feature, with the same
reviewed root step. A current administrator move cannot silently substitute a
scope-8 device for this root authorization.

Importing target state alone does not switch this host's coordinator. Apply the
existing independently verified move/successor and current-pin rules before
switching; otherwise retain the current pin and report the prepared target.
Same-pin repair keeps host/device/person keys, active feature, attachment,
integration profile, service and state path. A new machine's live ceremony never
uses this recovery command to change its locked request pin.

## Exact submitted recovery outcomes

Only an exact persisted, explicitly approved import intent and authorization may
interpret the target's original stored outcome as historical recovery evidence.
Verify the outcome's exact reviewed target descriptor, immutable network identity,
feature ID and every PF originally authorized by the frozen snapshot. Independently
verify the complete historical public snapshot. Retain the exact original response,
then union its verified objects with every current local object and run
`VerifyStoredCatalogRepair` and the current complete projection. Preserve the local
coordinator pin, feature, restrictions, operations, root epoch and access high-water;
retain newer local reachability hints. Atomically mark only this original import
intent complete. Completion establishes no target freshness or agent readiness.

Generic live maps still reject omission of any locally retained proof. A move
still requires fresh separately verified destination state and current reviewed
move authority; an old recovery receipt cannot waive those checks or switch a pin.

## Verification

The independent author checks exact signature/hash/name/epoch/pin/time binding,
old-root and administrator refusal, immutable retry after expiry, no partial
write, current member and known-restriction enforcement, same-pin older-backup
repair, and new-target move/repair with the original feature ID. Existing active
imports require no additional root signature and cannot reset the feature.
Both host implementations keep root keys private and review fixed external
templates; installed recovery preserves host/device/person identities and the
existing service.

## Definitive rotation refusal and bounded preview retention

An active pending root rotation is retired only after a strict authenticated
response from the independently pinned actual coordinator definitively refuses
the mutation with `invalid`, `state_conflict` or `operation_conflict`. Before
deleting, a transaction must confirm the exact pending transition is still the
one refused. Deletion retires its proposed seed only; it never installs that
seed or overwrites current root metadata. A different/newer pending transition
remains intact. Local request/TLS construction failures, malformed responses,
transport/5xx failures, missing proofs, quotas and rate limits retain pending
state. `forbidden` also retains it with explicit repair guidance. Ordinary sync
can learn the accepted competing root after the definitively rejected pending
transition is retired. Independent checks cover competing same-epoch root
rotations and unchanged retention across uncertain failures.

Before enforcing the eight-import-intent preview limit, reclaim validated rows
whose deadline plus 24 hours has passed and which were never submitted or have a
completed immutable outcome. Submitted unresolved rows are never reclaimed,
regardless of age. Validate retained records and expiry before deletion; no
public proof, membership, access maximum, receipt in an unresolved row or
network authority is removed. Independent checks fill the preview quota, advance
the decision clock past this retention window, then verify new capacity while
submitted unknown outcomes remain byte-for-byte unchanged.
