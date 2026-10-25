# Verified access selection and version high-water

This UP-06c slice adds a reusable, state-free access-state projection in Go and
Rust. It composes the signed catalog, strict readers, current exact path verifier,
and known restrictions. It adds no writer, runtime route, persistence, propagation,
freshness assertion, or permission-decision API. Caller-pinned prior state must be
loaded and committed atomically by the eventual store. Existing catalog facts and
management-action APIs accept these catalog kinds without treating them as grants.

## Inputs and support

The caller pins the descriptor, selected epoch, persisted feature ID (a known
`lf_` ID is required), current time, and prior policy/group high-water state.
The currently supported root/epoch rules remain those of the catalog verifier;
root-chain support can extend those rules independently.

Catalog kinds `policy` and `group` contain exact legacy signed JSON. Ordinary
`person_record` supports `peerspan-policy-v1`, `peerspan-policy-v2` and
`peerspan-group-v1`, operation `-`, in addition to existing supported kinds.
Standalone invitations remain outside this slice. Preserve the complete selected
body, including policy rules, capability rules, trusted hosts and edits. Do not
merge bodies, synthesize edits, or infer access from labels. Versions are positive
unsigned 64-bit integers, including values above signed 64-bit range.

Verify every candidate's strict shape, network, exact signature and ordinary
context before it can affect selection. For ordinary records, verify the complete
structural certificate chain, required scope (1 for policy, 8 for group), owner
identity, and policy expiry no later than the selected certificate path's expiry.
An invalid candidate fails the call; missing structural certificates retain the
existing exact `proof_required` error. Invalid signatures, wrong scope and policy
path-expiry overflow never raise a high-water mark. Certificate structural rules
apply even to an unusable/expired signer; no current-authority fallback is allowed.

Legacy policies use their owner's original-person SSHSIG namespace and existing
policy signed message. Legacy groups use the existing group signed message and
current network-root raw signature or SSHSIG by an original person with a known
root-issued administrator delegation. Unknown administrator keys fail `forbidden`.
Structural recognition of a withdrawn administrator is sufficient to remember a
signed group's version, but never makes its group active. The selected ordinary
group likewise needs a historically recognized delegation to affect selection;
a signature by an arbitrary nonadministrator cannot poison the version mark.

## Selection and authority

Selection precedes current authority and policy-window evaluation. For each policy
owner, the highest version wins; ties prefer the lower SHA-256 of the exact signed
message (the ordinary authorization message for an envelope, the legacy policy
message for a legacy object). For each group name the highest version wins; any
two verified candidates at the same group version with different signed-message
hashes are `state_conflict`, including versions below the current maximum. Equal
message aliases choose the lexicographically smallest exact `pf_` proof ID.

Prior state contains the selected version and signed-message hash for every known
owner/group. The result is their union with verified candidates. A policy candidate
can replace prior state only with a higher version or an equal version with a
lower hash. A group candidate at the prior version must have its exact hash;
different hashes conflict even if a newer group exists. A missing exact prior
selection remains as an inactive row; older permissive candidates cannot replace
it. A newer usable statement can replace an inactive maximum normally. The API
returns the new high-water values even when the selected statement is inactive.

Before a candidate advances selection, require independently recognized person
admission evidence and, for a device, its complete verified issuer activation.
A bare removal, administrator delegation, binding or inert excluded admission
grant cannot supply that admission evidence. Verified historical admission may
remain recognized after removal or a root epoch change; it does not itself supply
current admission or current access authority.
Missing dependencies fail the entire call with `proof_required`; a signature alone
cannot advance the high-water mark. Known unusable final authority is recorded
inactive. Legacy policy owners must be currently admitted. Ordinary policies require the exact currently live
scope-1 path for the owner. Both policy forms use the existing half-open validity
window: `issued_at - 5 minutes <= now < valid_until`, and a 1-to-90-day signed
window. Ordinary groups require a live scope-8 path and current root-issued admin
role; legacy administrator groups require current person admission and admin role.
The current network-root legacy group selection needs no person admission.
Explicit person/host removal, unbinding, device revocation, role withdrawal,
certificate expiry and pending activation cannot be bypassed by another path.
A person checkpoint or administrator kept list cannot revive policy/group access.

An unusable selected candidate returns a row with `active: false` and the existing
path error code, or `expired` for an inactive policy window. Missing exact selected
proof uses its
known version/hash, IDs/body `-`, and `proof_required` with no guessed proof IDs.
Missing, malformed/invalid dependencies or catalog conflicts fail the whole call
rather
than becoming an inactive row. No partial projection is returned on failure.

## API and conformance transport

Go exposes `VerifyAccessState(AccessContext, catalog)`; Rust exposes
`verify_access_state(AccessContext, catalog)`. The context contains descriptor,
epoch, feature/time pins and typed prior rows. Returned rows contain exact selected
body bytes and identifiers, or no selected body for a missing high-water winner.
The state-free probe accepts exactly:

```text
kind: "access_state"
network_base64: exact descriptor JSON
catalog_base64: exact signed catalog JSON
epoch: selected unsigned epoch
known_feature_id: "-" | lf_...
now: exact UTC-second timestamp
prior_policies: [{person_public_key, version, message_hash}, ...]
prior_groups: [{name, version, message_hash}, ...]
```

All fields are required. Prior arrays are strictly sorted by owner key/group name,
with no duplicates; row fields are exact. Keys/names use the existing validators,
versions are positive u64, and hashes are exactly 64 lowercase hex characters.
Maximum 16,384 prior rows total; descriptor/catalog decoded sum <= 512 KiB;
existing object/JSON/Base64/2 MiB framing rules apply. Unknown feature `-` is
`upgrade_required`; wrong persisted feature is `state_conflict`.

Success is exactly `{ok:true, network_id, feature_id, policies:[...], groups:[...]}`.
Policy rows have exactly `{person_public_key, version, message_hash, proof_id,
record_id, body_base64, active, code, required_ids}`. Group rows substitute `name`
for `person_public_key`. Rows are sorted by owner/name. `proof_id` is exact `pf_`;
`record_id` is `ar_` for an ordinary record and `-` for legacy. `body_base64` is
canonical Base64 of the exact catalog object's signed JSON, not the envelope's
unsigned payload. Active rows have `code:"active"`, `required_ids:[]`. Inactive
rows expose no permission grant. Existing failures are exactly `{ok:false,code}`,
with `required_ids` only for `proof_required`.

## Verification

The [recorded results](results/linking-policy-state.json) include 146 independent
policy/group cases and all existing linking suites (2,989 checks per
implementation), full language gates, builds and unchanged fixture hashes.

A separate conformance author derives cases solely from these contracts and public
fixture signers, without inspecting either implementation:

- Legacy/ordinary v1/v2 policies and legacy/ordinary groups; original person,
  current root, active device, exact required scopes/role and owner identity.
- Complete selected bodies, optional fields/edits and exact aliases; unsigned
  indexes cannot substitute signed bytes; invalid signatures/context/shape fail.
- Positive u64 boundaries, maxima, same-version policy lower-hash ties,
  same-version group conflicts and conflict below a later maximum.
- Prior high-water lower/equal/higher versions, retained tie hash, omitted winner,
  no fallback after expiry/removal/revocation/role withdrawal, and newer recovery.
- Policy skew/window endpoints, required certificate expiry cap, ancestor expiry,
  unbinding, pending activation, exact proof IDs and checkpoint non-revival.
- Prior-row sorting/duplicates/types/extra fields, strict encoding/size/framing,
  feature pin gates and existing linking suites as regressions.
