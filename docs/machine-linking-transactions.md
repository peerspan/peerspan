# Machine linking: transactions, persistence and recovery

Status: **UP-06b accepted in [PR #43](https://github.com/peerspan/peerspan-internal/pull/43)**,
2026-10-23. The first [UP-06c signed-object readers](linking-reader-checks.md)
verify cryptographic bytes in both languages. The
[certificate-path evaluator](linking-path-checks.md) checks exact signing paths
against independently verified current state. Building that state from catalogs
and activation transcripts, propagation, transaction execution and recovery
remain pending.
The [signing primitives](machine-linking-contract.md) were accepted in
[PR #41](https://github.com/peerspan/peerspan-internal/pull/41). This document
completes their transaction containers and implementation gates. Both hosts and
the Go coordinator must agree on these bytes and outcomes before writers ship.
Rust remains recommended, Go supported, and release configuration deferred.

## 1. Common types

Use `L`, `H`, canonical encodings, times, SSHSIG and bounds from the primitives.
Every field shown is required. `"-"` is an explicit absent value; new JSON never
uses null. Arrays are present even when empty. Unsigned JSON bytes are retained
in `payload_base64`; nobody reconstructs signed bytes by serializing an object.
Byte limits include decoded data and nested proof material. Transport uses the
existing pinned TLS/mTLS identities. An address or a coordinator signature is
never person, membership or policy authority.

### Signed ceremony packet

A packet has exactly:

```text
format: 1
request_id: link_...
role: request | owner | selection | administrator | commit | result
writer_public_key: actual signing public key
person_public_key: original person public key, or "-"
certificate_id: "-" | root | dc_... | network_root | coordinator
payload_base64: exact strict JSON bytes
host_signature: raw Ed25519 or "-"
device_signature: SSHSIG or "-"
authority_signature: SSHSIG, raw Ed25519, or "-" as specified below
```

All applicable signatures cover the **same** message:

```text
M = L("peerspan-link-packet-v1", request_id, role, writer_public_key,
      person_public_key, certificate_id, H(decoded payload_base64))
packet_id = "lp_" + H(L("peerspan-link-packet-id-v1", H(M),
                        host_signature, device_signature, authority_signature))
```

| Role | Writer and required signatures |
| --- | --- |
| `request` | New host key; host raw + new device SSHSIG; authority `-`; person/certificate `-`. |
| `selection`, `commit` | New host key; host raw + new device SSHSIG; authority `-`; selected original person; certificate `-`. |
| `owner` | Original person or active ancestor device key; authority SSHSIG; host/device `-`; original person and `root`/exact certificate ID. |
| `administrator` | Current admin person/device, or current network root; authority SSHSIG for person/device, raw or SSHSIG for network root; host/device `-`. Network root uses person `-`, certificate `network_root`. |
| `result` | Pinned coordinator key; authority raw Ed25519; host/device `-`; person `-`, certificate `coordinator`. |

Resolve the expected key independently. Reject extra/missing signature roles.
Request/selection/commit device signatures prove possession, without giving the
pending device any person authority. Result packets authenticate a response,
without making a coordinator receipt a trusted timestamp or admission proof.

### Network-root authorized records

A root-only administrator may approve linking without using a person signer.
For that case, introduce a companion to the person envelope, without changing
its format:

```text
format: 1
kind: peerspan-host-admit-v1
network_id: net_...
epoch: current root epoch
operation_id: link_...
payload_base64: unsigned host-admission JSON from the primitives
signature: current network root, raw Ed25519 or SSHSIG
```

```text
R = L("peerspan-root-authorization-v1", kind, network_id, epoch,
      operation_id, H(decoded payload_base64))
record_id = "rr_" + H(L("peerspan-root-authorized-record-v1", H(R), signature))
```

V1 restricts this companion to linking host admission. It is not an alternative
format for root rotation, administrator delegation/removal, or attestation. Its
operation ID is mandatory; it cannot be redeemed outside its complete activation.

### Proof catalog

A catalog is `{format: 1, network_id, objects}`. Each object has exactly
`{id, kind, body_base64}`. Its decoded body is strict JSON; its transport ID is:

```text
id = "pf_" + H(L("peerspan-link-proof-v1", kind, H(decoded body_base64)))
```

Sort by ID, reject duplicate IDs and conflicting semantic IDs. Resolve semantic
references (`dc_`, `ar_`, `rr_`, `lp_`, `lf_`) from decoded objects, never from a
coordinator's asserted index. Catalog kinds are `rotation`, `admin_delegation`,
`admin_removal`, `person_admission`, `person_membership`, `host_membership`,
`host_admission`, `host_binding`, `host_unbinding`, `host_leave`,
`host_revocation`, `invite_revocation`, `person_removal`, `attestation`, `group`, `policy`,
`feature`, `join_ack`, `certificate`, `device_revocation`, `checkpoint`,
`person_record`, `root_record`, `activation`, and `invite_redemption`.
Legacy kinds contain their existing public statement shape; new kinds contain
only the shapes specified here or in the primitives. No token/private seed is
accepted. `admin_removal` accepts its existing shape or format 2 (§5).

A submitted catalog is at most 1 MiB / 4,096 objects. A full map may carry up to
8 MiB decoded public objects within its existing 16 MiB response limit. It must include all proofs
not already in verified durable state. Missing dependencies return
`proof_required`, with IDs, rather than silently trusting the coordinator or
performing an arbitrary fetch. Reject authority dependency cycles; resolve
ancestor activations before using their keys. Merely parsing a certificate does
not activate it. A certificate and its own activation can reference one another
as data; that certificate must never authorize its own activation. Index nested
public statements from their exact original JSON slices inside packet payloads,
not a reserialization; this preserves their `pf_` IDs across Go/Rust recovery.

## 2. Feature activation and upgraded readers

Before any delegated write, the network root signs a feature proposal with
exactly `format: 1`, `network_id`, `epoch`, `version: 1`, `issued_at`,
`host_public_keys` (sorted, distinct current admitted hosts), and `signature`:

```text
F = L("peerspan-link-feature-v1", network_id, epoch, "1", issued_at,
      host_count, ...host_public_keys)
feature_id = "lf_" + H(F)
```

The signature is raw Ed25519 or SSHSIG by the root of that epoch. Every listed
host signs `{format: 1, feature_id, host_public_key, signature}` over
`L("peerspan-link-feature-ack-v1", feature_id, host_public_key)` with its host key.
A feature object is `{proposal, acknowledgments}`, acknowledgments sorted by
host key, exactly one for each proposal host. Each host checks the proposal's
roster against its current verified roster before acknowledging. The root and
coordinator recheck the roster before activation; a concurrent join/leave
requires a fresh proposal. Empty rosters are invalid.

An acknowledgment means this host has installed the new reader/storage support;
it is signed only by an upgraded daemon. The feature is persisted atomically at
coordinator and hosts, is monotonic, and survives root rotation and departure of
roster hosts. A second distinct feature for the same network returns conflict.
An identical retry succeeds. A root rotation cannot turn the feature off.
Offline/old hosts must be upgraded or explicitly removed before activation.

`network enable-linking --network ID [--root-key PATH]` prepares a root-signed
proposal, publishes it, collects acknowledgments, then submits the complete
feature. Upgraded daemons acknowledge a pending proposal only after their local
migration and reader support are ready and their verified roster/epoch matches.
This acknowledges reader capability, not an owner delegation. Pending proposals
never enter the active catalog. Their first activation must occur before
`issued_at + 24 hours`, with current root epoch and unchanged roster. A stale or
incomplete proposal identifies required upgrades; it never auto-removes a host.
Preparing, acknowledging and activating use separate routes below. Root CLI
signing follows the existing raw/SSH-root provider, without copying that key.

After activation, every newly admitted host must acknowledge that exact feature.
A link commit supplies this acknowledgment through its signed `feature_id`.
Explicit invite/admission joins supply a `join_ack` object with the same fields
and host signature as a feature acknowledgment. This does not authorize their
membership; it is an additional required capability assertion.

Coordinator registration/sync/join callers advertise `linking_version: 1` and
request v2 maps. An activated network refuses old mutation/map paths with
`426 upgrade_required`; it never returns a legacy map omitting delegated proof.
Old host binaries also reject the new local database version. A claimed version
without the signed acknowledgment is insufficient for admission. A coordinator
that omits an already known feature cannot downgrade a host's durable state.

## 3. Ceremony and exact payloads

### Request

The `request` packet payload is exactly:

```text
mode: new | renew
host_public_key, device_public_key
request_nonce: canonical Base64 of 32 random bytes
coordinator_address, coordinator_public_key
created_at, expires_at
expected_network_id: net_... or "-"
expected_person_public_key: key or "-"
renewed_certificate_id: dc_... for renew, "-" for new
```

Derive the request ID from the primitives' request message and these keys/nonce.
`expires_at = created_at + 300 seconds`; the deadline is immutable. Both local
clocks must consider the request current before expansion. No polling extends it.
The request's coordinator address/key must equal the pinned mailbox connection.
A live ceremony does not follow a coordinator move; start a new request at the
verified new pin. Expected network/person, when supplied, must match all offers.
Renew requires both expectations and reuses the same nonrevoked device and host
keys. New requests reuse durable pending keys on retry; they never overwrite a
conflicting existing network/person or regenerate a person key.

### Owner offer

The `owner` packet payload is exactly:

```text
request_packet_id
network: {network_id, name, genesis_root_public_key,
          coordinator_address, coordinator_public_key}
epoch, feature_id, person_public_key
certificate: proposed device certificate
binding_record: person authorized binding draft for new, "-" for renew
membership_proof_id: "-" for new, pf_... for renew
binding_proof_id: "-" for new, pf_... for renew
```

The network descriptor's ID derives from its genesis root. Verify its root
chain, current epoch, feature, person admission and issuer's complete authority.
The owner offer's person/certificate/key must match the packet signer and
certificate issuer. For new linking the issuer needs binding and delegation
scopes; renewal needs delegation scope. The certificate names the request ID and
both new keys, scopes within the issuer, and expiry within the primitive bounds.

A new binding draft is the exact person-authorized record from the primitives,
with operation ID equal to the request ID and `host_signature: "-"`. This is a
**draft**, never a valid standalone binding. Its owner signature is already
fixed. The person, host, network, epoch and signer must match this offer. Binding
and certificate are signed by the same owner authority. The final host consent
is added only by the new machine.

Renewal requires currently valid existing membership and same-person binding,
identified by public catalog IDs. It creates neither a replacement admission
nor a binding. If historical admission/binding authority is incomplete, obtain
the required checkpoint first; renewal does not waive that check. The old
certificate identifies the device/host/person but need not still be live.

### Selection and administrator offer

The new machine verifies and privately persists one `selection` packet with
payload exactly `{owner_offer_id, network_id, epoch, feature_id,
person_public_key}`. Both new keys sign. Show the selected network/person and
key fingerprints before consent. Selection permanently fixes the owner offer
for this request ID; a second distinct selection conflicts even before commit.

Only after selection may the code be handed to a separate administrator. An
administrator packet payload is exactly `{owner_offer_id, selection_id,
admission_record}`. The admission is a person-authorized or root-authorized
record, with operation ID equal to this request, admitting exactly the new host
under the selected person's admitted member label and current epoch. The packet
signer must equal the admission signer. Person administration requires bit 8
plus a current administrator role. Owner approval alone confers no role.

If one existing machine has both roles, it signs both packets after one review;
it still verifies and persists the new machine's selection before issuing the
administrator packet. Otherwise the new machine reports `awaiting_administrator`.
Renewal has no administrator offer and does not add/remove membership authority.

### Commit and activation

The `commit` packet payload is exactly:

```text
mode, request_packet_id, owner_offer_id, selection_id
administrator_offer_id: lp_... for new, "-" for renew
network_id, epoch, feature_id, person_public_key, certificate_id
binding_record: final binding with host consent for new, "-" for renew
admission_record_id: ar_... or rr_... for new, "-" for renew
expires_at: original request deadline
```

Check every reference and scalar against the exact referenced packet; no local
substitution of a chain, owner, admission, scope, expiry or selected offer is
allowed. The final binding differs from the draft **only** in its host signature,
which covers the primitive binding-consent message. The new host and new device
sign the commit packet. The manifest ID is the commit packet ID. Persist that
packet and the operation ID (the request ID) before any submission.

An activation object is exactly `{request, owner, selection, administrator,
commit}`, each a complete packet; `administrator` is `"-"` for renewal. An
activation's semantic ID is its request ID. The public catalog supplies ancestor
certificates/activations, root/person/admin proofs and the feature. Validate in
this order, without activating the target certificate while checking its issuer:

1. Strict parsing, byte bounds, derived IDs, pinned coordinator/genesis context,
   host/device possession proofs, exact references, expected network/person.
2. Current feature, root epoch, valid admitted person and issuer path. All known
   sticky removals/revocations and policy/group high-water marks apply.
3. Owner/delegation scope, certificate bounds and draft binding authority;
   exact new-machine selection; separate current admin/root approval for new.
4. Final host consent and both commit signatures; no conflicting existing
   person/host binding, permanent unbinding, host leave/revocation or revoked
   device key. Renewal validates its referenced current membership/binding.
5. For a first finalization, `created_at <= now < expires_at` and all issuing
   authority is live now. Recheck under the same write transaction as commit.
6. Atomically store admission + membership/address + binding + certificate
   activation + complete operation result for new, or only the fresh certificate
   activation/result for renew. Record events once. Nothing is partially visible.

An incomplete proof is never an admission. Generic routes refuse any linking
record until its exact complete activation exists, including records signed by
an original person or network root. Root/private-key possession does not strip
the operation ID or turn an offer into a reusable legacy admission.

### Results, repetition and historical verification

A link-operation request is at most 512 KiB in total, within the general
1 MiB mutation limit. Precompute and check the complete result packet against
1 MiB before mutation; capacity failure leaves no admission. Return the request's
sufficient public catalog and activation, not an unrelated full-network snapshot.
The `result` packet payload is exactly `{manifest_id, activation, catalog}`.
It is returned only for a committed operation and signed by the pinned
coordinator. The joining host independently verifies and atomically persists
its network, person binding, public proof catalog and selected signer. It then
reports `linked`; agent attachment/readiness is a later `up` stage.

Identical committed retries return the original stored result **before** deadline
or current-authority checks. They do not perform another mutation. A different
manifest under the same request ID returns `operation_conflict`. A retry may
retrieve evidence even if the host was subsequently removed; returning that
public evidence never restores live authority or marks an unusable signer ready.
An honest coordinator's deadline check is not independently provable by a
receipt timestamp. Later receivers check the signed transcript and retained
current authority, not when the coordinator claims to have committed. Historical
packets remain signature-valid after the request deadline; usable delegated
records remain bounded by certificate expiry/revocation and checkpoint rules.
A malicious coordinator can delay a fully authorized operation, not forge it.
The 300-second honest-coordinator deadline is **not cryptographic withdrawal of
already signed consent**. Withheld complete consent can still prove durable
membership later while its authority remains usable. Device-certificate expiry
limits signing, not an otherwise valid root/person admission and binding. Use
explicit host revocation/unbinding to invalidate that durable authority.
When checking historical activation, its original epoch must be in the verified
root chain; a subsequent rotation alone does not erase the transcript. Current
root/role/removal and retained-record rules still apply to each durable record.
The target device certificate's expiry disables its live signing authority, not
an independently valid original-person/root admission or binding. It must not
prevent same-key renewal when the issuer and existing records remain valid.

## 4. Routes, cancellation and limits

All new coordinator routes use the existing pinned mTLS transport. Routes below
are under `/coord/v2`; local routes are under the private Unix `/v1` router.
Secrets are entered at a hidden prompt or stdin and never placed in path/query
arguments. The locator is the primitive hash, not the private code.

| Coordinator route | Exact request body; response |
| --- | --- |
| `POST /link-mailboxes` | `{frame, created_at, expires_at}`; frame must be a request from the TLS caller host. 201 mailbox view; identical repeat 200. |
| `POST /link-mailboxes/{locator}/frames` | `{frame}`; 201 `{sequence}`, identical frame repeat 200 with original sequence. Different bytes under one frame tuple return conflict. |
| `GET /link-mailboxes/{locator}?after=N` | No body; 200 mailbox view with frames after nonnegative sequence N, sorted ascending. |
| `DELETE /link-mailboxes/{locator}` | No body; creator host only; 200 `{state: deleted}`. This deletes transport, never committed membership. |
| `POST /networks/{id}/link-feature/proposals` | `{proposal, catalog}`; root-signed current-epoch/current-roster proposal; 201 `{feature_id}`, exact retry 200. At most 8 pending/network. |
| `GET /networks/{id}/link-feature/proposals` | Current member; 200 `{proposals: [{proposal, acknowledgments}]}`, including incomplete candidates, sorted by feature ID; no active-feature assertion. |
| `POST /networks/{id}/link-feature/acknowledgments` | `{acknowledgment, catalog}`; TLS caller must equal the listed acknowledgment host; 201 `{feature_id}`, exact retry 200. |
| `POST /networks/{id}/link-feature` | `{feature, catalog}`; root authorization and exact roster; 201 `{feature_id}`, identical retry 200. |
| `GET /networks/{id}/map` | No body; current member only; 200 v2 map (§5). |
| `POST /networks/{id}/link-operations` | `{activation, catalog, address, candidates}`; TLS caller must be the new/renewing host. 201 result packet; identical committed retry 200. |
| `GET /networks/{id}/link-operations/{request_id}` | No body; joining host or current network member; 200 stored result packet, 404 unknown. |
| `POST /networks/{id}/statements` | `{catalog}`; current member; validate each new statement and its operation/feature constraints, atomically store, 200 v2 map. |
| `POST /networks/{id}/invite-redemptions` | `{redemption, catalog, address, candidates, join_ack}`; `host`/`member` requires TLS caller key equal to `redemption.host_public_key` and a matching feature acknowledgment; `person` requires an existing current member, `join_ack: "-"`, `address: ""` and `candidates: []`, with no transport admission. 201 v2 map, identical retry 200. |

A mailbox view is exactly `{request_id, locator, created_at, expires_at,
next_sequence, state, frames}`, state `open|expired|deleted`, and frames
`[{sequence, frame}]`. Sequences start at 1; `next_sequence` is the next unused
number. Missing/expired/deleted mailboxes return 404/410/410 on writes; reads of
retained terminal mailboxes return their state. Relay metadata is not authority.
Encrypted frame plaintext is exactly
`{request_id, role, writer_public_key, packet, catalog}`. Repeated metadata must
match the header and any packet. A catalog may be split across frames; catalog-only
frames use `packet: "-"`. Their metadata provides no authority. Merge catalog
objects by their verified IDs, within the mailbox and aggregate proof bounds,
before evaluating dependent packets. Result traffic may use this same shape or
the direct operation route; never put a private code into that public result.

### Cancellation has explicit limits

- Before the new machine signs final consent, local cancellation retires the
  request/code; keep host/device keys for a fresh request. No complete activation
  can exist. Mailbox deletion alone is not a revocation.
- After an owner offer is published, stopping the approver returns `offer_sent`,
  not a withdrawal acknowledgment. V1 adds **no revocable-offer timestamp**.
  To invalidate the proposed device authority, the issuer may explicitly revoke
  that pending certificate's device key using the existing signed device
  revocation. The target need not be activated; its issuer/ancestor must be live.
  This is sticky: another attempt needs a fresh device key, preserving host and
  person identity. Show that consequence before signing.
- An administrator cannot silently withdraw a signed admission offer. An
  explicit host revocation uses existing administrator authority and permanently
  revokes that host key. Show the effect; do not run it just because polling stops.
- Known revocations block first commit and live authority immediately. Withheld
  revocations can arrive after commit. Signing-key revocation does not remove
  membership: report remaining binding/trust/membership cleanup explicitly.
- Once final consent may have been sent, local cancellation/timeout leaves
  `finalizing`. Query the exact operation until the outcome is known. After
  expiry, a 404 from an honest coordinator means no recorded commit, but it is
  not signed rollback evidence against a malicious coordinator that retained
  the complete consent. Keep the local operation tombstone and never reuse it.

### Fixed private-preview limits

| Resource | Limit / outcome |
| --- | --- |
| Request | Exactly 300 seconds; immutable deadline. |
| Mailbox | 64 frames; 512 KiB total serialized frame bytes; decoded ciphertext at most 64 KiB + 16 bytes per frame. |
| Creation | 5/IP/hour; 1,000 globally/hour; at most 8 open/IP, 256 open globally, 4,096 retained mailboxes and 256 MiB total mailbox bytes. |
| Frame writes | 60/IP/minute and 12,000 globally/minute. |
| Polling | At least 2 seconds per TLS-host/locator; 120/IP/minute and 12,000 globally/minute. |
| Terminal transport retention | Until request deadline + 24 hours, then delete ciphertext/locator state; public committed proof is retained separately. |
| Public network proof state | 8 MiB decoded retained objects and 4,096 public objects/network, 4,096 link operations/network, 4,096 certificates/person/network. Reject additions before exceeding a bound. |

IP means authenticated connection source IP; do not trust forwarded headers.
Fixed windows use coordinator UTC minute/hour boundaries. An idempotent retry
uses no extra storage slot but consumes request rate budget. Rate excess is
429 `rate_limited` with integer `Retry-After` seconds to the next allowed poll or
window. Byte/count capacity is 409 `quota_exceeded`. Never evict sticky proof,
operation IDs or high-water marks to make room. Signed compaction is outside v1;
reaching a durable-state bound stops expansion, not enforcement or read access.

## 5. Maps, invites and administrator history

### Map v2

A v2 map is exactly `{format: 2, network, catalog, members}`. `network` is the
owner-offer descriptor. `members` is a sorted array of exactly
`{host_id, host_public_key, membership_proof_id, binding_proof_id,
join_proof_id, address, candidates, updated_at}`. Binding is `"-"` for an unbound
host; join proof is `"-"` only for a feature-proposal roster host, otherwise a
`pf_` feature acknowledgment or activation. All other proof IDs resolve in the
catalog. Person/admin/policy/group views are derived from the public statements,
not unsigned member fields. Addresses/candidates/updated time retain today's
untrusted reachability-hint semantics and existing validation. Root chain and
coordinator move/successor proofs retain the existing coordination contract.
The network descriptor names the verified current coordinator pin.

A map is at most the existing 16 MiB response bound (the response exception to
the primitives' 1 MiB mutation envelope bound). Reject a response that
omits required proof for this host or contradicts durable feature/operation/
revocation/high-water state; preserve the last verified state and report
`proof_required` or `state_conflict`. Never replace a complete local proof with
an incomplete remote one. Member entries with independently bad proofs retain
today's drop-invalid-entry behavior; missing dependencies for an active signer
produce incomplete authority and never an implicit allow. Peer synchronization
uses the same catalog container and validation, without exposing local routes.
High-water marks mean the highest versions this host has verified; an unsigned
coordinator response is not proof that no unseen update exists. Withholding can
delay learning new policy/revocation state, under the existing freshness rules.
Persisted marks and known restrictive statements cannot be rolled back by omission.

### Invites from delegated administrators

New delegated invites use the prefix `peerspan-authorized-invite-v1.` followed by
unpadded canonical base64url of exactly:

```text
format: 1
network: network descriptor
mode: host | person | member
invite_seed: canonical Base64 of 32 bytes
host_invite: person authorized peerspan-invite-v1 record or "-"
person_invite: person authorized peerspan-person-invite-v1 record or "-"
catalog: public authority/feature proofs
```

Host mode requires only host invite; person mode only person invite; member
requires both. Both parts share invite key, member, expiry, network and exact issuer authority. The seed
must derive that public key. Invites use ordinary operation ID `-`; each invite's
expiry is no later than its signing chain expiry and the existing 30-day bound.
Current root/root-person invite workflows remain supported using their existing
formats plus the v2 reader acknowledgment when joining an activated network.
In a public redemption, an existing-format host invite is represented by exactly
`{network_id, invite_public_key, member, invite_expires_at, signature}`; an
existing-format person invite additionally has `invite_epoch`. Preserve the
original signature value from the token's corresponding invite-signature field.
Validate the existing signed-line format under its actual root/person-admin key;
never reinterpret a device signature as a legacy person signature.

A public redemption has exactly `{format: 1, mode, person_action, host_public_key,
person_public_key, joined_at, host_invite, person_invite,
host_member_signature, person_member_signature}`. `person_action` is exactly
`none`, `admit` or `skip`, with these required combinations:

| Mode / person action | Host fields | Person fields and required state |
| --- | --- | --- |
| `host` / `none` | Host key, host invite and host-member signature required. | `person_public_key`, `person_invite` and `person_member_signature` are all `"-"`. |
| `person` / `admit` | `host_public_key`, `host_invite` and `host_member_signature` are all `"-"`; caller is an existing current member. | New person key, person invite and person-member signature required. |
| `member` / `admit` | Host key, host invite and host-member signature required. | New person key, person invite and person-member signature required; both invite halves must agree as specified above. |
| `member` / `skip` | Host key, host invite and host-member signature required. | Keep the exact **already-admitted** `person_public_key`; set `person_invite` and `person_member_signature` to `"-"`. Verify that key's current person admission from durable state/catalog and that its admitted label matches the signed host-invite member label. |

Other combinations, a missing `person_action`, or fields inconsistent with the
selected action return 400 `invalid`. Never infer `skip` from missing fields.
An unknown or removed person cannot satisfy `skip`; a label alone cannot select
that identity. Missing required admission proof returns `proof_required`; a
known removed person returns `forbidden`. A known label mismatch is
`invalid`. Token mode `member` still requires both invite halves when decoding
the private token; only the **public skip redemption** omits its unused person
half. The skipped person-invite half is not consumed or retained as a redeemed
grant, and the operation's person result is `skipped`.

Host/member uses an invite-key raw signature on the existing host-member
statement. Person/member with `person_action: admit` uses the existing
person-member statement. Public records contain no seed. For host/member, the
TLS caller must prove the named host key and `join_ack` must name that key and
the active feature. For person-only, `host_public_key` remains `"-"`; authorize
the actual TLS caller from current membership, not by comparing it with that
absent field. Its empty address/candidates and absent acknowledgment leave
transport membership and reachability unchanged.

Choose the person action explicitly before mutation. A first `admit` for an
already-admitted key returns 409 `state_conflict`; rebuild an explicit `member`
skip against current verified state when appropriate. Check action/state
preconditions before consuming either invite half or admitting a host. An exact
completed retry still returns its stored outcome before these first-use checks.
No skip action admits/removes/replaces a person, binds the joining host to that
person, or grants owner access. Same-person binding still needs owner + host
consent, even when the existing person and label match.

An invite is a live grant: first redemption requires current issuer authority,
current administrator role, feature acknowledgment, expiry and single-use checks.
For durable membership after that issuer becomes unusable, or after a new
delegated invitation expires, retain the exact
host/person invite record ID in a checkpoint **only through a completed public
redemption that names it**, alongside that redemption. For this purpose checkpoint `records` additionally
accepts the exact `pf_` ID of an `invite_redemption` object, with no change to
checkpoint signing bytes. No other `pf_` kind is retainable.
Without that endorsement a backdated `joined_at` is not trusted proof of
redemption before expiry; request a checkpoint, retaining incomplete state. The checkpoint
signer must be the invitation issuer's original person or unaffected strict
ancestor with administration scope. This does not retain a redeemable invite or extend its expiry. This narrowly refines UP-06a's exclusion
of invites from retention; otherwise an invited member could not retain history.
A retained invitation cannot authorize a new redemption or different key.

### Root-signed administrator removal

Format 2 removal is exactly `{format: 2, network_id, person_public_key,
revoke_admitted, removed_at, kept}` plus `signature` by any valid network root.
Its message is `L("peerspan-admin-remove-v2", network_id, person_public_key,
revoke_admitted, removed_at, kept_count, ...kept)`. Kept entries are sorted unique
`legacy:<existing statement digest>`, `record:<ar_ ID>`, or
`redemption:<pf_ redemption ID>`. With `revoke_admitted: true`, kept is empty.
Legacy invitation history keeps its existing statement-digest validation.
Version 1 removals continue to apply only their existing legacy digest list;
they retain no new envelopes implicitly. Refuse conflicting nonidentical
removals for a person, except the existing irreversible escalation to
`revoke_admitted: true`.

For a removed admin, a new administrator record needs its exact `record:` entry;
a completed invited membership additionally needs its exact `redemption:` entry
and the corresponding invite record's `record:` entry. This root list and a
person's valid history checkpoint are **both** required if both admin-role and
device-path authority have become unusable. Neither can substitute for the
other. No list revives policies, device keys, a role, or a live invite. Feature
activation keeps policy/group high-water marks even when root removal invalidates
the latest delegated version; do not take the old legacy group-revert exception
as permission to restore a lower version in an activated network.

## 6. Durable storage and signer selection

On main baseline `90ddd29`, host schema is 18 and coordinator schema is 6.
Reserve host **19**, coordinator **7** for this slice. If another migration lands
first, renumber both implementations together before writers land; never reuse
an occupied version. The host migration atomically adds the shared tables below,
sets `user_version = 19`, and changes no existing identity, membership, policy,
service or attachment. Migration failure rolls back. Old binaries refuse it.

```sql
CREATE TABLE link_device_keys (
 public_key TEXT PRIMARY KEY, seed BLOB NOT NULL CHECK(length(seed) = 32),
 created_at TEXT NOT NULL
);
CREATE TABLE link_pending (
 request_id TEXT PRIMARY KEY, role TEXT NOT NULL, state TEXT NOT NULL,
 deadline TEXT NOT NULL, record TEXT NOT NULL, secret BLOB
);
CREATE TABLE link_frames (
 request_id TEXT NOT NULL, role TEXT NOT NULL, writer_key TEXT NOT NULL,
 frame_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(request_id, role, writer_key, frame_id)
);
CREATE TABLE link_operations (
 request_id TEXT PRIMARY KEY, network_id TEXT NOT NULL,
 manifest_id TEXT NOT NULL, record TEXT NOT NULL, locally_applied INTEGER NOT NULL
);
CREATE TABLE link_objects (
 network_id TEXT NOT NULL, proof_id TEXT NOT NULL, kind TEXT NOT NULL,
 body BLOB NOT NULL, PRIMARY KEY(network_id, proof_id)
);
CREATE TABLE link_features (
 network_id TEXT PRIMARY KEY, feature_id TEXT NOT NULL, record TEXT NOT NULL
);
CREATE TABLE link_signers (
 network_id TEXT PRIMARY KEY, person_key TEXT NOT NULL, device_key TEXT NOT NULL,
 certificate_id TEXT NOT NULL
);
CREATE TABLE link_highwater (
 network_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL,
 version INTEGER NOT NULL, record_hash TEXT NOT NULL,
 PRIMARY KEY(network_id, kind, subject)
);
```

`record` is strict JSON retaining the exact signed packet/frame bytes through
Base64 fields. Pending records contain the request, locked selection, received
packet IDs and immutable outbound frames; never display them in ordinary status.
Persist new keys and request nonce/secret before display, a sealed frame before
publish, selection before administrator handoff, and commit before submission.
`secret` is the 16-byte code seed while resuming the ceremony, or SQL NULL when
not held and for terminal requests. Approvers may persist it only while the
ceremony is pending.
The feature table's record is exactly `{state, proposal, acknowledgments,
activate}` while preparing/collecting, state `preparing|collecting|active`.
A candidate row does not assert active feature support. Once active, its proposal
and acknowledgment set are immutable. A single request may record both owner and
administrator packet IDs under role
`approver`. Roles are `new`, `renew`, `approver`; no second row overwrites the
new machine's own operation. Same-machine self-linking is refused.

The local daemon owns a network-scoped device signing provider in its private
state. It creates a distinct device key per network enrollment, supports typed
owner/admin operations, and never exports the seed or offers a general raw-sign
API. This enables policy renewal without the original person key locally.
Original person/SSH private keys stay in the existing CLI/SSH provider. They are
never inserted into the daemon database. All state keeps current owner-only
permissions. SQLite/WAL/backups can retain deleted secret bytes; terminal cleanup
removes live secrets without promising secure erasure of prior backups.

A successful new/renew result, public proofs, signer selection, membership/binding
updates and events are committed locally in one transaction. `locally_applied`
becomes 1 only then. Before this, startup resumes `finalizing` using the same
operation ID. A completed retry records no duplicate event. Verified public
objects, revocations, high-water marks and operation tombstones are not removed
when pending code/ciphertext is deleted.

Coordinator migration 7 adds `link_mailboxes` (locator/request/creator/deadline/
terminal metadata), immutable `link_frames`, and public `link_operations`,
`link_objects`, `link_features`. It stores no device/person/code seeds. The
coordinator shares no database with hosts, so its physical column layout remains
internal, but all five categories and the atomic commit/unique operation and
frame constraints are required. Its existing backup/restore includes these
categories; a partial restore must fail verification rather than recreate IDs.

`up`, owner commands and daemon renewal first resolve an existing network's
stable person and selected live device provider. An expired/missing/revoked
provider produces repair for that person; it never falls through to new-person
key generation. An explicit original-key option is allowed only when it matches
the bound original person. Renewal selects the shortest usable path (then ID)
from verified state and cannot silently replace a user's selected identity.

## 7. Local API, proposed CLI and outcomes

These commands/routes are proposed, unavailable until implementation:

| CLI | Private local route and exact request |
| --- | --- |
| `network enable-linking --network ID [--root-key PATH]` | `POST /v1/networks/{id}/link-feature` with `{activate}`; false previews, true persists the activation intent, signs/publishes with a local root or returns an external root signing request. |
| `link [--renew] [--network ID] [--expect-person KEY]` | `POST /v1/link/requests` with `{mode, network_id, person_public_key, coordinator_address, coordinator_public_key}`; unresolved optional values are `-`. Returns 201 public request view plus `display_code` once. |
| `link approve --network ID [--person PERSON_ID] [--code-stdin]` | `POST /v1/link/approvals` with `{code, network_id, expected_person_id, expected_host_key, expected_device_key, signer, approve}`; preview uses `approve: false` and may use `-` for expected person/keys; actual approval requires reviewed exact person/keys and true. |
| `link admit --network ID [--person PERSON_ID] [--code-stdin]` | `POST /v1/link/admissions` with the same review fields; refuse before a signed selection exists. |
| `link status [REQUEST_ID]` | `GET /v1/link/requests[/ID]`; public request views, no code, ciphertext, private keys or unsigned readiness claims. |
| `link resume REQUEST_ID` | `POST /v1/link/requests/{id}/resume` with `{}`; use durable state, never regenerate identity. |
| `link cancel REQUEST_ID` | `POST /v1/link/requests/{id}/cancel` with `{}`; cancel pre-consent, explain sent offers, or retain finalizing as specified above. |

Feature responses are exactly `{state, feature_id, proposal, acknowledgments,
pending_hosts, signing_requests}`; pending hosts are sorted public keys and
signing requests use the shape below. For an external root, submit
`POST /v1/networks/{id}/link-feature/signed` with `{signature}` over the exact
persisted proposal message; return the same shape. Only the network-root provider
can authorize this action. With activation intent true, the daemon resumes
collection and submits the complete feature after all acknowledgments arrive;
missing hosts remain visible without any automatic removal. A published stale
proposal expires and requires a fresh root signature; no deadline extension.

Approval/admission responses are exactly `{request, review, signing_requests}`.
`review` is exactly `{network_id, person_id, host_public_key, device_public_key,
scopes, not_after, signer_public_key, authority_warning}`. `signer` selects
`auto`, `person_root`, `network_root` or a specific `dc_` path. `auto` uses the
current selected device when sufficient, otherwise the existing original-person
provider for owner actions and existing root/admin selection for administration.
A preview never publishes or signs an offer. Persist all reviewed inputs,
including fixed times, selected issuer and requested scopes before approval.

Each signing request is exactly `{object_type, message_base64,
signer_public_key, signature_format}`; format is `sshsig` or `ed25519`.
Original/SSH-root signing uses the CLI provider, never its private seed in the
daemon. Submit to `POST /v1/link/requests/{id}/signed` with exactly
`{object_type, signature}`; response is the same approval/admission shape.
Types are `feature_proposal` (only through the feature signing route),
`certificate`, `binding_authorization`, `owner_packet`,
`admission_authorization`, `administrator_packet`. The daemon presents only the
next dependency-ready inputs: certificate/binding first, then the owner packet
containing their verified signatures; admission then its administrator packet.
It accepts a signature only over the persisted requested bytes from the reviewed
template. No timestamp, subject, authority or payload can change between steps.
An internal device/root provider follows the same dependency order after explicit
consent, returning an empty signing request list when complete. The signed route
accepts no arbitrary messages and cannot create an unreviewed operation.

A public request view is exactly `{request_id, mode, state, network_id, person_id,
host_id, device_fingerprint, expires_at, completed, attention, next}`. Unknown
network/person use `-`. `completed` is an ordered array of stage names, not a
readiness assertion. Device fingerprint is `SHA256:` plus unpadded Base64 of the
raw device-key SHA-256. The request response includes the display code only on
initial creation and explicit owner-local resume while pending; never in normal
status/events/logs. CLI human output on stderr, JSON on stdout; do not put a
code in arguments. Interactive consent defaults to no; noninteractive consent
requires exact network/person and both reviewed keys, not a bare `--yes`.

New/renew states are `waiting_owner`, `waiting_selection`,
`awaiting_administrator`, `ready_to_commit`, `finalizing`, `linked`, `incomplete`,
`cancelled`, `expired`. Approver states are `review`, `offer_sent`, `incomplete`.
A renewal moves from selected owner directly to ready-to-commit. `linked` means
verified locally persisted **currently usable** membership/binding/signer; an
operation committed but later revoked/expired is `incomplete`, with its stable
identity and repair path. An honest-coordinator unknown result after deadline
can be displayed expired, while retaining the consent/tombstone and explaining
that submitted authorization was not revoked.

Errors retain `{code, error}` plus `details` (strict object of `request_id`,
`stage`, `required_ids`, `next`; absent scalars `-`, arrays empty). Required codes:

| HTTP | Code / use |
| --- | --- |
| 400 | `invalid`: parsing, encoding, signature, type or reference mismatch. |
| 403 | `forbidden`, `authority_expired`, `device_revoked`, `authority_would_be_invalidated`: permission/path failure; preserve identity. |
| 404 | `not_found`: unknown mailbox/operation/request, never rollback evidence. |
| 409 | `operation_conflict`, `state_conflict`, `quota_exceeded`, `proof_required`: immutable-ID, local/remote state, capacity or missing-history conflict. |
| 410 | `expired`, `deleted`: first finalization after deadline or terminal mailbox. |
| 426 | `upgrade_required`: missing feature/reader support; no key-copy fallback. |
| 429 | `rate_limited`, with `Retry-After`. |
| 500 | `internal`: generic internal error, with no secrets or partially applied mutation. |
| 503 | `unavailable`: pinned coordinator unavailable or required fresh authority sync failed. |

Preview/cancellation/status success does not mean linking succeeded. Incomplete
CLI operations exit nonzero with the public view and next step; completed link
exits 0. `up` resumes a linked person/provider before attachment and reports each
stage separately. Freshness for authority expansion requires a successful pinned
sync under today's coordination freshness bound and inspection of structured
sync errors; stale cached role claims alone cannot approve another machine.

## 8. Vectors and verification requirements

[Transaction vectors](../conformance/vectors/machine-linking-transactions-v1.json)
provide deterministic bootstrap authority, feature activation, root-person → B,
B → C, and same-key renewal transcripts. Signed negative inputs distinguish
valid cryptographic signatures from missing or wrong semantic authority. They
are specification fixtures, not runtime acceptance or a security review.
[Invite-redemption vectors](../conformance/vectors/machine-linking-invite-redemptions-v1.json)
fix all four valid mode/action combinations and the corresponding caller and
missing/skipped-field rejection cases, using the transaction fixture's verified
authority catalog as their starting state.

The separately authored conformance suite must check all four Go/Rust
creator/joiner pairings, both owner/admin role arrangements, and at least:

1. Full transcripts, exact packet/record/catalog IDs, unchanged primitive vectors;
   malformed encodings, JSON duplicates/unknowns/nulls, bad signatures and limits.
2. Nonadmin owner plus independent administrator with a locked selection; missing
   admin role, stale role, insufficient scope, changed keys/person/network/epoch,
   altered owner offer, selection or manifest all fail without partial mutation.
3. Root-admin and delegated-admin admission; complete B → C while original person
   machine is offline; direct-root renewal of the same host/device after its old
   certificate expires, subject to retained membership and binding proofs.
4. Every primitive delegation/revocation/checkpoint case, including exact retained
   invited membership versus an unauthorized fresh redemption. Root admin-removal
   format 1/2 retention, irreversible escalation and policy/group high-water rules.
5. Crashes immediately before/after each persisted key/frame/selection/commit and
   each coordinator/local transaction. Lost responses, duplicates and conflicting
   manifests must preserve IDs, exactly-once events and atomic visible state.
6. Cancellation before consent, stopped approver after offer, explicit pending-key
   revocation, cancellation during unknown commit, expired first commit, committed
   retry after deadline/revocation, and cleanup that never claims full retirement
   from signing-key revocation alone.
7. Feature roster races, offline/old host refusal, later join acknowledgments,
   omitted/downgraded maps, root rotation and coordinator movement; reject old
   binaries on migrated state and preserve an interrupted migration atomically.
8. Cross-implementation reads of pending/committed state and signer discovery;
   original private key absent on B/C; no replacement person, copied original
   seed, secret in logs/status/process arguments, or changed service/attachment.
9. Rate/count/byte boundaries, terminal ciphertext cleanup, durable-state capacity
   refusal, coordinator backup/restore and existing explicit invite regression.
10. Person-only redemption by a current member succeeds without a new host or
    address update; an outsider fails. Host/member redemption requires the exact
    joining TLS key and feature acknowledgment. Explicit member skip preserves
    the existing person and leaves the joining host unbound, consumes no person
    invite, and has an idempotent retry. Unknown/removed or label-mismatched skip
    subjects, missing admit fields, inferred skip, invalid mode/action pairs and
    admission races fail before any invite consumption or host mutation.

After verifier/state propagation passes, implement the ceremony and `up` handoff
in both hosts, run installed-bundle recovery checks, and update the quick start
only when the commands exist. Live-agent and fresh-machine results remain
separate from scripted protocol evidence.
