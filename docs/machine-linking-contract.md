# Machine linking: delegated signing and pairing primitives

Status: **UP-06a accepted in [PR #41](https://github.com/peerspan/peerspan-internal/pull/41)**,
2026-10-23. The shared Go and Rust verifiers now cover signed catalogs, root
chains, complete activations, retained history, restrictions and monotonic
policy/group selection. The composed host/coordinator runtime implements durable
propagation, approved new/renew ceremonies and live delegated writes under the
[transaction contract](machine-linking-transactions.md) and
[host runtime checks](linking-host-checks.md). The
[Linux validation record](results/linking-launch-validation.json) contains the
independent runtime and installed-bundle results, per-run sources and known
limits.

This refines the [UP-05 design](https://github.com/peerspan/docs-internal/blob/main/docs/machine-linking.md),
accepted in [docs PR #9](https://github.com/peerspan/docs-internal/pull/9).
Both Go and Rust implement the shared behavior. Rust remains the recommended
install; Go remains supported. Private release configuration, macOS and live
model validation remain separate work.

This document fixes signed bytes, authority evaluation and encryption primitives.
The [UP-06b transaction contract](machine-linking-transactions.md), accepted in
[PR #43](https://github.com/peerspan/peerspan-internal/pull/43), fixes transaction
containers, migration, routes and CLI. Writers require those complete runtime
and current-authority checks; a cryptographic reader result alone supplies no
signing authority, membership or readiness.

## Required result

A linked machine remains the same admitted person and can manage that person's
access and trust settings and approve further machines. It holds its own device
signing key, separate from its host transport key. The original person private
key is never copied. Membership, person binding, signing authority, and agent
readiness remain separate checks.

The original person public key continues to identify the person in policies,
grants, bindings, administrator roles, and addresses. A device key is a signer,
never a replacement person. Network-root-only operations stay root-only.

## 1. Encodings

`L(a, b, ...)` means UTF-8 lines joined with LF, **without a trailing LF**.
Every interpolated scalar excludes CR, LF and NUL. `H(x)` is lowercase hex
SHA-256 of the exact bytes `x`. IDs contain their prefix followed by 64 hex
characters. Public keys are canonical padded standard Base64 of 32 bytes;
raw Ed25519 signatures are canonical padded standard Base64 of 64 bytes.
Reject noncanonical encodings, invalid Ed25519 keys/signatures and trailing bytes.

New timestamps use exactly `YYYY-MM-DDTHH:MM:SSZ`, actual UTC calendar times,
without leap seconds. Integers use unsigned decimal with no leading zero except
`0`; epochs are nonnegative and scope masks are positive. Validity is half-open:
`issued_at <= now < not_after`. No grace period extends expiry. Local clock
errors stop authority expansion with a repair diagnostic.

Person and device signatures use the existing Ed25519 SSHSIG format:
namespace `peerspan-person-v1`, empty reserved field, hash `sha512`, version 1,
Base64 of the complete binary SSHSIG blob. Each application statement below has
its own first line. Signing the SHA-512 SSHSIG preimage uses ordinary Ed25519,
not Ed25519ph. Verify the embedded key against the independently resolved signer.
See [OpenSSH's format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
and [Ed25519](https://datatracker.ietf.org/doc/html/rfc8032).

New objects are strict JSON: duplicate keys, unknown fields, nulls, invalid UTF-8,
and trailing JSON are errors. A transport envelope is at most 1 MiB, including
all proofs. A decoded signed payload is at most 256 KiB. Limits apply before
allocation and recursively to supplied proofs. Hashes of JSON always cover
retained **original bytes**, never a reserialization. No canonical-JSON algorithm
is implied.

## 2. Device certificates

A certificate has exactly these fields:

```text
format: 1
network_id: net_...
person_public_key: original person public key
device_public_key: new device signing public key
host_public_key: corresponding host transport public key
parent_id: "root" or dc_...
scopes: integer mask
issued_at: time
not_after: time
request_id: link_...
signature: SSHSIG
```

Its unsigned message is:

```text
L("peerspan-device-certificate-v1", network_id, person_public_key,
  device_public_key, host_public_key, parent_id, scopes,
  issued_at, not_after, request_id)
```

`certificate_id = "dc_" + H(message)`; the ID is derived, not a JSON field.
The original person key signs a certificate whose `parent_id` is `root`.
Otherwise the signer is the device key in the exact referenced parent.
Certificates carry no private material. An issuer signature proves delegation
intent; activation additionally requires the complete linking proof (§6).

| Bit | Scope | Permitted person authority |
| --- | --- | --- |
| 1 | owner policy | Publish/edit/renew this person's policies, including trusted hosts. |
| 2 | binding | Bind/unbind hosts for this person; the target host must consent to binding. |
| 4 | delegation | Issue child certificates and revoke strict descendants. |
| 8 | network administration | Exercise this person's **current** network-administrator role. |

The standard profile is `15`. Unknown bits and zero are rejected. Bit 8 neither
admits the person nor makes them an administrator. It can become usable if that
person is later delegated an administrator role by the network root. Approval
must disclose this conditional authority and the ability to trust oneself.
Raw source calls still need the serving host's local open list.

### Validation order

1. Resolve the network and its verified current root epoch, admitted original
   person, host membership/binding, and all known removals/revocations. Labels
   and coordinator capability claims provide no authority.
2. Resolve the exact parent chain, oldest first. At most **eight certificates**
   may separate a signer from the person key. Reject cycles, repeated device
   keys or host keys within one chain, and a device key equal to the person key
   or any host key in the chain. A device key and host key must differ.
3. Every certificate names the same network and original person. Verify every
   signature. A non-root issuer needs bit 4. A child has a subset of the
   parent's scopes, `issued_at >= parent.issued_at`, and
   `not_after <= parent.not_after`. Each interval is nonempty and at most
   **90 days (7,776,000 seconds)**. Default expiry is the earlier of now plus
   90 days and parent expiry. The original person key has no certificate expiry.
4. For a live operation, every certificate is currently valid and activated.
   Each path host must still be admitted and bound to this person. An expired,
   revoked, unbound, departed or membership-revoked ancestor disables this path.
   Check every known device-key revocation, even if another certificate names
   the same key. The absence of a proof is an error, not permission.
5. Check operation scope, stable person, payload semantics, current network
   epoch and administrator role where needed. Recheck immediately before commit.

The original person can refresh a device directly; an active delegated machine
can issue a fresh certificate along its own path, subject to these limits.
Neither can restore a revoked device key. Renewal preserves the person's and
host's identity; a revoked key requires a new device key and fresh approval.
An expired signer cannot renew itself. A sibling path cannot extend its own
outer expiry. The original key therefore remains periodically necessary.

Multiple independent paths may exist for one nonrevoked device. Evaluate the
path explicitly named by an operation; never substitute a different chain under
its signature. CLI signer selection prefers the shortest usable path and then
lexicographically smallest certificate ID. A damaged path does not disable an
independent valid path.

## 3. Authorized records

Delegation cannot be introduced by putting a device SSHSIG into an existing
root-person `signature` field. New records use this separate envelope:

```text
format: 1
kind: existing signed statement domain (table below)
network_id: net_...
epoch: current root epoch
operation_id: "-" for an ordinary action, or link_... for linking
person_public_key: original person public key
certificate_id: "root" or dc_...
payload_base64: exact unsigned JSON payload bytes
signature: SSHSIG by the person or referenced device
host_signature: "-" except for a host binding
```

`payload_base64` contains the unsigned public object. Existing payload validation,
field names, policy formats, version/edit rules, and size bounds continue to
apply. Network/epoch fields in the payload must agree with the envelope.
Owner operations name the same person
in payload and envelope. In administrator operations the payload person is the
**subject**, not necessarily the administrator signer.

The unsigned field sets are fixed below; all listed fields are required except
the existing format-dependent optional policy fields. A token's private invite
seed and its transport/discovery fields are **never** part of a public payload.

| Kind suffix (after `peerspan-`) | Unsigned JSON fields |
| --- | --- |
| `policy-v1`, `policy-v2` | Existing policy JSON, excluding `signature`; preserve format-specific fields and nested rules/edits. |
| `host-bind-v1` | `network_id`, `person_public_key`, `host_public_key`, `bound_at` |
| `host-unbind-v1` | `network_id`, `person_public_key`, `host_public_key`, `unbound_at` |
| `host-admit-v1` | `network_id`, `epoch`, `host_public_key`, `member`, `admitted_at` |
| `person-admit-v1` | `network_id`, `epoch`, `person_public_key`, `member`, `admitted_at` |
| `person-remove-v1` | `network_id`, `person_public_key`, `removed_at` |
| `revoke-host-v1` | `network_id`, `host_public_key`, `revoked_at` |
| `revoke-invite-v1` | `network_id`, `invite_public_key`, `revoked_at` |
| `invite-v1` | `network_id`, `invite_public_key`, `member`, `invite_expires_at` |
| `person-invite-v1` | `network_id`, `invite_epoch`, `invite_public_key`, `member`, `invite_expires_at`; `invite_epoch` equals the envelope epoch. |
| `group-v1` | `network_id`, `name`, `version`, `defined_at`, `members` |

The signed message is:

```text
L("peerspan-person-authorization-v1", kind, network_id, epoch,
  operation_id, person_public_key, certificate_id, H(decoded payload_base64))
```

A binding additionally has raw Ed25519 consent from the payload's host key over
`L("peerspan-binding-consent-v1", H(authorization message))`. The host signature
is required even when a person controls both machines. Other kinds require the
literal `"-"`. Define `record_id` as `"ar_" + H(L("peerspan-authorized-record-v1",
H(authorization message), signature, host_signature))`. Proof chains travel
alongside records; their transport order does not affect the ID.

| `kind` | Required scope and additional checks |
| --- | --- |
| `peerspan-policy-v1`, `peerspan-policy-v2` | Bit 1; signer person equals policy owner. Policy expiry cannot exceed any certificate in its signing path. |
| `peerspan-host-bind-v1`, `peerspan-host-unbind-v1` | Bit 2; signer person equals bound/unbound person; binding requires host consent. |
| `peerspan-host-admit-v1`, `peerspan-person-admit-v1`, `peerspan-person-remove-v1`, `peerspan-revoke-host-v1`, `peerspan-revoke-invite-v1`, `peerspan-invite-v1`, `peerspan-person-invite-v1`, `peerspan-group-v1` | Bit 8 **and** current network-administrator role; preserve each operation's existing admission, revocation, version, and conflict rules. |

This is an exhaustive registry for person-authorized records in this version.
For `certificate_id = root`, the original person key supplies the corresponding
person authority without a scope mask; administrator actions still require its
current role. The envelope does not support a network-root signer. Existing raw
network-root statements, administrator delegation/removal, root rotation,
attestations, host-signed leave and invite-key redemption retain their distinct
formats. A delegated person must not sign those root-only statements.

New invite and person-admission token/map containers must carry the new envelope
without converting it into a legacy signature; their exact containers belong in
UP-06b. Old root-person statements remain readable. No signature is accepted
under both the old and new domains.

## 4. Revocation and retained history

A device revocation has exactly `format` (1), `network_id`,
`person_public_key`, `target_device_public_key`, `target_certificate_id`,
`issuer_certificate_id` (`root` or `dc_...`), `revoked_at`, and `signature`.
The SSHSIG signs:

```text
L("peerspan-device-revoke-v1", network_id, person_public_key,
  target_device_public_key, target_certificate_id,
  issuer_certificate_id, revoked_at)
```

The target certificate must bind the named key/person/network. The issuer is
the original person key or an active **strict ancestor** in that target's chain
with bit 4. A sibling cannot revoke the target. Revocation sticks to the target
key for this network/person, across all its certificates and descendants whose
path traverses it. Save the complete target and issuer proofs with the
revocation. The timestamp is descriptive, not evidence that a later backdated
statement was authorized.

Once verified and persisted, a revocation remains effective after the issuer
expires or departs. An issuer that was live when the revocation was first
received cannot establish that history for a new receiver using receipt time.
Distribute retained evidence as below before the issuer's proof becomes unusable;
without it a new receiver refuses the affected authority path rather than
discarding a known revocation or trusting an alleged signing time.

### Self-invalidating changes

V1 **refuses** a delegated mutation that would disable its own named authority
path: revoking itself/ancestors, unbinding/removing a path host, or removing its
own person admission. Return `authority_would_be_invalidated`, identify the
affected path and require the original person key or an unaffected authority.
Do not accept the mutation and later depend on its claimed earlier signature
time. Existing host-signed leave remains possible; it disables that path and
must explain the resulting loss of signing authority.

### Checkpoints

Live delegated signatures are not perpetual authority for durable records.
Before an issuer path becomes unusable, retain exact public record IDs in a
checkpoint signed by the original person key or an unaffected active strict
ancestor. A checkpoint has exactly `format` (1), `network_id`,
`person_public_key`, `issuer_certificate_id`, `issued_at`, `records` (sorted,
unique `ar_...` IDs or `dr_...` revocation IDs; the transaction contract adds
completed-redemption `pf_` IDs), and `signature`. Its message is:

```text
L("peerspan-person-checkpoint-v1", network_id, person_public_key,
  issuer_certificate_id, issued_at, record_count, ...records)
```

`dr_` is `H` of the revocation message prefixed with `dr_`. A checkpoint is
additive; an omitted record is not deleted and an older checkpoint does not
replace a newer one. It never checkpoints itself or another checkpoint. Its
signer must have the scope needed for **each** retained record; the original
person key has all person scopes. A delegated checkpoint is usable only while
its own complete authority path is live. A root-person checkpoint is the durable
anchor; periodic root access can create one directly, including for an expired
path whose exact records the person chooses to endorse.

Retention covers admissions, bindings, unbindings, restrictive revocations and
person removals. The [transaction contract](machine-linking-transactions.md#invites-from-delegated-administrators)
adds exact completed invitation/redemption history, without preserving a live
invite. Retention does not cover policies, live invites, groups, certificates,
activation authority, or a person's administrator role. No checkpoint extends
policy validity, resets version high-water marks, revives a device, overrides
network-root revocations/removals/epoch rules, or authorizes a new operation.
Administrator-signed retained records additionally remain subject to that
person's network-root administrator delegation/removal and its existing exact
retained-statement rules. The person cannot preserve a role the root withdrew.
UP-06b must specify how new record IDs enter that root-signed retained list.

If the highest policy or group definition loses usable signing authority, stop
access derived from it and preserve its version high-water mark until an active
authority publishes a valid replacement. Never restore an older, more permissive
policy or group definition as an expiry/revocation fallback.

Unknown history is incomplete state: preserve the records and request an
unaffected ancestor/root checkpoint. Do not synthesize a new identity, silently
fall back to a permissive policy, or assert successful linking. A descendant can
approve another machine while the original machine is offline, but durable
proofs need retention/renewal before its path expires. This is an explicit
availability limit of the first version.

Revoke signing authority, unbind the host, remove it from trusted hosts and
obtain administrator membership revocation to retire a machine completely.
Signing-key revocation alone is never reported as complete machine removal.
Known revocations apply immediately; withholding can delay other receivers.

## 5. Pairing encryption

The private code is 16 cryptographically random bytes `S`, encoded using
[RFC 4648 Base32](https://www.rfc-editor.org/rfc/rfc4648.html#section-6), without
padding: 26 characters. Display `psl1-` and groups of 5, 5, 5, 5, 6 characters.
Input accepts that exact grouping or the ungrouped 26 characters and ASCII case
folding. Reject other whitespace, punctuation, padding, nonzero unused pad bits,
and lengths. Do not accept ambiguous `0`/`1` substitutions. The coordinator sees
only `locator = H(UTF8("peerspan-link-locator-v1") || 0x00 || S)`.

The new machine also generates an independent 32-byte random request nonce `R`.
Given the pinned coordinator public key and both new public keys:

```text
request_message = L("peerspan-link-request-id-v1", coordinator_public_key,
                    host_public_key, device_public_key, Base64(R))
request_id = "link_" + H(request_message)
salt = SHA256(UTF8("peerspan-link-extract-v1") || 0x00 ||
              raw_coordinator_public_key)
PRK = HKDF-Extract-SHA256(salt, S)
```

Each frame has exactly `format` (1), `request_id`, `locator`, `role`,
`writer_public_key`, `frame_id` (lowercase hex of 32 fresh random bytes), and
`ciphertext` (standard padded Base64 of ciphertext followed by its 16-byte tag).
Roles are `request`, `owner`, `selection`, `administrator`, `commit`, `result`.
They distinguish channel context, not authorization. The writer key and request
ID are visible metadata; frames cannot conceal which public keys are pairing.

```text
context = L("peerspan-link-frame-v1", request_id, locator,
            coordinator_public_key, role, writer_public_key, frame_id)
K = HKDF-Expand-SHA256(PRK, context, 32)
AAD = context
nonce = 12 zero bytes
ciphertext = AES-256-GCM-Seal(K, nonce, plaintext, AAD)
```

**K is a one-message key.** Each writer allocates a fresh frame ID before
sealing, seals once, and durably stores the complete immutable frame before
publishing. Retries retransmit that frame byte for byte. A different plaintext
needs a fresh ID/key; never reseal with an old frame ID. Receivers reject two
different ciphertexts for the same `(request_id, role, writer, frame_id)`.
Independent writers/roles derive different keys; a shared counter is unnecessary.
The zero nonce is valid only with this one-message-key rule. See
[HKDF](https://www.rfc-editor.org/rfc/rfc5869.html#section-2) and
[AEAD_AES_256_GCM and nonce requirements](https://datatracker.ietf.org/doc/html/rfc5116#section-5.2).
These primitives do not constitute a security review of the application protocol.

Frame plaintext is strict UTF-8 JSON, at most 64 KiB; it repeats the request ID,
role and writer key, which must match the authenticated header. All identity and
authority claims additionally require the appropriate signatures. A code holder
can produce a valid frame; AEAD authentication does not prove person authority.
The coordinator never receives `S`, `PRK` or `K`. Pending ceremony plaintext stays
encrypted; the proposed finalization route discloses the public signed activation
proofs for validation, without the code or private keys. Logs, errors and metrics
never include the private code or plaintext ceremony payloads. Private pending
state is owner-only and secrets are deleted at terminal completion. Public keys
and outcomes remain auditable.

## 6. Linking transaction requirements for UP-06b

The next slice must supply exact strict schemas and signing inputs for the
following ceremony, reusing the primitives above. Those bytes are deliberately
not invented independently in either host implementation.

1. A five-minute request proves possession of both new keys and binds protocol,
   coordinator pin, request ID and deadline. It cannot enroll a host on its own.
2. An owner offer binds the request, selected network/current root epoch,
   original person, both keys, parent chain, scopes/expiry, proposed certificate
   and binding. The new machine explicitly locks that owner/network before
   requesting separate administrator approval. A separate administrator gets
   the code only after that signed selection, and the UI explains the selected
   owner. Never silently switch owner after a selection.
3. Administrator approval binds the exact owner offer and admission. An owner
   without a current admin role stays `awaiting_administrator`. A machine with
   both roles may supply both proofs in one review. No reusable legacy admission
   signature is sent in an approval offer.
4. The new host/device sign final consent to the complete manifest: request,
   owner offer, administrator offer, certificate, binding, admission, epoch,
   keys and deadline. Both sides persist the operation ID before submission.
   A mailbox offer signature is never a substitute for this consent.
5. The coordinator transaction atomically stores admission, binding, certificate
   activation and operation result. Every receiver verifies the complete proof
   bundle itself. Generic endpoints reject linking records whose `operation_id`
   is not `-` unless that exact activation proof is present. Pending certificates
   cannot authorize their own admission, binding or any other operation.
6. The coordinator rejects a first commit after the fixed deadline. Exact retries
   return the original committed result, including after expiry. Conflicting
   manifests under one operation ID fail. Later receivers verify signed consent
   and authority, not a coordinator-asserted trustworthy commit timestamp.
   A malicious coordinator can delay an otherwise authorized operation; it
   cannot forge consent or make expired live signing authority usable.

### Cancellation and recovery

| Point reached | Required outcome |
| --- | --- |
| New machine has not signed final consent | It can cancel locally, retire the nonce/code and keep its keys; no activation proof exists. |
| Approver has sent a signed offer | Stopping its command is not withdrawal. The new machine may complete the offer within its window. Offer revocation needs a signed, propagated invalidation defined in UP-06b. |
| Final consent might have been sent | Report `finalizing`/unknown, query by operation ID and key IDs, and recover the exact result; do not report rollback. |
| Remote commit, local persistence interrupted | Recover and save the same admission, binding and certificate. Never re-enroll or generate another person. |
| Authority expires or an ancestor departs | Preserve identity/attachments, refuse new management and linking, and name the required ancestor/root renewal or checkpoint. |
| Linked and coordinator unavailable | Existing peer operations follow the outage contract and valid cached proofs. Authority expansion waits for current verified state. |

Request lifetime is exactly 300 seconds, never extended by polling. Bound a
mailbox to 64 frames and 512 KiB total stored bytes; each frame plaintext is at
most 64 KiB. Poll no faster than every 2 seconds and honor `Retry-After` on 429.
UP-06b must set per-source/global quotas, terminal retention and GC rules,
upgrade feature activation, and all conflict/error shapes. Do not discard sticky
revocations or version high-water marks to free quota.

### Upgrade and implementation gates

- Upgrade coordinator and all affected admitted hosts before enabling delegated
  writes. Unsupported readers must fail closed. UP-06b must specify a signed
  network-root feature activation with acknowledgments from all admitted hosts;
  offline/old hosts block activation until upgraded or explicitly removed.
  Unsigned version advertisements are insufficient. No private-key export fallback.
- Update every verifier and propagation path: maps, peer sync, policies,
  person/host admission, bindings, invites, groups, retained-admin records,
  revocations and renewal. A command-only signer patch cannot ship.
- Specify local signer discovery before automatic key generation, including
  `up`, owner CLI and daemon policy renewal. Expired authority is a repair case
  for the existing person. Keep explicit original-key workflows supported.
- Freeze request/offer/selection/admin/commit/result wire schemas, renewal versus
  new-host transitions, cancellation invalidation, durable operation recovery,
  storage migration, proof limits and error codes before writing either host.
- A separate author builds the conformance suite from the reviewed contract,
  under [AGENTS.md](../AGENTS.md). Runtime work follows that review, in slices
  shared by Go, Rust and the Go coordinator.

## 7. Vectors and verification

[machine-linking-v1.json](../conformance/vectors/machine-linking-v1.json) contains
**public fixture seeds**, never deployment keys. It freezes these primitive
examples: root-person → B → C certificates, SSHSIG inputs/signatures, binding
authorization and host consent, revocation/checkpoint messages, code encoding,
request ID, HKDF salt/PRK/key and AES-GCM ciphertext/tag. Fixture JSON strings are
literal byte inputs. The sample binding uses ordinary operation ID `-`; it is
not a complete linking activation transcript.

These are primitive vectors, not evidence that a protocol verifier, linking
ceremony, or recovery implementation exists. Full activation and signed semantic
negative vectors belong to UP-06b's completed transaction specification.

The reviewed contract must be exercised across Go/Rust signers and verifiers:

1. Reproduce every fixed byte/signature/ID. Reject altered payload bytes,
   trailing LF, wrong SSHSIG namespace/hash/key, bad AEAD tag/AAD, wrong coordinator,
   role, request ID and noncanonical Base32/Base64 (including unused pad bits).
2. Root → B → C works while the original machine is offline. Depth eight works;
   nine, cycles, repeated keys, wrong network/person, unknown/escalated scopes,
   a parent without delegation scope, and child expiry beyond parent fail.
   `now == not_after` is expired. A pending certificate has no live authority.
3. Owner actions retain stable person identity. Current role plus bit 8 permits
   administration; bit 8 alone does not. Network-root-only actions stay refused.
   A nonadministrator owner waits for separate admission of the same locked offer.
4. Revoke B, reject new B/C operations and leave an independent branch usable.
   An unaffected ancestor/root can revoke descendants; a sibling cannot.
   Backdating and replacement certificates cannot revive a revoked device key.
5. Refuse a self-invalidating delegated mutation without changing state. Root or
   an independent current authority can perform it. Restrictive host leave still
   works and explains the disabled path.
6. Expire/revoke a signer before a fresh receiver imports its history. Exact
   retained durable records work with a valid checkpoint and administrator/root
   constraints; unknown history fails closed. Checkpoints cannot revive policies,
   invites, certificates or role authority. Preserve policy version high-water
   marks when replacing an unusable highest policy.
7. Repeat/interleave offers, replay into another network/request, race conflicting
   owner selection and submit incomplete proofs. No membership, binding or live
   certificate appears before complete atomic activation. Restart each side
   after each persistence/commit boundary and recover stable IDs exactly once.
8. Check cancellation at every boundary, expiration before commit, lost result
   after commit, immutable frame retries, quotas, secret redaction and upgrade
   refusal. Neither a successful mailbox write nor remote commit alone reports
   `linked`; local verified persistence is required. Agent readiness is separate.
