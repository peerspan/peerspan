# Coordinator-free networks: wire formats

Status: **DRAFT for owner review, 2026-10-27.** Appendix to the
[coordinator-free spec](decentralized-spec.md). It gives the exact records,
packets, codes, routes, stored records, IDs and sizes. Every format is carried
over unchanged from the 2026-10-26 files unless a line says **Changed**, with
the decision (DEC-Sx or DEC-Qx) that changed it. Nothing here is open.

## 1. Conventions

- `H(x)` is SHA-256, written as 64 lowercase hex digits.
- `L(a,b,…)` is the UTF-8 strings joined by one LF, with no trailing LF. A part
  containing CR or LF is rejected.
- **Keys** are canonical padded standard Base64 of 32 raw Ed25519 bytes.
- **Binary JSON fields** are canonical padded standard Base64. **Display codes**
  use unpadded Base64URL.
- **Times** are whole-second UTC `YYYY-MM-DDTHH:MM:SSZ`, years 0001–9999, no
  leap second, no offset.
- **Integers** are JSON numbers without sign, fraction or exponent. u64 fields
  take 0 to 2^64−1 unless stated positive.
- **Strict JSON.** Reject invalid UTF-8, unknown, missing or duplicate fields,
  null, floats, negative or out-of-range numbers, wrong types and non-canonical
  Base64. Arrays are always present. An absent value is the string `-`.
- **Sorting** is by bytes of the stated key; "unique" means no duplicates after
  that sort.
- Formats below use JSON-like notation: `{a,b}` is an object with exactly those
  fields.

## 2. Descriptor and IDs

```text
{format:1, protocol:"peerspan-decentralized-v1", network_id, name, genesis_root_public_key}
```

- `network_id` = `net_` + H(genesis root public key), as in the coordination
  contract.
- `name`: trimmed, 1–128 bytes UTF-8, no control characters. It never changes.

```text
context_id = "ctx_" + H(L("peerspan-decentralized-context-v1",
                          "peerspan-decentralized-v1", network_id, name,
                          genesis_root_public_key))
```

A remembered network ID with a different name, genesis key or protocol is a
hard conflict.

## 3. Statements

### 3.1 Envelope

```json
{"format":1,"kind":"KIND","context_id":"ctx_...","payload_base64":"BASE64","signatures":[{"role":"ROLE","public_key":"KEY","format":"ed25519","signature":"BASE64"}]}
```

- `signatures` sorted by `role`, roles unique, only the kind's declared roles.
- `format` is `ed25519` (canonical Base64 of 64 raw bytes) or `sshsig`
  (canonical Base64 of the binary OpenSSH SSHSIG, Ed25519, SHA-512, namespace
  `peerspan-person-v1`).
- Original person keys use `sshsig`; host and device keys use `ed25519`; the
  root may use either.

### 3.2 IDs and signing message

```text
unsigned = L("peerspan-decentralized-statement-v1", KIND, CONTEXT_ID,
             H(exact decoded payload bytes))
statement_id = "ds_" + H(unsigned)

signature message = L("peerspan-decentralized-signature-v1", STATEMENT_ID,
                      ROLE, PUBLIC_KEY)

proof_id = "dp_" + H("peerspan-decentralized-proof-v1\n" + KIND + "\n" +
                     H(exact envelope bytes))
```

Note that the proof-ID message ends with the hash and has no trailing LF.

### 3.3 Catalog

```text
{format:1, context_id, objects:[{id, kind, body_base64}]}
```

- Sorted by `id` (a proof ID), unique. Each `kind` equals its decoded kind.
- The one composite kind is `activation` (section 9.5). **Changed (DEC-S12):**
  the `migration` composite kind is removed.
- Set ID, when a transport needs one:

```text
cat_ + H(L("peerspan-decentralized-catalog-v1", CONTEXT_ID,
           DECIMAL_OBJECT_COUNT, SORTED_PROOF_ID_1, …, SORTED_PROOF_ID_N))
```

  For an empty catalog the message ends at the count line `0`.

## 4. Grants

### 4.1 Grant payload

Kinds: `admin_lease`, `person_lease`, `host_lease`, `binding_lease`,
`device_lease`.

```json
{"root_state_id":"ds_...","operation_id":"-","sequence":1,"predecessors":[],"resolves":[],"retained_statement_ids":[],"subject":{"person_public_key":"-","host_public_key":"-","device_public_key":"-","member":"-","scopes":0},"issuer":{"kind":"root","person_public_key":"-"},"parents":[],"issued_at":"UTC","not_before":"UTC","not_after":"UTC"}
```

- `sequence`: positive u64. `predecessors`, `resolves`,
  `retained_statement_ids`: sorted unique statement IDs (at most 4096).
- `issuer.kind`: `root`, `person` or `device`; `person_public_key` is `-` only
  for root.
- `parents`: sorted array of `{role,id}`, unique by role. Roles:
  `issuer_admin`, `issuer_device`, `issuer_person`, `subject_binding`,
  `subject_host`, `subject_person`.
- `operation_id`: `-`, or the join request ID for a grant signed inside a join
  request.
- Unused subject fields are `-`; unused `scopes` is 0.

### 4.2 Subjects, parents and signatures

| Kind | Subject | Required parents | Signature roles |
| --- | --- | --- | --- |
| `admin_lease` | person; scopes 8 | none (root) | `issuer` (root) |
| `person_lease` | person, member; scopes 0 | root: none; person admin: `issuer_person`, `issuer_admin`; device admin: those plus `issuer_device` | `issuer` |
| `host_lease` | host, member; scopes 0 | as `person_lease` | `issuer`, plus `host` for `operation_id` `-` except a deadline-only renewal |
| `binding_lease` | person, host; scopes 2 | `subject_person`, `subject_host`, `issuer_person`, plus `issuer_device` for a device signer | `host`, `issuer`; `issuer` only for a deadline-only renewal |
| `device_lease` | person, host, device; scopes 1–15 | `subject_person`, `subject_host`, `subject_binding`, `issuer_person`, plus `issuer_device` for a device signer | `issuer` |

- **Changed (DEC-Q6, DEC-Q7, DEC-Q8):** a deadline-only device renewal (same
  keys, same or fewer scopes, target still current) uses `operation_id` `-`.
  When a sibling device signs it, the target's existing `issuer_device` parent
  is kept, the sibling is only the `issuer` signer (current, same person,
  scope 4), and the renewal is capped by the person, host and binding parents,
  not by the sibling's or the old issuer device's `not_after`. The signer may
  not be the target device.
- A deadline-only device renewal signed by the original person key preserves
  an existing `issuer_device` parent too. This exception applies only to a
  renewal of an already trusted, current device grant; ordinary original-key
  issuance has no `issuer_device` parent. The original-key renewal keeps the
  normal parent deadline caps and the target's delegation ancestry.
- **Changed (DEC-Q21):** the creator device grant made by `network create` uses
  `operation_id` `-`, sequence 1, scopes 15, issuer the original person key,
  and the genesis person, host and binding grants as parents. These two are the
  only device grants valid with `operation_id` `-` (confirmed, DEC-Q21).
- **Changed (DEC-Q27):** the creator device may sign deadline-only renewals of
  its own device grant and of its person's binding while it is that person's
  only current device (DEC-Q30). A
  deadline-only binding renewal signed by any device is capped by the
  `subject_person` and `subject_host` parents only.
- **Changed (DEC-Q28):** a deadline-only renewal of a `host_lease` or
  `binding_lease` carries only the `issuer` signature; the `host` role is
  required only at first issue.
- **Changed (DEC-Q29):** an `issuer_device` ancestor counts as current while
  its device stream has a current, unrevoked head.
- **Changed (DEC-Q31):** for a deadline-only renewal whose `issuer` signer is
  not the `issuer_device` parent, `issuer.kind` is `device`, the rule that the
  signer equals the `issuer_device` key is relaxed, and the verifier uses the
  current head of the stream `device/PERSON/SIGNING_KEY` as the signer's grant
  (current, unbanned, scope 4, same person). No format change.
- **Changed (DEC-S9, DEC-Q10):** a binding renewal may be signed by a scope-2
  or scope-4 device.
- A ceremony host lease carries only `issuer`; the host's consent is in the
  join request.

### 4.3 Timing

- 7 days = 604800 seconds; 24 hours = 86400 seconds.
- `issued_at ≤ not_before < not_after`; `not_after − issued_at ≤` the kind's
  maximum; `not_after ≤` every parent's `not_after`, except as changed above
  for sibling renewals.
- Usable when `not_before ≤ decision_time < not_after`.
- **Changed (DEC-S15):** the rule that a verifier refuses a freshly signed
  statement whose `issued_at` is more than 300 seconds before decision time is
  removed. `issued_at` later than decision time still refuses.

## 5. Policies and groups

Envelope kinds `policy` and `group`. Payload fields, exactly:

```text
{root_state_id, operation_id:"-", sequence, predecessors, resolves, issuer,
 parents, issued_at, not_before, not_after, body_base64}
```

- One `issuer` signature. No `retained_statement_ids`.
- `body_base64` is the existing unsigned `peerspan-policy-v2` or group-v1 body.
  Its version equals `sequence`; its issued and expiry fields equal the
  wrapper's.
- Policy: `valid_until − issued_at` is positive and at most 86400 seconds,
  capped by every parent. The old 1-day minimum and 90-day maximum apply only
  to legacy records.
- Policy signer: the person's original key or a scope-1 device. Group signer:
  the root or a scope-8 admin.

## 6. Root states

```json
{"epoch":0,"predecessors":[],"resolves":[],"migration_proposal_id":"-","root_public_key":"KEY","issued_at":"UTC","retained_statement_ids":[]}
```

| Form | Constraints | Signature roles |
| --- | --- | --- |
| Genesis | epoch 0; empty arrays; key = descriptor genesis key | `issuer` (genesis key) |
| Normal transition | exactly one predecessor; `resolves` empty; epoch = predecessor + 1 | `issuer` (predecessor's root), `new_root` (next root) |

- `retained_statement_ids` lists finite grants kept (never a root state).
- **Changed (DEC-S12, DEC-S13):** the migrated initial form and the fork
  resolution form (with its `root_branch:P` roles) are removed; readers reject
  a root state with more than one predecessor (DEC-Q19).
- **Changed (DEC-Q14):** `migration_proposal_id` stays, always `-`.

## 7. Restrictions

Kinds `admin_withdraw`, `person_remove`, `host_revoke`, `host_unbind`,
`device_revoke`. Payload:

```json
{"root_state_id":"ds_...","issuer":{"kind":"root","person_public_key":"-"},"parents":[],"issued_at":"UTC","target":{"statement_id":"-","person_public_key":"-","host_public_key":"-","device_public_key":"-"},"kept_statement_ids":[],"ratifies":"-"}
```

One `issuer` signature; no sequence or expiry.

| Kind | Target fields set | Kept list |
| --- | --- | --- |
| `admin_withdraw` | `statement_id` (the admin grant), `person_public_key` | person and host grants issued under that role |
| `person_remove` | `person_public_key` | empty |
| `host_revoke` | `host_public_key` | empty |
| `host_unbind` | `statement_id` (the binding), `person_public_key`, `host_public_key` | empty |
| `device_revoke` | `person_public_key`, `device_public_key` | empty |

`ratifies` is `-` or the ID of an older ban of the same kind with the same
target and kept list.

## 8. Contacts and endpoints

### 8.1 Endpoint

`HOST:PORT`, at most 260 ASCII bytes.

- PORT: 1–65535, no leading zero or sign.
- HOST: dotted-decimal IPv4 (four octets 0–255, no leading zeros), bracketed
  lowercase RFC 5952 IPv6, or lowercase ASCII DNS (1–253 bytes, no final dot,
  labels 1–63 of `a-z0-9-`, no leading or trailing hyphen, IDNA already
  `xn--`). IPv4-mapped IPv6 is written as IPv4.
- Invalid: zones, empty host, unspecified address, whitespace or controls, URL
  parts, Unicode DNS, and any all-digits-and-dots host that is not canonical
  IPv4 (`123`, `127.1`, `01.2.3.4`, trailing dot). `123.example` is DNS.
- Loopback and link-local literals are allowed as hints.

### 8.2 Signed contact

```text
{format:1, context_id, host_public_key, sequence, issued_at, expires_at,
 payload_base64, signature}
payload = {quic_addresses:[ENDPOINT], bootstrap_addresses:[ENDPOINT],
           relays:[{address:ENDPOINT, public_key}]}
signature = Ed25519 by the host over
  L("peerspan-decentralized-contact-v1", context_id, host_public_key,
    sequence, issued_at, expires_at, H(decoded payload bytes))
```

- `context_id` is `-` only for a fresh unbound endpoint.
- Address arrays sorted by ASCII, relays by (address, key); each unique, at most
  8; at most 16 addresses in total; body at most 8 KiB.
- `expires_at − issued_at ≤ 300` seconds; at most 30 seconds future skew.
- `sequence` only increases per host and context. Two different contacts at
  the same sequence suppress that sequence until a higher one arrives.

## 9. Join request

### 9.1 Request payload and ID

```text
{mode:"new"|"renew", host_public_key, device_public_key, request_nonce,
 expected_network_id, expected_context_id, expected_person_public_key,
 migration_proposal_id, renewed_device_lease_id, created_at, expires_at}
request_id = "link_" + H(L("peerspan-decentralized-request-id-v1",
                           H(exact request payload bytes)))
```

- `request_nonce`: 32 random bytes, Base64. The pairing secret: 16 random
  bytes.
- Unknown expected values are `-`. A renewal fills all of them and the prior
  device grant ID.
- **Changed (DEC-S4, DEC-Q1):** `expires_at = created_at + 3600` seconds
  (was + 300). The 10-minute inactivity rule is enforced locally.
- **Changed (DEC-Q14):** `migration_proposal_id` is always `-`.

### 9.2 Packet

```text
{format:1, context_id, request_id, role, writer_host_public_key,
 signer_public_key, person_public_key, issuer_id, payload_base64,
 host_signature, device_signature, authority_signature_format,
 authority_signature}
M = L("peerspan-decentralized-packet-v1", context_id, request_id, role,
      writer_host_public_key, signer_public_key, person_public_key, issuer_id,
      authority_signature_format, H(decoded payload bytes))
packet_id = "dpk_" + H(M)
```

- Every packet: raw Ed25519 `host_signature` over `M` by the writer host.
- `request`, `selection`, `commit`: also `device_signature` by the request
  device (which is `signer_public_key`); authority fields `-`.
- `owner`, `owner_finalization`, `administrator`: `authority_signature` over `M`
  in `authority_signature_format` (`ed25519` for a device or raw root, `sshsig`
  for an original key or SSH root); `device_signature` `-`.
- `outcome`: signer, person, issuer, device and authority fields `-`.
- Role bindings: `request`, `selection` and `commit` are written by the target
  host and signed by the target device. `request` has context, person and
  issuer `-`. `selection` and `commit` have person = the selected original key
  and issuer `-`. `owner` and `owner_finalization` have person = the owner and
  `issuer_id` = the signing device grant's ID or `-` for the original key.
  `administrator` has person = the admin's original key and `issuer_id` = the
  admin's device grant or `-`; for the root, person `-` and `issuer_id` = the
  root state ID.
- Packet at most 1 MiB, payload at most 256 KiB, request packet at most 8 KiB.

### 9.3 Stage payloads

| Stage | Payload |
| --- | --- |
| Owner offer | `{request_packet_id, descriptor, root_state_id, person_lease_id, issuer_lease_ids, mode, member, host_public_key, device_public_key, scopes, not_after, renewed_device_lease_id}` |
| Selection | `{request_packet_id, owner_offer_id, context_id, person_public_key, host_public_key, device_public_key, selected_at}` |
| Administrator | `{selection_id, owner_offer_id, root_state_id, issuer_lease_ids, person_lease, host_lease}` |
| Owner finalization | `{selection_id, administrator_offer_id, root_state_id, person_lease_id, host_lease_id, binding_lease, device_lease}` |
| Commit | `{manifest_base64, binding_host_signature, committed_at}` |
| Outcome | `{context_id, request_id, manifest_id, activation_id, activation_sha256, observed_root_state_id, applied_at}` |

- `issuer_lease_ids`: sorted unique.
- New-person owner offer: `root_state_id` and `person_lease_id` `-`,
  `issuer_lease_ids` empty, signed by the new person's original key only.
- Administrator `person_lease`/`host_lease`: a full signed envelope, or the ID
  string of an already current unchanged grant.
- Owner finalization `binding_lease`: a draft envelope with both `host` and
  `issuer` entries, the host entry's `signature` `-`; or, for renew mode with an
  unchanged binding, its ID string.
- Commit `binding_host_signature`: the host's signature on the binding, or `-`
  when an unchanged binding is reused.
- **Changed (DEC-S7, DEC-Q4):** when the admin stage is folded,
  `administrator_offer_id` is `-` and `person_lease_id`/`host_lease_id` name
  grants signed by the owner's admin path; their bodies travel in the commit
  catalog.

### 9.4 Manifest

```text
{format:1, context_id, request_id, request_packet_id, owner_offer_id,
 selection_id, administrator_offer_id, owner_finalization_id, root_state_id,
 person_lease_id, host_lease_id, binding_lease_id, device_lease_id,
 binding_proof_id, device_proof_id, ancestor_statement_ids, proof_ids}
manifest_id = "dm_" + H(L("peerspan-decentralized-manifest-v1",
                          H(exact manifest bytes)))
```

- At most 16 KiB.
- `ancestor_statement_ids`: the device grant's complete closure. Starting from
  the person, host, binding and device grants, add every `root_state_id`,
  parent, predecessor, `resolves` entry and `retained_statement_ids` entry of
  each reached statement, and for a reached ban its `target.statement_id`,
  `ratifies` and kept entries, until nothing new is added. Exclude the device
  grant itself.
- `proof_ids`: the exact proofs presented, including every signature, the
  device grant body and any known required current retainer. Never the
  activation itself or an outcome.

### 9.5 Activation

```text
{format:1, context_id, request, owner, selection, administrator,
 owner_finalization, commit}
activation_id = "da_" + H(L("peerspan-decentralized-activation-v1",
                            context_id, request_id, manifest_id,
                            commit_packet_id))
```

- Each role holds the exact packet object. `administrator` is `-` for a renewal
  with unchanged person and host grants and, **changed (DEC-S7)**, for a folded
  admin stage.
- At most 1 MiB. Its catalog travels separately. As a catalog object it has kind
  `activation` and an ordinary proof ID over its exact bytes.

## 10. Codes

### 10.1 Invite code (`psi2-`)

`psi2-` + unpadded Base64URL of:

```text
{format:1, context_id, inviter_host_public_key, payload_base64, signature}
payload = {descriptor, expected_person_public_key, member, issued_at,
           expires_at, contacts:[SIGNED_CONTACT], helpers:[{address,public_key}]}
I = L("peerspan-decentralized-contact-invitation-v1", context_id,
      inviter_host_public_key, H(decoded payload bytes))
invitation_id = "di_" + H(I)
signature = Ed25519 by the inviter host over I
```

- Contacts all signed by the inviter host for this context; at most 4 contacts
  and 4 helpers, ordered as in section 10.2. Whole code at most 32 KiB.
  **Changed (DEC-Q25):** inside a valid invite, contacts past their 300-second
  expiry are still used as address hints; they confer nothing else.
- **Changed (DEC-S4, DEC-Q2):** `expires_at − issued_at` is 60 to 86400
  seconds (was exactly 300); the default is 3600. Accepted while
  `issued_at ≤ decision_time + 30` and `decision_time < expires_at`.
- **Changed (DEC-Q3):** the payload gains `return_secret_base64` (16 random
  bytes), placed after `helpers`:
  `{descriptor, expected_person_public_key, member, issued_at, expires_at,
  contacts, helpers, return_secret_base64}`. The joiner uses it as the pairing
  secret of section 11 with `request_id` replaced by the `invitation_id`:
  locator, read capability, keys and AD are derived from the return secret and
  the invitation ID, and one frame of role `request` carries the request code's
  JSON object in `packet_base64` with `catalog_base64` `-`. It is posted to a
  mailbox whose window is the invite's `issued_at`..`expires_at`.

### 10.2 Request code (`psl2-`)

`psl2-` + unpadded Base64URL of:

```text
{format:1, request_id, secret_base64, request_packet_base64,
 contacts:[SIGNED_CONTACT], helpers:[{address,public_key}]}
```

- At most 4 contacts and 4 helpers; at most 32 KiB.
- **Changed (DEC-Q33):** while the request is within its window, contacts in
  the code past their 300-second expiry are still used as address hints.
- Contacts are signed by the request's writer host. Contacts sorted by
  (context_id, host key, sequence as u64, H(body)); helpers by (address, key).
- **Changed (DEC-S6, DEC-Q3):** for an invite-based join, printed only when
  every return path fails within one 30-second attempt.

Codes are never put in logs, URLs, query strings, status or peer routes.

## 11. Encrypted frames

```text
{format:1, request_id, locator, role, writer_host_public_key, frame_id,
 created_at, expires_at, ciphertext_base64, signature}
```

```text
locator  = H(L("peerspan-decentralized-locator-v1", Base64(secret)))
read_cap = H(L("peerspan-decentralized-read-cap-v1", Base64(secret)))
salt     = SHA256(L("peerspan-decentralized-frame-salt-v1", request_id))
key      = HKDF-SHA256(secret, salt,
             L("peerspan-decentralized-frame-key-v1", request_id, role,
               writer_host_public_key), 32)
nonce    = first 12 bytes of SHA256(L("peerspan-decentralized-frame-nonce-v1",
             frame_id))
AD       = L("peerspan-decentralized-frame-v1", request_id, locator, role,
             writer_host_public_key, frame_id, created_at, expires_at)
ciphertext = AES-256-GCM(key, nonce, AD, plaintext), including the 16-byte tag
signature  = Ed25519 by the writer host over
             L("peerspan-decentralized-frame-envelope-v1", AD, H(ciphertext))
plaintext  = {packet_base64, catalog_base64, contacts}
```

- `frame_id`: 32 random bytes as lowercase hex, never reused.
- Roles: `request`, `owner`, `selection`, `administrator`,
  `owner_finalization`, `commit`, `outcome`, `proofs`.
- `created_at`/`expires_at` equal the request window.
- `packet_base64` or `catalog_base64` may be `-`, not both. A catalog component
  is at most 2 MiB and split only between whole objects. Plaintext at most
  4 MiB.

## 12. Mailbox routes

On a first-contact listener or helper, ALPN `peerspan-bootstrap/1`.

| Route | Request | Success |
| --- | --- | --- |
| `POST /bootstrap/v1/mailboxes` | `{format:1, request_id, locator, read_cap_hash, created_at, expires_at, frame}` | 201 `{request_id, locator}`; same retry 200 |
| `POST /bootstrap/v1/mailboxes/{locator}/frames` | `{frame}` | 200 `{frame_id}`; same frame 200; same ID, other bytes 409 |
| `GET /bootstrap/v1/mailboxes/{locator}` | none | 200 `{format:1, request_id, created_at, expires_at, frames:[FRAME]}` |
| `DELETE /bootstrap/v1/mailboxes/{locator}` | none | 204, idempotent |

- Every route needs exactly one `Authorization: Bearer READ_CAP` (64 lowercase
  hex). Missing: 403. Malformed or duplicated: 400. Wrong for a known box: 403.
  `read_cap_hash` = H(READ_CAP as UTF-8).
- The frame writer must equal the TLS client key (403 otherwise). The first
  frame has role `request`.
- Optional operator credential: one `X-Peerspan-Resource-Token: BASE64` header,
  at most 1024 decoded bytes, no CR, LF or NUL.
- Window: `created_at ≤ now + 30`, `now < expires_at`, frames equal the box.
  The return mailbox of an invite (section 10.1) uses the invite's window.
  **Changed (DEC-S4, DEC-Q1):** lifetime is exactly the request window (was
  exactly 300 seconds). Elapsed: 410. Impossible: 400.
- Expiry or DELETE erases ciphertext; a tombstone of at most 1 KiB stays until
  `expires_at` + 24 hours. GET of deleted: 404; of expired: 410. Create or append
  on a tombstone: 410.

```text
creation_identity_hash = H(L("peerspan-decentralized-mailbox-create-v1", "1",
  request_id, locator, read_cap_hash, created_at, expires_at,
  H(exact first FRAME bytes)))
```

- Frames returned sorted by (role, writer key, frame ID).
- No query strings, no trailing-slash or percent-encoded aliases; unknown route
  404; wrong method 405 with `Allow`.
- Errors: `{code, error, required_ids:[]}`; 400 invalid, 403 forbidden, 404
  not_found, 409 state_conflict/operation_conflict/quota_exceeded, 410 expired,
  429 rate_limited with `Retry-After`.

## 13. Completion routes

On the first-contact listener (HTTP) and on QUIC ALPN `peerspan-completion/1`.

| Route | Request | Success |
| --- | --- | --- |
| `POST /bootstrap/v1/activations` | `{activation, catalog}`, at most 20 MiB | 200 `{outcome, activation, catalog}` |
| `GET /bootstrap/v1/operations/{request_id}` | none | 200 same shape; 404 if no outcome |

- Client and server must both be participants; else 403. Mismatched applied
  request: 409 `operation_conflict`.
- QUIC completion: one bidirectional stream, one request, then close; 30-second
  overall bound. Relayed provisional routes: at most 16 per helper key and 128 in
  total, 5-second handshake; at most 4 requests per key, 16 per source, 128 in
  total.

## 14. Relay (`peerspan-relay/4`)

Frame: 1 type byte, 2-byte big-endian length, payload.

| Type | Payload |
| --- | --- |
| `0x00 AUTH` | operator token, 0–1024 bytes UTF-8; empty = anonymous |
| `0x07 AUTH_OK` | empty (server) |
| `0x08 AUTH_REFUSED` | empty (server), then close |
| `0x01 SEND` | 32-byte destination host-ID digest + 1–1500 datagram bytes |
| `0x02 RECEIVE` | 32-byte source host-ID digest + 1–1500 datagram bytes |
| `0x03 UNREACHABLE` | 32-byte destination digest |
| `0x04 PING` | empty |

- AUTH within 5 seconds of TLS. Registration 300 seconds; renew by 240. No SEND
  while AUTH is pending. Idle close at 60 seconds; clients ping every 15.
- Any other type, wrong direction, wrong length or bad UTF-8 closes the
  connection.
- A new authenticated connection for the same key replaces the old one. A
  different key under the same digest is refused.
- Limits: 1024 connections, 1024 queued datagrams per connection, 64 MiB queued
  in total, 32 MiB per minute per host key and per source, 1024 frames per
  second (burst 1024), AUTH 2 per second (burst 8), 64 connections per source.
  Source = full IPv4 or IPv6 /64.

## 15. Peer and repair routes

| Route | Request | Success |
| --- | --- | --- |
| `GET /peer/v2/networks/{id}/catalog` | none | 200 `{catalog}`, at most 20 MiB |
| `POST /peer/v2/networks/{id}/catalog` | `{catalog}`, at most 20 MiB | 200 `{catalog}` (the verified union) |
| `GET /peer/v2/networks/{id}/contacts` | none | 200 `{contacts:[SIGNED_CONTACT]}`, at most 1 MiB |
| `POST /peer/v2/networks/{id}/contact` | `{contact}`, at most 16 KiB | 200 `{contact}` |
| `GET /repair/v1/networks/{id}/catalog` (ALPN `peerspan-state-repair/1`) | none | 200 `{catalog}`, at most 20 MiB; 1 per second, burst 4 |

**Changed (DEC-S12):** `GET/POST /peer/v2/networks/{id}/migration` is removed.

## 16. Owner-local API

### 16.1 Errors

```text
{code, error, details:{network_id, context_id, request_id, stage,
 required_ids, conflict_ids, next}}
```

- `stage`: create, request, owner, selection, administrator,
  owner_finalization, commit, apply, sign, repair, transport or clock.
  **Changed (DEC-S12):** `migration` is removed.
- Strings at most 1024 bytes, no secrets.

| HTTP | Codes |
| --- | --- |
| 400 | invalid |
| 403 | forbidden, authority_expired, device_revoked, not_yet_valid, authority_would_be_invalidated |
| 404 | not_found |
| 409 | proof_required, state_conflict, operation_conflict, version_exhausted, quota_exceeded, clock_rollback, review_required, signer_unavailable, recovery_required |
| 410 | expired |
| 426 | upgrade_required |
| 429 | rate_limited |
| 500 | internal |

**Changed (DEC-S12):** `migration_pending` is removed.

Mutation bodies at most 1 MiB unless stated; responses at most 32 MiB; GET has
no query or body; `approve` never defaults to true.

### 16.2 Views

```text
NETWORK_VIEW = {id, name, mode:"decentralized", context_id,
  genesis_root_public_key, root_state_id, root_public_key, root_epoch, member,
  host_public_key, person_public_key, provider, provider_state, authority,
  delivery, created_at}
authority      = {state, not_after, required_ids, conflict_ids}
provider_state = {state:"available"|"unavailable"|"not_selected", code, error,
                  required_ids}
delivery       = {pending_proof_ids, peer_errors:[{host_public_key, code}]}
PROVIDER_VIEW  = {kind:"original_person"|"device"|"network_root",
  person_public_key, host_public_key, device_public_key, lease_id,
  root_state_id, scopes, not_after}
```

- `authority.state`: usable, unbound, authority_expired, proof_required,
  state_conflict, forbidden, device_revoked, not_yet_valid, clock_rollback.
  **Changed (DEC-S12):** `migration_pending` removed.
- `provider` is null only when no provider is selected. In a root split
  `root_state_id` and `root_public_key` are `-`.

| Route | Response |
| --- | --- |
| `GET /v2/networks` | `[NETWORK_VIEW]` sorted by ID |
| `GET /v2/networks/{id}` | `NETWORK_VIEW` |
| `GET /v2/networks/{id}/members` | `{context_id, members:[{host_public_key, member, person_public_key, host_lease_id, binding_lease_id, device_lease_id, not_after}]}` |
| `GET /v2/networks/{id}/persons` | `{context_id, persons:[{person_public_key, member, person_lease_id, not_after}]}`, at most 4096 |
| `GET /v2/networks/{id}/policy/{person}` | `{statement_id, statement_base64}`; 404 when none current |
| `GET /v2/networks/{id}/groups` | `{context_id, groups:[{name, statement_id, statement_base64}]}` |
| `GET /v2/networks/{id}/access-versions` | `{policies:[{person_public_key, version, statement_ids, head_ids}], groups:[{name, version, statement_ids, head_ids}]}` |
| `GET /v2/networks/{id}/provider` | `PROVIDER_VIEW`; 404 only when none selected |
| `POST /v2/networks/{id}/provider` | body `{provider_id, person_public_key, host_public_key, approve}`; returns `{network, provider, provider_state}` |
| `GET /v2/networks/{id}/catalog` | `{catalog}` |
| `GET /v2/networks/{id}/planning` | `{network, decision_time, catalog, streams:[{stream_kind, subject, subject2, head_ids, version, statement_ids, floor_proof_ids}]}` |

### 16.3 Creation

- `POST /v2/networks`: `{name, member, person_public_key, approve}` → 200
  `{creation_id, review, signing_requests, network, committed}`.
- `review` = `{name, member, descriptor, root_state_id, person_public_key,
  host_public_key, not_after, authority_warning}`. `network` is null until
  complete.
- `creation_id` = `create_` + 32 random bytes as lowercase hex.
- `GET /v2/network-creations/{id}`; `POST .../approve` with `{context_id,
  root_state_id, person_public_key, host_public_key, approve}`; `POST
  .../signed` with the common signatures body.
- **Changed (DEC-S15):** the 300-second re-approval window for an unfinished
  creation is removed.

### 16.4 Signing requests and actions

```text
SIGNING_REQUEST = {intent_id, slot_id, object_type, object_id, role,
                   public_key, format, template_base64, message_base64}
signed body     = {intent_id, signatures:[{slot_id, role, signature}]}
```

- `slot_id` positive u64 from 1 in dependency order. At most 16 requests per
  batch; 1–16 signatures per submission, unique by (slot_id, role), sorted.
- `object_type`: root_state, admin_lease, person_lease, host_lease,
  binding_lease, device_lease, policy, group, admin_withdraw, person_remove,
  host_revoke, host_unbind, device_revoke, owner_offer_packet,
  administrator_packet, owner_finalization_packet. **Changed (DEC-S12):**
  migration_proposal, migration_ack and migration_commit removed.
- For the three packet types `role` is `authority`, `message` is the packet's
  `M`, `public_key` is its `signer_public_key`.

`POST /v2/networks/{id}/actions`:

```text
request  = {kind, provider_id, signature_format, payload_base64, approve}
response = {action_id, review, signing_requests, statement_base64, proof_id,
            catalog, committed, delivery}
review   = {kind, statement_id, provider, subject, sequence, not_after,
            authority_warning}
action_id = "act_" + H(L("peerspan-decentralized-action-intent-v1",
                         context_id, kind, statement_id, provider_id))
```

- `kind`: admin_lease, person_lease, host_lease, binding_lease, policy, group,
  admin_withdraw, person_remove, host_revoke, host_unbind, device_revoke,
  root_state. **Changed (DEC-Q6):** also `device_lease`, only for a
  deadline-only renewal.
- `provider_id`: `auto`, `network_root`, an owned device grant ID, or the bound
  original key. `signature_format`: `auto`, `ed25519`, `sshsig`.
- `GET .../actions/{action_id}`; `POST .../actions/{action_id}/signed`.
- `POST /v2/networks/{id}/policy-claims`: `{capability, provider_id,
  signature_format, payload_base64, approve}`; same response shape, kind
  `policy_claim`, `committed:false` always. `GET .../policy-claims/{action_id}`;
  `POST .../signed`.

### 16.5 Root rotation

- `GET /v2/networks/{id}/root-retention` → `{network_id, context_id,
  decision_time, root_head_ids, catalog, candidates:[{statement_id, kind,
  required_retained_ids, effective_scopes, effective_not_after}],
  excluded:[{statement_id, code, required_ids}]}`.
- `POST /v2/networks/{id}/root-transitions`: `{new_root_public_key,
  new_root_signature_format, signature_format, retained_statement_ids,
  approve}` → action response. `new_root_public_key` `-` asks the daemon to
  generate a raw root seed.

### 16.6 Policy edits

- `GET /v2/networks/{id}/policy-edits` → `{context_id, person_public_key,
  edits:[{seq, state, signed_version, dropped}]}`.
- `POST /v2/networks/{id}/policy-edits/reapply-preview`: `{provider_id}` → 200
  `{context_id, person_public_key, host_public_key, provider, payload_base64,
  unsettled_seqs}`; `payload_base64` `-` when nothing is unsettled.
- **Changed (DEC-S16):** `POST /v2/networks/{id}/policy-edits` (reservation) is
  removed.
- `POST /v2/networks/{id}/policy-edits/plan`: `{provider_id}` → 200
  `{context_id, person_public_key, policy, version, seq, created_at}`, read-only:
  the current policy reference and version and this host's next edit number
  (DEC.impl28).

### 16.7 Invitations and sync

- `POST /v2/networks/{id}/invitations`: `{member, expected_person_public_key}`
  → 201 `{network_id, context_id, invitation_id, invitation, expires_at}`.
  **Changed (DEC-Q2):** the body is `{member, expected_person_public_key,
  expires_at}`; `expires_at` is 60 to 86400 seconds after decision time.
- `POST /v2/networks/{id}/sync`: `{}` → 200 `{network, attempted,
  learned_proof_ids, unavailable:[{host_public_key, code}]}`.

### 16.8 Join requests

```text
LINK_VIEW = {request_id, role, mode, state, network_id, context_id,
  migration_proposal_id, person_public_key, host_public_key,
  device_public_key, created_at, expires_at, request_packet_id,
  owner_offer_id, selection_id, administrator_offer_id,
  owner_finalization_id, manifest_id, activation_id, outcome_id,
  selection_approved, commit_approved, completed, attention, next}
```

- `role`: requester or approver. `state`: pending, needs_selection,
  needs_administrator, needs_owner_finalization, needs_commit, finalizing,
  linked, cancelled, expired, blocked. **Changed (DEC-S12):**
  migration_prepared and migration_adopted removed. **Changed (DEC-Q14):**
  `migration_proposal_id` always `-`.
- `completed`: ordered subset of request_created, owner_offered,
  owner_selected, administrator_offered, owner_finalized, commit_persisted,
  locally_applied.

| Route | Request | Success |
| --- | --- | --- |
| `POST /v2/link/requests` | `{mode, network_id, person_public_key, migration_proposal_id, contact_invitation, helpers}` | 201 LINK_VIEW + `display_code`; same retry 200 |
| `GET /v2/link/requests`, `GET .../{id}` | none | LINK_VIEW list / one |
| `POST .../{id}/resume` | `{}` | 200 LINK_VIEW |
| `POST .../{id}/cancel` | `{}` | 200 LINK_VIEW |
| `POST /v2/link/approvals` | `{code, network_id, person_public_key, provider_id, signature_format, scopes, not_after, expected_host_public_key, expected_device_public_key, approve}` | `{request, review, signing_requests}` |
| `POST /v2/link/admissions` | `{code, network_id, person_public_key, provider_id, signature_format, owner_offer_id, selection_id, expected_host_public_key, expected_device_public_key, approve}` | same |
| `POST .../{id}/finalization` | `{owner_offer_id, selection_id, administrator_offer_id, network_id, context_id, person_public_key, host_public_key, device_public_key, approve}` | same |
| `GET .../{id}/approval` | none | same; 409 when no approved plan |
| `POST .../{id}/signed` | signed body | same |
| `POST .../{id}/selection` | `{owner_offer_id, network_id, context_id, person_public_key, host_public_key, device_public_key, approve}` | `{request, review}` |
| `POST .../{id}/commit` | `{owner_offer_id, selection_id, administrator_offer_id, owner_finalization_id, network_id, context_id, person_public_key, host_public_key, device_public_key, approve}` | `{request, review}` |

Review:

```text
{stage, network_id, context_id, person_id, person_public_key,
 host_public_key, device_public_key, root_state_id, provider, owner_offer_id,
 selection_id, administrator_offer_id, person_lease_id, host_lease_id,
 binding_lease_id, device_lease_id, scopes, not_after, authority_warning}
```

**Retained request references:** the CLI may accept a retained request ID and
resolve its private code locally. The ordinary approvals/admissions HTTP bodies
remain the exact code-based shapes in the table and runtime contract. The
earlier DEC-Q3 sentence advertising an additional HTTP `request_id` field was
stale: that expansion is not available. Do not send `code:"-"` plus `request_id`.
The guided admission-consent endpoints have their separate section21
context/request-ID contract and do not expand these ordinary wire bodies.

For an owner approval, `provider_id:"network_root"` explicitly requests the
root-seed fold (spec 8.2). The selected owner provider still signs the owner
stages; the current local root seed signs the folded host grant. The review's
`provider` names that owner provider, `authority_warning` explicitly states
the additional root use, and `host_lease_id` pins the exact root-signed host
template under the same approval. No provider selection is changed. Admission
reviews continue to use `network_root` as their root signing provider.

### 16.9 Info and status

- `GET /v2/info`: existing fields, `default_coordinator: null`,
  `network_protocols: ["peerspan-decentralized-v1"]`.
- Legacy network status entry:

```text
{mode:"legacy_history", migration_required:true, id, name, coordinator,
 last_sync_at, last_sync_error, members, person, policy,
 policy_deliveries_pending}
```

  The nine old fields keep their types (`last_sync_at` and `last_sync_error`
  string or null; `person` null or `{id,label}`; `policy` null or
  `{version,valid_until}`). Unchanged (DEC-Q15).
- Attention entries use the existing `{kind, subject, detail, command}`.

## 17. Transport file

```text
{format:1, advertise_bootstrap:[ENDPOINT], advertise_quic:[ENDPOINT],
 rendezvous:[{address, public_key, token_file}],
 relays:[{address, public_key, token_file}], publish_contacts:boolean}
```

`token_file` is `-` or a protected local file. Bind syntax may use wildcard
addresses and port 0; advertised endpoints may not. **Changed (DEC-Q20):**
`publish_contacts` must be `false`.

## 18. Helper files

- Stdout on listen: `{public_key, address, protocols:["peerspan-bootstrap/1",
  "peerspan-relay/4"]}`. `info`: `{public_key, protocols:[…]}`.
- Tokens file (owner-only regular file, at most 1 MiB):
  `{format:1, accounts:[{id, tokens:[BASE64]}]}`. IDs 1–128 bytes of
  `[a-z0-9_-]`, sorted, at most 1024 accounts, 1–8 tokens each; tokens 1–1024
  decoded bytes, sorted, unique across the file.
- Stored frame bodies at most 512 MiB in total.
- Archive: `peerspan-helper-VERSION-linux-ARCH.tar.gz` with the binary, the
  operator guide and `RELEASE.json` (`version, source_revision, source_dirty,
  os, architecture`), plus `.sha256`.

## 19. Stored records

All records are strict JSON as in section 1. U64 columns store 0 to 2^63−1 as
SQLite INTEGER and 2^63 to 2^64−1 as an 8-byte big-endian BLOB.

### 19.1 Tables (introduced in schema 23, unchanged in schema 24)

Schema24 additionally adds one owner-local project-review table, specified in
the [guided session contract](guided-session-contract.md#advanced-cli-and-storage).
It changes no DEC columns or authority records below.

```sql
CREATE TABLE dec_contexts (network_id TEXT NOT NULL, context_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, context_id));
CREATE TABLE dec_objects (network_id TEXT NOT NULL, context_id TEXT NOT NULL, proof_id TEXT NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY(network_id, context_id, proof_id));
CREATE TABLE dec_admissions (network_id TEXT NOT NULL, context_id TEXT NOT NULL, statement_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, context_id, statement_id));
CREATE TABLE dec_restrictions (network_id TEXT NOT NULL, context_id TEXT NOT NULL, restriction_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, context_id, restriction_id));
CREATE TABLE dec_activations (network_id TEXT NOT NULL, context_id TEXT NOT NULL, activation_id TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, context_id, activation_id));
CREATE TABLE dec_heads (network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL, subject TEXT NOT NULL, subject2 TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2));
CREATE TABLE dec_highwater (network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL, subject TEXT NOT NULL, subject2 TEXT NOT NULL, version INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2));
CREATE TABLE dec_signers (network_id TEXT NOT NULL, context_id TEXT NOT NULL, provider_kind TEXT NOT NULL, person_key TEXT NOT NULL, device_key TEXT NOT NULL, lease_id TEXT NOT NULL, PRIMARY KEY(network_id, context_id));
CREATE TABLE dec_clock (network_id TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE dec_intents (intent_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL, kind TEXT NOT NULL, record TEXT NOT NULL, secret BLOB);
CREATE TABLE dec_pending (request_id TEXT PRIMARY KEY, deadline TEXT NOT NULL, record TEXT NOT NULL, secret BLOB, terminal_read_cap BLOB);
CREATE TABLE dec_frames (request_id TEXT NOT NULL, role TEXT NOT NULL, writer_key TEXT NOT NULL, frame_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(request_id, role, writer_key, frame_id));
CREATE TABLE dec_operations (network_id TEXT NOT NULL, context_id TEXT NOT NULL, request_id TEXT NOT NULL, activation_id TEXT NOT NULL, manifest_id TEXT NOT NULL, record TEXT NOT NULL, locally_applied INTEGER NOT NULL CHECK(locally_applied = 1), PRIMARY KEY(network_id, context_id, request_id));
CREATE TABLE dec_outbox (delivery_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL, target_key TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE dec_migrations (network_id TEXT NOT NULL, proposal_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, proposal_id));
CREATE TABLE dec_contacts (network_id TEXT NOT NULL, context_id TEXT NOT NULL, host_key TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, context_id, host_key));
CREATE TABLE dec_helpers (kind TEXT NOT NULL, address TEXT NOT NULL, public_key TEXT NOT NULL, record TEXT NOT NULL, credential BLOB, PRIMARY KEY(kind, address, public_key));
```

**Changed (DEC-Q14):** `dec_migrations` stays and is never written.

Stream columns: root is (`root`,`-`,`-`); admin, person, host, binding, policy
and group are (kind, subject, `-`); device is (`device`, PERSON, DEVICE).

### 19.2 Records

| Where | Record |
| --- | --- |
| `networks.record` | `{format:2, mode:"decentralized", descriptor_base64, context_id, root_state_id, own_identity:{member, person_public_key, host_public_key}, created_at}` |
| `dec_contexts` | `{format:1, descriptor_base64, origin:"genesis", initial_root_state_id, origin_proof_id, migration_proposal_id:"-", adopted_at}` (**Changed (DEC-S12):** origin `migration` removed) |
| `network_members` | `{format:2, mode:"decentralized", host_public_key, member, person_public_key, host_lease_id, person_lease_id, binding_lease_id, activation_id}` |
| `dec_admissions`, `dec_restrictions` | `{format:1, kind, proof_id, admitted_at, basis:{kind, evidence_ids}}`; basis kind `current` or `retention` (bans: `current` or `ratification`) |
| `dec_activations` | `{format:1, proof_id, manifest_id, admitted_at, basis:{kind, evidence_ids}}` |
| `dec_heads` | `{format:1, head_ids:[DS]}` |
| `dec_highwater` | `{format:1, statement_ids:[DS], floor_proof_ids:[DP]}`; `version` U64 |
| `dec_signers` | `provider_kind` `original` (device_key and lease_id `-`) or `device` |
| `dec_clock` | `{format:1, largest_local_time}` |
| `dec_frames` | `{frame_base64}` |
| `dec_operations` | `{format:1, activation_base64, catalog_base64, outcome_packet_base64, applied_at}` |
| `dec_outbox` | `{format:1, kind:"proofs"\|"activation", body_base64, proof_ids, created_at, attempts, next_attempt_at, last_error_code, last_error_detail}`; ID `ddel_` + 128-bit hex |
| `dec_contacts` | `{format:1, message_hashes:[HASH], conflicted, contacts_base64:[BASE64]}` |
| `dec_helpers` | `{format:1, enabled}`; kind `rendezvous` or `relay`; credential at most 1024 bytes |

**Changed (DEC-S12):** basis kind `migration` and outbox kind `migration` are
removed.

### 19.3 Signing plans (`dec_intents`)

```text
{format:1, operation_id, approved, approved_at, review_base64, provider,
 root_state_id, person_public_key, host_public_key, device_public_key, scopes,
 not_after, created_at, expires_at,
 templates:[{slot_id, object_type, template_base64}],
 signatures:[{slot_id, role, signature}], completed, terminal, result_base64}
provider = {kind:"original"|"device"|"root"|"requester", signer_public_key,
            signature_format, lease_id}
```

- `intent_id` = `dint_` + 128-bit random lowercase hex.
- `kind`: owner, administrator, create, action, policy_claim, root_transition,
  selection, requester_commit. **Changed (DEC-S12):** migration and
  migration_identity removed, with the `host` provider kind.
- Template `object_type` adds `selection_packet` and `commit_packet` to the
  signing-request list.
- `terminal`: `-`, applied, cancelled, expired.
- `secret`: NULL, or a pending raw root seed for create or root_transition.
- At most 64 unfinished and 4096 total plans per host.
- **Changed (DEC-S15, DEC-Q17):** `expires_at` is `-` for create, action,
  policy_claim and root_transition plans (was a 300-second boundary); link
  stage plans keep the request window. A plan refused with `review_required`
  gets `terminal` `expired`; never-applied terminal plans are deleted 24 hours
  later.

### 19.4 Join requests (`dec_pending`)

```text
{format:1, roles, mode, migration_proposal_id, expected_network_id,
 expected_context_id, expected_person_public_key, contact_invitation_base64,
 descriptor_base64, host_public_key, device_public_key, request_nonce,
 request_packet_base64, owner_packet_base64, selection_packet_base64,
 administrator_packet_base64, owner_finalization_packet_base64,
 commit_packet_base64, outcome_packet_base64, catalog_base64, owner_offer_id,
 selection_id, administrator_offer_id, owner_finalization_id, manifest_id,
 activation_id, selection_approved, commit_approved, owner_intent_id,
 administrator_intent_id, selection_intent_id, commit_intent_id, terminal,
 carrier_endpoints, outbound_frames}
```

- `roles`: ordered subset of requester, owner, administrator.
- `terminal`: `-`, applied, cancelled, expired, stopped. **Changed (DEC-S12):**
  migration_prepared and migration_adopted removed.
- `carrier_endpoints`: `[{kind:"participant"|"helper", address, public_key}]`.
- `outbound_frames`: `[{role, writer_public_key, frame_id,
  acknowledged_by:[{address, public_key}]}]`.
- `secret`: the 16-byte pairing secret while needed. `terminal_read_cap`: 32
  bytes, only after apply while sealed outcome frames still need sending.
- **Changed (DEC-Q26):** the inviter stores each live invite's return secret
  in a `dec_pending` row whose `request_id` column holds the invitation ID
  (`di_…`), `roles` `["owner"]`, `secret` the 16-byte return secret,
  `deadline` the invite's `expires_at`, `contact_invitation_base64` the
  invite's exact bytes, and every other record field `-`, `[]` or `false`.
  **Changed (DEC-Q32):** these rows count toward the 4096 total rows but not
  the 8 active requests.

### 19.5 Policy edit record

The existing `policy_edits` row (primary key `network_id, person_id, seq`)
holds, for coordinator-free networks:

```text
{format:2, mode:"decentralized", context_id, seq, state, start, signed,
 signed_version, dropped, reserved_at, signed_at, unsettled_at, closed_at,
 dropped_at}
POLICY_REFERENCE = {statement_id, proof_id, statement_base64, body_base64}
```

- `start`, `signed`: `-` or POLICY_REFERENCE.
- **Changed (DEC-S16, DEC-Q18):** `state` is settled, unsettled or closed;
  `reserved` is no longer written; `reserved_at` holds the preparation time.

Dropped-addition keys:

| Addition | Key |
| --- | --- |
| New agent rule | `rule AGENT` |
| New principal in an agent rule | `principal PRINCIPAL in rule AGENT` |
| New capability rule with principals | `capability rule CAPABILITY` |
| New principal in a capability rule | `principal PRINCIPAL in capability rule CAPABILITY` |
| New empty-principal capability claim | `claim CAPABILITY` |

Older rows may spell a principal key with `of` instead of `in`; both mean the
same addition, and one row may not hold both.

## 20. Verifier carrier and test controls

### 20.1 `--decentralized-verify`

Both verification binaries read JSON lines on stdin and write one compact JSON
line per input on stdout. At most 64 MiB per line including LF. An empty line is
`invalid`. All operations are pure.

Requests (`format:1` and `kind`):

| Kind | Fields | Success |
| --- | --- | --- |
| `descriptor` | `descriptor_base64` | `{ok:true, context_id, network_id, genesis_root_public_key}` |
| `statement` | `descriptor_base64, statement_base64` | `{ok:true, context_id, statement_kind, statement_id, proof_id, payload_base64, signers:[{role, public_key, signature_format}]}` |
| `catalog` | `descriptor_base64, catalog_base64` | `{ok:true, context_id, proof_ids}` |
| `clock` | `now, clock_guard` | `{ok:true, decision_time, next_guard}` |
| `projection` | `descriptor_base64, prior, candidate_catalog_base64, now, operation:"read"\|"fresh"\|"repair"` | `{ok:true, context_id, decision_time, root:{head_ids, maximum, selected_id, conflicted, code, required_ids}, streams:[{stream, head_ids, maximum, selected_id, active, code, required_ids}], restrictions, inert_statement_ids, next_prior}` |
| `action` | `descriptor_base64, prior, candidate_catalog_base64, now, actor:{person_public_key, host_public_key, device_public_key, issuer_id}, action_kind, unsigned_payload_base64` | `{ok:true, context_id, decision_time, issuer_id, signer_public_key, required_parent_ids, effective_not_after}` |
| `activation` | `descriptor_base64, prior, catalog_base64, activation_base64, now, expected` | `{ok:true, context_id, request_id, manifest_id, activation_id, person_public_key, host_public_key, device_public_key, device_lease_id, scopes, effective_not_after, required_statement_ids, required_proof_ids, review_pins_matched}` |

```text
PRIOR = "-" | {format:1, context_id, catalog_base64, admitted_statement_ids,
  admitted_restriction_ids, admitted_activation_ids, root_head_ids,
  maxima:[{stream, sequence, statement_ids, head_ids}],
  migration_proposal_id, clock_guard}
EXPECTED = "-" | {request_id, context_id, mode, person_public_key,
  host_public_key, device_public_key, renewed_device_lease_id, owner_offer_id,
  selection_id, administrator_offer_id, scopes, not_after}
failure = {ok:false, code, required_ids}
```

- Stream tuples: `["root"]`, `["admin",P]`, `["person",P]`, `["host",H]`,
  `["binding",H]`, `["device",P,D]`, `["policy",P]`, `["group",NAME]`.
- Codes: invalid, quota_exceeded, proof_required, state_conflict,
  operation_conflict, forbidden, authority_would_be_invalidated,
  device_revoked, authority_expired, not_yet_valid, expired, clock_rollback,
  upgrade_required.
- **Changed (DEC-S12):** the `migration` kind and `LEGACY_PRIOR` are removed.
  **Changed (DEC-Q14):** `PRIOR.migration_proposal_id` is always `-`.

### 20.2 Test controls

Ignored unless the process has `PEERSPAN_DEC_TEST_MODE=1`.

- `PEERSPAN_DEC_TEST_CLOCK_FILE`: a regular file holding one UTC time
  (optionally one final LF), read at every decision. Unreadable: 500 internal.
- `PEERSPAN_DEC_TEST_BARRIER_DIR` (0700, files 0600): an armed `NAME.arm`
  holds an operation ID or `-`. At the named point the process writes
  `NAME.entered` and waits for `NAME.continue`. Points: dec.intent.after_commit,
  dec.approval.after_commit, dec.signature.after_commit,
  dec.frame.after_commit, dec.request.after_commit, dec.owner.after_commit,
  dec.selection.after_commit, dec.administrator.after_commit,
  dec.owner_finalization.after_commit, dec.requester_commit.after_commit,
  dec.apply.before_transaction, dec.apply.after_commit. **Changed
  (DEC-S12):** the three migration points are removed.
- `PEERSPAN_DEC_TEST_FAIL_AFTER_SCHEMA_DDL=1`: opening an older schema fails
  with `test schema migration failure` after creating the schema 23 tables and
  before commit.

## 21. Limits

| Item | Limit |
| --- | --- |
| Statement or activation body | 1 MiB |
| Decoded statement payload | 256 KiB |
| Catalog JSON / decoded bodies / objects | 16 MiB / 8 MiB / 4096 |
| ID arrays | 4096 entries |
| JSON nesting / device depth | 64 / 8 |
| Device grants per person | 4096 |
| Packet / request packet | 1 MiB / 8 KiB |
| Manifest | 16 KiB |
| Invite or request code | 32 KiB |
| Contact body / addresses | 8 KiB / 8 per list, 16 total |
| Frame plaintext / POST body / catalog component | 4 MiB / 8 MiB / 2 MiB |
| Mailbox frames / ciphertext / GET response | 64 / 32 MiB / 48 MiB |
| Mailboxes per client host / source / total | 4 / 16 / 1024 active; 64 / 256 / 4096 with tombstones |
| Helper stored ciphertext | 256 MiB |
| Activation publication, catalog exchange, repair | 20 MiB |
| Owner-local response / private record | 32 MiB / 32 MiB |
| Ordinary mutation body | 1 MiB |
| First-contact handshakes | 16 per source, 128 total, 5 s |
| Requests after TLS | 4 per key, 16 per source, 128 total |
| Headers / body / response | 5 s and 16 KiB, 64 fields / 10 s / 10 s |
| Queued receive or response bytes | 64 MiB each |
| Mailbox rates | writes 2/s burst 8; reads 1/s burst 4 |
| Pending join requests per host | 8 active (invite rows excluded), 4096 total |
| Outcomes per network | 4096 |
| Unfinished creations per host | 8 |
| Outbox | 4096 rows, 512 MiB bodies, 1 GiB records |

## 22. ID prefixes

| Prefix | Meaning | Formula |
| --- | --- | --- |
| `net_` | network | section 2 |
| `ctx_` | context | section 2 |
| `ds_` | statement | section 3.2 |
| `dp_` | proof | section 3.2 |
| `cat_` | catalog set | section 3.3 |
| `link_` | join request | section 9.1 |
| `dpk_` | packet | section 9.2 |
| `dm_` | manifest | section 9.4 |
| `da_` | activation | section 9.5 |
| `di_` | invitation | section 10.1 |
| `psi2-` | invite code | section 10.1 |
| `psl2-` | request code | section 10.2 |
| `create_` | creation | random, section 16.3 |
| `act_` | action | section 16.4 |
| `dint_` | signing plan | random, section 19.3 |
| `ddel_` | delivery | random, section 19.2 |
