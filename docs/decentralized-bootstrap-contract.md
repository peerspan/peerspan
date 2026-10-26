# Coordinator-free bootstrap, linking and optional helpers

Status: shared contract candidate for DEC-01/03/04/05/06, 2026-10-26.
The complete contract set must be reviewed and merged before implementation
or independent executable cases, as fixed by the umbrella contract. This document
chooses the recommended mechanisms and records their costs and alternatives.
It does not describe available commands.

The final launch lifecycle creates and enrolls networks without any coordinator
process, configured coordinator identity or successful coordinator sync. Legacy
runtime creation/enrollment is not an alternative public launch mode. Retained
legacy signed proofs have historical and explicitly authorized migration uses;
no old descriptor, signature or in-flight consent is reinterpreted in place.

## 1. Shared encoding and context

`H` is SHA-256, rendered as 64 lowercase hex digits. `L(parts)` is UTF-8 strings
joined by one LF, with no trailing LF; fields reject embedded CR/LF. Integers are
positive decimal u64 unless a field explicitly permits 0; no float or signed
integer aliases. Keys use canonical padded standard Base64 of 32 Ed25519 bytes.
Binary JSON fields use canonical padded standard Base64. Display tokens use
unpadded Base64URL and reject alternate spellings. UTC timestamps use exact
whole-second `YYYY-MM-DDTHH:MM:SSZ`.

New objects reject unknown/missing fields, null, duplicate keys, invalid UTF-8,
noncanonical encodings and out-of-range integers before cryptographic use.
Payload bytes are retained verbatim: signatures and IDs hash their exact
Base64-decoded bytes, not a receiver's JSON reserialization. Semantic IDs exclude
signatures; exact proof IDs include the complete original body. Valid signature
aliases cannot change the signed intent or choose a different authority branch.

The exact descriptor is:

```text
{format:1, protocol:"peerspan-decentralized-v1", network_id, name,
 genesis_root_public_key}
```

`network_id` retains the existing genesis-root-derived network ID. Name is
immutable: a trimmed 1..128-byte UTF-8 label without control characters.
The descriptor contains no coordinator, helper, relay, DNS or contact field.

```text
context_id = "ctx_" + H(L("peerspan-decentralized-context-v1",
                         "peerspan-decentralized-v1",network_id,name,
                         genesis_root_public_key))
```

The literal format/protocol above are mandatory; the protocol is included
verbatim in the digest; other values cannot be supplied under that domain.
Descriptor identity is not adoption authority:
new genesis and migration/adoption must pass the authority contract. A different
name/genesis/protocol under a remembered network ID is a hard conflict.

Use the authority contract's exact catalog:
`{format:1,context_id,objects:[{id,kind,body_base64}]}`, sorted by proof ID.
`dp_` identifies the kind plus exact original body; `ds_` identifies the signed
statement kind/context/exact payload independently of signatures. Lease ancestry
uses exact `ds_` references. Catalog/set hashes prove exact content only, never
that no unseen revocation or fork exists.

## 2. First contact and contact statements

Recommended first contact is explicit authenticated contact handoff. A fresh
creator needs no helper: it creates genesis and its initial state locally.
Fresh creation initializes the original-person provider through ordinary
root/admin/person/host/binding proofs and their required signatures. It issues
no initial device lease. Adding or renewing any device later still uses the
complete requester ceremony and both explicit confirmations, including on the
creator itself. Root possession is no device-consent bypass. A
pair of reachable devices exchanges a pairing token/contact directly. Existing
members exchange contacts only through authenticated state/peer channels.
There is no public network roster lookup or DHT in this milestone.

A host-signed contact has exact fields:

```text
{format:1,context_id,host_public_key,sequence,issued_at,expires_at,
 payload_base64,signature}
```

Decoded contact payload is exactly
`{quic_addresses:[HOST:PORT],bootstrap_addresses:[HOST:PORT],
relays:[{address:HOST:PORT,public_key}]}`. Its exact original bytes are retained.
`context_id` is the exact network context, or literal `"-"` only for a fresh
unbound pairing endpoint. Addresses use the exact new-context endpoint grammar
below; no legacy address spelling is silently rewritten inside a signed object.
Address arrays use bytewise ascending ASCII endpoint order; relay entries
use (address, canonical public_key) ASCII order. Each is unique and limited to 8;
the total advertised addresses are limited to 16. A contact body is at most 8 KiB.
`sequence` is monotonic for this host/context; validity is at most 300s and the
issuer refuses a new contact with a lower local clock or sequence. Signature:

```text
L("peerspan-decentralized-contact-v1",context_id,host_public_key,
  sequence,issued_at,expires_at,H(decoded payload bytes))
```

The signature is raw Ed25519 by the host key.

The endpoint is at most 260 ASCII bytes and exactly `HOST:PORT`. Port is decimal
1..65535 with no leading zero or sign. HOST is either canonical dotted-decimal
IPv4 (four 0..255 octets, no leading zero), bracketed RFC5952 lowercase IPv6, or
lowercase ASCII DNS. IPv4-mapped IPv6 is represented as IPv4. DNS is 1..253 bytes,
no final dot, labels 1..63 bytes containing only `a-z`, `0-9`, `-`, with no leading
or trailing hyphen; IDNA must already be an ASCII `xn--` label. IPv6 brackets
are mandatory and cannot wrap DNS/opaque text. Zones, empty host, unspecified
IP, controls/whitespace, URL delimiters/credentials/path and Unicode DNS are
invalid. DNS resolution/routability is not authority. An implementation does not
reinterpret a signed noncanonical spelling as a different endpoint. Existing
legacy proof/address grammar remains unchanged in its own context. Loopback
and link-local literals are permitted transport hints, without zones or an
implied interface/routability guarantee; they confer no remote authority.

Validate contact time at the decision clock, permitting at most 30s future skew,
then target possession with the normal pinned TLS/QUIC identity. For a network
contact, verify the host's independent current authority before treating it as a
network participant. A fresh contact proves only possession of its own key.
The highest observed sequence is sticky; a signed semantic conflict at the same
host/context/sequence suppresses that sequence until a higher nonconflicting
contact arrives. Old/expired hints cannot erase a remembered newer contact.
Validate syntax, signature and current validity BEFORE changing the sticky
sequence: an expired or more-than 30s-future high-sequence contact cannot poison
the remembered head. A contact within the explicit30s hint skew may advance a
valid hint head; that tolerance supplies no authority or clock advance. An expired or more-than 30s-future hint may be retained as bounded inert data
only, without replacing a currently valid one. Contacts never renew leases, grant access or prove
state freshness.

Contact publication to a helper is opt-in and encrypted inside the opaque
rendezvous channel below. Do not expose an unauthenticated query that enumerates
network members, person labels, agents, capabilities or their signed catalogs.
Operators can still observe connected addresses, timing and opaque locator
correlation; this protocol makes no anonymity claim.

## 3. Fresh-host transport boundary

Ordinary peer TLS continues to reject unknown host keys. Bootstrap uses a
separate listener and ALPN `peerspan-bootstrap/1`, with a separate strict router.
It can accept a well-formed Ed25519 client certificate proving key possession
without admitting that key into a network. It serves only the mailbox routes in
section 7 and participant completion routes in section 5. It never serves
owner-local administration or ordinary peer routes.
An implementation may share a physical listener only if the ALPN selection,
certificate policy and router isolation are equivalent and independently tested.

A pairing token pins the target bootstrap host's Ed25519 key, so the initiator
verifies that key before sending any secret-derived capability. An arbitrary
address/helper/DNS answer cannot replace it. Helpers have their own transport
TLS pins and optional operator resource credentials; neither is a network pin.
HTTP Host, helper certificates and successful requests provide no membership,
access, epoch or completeness authority.

Recommended first implementation uses the existing HTTP/1.1-over-TLS primitives
on this isolated listener; normal post-enrollment traffic retains existing QUIC.
This avoids a transport-library migration and a global relaxation of peer pins.

Before TLS completes, allow at most 16 handshakes per actual source bucket and
128 globally, with5s handshake timeout. Bootstrap HTTP uses one request per TLS
connection and then closes. After TLS, bound active requests to 4 per actual host
key,16 per source and 128 globally. Read headers within 5s, at most 16 KiB/64 header
fields; require one canonical Content-Length for POST and reject Transfer-Encoding,
ambiguous lengths and request pipelining. GET/DELETE have no body (absent or zero
length only). Finish a bounded route body within 10s and a response write within
10s. Aggregate in-flight body receive buffers and queued response bytes are each
at most 64 MiB; reserve capacity before accepting a Content-Length/body buffer; saturation returns quota
where a response is still possible, otherwise closes. Unknown/stalled clients
cannot allocate unbounded workers, body buffers or ordinary-peer/admin slots.
All protocol/body/header failures return strict400 JSON where framing permits,
then close; timeouts/failed TLS simply close without an authority result. These
transport deadlines never extend a consent window or signed lease.

## 4. Pairing identity, token and packet

Each attempt has a fresh 32-byte random `request_nonce` (canonical standard
Base64) and a 128-bit random secret.
New attempts use an owned host key and a separate per-machine device key; renewal
reuses the exact existing host/device/person and chooses new nonce/secret.
An existing original-person private key never moves to a linked requester or
a helper. A person generated by that owner on its original machine may retain
its existing protected local key file/provider there; it is never imported into
the trust database, returned by the daemon or copied to another machine.

Request payload (exact fields):

```text
{mode:"new"|"renew",host_public_key,device_public_key,request_nonce,
 expected_network_id,expected_context_id,expected_person_public_key,
 migration_proposal_id,renewed_device_lease_id,created_at,expires_at}
```

Unknown expected values are literal `"-"`. Migration_proposal_id is literal
`"-"` for every ordinary request and the exact approved migration-proposal ds_
for staged preparation; request ID/signatures bind it from the outset. It
cannot be inferred or inserted after signing. Every staged selection/final root
must belong to that same approved proposal. A renewal supplies every expected
identity/context and an exact prior device lease ID. `expires_at=created_at+300s`.

```text
request_id = "link_" + H(L("peerspan-decentralized-request-id-v1",
                           H(exact request payload bytes)))
```

Every packet has exactly:

```text
{format:1,context_id,request_id,role,writer_host_public_key,signer_public_key,
 person_public_key,issuer_id,payload_base64,
 host_signature,device_signature,authority_signature_format,authority_signature}
```

Its signing message and semantic ID are:

```text
M = L("peerspan-decentralized-packet-v1",context_id,request_id,role,
      writer_host_public_key,signer_public_key,person_public_key,issuer_id,
      authority_signature_format,H(decoded payload bytes))
packet_id = "dpk_" + H(M)
```

Every packet has a raw Ed25519 host signature over `M` by its writer host.
Request, selection and final commit additionally have raw Ed25519 signatures by
the request device; `signer_public_key` is that device and authority signature/
format are `"-"`. Owner, owner-finalization and administrator packets have the
exact selected authority signature and `device_signature: "-"`. Their explicit
`authority_signature_format` is `ed25519` for an owned device or raw root,
`sshsig` for an original person or selected external SSH root. Original-person
SSHSIG uses the EXISTING namespace `peerspan-person-v1`, SHA512 and
`ssh-ed25519`; raw signatures are canonical Base64 of 64 bytes. Format and key
role must match, not be inferred from a submitted signature's apparent length.
Legacy formats/signature requirements are not changed.

Outcome packets have signer/person/issuer/device/authority/authority-format
fields `"-"` and the writer's raw host signature only. A request uses
context/person/issuer `"-"`; every later role pins the selected context. The
authority contract determines current role/path/scopes and finite lease IDs;
transport possession is insufficient. A device signature is proof of that
particular key's possession, not a substitute for reviewed requester consent.

Role bindings are exact: request/selection/commit writer is the request's target
host and signer is its target device. Request person/issuer/context are `"-"`;
selection/commit person is the selected original key, issuer is `"-"`, and
context is selected context. Owner and owner_finalization are original-person
or same-person device roles, never network-root substitutes; person is that
owner and issuer_id is the exact issuing device lease ds_ or `"-"` for original
person signing. Administrator person is the actual administrator's original key
and issuer is its exact device lease or `"-"` for original-person signing; a
network-root administrator instead has person `"-"` and issuer_id equal to the
exact selected root_state_id. Its signer is that root. All authority keys/path
parents must independently match these typed roles. A packet cannot select a
path by a display name or infer a device issuer from a submitted signature.

A packet is at most 1 MiB and its decoded payload at most 256 KiB; a manifest is
at most 16 KiB. A selected bootstrap proof closure is at most 16 MiB of catalog JSON,
with individual public objects and stored catalogs keeping the authority
contract's own limits. In addition the exact request packet is at most 8 KiB,
contact metadata/token overhead must fit the 32 KiB token cap, each selected
activation at most 1 MiB and complete publication request/response at most 20 MiB.
These aggregate ceilings apply even when each nested object is individually
valid; report quota rather than truncation. Larger complete source state is
never truncated:
select the sufficient exact closure or refuse `quota_exceeded`. Catalog-only
frames can carry partial proof sets; no partial set becomes active state.

The requester-origin private token is `psl2-` plus unpadded Base64URL of exact JSON:

```text
{format:1,request_id,secret_base64,request_packet_base64,
 contacts:[SIGNED_CONTACT],helpers:[{address,public_key}]}
```

At most 4 contacts/helpers each, token at most 32 KiB including prefix. EVERY
contact must be signed by the exact request packet writer host. Its context is
the request's known expected context, or `"-"` when that expectation is unknown.
Its expected pins remain immutable. Contact arrays use bytewise ascending
(context_id, host_public_key, decimal sequence as numeric u64, H(exact body))
order, without duplicate exact bodies; helper arrays use ASCII (address,
canonical public_key) order, unique by that tuple. Conflicting signed contact
semantics at the same host/context/sequence invalidate a token, not a hash win. A helper is only a
replaceable carrier. Tokens are shown only by explicit private create/display or
resume action. Automatic pending `up`, public status, logs and peer routes never
redisplay the secret or token. Do not put tokens in process logs/URLs/query
strings. Token parsing verifies all syntax/signatures before key generation,
network adoption, publication or consent.

### Inviter-origin contact invitation and identity review

The distinct inviter-origin token is `psi2-` plus unpadded Base64URL of the exact
strict JSON contact-invitation object:

```text
{format:1,context_id,inviter_host_public_key,payload_base64,signature}
```

Its decoded payload is exactly:

```text
{descriptor,expected_person_public_key,member,issued_at,expires_at,
 contacts:[SIGNED_CONTACT],helpers:[{address,public_key}]}
```

The context is derived from that exact descriptor; `member` uses the authority
contract's member-label bounds. `expected_person_public_key` is an exact stable
original-person key, or `"-"` when the inviter has not selected one. Contacts are
all signed by the exact inviter host under this context. Contacts and helpers
use the same contact/helper ordering and uniqueness as psl2, at most 4 each,
and obey section 2 endpoint/key bounds. Token
size is at most 32 KiB including its prefix; the aggregate cap still applies when
the nested objects are individually valid. No private key, pairing secret,
permission, lease, catalog or claimed administrator role is carried. Signature
is raw Ed25519 by `inviter_host_public_key` over:

```text
I = L("peerspan-decentralized-contact-invitation-v1",context_id,
      inviter_host_public_key,H(exact decoded payload bytes))
invitation_id = "di_" + H(I)
```

`expires_at=issued_at+300s`; accept only at `issued_at <= decision_time+30s`
and `decision_time < expires_at`, with current contact bounds independently
checked. The signature proves this host authored these introduction terms. It
does not prove the host is a member/admin, establish a previously unknown root
as trusted, grant bearer access or assert a global single-use/revoked status.
Current issuer/root/lease authority is independently verified during the actual
reviewed ceremony. No catalog kind or `invite_revoke` authority variant is
introduced for this contact-only token.

Before identity generation, key saving, service enrollment or publication, the
invitee verifies the entire strict token and presents the exact network/name,
context/genesis fingerprint, inviter host, proposed member and person-key pin.
The local owner explicitly selects an existing original-person identity or
approves creating a new one on this machine. A supplied person pin must match;
never replace an existing identity, generate a substitute to repair a mismatch
or copy the inviter's original key. New original keys remain owner-local and
follow existing private-file permissions and SSH signing. This contact review
is additional to, and cannot stand in for, the later owner-selection and final
commit confirmations.

Then create and durably retain the ordinary requester-origin `psl2-` attempt,
pinning the invitation's exact descriptor/context and selected original person.
Retain the reviewed invitation/label expectations with local intent; owner
selection must match them before consent. The invitee explicitly sends its new
request code back to the inviter over the already chosen out-of-band channel.
The inviter reads that code and performs the ordinary exact owner/admin review;
for a new person, the invitee's selected original key supplies pending
self-consent while an independently authorized root/administrator supplies
admission. Being introduced by the same host is no administrator credential. No invisible
inbox or helper lookup locates an arbitrary invitee. Both outbound-only devices
can use a common independently operated mailbox from the request code; a
reachable direct pair needs no helper. A contact invitation alone never claims
to deliver a reply to two unreachable devices without such a path.

Expiry prevents beginning a new local invitation review/request. It does not
cancel a separately persisted, already reviewed request or revoke its eventual
completed grants. Leaked contacts/codes can be abandoned locally; known actual
person/host/device restrictions, not a pretend global contact-token deny, govern
authority. Reissue uses fresh signed contact terms, not mutated old bytes.

## 5. Reviewed transcript and pending grants

Every lease payload includes signed `operation_id`: `"-"` only for an
independently active ordinary admin/person/host or fully signed binding grant;
exact request ID for a ceremony component. Ordinary host grants still require
the authority contract's target-host consent, not issuer signature alone.
Operation-bound
person/host/binding/device leases are inert until the exact complete transcript
validates. Every NEW or RENEWED device lease must use a non-`"-"` operation ID and
complete target-host/device proof of possession plus separate reviewed requester
commit. There is no ordinary independently active device-issuance bypass.
Migration follows its own equally explicit consent/PoP contract, not an
unbound-device exception. Their presence in a catalog or helper response
is insufficient.
Lease IDs use the authority contract's signature-independent `ds_` derivation.

Recommended order:

1. **Request:** requester signs the exact request. It creates no network,
   admission, binding or selected signer. A retry reuses the same persisted
   request/secret/keys; a new attempt has a new request ID.
2. **Owner offer:** reviewed owner proves the selected person's identity and
   proposes exact target host/device, mode, scopes, lifetime ceiling and selected
   issuer. Payload is exactly `{request_packet_id,descriptor,root_state_id,
   person_lease_id,issuer_lease_ids,mode,member,host_public_key,device_public_key,
   scopes,not_after,renewed_device_lease_id}`. Arrays are sorted unique exact
   statement IDs. New-person admission may prove possession of its unadmitted
   original key but confers no current person/admin authority. In that case
   root_state_id and person_lease_id are `"-"`, issuer_lease_ids is empty and
   only that original person's typed possession signature is permitted. Its
   descriptor/context/label/person pins come from the reviewed psi2 terms;
   this initial offer claims no current root or reusable positive authority.
   The inviter acts only as actual administrator, not that new person's owner.
   The invitee guides its own original-key possession offer before returning
   the request to the inviter for admission. Otherwise person_lease_id names the
   current selected admission and issuer_lease_ids contains the exact direct
   issuer_person and, for device signing, issuer_device parent IDs.
3. **Requester selection:** payload exactly `{request_packet_id,owner_offer_id,
   context_id,person_public_key,host_public_key,device_public_key,selected_at}`.
   An explicit default-no review locks this offer and identity tuple. A later
   offer cannot inherit consent, even with the same label.
4. **Administrator offer:** after verifying that selection, current root or
   current finite scope 8 administrator signs exactly `{selection_id,
   owner_offer_id,root_state_id,issuer_lease_ids,person_lease,host_lease}`.
   For root signing issuer_lease_ids is empty; person administration supplies
   exact issuer_person+issuer_admin IDs and device administration also its exact
   issuer_device ID, sorted unique. Supplied leases must have the exact
   operation ID, owner label and target
   keys/parents/lifetime from the selected terms. A preexisting unchanged
   independently verified active person/host lease (ordinary or from an already
   complete earlier operation) may be referenced by ID instead of a new object;
   wire values are either a signed envelope object or its exact `ds_` string,
   never an unsigned projection. Renewal may use existing eligible person/host
   evidence; it cannot replace the stable identity or silently widen authority.
   For RENEW only, if exact current person and host leases are unchanged, the
   administrator packet and administrator_offer_id are both literal `"-"`.
   No fresh scope8 is required merely to reference those current leases. Any
   person/host lease change requires the full current root/admin stage.
5. **Owner finalization:** current selected owner verifies the exact admin grant
   and signs `{selection_id,administrator_offer_id,root_state_id,person_lease_id,
   host_lease_id,binding_lease,device_lease}`. Binding's owner signature covers
   exact person+host+issuer ancestors; its target-host signature is pending.
   The new binding draft has the full canonical sorted `host` and `issuer`
   signature entries, with the exact target-host public key/format and literal
   `signature:"-"` in the host entry; the issuer entry has its actual signature.
   Only this nested typed pending binding permits that placeholder. Omitting
   the host entry or supplying a completed host signature here is invalid.
   Device lease names the exact target device/scopes and every required parent.
   For RENEW with an unchanged current complete binding, binding_lease is its
   exact ds_ string rather than a new envelope: no scope2 is needed merely to
   reference it. A new binding instead requires owner scope2 and target-host
   consent. New D issuance still requires the original owner or a current
   strict owner-device ancestor with scope4, unchanged subset/deadline rules;
   an expired old target D is history/PoP identity only, never an issuer.
   A narrowly pending self person lease authorizes only that same operation's
   own binding/device consent, never unrelated grants or an admin role.
6. **Requester final commit:** requester verifies every full ancestor and
   current known restriction, adds the target-host signature to the exact
   binding statement, builds the final manifest, and separately reviews/approves
   committing it. No selection or resume implies this consent. Persist exact
   signed commit and all grant bytes before any publication.
7. **Application/outcome:** a participant independently verifies the complete
   transcript/current finite authority and applies its local transaction. An
   outcome acknowledges that exact local application; it is not a global receipt
   or a substitute for any missing signature/lease.

All participant signatures bind their writer host so an original-person signer
cannot be transplanted into a helper's claimed participant outcome. A selected
device path must be owned by that writer host and same person. Original-key
signing returns fixed typed external slots; there is no arbitrary sign endpoint,
new root fallback or hidden original-key import.

A same-review owner may preapprove later administrator/finalization work only
when its exact selected path also has current scope 8/admin authority. Later
signatures wait for dependency-ready exact templates and revalidate current
eligibility. Otherwise a separate actual administrator review is required.
An attempted alternate administrator after that locked review returns 409
`state_conflict`, not fallback. Requester selection and final commit remain
separate in both cases.

### Final manifest and activation

The manifest is exactly:

```text
{format:1,context_id,request_id,request_packet_id,owner_offer_id,selection_id,
 administrator_offer_id,owner_finalization_id,root_state_id,
 person_lease_id,host_lease_id,binding_lease_id,device_lease_id,
 binding_proof_id,device_proof_id,ancestor_statement_ids,proof_ids}
```

All selected identity/scopes/expiry/operation fields must agree across the
referenced exact payloads. The sole initial root-state exception is the new
unadmitted-original-person possession owner offer: its root_state_id is `"-"`,
while administrator, owner_finalization and final manifest/commit all lock the
same independently verified actual current root. That `"-"` intent cannot
substitute for a final root, alter the reviewed descriptor/person or let later
signing choose another authority branch. Existing-person and migration offers
must name their exact eligible current/staged root. Ancestor statement IDs are the complete sorted unique
transitive dependency closure required for the issued D, including root states,
P/H/B, issuer ancestors and required predecessor/retention provenance. Exclude
the issued D itself: device_lease_id names it separately. `proof_ids` pins the exact original
proof bodies presented for this intent, including every signature. Missing
required bodies are `proof_required`, never inferred from names or receipts.
It includes the exact D body and required ancestor/consent provenance, but not
the containing activation or its current outcome: those cannot be inputs to
their own signed manifest. Earlier complete activation/migration provenance
needed by an ancestor retains its exact original proof.
If authority heads changed during the ceremony, every old ancestor must have
the authority contract's exact signed retention through each intervening
replacement; original deadlines/scopes/restrictions still apply. A local claim
that an issuer was admitted before cannot substitute for portable evidence.
A known current restriction is always applied even if absent from this frozen
intent. Additive evidence does not rewrite its signed bytes.

```text
manifest_id = "dm_" + H(L("peerspan-decentralized-manifest-v1",
                           H(exact manifest bytes)))
```

Commit payload is exactly `{manifest_base64,binding_host_signature,committed_at}`.
The final binding proof is the owner-provided exact payload/issuer signature plus
this host-role signature, in the authority contract's canonical envelope shape.
For RENEW reusing an exact current complete binding, binding_host_signature is
literal `"-"`; its manifest still pins that complete original binding proof.
For every new binding the field must hold the actual target-host role signature.
Construct and retain that complete original proof body before hashing the
manifest. The pending binding nested in owner_finalization is only a typed
ceremony component: it is not admitted as a complete standalone lease or indexed
as active evidence. The final manifest-pinned binding body must be supplied
verbatim in the accompanying catalog, with the same payload and issuer signature
and the exact commit host signature; never fabricate a new envelope by merging
public aliases at read time. Statement IDs exclude signatures, so there is no
binding/device/consent reference cycle.

Activation is exactly `{format:1,context_id,request,owner,selection,administrator,
owner_finalization,commit}`. All role values are exact packet objects except
administrator, which is literal `"-"` only under the unchanged-P/H RENEW exception.
Owner_finalization's binding_lease is correspondingly an exact complete binding
ds_ reference under the unchanged-B exception, otherwise its typed draft.
These unions do not permit a missing packet/consent on any other path. Activation is at most 1 MiB. Its proof catalog travels
separately; activation never embeds a catalog containing itself. That catalog
contains the exact required signed proofs and grants nothing by its mere
presence. The operation's semantic ID is:

```text
activation_id = "da_" + H(L("peerspan-decentralized-activation-v1",
                            context_id,request_id,manifest_id,commit_packet_id))
```

The public catalog kind is exactly `activation`, a composite rather than a
statement envelope. Its `dp_` uses kind `activation` and the exact original
complete activation body under the common proof-ID rule; `da_` above identifies
its operation/consent semantics and is not a replacement proof ID. Every nested
packet and manifest is retained in its original bytes. Nested leases may be
indexed by their exact IDs from that original enclosing proof; do not fabricate
reserialized standalone evidence. Aliases with different exact complete bytes
retain their separate dp_ values and must validate the same exact signed intent.
Conflicting immutable intents for one request are `operation_conflict`.

An ordinary authenticated state replication carries the activation entry plus
its sufficient exact lease/ancestor/root/restriction closure. A third host can
verify every target signature and operation dependency from those public proofs
without a pairing secret, original key or participant outcome. Missing complete
consent remains inert/proof_required, not a lease activated by envelope presence.
The manifest's proof_ids cover its external grant/dependency bodies, never this
activation's own proof ID or a later outcome; this avoids a self-reference.
An object in that list must match the exact supplied original body. A catalog
may include additional independently valid proof aliases/current restrictions,
but cannot substitute them for an exact manifest-pinned original proof.

### Complete consent and current component authority

Complete exact consent provenance and current device usability are separate.
Verify all seven applicable stages, exact nested bytes and target signatures
before using an operation-bound component. A cold receiver may verify the
complete dependency DAG of earlier activations needed by the selected issuer
path, without inventing earlier local admission or a trusted past commit time.
This explicit ceremony exception covers only the manifest-selected P/H/B/D,
the actual packets' exact issuer references, and their full required ancestry
and complete ancestor activations. Resolve that finite DAG in dependency order;
cycles or missing required consent fail. It does not authorize unrelated
ordinary grants or a general same-batch grant-as-issuer fixed point.

Each selected component still requires its own CURRENT complete issuer,
parent, retention, restriction, scope and expiry checks before admission.
For example, an earlier operation's expired target D does not prevent learning
its independently current P/H/B. That expired D is not newly admitted, added
to heads/maxima, or usable as an issuer; a previously admitted D retains only
its contracted durable history. Complete consent never revives an expired
issuer, supplies missing retained ancestry, or proves past admission from a
timestamp. The component's current authority must be established independently
of any activation marker. This permits an original owner to renew a target
using the unchanged independently current P/H/B without treating the expired
old D as an issuer.

A newly successful participant application and the pure `activation` verifier
still require the selected new D to be currently usable. Historical exact
outcome reads remain read-only. Learning complete consent provenance alone
does not install a selected signer, create a participant outcome, or claim
current activation success.

Selected: reusable exact consent with independent current component checks and
a bounded activation dependency DAG. Discarded: requiring the old target D to
remain active before learning its live parents; admitting every component
because a complete transcript exists; enabling unrelated same-pass issuance.
Selected for the nested binding draft: fixed role/key/format slots with the
host signature `"-"`, matching the final envelope's shape. Discarded: omitted
host roles or a precompleted binding inside owner finalization, which obscure
the exact signature supplied by the separate requester final commit.

An outcome is a host-signed packet whose payload is exactly
`{context_id,request_id,manifest_id,activation_id,activation_sha256,
observed_root_state_id,applied_at}`. The referenced activation and sufficient
proof catalog travel alongside the outcome, never inside its bounded payload.
Its writer is the requester or a verified
owner/admin participant host from the transcript. Receivers verify the entire
activation independently and union every local restriction/high-water mark.
Different participants may have different observed state/outcome bytes; none is
a canonical global ordering decision. Only exact matching activation identity
is a retry of this operation.

### Timing, retries and crash boundaries

The 300s window governs honest local request/review/selection/final-commit signing.
At/after expiry an incomplete local attempt signs nothing new. A persisted final
commit remains an unresolved immutable operation until its exact outcome is
settled; timeout/absence/helper replacement never clears or regenerates it.
Complete preapproved transcripts may be learned after that window only under
CURRENT unexpired referenced authority plus every known restriction. Neither a
participant timestamp nor a helper/outcome signature proves a globally trusted
pre-deadline commit or absence of unseen revocation. This is a deliberate change
from old coordinator first-use timing, not a weakening of the old verifier.

Exact retries preserve nonce, keys, selected offer, grants, packet/signature bytes,
manifest and original local outcome. A conflicting immutable tuple is
`operation_conflict`; new pre-consent offer mismatch is `state_conflict`/invalid
as specified by its exact typed guard. Retrying an older completed operation
cannot replace a newer device selection, root state, lease, policy maximum or
restriction. At most one local operation record per request ID is applied.
No protocol claim of global exactly-once execution or globally consumed bearer
invitation follows from local deduplication.

Durable order: persist approved intent before generating typed signatures;
persist signature before encryption; persist exact ciphertext before transport;
persist final requester commit before first publication; apply exact catalog,
restrictions, high-water, selected provider, public outcome and one application
event in one transaction. Before that transaction seal any still-needed terminal
outcome frame using the existing secret and persist its exact ciphertext there.
Erase the raw pairing secret immediately on local apply. Retain only already
sealed needed terminal frames plus a separate32-byte raw derived read_cap BLOB
until their exact storage acknowledgment or request expiry; header renders it
as64 lowercase hex. It is a resource capability, not a decryption key/seed:
never reseal, derive a new frame, log/return it or reuse the secret column.
Then erase the capability and those ciphertexts. Public retained participant
outcome GET/exact POST retries require neither secret nor resource capability. Crash/restart resumes those bytes, never consent.
Original private keys are never imported into the database or transport.
Existing owner-local generated key files/providers remain available only on
the original machine under their private-file/signing contract; this is not
permission to copy an original key to a linked device. Terminal public
operation records survive secret/frame deletion and remain exact retry evidence.

An unbound team invitation is a contact/approval invitation only. It cannot
itself admit an arbitrary holder. Every requester key tuple requires the exact
reviewed person/admin approvals above. There is no advertised single-use bearer
membership token whose safety depends on a global consumed-token table.

### Complete publication after rendezvous expiry

The isolated bootstrap router also provides:

| Route | Request | Success |
| --- | --- | --- |
| `POST /bootstrap/v1/activations` | Exactly `{activation:ACTIVATION,catalog:CATALOG}`; at most 20 MiB whole body |200 `{outcome:PACKET,activation:ACTIVATION,catalog:CATALOG}` |
| `GET /bootstrap/v1/operations/{request_id}` | No query/body; authenticated transcript participant |200 same retained local outcome/activation/catalog;404 if no local outcome |

These complete-publication routes are participant-host routes, not opaque helper
routes. An independent helper need not implement them and cannot issue their
application outcome without being an independently verified participant.

The actual mTLS client host key AND the receiving server's actual host key
must each be the requester or a cryptographically verified owner/admin writer
host in that exact complete transcript. A nonparticipant server returns 403
forbidden and produces no outcome; nonparticipants learn independently valid
complete evidence only through ordinary authorized state replication.
This narrow carrier may
accept unknown TLS keys only on the isolated bootstrap router. It verifies the
complete exact consent/leases/current restrictions before effect; it exposes no
partial-grant, generic import, user-administration or raw-sign operation.
Outcome/activation/catalog response is at most 20 MiB, with no silent omission.
Apply the
same per-client rate and aggregate bootstrap resource bounds as mailbox writes.

The 300s window prevents new honest local consent/signing after expiry; it does
not turn deletion of a helper box into erasure of a persisted final commit.
This publication route lets an already complete immutable operation survive
helper loss. A receiver which is itself the requester also requires its exact
persisted approval and authorized context adoption; a public POST cannot create
new local consent, replace a newer signer or bypass snapshot recovery rules.
An existing participant applies only an independently valid addition to its
known context. Every unknown/restored-context adoption still follows the
separate authority contract. A response is a local outcome, not a claim of
network-wide uniqueness or freshness.

Before creating a first local outcome, the participant revalidates current
unexpired authority, all known restrictions and exact local approval/adoption
requirements in its final atomic transaction. Merely naming another host as a
packet writer is insufficient: every such packet host signature must validate.
For an already applied exact operation, GET and exact POST retry return the
original retained local outcome/activation/proof bytes even after its request
window or leases expire. This path authenticates the caller's exact participant
host key, validates immutable request/activation identity and reads the retained
operation; it does not reapply grants, overwrite newer state, select a signer,
mark a contact ready, claim current eligibility or advance decision time.
A mismatched already-applied intent is 409 operation_conflict. The ordinary
current permission checks still gate every new action. An unresolved complete
operation with no local outcome uses first-application checks, never this
historical-return exception. Retention is bounded to 4096 local outcomes per
context, separately from the catalog object quota. Exhaustion refuses new work
rather than silently evicting unresolved or relied-upon history.

## 6. Portable encrypted frames

Frame is exactly:

```text
{format:1,request_id,locator,role,writer_host_public_key,frame_id,
 created_at,expires_at,ciphertext_base64,signature}
```

`frame_id` is fresh random 32 bytes rendered lowercase hex. It is persisted before
publication and never reused for different plaintext. Frame roles are request,
owner, selection, administrator, owner_finalization, commit, outcome or proofs.
`created_at/expires_at` are the immutable request window; they do not attest
when an encrypted inner signature was actually produced.

```text
locator = H(L("peerspan-decentralized-locator-v1",Base64(secret)))
read_cap = H(L("peerspan-decentralized-read-cap-v1",Base64(secret)))
salt = SHA256(L("peerspan-decentralized-frame-salt-v1",request_id))
key = HKDF-SHA256(secret,salt,
                 L("peerspan-decentralized-frame-key-v1",request_id,
                   role,writer_host_public_key),32)
nonce = first12bytes(SHA256(L("peerspan-decentralized-frame-nonce-v1",frame_id)))
AD = L("peerspan-decentralized-frame-v1",request_id,locator,role,
       writer_host_public_key,frame_id,created_at,expires_at)
```

Ciphertext is AES-256-GCM of exact plaintext bytes under that key/nonce/AD,
including its 16-byte tag. Outer raw host signature covers
`L("peerspan-decentralized-frame-envelope-v1",AD,H(ciphertext bytes))`.
Plaintext is exactly `{packet_base64,catalog_base64,contacts}`; packet or catalog
may be literal `"-"` but not both; contacts is a bounded contact array. A
catalog component is at most 2 MiB decoded JSON; send multiple catalog-only
frames when the complete sufficient closure needs them. Split only BETWEEN
exact complete original public objects: every 1 MiB maximum body fits its Base64
entry inside a 2 MiB component. Never fragment/reserialize signed object bytes.
Each component is a strict complete catalog with the same context; verify
component/body/count bounds before indexing, then enforce 16 MiB raw reconstructed
catalog/8 MiB decoded body sum/4096 objects across their union before state effect.
Frames may carry partial dependency sets, never partial object bodies. Decode,
verify and persist exact inner signatures independently before any effect.
Wrong request/role/key/time/context or malformed complete content is invalid.

No helper/address key enters the new request ID, AEAD key, nonce or AD. Exact
ciphertext therefore survives changing/disabling every helper. A party knowing
the private token can read/write this channel but cannot forge owner/admin/
requester signatures or selected keys. A helper can drop/reorder/replay/delay
frames or lie about storage; none of those actions grants authority.

## 7. Isolated direct mailbox and optional helper wire

Direct bootstrap and optional rendezvous implement the same bounded carrier:

| Route | Request | Success |
| --- | --- | --- |
| `POST /bootstrap/v1/mailboxes` | `{format:1,request_id,locator,read_cap_hash,created_at,expires_at,frame}` |201 `{request_id,locator}`; exact retry 200 same value |
| `POST /bootstrap/v1/mailboxes/{locator}/frames` | `{frame}` + bearer read capability |200 `{frame_id}`; exact duplicate 200; same ID/different bytes 409 |
| `GET /bootstrap/v1/mailboxes/{locator}` | No query/body; bearer read capability |200 exact `{format:1,request_id,created_at,expires_at,frames:[FRAME]}` |
| `DELETE /bootstrap/v1/mailboxes/{locator}` | No query/body; bearer read capability |204, idempotent |

Every named mailbox route, including create, requires exactly one
`Authorization: Bearer READ_CAP` header. READ_CAP is exactly 64 lowercase ASCII
hex digits derived in section 6. The scheme/case/one ASCII space are literal;
reject duplicate headers, comma-joined values, extra whitespace, alternate
schemes or URL/query capability aliases with 400 invalid. A missing header is 403
forbidden. Creation's `read_cap_hash` is `H(UTF8(READ_CAP))` and must match;
for a known record a wrong capability is 403. Unknown canonical locators are 404.
TLS must prove a well-formed Ed25519 client host key on this isolated listener.
Create/append frame writer must equal that actual TLS key, and create's first
frame must have role request. Outer signatures prove resource-client possession,
never network authority. GET/DELETE can use another actual host key only with
the exact capability. An otherwise well-formed frame with a valid signature
whose writer differs from the actual TLS host returns403 forbidden and changes
no stored state. Malformed keys/signatures remain400 invalid. Selected:
distinguish a proven but unauthorized resource writer from malformed content.
Discarded: accepting a valid signature from another TLS writer or reporting
that possession mismatch as a syntax error.
Optional operator credentials use exactly one
`X-Peerspan-Resource-Token: BASE64` header: canonical standard Base64 of an
operator-issued UTF-8 token of at most 1024 decoded bytes, no CR/LF/NUL. Omit it
for anonymous resources; duplicate/noncanonical/oversized header is400 invalid.
An operator which requires a credential rejects absence/refusal with403. Local
helper configuration looks it up by exact endpoint/key; display tokens and
public helper lists never embed it. The operator maps a validated credential
to its resource account; no client-supplied account name is trusted. This header
is separate from bearer read capability and never enters network authority.

All frames share the exact request ID/locator/window. A helper validates fixed
syntax/signatures/bounds, not membership, inner consent, catalogs or access.
A direct endpoint applies the same wire and quotas. Successful storage is not a
durable authority commitment: participants retain exact outbound frames and can
retry any carrier with the same bytes. A TLS/transport key or operator-token
change requires explicit transport configuration/review, never a network root
change or re-signing the operation.

Creation/append validates `created_at <= now+30s`, exactly 300s lifetime and
`now < expires_at`; impossible/far-future windows are 400 invalid and an elapsed
window is 410 expired. Frame times must equal its box. The helper clock controls
resource retention only; it cannot certify inner chronology or state freshness.
At expiry erase all ciphertext atomically with marking the record expired.
DELETE similarly erases all ciphertext immediately and marks deleted. Release
ciphertext-byte and active-box slots in that same transition. Keep a tombstone
with only request/locator/creator TLS key and source bucket, read-cap hash,
original window, creation_identity_hash and deleted/expired state, at most
1 KiB per tombstone, through
original expires_at+24h. Never retain encrypted frames in that tombstone.

GET deleted is 404; GET expired is 410 while its tombstone is retained. Correctly
authenticated DELETE of deleted/expired is 204 and changes no deadline. POST
create/append against either retained tombstone is 410: an exact retry cannot
revive erased ciphertext or replace the original request/window. A live same-identity creation retry returns200. Define:

```text
creation_identity_hash = H(L("peerspan-decentralized-mailbox-create-v1",
                            "1",request_id,locator,read_cap_hash,created_at,
                            expires_at,H(exact original first FRAME bytes)))
```

Retain/inject that same original first-frame byte slice on cross-language
retry; do not parse/re-encode it. Outer HTTP JSON field order/whitespace aliases
are not conflicts. Changed signed first-frame bytes or any typed creation term
under the same live locator is409 operation_conflict. Frame-ID/different-exact-
bytes conflict remains independently enforced. A first expired creation is 410 even if its record has
already been cleaned up. After the 24h tombstone window, remove metadata; GET
and DELETE of the now unknown locator return 404. New honest attempts MUST use
fresh nonce/secret/request/locator, never recreate an old channel. Finite helper
storage cannot promise to remember every malicious locator reuse forever;
a fresh syntactically valid creation after metadata retirement has no retained
authority and cannot resurrect any participant intent, signature or outcome.

The exact named routes reject all query strings and incorrect body shapes with
400 JSON. Unknown routes are 404 JSON; wrong methods, including implicit HEAD,
are 405 JSON with the exact named route's Allow methods. No redirect or trailing
slash alias is implied. Locator/request path components are canonical literal
ASCII IDs; reject percent-encoded aliases. Unknown ALPN fails before HTTP;
ordinary peer ALPN still rejects unknown identities. None of these errors enters
owner-local/ordinary peer administration. Frames are returned in deterministic
`(role,writer_host_public_key,frame_id)` byte order; this is no latest cursor.
Deletion makes no assertion about other copies or authority withdrawal.

Fixed ceilings:64 frames/mailbox;4 MiB plaintext/frame;8 MiB submitted frame/request
body;32 MiB sum of decoded ciphertext/mailbox;48 MiB GET response;4 active boxes
per actual client host, 16 per source, 1024 globally and 256 MiB global stored
ciphertext. Live records plus tombstones are at most 64 per creator host, 256 per
source and 4096 globally. Reject new creation with 409 quota_exceeded rather than
evict a live record or unexpired tombstone. Additional metadata is bounded by
these counts; delete/expiry release active/byte quotas but not tombstone-count
quota until collection. No truncated successful response is allowed.


These independently inclusive byte caps account for Base64 and whole wrappers.
A 16 MiB selected catalog expands to about 21.34 MiB of frame plaintext; all packet
bodies in a valid 1 MiB activation add about 1.34 MiB, fitting the 32 MiB aggregate
ciphertext ceiling with normal frame metadata. A 4 MiB plaintext becomes less
than 8 MiB outer JSON; a 32 MiB ciphertext box fits 48 MiB GET. The 20 MiB publication
cap holds a 16 MiB catalog,1 MiB activation and bounded outcome/wrapper. Do not
combine maximum packet/catalog components into one frame if that exceeds4 MiB;
use separate whole-object frames. Old 1 MiB closure/512 KiB component/1 MiB mutation
caps were discarded because even a valid 1 MiB migration origin becomes roughly
1.34 MiB in a catalog and could not be sent. No new byte-fragment cryptosystem
or silent truncation is introduced. Global ciphertext256 MiB and each receive/
response queue64 MiB remain fixed, so large valid boxes consume real shared
quota rather than allocate unbounded memory. If a set still exceeds an actual
aggregate/state cap, return quota with no partial authority effect.

Mutation token bucket:2/s sustained, burst 8. GET token bucket:1/s sustained,
burst 4. Charge every attempt, including malformed/bad-capability failures, to
BOTH the actual TLS host key and actual socket source, across connections and
all locators; operator account quotas can additionally aggregate multiple keys.
The more restrictive bucket wins. Source identity is full IPv4 or IPv6 /64,
after IPv4-mapped normalization; never trust forwarded headers or submitted
writer IDs. Counters use monotonic local transport time and survive connection
replacement for their token refill interval. This transport clock is separate
from signed network decision time. No global quota/freshness assertion follows
from a helper's counters. A successful delete needs the same quotas and does
not reset rate buckets. Apply stricter operator ceilings if configured.

Errors are strict JSON `{code,error,required_ids:[]}` with no secrets:
400 invalid,403 forbidden,404 not_found,409 state_conflict/operation_conflict/
quota_exceeded,410 expired,429 rate_limited with integer Retry-After. Opaque
helpers do not invent `proof_required` authority answers. A transport failure,
429, timeout or missing frame leaves the local intent intact and is eligible
for another configured carrier; no catch converts it to authority success.

The mailbox is not an enrollment authority even if hosted by a participant.
Changing endpoint/key requires transport review/configuration, not a new network
root or re-signing immutable operations. A carrier may be removed entirely once
direct exchange is possible. No Peerspan-operated endpoint is hard-coded or
required by descriptor, packet, install or release creation.

## 8. Independently replaceable encrypted relay

Retain end-to-end peer QUIC and host identity verification. An optional relay
forwards encrypted datagrams addressed by host ID; it cannot terminate peer QUIC,
read peer requests, establish a network member or mint an access lease.
Use new ALPN `peerspan-relay/4` to distinguish membership-independent transport
registration from the old coordinator-authorized relay. TLS proves a client's
host key; optional operator tokens authorize resource use only. Host ID derives
from the actual client key. No submitted network roster grants relay or network
authority by assertion.

Version 4 frames have one type byte, a 2-byte unsigned big-endian payload
length and that exact payload. After TLS, the client sends AUTH within 5s:

| Type | Payload |
| --- | --- |
| `0x00 AUTH` | UTF-8 operator resource token,0..1024 bytes; empty requests anonymous resources |
| `0x07 AUTH_OK` | Empty; server reply only |
| `0x08 AUTH_REFUSED` | Empty; server reply followed by close |
| `0x01 SEND` |32-byte destination host-ID digest plus 1..1500 encrypted datagram bytes |
| `0x02 RECEIVE` |32-byte actual registered source host-ID digest plus 1..1500 datagram bytes |
| `0x03 UNREACHABLE` |32-byte destination digest |
| `0x04 PING` | Empty |

Direction/state rules are exact:

| Connection state | Client may send | Server may send |
| --- | --- | --- |
| Awaiting initial AUTH | AUTH only | AUTH_OK or AUTH_REFUSED only |
| Registered, no AUTH outstanding | SEND, PING, AUTH renewal | RECEIVE, UNREACHABLE, PING; AUTH_OK/REFUSED only as response to AUTH |
| AUTH renewal pending | No SEND or second AUTH; PING allowed | Existing registered RECEIVE/UNREACHABLE/PING only until prior registration expiry, plus the one AUTH_OK/REFUSED response |
| Expired/refused/closed | Nothing; create a new connection | No forwarding; close |

Client RECEIVE/UNREACHABLE/AUTH_OK/AUTH_REFUSED and server AUTH/SEND are protocol
errors. Before AUTH_OK no data is forwarded. The client pauses SEND until each
AUTH succeeds; server rejects a premature SEND rather than queueing it as an
authenticated action. PING has no implicit echo/pong. A server can continue
bounded delivery under the still-current old registration while renewal is
pending, never beyond its deadline or a refusal. No control frame extends the
registration except successful AUTH. The connection closes on wrong-direction,
unknown type, invalid UTF-8 AUTH, CR/LF/NUL in a resource token, incorrect exact
payload length, oversized payload, truncated frame or state violation; it emits
no fabricated application outcome. AUTH_REFUSED is used only for a syntactically
valid but unauthorized/over-quota AUTH. Binary relay errors never enter HTTP or
owner-local routing.

No other type is valid. In particular old `changed`/`presence` frames are not
accepted on this version; direct peer exchange handles those scheduling needs.
The sender identity comes only from its TLS client key, never its payload.
AUTH_OK gives a 300s transport registration lease. The client reauthenticates on
the same TLS connection by 240s; AUTH may repeat only for that unchanged TLS key. The submitted
current resource credential must independently pass operator authorization;
credential rotation cannot reset key/source/account counters. PING does not extend registration expiry. Close a
connection after 60s with no frame in either direction, including PING; an honest
idle client pings every 15s. Expiry/refused renewal closes the connection without
any network membership/access effect.

A successfully authenticated replacement connection for the SAME actual host
key atomically replaces/closes its old registration. Failed AUTH cannot evict
an old connection. Stale old-connection frames/queued sends cannot overwrite or
impersonate the replacement. Different public keys cannot register under one
host-ID digest; refuse a collision instead of replacing. There is no routing
claim from an arbitrary payload host ID.

After AUTH_OK, SEND can target only an actually connected registered host;
an unknown target receives UNREACHABLE. This is a connectivity observation,
not membership revocation. Operator token refusal cannot change a network.

Default resource ceilings:1024 connections,1024 queued datagrams/connection,
64 MiB globally queued bytes and 32 MiB/minute inbound datagram bytes/client host.
Operator configuration may narrow these quotas. Byte/rate quotas are charged
to the actual client host key across reconnects/registration renewal over a
rolling monotonic 60s window; reauth/reconnect does not reset them. Also bound
all frames (including PING/AUTH) to 1024/s/client with burst 1024 and AUTH to 2/s
with burst 8. Apply those byte/rate ceilings independently to the actual socket
source as well as the host key; optional account ceilings additionally aggregate
keys. At most 64 registered connections share one source bucket. Source-address
accounting uses the actual socket peer, IPv4 in full/IPv6 /64 after IPv4-mapped
normalization, never untrusted forwarded headers.
The 32 MiB counter counts encrypted datagram bytes, excluding the 32-byte
destination digest and framing. Pending TLS handshakes are bounded to 16 per
source/128 globally with 5s timeout; AUTH has the separate 5s post-TLS deadline.
Counters and queues are local transport accounting, not signed network evidence.
Apply backpressure or drop datagrams on saturation without granting priority
or authority; QUIC retains
its normal loss semantics. An honest client pings after 15s idle, bounds connection
attempt to 5s and exponential reconnect backoff to 30s. No token is logged.
Relay output remains opaque QUIC ciphertext and never carries a catalog or
plaintext task/capability body. This protocol introduces no privileged forwarding,
subnet route, arbitrary TCP proxy or network authority credential.

Hosts may retain multiple independently configured relay endpoints and switch
on transport failure without changing network identity/history or ciphertext.
For two mutually unreachable NATed devices, both need at least one mutually
reachable relay (or an actually reachable bridging participant); arbitrary
unconnected relay lists alone do not create a path. The bootstrap mailbox gives
both outbound-only devices a reviewed enrollment path, and the relay carries
the resulting end-to-end QUIC connection. Test a shared independent operator,
replacement operator and total helper outage separately. With no reachable
path, report unavailable; never claim that cryptographic validity implies
connectivity or that direct networking always works.

## 9. Migration, decisions and verification

Schema is currently 21, including per-call approvals 20 and builtin/gh 21. The
root-owned schema 22 migration must preserve those tables, host/person/device
keys, operation history, exact original proofs, restrictions and high-water.
A signed authorized transition binds old network/genesis/name/history and new
context. Legacy contexts remain exact historical input; no old coordinator
receipt, feature pin, last-sync timestamp or dummy descriptor becomes new-mode
authority. Downgrade/re-adoption cannot clear the remembered mode/transition.
Unresolved old operations remain public recovery evidence; a new-domain attempt
requires fresh reviewed consent and never silently adopts old intent.

Chosen alternatives: explicit contacts and existing crypto/QUIC before a public
DHT/new library; isolated bootstrap before globally accepting unknown peer TLS;
finite independently verified authority before mandatory online quorum; separate
participant outcomes before global consumed-token/receipt serialization;
whole target-bound approvals before bearer membership; portable encrypted frames
before helper-key-bound AEAD; optional encrypted helpers before a mandatory
vendor service. Costs include explicit contact handoff, finite renewal duties,
visible partitions and real relay dependence where direct reachability fails.

Independent verification derives from the final unified contracts, covering:
new creation/link/policy/capability work with no coordinator/defaults; direct
Go/Rust combinations; unknown-host router/ALPN isolation; exact separate consent
and no key copy; partial op-bound grant inertness; complete pending self-consent
without unrelated authority; immutable retries and every persistence crash
boundary; conflicting request/manifest/lease histories; malicious backdating and
late exact complete learning versus explicit historical repair; current expiry,
known revocation/forks and rollback; signed contact replay/substitution and
privacy; inviter-origin contact token/person-key pin and key-generation review;
third-host activation replication without outcomes; nonparticipant outcome
refusal and historical outcome retries after expiry; helper exact Authorization,
TLS/source/account aggregation, drop/reorder/replay/forgery/quota abuse and
independent failover; ciphertext deletion/tombstone/expiry/recreation boundaries;
restrictive NAT with two independent relays; migration/restart/downgrade;
installed setup/real adapter readiness; and separate-machine live-agent task,
artifact/result and withdrawal. A signed heartbeat, fixture adapter or helper
receipt is never evidence of no unseen revocation or a completed model task.
