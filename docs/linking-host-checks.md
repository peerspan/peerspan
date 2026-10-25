# Approved linking host runtime and recovery

This contract completes host portions of UP-06c.3 and UP-06d in Go and Rust.
The [transactions](machine-linking-transactions.md) pin the wire messages,
cryptographic signatures, schema 19, states, limits, errors and existing CLI.
The [runtime foundation](linking-runtime-checks.md) pins coordinator mailbox
transport and deterministic test controls. This extension resolves host consent
and transport gaps without changing the original person's identity or copying
that person's private key. Runtime work starts only after independent authors
have this contract.

## Coordinator transport and the legacy bridge

Upgraded hosts use these additional coordinator routes, under `/coord/v2`:

- `POST /networks`: existing registration fields `{name, root_public_key,
  membership, address, candidates}` plus `linking_version: 1`.
- `POST /networks/{id}/sync`: exactly `{address, candidates, linking_version: 1}`.
- `POST /networks/{id}/members`: existing membership or admission join fields,
  address/candidates, plus `join_ack` and `linking_version: 1`. `join_ack` is `-`
  before feature activation; afterwards it is the exact signed host feature ack.

Before feature activation these return the existing strict legacy map, with no
`format` field. An upgraded host uses existing legacy signature/chain/member
verification in that case. Once the feature is active they return exactly the
transaction contract's `{format: 2, network, catalog, members}`. The descriptor's
coordinator address and key must equal the actual pinned connection. Signed moves
and successors retain their separate existing verification.

The legacy bridge is available only when this host has no durable feature pin.
After learning a complete verified active feature, commit its exact immutable ID
and public proofs; any subsequent legacy map, omitted/conflicting feature,
missing known restrictive proof, operation rollback or high-water rollback fails
closed. Preserve the last complete verified state. Activated coordinator networks
refuse all old `/coord/v1` mutations/maps/sync/join paths with `426
upgrade_required`; prefeature v1 bodies and behavior stay unchanged.

`linking_version: 1` advertises the implemented reader/storage/mutation support,
not a user-agent assertion. The daemon sends it only when this complete runtime
support is present. Before activation, feature preparation/ack collection uses
the fresh existing legacy map; proposal roots, epochs and roster are verified.
Acknowledging an installed reader never asserts agent readiness.

## Durable host state and authority

For map-2 coordinator transport, verify catalog `coordinator_move` objects using
the current verified root/administrator rules before selecting the highest
valid sequence. An invalid historical higher move cannot hide a lower valid
current move. Apply the existing move precedence and monotonic applied sequence.
For successor proofs, start at the independently known actual connection pin,
select its highest-sequence valid first edge, then follow only exact consecutive
sequence-plus-one edges from each resulting key. Stop when the next edge is
missing, bound traversal by the finite catalog, and run the existing complete
`VerifySuccessors` checks on the selected chain. Repeated public keys are allowed
for address-only successors and returning to an earlier key; increasing sequence
and unique previous-key/sequence edges prevent unbounded traversal. Catalog
import alone never changes a host's independently pinned connection.

During atomic first adoption, access-state verification may use the feature ID
from independently verified adoption evidence before storing feature and
high-water together. An existing durable feature must still match exactly.
Enable-linking first verifies the complete feature using its original durable
`known_feature_id: "-"`. Generic first map adoption independently enforces
those same first-feature deadline, current epoch and exact roster conditions,
or requires the separately approved fresh-root repair workflow. A new link
result instead uses the feature already locked by the requester's approved
owner/selection and a complete verified activation. A raw map/catalog feature
never substitutes for a previously durable feature or bypasses first adoption.

Migrate atomically from 18 to the exact eight schema-19 tables in transaction
section 6. Preserve host identity, roots, networks, policies, services, sessions,
attachments and adapter credentials. Failed migration rolls back. Old binaries
refuse schema 19; newer unsupported schemas remain refused. Both languages can
open each other's migrated state and resume pending/committed operations.

The signed `link_objects` catalog is append-only for known public authority:
keep revocations/removals, feature pins, operation tombstones and policy/group
high-water when transport/pending secrets expire. Resolve candidates from exact
stored body bytes, never a reserialized or unsigned map view. Merge by derived
proof/semantic IDs in a private snapshot, verify its full dependency closure,
root chain, durable feature, exact known restrictions and prior access-state
high-water before committing. Conflicts/omissions and failed capacity checks
leave every last verified row intact. Member reachability hints remain untrusted;
a member's bad independent proof can be dropped, while a missing dependency for
this host/current signer is an explicit repair failure.

Full-map verification has the existing 16 MiB response limit, at most 8 MiB
summed decoded public objects and 4,096 retained objects/network. Individual
signed-object limits remain unchanged; the 64 KiB bound is frame plaintext.
Strict `DecodeMutation` parsing remains fixed at 1 MiB. Private persisted records
may nest Base64 copies of public packets/catalogs; `DecodeStoredJSON` has a fixed
32 MiB private-row parsing bound and confers no signature/authority. Every network
response still separately enforces 16 MiB and the decoded catalog 8 MiB bound.
The 512 KiB state-free verification probes retain their existing bounds. Fixed
stored-state verification entry points accept the full-map budget; an arbitrary
caller-provided budget never relaxes signature or dependency rules.

Public policy/group versions, policy/capability citations, edit version fields
and delivery/status version views are u64 in both implementations. Their
existing positive legacy JSON and signing lines remain unchanged. Refuse
version progression at `2^64-1` before incrementing or signing; never wrap to
zero. Generation refusal is HTTP 409 `quota_exceeded` with public error phrase
`access version exhausted`; CLI-local preflight uses the same phrase. Check this
before an edit reservation, signature or publication. Explicit signed payloads
may jump to any strictly higher positive u64; CLI-generated updates use guarded
prior-plus-one and edit reservations retain their existing exact-next-version
rule. Existing policy/group, edit and delivery records retain JSON TEXT storage,
so this requires no additional table or schema migration.

Verifier versions are u64. Preserve the exact schema's INTEGER-affinity
`link_highwater.version` column while supporting the full verified range. Encode
`1..2^63-1` as positive SQLite INTEGER; encode `2^63..2^64-1` as an exact eight-byte
unsigned big-endian SQLite BLOB (INTEGER affinity preserves BLOB storage).
Canonical decoding accepts only those two forms: reject negative/zero integers,
REAL/TEXT, non-eight-byte BLOB and a BLOB whose high bit is clear. Compare decoded
values in application u64 arithmetic, never SQL MAX, numeric affinity coercion,
wrap or truncation. A restrictive maximum remains learnable over the full range.
Never reset an epoch's marks or fall back to a lower policy/group because the
highest lost usable authority. Materialized existing
policy/group views come only from active selected signed statements; inactive
maxima cannot provide access. Preserve complete body edits/trusted hosts/rules.

The network-scoped device provider owns a distinct 32-byte seed per enrollment,
kept only in `link_device_keys` under existing private-state permissions. It
supports typed certificate/binding/admin/policy/revocation/checkpoint operations
with transaction-time current authority checks. It exposes no raw-sign route and
never exports the seed. Original-person and external SSH/root providers remain
CLI-side. On an activated network, every explicit original-person selection
must match the bound stable person; failure to find a live device returns repair,
never creates a new person. Before activation, the existing explicit held-key
workflow may still act for another current person under its original authority.
Only a strict `426 upgrade_required` from the read-only active-feature check
selects that legacy behavior; successful verified activation requires the bound
identity check and every other failure refuses without signing or fallback.
The existing `network bind --person-key PATH` recovery command may establish a
first binding for an independently verified local member whose person binding
is absent. Its original key and person admission still verify; a different
existing binding is refused. This binding-specific allowance does not change
access/capability provider selection or authorize fallback from a broken selected
device signer.
Pick the shortest usable renewal issuer path, then certificate ID, unless the
user selected an exact issuer.

### Local access views and peer propagation

Each local projection uses one coherent database snapshot for its retained
catalog, durable feature/root/coordinator pins and policy/group high-water.
Capture all bytes, references and maxima under the same read transaction, then
close that transaction before expensive pure verification when the caller does
not already own a write transaction. A concurrent renewal cannot combine an
older catalog with a newer maximum and temporarily hide the selected policy.
Verification, validity windows, missing-proof refusal and no-fallback rules are
unchanged. The independent automatic-renewal gate requires every observed view
to remain the verified prior policy or the verified renewal, never a transient
missing-policy response caused by mixed snapshots.

For an enveloped selected policy, `PolicyView` projects only its verified active
unsigned payload fields, uses flat `signature: "-"`, retains `expires_soon`, and
adds optional `authorization_base64`: canonical padded Base64 of the exact
original signed envelope bytes. The existing already-unsigned `Group` view keeps
`name, version, members, signer` and its existing member filtering, adding only
optional `authorization_base64`; no new group signature/network/time fields.
Legacy views omit the new field. Signed legacy Policy/Group wire types do not
gain view metadata. Internal rule evaluation uses the independently verified selected
payload. Exact public envelopes remain in `link_objects`; no projected unsigned
view may be propagated as a legacy signed policy/group. An inactive highest
selection never falls back to an older active body.

For next-version generation, owner-local `GET
/v1/networks/{id}/link-access-versions` has no body or query and returns exactly
`{policies: [{person_public_key, version, message_hash}], groups: [{name,
version, message_hash}]}`. Arrays are sorted by their exact subject key and may
be empty. Versions are positive u64 and message hashes use canonical lowercase
SHA-256. The read verifies the current epoch's complete projection together with
the exact retained high-water; invalid or missing required evidence fails closed.
It performs no sync, mutation or signing and makes no authority/readiness claim.
CLI and daemon generation consult these maxima before guarded `+1`; permission
evaluation continues to use only active selected bodies. Fresh writers recheck
under their existing lock, so a stale generation race is rejected.

Active v2 root rotation derives its renewal plan from the complete independently
verified current host/person projection, including linked hosts with no legacy
member-row admission. Preserve every old exact public object and high-water.
Only active root-signed group bodies are renewed by the new root, at guarded
next version; the legacy same-version renewal exception does not apply after
activation. An inactive maximum cannot resurrect an older group and device
envelopes are retained exactly. Pending rotation/root-seed replacement and the
accepted public rotation/renewals are committed atomically under the existing
rotation retry rules. No root transition disables the durable feature or resets
the selected original person/device.
Before ordinary active sync, a durable pending rotation is resubmitted and its
verified response commits the matching new root seed and full public projection
in one transaction. A lost reply or restart cannot advance the public epoch
while leaving the old seed installed. Unsettled transport retains the exact
pending intent and prevents ordinary sync from bypassing its completion.
A current-authorized held move learned through an authenticated peer catalog
is considered before contacting an unavailable old coordinator; historical
recognition alone never makes a held move current-authorized.

Active upgraded peers use authenticated mTLS `GET` and `POST`
`/peer/v1/networks/{network}/link-catalog`. GET has no body/query and returns
exactly `{catalog}` with the full retained public catalog within the fixed
16 MiB response cap. POST is exactly `{catalog}` within the fixed 1 MiB total
mutation limit, and returns the same envelope with the verified full union
within 16 MiB. Only a current independently verified network member can use
these routes; absent active durable feature returns `upgrade_required`.
Verify historical complete evidence and atomically append immutable exact
objects, preserving all known restrictions, feature, operations and prior
high-water. A draft cannot activate its signer. Replication does not authorize a
fresh signature. Sufficient proof/delta batches carry large catalogs without
raising the mutation limit. Old peer policy-array GET/POST return
`upgrade_required` after durable activation; prefeature behavior stays unchanged.

Existing `policy_deliveries.record` gains optional `catalog_base64` only for
upgraded delivery rows; legacy rows omit it. Upgraded rows require canonical
Base64 of the exact sufficient signed catalog, fixed before enqueueing. Their
existing `policy` model may have `signature: "-"` solely for internal version and
status fields. Every upgraded send/retry/repair dispatches the retained catalog
exclusively; it never publishes that unsigned model through legacy policy-array
routes. Existing retry and public delivery status semantics remain. Check the
complete POST `{catalog}` against 1 MiB before enqueue/public mutation; an
oversized sufficient closure fails atomically. Private persisted row parsing
keeps its fixed 32 MiB bound. Both implementations preserve the optional field
when opening each other's rows.

## Typed device management actions

`GET /v1/networks/{id}/link-signer` is a read-only discovery route. Successful
HTTP 200 is exactly `{network_id, person_public_key, device_public_key,
certificate_id, scopes, not_after}`. It resolves the exact selected local row,
owned device seed and current verified path, using a present non-administrator
scope when available; a scope-8-only path also requires the current administrator
role. It establishes no sync freshness or readiness. No selected row returns
404. A present row with missing/corrupt seed, unresolved dependencies, expiry,
revocation or role loss returns structured repair for the same stable person;
it never returns 404 to trigger an original/new-identity fallback. Writers still
freshly sync and revalidate. An explicitly chosen original-person key must match
the bound original person, and a failed selected path never silently falls back.

`POST /v1/networks/{id}/link-actions` is private local administration, with
exact request `{kind, payload_base64, certificate_id}`. `kind` is exactly one
ordinary person-record kind in the accepted payload registry, or the explicit
`device_revocation` variant below. Decode strict
unsigned typed payload bytes; reject unknown kinds, fields, arbitrary messages
and signature injection. `ValidateActionPayload(kind, raw)` / Rust equivalent
only checks the existing ordinary typed payload registry; it never verifies a
signature or supplies authority. Providers check current path and typed
preconditions before using a local private key, then verify the exact signed
action before publication. `certificate_id: "auto"` resolves the current selected
local device; an exact `dc_` requires its locally owned seed, same original
person and fully usable exact path. Never silently replace the bound identity.
Fresh pinned sync and current authority/preconditions are rechecked under the
network lock before signing/publication. Verify scopes, role, expiry and
self-invalidating delegated changes with the reusable action verifier.

The fixed-budget pre-sign helper `VerifyStoredActionIntent(ctx ActionContext,
actionKind, catalog, payload)` returns `ActionAuthority` with `record_id: "-"`.
For `person_record`, payload is exactly `{kind, payload_base64}` containing a
strict ordinary unsigned payload. For `device_revocation`, it is the exact
unsigned revocation object below. It uses the same current path, scopes,
administrator role, expiry and self-invalidation preconditions as signed action
verification, without claiming a signature or publication. Host-specific
consent, fresh sync, mutation preconditions and access maxima remain additional
gates. Signed action verification is mandatory after signing and before
publication; intent verification cannot replace it.

Every successful response is HTTP 200, including `committed: false` invitations
and exact retries. Response is exactly `{record_id, proof_id, record_base64,
catalog, committed}`.
IDs derive from the exact signed record bytes. For ordinary published actions,
post the exact catalog to v2 statements and atomically apply the verified result
locally before returning `committed: true`. Preserve complete public record
bytes so downstream readers never reinterpret a device signature as legacy.
Owner `allow`/`deny`/trust/edit/renewal and administrator CLI operations use this
typed provider on linked machines, preserving existing user command shapes.
Original-person SSH submissions remain supported; their valid legacy statements
can be published as legacy catalog objects over v2 statements.

For `kind: "device_revocation"`, the unsigned payload is exactly the existing
format-1 revocation object without `signature`: `{format, network_id,
person_public_key, target_device_public_key, target_certificate_id,
issuer_certificate_id, revoked_at}`. Original person and issuer fields must match
the resolved local provider, including an exact issuer even when outer selection
was `auto`; a race never substitutes a different path. Sign the existing
revocation message and run current action authorization with action kind
`device_revocation`. The result uses its derived `dr_` and `pf_` IDs and follows
the same v2 publication/local commit. Self/ancestor/same-key self-invalidating
revocations remain refused before strict descendant checks.

A checkpoint is not an ordinary management action. Its issuer must be the
original-person root or a currently live, unaffected and authorized strict device
ancestor for every retained record, with the union of those record scopes. Only a verified typed checkpoint writer
or an exact external original-person signing workflow may perform this repair;
cryptographic `Read` success or ordinary action fallback cannot authorize it.

The explicit typed `link-actions` variant is `kind: "checkpoint"`. Its unsigned
payload is exactly `{format, network_id, person_public_key,
issuer_certificate_id, issued_at, records}`, the format-1 checkpoint without
`signature`. `issued_at` is strict whole UTC seconds and records keep the existing
sorted exact-ID rules. The payload's original person and issuer must equal the
resolved owned local provider, including when outer `certificate_id` is `auto`.
Fresh sync, the current local binding and the exact owned issuer seed are host
gates. Before any signature, call `VerifyStoredCheckpointIntent` /
`verify_stored_checkpoint_intent` with the same catalog context and unsigned
bytes. This fixed stored-budget helper reuses the signed checkpoint's exact
retention target/person, strict ancestor, current path and combined scope checks,
skipping only the absent signature. It produces no signed ID, state or authority
claim. Sign only the resulting fixed checkpoint message; signed
`VerifyStoredCheckpoint` remains mandatory before publication. Success is HTTP
200 with the existing result shape and exact signed checkpoint bytes:
`record_id` is `"-"` under the existing checkpoint reader semantics and
`proof_id` is the exact `pf_` for those bytes. Ordinary person-record/action
fallback is forbidden.

Live `invite-v1`/`person-invite-v1` grants have their strict scope-8/current-admin
and expiry checks but are not unsupported standalone public catalog entries.
Return their signed record with `committed: false`; the CLI constructs the
accepted private authorized invite token containing the separate invite seed
and sufficient public authority catalog. This result claims no admission or
invite consumption. First-redemption current authority, host TLS caller, feature
ack, mode/admit/skip preconditions, single-use transaction and exact committed
retry remain coordinator obligations.

## Exact local consent extensions

The original approval/admission routes and review shapes remain as specified in
transaction section 7. For admission by a separate administrator, request
`expected_person_id` and `review.person_id` pin the selected owner's stable
identity. The local administrative provider resolves from the local bound
administrator (or exact selected issuer), never by substituting the target owner.
`review.signer_public_key` and signing requests pin that actual administrator's
signing key; the admission envelope's `person_public_key` names that signer,
while its admitted host/member fields remain those fixed by the selected owner. A preview signs/publishes nothing; approval requires exact
reviewed network/person/host/device pins. `auto` resolves once to a concrete
issuer before consent. Persist fixed scopes, issuance/expiry, dependency bytes
and signing templates. External signing requests expose only the next typed
message that is ready; submission verifies a signature over those persisted
bytes. No timestamp, role, subject or selected path changes between steps.

An invalid actual-network approval pin returns `400 invalid` before approving,
signing or publishing. Independently verified incoming transport may be cached;
that cache grants no new owner/admin intent, signed packet, outbound publication
or public authority. If the code already names an approved local intent, preserve
its exact intent, signing template and packet bytes and all requester consents.

The new machine separately consents to selecting an owner offer and making a
final commit. `resume {}` never implies consent to a mutable offer or to a later
administrator record. Two additional private Unix-only routes are:

```text
POST /v1/link/requests/{id}/selection
{owner_offer_id, network_id, person_public_key,
 host_public_key, device_public_key, approve}

POST /v1/link/requests/{id}/commit
{owner_offer_id, selection_id, administrator_offer_id, network_id,
 person_public_key, host_public_key, device_public_key, approve}
```

All fields are required, strict and exact; `approve` is a JSON boolean. For a
renewal `administrator_offer_id` is `-`. With `approve: false`, return public
request view and an immutable proposed review; missing unknown pins may be `-`
only in preview. With true, every supplied reference/key must exactly match the
reviewed, currently verified offer/selection/admin record. A race/conflict does
not choose another candidate. Fix and persist selection/commit before publish
or coordinator submission. Distinct second selection/commit is
`operation_conflict`; identical durable repeats reuse exact bytes and IDs.

Both new routes return exactly `{request, review}`. Selection `review` has
exactly `{owner_offer_id, network_id, person_id, person_public_key,
host_public_key, device_public_key, certificate_id, issuer_certificate_id,
scopes, not_after, signer_public_key, authority_warning}`. Final review adds
exactly `{selection_id, administrator_offer_id, admission_record_id,
admission_record_base64, administrator_signer_public_key}`. The admission Base64
is the exact signed public record, never ciphertext. For renewal all admin fields
are `-`. Derive `person_id` from the exact original public key and require the
request's person expectation, supplied key and derived ID to agree. Reviews
contain no code, seed, ciphertext or private provider material. In every review,
`authority_warning` is a string: public explanatory text, or literal `-` when no
warning applies. Standard profile 15 discloses conditional administration and
the ability to trust itself and approve further machines. Original
approval/admission views remain unchanged.

Selection consent never automatically signs the final commit when an admin offer
later appears. Renew also requires both consent stages. Current authority,
feature, epoch, request deadline and locked references are rechecked before each
new signature and immediately before submission. Committed retry retrieval uses
stored exact results first and never restores authority removed afterwards.

## CLI and `up`

All transaction-section-7 commands remain. Additional exact commands are:

```text
link select REQUEST_ID --owner-offer ID --network ID --expect-person KEY
    --expect-host-key KEY --expect-device-key KEY [--approve]
link commit REQUEST_ID --owner-offer ID --selection ID --administrator-offer ID
    --network ID --expect-person KEY --expect-host-key KEY --expect-device-key KEY
    [--approve]
```

New and renewal request creation support the paired flags `--coordinator
HOST:PORT --coordinator-key KEY`, mapping to the existing exact API pin fields.
An unresolved new network otherwise uses the compiled default or returns an
actionable error. Overrides for renewal or a known network must equal its
current verified pin. Resume cannot override persisted pins.

Without `--approve` these preview. With it all pins are required, including the
literal admin offer `-` for renew. Existing `link approve`/`link admit` gain
`--expect-host-key`, `--expect-device-key` and `--approve`; `--person PERSON_ID`
pins their existing stable-person field. No bare `--yes` authorizes linking.
Private code uses hidden prompt or `--code-stdin`, never process arguments.

Interactive `link`/`link resume` guides selection and final commit with separate
default-no prompts after displaying their exact reviews. Machine output remains
JSON on stdout and human guidance on stderr. Noninteractive incomplete work
returns the strict public view/next step and nonzero; it never supplies consent.
Public request view `completed`, `attention` and `next` are ordered arrays of
strings. Completed stage names are exactly `request_created`, `owner_offered`,
`owner_selected`, `administrator_offered`, `commit_persisted`, `locally_applied`
in that order, with no duplicates and only after their durable verified stage.
Renewal omits `administrator_offered`; `locally_applied` requires the atomic
result transaction. This is stage history, never inferred current readiness.
`GET /v1/link/requests` returns a request-ID-sorted array of strict public views;
`GET /v1/link/requests/{id}` returns one strict public view. Creation and explicit
still-pending local resume add exactly `display_code` to the flat public view.
Normal status and terminal resume contain no display-code field.

Display code is returned only for initial creation and explicit local resume of
a still-pending request. Normal status/events/logs contain no code/ciphertext/private key.

`up` first discovers stable existing network/person/device state. It resumes an
incomplete link or uses the existing currently live selected device before agent
attachment. Expired/revoked/unknown authority returns repair for that same person.
It never falls through to generated replacement-person identity or key copying.
The linked, attached and agent-ready stages remain distinct; only the existing
adapter readiness handshake can establish readiness. Preserve existing service,
state path, attachment and integration profile during every retry/repair.

## Shared pending records and signing intentions

`link_pending.record` is strict format-1 JSON with exactly these fields:

```text
format: 1
network_base64, expected_network_id, expected_person_public_key
coordinator_address, coordinator_public_key, host_public_key, device_public_key
request_nonce, request_packet_base64, owner_packet_base64
selection_packet_base64, administrator_packet_base64, commit_packet_base64
result_packet_base64, catalog_base64
owner_offer_id, selection_id, administrator_offer_id, manifest_id
after_sequence: u64
selection_approved, commit_approved: boolean
owner_intent, administrator_intent: typed object or "-"
outbound_frames: [{role, writer_public_key, frame_id, published, sequence}]
```

Unknown packet/descriptor/catalog bytes and IDs use literal `-`; never null.
Known Base64 retains exact original bytes. Original request expectations, keys,
nonce and coordinator pins never change. Network descriptor may resolve once
from `-` to the reviewed exact descriptor. `after_sequence` is the monotonically
processed mailbox cursor, independent of signature authority. Outbound frame
references are kept in creation order; `published` is boolean and `sequence` is
zero until an acknowledged publish. The shared `link_frames.record` is exactly
`{frame_base64}` and is the sole immutable store of sealed frame bytes; table
request/role/writer/frame tuple must match the decoded frame. No resealing occurs
on either an unknown publish result or a cross-language restart.

For a new/renew requester, `owner_packet_base64` becomes locked only on explicit
selection approval. A preview can name a valid candidate by exact offer ID; an
unpinned preview chooses the lowest valid owner-offer ID and discloses it. A true
submission still requires that exact ID and keys, irrespective of later offers.
For an approver, the owner packet field stores the exact reviewed/received
selected owner offer (its own published owner offer when acting as owner); the
administrator field stores its own fixed published admin offer. A separate admin
retains the received selected owner packet. A received selection must reference
that exact reviewed owner offer; no mutable latest offer can replace it.
Distinct locked packets or references conflict. Both consent booleans become true
only through their explicit requester consent route, and never revert or follow
a mailbox hint. Packet references and derived IDs must agree on every restart.

Each non-`-` intent has exactly:

```text
format: 1
approved: boolean
epoch, feature_id, person_public_key, certificate_id, signer_public_key
scopes, issued_at, not_after
certificate_template_base64, record_template_base64, packet_template_base64
signatures: [{object_type, signature}]
```

Owner slots are exactly `certificate`, `binding_authorization`, `owner_packet`
in that order for new linking; renew omits the binding slot and its record
template is `-`. Administrator slots are exactly `admission_authorization`,
`administrator_packet`. Its certificate template is `-`. All absent signatures
are `-`. These are typed templates for the exact contract objects, not arbitrary
messages; unsigned template signature/host-consent positions are `-`. Each
signature must verify against its derived dependency-ready message before its
slot is filled. A filled slot never changes. Packet template starts as `-`, then
is constructed and durably fixed exactly once after child signatures are ready.
Only that exact fixed template produces the next packet signing request.

An owner intent's scopes are the displayed child scopes: standard profile 15 for
an original-person issuer, otherwise the issuer's allowed subset of 15. Its
fixed issue time is the approval-template creation time; expiry is the earlier
of that time plus 90 days and parent expiry. Administrator intent scope is 8;
its fixed issue time supplies `admitted_at`, and `not_after` is the selected
issuer expiry or `-` for original-person/network-root. Root-only administrator
uses person `-`, certificate `network_root`. A same-machine owner/admin approval
may persist administrator intent approved for the exact reviewed request/owner
and keys; its packet is constructed only after the matching signed selection
has been verified and persisted. It never selects or commits for the requester.
This single-review path requires that the selected owner signer itself currently
has scope 8 and the administrator role. It fixes that same signer/issuer and the
exact reviewed owner offer, network, person, host, device and scopes. Freshly
revalidate that path/role before each administrator signature and publication.
An owner-only review never selects a network root or alternate administrator as
a fallback. Otherwise use a separate explicit `/admissions` review. An original
SSH provider exposes the later dependency-ready administrator slots to the CLI
when resuming the same reviewed approval; its private key is never imported.

`GET /v1/link/requests/{id}/approval` has no query/body and returns exactly the
existing `{request, review, signing_requests}` shape. It reads only persisted
approved approver intent and already fixed dependency-ready signing slots;
it creates no template, consent, signature or publication and returns no code
or seed. Missing request is 404; an existing requester or unapproved approver
is 409 `state_conflict`. Resume may materialize a later administrator packet
template only after matching selection and fresh authority checks. The CLI then
reads this endpoint and submits its typed signatures with the already selected
matching original key. Requester resume may ignore this inapplicable auxiliary
409; it cannot silently select another provider.

Preview may retain the immutable local public review/template needed for consent
and recovery; it produces no signature, outbound offer or network mutation.
Approval changes only the corresponding approved intent before typed signing.
When signatures are dependency-ready, the CLI receives exactly those requests
from transaction section 7; signed submission contains only object type and
signature. It cannot alter any template or choose an arbitrary message.
All persisted JSON is compact UTF-8 with recursively sorted object keys and no
unnecessary escaping when first constructed; accepted original signed bytes are
always retained, independent of whitespace/order. Neither language rebuilds
already persisted signed payloads or frames during resume.

## Persisted recovery and deterministic barriers

Persist device key/request nonce/code seed and public request before displaying
the code, each sealed immutable frame before publishing, selected owner before
admin handoff, and final signed commit before coordinator submission. Restart
uses those exact bytes; never reseal under an existing frame ID. Encrypted plaintext has exactly `{request_id, role, writer_public_key, packet,
catalog}`. `catalog: "-"` means no public proof chunk (including the initial
unknown-network request); otherwise it is an exact catalog object. A catalog-only
frame uses `packet: "-"` and a nonempty actual catalog. Both fields `-` is invalid;
never synthesize a network ID to fill an absent catalog. Received catalog-only
frames establish no authority. Decrypted strict metadata must match
header/request/packet, and merged proof bounds apply before dependency resolution.

Successful result application atomically stores network/person/binding, exact
public proofs, feature/high-water, selected device/provider, operation result,
`locally_applied: 1` and its one event. A lost response/restart reuses that result;
no duplicate event or membership mutation. While outcome is unknown retain
`finalizing` and stable consent even after deadline. Cancellation before requester final-commit
consent retires the request/code and deletes transport; stopping an approver reports `offer_sent`; cancellation
never silently revokes a device/host or undoes committed authority. Terminal
cleanup removes live code/secret/ciphertext while retaining public proof and
operation tombstones, without promising secure erasure of backups/WAL.
Successful local apply retains its strict public `link_pending` record
indefinitely for status/resume, sets `secret` to SQL NULL and deletes its
`link_frames` in that same atomic transaction. Exact public packet/ref fields
remain; the operation result is the sole committed outcome. Cancelled/expired
pre-final-consent requests retire secret/ciphertext immediately and retain their
public tombstone through deadline plus 24 hours, after which it may be removed.
Commit-persisted/finalizing public intent and operation tombstones survive expiry
or an unknown-operation 404 until outcome is resolved. Terminal rows do not
consume active-pending quota; durable operation bounds remain unchanged.
The atomic application event is exactly `network.link_applied`, with subject
equal to the request ID for both new and renewal. Ordinary membership/binding
events may also occur; this event makes no agent-readiness claim.

For an already locally applied request, a well-formed conflicting supplied
owner/selection/administrator/network/person/host/device pin returns HTTP 409
`operation_conflict`, preserving its exact original outcome and newer signer
selection. Malformed JSON/identifiers and missing mandatory approval fields
remain HTTP 400 `invalid`; a first pending consent/reference mismatch also
remains 400 `invalid`. An identical committed retry reconstructs its full review
from the immutable persisted transcript without requiring current signing
authority or reapplying signer, membership, proof or reachability mutations.

Host barriers use the runtime foundation's opt-in environment controls:
`host.request.after_commit`, `host.frame.after_commit`,
`host.selection.after_commit`, `host.finalize.after_commit`,
`host.result.after_commit`. They occur after durable commit and before display,
publish/submission or response. They contain only public request IDs. Both
implementations honor the same barriers and test clock; production uses UTC.
`host.frame.after_commit` applies to any durably persisted frame, received or
outbound. A conformance check targeting an unpublished administrator frame first
processes its exact incoming selection and fixes the external administrator's
dependency-ready signing slots, then arms the barrier before submitting the
final packet signature. Earlier received frames are not evidence of a sealed
unpublished administrator packet.

## Sufficient ceremony proof catalogs

`SelectStoredProofCatalog(CatalogFactContext, full_catalog, seeds)` in Go and
`select_stored_proof_catalog` in Rust select public dependencies from a verified
stored snapshot. Each seed is exactly a public `{kind, body}` pair in the host
language API: an accepted catalog kind or `packet`, with its original JSON bytes.
Seeds must be complete strict public signed objects/packets, never unsigned
persisted templates or standalone drafts. A signed owner packet may contain the
accepted owner-signed binding draft whose host signature is still `-`. Seeds
are dependency hints, never authority or catalog assertions. They are not
inserted into the returned catalog; a pending target certificate remains inert.
The complete source must pass the full stored network verifier before selection.
Ceremony-local `lp_` references are not standalone catalog dependencies: follow
a source activation when present, but missing local offer/request/selection
packets remain the separate ceremony verifier's responsibility.
The caller must separately verify the exact current offer/selection/activation,
freshness, consent and transaction preconditions before signing or committing.

Selection is a deterministic conservative fixed point, not a minimum-size proof:

- Retain the complete signed root chain and durable feature. A feature roster's
  unrelated hosts do not become dependency seeds merely by appearing in its
  signed roster or embedded acknowledgments.
- Follow exact proof and semantic references, including certificate parents,
  original certificate activations, renewal membership/binding proofs, operation
  activations, and referenced checkpoint records. Preserve each selected object's
  exact bytes and derive its transport/semantic IDs independently.
- For each encountered person retain original admission/membership alternatives,
  recognized administrator delegations and withdrawals, and applicable retention
  checkpoints. For each encountered host retain membership/admission, binding,
  current attestation and feature-acknowledgment alternatives. Completed invite
  redemptions supplying these facts retain their original signed invitations.
  For an encountered linked host, retain its completed activation alternatives
  even when a newer root admission or attestation supplies current membership;
  those new statements do not replace the original feature participation proof.
- Discover legacy SSHSIG issuers from the signature itself and include their
  delegation/withdrawal evidence. Keep the complete signed kept list; including a
  withdrawal does not require unrelated kept records unless an exact selected
  record/checkpoint references them.
- Retain every sticky person/host/device/invite restriction affecting any
  encountered subject, including restrictions whose issuer requires further
  original admission, certificate activation or retained-history dependencies.
  Repeat dependency and restriction discovery until stable. Never hide a known
  restriction to make a currently unusable path appear usable.
- Unrelated policies, groups, certificates, activations and grants are omitted.
  An exact reference may still pull an otherwise unrelated object into the
  closure. Conservative alternatives for an encountered subject are permitted;
  the selector cannot discard a restricting alternative to fit a byte limit.

Seed bodies total at most 512 KiB, with at least one and at most 4,096 seeds.
Conformance compares required/excluded proof IDs and exact source body bytes;
no minimum subset or particular equivalent-byte alias is contractual.

The returned entries are a subset of the source's original top-level entries.
Nested references select their enclosing original activation/redemption, rather
than creating new top-level entries from nested records.
The returned format-1 catalog is sorted by independently derived proof ID and
contains no duplicate or conflicting semantic identities. It must itself pass
full stored network verification. Original signed bytes are never rebuilt or
truncated. The fixed submitted-catalog limit is 1 MiB and 4,096 objects; an
irreducible or conservative closure exceeding it returns `quota_exceeded` and
no partial catalog. Missing exact dependencies return `proof_required`.
The fixed stored-snapshot conformance adapter adds `kind: "proof_selection"`
with exact fields `kind, network_base64, catalog_base64, seeds, epoch,
known_feature_id, now`; `seeds` is a nonempty array of exact objects
`{kind, body_base64}`. Success is exactly `{ok: true, catalog_base64}`. Failure
uses the existing `{ok: false, code}` shape, additionally `required_ids` only
for `proof_required`, with no partial output. This adapter is never a route.

Operation request, result-packet/payload and encrypted mailbox/frame aggregate
bounds are checked separately against the complete selected bytes before any
network or local authority mutation. A large unrelated full-network snapshot
must not force publishing that full snapshot; a genuinely oversized sufficient
closure fails atomically.

## Verification

The independent author derives black-box cases from these contracts and public
fixture signers without either implementation:

- Atomic schema migration/old-version refusal; cross-language opening of pending
  and committed state, exact packet/frame retries, no replacement identity/key.
- All Go/Rust creator/new/approver combinations; same owner/admin machine and
  separate roles; device B approves C with original person machine offline.
- Feature proposal/ack roster races/offline host/old host refusal, v1/v2 downgrade
  and omission protection, current root/role/expiry/revocation and exact high-water.
- No preview side effects, exact owner selection and distinct final consent,
  substituted offer/key/person/admin/refusal races; default-no and noninteractive
  exact-pin requirements, codes absent from argv/status/events/logs.
- Partial typed external-sign steps, persisted template immutability, wrong or
  arbitrary signatures, scopes/expiry/path narrowing, original seed absent on B/C.
- Restart/lost response at each barrier, unknown finalization, cancellation stages,
  committed retry after expiry/revocation, exactly-once local event/application.
- Same host/device renewal after expiry with usable original-root/unaffected
  ancestor and exact retained history; selected signer repair never key copying.
- Capacity/rate limits, full-u64 canonical INTEGER/BLOB round-trip and invalid
  encoding refusal with atomic prior-state preservation, terminal cleanup and
  tombstone retention, and coordinator restore.
- Existing explicit invite and capability/policy propagation regressions, all
  relevant shared language/CLI/peer suites and installed Linux bundle `up` checks.

Peer catalog POST authenticates the actual mTLS sender against the independently
verified prior local membership and all known restrictions before applying the
incoming historical union. A current sender may propagate its own valid removal;
that removal governs subsequent entry. Added grants in the incoming body cannot
supply the prior gate, and removal retains no subsequent GET/read authority.

Daemon automatic policy renewal and edit reapplication select the owned device
whenever a `link_signers` row exists. A broken selected row requires repair and
never falls back to an original key. Before signing, fresh sync verifies the
actual pin, current binding, owned seed and fixed typed intent. After signing,
verify the exact action again; cap policy expiry at the live path minimum and
choose checked retained maximum plus one. Reapplication rechecks its exact
stored policy and edit plan/reservation under the existing mutation transaction.
Catalog, projection, edit changes and delivery queue commit atomically. With no
selected row the existing original-person renewal provider remains available.

For a feature-active network with a selected device signer, daemon renewal
eligibility (the due fraction and remaining policy lifetime) uses the same
shared decision clock as the typed provider and signing checks. This includes
the explicitly enabled injected test clock; production uses normal UTC.
Legacy/original-provider scheduling is unchanged. This grants no extra renewal
authority and does not relax any current path, expiry or edit guard.

## Atomic capability claims with device providers

`POST /v1/capabilities` keeps its existing fields and `policies` array and gains
optional `catalogs: [{network_id, catalog}]` (omitted or empty for legacy).
A network occurs once across both arrays. Exactly one checked claim is supplied
for each network bound to the one selected original person, preserving existing
name-based claims; unsigned projections never enter `policies`. One transaction
revalidates every exact signed envelope, current path, local person/host/name
claim, current maxima/edit reservations and capability source/name. Capability,
all catalogs/projections, edit changes and delivery rows commit together; any
refusal stores none.

The explicit `link-actions` variant `policy_claim` takes `payload_base64` of
exactly `{capability, policy_base64}`. The latter is canonical Base64 of the exact
unsigned `peerspan-policy-v2` payload. Check scope 1, owned live device, current
binding, fresh actual-pin sync, exact current edit reservation and guarded
version before signing. The policy must claim that capability for this host and
must not claim the same name for another host. Sign only the fixed ordinary
person-record envelope; return the existing ar_/pf_/record/catalog result with
`committed: false`. Store/publish no policy or delivery. Atomic capability create
revalidates everything. CLI identical-name preflight signs nothing. Original-key
CLI supplies the existing signed policy; selected-device CLI supplies the checked
preparation's exact catalog. Existing stale create races remain rejected.

## Format-2 administrator withdrawal and exact retention plans

On an activated network, the existing daemon-root `POST
/v1/networks/{id}/admin-removals` `{person, revoke_admitted}` form creates the
accepted format-2 removal. The route additionally accepts exactly
`{removal_base64}`: canonical Base64 of the exact signed `admin_removal_v2`
object. This field is mutually exclusive with `person`, `revoke_admitted` and
legacy `removal`, including explicitly supplied empty/false values. Legacy
signed `removal` remains its existing explicit legacy statement; pre-feature
root generation remains legacy. The Base64 variant requires an active durable
feature and a signature by the current root before a new publication. A signed
root's exact kept list is its consent; the host never adds omitted entries.

`GET /v1/networks/{id}/admin-removal-plan?person=PERSON&format=2` returns exactly
`{format: 2, person_public_key, kept}`; without `format`, the legacy response
remains unchanged. Reject unknown/duplicate query parameters and other format
values. This is a verified read, with no signing, sync, publication or authority
claim. `BuildStoredAdminRemovalPlan(ctx, catalog, person)` / Rust equivalent
validates the complete stored source and returns the same sorted unique exact
kept tags: `legacy:` plus the actual signed legacy-message SHA-256, `record:`
plus the exact ordinary authorization AR, and `redemption:` plus the original
completed redemption PF. Resolve nested records through their exact original
bytes. Include target-administrator scope-8 records with verified usable
historical issuer evidence, active group candidates, and eligible completed
redemptions together with every actual signed invitation half. A legacy
signature recognized as a network-chain root remains root authority even when
that key also names the target person; it is not administrator-issued. Typed
person authorization retains its explicitly named person role. Existing
withdrawal exclusions, revocation, expiry without valid retention and inactive
access maxima cannot become eligible through planning. No checkpoint revives
an inactive policy/group.

A fresh withdrawal is verified against the independently held prior authority,
then its sticky local catalog/projection and existing revocation event commit
before network publication. Retain every old exact public object, feature and
high-water. A failed/unknown publication keeps those exact signed bytes for
resubmission; an identical generated retry reuses them, and `revoke_admitted`
may only escalate an existing plain withdrawal. An external signed conflict
cannot replace a retained same-kind withdrawal. Success retains the existing
`RevocationResult` response and route status. No role, device, policy or group
is reactivated by applying or retrying a withdrawal.

The stored-snapshot diagnostic adapter adds `kind: "admin_removal_plan"`, exact
fields `kind, network_base64, catalog_base64, epoch, known_feature_id, now,
person_public_key`. Success is exactly `{ok: true, kept}`; failures use the
existing code and exact missing-proof shape. This adapter performs no signing
or persistent mutation.

The plan's group entries come only from the highest selected active body for
that name; an inactive higher maximum suppresses every lower group tag. A full
source containing an ordinary admission whose expired issuer cannot be resolved
without its missing exact checkpoint fails the whole plan with the exact
required AR. Planning never discards unresolved authority to produce a partial
answer. A known inactive access candidate remains high-water and contributes no
group tag; that alone does not invalidate an otherwise complete snapshot.

## Active coordinator move bridge and exact retry intent

The existing `network move` and owner-local move routes retain their public
shape on activated networks. Moves retain their existing current-root or named
original-administrator signature shape. A selected device key cannot sign while
claiming the original person key: refuse that attempt with root/original-admin
signing guidance before signing, importing or mutating state. No new ordinary
record kind or implicit device-to-original authority is introduced.

Verify the complete durable projection, current move authority and guarded next
sequence before publication. Import the exact full public catalog including the
new signed move into the actual target pin via `/coord/v2/networks/import` with
exact `{network, catalog, feature_authorization: "-"}`. A target without the
feature requires the existing explicitly reviewed root feature-import workflow;
`network move` never manufactures or signs that recovery authorization. Verify
the returned target descriptor, durable feature and every exact submitted proof
before retaining the move locally. Publish to the old coordinator through
`/coord/v2/networks/{id}/moves` with exact `{move, catalog}` and a sufficient
verified dependency closure, then use existing authenticated peer propagation
and independently verified target sync. Only a verified live target map may
change the coordinator pin or freshness. Existing `MoveResult` fields remain;
v2 imports have no legacy added/skipped counters, represented as zero.

Before the first target import POST, retain one public-only intent per network
in `network_statements`, kind `pending_link_move`, empty subject. Its exact
format-1 record is `{format, source_network_base64, network_base64, feature_id,
move_base64, request_base64, submitted, result_map_base64}`. The first two fields
encode the exact source and target network descriptors; `request_base64` encodes
the immutable public import request, including its complete catalog. The move
must independently match that request and both network identities. No private
root, person, invite or device seed is retained. `result_map_base64` is `"-"`
until a verified response is retained. Enforce the fixed 1 MiB submitted request
limit before persistence/publication. The record is retained across restart.

A timeout, malformed reply or unknown outcome retries the exact signed move
and exact request bytes; it never re-signs at the same sequence. While that
intent still needs completion/following, the existing move-plan response returns
the exact pending `move` with `next_sequence` equal to its own sequence; the CLI
reuses those bytes when the requested target matches. A different
target or conflicting externally supplied move while that outcome is unknown
returns `operation_conflict`. An authenticated definitive non-commit response on the first submission
may retire the failed intent. A later refusal cannot disprove an earlier unknown
commit and never retires that uncertain intent. A retained newer local move with independently verified current authority makes
an older intent obsolete; a different move at the same sequence is a conflict.

A response to that exact persisted intent may be verified as its original
snapshot: require the actual target descriptor, durable feature, and every
submitted PF, independently verify the complete response, then union all current
local proofs and retained high-water before atomic local application. Preserve
newer hints, restrictions, pin and freshness. Retain the exact response and mark
the intent complete in that same transaction. This exception cannot relax any
generic live-map omission check. A later live target sync must independently
prove the complete current projection before changing the pin. Retrying a
complete intent may resume publication/following without regenerating a move;
a later different target starts a new intent at the guarded next sequence,
above every retained verified move sequence including currently inactive ones.
The existing legacy move signing API refuses sequence exhaustion rather than
overflowing its positive signed 64-bit sequence representation.

A successful mailbox GET records its decision-clock time for this host and
locator. A later resume with `now >= last` and elapsed time below two seconds
skips only the duplicate outbound GET and processes the already durable frames
and approved intentions. This creates no synthetic mailbox response or authority.
The first needed poll still performs an actual GET; remote 429 responses remain
visible. Both normal time and the injected test clock use this same rule.

The same successful-read rule applies when a repeated code-based owner or
administrator approval opens an already retained approver request. Reuse requires
the exact persisted approver role, code secret fingerprint, coordinator address
and coordinator public key, and an unexpired request. It skips only a redundant
mailbox GET; current-time projection, expected identity pins, signer selection and
the immutable reviewed intent still verify before any signature or publication.
An alternate issuer conflicting with an already reviewed intent remains
`409 state_conflict`. A first read, clock rewind, expired cache or failed GET
cannot supply this shortcut; a remote 429 remains visible.

## Owned root seed after an independently learned rotation

Applying a fully verified current root atomically retires an owned local root
seed whose derived public key no longer equals that root. Capture the durable
seed in the projection transaction, reject malformed private seed state without
partial mutation, and retain a seed that still matches the verified current
root. Retirement clears the obsolete seed and local root-provider flag together
with the public root/epoch projection; it neither changes the person's separately
verified administrator role nor removes public proofs, high-water or device keys.
A signed catalog never supplies a private root seed or restores a retired seed.

An exact accepted local rotation installs only its already persisted and verified
pending seed later in that same transaction, restoring the local provider flag
only when that accepted seed exists. A rejected pending seed never installs.
Independent competing-rotation checks distinguish retirement of the refused
pending transition from retirement of the obsolete prior owned root seed; a
normal following sync must learn the winning root with no obsolete root provider.

## Durable restrictive publication before active sync

An offline local-first restriction retains a public-only marker in existing
`network_statements`, kind `pending_link_restriction`, subject equal to its exact
PF, record exactly `{format: 1, proof_id}`. Write the marker in the same
transaction as the sticky exact catalog/projection, before publication. Every
marker must name an actual verified restrictive object in that network's
retained catalog. One marker per PF and the existing 4,096-object catalog limit
bound this bookkeeping; no private seed, duplicate catalog or request is saved.

Before pending rotation and ordinary strict active sync, load and verify the
complete current catalog and all pending PFs. Repair the actual current pinned
coordinator through the existing active-feature historical import route, exact
`{network, catalog, feature_authorization: "-"}`. No new root authorization,
feature adoption or first-use grant is generated. Use the full current catalog
when its request fits 1 MiB; otherwise use a verified sufficient closure seeded
by all exact pending restriction objects, enforcing the aggregate request bound
without truncation. An irreducible closure refuses with `quota_exceeded` and
keeps every marker and prior public object.

This repair has no immutable operation ID and returns a live current map. Its
request may be rebuilt from the current monotonic verified union on retry.
Clear markers only in the transaction that independently verifies the returned
live map retains every pending PF and the complete current projection. Unknown
failure, malformed response, missing proof, expired authority or transport loss
keeps the markers. No saved receipt can establish pin/freshness or relax live
map omission checks. An explicit identical restriction retry also retains its
exact signed bytes; successful verified publication may acknowledge its marker.

When a durable pending rotation exists, restriction repair verifies the full
live response and acknowledged PFs under the exact current pin, but its
transaction clears only acknowledged markers. It defers public root,
projection and freshness application to `completeLinkRotation`, preserving the
atomic seed/public-epoch/pending-retirement transition after a lost rotation
reply. Missing rotation proof keeps the marker and surfaces exact repair.


Typed restrictive actions use the same local-first publication transaction.
The exact registry is `device_revocation`, and `person_record` payload domains
`peerspan-person-remove-v1`, `peerspan-revoke-host-v1`,
`peerspan-revoke-invite-v1`, and `peerspan-host-unbind-v1`. Complete the existing
fresh sync, owned current signing path, unsigned intent, signed authority and
fresh-additions checks before applying the sticky union. Persist exact signed
catalog/projection and its `pending_link_restriction` marker atomically before
the first publication POST. Failed or uncertain publication returns the existing
structured error while retaining the restriction and marker; it returns no
success or `committed: false` signed-mutation result. HTTP 200 with
`committed: true` still requires verified live acknowledgement. Nonrestrictive
actions keep their existing publication order; `policy_claim` preparation stays
nonpersisting and creates no marker.

A persisted but unpublished approver frame is still a new publication. Resume
first refreshes the exact pinned network and revalidates its approved owner or
administrator issuer path, role, epoch, LF and request lifetime before replaying
those exact bytes. Completed signatures and frames are never regenerated.
An explicit resume of an unpublished administrator frame after independently
verified current-role loss returns `403 forbidden`. Retain the exact approved
intent and frame with `published: false` and `sequence: 0`; a worker may keep
repair attention, but no new signature or administrator frame is published.
Existing expired-request terminal cleanup and `410 expired` remain separate.

When no durable root rotation is pending, a remote restriction-repair transport
or HTTP failure may fall through to the existing independently verified move
and successor following path while retaining every marker. Local malformed
marker, catalog or authority-path errors remain hard failures. Before strict
sync at an actual candidate target, repair all pending restrictions there using
the same exact signed closure and 1 MiB request bound. Only the final chosen live
map that independently proves the complete current local catalog and all marker
PFs may atomically clear those markers and apply pin/freshness, subject to the
existing current move and successor checks. A pending root rotation instead
keeps the exact repair refusal and directs the owner to resume that rotation;
no transport fallback may split its seed/public-epoch transition.

Verified active-map projection preserves the existing external-root signature
format hint. Derive `root_ssh: true` only from independently verified SSHSIG
statements signed by the exact current root: current-epoch attestations, direct
administrator delegations, person/host admissions, feature proposals, and root
records (including an exact root admission inside a completed activation), or
an active selected legacy group signed by that root. Preserve an existing true
hint only while both the root epoch and current public key remain identical.
Historical roots, ordinary person/device records and unsigned hints cannot set
it. This affects the exposed root signing format only and supplies no root seed,
provider selection, role or signing authority.

## Conformance fault after accepted rotation

If a durable pending root rotation completes and the subsequent ordinary sync
fails in the same operation, recording that failure must preserve the newly
committed public epoch/root, matching root seed, complete projection and cleared
pending rotation. Failure metadata cannot restore a network view loaded before
the accepted transition.

A conformance-only TLS stand-in may reuse its own disposable coordinator's
identity, discovered without private column assumptions by deriving and matching
the CLI-reported public key from candidate 32-byte seeds. It forwards the exact
signed proof bytes and normalizes only the unsigned outer map descriptor to its
actual pinned listening address. After successfully forwarding the rotation
mutation and its verified map, it returns 503 to subsequent ordinary syncs.
This models a transport failure after acceptance without adding a protocol route
or runtime hook. It supplies no root/person authority or private-key transfer to
another machine. The check must observe the accepted epoch/seed transition and
the later sync error, then verify ordinary recovery without duplicate application.

Interactive guided setup re-reads the exact durable request after resuming a
pending machine link and proceeds only when its public state is `linked`.
Declining either owner-selection or final-commit consent, or returning while
the same request is incomplete, stops before ordinary create/join or agent
attachment. A successfully printed incomplete `link resume` view is not setup
completion and cannot trigger generation of a replacement person. Independent
installed verification covers both default-no consent exits while preserving
the request, identity and existing service.

The two requester consent prompts contain the exact questions
`Select this exact owner offer?` and `Commit this exact machine link?`, followed
by the literal default-no marker `y/N` enclosed in square brackets or
parentheses. A blank line declines; only `y` or `yes`, ignoring ASCII case and
surrounding whitespace, approves. Independent PTY checks identify the relevant
question and marker before sending a blank answer; they do not infer consent
from timeout or from another guided-setup prompt.

With no local network and no explicit create/join input, interactive `up` offers
`Create a network, link this machine, or join with an invite (create/link/join)`.
Choosing `link` creates exactly one new request through the existing local API
with mode `new`, absent network/person pins `-`, and the supplied coordinator
pair or its existing build default. It runs the same guided selection and final
consent, then re-reads that exact request. Only `linked` proceeds using the
installed network and selected device; incomplete/declined linking retains the
request and resume guidance and stops before ordinary create/join, person-key
generation or attachment. Missing coordinator configuration remains an
actionable error, and no noninteractive choice is inferred. Installed checks
cover the fresh interactive `link` choice as well as existing pending resume.

Automatic `up` resume of an existing pending request suppresses its private
display code before output, including interactive resume. Explicit `link` or
`link resume` keeps the documented code display. Choosing fresh interactive
`up` → `link` explicitly starts the ceremony and may display that new one-time
code on the terminal. Guided output controls this at the display point; it does
not print then filter or redact a code.

## Device-aware policy renewal attention

Status checks a selected device policy renewer using the same read transaction
and fully verified projection as the selected policy. Require the actual owned
seed, exact selected network/person/certificate/device, current host binding,
durable feature/root/path, policy scope `1`, and current decision-time expiry
and restrictions through the existing device-provider eligibility check. This
read performs no remote I/O, signing, fresh sync, new transaction, lease renewal
or persistent mutation. A selected row alone never establishes eligibility.

A valid selected provider produces no `person_agent_unreachable` item. An
ineligible selected provider never falls back to the original SSH signer and
instead uses the existing four-field attention object exactly:

- `kind`: `person_device_signer_unavailable`;
- `subject`: the exact network ID;
- `detail`: a public string starting `selected device cannot renew this person's
  access policy: CODE: MESSAGE`, where `CODE` and `MESSAGE` are the actual
  structured failure code and public message;
- `command`: `peerspan network sync NETWORK_ID`.

This new kind sorts immediately after `person_agent_unreachable`. It adds no
status object fields or authority claim. Invalid complete projection keeps the
existing fail-closed status response. With no selected row, original-provider
attention remains unchanged. Selected-device policy-expiry attention must not
recommend ssh-agent or obtaining the original person private key.

Only for `authority_expired`, an additional detail may suggest
`peerspan link --renew --network NETWORK_ID` after syncing when the complete
verified facts still establish this same owned target certificate's activation,
current person/host membership and binding, and an unrevoked target device.
Explain that another currently authorized machine must approve; do not promise
renewal success. Missing/corrupt seed, missing proof, other restrictions or
insufficient policy scope receive only sync/repair guidance.

### Verification

At the same installed renewal/reuse points, a valid selected policy provider
with no original private key or ssh-agent has neither original-agent nor
selected-device failure attention, and status changes no catalog, high-water,
selection, pending intent or private credential. One bounded native case per
implementation selects a cryptographically valid owned device path without
policy scope `1`: status reports the exact device-repair kind/network and
`forbidden` code, with the sync command and no original-key fallback, signing,
publication or state mutation. Existing no-selection original-provider attention
and complete-projection refusal retain their prior behavior.

The bounded insufficient-scope fixture may independently sign a complete valid
scope-2 activation with its own fixture keys/public packet helpers and import
that historical public catalog through the authenticated route. While its
fixture host is stopped, change only the documented selected certificate ID to
that exact valid certificate for the same already owned device, host and person.
The public `link-signer` read must first verify scope `2`; status must then refuse
policy-renewer eligibility with the pinned `forbidden` attention. This adds no
narrow-scope production issuance API, raw-row authority or verifier exception.

Selected-provider status eligibility is independent of an active policy body.
For the host's currently verified person binding, evaluate its retained selected
provider even when expiry or revocation has removed that provider's policy from
the active projection. Derive the expected stable person from the verified
binding, never an inactive policy or an unverified selection row. The same
`authority_expired` or `device_revoked` repair attention remains visible, with no
original-signer fallback. This neither renders an inactive policy as active nor
restores its permission or a lower body. Independent verification extends the
bounded status case through selected-path expiry/revocation and checks inactive
policy denial together with the exact device-repair attention and unchanged
retained selection/high-water.
