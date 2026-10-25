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
CLI-side. Every explicit original-person selection must match the bound stable
person; failure to find a live device returns repair, never creates a new person.
Pick the shortest usable renewal issuer path, then certificate ID, unless the
user selected an exact issuer.

## Typed device management actions

`POST /v1/networks/{id}/link-actions` is private local administration, with
exact request `{kind, payload_base64, certificate_id}`. `kind` is exactly one
ordinary person-record kind in the accepted payload registry, or the explicit
`device_revocation` variant below. Decode strict
unsigned typed payload bytes; reject unknown kinds, fields, arbitrary messages
and signature injection. `certificate_id: "auto"` resolves the current selected
local device; an exact `dc_` requires its locally owned seed, same original
person and fully usable exact path. Never silently replace the bound identity.
Fresh pinned sync and current authority/preconditions are rechecked under the
network lock before signing/publication. Verify scopes, role, expiry and
self-invalidating delegated changes with the reusable action verifier.

Response is exactly `{record_id, proof_id, record_base64, catalog, committed}`.
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
transaction section 7. A preview signs/publishes nothing; approval requires exact
reviewed network/person/host/device pins. `auto` resolves once to a concrete
issuer before consent. Persist fixed scopes, issuance/expiry, dependency bytes
and signing templates. External signing requests expose only the next typed
message that is ready; submission verifies a signature over those persisted
bytes. No timestamp, role, subject or selected path changes between steps.

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

Host barriers use the runtime foundation's opt-in environment controls:
`host.request.after_commit`, `host.frame.after_commit`,
`host.selection.after_commit`, `host.finalize.after_commit`,
`host.result.after_commit`. They occur after durable commit and before display,
publish/submission or response. They contain only public request IDs. Both
implementations honor the same barriers and test clock; production uses UTC.

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
