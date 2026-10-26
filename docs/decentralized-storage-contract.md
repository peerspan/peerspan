# Decentralized durable state and schema 23

Status: DEC-01/02/03/05 shared contract candidate,
2026-10-26, against main `6d3823fd3115fff247b1af8551553baf30e97f0f`.
Read with the authority, bootstrap, migration, runtime and verification
contracts. This document fixes shared durable representations needed for Go
and Rust to reopen the same state and resume exact operations. It does not
prescribe module layout, in-memory caches or public API response shapes.
Runtime implementation and independent executable cases begin only after the
complete contract set is reviewed and merged, as fixed by the umbrella contract.

## 1. Additive migration and existing data

Merged remote MCP/OAuth PR86 (`ec1052fa71b83f24921fdf70dfc7468cdd488ea4`)
allocated schema22. DEC therefore uses schema23. The earlier DEC22 allocation
was an unmerged experimental storage slice, superseded before release; its
retained test receipts describe those exact older artifacts only.

Schema23 adds exactly the seventeen DEC tables below in the host's SQLite
migration transaction and sets `PRAGMA user_version = 23` only there. Keep
all schema21 and schema22 tables, columns, records and keys, including remote
MCP definitions, OAuth sign-in/credential state, source snapshots and configured
headers. Opening a database performs
no protocol migration, automatic enrollment, lease renewal or original-key
import. A failed migration rolls back; a version above 23 is refused before
changing any table, identity, file or service. Existing private-directory,
process-lock, foreign-key, busy-timeout and synchronous durability rules remain.

In particular preserve identity, peers/manual grants, received/outbound work,
networks and legacy statements, all link_* history, policies/edits/deliveries,
agents/sessions/attachments/adapter credentials, tasks/artifacts/sources,
capabilities, schema20 per-call approvals, schema21 resource/gh data and
schema22 remote MCP/OAuth state. An explicit network cutover preserves those
same product facts; database opening itself never initiates that cutover.
Existing schema21/22 network JSON is not rewritten just to add a mode field.
The older binary rejects schema 23 rather than interpreting DEC state as
coordinator-based state. Neither expiry nor a transport error lowers the mode.

A legitimate schema21 database runs the existing OAuth22 migration and the
additive DEC23 migration in the same opening transaction; a failure preserves
its original version21 and state. A legitimate OAuth22 database adds only the
DEC23 migration; failure preserves version22 and its exact existing state.
The [opt-in late-DDL failure control](decentralized-verification-contract.md#schema-migration-rollback-control)
verifies the actual opening transaction's rollback after both migrations have
run; preflight refusal alone is not that evidence.
Fresh databases run the preceding normal migrations too. The seventeen DEC
names are reserved: a pre23 database containing any of them is refused before
migration changes. Never reinterpret an experimental DEC22 database as OAuth22,
drop its tables, change its version to disguise its history, or use a missing
OAuth table as permission to repair another schema22 meaning.

Selected: advance DEC to the next free version and preserve the independently
merged OAuth migration. Discarded: sharing version22 for two layouts, renumbering
the merged OAuth feature, deleting its state, or silently upgrading unshipped
experimental DEC22 fixtures. Earlier valid test receipts stay historical;
current acceptance adds genuine OAuth22-to23 opening and refusal evidence.

The existing SQL table is already
`networks(id TEXT PRIMARY KEY, record TEXT NOT NULL, root_seed BLOB)`.
Coordinator fields are inside legacy JSON, not SQL NOT NULL columns. Keep that
table and use an explicit new tagged record; do not manufacture empty/fake
coordinator addresses, keys, last-sync timestamps or legacy memberships.

## 2. Shared scalar and JSON conventions

All table/column names and primary keys below are normative. Additional indexes
or nonauthoritative caches are implementation choices. Text identity comparisons
use exact UTF-8 bytes/SQLite BINARY collation, without case folding or trimming.
Existing label conflict rules remain separate from key identity.

New private `record` values are strict format-1 JSON unless a tagged format-2
record is specified below. Reject missing/unknown fields, duplicates, null,
invalid UTF-8, float/negative/out-of-range integer aliases and wrong types.
Arrays are always present, including empty arrays. An absent public ID, exact
byte string or optional reference is literal `"-"`; optional typed values are
`"-"` or the specified strict object. Never use JSON null. SQL NULL is allowed
only for the explicitly nullable secret columns and existing legacy columns.
Readers do not silently default or repair corrupt records.

The existing `policy_edits.record` has the strict tagged DEC variant specified
in the [policy edit supplement](decentralized-policy-edit-contract.md).
Its exact original proof references preserve legacy rows and do not add SQL
tables or manufacture a legacy signed policy.

Private outer JSON object-key order is not an identity or authorization input;
compact sorted-key output is recommended. Every Base64 field containing public
proofs, packets, templates, reviews or signed source snapshots preserves the
**exact original decoded bytes**, regardless of outer private serialization.
Numbers are parsed/stored as integers, never via float64. Status/read-only
reopening does not rewrite a record to normalize it. New stored JSON has a
fixed 32 MiB parser cap; every nested object/catalog retains its own protocol
cap. A pending selected catalog can be up to16MiB decoded JSON (about21.3MiB
in its private Base64 field); packet/intent/reference overhead must still fit
the same32MiB whole private record. Exceeding any independent cap is a refusal,
never truncation. Do not silently lower an otherwise valid object's limit to
make a transport wrapper fit.

The shared transport budgets are separate from this private parser cap:

| Boundary | Fixed ceiling |
| --- | --- |
| Selected bootstrap proof catalog |16MiB exact catalog JSON |
| Each catalog-only frame component |2MiB exact catalog JSON; split only between complete exact public objects |
| Frame plaintext / submitted frame POST body |4MiB /8MiB |
| Decoded sealed ciphertext per mailbox/local request |32MiB |
| Mailbox GET response / global stored mailbox ciphertext / aggregate queued response bytes |48MiB /256MiB /64MiB |
| Complete activation publication, ordinary full-catalog exchange and proof-repair body/response |20MiB whole envelope, with the inner catalog's16MiB bound unchanged |
| Owner-local v2 response containing typed ready templates |32MiB, with at most16 ready slots per batch |

Object/activation limits stay unchanged: do not fragment one exact signed
object, reserialize it to synthesize pieces, add new cryptography or invent a
partial activation protocol. Packing a maximum-size packet with a maximum-size
catalog component can exceed the frame cap; emit separate valid frames rather
than raising the cap or omitting dependencies. Exact sealed frames remain
portable between carriers and all aggregate limits apply independently.

### Full-u64 SQLite values

A column marked U64 has declared SQLite INTEGER affinity, but these exact
storage classes/encodings:

- Values 0 through 2^63-1: nonnegative SQLite INTEGER.
- Values 2^63 through 2^64-1: SQLite BLOB of exactly eight unsigned big-endian
  bytes, with the high bit set.

Reject REAL, TEXT, negative INTEGER, wrong-length BLOB or a low-half BLOB.
A positive stream version additionally rejects zero; root epoch and counters
may use zero only where their contracts allow it. Compare/increment in the
application as u64, never SQL MAX, CAST, numeric coercion or signed overflow.
JSON values must equal corresponding U64 columns. Max-u64 remains observable;
required fresh increment refuses `version_exhausted` before signing/reservation.

For a stream key, use three exact columns `stream_kind,subject,subject2`:

| Public stream tuple | stream_kind | subject | subject2 |
| --- | --- | --- | --- |
| root | root | `-` | `-` |
| [admin,PERSON], [person,PERSON], [host,HOST], [binding,HOST], [policy,PERSON], [group,NAME] | first component | second component | `-` |
| [device,PERSON,DEVICE] | device | PERSON | DEVICE |

No concatenated delimiter parsing or signed-message-hash winner is used. The
public verifier's stream tuple is reconstructed exactly from these columns.

## 3. Network record, context pin and verified member cache

For a DEC network, `networks.record` is exactly:

```text
{format:2,mode:"decentralized",descriptor_base64,context_id,
 root_state_id,own_identity:{member,person_public_key,host_public_key},created_at}
```

Its id column equals the descriptor network ID. The descriptor has the exact
new protocol and no transport fields. `created_at` is the local new-context
creation/adoption time, not a claim of a remote historical creation time.
`root_state_id` is the unique verified current root head or `"-"` when a known
root/origin dispute prevents selection; it is a cache, never a competing root
pin. Every authority read recomputes/checks all admitted root heads, restrictions
and clock. A stale cached root cannot choose a branch or revive positive paths.
Do not cache coordinator readiness in this record.

own_identity is the last independently verified local member/person/host tuple,
retained for display and same-identity repair even after expiry, unbind, removal
or a fork. Its host key equals this store's identity; an originally unbound host
uses person_public_key `-`. This historical cache is never authority and cannot
supply a missing grant or choose a branch. Only an explicit valid owner rebind/
selection can replace the remembered person/provider; an independently valid
same-owner membership label update may refresh member. An old outcome retry or
expired current projection cannot erase/replace this tuple. If its supporting
body is missing, display the remembered identity with exact repair state and
grant no authority through it.

`root_seed` retains its existing owned 32-byte seed-or-SQL-NULL representation.
Validate its actual length and derived public key before provider use. On
application of a fully verified unique current root, clear an obsolete owned
seed in the same transaction. An exact accepted local rotation installs its
accepted pending seed later in that same transaction. A root fork has no chosen
replacement: retain the seed as private recovery material but expose no usable
root provider until the dispute is resolved. No seed means no inferred owned
root; an external SSH key is never imported into this column.

```sql
CREATE TABLE dec_contexts (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id)
);
```

Context record is exactly:

```text
{format:1,descriptor_base64,origin:"genesis"|"migration",
 initial_root_state_id,origin_proof_id,migration_proposal_id,adopted_at}
```

For genesis, origin_proof_id is the exact genesis root-state dp_ and proposal
is `-`; for migration it is the complete migration dp_ and exact proposal ds_.
The descriptor/origin/adoption pins never silently change. Preserve conflicting
complete root origins as evidence; do not replace the first pin to select a
winner. No ordinary public proof inserts local adoption consent. Staged,
unadopted contexts live only in pending/migration records, not this active pin.
Leave/expiry does not delete remembered context/restriction history or permit a
legacy rejoin. Whole-state loss has the authority contract's stated limits.

Existing `network_members` may contain this tagged derived DEC record:

```text
{format:2,mode:"decentralized",host_public_key,member,person_public_key,
 host_lease_id,person_lease_id,binding_lease_id,activation_id}
```

Its host_id column is the existing host ID derived from host_public_key. Unbound
person/binding fields are `-`; ordinary host authority can have activation_id
`-`. This record supplies no signature or admission by itself. It is a derived
cache for existing product lookup, rebuilt atomically from verified facts; a
read must still evaluate current deadlines/restrictions/forks. Contacts are
separate hints, never part of membership authority. No unsigned DEC projection
is propagated as a legacy signed statement.

## 4. Exact public proofs and local admission provenance

```sql
CREATE TABLE dec_objects (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, proof_id TEXT NOT NULL,
 kind TEXT NOT NULL, body BLOB NOT NULL,
 PRIMARY KEY(network_id, context_id, proof_id)
);
CREATE TABLE dec_admissions (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, statement_id TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, statement_id)
);
CREATE TABLE dec_restrictions (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, restriction_id TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, restriction_id)
);
CREATE TABLE dec_activations (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, activation_id TEXT NOT NULL,
 request_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, activation_id)
);
```

Objects preserve exact original UTF-8 public bodies as BLOB, including all valid
same-ds_ aliases. Recompute exact kind/context/dp_ before insertion; same primary
key with different bytes is corruption/conflict, never an upsert replacement.
Composite activation/migration and nested dependency rules follow their public
contracts; no reserialization invents standalone dp_ evidence. Existing legacy
bytes remain in their old tables/context. Unknown-context or incomplete drafts
are bounded untrusted repair/pending material, not admitted dec_objects merely
because a helper delivered them.

An ordinary root/lease/access admission record is exactly:

```text
{format:1,kind,proof_id,admitted_at,
 basis:{kind:"current"|"retention"|"migration",evidence_ids:[ID]}}
```

A restriction record has the same fields, with basis.kind one of `current`,
`ratification`, `migration`, and its id column the exact restriction ds_. The
kind and target come from the exact signed object, not an unsigned effect
cache. Ratification evidence includes exact old/new statement/proof references.
Activation admission record is exactly:

```text
{format:1,proof_id,manifest_id,admitted_at,
 basis:{kind:"current"|"retention"|"migration",evidence_ids:[ID]}}
```

The activation record preserves verified complete-consent provenance. It does
not admit all nested statements or prove their current usability. Each such
statement has its own independently established admission basis; an expired
previously unadmitted target D acquires no admission/head/maximum from this
record. Its independently live P/H/B may be admitted under the bootstrap
contract's exact complete-activation dependency rule. No activation record
alone establishes a selected signer, participant outcome or past global commit.

Arrays are sorted unique exact dependency/retention/migration IDs. The admitted
statement must retain a complete valid proof alias. An ordinary ds_ reference
may resolve through another complete alias with exactly the same ds_; an
explicit dp_ reference in a frozen manifest/source snapshot requires its exact
original body and cannot be repaired by a different envelope alias. admitted_at is a
**local** decision time, not a transferable receipt or evidence of remote
signing time. On later read, validate structural provenance/signatures/consent;
expiry can make a legitimate admitted object inactive without erasing its
history, head or high-water. A private marker never excuses a forged object,
missing consent or missing ancestor. Missing a selected body preserves the
known head/maximum and yields repair for that domain, never lower fallback.

For a statement supplied by an exact retained activation or migration container,
the admission record's proof_id names that complete top-level container dp_,
whose original body is in dec_objects. A standalone statement instead names its
own stored complete alias dp_. Reopening must verify that the named container
actually supplies this exact admitted ds_ and its original complete nested
signatures, required consent and dependency closure. Merely pointing at any
valid container is insufficient. A derived nested-statement dp_ that is not an
actual standalone catalog object is not a stored source proof. Do not fabricate
a standalone dec_objects row by reserialization. Manifest-pinned standalone
binding/device proofs still require their exact original catalog bodies.
Selected: retained original container provenance for exact nested statements.
Discarded: virtual standalone proof rows or treating a container marker as
admission/current authority for every nested statement. The statement's typed
admission basis and current eligibility remain independently required.

A candidate network catalog cannot set these rows, admitted_at, heads, maxima,
clock or context pins. Only the local verifier's admission transaction may do
so after the current/retention/migration rules. The caller reconstructs the
private PRIOR snapshot from these rows, admitted activation IDs, heads/maxima
and exact objects; no peer-supplied JSON becomes trusted prior metadata. An
unseen expired delegate's backdated max-u64 grant or deny remains inert repair
material until the normal current authorization/ratification rule succeeds.
Previously admitted restrictions remain sticky after issuer loss/expiry.

## 5. Stream heads and monotonic maxima

```sql
CREATE TABLE dec_heads (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
 subject TEXT NOT NULL, subject2 TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2)
);
CREATE TABLE dec_highwater (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
 subject TEXT NOT NULL, subject2 TEXT NOT NULL, version INTEGER NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2)
);
```

Head record is exactly `{format:1,head_ids:[DS]}`, sorted unique maximal admitted
heads after normal predecessor/resolution processing. Multiple incomparable
heads are retained, never selected by hash or greater sequence. Scope/expiry
or current restrictions do not delete heads. Root uses the same root-key tuple;
all root heads remain represented when the network record has root_state_id `-`.

High-water record is exactly
`{format:1,statement_ids:[DS],floor_proof_ids:[DP]}`. Its U64 version column is
the maximum **admitted** sequence/epoch, not a candidate signature's number.
statement_ids lists the admitted statements at that maximum. A signed migration
floor may have no new-context statement ID; floor_proof_ids contains the exact
complete migration proof authenticating it. Ordinary new networks have no
inherited floor. Preserve root epoch0 and positive lease/access distinctions.
High-water never supplies an active body, resolves a fork or forgives expiry.

Objects, admission provenance, heads and maxima commit together. Recompute/check
the required graph against one immutable snapshot. A stale/corrupt cache fails
closed for that domain; it cannot replace exact signed evidence. Repair can
supply missing exact bodies without lowering retained maxima. A fork or missing
Alice policy does not block a separately complete Bob/root restriction closure.
Forged/malformed submitted bodies still fail their ingestion; they are not a
legitimate fork or proof-repair exception.

## 6. Owned devices, selected provider and local clock

Reuse existing `link_device_keys(public_key,seed,created_at)` for exact owned
32-byte device seeds. The table name does not make a DEC key a legacy grant.
Validate the derived public key on every load; never silently substitute a new
key, another person or an original-key provider after a selected-device error.

```sql
CREATE TABLE dec_signers (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, provider_kind TEXT NOT NULL,
 person_key TEXT NOT NULL, device_key TEXT NOT NULL, lease_id TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id)
);
CREATE TABLE dec_clock (
 network_id TEXT PRIMARY KEY, record TEXT NOT NULL
);
```

provider_kind is exactly `original` or `device`. An original row explicitly
selects person_key; device_key and lease_id are `-`. Derive its current person
lease from the verified stream, so ordinary person-lease renewal does not
silently require a new original-provider selection. A device row pins the
owned key and exact selected ds_ lease for that same person/host/context; it is
not authority without the full current verified path. Reject mixed variants.
No root auto-provider is represented here: root signing remains explicit.

Initial original-provider creation inserts its explicit original row atomically.
A successful new requester's application selects its exact matching device
atomically. No row means **no selected provider**, never implicit original
fallback merely because a device row is absent. A present invalid device stays
selected with structured repair; no newly generated key, other person or
original provider replaces it. An explicit ad-hoc original/root signer choice
for one action does not itself change the persistent owner provider. Changes
require the runtime's explicit valid rebind/selection consent. Preserve the
remembered selected person through expiry/withdrawal and old outcome retries;
actual current path/private-provider checks remain mandatory. Legacy
link_signers rows remain history, never a DEC fallback.

Clock record is exactly
`{format:1,largest_local_time:"YYYY-MM-DDTHH:MM:SSZ"}`. One network-level row
survives context migration; do not replace it with a context-scoped reset.
Use actual local time and the maximum local anchor under the authority contract.
No peer/helper/object timestamp advances it. Status/doctor/read-only results do
not write it. Before signature and final apply, recheck the latest guard and
authority from one coherent snapshot. Only the explicitly allowed monotonic
clock write may survive a later refused authority operation; no other table,
provider, consent, reservation, event or delivery changes under that exception.

## 7. Typed private signing intentions

```sql
CREATE TABLE dec_intents (
 intent_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL,
 kind TEXT NOT NULL, record TEXT NOT NULL, secret BLOB
);
```

intent_id is a fresh local random128-bit lowercase hex value prefixed `dint_`;
it is an owner-local lookup/idempotency key, not a public authority ID. Unknown
network/context are `-` until explicitly resolved once. kind is one of
`owner`, `administrator`, `create`, `action`, `policy_claim`, `root_transition`,
`migration`, `migration_identity`, `selection`, `requester_commit`. A policy_claim is the runtime's prepare-only capability claim:
reopening/resuming its signatures cannot change it into an applying ordinary
action. Only the separate atomic capability-create transaction may admit its
candidate policy and associated capability/edit/delivery changes.
A request's owner/administrator fields below reference this table instead of
embedding another independently mutable copy.

The exact record is:

```text
{format:1,operation_id,approved,approved_at,review_base64,provider,
 root_state_id,person_public_key,host_public_key,device_public_key,
 scopes,not_after,created_at,expires_at,
 templates:[{slot_id,object_type,template_base64}],
 signatures:[{slot_id,role,signature}],completed,terminal,result_base64}
```

provider is exactly
`{kind:"original"|"device"|"root"|"requester"|"host",signer_public_key,signature_format,lease_id}`;
lease_id is the exact selected device ds_ or `-` for the other kinds. This is a
PRIVATE provider selector, not the runtime public provider summary. Review is
the exact nonsecret typed owner-local review from the runtime contract. Unknown
not-yet-resolved IDs/template bytes/signatures are `-`. Templates and signature
slots are ordered by dependency order. Template slot_ids are consecutive
positive u64 starting at1; signature entries are unique by slot_id/role and
ordered by slot_id then role. This permits several same-kind migration leases
without ambiguous object_type lookup. A filled signature/template never changes.
completed means all required typed signatures are durably fixed, not published
or globally applied. terminal is `-`, applied, cancelled or expired.

The private requester provider is allowed ONLY for selection/requester_commit
intents. It pins the pending request's exact locally owned device public key,
signature_format ed25519 and lease_id `-`; its host key must also equal this
store's identity. Validate its owned seed and exact pending request, role,
context/person/owner and selected terms before every signature. It establishes
no current device authority, membership, provider selection or reusable signer.
Never store requester in dec_signers or accept it for another intent kind.
Requester intent secret is SQL NULL. Only actual owned host/device keys fill
their fixed roles; these intents expose no external or arbitrary-message slots.

The private `host` selector is allowed ONLY for `migration_identity`. It is
exactly this store's host key, ed25519 and lease_id `-`. This intent has NO
signature templates or signature slots; the selector grants no signing power
and is forbidden in dec_signers and all other intent kinds. It records only the
owner-approved local roster contribution before a signed proposal exists.
Its network_id is the exact existing legacy network; context_id, operation_id
and root_state_id stay `-`, never a fabricated future proposal/root. Its
person/host/device/scopes equal the reviewed own roster entry. Review is the
runtime's exact identity-stage review, with proposal/new-context/prepared hash
`-`; its source hashes describe the reviewed source snapshot, not an adoption
pin or permission to trust a later proposal.

There is at most one nonterminal migration_identity intent per legacy network
and local host. Preview creates no intent or key. Approval atomically persists
approved=true, actual approved_at, the exact tuple/review and, ONLY when this
bound host has no prior device, one freshly generated32-byte device seed in
secret. Validate that seed against device_public_key. An existing device uses
its existing protected owned key; secret stays NULL. An unbound host has
person/device `-`, scopes0 and secret NULL. No original-person or host private
key is copied into this record. Its templates/signatures are empty and
completed=true: there are no signatures to produce, not an applied migration.
terminal stays `-`, result_base64 is `-`, not_after is `-`; created_at and the
fixed expires_at=created_at+300s record the initial review boundary. This
nonsigning tuple does not expire into permission to generate a replacement
key. Repeated approval of the same tuple returns the same intent/seed and
approved_at, including after that boundary; changed identity/scopes or a
different pending contribution returns operation_conflict. Current source
verification and separate proposal review/acknowledgment remain mandatory.

The exact locally approved proposal references this contribution through its
own roster and the staged pending request, without changing the identity
intent's unresolved context/operation fields. The original seed has one
protected durable home. For a staged local requester only, look up the unique
approved migration_identity intent by exact legacy network/local host and
require equality of its member/person/device/scopes with that proposal's own
roster entry and the pending request's keys. Zero matching rows, multiple
nonterminal rows or a mismatching tuple refuses; no mutable latest-intent
selection or seed fallback. No extra dec_pending field is required. Approval, linking,
restart, expiry and partial failure never regenerate/copy it. Whole-migration
adoption atomically moves that seed into its normal owned-device home, retires
the pending copy and marks this identity intent terminal applied; this grants
no expired positive authority. Preserve the unresolved approved intent/key if
any step fails. This is a new typed use of existing schema23 dec_intents;
there is no DDL change or fake dec_migrations row before a real proposal ds_.

result_base64 is `-` except an applied create, action or root_transition intent,
where it is canonical Base64 of that exact original successful runtime response
wrapper, fixed atomically with the local application. Decode and validate the
kind's exact response shape and agreement with the fixed operation ID, review,
typed signed objects and committed=true. Retain its original bytes; retries do
not reconstruct it from mutable network/provider/catalog/delivery state. It is
a historical response, not a current authority assertion. Other intent kinds,
including prepare-only policy_claim, cannot use this field to fabricate an
applied action, participant outcome or migration adoption. The independent
32MiB whole private-record limit still applies before committing anything.
Selected: explicit exact completed-response storage in the existing intent.
Discarded: changing a completed response by reconstructing current summaries,
or inserting non-link outcomes into the participant-only dec_operations table.

approved_at is `-` before approval, then the actual guarded local review time.
An explicit permitted re-review may advance it for the same unchanged intent;
GET, resume and signature submission never do. An exact repeated approval
inside its still-valid window preserves the original approved_at.
expires_at is the exact hard request/migration window, or the fixed initial
created_at+300s review boundary for an ordinary typed create/action/root preview.
No review extends a signed request/migration window, finite proof deadline or
the ordinary action/root pure-verifier300s signing window.

For an incomplete nonterminal CREATE only, explicit same-pin re-review through
the runtime approve route can renew the local signing approval window: actual
decision_time-approved_at must be0..300s inclusive before each new signature.
Its original created_at/expires_at, operation/context/root/person/host identity,
secret, templates and existing signatures remain exact; expires_at is not
rewritten to conceal the initial review boundary. Expired approval requires
review_required until that explicit consent, with no signature or application.
Already completed=true means all required signatures are durably fixed. An
unsigned-preview age limit cannot by itself reject application of those exact
signed proofs; all current proof, identity, consent and final-transaction checks
still apply. Applied historical responses retain their separate immutable retry
rules. No terminal intent is resurrected or collected by a review refresh.

Exact object_type values are `selection_packet`, `commit_packet`, `owner_offer_packet`, `admin_lease`, `person_lease`, `host_lease`,
`binding_lease`, `device_lease`, `administrator_packet`,
`owner_finalization_packet`, `root_state`, `policy`, `group`, `admin_withdraw`,
`person_remove`, `host_revoke`, `host_unbind`, `device_revoke`,
`migration_proposal`, `migration_ack`, `migration_commit`. The operation kind
and fixed review constrain the allowed subset/order/subjects, not a caller's
arbitrary list. Each template
must decode to that exact typed object with only its declared unsigned signature
positions `-`; derive its signing message from the template on every use.
Never persist a generic arbitrary-message slot that the daemon will sign.
A dependency-blocked template is `-` until exact verified dependencies are
available, then is fixed once. Current path/clock/consent is rechecked before
each signature/publication; later dependency arrival creates no new approval
or alternate provider. Same-review admin intent obeys the runtime authority
and consent rule, not merely co-location of owner/admin rows.
selection permits only its exact selection_packet. requester_commit permits
the exact new binding host-role template when needed and its commit_packet;
an unchanged complete binding creates no new binding signature slot. Host and
device packet roles bind the existing bootstrap message, with no new codec.

Original private keys are never persisted. secret is SQL NULL except the
nonsigning migration_identity device-seed case above, or a
create/root_transition intent may hold the exact locally generated pending
root32-byte seed; validate its key against the fixed genesis/new-root template.
It installs only when that exact reviewed creation/accepted transition verifies,
in the same public-root/retirement transaction. An external SSH root has secret
NULL. Reject unexpected secret bytes rather than accepting another provider.
At most64 uncompleted and4096 total intent rows exist per host. Capacity is
checked before new seed generation/signature/submission. Unapproved expired
unreferenced previews can be collected after expires_at+24h. Never collect a
referenced or potentially escaped approved/signed unresolved intent merely
because its deadline passed.

## 8. Seven-stage pending operations and sealed frames

```sql
CREATE TABLE dec_pending (
 request_id TEXT PRIMARY KEY, deadline TEXT NOT NULL, record TEXT NOT NULL,
 secret BLOB, terminal_read_cap BLOB
);
CREATE TABLE dec_frames (
 request_id TEXT NOT NULL, role TEXT NOT NULL, writer_key TEXT NOT NULL,
 frame_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(request_id, role, writer_key, frame_id)
);
```

The exact pending record is:

```text
{format:1,roles,mode,migration_proposal_id,expected_network_id,expected_context_id,
 expected_person_public_key,contact_invitation_base64,descriptor_base64,
 host_public_key,device_public_key,
 request_nonce,request_packet_base64,owner_packet_base64,selection_packet_base64,
 administrator_packet_base64,owner_finalization_packet_base64,
 commit_packet_base64,outcome_packet_base64,catalog_base64,
 owner_offer_id,selection_id,administrator_offer_id,owner_finalization_id,
 manifest_id,activation_id,selection_approved,commit_approved,
 owner_intent_id,administrator_intent_id,selection_intent_id,commit_intent_id,terminal,
 carrier_endpoints,outbound_frames}
```

roles is an ordered unique subset of requester, owner, administrator. mode is
new/renew. migration_proposal_id is `-` ordinarily, or the exact locally
approved migration proposal ds_ for a staged request; the signed request
payload carries the identical field/pin. A staged request uses mode new and
that proposal's exact existing roster keys, descriptor and context. No other
operation, remote hint or mutable latest proposal can substitute for the pin.
The seven packet fields correspond to request, owner offer,
requester selection, administrator offer, owner finalization, final requester
commit and local outcome. Exact raw bytes and their derived IDs agree.
Known pins/nonce/keys are immutable; descriptor can resolve from `-` once under
explicit reviewed adoption. Both requester consent booleans start false and
only their separate explicit consent actions turn them true. They never follow
a mailbox hint, owner/admin review or resume. An approver retains its exact
reviewed selected owner offer, including when another machine wrote it.
selection_intent_id and commit_intent_id start `-`. Explicit selection/commit
approval atomically fixes the corresponding approved typed intent reference,
its exact reviewed pins and consent boolean BEFORE generating a signature.
The reference names the same request_id as operation_id and the corresponding
selection/requester_commit kind. All later transactions retain those exact pins.
An approved boolean can therefore precede a complete packet; it is not evidence
that a stage is signed, published or applied. Finalizing/unresolved-final-commit
semantics require the durably complete exact commit packet, not that boolean
alone. Missing referenced intent or a conflicting kind/tuple is corruption,
never permission to recreate approval or choose another key/template.
This amends the unshipped DEC pending shape before runtime release. A draft
record lacking the new required fields is refused unchanged; do not normalize
it into consent, reset identity/state, or modify any legacy linking record.
The outcome field is a participant's fixed local result, not a global receipt.
contact_invitation_base64 is `-` when no invitation was reviewed at local
request creation, otherwise standard Base64 of the exact original decoded
psi2 contact-invitation object bytes. Preserve it in the same transaction as
the requester attempt, before any publication. Its verified descriptor/context,
person pin and member-label expectation are immutable requester review pins;
derive them from those retained exact bytes, never from an arriving owner offer.
Creation verifies the invitation at the request's guarded created_at. Reopen
rechecks the exact syntax/signature and those fixed creation-time pins; later
invitation expiry does not erase or replace the review or extend the request
window. Owner selection must match the retained member label, descriptor/context
and selected original-person pins before consent, including after either host
implementation reopens. A mismatch refuses without selecting/signing. An
approver-only pending operation does not invent this local requester review.
For the pinned unchanged-P/H/B renewal exception, administrator packet/ID are
`-`, binding remains an exact already current statement reference and no new
binding signature/template is created. It still has owner finalization and
separate final requester consent, with every finite ceiling intact.

terminal is `-`, applied, cancelled, expired, stopped, migration_prepared or
migration_adopted. Despite the field name, **not every non-`-` value is resolved
or cleanup-safe**. This is private lifecycle metadata; public status/stage
arrays are derived under the runtime contract, not an independent readiness
claim. Ordinary final commit without known outcome remains finalizing after
the deadline. A complete staged requester commit instead sets migration_prepared:
it stops ordinary link autoapplication but remains UNRESOLVED, counts toward
active quota and cannot expire, clean up or timeout-abort its public intent.
It creates no active context/provider, participant outcome or network.link_applied
event. Only complete authorized whole-migration adoption sets migration_adopted,
records activation provenance with basis migration and the network.migrated
event. It is terminal history, not a fabricated participant outcome/link event;
locally_applied ordinary-link stage/outcome ID is not invented. `up` resumes the
whole migration while prepared, then checks the actual current network/provider
after adoption; it never ordinarily applies the staged transcript.
`secret` is the exact16-byte pairing secret while private transport is needed,
otherwise SQL NULL. terminal_read_cap is SQLNULL until local apply; if already
sealed terminal outcome frames still need publication, that same apply
transaction derives the exact read capability from the old secret, stores its
32 raw digest bytes in terminal_read_cap, then erases the16-byte secret. Its
Bearer header is rendered as lowercase hex64 under the bootstrap wire. It is
not a decryption key and cannot reseal/create new frames. It is usable only to
publish those exact already sealed terminal outcome frames at the fixed request
locator. Erase it with those frames after their required storage acknowledgment
or deadline. Reject a non32-byte capability, use outside applied terminal
state, or any attempt to reinterpret it as secret. No seed/secret/capability
occurs in record, events or public status.

carrier_endpoints is a mutable transport-only array of
`{kind:"participant"|"helper",address,public_key}` sorted by kind/address/key.
Replacing a carrier does not change context, intent, frames or consent. An
outbound entry is exactly
`{role,writer_public_key,frame_id,acknowledged_by:[{address,public_key}]}`.
Entries remain in creation order, acknowledgments sorted/unique. There is no
network-global sequence/cursor: a helper's success acknowledges only storing
those exact frame bytes. Another carrier can need the same frame. Receiving
an acknowledgment never supplies authority, global commitment or a new frame.

Each dec_frames record is exactly `{frame_base64}`. The decoded sealed outer
frame must match its table tuple and fixed request/locator/window. Persist its
exact bytes once; unknown publication/restart never reseals. Duplicate receipt
of already durable bytes does not create a new frame or after-frame barrier.
A tuple with different bytes is operation_conflict. Received and outbound frame
insertion both precede any dependent interpretation/publication under the
bootstrap crash order. A persisted-frame barrier fires after the transaction
that inserts new frame rows, never solely for a repeated acknowledgment.

Allow at most8 active and4096 total local pending/tombstone rows per host.
Resolved applied/cancelled/expired/stopped/migration_adopted rows do not consume
the active quota, but still consume total capacity; migration_prepared remains
active/unresolved regardless of its non-`-` terminal field.
At most64 frame rows and32MiB decoded sealed ciphertext per local request are
retained; another carrier does not multiply the same stored frame bytes. Each
record still obeys32MiB and its selected proof catalog is at most16MiB. Capacity
failure occurs before a new request/key/signature and never evicts unresolved
intent. Successful apply keeps public pending/outcome evidence and sets secret
SQLNULL atomically. Delete unnecessary frames; already sealed still-needed
terminal outcome frames can remain until sent or request deadline. Never create
new ciphertext after secret retirement. At/after deadline erase every remaining
frame, pairing secret and terminal_read_cap, including unresolved finalizing
requests; preserve all their exact public intent. Subsequent completion uses the exact public participant routes, not
resealing. Cancelled/expired pre-final-commit requests erase secret/frames
immediately and may remove the public tombstone only after deadline+24h. Unknown postcommit
outcomes retain the exact public intent indefinitely until resolved; neither
expiry, helper404 nor quota cleanup regenerates an attempt or discards it.

## 9. Immutable local outcomes and delivery

```sql
CREATE TABLE dec_operations (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, request_id TEXT NOT NULL,
 activation_id TEXT NOT NULL, manifest_id TEXT NOT NULL, record TEXT NOT NULL,
 locally_applied INTEGER NOT NULL CHECK(locally_applied = 1),
 PRIMARY KEY(network_id, context_id, request_id)
);
CREATE TABLE dec_outbox (
 delivery_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL,
 target_key TEXT NOT NULL, record TEXT NOT NULL
);
```

A local operation record is exactly
`{format:1,activation_base64,catalog_base64,outcome_packet_base64,applied_at}`.
It exists only for an actual transcript participant allowed to produce that
outcome and is inserted with locally_applied=1 in the application transaction.
No zero/nonapplied dec_operations row is an outcome; pending intent lives in
its separate tables. Its fixed outcome/activation/catalog bytes never change after local
application. Third-party replication instead records activation admission and
verified network facts without fabricating a participant outcome. More than
one admitted activation identity for a request is visible conflict, not a hash
winner or silent overwrite. At most4096 local outcomes per network; capacity
refuses before a new application and never evicts an older outcome/authority.
Exact historical outcome return creates no current admission or provider change.

At first application, outcome applied_at and observed_root_state_id are fixed
from the final transaction's actual guarded decision and verified root. The
bounded host signature and optional terminal-frame encryption happen there,
after capacity preflight and current revalidation. Outcome, frame/read-cap,
secret retirement, public authority/provider state and one event commit
atomically; no intermediate outcome/signature/frame transaction or earlier
timestamp is substituted. A failure preserves the unresolved exact public
requester commit and supplies no local applied outcome.

A delivery ID is local random128-bit lowercase hex prefixed `ddel_`. Its record
is exactly:

```text
{format:1,kind:"proofs"|"activation"|"migration",body_base64,
 proof_ids,created_at,attempts,next_attempt_at,last_error_code,last_error_detail}
```

The body is an exact typed peer publication envelope under the runtime contract;
it never carries private prior/admission/clock rows. Target key is the independent
peer host key, never a helper/operator key. Helpers/contacts select paths only.
Payload/proof_ids are fixed before first send; retry scheduling/error fields
may change, with safe public error text at most1024 bytes. attempts is u64;
saturation stays saturated rather than wrapping. A full future state is a new
coalesced delivery only if its exact validated monotonic union preserves all
held proof/restriction obligations, never a mutated partially acknowledged body.

Across all local DEC networks, the outbox has independently inclusive ceilings
of4096 rows,512MiB summed exact decoded body bytes, and1GiB summed UTF-8 record
bytes. Preflight the entire prospective target set plus all existing unresolved
deliveries before signing/application, and recheck inside the final transaction.
Exceeding any ceiling is409 quota_exceeded with no partial public-state commit
or partial target set. A transport failure never frees a delivery slot. Only
actual acknowledged retirement or the validated exact monotonic coalescing above
can reclaim capacity; retained public proof obligations remain independently
durable. Finite fanout can therefore refuse a large publication even when one
body fits its20MiB wire cap. Selected: bounded whole-host delivery storage and
an explicit atomic refusal. Discarded: unbounded per-target duplication, silent
eviction of unknown deliveries, or committing only part of a restrictive change.

Local public change, restrictive admission, heads/maxima and target deliveries
commit together before attempted transport. There is no required remote
coordinator acknowledgment or last-sync flag. A receiver acknowledgment is
only that receiver's verified local observation. Complete proof facts remain
retained even after that target delivery is retired. Unknown failure preserves
the outbox. A newly discovered member receives sufficient retained closure;
it does not make old helper receipts proof of current globally complete state.

## 10. Migration preparation, fence and atomic adoption

```sql
CREATE TABLE dec_migrations (
 network_id TEXT NOT NULL, proposal_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, proposal_id)
);
```

The exact shared record is:

```text
{format:1,context_id,state,proposal_base64,source_catalog_base64,
 source_state_base64,prepared_catalog_base64,initial_root_state_base64,
 acknowledgments_base64,commit_base64,migration_base64,
 local_acknowledgment_base64,root_intent_ids,local_ack_intent_id,
 approved,fenced,publication_started}
```

state is needs_approvals, prepared, acknowledged, adopted or conflict.
Acknowledgments are exact original signed bodies sorted by roster host key;
root_intent_ids lists dependency-ordered typed creation/preparation/commit
intents. An absent byte field/reference is `-`; arrays remain present.
Source-state floors/restrictions/roster and nonce are exactly the signed source
snapshot/proposal, not recalculated from a later smaller catalog. Prepared
catalog and final commit pin the exact one proposal/hash. publication_started
is a monotonic local transport flag, never proof of global adoption.

Before publishing its signed local acknowledgment, the host atomically fixes
its exact approval, acknowledgment and fenced=true. The fence blocks the
migration contract's new legacy management/enrollment/final signing **and**
new network-derived admissions/queued starts/hops; manual authority is not an
automatic fallback. Existing accepted work/results/cancellation and valid
restrictions keep their documented paths. No timeout clears fenced. Missing
approval/known host/operation/retention blocks progress without dropping the
roster or replacing identity. Incomplete staging, including complete per-host migration_prepared transcripts,
never installs dec_contexts, networks format2, dec_signers, participant outcomes
or usable grants. It does not emit network.link_applied. The exact proposal pin
and whole-migration adoption gate remain separate from per-host requester
consent; ordinary resume cannot cross that boundary.

Full adoption atomically writes exact complete migration evidence, context/mode/
root pin, all source restrictions/floors, ordinary admissions and activation
provenance, heads/maxima, verified member cache, matching selected provider and
one network.migrated event; legacy/product state is preserved. An expired
prepared path is not selected as usable. Competing valid origins are retained
and freeze positives rather than overwriting the adopted proposal. Root/private
seed retirement follows section3. Only the documented clock-anchor write may
survive an otherwise failed adoption transaction.

## 11. Contacts and optional operator configuration

```sql
CREATE TABLE dec_contacts (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, host_key TEXT NOT NULL,
 sequence INTEGER NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, host_key)
);
CREATE TABLE dec_helpers (
 kind TEXT NOT NULL, address TEXT NOT NULL, public_key TEXT NOT NULL,
 record TEXT NOT NULL, credential BLOB,
 PRIMARY KEY(kind, address, public_key)
);
```

Contact sequence uses the U64 codec. Record is exactly
`{format:1,message_hashes:[HASH],conflicted,contacts_base64:[BASE64]}`.
Hashes are sorted unique SHA256 of the bootstrap contract's exact contact
signing message, not raw outer JSON; same-message envelope aliases are not
semantic conflicts. Keep one hash for a unique contact, two distinct hashes
and conflicted=true after equivocation. Two representative bodies suffice;
additional same-sequence variants cannot restore usability. Bodies are sorted
by SHA256 of exact bytes and must match retained message hashes/sequence.
A fresh unbound pairing contact uses network/context `-`. The highest verified
sequence, representative hashes and conflict flag survive expiry/body cleanup;
no lower or newly fabricated same-sequence hint returns. An empty contacts
array supplies no reachable address. Only a higher independently valid contact
sequence replaces the prior hashes/conflict guard. Contacts never become
admitted authority proofs or advance the decision clock.

Helper kind is rendezvous or relay. Record is exactly `{format:1,enabled}`;
credential is SQL NULL or exact private operator-token bytes within the bootstrap
protocol's cap: at most1024 UTF-8 bytes, no CR/LF/NUL. Owner-local configuration alone may create/change these rows.
Transport tokens are never stored in proof/pending JSON, contacts or logs.
Disabling/removing a helper does not alter network mode, ancestry, deadlines,
consent, peer pins or local outcomes. No default required operator row exists.
This table shares optional transport settings only; it does not require either
implementation to keep its connection cache or counters in SQLite.

## 12. Coherent reads, transactions and verification

Load catalog bytes, admission provenance, context/root pins, heads/maxima,
selection, fence and decision guard from one immutable snapshot/read transaction.
Pure expensive verification may happen after closing that read transaction.
Before signing/applying, check that exact dependencies/pins/guard still match
and revalidate current time/authority in the final transaction; a torn newer
maximum/older catalog cannot erase a policy or enable lower fallback. Never
hold a SQLite transaction over a remote request, SSH prompt or user review.

Required independent cases include legitimate21-to23 and merged OAuth22-to23
opening/refusal/rollback, with all4 Go/Rust directions for the actual OAuth22
baseline. Create real remote MCP/OAuth product state through public interfaces;
retain every old table definition/row, exact tokens/headers/private files and
public source/capability views. For actual OAuth22 inputs, only the seventeen
additive DEC tables/version may differ. Schema21 inputs additionally receive
the existing OAuth22 migration's changes, with every original21 fact preserved.
Verify restart, schema22 old-binary downgrade
refusal, future24 refusal and stopped-copy malformed DEC table/generated-column
refusal without other file/row/version mutation. Experimental DEC22 inputs with
reserved DEC names refuse rather than becoming a second schema22 meaning.
Keep earlier experimental22 receipts historical; do not relabel an artifact,
rewrite an original fixture's version, or count an old run as OAuth22-to23.
Other cases include no fake coordinator fields or private-original
seed; exact alias/provenance/head/max-u64 persistence; expired/inactive/forked
selection without fallback; per-domain missing-body repair plus unrelated deny;
clock restart/context migration/final-TX race; all7 transcript stages and exact
external fixed slots across restart; each durable signature/frame/commit/apply
boundary; sticky local restriction/outbox before unavailable transport; immutable
outcome retry versus newer selection; root seed retirement versus own accepted
rotation; migration fence/competing origin/event deduplication; contact/helper
replacement without authority changes; unchanged21 manual grants, tasks,
capabilities, approvals, bounds, sessions and private credential/profile files,
plus the merged schema22 remote MCP/OAuth product state.

Chosen conventions keep exact shared state and typed intent below independent
public authority verification. Discarded: adding fake coordinator columns,
rewriting legacy records on open, per-language pending extensions, arbitrary
message signing, importing private original keys, authoritative member caches,
peer-supplied prior state, signed SQLite numbers, global helper cursors,
expiry-based deletion of restrictive history, and timeout-based fence abort.
