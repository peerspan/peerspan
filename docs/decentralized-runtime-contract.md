# Coordinator-free owner-local and peer runtime

Status: DEC-03/04/05/06 shared contract candidate, 2026-10-26.
Review with the [authority](decentralized-authority-contract.md),
[bootstrap](decentralized-bootstrap-contract.md),
[migration](decentralized-migration-contract.md) and
[storage](decentralized-storage-contract.md) contracts before code or executable
cases. Review and merge the complete contract set before either starts, as
fixed by the umbrella contract. This fixes one recommended runtime interface. Exact statement bytes and
cryptography come from those contracts; these routes do not invent authority.
All APIs below use the existing private Unix administration socket unless a
section explicitly names peer/bootstrap/repair transport.

## 1. Mode, strict decoding and local success

New networks use only `peerspan-decentralized-v1`. An explicit schema23 database
upgrade preserves old data but does not adopt that mode for an existing network.
Migration requires the complete migration protocol. No failed request, missing
helper, recent contact or empty coordinator pin can choose a different mode.

A narrow preexisting-legacy-operation exception permits settlement before
migration: the original owner-local `/v1/link/requests/{id}/resume` may retrieve
and verify/apply ONLY an exact already durably signed final-commit operation's
immutable original outcome, and its cancel route may cancel only a precommit
local attempt. Resume cannot create a legacy signature, approval, final consent,
admission, enrollment, key or replacement attempt. It uses the exact stored old
context/descriptor/keys/deadline/feature and original legacy verifiers. It may
read the independently pinned old endpoint solely for that exact historical
outcome or accept already retained exact outcome evidence; no new coordinator
configuration/default is required or inferred. Any application affects only
OLD history/source state, never DEC authority or a migrated provider/context.
A timeout/404 cannot prove noncommit. If exact settlement cannot be verified,
return409 recovery_required and preserve all old evidence/identity/fence. No
such operation is silently discarded or resumed under a new context. Normal
up does not use this exception as a legacy creation/signing fallback.

New owner-local management uses `/v2`. Existing task, message, capability,
source, agent, adapter, session, project and per-call approval APIs retain their
current paths and product schemas; their network authorization uses the actual
network's verified mode. Preserve manual grant allow_disconnected: false/omitted
STILL requires the requester's independently current DEC membership/path in a
shared network, replacing recent-coordinator-sync only. True permits the owner's
actual explicit disconnected grant independently, subject to its exact target,
expiry, revocation, content/agent/resource limits. A known peer key alone is no
grant; a DEC policy cannot be relabeled manual to escape expiry/forks. In particular preserve PR78/80 checks, same-person
source rules, per-call approvals, budgets, target ownership and accepted-work
semantics. Their `/v1` path is not a legacy-network authority fallback.

Legacy network-creation/enrollment/signing/mutation routes return426
`upgrade_required` with migration/coordinator-free guidance. Legacy proof/history
reads and explicitly typed migration preparation remain available. Requesting a
DEC network through an old coordinator-map or legacy-network projection route
returns426 rather than synthesizing missing coordinator fields. There is no
new-network compatibility flag which recreates the old coordinator lifecycle.

A v2 request uses strict UTF-8 JSON: duplicate/unknown/missing fields, nulls,
wrong types, malformed IDs/keys/Base64/timestamps or overflow fail before
signing or mutation. Unless declared otherwise a mutation body is at most 1 MiB,
GET has no query/body, and an explicit boolean `approve` never defaults true.
The no-null rule applies to signed objects and strict private persistence.
Nullable public RESPONSE fields below are explicit exceptions: creation/adoption network
and NETWORK_VIEW provider can be null exactly where declared; no request or
signed payload gains nullable fields by analogy.
Owner-local v2 response bodies are at most 32 MiB, allowing 16 ready templates
of up to 1 MiB each after Base64 expansion; individual objects keep their bounds.
Normal/repair catalog and complete-publication whole bodies use 20 MiB, not a
raw 16 MiB wrapper limit. All wire strings/arrays use shared bounds/comparators. The
mode/context is read from durable state, not caller assertions.

`committed:true` means the exact verified statement/operation and its local
projection/outbox/event are durably committed on THIS host. It is not a central
acknowledgment, global commit, delivery guarantee, no-unseen-revocation proof or
integration readiness. Valid local authority works offline until its precise
hard limit or a known restriction/conflict. Signature and final application
recheck the latest coherent state and guarded decision time; successful gossip
is never an additional authority credential.

### Public errors and failure boundaries

A v2 failure is exactly:

```text
{code,error,details:{network_id,context_id,request_id,stage,
 required_ids,conflict_ids,next}}
```

Unknown identity fields are `"-"`; required/conflict IDs are sorted unique;
next is an ordered array of exact public repair/resume commands or `[]`.
Error/detail strings are public safe UTF-8, at most 1024 bytes each, without
code/token/ciphertext/private key paths. Stage is one of create, request, owner,
selection, administrator, owner_finalization, commit, apply, sign, repair,
transport, clock or migration. HTTP status/code mapping is exact:

| HTTP | Code / condition |
| --- | --- |
|400| invalid: malformed/unknown fields, IDs, signature, oversized byte framing, wrong first consent/network/key pin |
|403| forbidden: independently denied scope/role/target/known restriction; authority_expired: required finite path expired; device_revoked: target/ancestor stable device ban; not_yet_valid: required finite path has not begun; authority_would_be_invalidated: typed action would disable its own required issuer path |
|404| not_found: no such record; provider uses this only for absent selection |
|409| proof_required, state_conflict, operation_conflict, version_exhausted, quota_exceeded, clock_rollback, migration_pending, review_required, signer_unavailable, recovery_required |
|410| expired: incomplete local pairing window elapsed, not a completed historical result |
|426| upgrade_required: legacy mutation/downgrade or incompatible protocol |
|429| rate_limited, with integer Retry-After transport seconds |
|500| internal, generic public `internal error` |

No unknown local route implicitly reaches a peer/bootstrap router:404 JSON.
Wrong method, including undeclared HEAD, is405 JSON code invalid with Allow;
query strings/extra GET bodies are400. Decode/framing failure applies nothing.
A present missing/corrupt private key is signer_unavailable, not an absent
selection or permission to choose another signer. A path failure reports its
actual authority code instead. A view can still truthfully show cached public
authority while the selected signing provider is unavailable.

Before local commit, an operation failure preserves all intent/templates,
identity, authority/maxima, reservations, selection and outboxes except the
explicit clock-only metadata exception. After committed true, a failed delivery
is recorded in delivery and retried; it cannot roll back the local restriction
or masquerade as an uncommitted signing preparation. Historical completed retry
returns its exact prior result without a new signature or authority claim.

## 2. Public network and provider views

The exact v2 `NETWORK_VIEW` is:

```text
{id,name,mode:"decentralized",context_id,genesis_root_public_key,
 root_state_id,root_public_key,root_epoch,member,host_public_key,
 person_public_key,provider,provider_state,authority,delivery,created_at}
```

`id` is the stable network ID. Member/person preserve the remembered independently
verified own-host identity tuple even when now expired/withdrawn/revoked. This is
identity/history, not current membership/permission. Only truly unknown/unbound
values use `"-"`; an unusable provider must never make up generate another person.
Epoch is full u64, the highest admitted observed root epoch/durable floor, not a
branch winner. With an unresolved root fork root_state_id/root_public_key are
`"-"`; no branch is selected by highest epoch. A remembered exact head whose body
is now missing retains its known ID/floor but is proof_required, never usable.
Future/unadmitted roots cannot advance this metadata. `created_at` is the local
record's strict creation time. Provider is the remembered typed PROVIDER_VIEW
public path summary or null only when no explicit persisted selection exists; it has no private key.

`authority` is exactly `{state,not_after,required_ids,conflict_ids}`. State is
`usable`, `unbound`, `authority_expired`, `proof_required`, `state_conflict`,
`forbidden`, `device_revoked`, `not_yet_valid`, `clock_rollback` or
`migration_pending`. It evaluates the current
PUBLIC own-host membership/person/binding proof path, not local private-key or
SSH-agent availability. Each policy/group/resource operation still evaluates
its own exact public issuer path and source checks; a global usable label does
not authorize another domain or hide its fork. Deadline is that public path's
finite ceiling or `"-"` if unavailable. Required/conflict arrays are exact sorted
unique IDs. Cached valid public membership/binding/policy remains valid if a
local signing key disappears; loss blocks signing/renewal, not unrelated work.

`provider_state` is exactly `{state,code,error,required_ids}`. State is
`available`, `unavailable` or `not_selected`; available/not_selected use code
and error `"-"`, empty required IDs. Unavailable reports the actual structured
public key/path/expiry/seed/SSH repair failure, with error at most 1024 bytes. It never erases the selected
identity or silently chooses an original key. Provider scopes/deadline describe
its independently verified public potential; actual signing ALSO requires this
available state and a final fresh check, never a cached view. Preparing fixed
external original-person/root SSH slots instead requires the exact valid public
path/consent, not daemon visibility of that private key or agent. Final signature
submission proves possession over only those typed templates. An explicitly
provided matching --person-key-file/--root-key may use that external path;
this is not fallback from an invalid selected device. Owned device/automatic
signing still requires its owned valid seed/provider.
`delivery` is exactly `{pending_proof_ids,peer_errors:[{host_public_key,code}]}`,
sorted by ID/key. These are local outbox/last-attempt observations, not authority.

The exact `PROVIDER_VIEW` is:

```text
{kind,person_public_key,host_public_key,device_public_key,lease_id,
 root_state_id,scopes,not_after}
```

Kind is `original_person`, `device` or `network_root`. Device names the exact
selected lease; private seed availability belongs to provider_state; person/host/device match its current verified
binding/path. Original person resolves the verified bound original key and its
actual owner-local SSH/file provider, with device `"-"` and lease_id equal to
the person lease. Network root has person/host/device/lease `"-"`, current root
state and actual owned/external root provider; it is not an owner-person
provider. Its host field therefore does not claim an owner-host binding. The
actual local writer belongs to an ordinary action/root_transition private
intent's exact `host` field. Other intent kinds keep their typed target pins:
link owner/administrator intents name the target host, which may differ from
the packet writer. A whole-network migration root preparation/commit has no
single target person/host/device; all three private subject fields are `-`,
with root scopes8. Initial preparation independently checks the owned writer,
approved preproposal own identity/roster contribution and explicit root
preparation approval; it supplies no later host participation consent. Later
participant stages still require their separate own proposal review. The final
root commit checks that participation and exact local acknowledgment/fence. None of
these fields establishes a bound root-host identity or replaces those checks.
Selected under the DEC delegation: use the absent-host marker consistently;
discarded: show the daemon's local writer as a bound root host, which would mix
transport placement with the root's authority identity.
Scopes are actual available typed powers: root8, original owner1|2|4 plus 8 only
with its current admin role, device's currently usable subset. Deadline is the
intersection of required finite parents; only root identity uses `"-"`.

`GET /v2/networks` returns ID-sorted `[NETWORK_VIEW]`.
`GET /v2/networks/{id}` returns one view. `GET /v2/networks/{id}/members` returns
exactly `{context_id,members:[{host_public_key,member,person_public_key,
 host_lease_id,binding_lease_id,device_lease_id,not_after}]}`, host-key sorted.
Only independently current member facts appear; unbound member person/binding/
device fields are `"-"`. Missing and inactive CURRENT facts are not guessed from transport hints;
NETWORK_VIEW still retains its separately identified own historical tuple.
`device_lease_id` is the unique independently current D matching this exact
host/person/binding, or `"-"` when there are zero or multiple such devices.
`not_after` is the H/P/B membership-path ceiling (H alone when unbound), not
the deadline of an arbitrary device. This display never selects a local provider.
Selected: report an unambiguous matching device only. Discarded: choosing across
different device streams by sequence/hash or implying that a host has only one
authorized device. Those choices invent a relationship the signed state does
not establish.
All these reads use one coherent stored snapshot and write nothing.

`GET /v2/networks/{id}/persons` returns exactly
`{context_id,persons:[{person_public_key,member,person_lease_id,not_after}]}`,
sorted/unique by person key, with at most4096 entries. Include only independently
current person admission, using its exact verified P label and effective finite
deadline; a person need not own a current host to appear. Transport records,
owner labels, pending migration P, legacy history and selected-provider metadata
cannot manufacture an admitted person. This is a local current view, not proof
that no unseen member or revocation exists. Native label resolution preserves
the existing ambiguity errors instead of choosing a key by label/hash order.

`GET /v2/networks/{id}/policy/{person}` takes an exact canonical person key in
the encoded path and no query/body. On success200 it returns exactly
`{statement_id,statement_base64}`: the exact ds_ and canonical standard Base64
of the ORIGINAL signed current policy statement, at most1MiB decoded and2MiB
whole response. Verify that person's actual current policy through the same
stored authority, retained provenance, restrictions, full-u64 maxima and actual
guarded NOW used by product authorization. A known missing body returns
proof_required with its exact IDs; a policy fork/conflict returns its ordinary
state_conflict/required references, never a hash-selected body. No current policy
or an independently inactive policy returns404 not_found. This read supplies
no new authority, admission, provider, signing permission or import provenance.
Clients may decode its unsigned policy body for display and proposed edits;
every later mutation or product action still performs its own current checks.
Never return a fabricated legacy PolicyView/signature or reinterpret the
statement's outer serialization as a new proof admitted by this GET.

`GET /v2/networks/{id}/groups` takes no query/body and returns exactly
`{context_id,groups:[{name,statement_id,statement_base64}]}`. Read one held
coherent snapshot at guarded DEC decision time. Include only independently
current usable group stream heads, unique and ordered by validated group name,
at most4096 entries. Each entry preserves the exact ORIGINAL signed group
envelope as canonical standard Base64 and its exact ds_; existing1MiB statement
and32MiB whole-response bounds apply. Do not truncate an incomplete response.

An absent, expired, withdrawn or otherwise independently inactive group supplies
no entry; a complete empty current view is200 with groups[]. Every remembered
group stream required by this aggregate must be evaluated. A missing selected
head/body or required ancestor refuses the whole GET with proof_required and
its exact derivable IDs. A known fork in any such group stream refuses the
whole GET with ordinary state_conflict and all exact conflicting heads, never
an omitted incomplete stream, partial200, lower body fallback or hash-selected
group. Corresponding diagnostic IDs are sorted/unique; multiple independent
causes retain the existing error-precedence rules. These errors do not make unrelated policy,
person or other domains unusable for their independently authorized operations.
Retained maxima and raw planning-head presence cannot manufacture current group
authority. Root/origin/clock failures retain their existing structured errors.

Native `network groups` uses this verified read for DEC networks and displays
names, members and versions decoded from these exact envelopes. An unavailable
local signing key does not invalidate a usable cached public group. Do not
fabricate a legacy group signature or fall back to v1/SSH signing to read it.
Every later group mutation or product action performs its own current checks.

These routes use one held coherent snapshot and guarded read time, with no clock
commit, projection rewrite, key generation, coordinator fetch or event. Reads
retain the ordinary structured error/clock-rollback rules. Native agents/person
resolution/access display use these verified v2 views; they do not route DEC
state through legacy coordinator parsers or treat planning heads as usable
policy authority. Existing legacy v1 policy/person response shapes stay exact.
The groups read also performs no signing, fetching, adoption, provider selection,
head/maximum/outbox update or other row mutation. Existing legacy v1 group
history remains unchanged.

`GET /v2/networks/{id}/provider` returns200 PROVIDER_VIEW when the actual
selected provider is usable and locally available,404 only when NO selection exists, or the actual
structured repair error for a present unusable selection. It never turns a
broken device row into an absent provider and falls back to an original key.
Explicit original-person signing must match the verified binding, except its
narrow first-binding/new-person self-consent cases. Root signing is explicit.

`GET /v2/networks/{id}/access-versions` returns exactly
`{policies:[{person_public_key,version,statement_ids,head_ids}],
groups:[{name,version,statement_ids,head_ids}]}`, sorted by stable subject/name. Each
positive full u64 version is the retained maximum and statement_ids is its sorted
statement IDs AT THAT NUMERIC MAX, possibly empty for a migrated floor.
Separate head_ids lists ALL admitted incomparable maximal stream heads,
including a lower-sequence fork. A greater version never hides that branch. Inactive/forked
maxima remain visible without entering permission maps. Generation checks
max+1 before reservation/signing and refuses `version_exhausted` at maxu64.

### Explicit provider selection and coherent planning

`POST /v2/networks/{id}/provider` is exactly
`{provider_id,person_public_key,host_public_key,approve}` and returns exactly
`{network,provider,provider_state}`. Provider_id is the bound original key or an
exact activated owned D lease. Approval validates the immutable own identity,
current public path and exact requested provider; original external slots need
no daemon key import. It changes only the explicit selected provider, never
membership/permission. A wrong person/host or unusable D fails without changing
selection. Preview writes/signs nothing. No root can be selected as owner. A genuine
first binding of this unbound local host through an explicitly supplied current
original person is permitted under normal owner+host signatures. `network bind`
then drives this exact explicit provider-selection route for that same reviewed
person/host; it cannot infer a provider from a missing row. A generic one-off
policy/root signature never changes selection. A bound-person mismatch refuses
until an explicitly authorized unbind/rebind and required admission steps.

`GET /v2/networks/{id}/catalog` returns exactly `{catalog:CATALOG}` under32MiB
owner response/16MiB raw catalog/8MiB decoded/4096-object bounds. It reveals only
public exact evidence, no private provenance, keys or repair-pending unadmitted
objects. `GET /v2/networks/{id}/planning` returns exactly
`{network,decision_time,catalog,streams}` from ONE coherent read snapshot.
Streams is sorted by (stream_kind,subject,subject2); each entry is exactly
`{stream_kind,subject,subject2,head_ids,version,statement_ids,floor_proof_ids}`,
using the storage contract's unambiguous stream tuple. Version is the numeric
maximum; statement_ids are at that maximum, while head_ids preserves all heads.
Decision_time is max(actual local UTC, persisted guard), without advancing it.
These owner-local planning summaries have no public signature or independent
authority. CLI builds exact parents/predecessors/new versions from this state;
final signing/apply still revalidates current complete proofs, not a stale plan.

## 3. Local genesis and original-person creation

`network create NAME [--as MEMBER] [--person-key-file PATH]` creates locally
without any coordinator/helper/peer operation. Existing name/label defaulting
and original-key selection/generation rules remain: explicit key, configured
owner key or an explicitly approved new protected owner-local key. A mismatched
existing identity is not replaced. Root state is a new raw owned root; the
initial provider is ORIGINAL PERSON, with no device selection or device lease.

Prepare ordinary genesis root_state, root-issued admin/person/host leases,
owner+host binding, and the existing creator policy under their finite bounds.
Root never signs another person's policy/binding; the original person signs
those exact typed objects. Host consent signs its ordinary host/binding grants.
The root/admin/P/H/B proofs authorize only their specified subjects. Every later
new/renewed device, including on the creator, requires the complete bootstrap
ceremony. Creating an original provider is not a device-consent shortcut.

`POST /v2/networks` is exactly `{name,member,person_public_key,approve}`. It
returns200 exactly `{creation_id,review,signing_requests,network,committed}`.
Review is exactly `{name,member,descriptor,root_state_id,person_public_key,
host_public_key,not_after,authority_warning}`. Network is null until complete,
then NETWORK_VIEW. Creation_id is `create_` plus 32 random bytes rendered lowercase hex,
fixed with a private creation intent before signing. Repeating the same live
name/member/person/host preparation reuses that intent/root/templates; another
pending or completed identity under the same name returns409 state_conflict.
A declined/unapproved preparation creates no active network, trust or policy.
Private root preparation may be retained for review/retry but is not published.

With approve true, persist this exact owned creation approval, then generate
only dependency-ready typed signatures. External original-person signatures
use section 4 slots; daemon imports no original key. A root held locally can
sign only the approved current creation objects. When the last required valid
signature is supplied, revalidate time/templates/identity and atomically commit
network/context/root, complete ordinary proofs, original provider, policy/maxima,
outboxes and one `network.created` event. `committed` becomes true; return the
same stored result on exact retry without replacing keys or resetting time.

The applied create/action result is a historical exact response, retained in
the intent's result_base64 and returned byte-for-byte by completed GET/retry.
Its embedded network/catalog/delivery summaries describe that local commit,
not current authority or delivery. Current views use their separate read routes.
Returning the historical result signs/applies nothing, changes no provider,
admission, timestamp or clock, and emits no second event. This distinction also
applies to the completed ordinary-action wrapper in section4.

`GET /v2/network-creations/{creation_id}` returns the same shape read-only.
`POST /v2/network-creations/{creation_id}/approve` requires exact
`{context_id,root_state_id,person_public_key,host_public_key,approve}` and returns
that shape. `POST /v2/network-creations/{creation_id}/signed` takes exactly
`{intent_id,signatures:[{slot_id,role,signature}]}` and returns that shape. Malformed signatures
or changed pins apply nothing. An incomplete unsigned intent older than 300s
requires re-review, not silent later timestamps; no already published fixed
object is regenerated. There are at most 8 unresolved creations/host; quota
refuses new preparation. Exact completed creation outcomes remain retained.

For an incomplete nonterminal creation, the explicit approve route with the
same exact context/root/person/host pins and approve:true may perform that
re-review after the initial300s boundary. It records the actual guarded
approved_at, checks all current creation/finite-proof preconditions, and permits
new signatures only while its age is0..300s inclusive. A still-fresh exact
approval retry preserves approved_at. No GET, ordinary resume or signature
submission refreshes consent; an expired approval returns409 review_required
before another signature/application. The CLI must show/reconfirm the same
review before invoking an expired approval again; stored approval is not new
consent. No key, timestamp, finite deadline, signed template or initial private
expires_at is regenerated. A changed tuple remains a conflict, not a refresh.

An already completely signed durable creation can apply after that initial
preview window without a new signature or approval, provided the same six exact
proofs, identity and current validity still pass at the actual final decision
and transaction. GET remains read-only. A stopped or expired finite authority
refuses application; this is not a deadline grace or automatic lease renewal.

Selected: explicit review of an unchanged pending creation plus independent
current verification of completed proofs. Discarded: next-second timestamp
equality, silently refreshed consent on resume, regenerated templates/keys,
extended request/migration deadlines or a general ordinary-action age bypass.

The native create command's explicit requested owned tuple supplies creation
consent; it verifies the daemon review before submitting matching SSH signatures.
JSON output is the final NETWORK_VIEW on success, or the explicit pending
creation result/nonzero when signing/review is incomplete. `up` can drive the
same interface, preserving all preexisting service/project/identity state.

## 4. Fixed typed signing and ordinary actions

A SIGNING_REQUEST has exactly:

```text
{intent_id,slot_id,object_type,object_id,role,public_key,format,
 template_base64,message_base64}
```

Intent_id is its exact persisted dint_ intention. Slot_id is the positive-u64
index of a typed template, consecutive from 1 in persisted dependency order;
role selects only a declared signature role on that template. Object_type is
exactly root_state, admin_lease, person_lease, host_lease, binding_lease,
device_lease, policy, group, admin_withdraw, person_remove, host_revoke,
host_unbind, device_revoke, owner_offer_packet, administrator_packet,
owner_finalization_packet, migration_proposal, migration_ack or migration_commit.
Object_id is its ds_/dpk_ semantic ID. Format is ed25519 or sshsig. Template is
its exact typed unsigned object with only declared unfilled signature positions
`"-"`, not a generic message. The CLI derives object ID, signature role/message,
provider key and expected format independently from that template. A ready
batch contains at most 16 requested signatures in dependency/slot/role order;
remaining slots are exposed on later exact reads/submissions after dependencies
or earlier signatures are fixed. This is a declared signing batch, not truncated
authority evidence. The persisted full typed intent retains every slot.

For owner_offer_packet, administrator_packet and owner_finalization_packet,
the declared SIGNING_REQUEST role is exactly `authority`; it fills only the
packet's authority_signature with its fixed authority_signature_format.
It is distinct from the packet's own role (owner, administrator or
owner_finalization). The message is exactly that packet's existing bootstrap
`M`, and public_key is its fixed signer_public_key. Host and device signatures
are separate locally owned key roles, never external authority slots. In these
three packet types device_signature remains `"-"`; the independently checked
host signature still binds the same exact `M`. Selected: one literal typed
external packet-authority role, using the existing message and cryptography.
Discarded: inferring a signature field from the packet role, accepting arbitrary
role names, or letting an external authority slot replace host/device consent.

Only persisted approved, dependency-ready typed templates expose slots. An
original-person SSH slot uses peerspan-person-v1/Ed25519/SHA512; a returned slot
cannot request arbitrary bytes, another person or an unrelated root action.
The CLI checks key/format/object/role/template before invoking the matching key.
A signed submission is exactly `{intent_id,signatures:[{slot_id,role,signature}]}`,
1..16 entries/1 MiB body, unique by (slot_id,role), ordered by slot_id/role;
it cannot alter a template, timestamp, scope or selected provider. Filled slots
are immutable; exact repeated valid signatures are idempotent. A different
signature alias must not silently replace stored exact public evidence.
Locally owned raw host/device/root keys sign only after the same pre-sign gates.
No provider remains usable merely because a template was approved earlier.

`POST /v2/networks/{id}/actions` is exactly
`{kind,provider_id,signature_format,payload_base64,approve}`. Kind is exactly one registered
ordinary DEC statement kind: admin/person/host/binding lease, policy, group,
admin_withdraw, person_remove, host_revoke, host_unbind, device_revoke or a
root_state transition/resolution. Device lease issuance is NOT an ordinary
action: always use the complete link ceremony. Payload is that kind's exact
strict unsigned payload bytes. Provider_id is `"auto"`, `"network_root"`, an
exact owned device lease ds_, or the exact bound original public key. Auto resolves ONLY the explicit persisted original/device selection. No row
returns404; row corruption/unavailability is repair, never an inferred original
provider. Fresh creation explicitly persists original selection; linking
persists device selection. An explicit one-off provider choice never changes
persistent selection. It never chooses network root or repairs a broken selection by fallback.
Root/provider/subject power must independently match the kind and all parents.
Signature_format is auto/ed25519/sshsig. Auto resolves once: device raw Ed25519,
original-person SSHSIG, root owned raw seed or explicitly configured SSH root.
A caller can explicitly request root SSHSIG slots without importing a key even
when the daemon has no matching agent; device must ed25519 and original must
sshsig. The resolved format is frozen in the intent. It is never inferred from
a submitted signature or changed to bypass unavailable selected authority.

Response is200 exactly `{action_id,review,signing_requests,statement_base64,
proof_id,catalog,committed,delivery}`. Action_id is `act_` plus H of the fixed
context/kind/statement ID/concrete provider ID under
`peerspan-decentralized-action-intent-v1` with L separators. Review is exactly
`{kind,statement_id,provider,subject,sequence,not_after,authority_warning}`.
Subject is the lease's exact subject, restriction's exact target, policy
`{person_public_key}`, group `{name}`, or root `{root_public_key,epoch}`.
Sequence is the full u64 stream sequence/root epoch, or0 for a restriction;
not_after is `"-"` only for root/restriction. Unready statement,
proof ID and catalog are `"-"`; otherwise exact public bytes/catalog, not an
unsigned projection. delivery is the NETWORK_VIEW delivery shape.
`GET /v2/networks/{id}/actions/{action_id}` reads this result.
`POST /v2/networks/{id}/actions/{action_id}/signed` takes the common signatures
body and returns that shape. Each action has one immutable concrete provider,
unsigned payload, consent and ready slot set. Expired/changed preconditions
refuse without silently signing another generation.

Preview may persist public typed templates but signs/publishes nothing. Approval
checks current independently prior authority, exact owned key/provider/binding,
latest guard, finite ceilings, scope/role, stream DAG/forks/maxima and existing
edit/claim reservations before any signature. Signed verification is mandatory
before application. Changed intervening authority causes structured repair,
not automatic re-review/rewriting. Actions which require host/new-root consent
remain pending until every declared signature exists.

Commit valid local restrictions, conflict heads and their delivery markers
before any remote attempt. Positive local grants/policies likewise have a local
atomic commit; no coordinator acknowledgment is required. Do not let a new
batch's positive admission establish issuer authority for another fresh grant.
The storage contract's whole-host outbox row/decoded-byte/record-byte ceilings
apply to the entire proposed fanout before signing/apply and again in the final
transaction. Capacity failure is quota_exceeded, without partial authority or
delivery changes; the per-message wire cap is not an aggregate storage promise.
Local publication failure preserves the committed exact proof/outbox; response
committed true may have delivery pending and does not claim peer receipt.
A failed pre-sign/apply operation commits none of those facts; only the shared
named monotonic decision-clock exception may persist on refusal.

Existing allow/deny, share/unshare, trust/untrust, groups, capability create/rm,
policy edits/reapply and automatic renewal use the actual verified typed
provider and the same reservation/atomicity rules. Keep active-only authorization
maps; consult retained maxima separately. Capability claim preparation signs
without publishing; atomic capability creation revalidates every claim/catalog
and commits all source/name/capability/policy/edit/delivery changes together or
none. An owner-local capability mutation carrying explicit DEC catalogs has a
20 MiB whole-body bound, each catalog still 16 MiB/8 MiB decoded/4096 objects; legacy-only
bodies and unrelated capability-call/resource bounds remain as specified. All matching-owner withdrawals complete before a different holder is
reported. An explicit owner filters unrelated bound networks before opening a
provider. No fake legacy wire policy is emitted from a DEC projection.

The [policy edit supplement](decentralized-policy-edit-contract.md) fixes the
strict private edit representation, POST reservation/read-only summary,
pure typed reapplication preview and interoperable dropped-addition keys, and
payload-bound edit sequence, including prepare-only claims and atomic final
settlement. Existing legacy edit history remains distinct.

### Prepare a capability claim without applying a policy

`POST /v2/networks/{id}/policy-claims` is exactly
`{capability,provider_id,signature_format,payload_base64,approve}`. Capability
is the existing validated local capability name. Payload is the exact unsigned
DEC POLICY wrapper, containing its exact unsigned policy-v2 body, not a generic
message or a separate claim catalog kind. Provider/format follow the ordinary
policy scope1/current bound owner rules; explicit external original SSH slots
remain supported. Preview/approval return the ordinary action result shape with
kind policy_claim in the local intent/review, template object_type policy and
`committed:false` always. GET /v2/networks/{id}/policy-claims/{action_id} reads
that preparation; POST /.../{action_id}/signed takes the common signatures body.

Before signing require exact current public issuer path, owned seed for device
autosigning, latest guard, exact current policy heads/retained maximum and edit
reservation preconditions, and a policy body with THIS host's claim of that capability and
no other-host claim of the same name. Retain explicitly reviewed unrelated
policy content/bounds; inactive bodies supply no authorization. A prior policy
need not still be active to issue a fresh authorized generation, but missing
head evidence requires repair and cannot justify lower fallback. Versions use
the retained maximum, not an active-only view.
The CLI's GET-identical capability preflight signs nothing. Final signature
submission independently verifies the resulting exact policy and current
preconditions. A finished preparation returns its exact statement Base64/dp_
and sufficient catalog including that candidate; no ordinary publication path
is invoked and no policy admission, projection, maximum, edit reservation,
capability or delivery row changes. Only private approved intent/signatures and
the named clock metadata may be retained. A result's committed:false describes
this preparation API, even if its exact bytes are later applied by atomic create.

The existing owner-local capability-create catalogs array carries that exact
signed sufficient DEC catalog per target network. No unsigned policy projection
enters the legacy policies array. Under one transaction, create revalidates
all source/name/owner/host/claim constraints, current authority/expiry/heads/
maxima/reservations and every catalog union, then commits capability plus all
policy/projection/edit/delivery changes or none. A stale preparation cannot
publish a policy before the create fails, and one network's refusal leaves
all networks untouched. This is prepare-only typed policy signing, not an
additional resource permission or arbitrary signing primitive.

### Next-root preparation and exact resolution

`GET /v2/networks/{id}/root-retention` has no query/body and returns exactly
`{network_id,context_id,decision_time,root_head_ids,catalog,candidates,excluded}`
from ONE coherent read snapshot, within the existing32MiB owner response and
inner catalog bounds. Root_head_ids is every known maximal root head, sorted.
Catalog contains exact retained verified public proof closure, including any
historical/inert bodies needed to verify literal references of admitted root
states/candidates. Such a body's presence does not assert its admission or
authority. No private markers or unverified incoming candidates are exposed or
newly admitted. Each candidate is exactly
`{statement_id,kind,required_retained_ids,effective_scopes,effective_not_after}`;
each excluded entry is exactly `{statement_id,code,required_ids}`. Both arrays
are sorted by statement_id, with unique IDs. Required arrays are sorted unique.

Candidates are independently eligible current finite lease/access stream heads
whose exact existing contribution can survive the proposed next-root transition
at this decision time. Required_retained_ids includes the candidate itself and
EVERY needed exact finite AUTHORITY CONTRIBUTION that the transition must carry.
This differs from literal catalog/manifest proof closure: an expired P1 needed
only as predecessor lineage for current P2 is supplied as proof, not retained
as live authority. It excludes root lineage and restrictions, which retain
their own rules. Effective_scopes
keeps the kind's actual role semantics (person/host/policy/group0, binding2,
admin8, device effective mask); it does not reinterpret zero as a device mask.
The exact signed bodies/ancestry in catalog disclose actual subjects/powers.
Effective_not_after is the earliest original/retaining finite deadline, never
an extended promise. For a root fork, use only the authority contract's narrow
all-branches-intersect retention evaluation; no branch becomes current.

Excluded lists known finite stream heads that cannot currently be preserved,
with their actual expiry/revocation/conflict/forbidden or missing-proof code and
exact required IDs when derivable. Missing bytes/unknown eligibility MUST NOT
be silently omitted as if the statement were known ineligible. Missing origin,
root-head closure or invalid private state that prevents a trustworthy preview
returns its structured error instead of an incomplete success. This read
generates no key/intent/signature, fetches nothing and writes no guard, admission,
provider or authority. It is local planning, not signed authority or a guarantee
that later signing/application will pass. Final preparation still revalidates
the complete exact retention set at fixed issued_at AND actual current time.

`POST /v2/networks/{id}/root-transitions` takes exactly
`{new_root_public_key,new_root_signature_format,signature_format,
retained_statement_ids,approve}` and returns the same action result wrapper.
A new_root_public_key of `"-"` explicitly requests an owned new raw root seed;
validate current heads/overflow/retention eligibility before generation, then
persist it in the private create/root-transition secret slot. Otherwise it is
an exact externally owned key; no seed import. New_root_signature_format is
ed25519 for a generated root or the explicitly requested ed25519/sshsig format
for the external new-root PoP. Signature_format selects current-root raw/SSHSIG
slots as above, never a delegated administrator substitute.

Construct the exact normal transition from the unique current root, or the
exact resolution covering every locally known incomparable root head, with
checked next epoch and explicit exact retained_statement_ids. Preview fixes
templates/key/review without signing/applying; repeating the same unresolved
intent reuses the exact pending key/state. A changed target/retention set while
its signed intent may have escaped returns409 operation_conflict. Missing body,
unknown branch or maxu64 refuses before signing/key generation. No timed abort.
The common signed endpoint collects only declared issuer/new_root/root_branch:P
roles. In a fork, a matching held old seed may sign its OWN exact branch role;
other branches/new root use their fixed external slots. This resolution-only
role gate is not a selected current root or ordinary positive authority. Its
review provider has root_state_id `"-"`/scopes0 until resolution; actual role
keys appear in each exact template/slot. Ordinary root-provider GET/actions stay
unavailable during the fork. All root roles verify before atomic application.

Commit accepted root proof/heads/retained admissions, current root metadata,
obsolete owned-seed retirement and exact new owned seed installation together,
with one network.root_rotated event. External SSH new root leaves owned seed
NULL. Local success needs no coordinator acknowledgment. Retry preserves this
exact result/key/retention, never regenerates a competing state/seed at the same
epoch. `network rotate-root ID` and --to-ssh --root-key PATH use this preparation
and fixed slots. `network resolve-root` is removed (DEC-Q19): a root split
freezes the network, and recovery is `network reinvite` (spec 13.2, 14.2).

The native rotate-root/resolve-root default obtains this preview and explicitly
reviews the full union of eligible candidates' required_retained_ids, exact
root heads, preserved powers/deadlines and excluded entries before approval.
Rotation preserves those roles until their existing bounds/restrictions; it
does not revoke them merely by changing the root key. A proof_required entry
blocks this full-set default until repaired, because its possible eligibility
is unknown. `--retain` and `--retain-none` are removed (DEC-Q13): the full
eligible set is always kept.
Never silently erase, truncate or change a rejected selection, choose a branch,
or automatically approve a new set after a concurrent state change. The daemon
root-transitions API continues to require the caller's exact explicit set.

### Contact-invitation minting

`POST /v2/networks/{id}/invitations` is exactly
`{member,expected_person_public_key}` and returns201 exactly
`{network_id,context_id,invitation_id,invitation,expires_at}`. Expected person is
an exact original key or `"-"`. Use the actual owned host and independently
current own-host membership/context; no person/device/root signing endpoint is
called. Generate the bounded current signed contact and psi2 introduction using
its fixed300s lifetime. An unavailable own host key refuses; no replacement key.
The intro claims no admin power, so minting it cannot bypass later current admin
approval; it is not a legacy invite signature/grant/consumption. Exact bytes
are shown only through this explicit owner-local action, not activity/status.
`invite MEMBER` invokes this route and explains the reply-code/admission step.

## 5. Seven-stage linking API and views

The public LINK_VIEW is exactly:

```text
{request_id,role,mode,state,network_id,context_id,migration_proposal_id,
 person_public_key,
 host_public_key,device_public_key,created_at,expires_at,
 request_packet_id,owner_offer_id,selection_id,administrator_offer_id,
 owner_finalization_id,manifest_id,activation_id,outcome_id,
 selection_approved,commit_approved,completed,attention,next}
```

Role is requester or approver, mode new or renew. State is `pending`,
`needs_selection`, `needs_administrator`, `needs_owner_finalization`,
`needs_commit`, `finalizing`, `linked`, `migration_prepared`,
`migration_adopted`, `cancelled`, `expired` or `blocked`.
Migration_proposal_id is `"-"` for ordinary linking or the exact signed staged
proposal ds_. It is part of the signed request payload and cannot resolve or
change later. Unknown other IDs/pins are `"-"`, never null/guessed. completed is an ordered subset of
`request_created,owner_offered,owner_selected,administrator_offered,
owner_finalized,commit_persisted,locally_applied`; attention/next are ordered
public strings. A stage appears only after its verified durable evidence. The exact unchanged
P/H renewal exception skips administrator_offered; it does not invent an admin
packet. Unchanged B still appears through its exact complete manifest proof.
Linked means atomic local complete application, not current network authority
or agent readiness. Exact current failures appear in attention/structured errors,
not by forgetting a completed stage. Expired unsigned attempts preserve identity.
Final commit persisted never changes into an expired/recreated operation.

`GET /v2/link/requests` returns request-ID-sorted `[LINK_VIEW]`;
`GET /v2/link/requests/{id}` returns one. Normal reads/status contain no code,
secret, ciphertext, original key, seed or fixed signing message.

`POST /v2/link/requests` takes exactly `{mode,network_id,person_public_key,
migration_proposal_id,contact_invitation,helpers}`. Unknown new-network/person pins are `"-"`;
Ordinary creation requires migration_proposal_id `"-"`; only the approved
migration/link route below can fix a staged proposal. Contact_invitation is
psi2 or `"-"`, provided privately, helpers is the bounded
public endpoint/key array. Before publication, retain the exact reviewed
invitation under storage's contact_invitation_base64 with the requester attempt.
Owner selection after a restart still checks its immutable member-label,
descriptor/context and person pins; it cannot request the original token again
or learn those expectations from the offer being reviewed. Renew requires exact known network/person/current
host/device and refuses replacement keys. Daemon creates/persists fresh nonce,
secret and owned per-machine device key for new enrollment. Identical live
creation intent reuses the exact pending request; a new explicit attempt after
precommit cancellation uses fresh nonce/secret and an unrevoked owned key as
allowed by the bootstrap contract. Success is201 flat LINK_VIEW plus exactly
`display_code`; exact live creation retry200 same view/code. This route grants
no context adoption or requester consent.

`POST /v2/link/requests/{id}/resume` takes exactly `{}`. It advances only approved
intents, verified incoming evidence, exact publication retries and application.
It never selects an offer/commits for a requester. Return200 flat LINK_VIEW;
explicit still-pending local resume alone additionally has display_code. Terminal
resume has no code. For an already locally applied operation, explicit resume
MUST attempt the bootstrap contract's exact complete public POST publication to
all other original transcript participants within one overall30s bound, even
when earlier delivery was acknowledged. It returns the same linked result plus
actual transport attention if unreachable/refused; it creates no new consent,
sender signature, key, secret, guard/provider/authority-event/outcome change.
Bounded transport scheduling/error observations retain storage section9's rules;
signed/protocol timestamps and applied_at remain exact. Owner-local GET and
exact application/commit retries remain historical pure reads without I/O.
Background and explicit polling share successful-poll
state/budget: reuse a successful exact host+locator read for2s only while the
clock has not rewound and code fingerprint/actual transport pins still match.
Still revalidate current intent/authority and process already durable frames.
First/expired/failed reads are not cached; actual remote429 remains visible.
Schedule aggregate helper reads across all local pending requests, not a fresh
rate bucket per locator/connection. An unneeded GET never establishes freshness. `POST /.../{id}/cancel` takes `{}` and returns LINK_VIEW;
precommit cancellation erases secret/frame ciphertext but keeps the public
bounded tombstone. Persisted final commit cannot be cancelled as uncommitted.

### Owner, administrator and finalization reviews

`POST /v2/link/approvals` takes exactly `{code,network_id,person_public_key,
provider_id,signature_format,scopes,not_after,expected_host_public_key,
expected_device_public_key,approve}`. Code arrives from hidden prompt/stdin, never command arguments.
The owner is the exact selected original person; provider resolves original or
same-person device. For an already admitted owner, scopes default in CLI to 15
capped by the actual path. For an unadmitted new original person, the requested
scopes default to 7; this is a proposed target mask, not preview authority or a
promise of future administrator scope8. An explicit mask remains subject to the
actual current signing path at each later review/signature/application stage.
For native link approve, omitted Not_after defaults to the earliest signed
request.created_at+7d/all actual finite ancestors. The exact signed request
creation time makes unchanged preview then approval deterministic. Explicit
--not-after remains exact, and the API still requires a fixed value. This is
only a conservative CLI default; new lease issuance keeps actual guarded time,
the ordinary issued_at+7d ceiling and every parent's earlier deadline. A changed
path/ceiling requires review rather than reusing old consent or widening expiry.
The possession-only preview's scopes0 does not make the requested
mask0 and does not authorize any ordinary provider work.
An unadmitted new original person first supplies a typed possession-only owner
offer from its own machine: reviewed psi2 descriptor/context/label/person pins,
root_state_id and person_lease_id `"-"`, issuer IDs empty. Its preview provider
has kind original_person, that exact person/host, root/lease/device `"-"`, scopes0
and not_after `"-"`; this is NOT a usable normal provider. The administrator
then supplies the independently verified actual current root/P/H. Only after
that can the invitee's exact original key consent to pending self B/D; final
owner/manifest/root fields are concrete and locked. Existing persons cannot use
this exception, and inviter/admin never substitutes for the new person's key.

`POST /v2/link/admissions` takes exactly `{code,network_id,person_public_key,
provider_id,signature_format,owner_offer_id,selection_id,
expected_host_public_key,expected_device_public_key,approve}`. Person pins the TARGET owner, while provider
is the actual current local administrator/root, potentially another person.
No target-owner substitution chooses the administrator's key. Root is explicit
provider_id network_root. Current scope8+admin/person/path is mandatory for an
admin device. For RENEW only, exact unchanged CURRENT P/H leases allow the administrator
packet/ID to be `"-"`, avoiding an unrelated scope8 requirement. Any P/H change
requires the ordinary current root/admin stage. Renewals still have explicit
owner-finalization and requester PoP/final consent.
The native link admit command recommends network_root as its explicit default
--signer and displays that root choice in help and the typed default-no review.
It sends literal provider_id network_root; this is not daemon auto selection or
a fallback after a failed selected provider. --signer auto remains an explicit
supported choice for the independently current selected administrator/device
path, including operation without the root key. A shorter actual admin-path
ceiling remains enforced; neither mode silently changes the owner offer.

`POST /v2/link/requests/{id}/finalization` takes exactly
`{owner_offer_id,selection_id,administrator_offer_id,network_id,context_id,
person_public_key,host_public_key,device_public_key,approve}`. It prepares the
exact owner-finalization B/D templates after independently verifying those
admin P/H parents (or the exact unchanged current P/H renewal proofs), selected
terms, current path and fixed lifetime. Unchanged current B on renewal is an
exact complete binding ds_ reference, requiring no new scope2/host signature;
changed B requires owner2+host consent, and D issuance still needs original owner
or current strict ancestor4. An expired target D is never an issuer. An approved
owner intent may preauthorize this bounded later step under its already reviewed
terms, so resume can materialize dependency-ready slots; it cannot widen terms
or choose another owner. This owner-finalization preapproval uses its actual
owner authority, including device scope4 and scope2 for a new/changed binding;
it does not require scope8 or preapprove administrator work. Any changed term
requires explicit fresh review. Requester final consent remains separate.

All three routes return exactly `{request,review,signing_requests}`. Review is:

```text
{stage,network_id,context_id,person_id,person_public_key,host_public_key,
 device_public_key,root_state_id,provider,owner_offer_id,selection_id,
 administrator_offer_id,person_lease_id,host_lease_id,binding_lease_id,
 device_lease_id,scopes,not_after,authority_warning}
```

Authority_warning is a nonempty public explanation, or `"-"`; profile15
explains conditional admin8, self-trust/access and approving more machines.
Stage is owner/administrator/owner_finalization; person_id is the existing
stable derivation of the exact TARGET original key. Provider identifies actual
signer, not necessarily target owner. Not-yet-defined references are `"-"` only
in a preview; dependency-ready templates fix them before any signature. Preview
signs/publishes nothing. Approval pins every supplied exact identity/term, then
persists approved intent before generating signatures. A wrong network/code/
expected key is400 invalid and changes no approval/publication/consent. Incoming
independently valid transport can be cached without granting intent. A cached
code never skips actual network checks.

`GET /v2/link/requests/{id}/approval` is read-only and returns that same wrapper
for persisted approved approver intent/ready slots; otherwise409 state_conflict.
It cannot materialize a template or approve anything. Resume may materialize a
new ready finalization/admin slot only after exact dependency/current checks.
`POST /v2/link/requests/{id}/signed` uses the common signatures body and returns
that wrapper; only persisted approved ready slots are accepted. No arbitrary
message, unknown signer, alternate root or private-key import is supported.

A same-review owner can preapprove its later admin work only if that EXACT
selected path currently has scope8/admin authority; all identity/terms stay
locked and later signing rechecks authority. Otherwise a distinct administrator
review is required. Attempting an alternate admin/root after the locked review
returns409 state_conflict before template/signature/publication. No role fallback.

### Two independent requester confirmations

`POST /v2/link/requests/{id}/selection` takes exactly
`{owner_offer_id,network_id,context_id,person_public_key,host_public_key,
device_public_key,approve}`.

`POST /v2/link/requests/{id}/commit` takes exactly
`{owner_offer_id,selection_id,administrator_offer_id,owner_finalization_id,
network_id,context_id,person_public_key,host_public_key,device_public_key,approve}`.

Both return exactly `{request,review}` with the same review field set above;
stage is selection/commit, provider is actual selected owner, and commit review
has every exact P/H/B/D and manifest dependency ready. Missing references can be
`"-"` in preview only; approval requires all exact pins, except the literal administrator ID `"-"`
under the unchanged-P/H RENEW exception. Selection creates only
its own signed device/host packet. Commit separately verifies every signature,
parent, restriction and actual target-host binding signature (or exact prior
complete unchanged B proof on renewal with commit signature `"-"`), then fixes exact
manifest/final consent before first publication. A later admin/owner_finalization
packet never implies commit consent. Both new and renewal require both stages.

A fresh requester may have no admitted network state when reviewing a complete
existing admitted-person owner offer. For selection preparation only, verify the exact selected owner's
current P/H/B binding path and actual issuer ancestry from the supplied signed
closure, without requiring those same bodies to have been admitted on this new
requester in an earlier import. Preserve the bound-original requirement; a
device issuer still requires its complete verified activation/retention basis.
Check the frozen descriptor/root and requester pins, current validity, every
typed signature/role/parent/scope, all known local heads/maxima/restrictions and
the guarded decision time. This is a bounded verification result for that exact
owner offer, never a new ordinary same-batch admission rule.

Preview and selection may retain exact incoming evidence only as private pending
data; they commit no authoritative next_prior, admission/head/maximum, network,
member, policy, selected provider or application. Preview grants no consent.
Explicit selection approval fixes only its own consent and host/device packet;
final commit remains separate and default-no. Missing actual bytes reports their
exact required IDs; complete but unusable authority reports its actual denial,
not an empty proof_required merely because the requester has no prior admission.

For selection and final commit, explicit approval first commits the exact
reviewed typed intent and its own consent boolean/reference. Only after that
transaction commits may the owned keys generate the fixed packet/binding
signatures. Commit exact generated/submitted signature batches and any newly
completed packet in subsequent signature transactions before encryption; commit each exact sealed
outbound frame in a subsequent transaction before transport. Apply the same
approval-before-signature and signature-before-encryption order to owner,
administrator and owner-finalization work. All stages use their already fixed
terms/current checks; resume can continue an approved unfinished stage but
cannot approve it, rewrite templates, extend its window or choose a new signer.
An approved boolean without a complete packet is displayed as pending signing,
not a completed stage or escaped final commit. GET remains read-only. The
requester-only private provider and packet templates are not external signing
requests and confer no network authority. Request/selection/commit response
shapes and the two independent default-no confirmations stay unchanged.
Each dependency-ready typed template is itself durably fixed before generating
its signatures. For a new binding, first retain its exact host signature, then
fix the resulting exact manifest/commit template before commit-packet signing.
No dependency arrival changes the already approved terms or supplies consent.

The separately specified new-original-person possession-only offer remains
selectable before administrator admission. Its root_state_id/person_lease_id
are `"-"` and issuer IDs empty: verify the exact original-key possession
signature and reviewed psi2 descriptor/context/label/person/requester pins.
Those placeholders supply no current root, membership, binding or reusable
authority. This exception does not apply to an existing admitted-person offer.
Once supplied by administrator/finalization, the concrete P/H/B/current-root
and issuer paths must pass their normal checks before later signing/application.

Selected: scoped current owner-path verification for cold preparation, preserving
binding and all known restrictions. Discarded: an unbound person-only shortcut,
fabricated prior or a second import to gain authority, general same-pass policy
admission, and selection/resume as network adoption or final requester consent.

An identical approved retry reuses exact IDs/bytes. A competing first consent
pin is400 invalid; conflicting already-persisted final operation/retry is409
operation_conflict. Complete exact outcome retrieval follows the historical
bootstrap-return rule, does not reapply state or replace a newer signer, and
never claims the old grant is presently usable. Raw pairing-secret cleanup and one network.link_applied event occur atomically
with first local application. A separate32-byte terminal read_cap and already
sealed needed outcome frames may survive only to exact frame storageack/request
expiry, under bootstrap bounds; no decryptkey/reseal/public exposure. Public
exact operation history survives and secret-free participant retries remain.

First application fixes outcome time/root only after the final transaction's
actual guarded authority/adoption checks. Its bounded host outcome signature,
optional terminal-frame sealing and secret retirement share that atomic commit
with state/provider/event changes. Earlier capacity preflight or a paused
before-transaction hook supplies no applied timestamp/outcome. This application
exception does not merge the earlier requester/approver approval, signature
and frame phases or add consent on resume.

## 6. Native commands and guided setup

Both CLIs retain network create/invite/join/list/members, link/approve/admit/
resume/status/cancel/select/commit and existing access/capability commands.
New `link finalize REQUEST_ID` drives the exact owner-finalization review/slots.
It has the same exact reference/key flags as finalization's body, and `--approve`
is explicit; omission previews. `--network`, `--expect-person`,
`--expect-host-key`, `--expect-device-key`, `--owner-offer`, `--selection`,
`--administrator-offer` and `--owner-finalization` map directly to their named
fields. No bare --yes authorizes linking. Code/token inputs use hidden TTY or
--code-stdin/--invite-stdin, or an explicit private input file, never argv.

`invite MEMBER` produces psi2 contact/approval introduction, not membership;
`join` verifies/reviews it before choosing/generating an original person and
returns the psl2 request plus the explicit return-code/approval next step.
It is a pending success envelope/nonzero until actual local linking completes,
never a misleading admitted/bound result. Existing identity/key selection and
source/private-file permissions remain. A same-person `link` creates a device
request without asking to copy/generate an original-person key. An original
person is selected only on its own original machine or explicit new-person join.

Interactive `link`/`link resume` show exact owner selection and final complete
manifest terms separately; questions remain `Select this exact owner offer?`
and `Commit this exact machine link?` with y/N in brackets or parentheses.
Blank declines; only trimmed case-insensitive y/yes approves. JSON stdout is
always the flat LINK_VIEW, with display_code only for the explicit allowed
requester display action. Auxiliary approval wrappers are internal, never the
final CLI output. Incomplete work and every refusal exit nonzero with exact
public next action; human prompts/guidance use stderr. No prompt may approve a
mutable subsequent packet or regenerate an escaped final commit.

`up` preserves existing setup/profile/service behavior but uses these new-mode
APIs. Fresh create needs no coordinator. Fresh join/link uses the explicit
handoff above and cannot attach an agent until the request is independently
linked and the actual provider is usable. Automatic pending up does not redisplay
a pairing code. Either default-no decline returns incomplete/nonzero with the
same request and no create/join fallthrough, person replacement, service rewrite
or attachment. Fresh explicit link choice may display its private code once
on its TTY. Migration pending/expired/forked authority reports repair for the
same identities and keeps profiles/credentials intact.

Keep current up-only exact-profile reuse: reject known explicit incompatible
settings before trust/enrollment; omitted expiry inherits the saved profile.
After membership/service gates verify actual credential/session/connection.
Ready+attached reuse skips duplicate launch; offline+recoverable preserves the
attachment and reports incomplete launch unless --no-start requested. Nonempty
harness args cannot be silently dropped by a reuse-without-launch path. Explicit
attach behavior, actual adapter readiness handshake and live-task evidence stay
separate. Linking/transport success cannot create adapter_ready/model success.

## 7. Explicit migration preparation and adoption

Migration uses only the complete public migration contract: current legacy-root
proposal/source endorsement, all-known-host roster/acks, original-person new
transcripts, exact prepared hash and final migration_commit. These routes do
not infer consent from schema upgrade, a public proposal, old device authority
or another participant's receipt. They add no fresh legacy enrollment pathway.

MIGRATION_VIEW is exactly:

```text
{network_id,proposal_id,context_id,state,source_catalog_sha256,
 source_state_sha256,prepared_catalog_sha256,root_state_id,
 local_acknowledgment_id,root_commit_id,missing_host_keys,required_proof_ids,
 approved,fenced,expires_at}
```

State is needs_approvals/prepared/acknowledged/adopted/conflict. Unknown values
are `"-"`, arrays sorted unique; public hashes are exact source/prepared bytes.
The review wrapper is exactly `{migration,review,signing_requests}`. Review is:

```text
{stage,network_id,proposal_id,legacy_root_public_key,legacy_epoch,
 new_context_id,roster,source_catalog_sha256,source_state_sha256,
 prepared_catalog_sha256,authority_warning}
```

Stage is identity/proposal/participation/acknowledgment/root_commit/adoption;
roster entries have the exact public proposal shape. The warning discloses the
original-key/all-known-host availability cost, finite deadlines and durable
fence with no timeout abort. No secret/root seed appears in these responses.

| Owner-local route | Exact request | Success |
| --- | --- | --- |
| GET /v2/networks/{id}/migration | No query/body |200 MIGRATION_VIEW; before preparation needs_approvals with proposal/context `"-"` |
| GET /v2/networks/{id}/migration/evidence | No query/body |200 exact existing peer evidence shape below from one coherent retained snapshot;404 not_found before a real signed proposal |
| POST /v2/networks/{id}/migration/identity | `{scopes,approve}` |200 `{migration,identity,review,signing_requests}`; identity is this host's exact proposal roster entry |
| POST /v2/networks/{id}/migration/prepare | `{roster,signature_format,approve}` |200 review wrapper, current legacy-root proposal/initial-root ready slots |
| POST /v2/networks/{id}/migration/review | `{proposal_id,approve}` |200 review wrapper for exact source/proposal/roster/new context |
| POST /v2/networks/{id}/migration/host-lease | `{proposal_id,host_lease_base64,approve}` |200 exact host-membership preparation wrapper below; own unbound host only |
| POST /v2/networks/{id}/migration/device-bans | `{proposal_id,person_public_key,approve}` |200 exact inherited-device-ban review wrapper below; original-person copy-only preparation |
| POST /v2/networks/{id}/migration/link | `{proposal_id}` |201 flat LINK_VIEW plus display_code for this explicit local staged requester creation; exact retry200 |
| POST /v2/networks/{id}/migration/evidence | `{proposal_base64,source_catalog_base64,source_state_base64,prepared_catalog_base64,acknowledgments_base64,commit_base64}` |200 review wrapper; exact same evidence fields as peer exchange; proposal_base64 required, commit_base64 `"-"` or canonical Base64 of the exact statement |
| POST /v2/networks/{id}/migration/acknowledgment | `{proposal_id,prepared_catalog_sha256,approve}` |200 review wrapper, exact own host/device ack after complete prepared review |
| POST /v2/networks/{id}/migration/commit | `{proposal_id,prepared_catalog_sha256,acknowledgment_ids,signature_format,approve}` |200 review wrapper, only current legacy root's exact final commit slot |
| POST /v2/networks/{id}/migration/adopt | `{proposal_id,commit_id,approve}` |200 `{migration,network}`; network null until adoption, else NETWORK_VIEW |
| POST /v2/networks/{id}/migration/resume | `{}` |200 review wrapper; advances only persisted approved work and ready signatures/adoption |
| POST /v2/networks/{id}/migration/signed | common exact intent/signatures body |200 review wrapper; only previously approved ready migration slots |

Signature_format is frozen auto/ed25519/sshsig current-legacy-root selection,
with explicit external SSH slots permitted without daemon key import. All
owner responses obey32MiB; evidence request whole20MiB, inner bounds unchanged.
Prepare/ack checks the final1MiB composite migration bound (and source/prepared
sub-bounds) before committing an irreversible approval/fence; oversized origins
require sufficient exact reduction, never omitted roster/facts or a stuck ack
for an already known impossible envelope. A first owner-local public-file import MUST include the exact signed proposal,
frozen original source catalog and source-state bytes, even before local review.
Validate their network/root/signature/hash/bounds, retain only as unapproved
migration preparation, then permit the separate explicit review. A later exact
evidence import preserves those fixed source bytes; changed source/prepared
identity conflicts. It never manufactures consent, acknowledgment/fence,
authority or adoption. No caller-supplied provenance is a trusted prior row.

For local-known compatibility and same-proposal resume, use the migration
contract's strict decoded descriptor/source-state and exact catalog-body tuple
comparisons. Do not compare hashes of an independently reserialized local
wrapper with the original endorsed source hash. The original proposed bytes,
nonce, keys, source hashes, approved review and every fixed template/signature
remain exact across Go/Rust reopening; genuine changed facts still fail their
ordinary coverage/conflict/repair checks. No semantic comparison applies to
the original signed proof body or a declared source/prepared/commit hash.

Owner-local evidence GET exports exact original public proposal/source/prepared/
acknowledgment/commit bytes in the peer evidence shape, at most32MiB with every
inner bound unchanged. Unknown later proof fields retain that shape's `-`
convention; a nonexistent proposal never creates a descriptor/catalog/source.
It signs/generates/fetches nothing and exports no private key, seed or credential.
No intent, approval, fence, guard, admission or provider changes. After adoption
it exports ONLY the immutable original transition snapshot, never later DEC
catalog/contact/authority additions. Existing source/prepared/transition
conflicts remain409. Exported wrappers confer no trust or remote local consent.
This is the explicit public-file handoff path; do not read/copy daemon TLS keys
or reconstruct a signed proposal's nonce/bytes from a review summary.
Selected: owner-local export of the existing exact public evidence carrier.
Discarded: inventing a second envelope, exporting daemon keys, direct database
extraction or relying on a review summary to reconstruct signed bytes.

Identity preview derives exact current own host/member/person and old selected
device from verified source; it generates nothing. Approval may generate an
owned device key ONLY if none previously existed, preserving old person/key/
scopes otherwise. No old delegated signature substitutes for original approval.
When a bound host has no prior device and has not approved its contribution,
preview uses device_public_key `-` and the explicitly requested valid positive
scopes; this is a visibly incomplete review, not a publishable proposal entry.
Approval fixes the one real device key. For an existing selected device,
requested scopes must equal its exact preserved scopes; an unbound host requires
scopes0 and person/device `-`. Mismatching requests return409 operation_conflict.
The approved own roster contribution is handed to the proposer through exact
known-participant exchange or an explicit public file, not a key copy.
Before a proposal exists, persist that contribution only as the storage
contract's nonsigning migration_identity intent. It is not a proposal,
selected provider, signature approval, acknowledgment, fence or adoption.
Repeated approval/restart returns the same reviewed tuple and any one generated
pending device key; elapsed review time cannot replace it. A changed tuple
returns409 operation_conflict. An unbound host approves its host-only entry
without inventing an original/root/device signer. Subsequent source/proposal
verification must still match the same own identity and preserve existing
selected-device keys/scopes. A missing approved contribution cannot be inferred
from another machine's roster or from possession of the host key.
The preproposal MIGRATION_VIEW keeps proposal/context/hashes/root/ack/commit/
expires_at `-`, missing arrays empty, approved:false and fenced:false; those
booleans describe proposal participation, not the separate identity approval.
Prepare requires the exact complete known roster and source/current root;
changed/omitted known facts block it. Review approves staged participation only;
it does not yet sign an acknowledgment or adopt the new context.

### Exact unbound host-membership handoff

An unbound roster host needs its own signature on the root-issued finite host
lease before the prepared catalog can be fixed. This uses the owner-local
host-lease route above, at most2MiB whole request with at most1MiB decoded exact
template bytes. The template is the exact proposed host_lease envelope with
the valid current legacy-root issuer signature already fixed and only its
declared raw local host signature `"-"`. It is not a public catalog object yet.
The proposer exposes that exact template through the existing ready host-role
SIGNING_REQUEST ONLY after its issuer signature is durably fixed. A public file
can carry those template bytes to the target's own administration socket;
there is no remote arbitrary-signing route or daemon-key export.

The target verifies its actual owned host key, approved proposal/source,
unique approved own identity contribution, exact unbound roster member and
the inert initial root. Require operation_id equal to this proposal ds_,
sequence1, no predecessors/resolves/retained IDs, root issuer, no finite parents,
person/device `"-"`, scopes0, exact target/member, and the ordinary finite
interval/7-day ceiling. Recheck source/root/restrictions, guarded NOW and the
proposal signing window before each new signature. Its issued_at must be within
the proposal's inclusive issued_at..expires_at range; at the target's signature
decision the host lease must already be within its valid finite interval and
unexpired. The target signs strictly before proposal expiry, as required for
all incomplete preparation. A bound or foreign host,
ordinary operation, changed root/proposal/tuple, alternate issuer or extra
signature role is refused; possession of the host key alone is insufficient.

Response is exactly `{migration,host_lease_base64,review,signing_requests}`.
Host_lease_base64 returns the exact supplied partial template until completed,
then the exact fully signed body. Review is exactly:

```text
{stage:"host_membership",network_id,proposal_id,host_public_key,member,
 root_state_id,host_lease_id,issued_at,not_before,not_after,authority_warning}
```

It discloses the exact finite membership and that no person/device ownership,
acknowledgment/fence or active authority follows. Preview writes/signs nothing.
Explicit approval first durably fixes the exact typed review/template/intent;
only a later transaction may sign its actual owned host role and persist the
fully verified body in prepared evidence. Signing_requests is empty: the target
never offers this owned key as an external slot. All signatures and the original
issuer bytes remain exact. Repeated same-template requests return the same
intent/body; resume advances only that fixed approved intent and completed
evidence, without another consent or template. A changed template after
approval is409 operation_conflict.
GET migration evidence exports the completed body through its existing partial
prepared catalog; the proposer imports it through the same evidence route.
Never insert partial signatures into a public catalog, regenerate a lease on
retry, or claim the shared prepared hash before all components are complete.

No fence, acknowledgment, active context/provider, ordinary activation/outcome
or authority event is created by this preparation. The separate acknowledgment
approval still pins the full prepared catalog and uses the storage contract's
own host-only or exact staged-device selector. Both recheck the full prepared
catalog, own review/actual host key and final guarded source/restrictions. An
unbound host requires its exact complete issuer+host signed host lease and has
no activation/device; ONLY an owned host additionally requires its complete
prepared activation and actual matching device seed. The exact acknowledgment
and fence are durable before publication. Neither selector grants a reusable signer.

### Original-person copies of inherited device bans

The device-bans route makes the migration contract's existing restrictive-copy
rule usable before adoption. It accepts no caller-supplied targets or arbitrary
statement body. Independently verify the exact locally approved proposal/source,
current legacy root, endorsed applicable restrictions and admitted sticky bans.
Select ALL required stable-device bans for this exact still-admitted original
person. An unkept inactive legacy signature alone does not qualify. A permanently
removed person retains its old device-ban history and root person ban; this
route cannot restore that person's positive path. Missing exact original proof
is proof_required with its ID; targets outside that selected person's exact
source-derived set and persons not source-admitted are forbidden. The selected
person may differ from the local writer's roster person: this is external
original-person signing on its own existing machine, never a binding assertion
or permission for the daemon to select another key.

Require the exact proposal-bound initial root and its one shared pending
person_lease for that person. These are inert staging facts, never a selected
provider. Each generated copy is the ordinary device_revoke schema: exact
root_state_id, issuer.kind person and matching original person, its required
issuer_person parent equal to that shared person_lease, only person/device
target fields, statement/host target `-`, kept_statement_ids empty and ratifies
`-`. Its sole issuer signature uses that original person's SSHSIG. No device,
host, root or administrator substitutes that signature, and no new target ban
can be introduced through this route. If no copy is required, return an empty
copy list with no intent or signature.

Response is exactly `{migration,review,signing_requests}`. This route's review
is exactly:

```text
{stage:"inherited_device_bans",network_id,proposal_id,new_context_id,
 person_public_key,root_state_id,person_lease_id,source_catalog_sha256,
 source_state_sha256,
 copies:[{device_public_key,source_proof_ids:[LEGACY_PROOF_ID],statement_id}],
 access_maxima:[{kind,subject,version,message_hash}],
 authority_warning}
```

Copies are sorted/unique by device key; each source_proof_ids list names ALL
exact applicable original proofs for that stable target, sorted/unique. Arrays
and full-u64 access_maxima use the source snapshot's existing strict bounds and
order. Access_maxima contains ALL exact source snapshot rows, without a
person-specific filter. Retain the4096 limit and complete migration's1MiB preflight; at most16 ready
signing slots are returned per batch. The warning discloses the exact inherited
irreversible bans, inert staging and absence of acknowledgment/fence/adoption.
Preview writes/generates/signs nothing, exposes no ready slots and shows copy
statement_ids `-` until their templates are durably fixed. Approval fixes the exact
typed review, original selector, source/proposal/root/person pins, actual guarded
issued_at and template bytes in a kind migration intent before any signature.
All templates in that intent are ONLY these required device_revoke copies.
Use operation_id equal to the proposal ds_, original provider with lease_id `-`
and signature_format sshsig, scopes0, device_public_key `-`, secret SQL NULL.
Host_public_key is the actual local writer, not the target device's old host;
not_after and result_base64 are `-`, expires_at is the fixed proposal deadline.
There is at most one such approved copy intent per proposal/person; find it by
those exact pins and template kinds, never a latest-intent rule.

Common migration/signed and resume can fill ONLY those approved exact original
slots, in dependency order, after rechecking actual source/root, pending person
head, known restrictions and guarded current time. This copy-only intent fixes
created_at/issued_at at actual approval and expires_at at the original proposal
deadline. New signatures require issued_at <= NOW < proposal.expires_at, with
the exact shared person head already valid and unexpired; no additional300-second
action-intent age limit applies to this narrow already-endorsed copy set. Neither
retry nor later signature refreshes a timestamp, target, source or deadline.
The original key remains on its existing machine. For this copy intent, signed
and resume return the same inherited_device_bans review variant when exposing
its ready slots or completed copies; ordinary MIGRATION_VIEW status is unchanged.
Completed signed copies enter only prepared evidence, retaining exact original
templates/signatures across retries/restart. Changed approved targets, proofs,
source or template pins conflict and never inherit approval. No active context,
provider, admission, ordinary restriction event, acknowledgment or fence follows
from these signatures. Normal actions still require ordinary adopted authority.

The existing root prepare similarly includes required stable-person/host ban
copies under the exact proposed root and approved source. It cannot sign a
device copy or expand the inherited target set. Complete prepared validation
still requires every applicable inherited ban before any acknowledgment.

Selected: one typed copy-only original-person preparation route using existing
bounded migration intents and signing submission. Discarded: hand-authoring
proofs, root/device substitution, dropping inherited restrictions, activating a
pending person to reach ordinary actions, generic unsigned statement imports,
new intent kinds/tables or introducing unrelated fresh denies during migration.
Also discarded: stranding a uniquely approved exact copy intent after300 seconds,
refreshing its signature time to hide that delay, filtering source maxima by
person, or restricting the external original signer to the daemon's own owner.

### Owned staged bootstrap and whole-migration completion

Staged original-owner preparation applies only the migration contract's narrow
exact preexisting-device-profile cutover cap: conditional nominal8 may be
preserved without minting an admin role. Ordinary owner preparation, no-prior-
device profiles and every current role/power/consent check retain their rules.

Migration/link requires the exact locally approved proposal and roster tuple.
It writes request migration_proposal_id and uses the same original seven-stage
protocol with the same existing keys, request mode new, original-person owner
slots and the narrow migration staging authority rule. Ordinary link/approval
cannot infer staging from a matching network ID or a supplied unapproved proof.
When final requester commit is complete, state is migration_prepared. Retain
it as UNRESOLVED active-quota work: no active context, dec_signers installation,
participant outcome, network.link_applied event, timeout abort or evidence
cleanup. Its exact public activation supplies prepared evidence only. Normal
bootstrap POST activations refuses staged application/outcome even if every
per-host packet is present; it cannot bypass all-host/root final migration.

Gather complete stage proofs and acknowledgments through the exact evidence
route, apply staging validation only, and fix the prepared catalog hash before
acknowledgment. Only the separate explicit ack request approves that exact full
hash and durably fences the old network. Resume never supplies that consent.
After all exact acks, root commit is another explicitly approved root typed
statement, persisted before publication. An existing ack preapproves eventual
exact adoption; resume can adopt once complete valid evidence exists, without
inventing another mutable consent or clearing a fence by absence/timeout.

An acknowledgment POST with approve false is typed preparation. It may persist
ONLY one exact unapproved migration_ack intent/template, its local_ack_intent_id
reference and the named monotonic decision-clock update. Approved remains false,
approved_at `-`, signatures empty, completed false and secret SQL NULL. It must
not create an acknowledgment, fence, consent, provider, public authority, event
or adoption, and exposes no ready owned-key signing slot. Exact retries keep
that fixed template; any later signature still requires separate durable
explicit approval and current full prepared/source/clock checks. A completely
read-only acknowledgment preview is also permitted. This bounded preparation
permission does not relax the separately explicit write-free identity,
host-membership or inherited-device-ban previews, or any GET's read purity.

The root commit POST with approve false has the same bounded typed-preparation
choice: it may remain read-only, or persist only its exact unapproved
migration_commit intent/template, that intent's entry in root_intent_ids, and
the named monotonic decision-clock update. The template fixes this proposal,
initial root, exact prepared hash, ALL exact retained acknowledgment IDs and
committed_at within the original signing window. Its root selector and source
remain exact. Approved is false, approved_at `-`, signatures empty, completed
false and secret SQL NULL; no ready signature slot or public commit appears.
The existing acknowledged fence and all participation/identity approvals remain
unchanged. No new consent, signature, event, provider, active authority or
adoption follows. Exact retries reuse the fixed intent/template. A later root
signature still requires separate durable explicit approval and the current
source/root/all-host/prepared/clock checks. No other row change is permitted.

Complete adopt atomically writes exact mode/context/origin, retained floors/
restrictions/proofs and activation admissions with basis migration, actual
usable selected device if eligible, public migrated state and one
network.migrated event. No per-host participant outcome/network.link_applied is
fabricated, including for expired prepared authority. Per-host pending view
becomes migration_adopted terminal history, not ordinary locally_applied stage.
An expired planned device remains the same identity with repair, never original
fallback/new key. `up` directs migration_prepared to whole-network migration
resume, and after adoption rechecks actual current authority/provider before
attachment; it does not ordinary-link-apply the old stage.

Known source participant hosts can exchange staged public evidence on GET/POST
`/peer/v2/networks/{id}/migration`. GET returns exactly
`{proposal_base64,source_catalog_base64,source_state_base64,prepared_catalog_base64,acknowledgments_base64,commit_base64}`,
where unknown byte fields are `"-"` and acknowledgments_base64 is always an
array. POST takes that same exact body, whole20MiB, and returns the current same
shape. Every present string is strict canonical standard Base64 of the EXACT
original decoded component, including JSON spelling/whitespace. Decode each
component under the migration contract's handoff bounds; preserve those bytes
through every read, storage, file/client handoff and export. Sort ACK strings by
the independently decoded roster host key. The wire wrapper may be reserialized
without changing any component. Reject old inline fields, unknown/duplicate
fields, noncanonical Base64, malformed/wrong-kind decoded objects and changed
declared hashes. Do not deserialize and then reserialize a component before
hashing or storage. Full composite M construction keeps its existing schema.
Owner-local evidence GET/POST and peer GET/POST use this one carrier. The actual TLS key must be a known
unrevoked admitted source host under independently verified local legacy/source
evidence, not recent coordinator sync or a submitted proposal's unsigned roster.
The explicit migration fence permits ONLY this narrow state exchange, not fresh
legacy work. Returned candidates remain untrusted until exact source/proposal/
staging/ack/commit verification. Receiving them never supplies local reviews or
adoption. Unknown peers stay bootstrap-only. Complete post-adoption migration
origin travels as its ordinary composite in DEC catalog replication; no old
coordinator is a new-mode authority.

After adoption the migration exchange cannot accept another source proposal or
import current DEC changes through old-source authorization. A roster host
whose exact acknowledgment is in the retained complete transition may still
GET that immutable ORIGINAL source/prepared/ack/commit snapshot, or exact POST
retry may return the same snapshot. This archival participant read is allowed
after expiry; it sends no later catalog, contact, permission or readiness facts
and applies nothing. Changed immutable transition identity is409
operation_conflict. It allows an approved offline participant to obtain the
already complete transition, not to bypass current DEC action/repair gates.
The ordinary local adoption checks/retained restrictions still apply afterward.

The `network migrate` commands and the `/v2/networks/{id}/migration` routes are
removed (DEC-OWN3, DEC-S12): in-place migration of a coordinator network is no
longer offered. Legacy networks stay read-only history (spec 14.1) and move with
`network reinvite` (spec 14.2).

## 8. Authenticated peer replication and narrow proof repair

Normal peer transport still authenticates the actual pinned host key, then
requires independently current member authority for this context before serving
network state/actions. No unknown peer can gain entry by submitting a catalog.
Exact contact signatures/DNS/relay keys never replace this gate.

| Peer route | Request | Success |
| --- | --- | --- |
| GET /peer/v2/networks/{id}/catalog | No query/body |200 `{catalog:CATALOG}`; whole response at most 20 MiB |
| POST /peer/v2/networks/{id}/catalog | Exact `{catalog:CATALOG}`; whole request at most 20 MiB |200 `{catalog:CATALOG}` full verified union, at most 20 MiB |
| GET /peer/v2/networks/{id}/contacts | No query/body |200 `{contacts:[SIGNED_CONTACT]}`; host-key/sequence ordered, at most 1 MiB |
| POST /peer/v2/networks/{id}/contact | Exact `{contact:SIGNED_CONTACT}`; at most 16 KiB |200 `{contact:SIGNED_CONTACT}` for the actual TLS writer host |

Check sender against the independently verified PRIOR local state before union.
A currently admitted host can carry its own valid withdrawal; after commit it
loses ordinary route eligibility. Independently verify exact candidate bytes,
retain all local restrictions/conflicts/maxima/operations, classify fresh versus
historical evidence, then atomically admit the allowed union/outbox/projection.
No unsigned peer map, omission, stale root, lower policy or advertised contact
can erase known state. Every newly admitted grant/restriction obeys its exact
current first-admission rule. Unrelated valid restrictions remain ingestible
despite another stream's fork. Replication must not normalize signed payloads.

Proof fetching is a SEPARATE ALPN/router `peerspan-state-repair/1` over TLS.
The server accepts only an exact host key already durably remembered as a
previously independently admitted member of the requested context, and not a
known permanently revoked host. Contact-only/manual-known keys do not qualify.
The client likewise pins a previously admitted peer key. Unknown hosts remain
bootstrap-only; normal peer routes are never opened through this exception.

Its only route is GET /repair/v1/networks/{id}/catalog, no query/body, returning
200 exactly `{catalog:CATALOG}` at most 20 MiB. Expired/missing-own-retention
callers may fetch these public proofs; no task, directory, contact, local-admin,
signing, arbitrary import or permission route is exposed. This deliberately
permits authority-proof disclosure to a remembered unrevoked former member for
repair, not ordinary action authority. Actual known host ban returns403;
unknown context/key fails without data. Apply bootstrap socket/header/timeout/
request-concurrency bounds, with at most 1 GET/s burst4 per actual host+source.
No body or response truncation. No server authority-state mutation occurs.

The client treats all repair bytes as bounded UNTRUSTED candidates. Union ALL
local evidence and latest guard, verify exact context/root origin, first-admission
rules/retained history and current projection before any local authority effect.
A fetch alone sets no membership, provider, readiness or freshness flag. Status
and result reads cannot silently fetch or write. An incomplete local authority
path may request repair at its remembered pin without pretending to have normal
route permission; it cannot use incoming new grants to authorize another fresh
grant in that same batch. No generic bootstrap catalog-import route is added.

`POST /v2/networks/{id}/sync` takes exactly `{}` and attempts known independently
pinned contacts, with4 parallel attempts,5s per connection and 30s total bound.
Return200 exactly `{network,attempted,learned_proof_ids,unavailable}`, with host
keys/proof IDs sorted and unavailable entries `{host_public_key,code}`. This is
a bounded attempted exchange, not a statement of globally latest state. If
local authority remains unusable, return its structured error with exact repair
IDs; unreachable peers do not erase valid offline local authority. The CLI is
nonzero when every attempted path is unavailable and names that transport limit.
It never claims successful sync from no peers. Local useful creation still
needs no sync. Pending exact outboxes retry on reachability; ordinary background
anti-entropy attempts are60s apart with up to 10s jitter, never lease renewal by
heartbeat. Fresh local outboxes are eligible immediately, checked at most 2s
apart; retries use bounded exponential delay up to 60s. Actual lease generation
requires its authorized provider and separate exact typed signature.

## 9. Info, status, transport configuration and release

`info` keeps its current nonnetwork fields, sets default_coordinator exactly
null, and adds `network_protocols:["peerspan-decentralized-v1"]`. No build-time
coordinator endpoint/key is compiled as launch authority. `GET /v2/info` has the
same public info object. `GET /v2/status` keeps current host/agent/session/
capability/task/approval/service/profile fields, with NETWORK_VIEW entries for
DEC networks and explicit legacy history/migration entries for old contexts.
No coordinator connected/last-sync label is projected as new-mode authority.

A legacy network entry is exactly
`{mode:"legacy_history",migration_required:true,id,name,coordinator,last_sync_at,
last_sync_error,members,person,policy,policy_deliveries_pending}`. The nine
preexisting NetworkStatus fields retain their current types: id/name/coordinator
are strings; last_sync_at/last_sync_error are string or null; members and
policy_deliveries_pending are nonnegative integers; person is null or exactly
`{id,label}` with string id and string-or-null label; policy is null or exactly
`{version,valid_until}` with fullu64 version and timestamp valid_until. These
nullable public response fields do not relax strict request/private-state
parsing. They report retained local legacy history and migration need, without
remote fetching or treating the old coordinator/last-sync as current authority.

Status is read-only over one coherent snapshot/decision time and performs no
remote request, key generation, signature or guard advance. Existing attention
ordering remains; DEC entries use the existing four attention fields
`{kind,subject,detail,command}`. Add after existing network-authority attention:
`network_authority_expired`, `network_proof_required`, `network_state_conflict`,
`network_clock_rollback`, `network_migration_pending`, then
`person_device_signer_unavailable`. Subject is network ID. Detail gives actual
code/required IDs/deadline; command is network sync, exact repair/renew or
migration resume as applicable. A clock-rollback detail
instructs correcting local UTC or waiting until the retained guard and rerunning
the actual command; there is NO command to lower/reset the guard. Valid selected scope1 provider
suppresses original SSH-agent warnings; a present invalid/expired device emits
its actual repair warning even if the policy is inactive, never SSH fallback.
Original-key provider attention applies only to that actual selected provider.
Reachability and actual adapter connected/channel/readiness stay separate.
No attention asserts no unseen revocation or suggests copying an original key.

Retain serve's existing owner-local/peer controls. Add `--bootstrap-listen`
HOST:PORT for the isolated bootstrap listener and `--transport-config PATH` for
optional helpers. Its exact strict private JSON is:

```text
{format:1,advertise_bootstrap:[ENDPOINT],advertise_quic:[ENDPOINT],
 rendezvous:[{address,public_key,token_file}],
 relays:[{address,public_key,token_file}],publish_contacts:boolean}
```

Arrays obey bootstrap endpoint/order/count bounds; token_file is `"-"` for
anonymous or an explicit protected local credential file, never a token value
in logs/public records. Publish_contacts is explicit opt-in encrypted publication.
No file/helpers is valid. Local bind syntax alone permits wildcard IP/port0;
advertised signed endpoints never do. `--bootstrap-listen` is an explicit port/
interface override. Otherwise a freshly configured peer-enabled daemon inherits
the configured peer listener INTERFACE with a separate ephemeral TCP port; no
peer listener means loopback-only bootstrap. Fresh install/up already enabling
peer networking advertises actual non-wildcard local interface addresses and
the bound port only inside private signed contact handoffs. This makes the
normal reachable LAN pair work without manual serve flags; addresses are hints,
not public roster publication or a promise of NAT traversal. Explicit advertise
and optional independently operated helper configuration handle other paths.
Do not silently rewrite an existing service unit to add listeners: preserve it
and return the exact bootstrap-listener configuration/restart repair step.
No public unauthenticated roster/address enumeration is started. Existing peer
QUIC and actual default integration behavior remain explicit. The separate
[optional helper operator](decentralized-helper-contract.md) supplies Go-only
peerspan-helper; neither host bundle launches/requires it, and no second helper
implementation is needed for both host clients to replace operators.

New create/join/link/up reject `--coordinator`, `--coordinator-key` and new-mode
JSON coordinator fields, rather than ignore them or interpret an empty value as
migration. `network move`/coordinator successor configuration is history-only;
new transport contacts/helper replacement never rotates authority. Scripts and
release workflow remove required coordinator build variables. Normal Go/Rust
archives and verified installer work without such variables/service. A provided
obsolete mandatory-coordinator build option fails with migration guidance;
no default private staging identity leaks into a package. Rust remains the
recommended default, Go selectable; private/public release decision is separate.

## 10. Verification and chosen costs

The independent author derives runtime cases after this contract is pinned:

- Current groups return exact independently verified original signed bytes/DS
  and decoded members from one coherent view, with every DB row including
  guard/provider unchanged. A remembered higher missing body or a group fork
  returns exact diagnostics without a lower historical fallback; expired or
  withdrawn groups disappear while their durable maxima remain. Native group
  display uses only the v2 route for DEC and works with an unavailable local
  signing key, without v1/SSH fallback. Other current domains remain independent.
- All four creator/requester/CLI pairings without a coordinator process, key,
  config or successful sync; local original-provider creation with no device
  lease; later creator-device creation still requires complete consent.
- Exact seven stages and typed slots, same-review/separate-admin paths, target
  versus actual admin identity, two default-no requester reviews, original-key
  absence on linked B/C, B approving C while A is offline and all deadlines.
- Exact retries/crashes at approved-intent/signature/frame/finalcommit/apply
  boundaries; historical outcomes after expiry; no implicit consent, new keys,
  fallback signer, duplicate event or rollback of newer provider/maxima.
- Root-retention preview/read purity and complete finite closure; default full
  eligible-set review, exact explicit subset/empty choice, missing-body repair
  rather than silent omission, effective powers/deadlines and concurrent final
  recheck. All-head resolver preserves only grants retained by every branch;
  ordinary root/provider/fresh actions stay frozen until complete resolution.
- Expired known-peer narrow proof repair, unknown/revoked-key isolation and no
  local/admin/task leak; current-self withdrawal propagation and unrelated
  conflict-domain restrictions; strict catalogs/aliases/closures/size quotas.
- Every deny/expiry/fork/clock case across task starts/calls/handoffs while
  accepted work/result/cancellation and independent manual grants stay correct: allow_disconnected false/omitted
  still needs the current DEC network predicate; explicit true grant can work
  after DEC expiry under its own limits; a known peer alone/relabeled DEC rule
  cannot bypass either;
  schema20 per-call approvals and schema21 resource limits/gh sources unchanged.
- Original/device automatic policy/edit/capability workflows, inactive maxu64
  guards, atomic claims/removal, peer-delivery retries and no fake legacy policy.
- Truthful info/status/provider and inactive-policy device warnings; guided
  pending resumes/default-no, no code redisplay, exact original attachment and
  real adapter readiness; installed normal packages with no mandatory helpers.
- Replace all helpers with independent operators, restrictive NAT/relay failure,
  complete helper outage, explicit migration and cross-language state reopening.
  Live separate-machine work requires checked output/withdrawal, separately
  from deterministic fixture readiness.
- Explicit already-applied resume triggers actual bounded exact complete POST
  through replacement configured resources despite prior acknowledgment. All
  authority/guard/provider/event/outcome/private-key hashes remain unchanged;
  erased secrets/ciphertexts stay erased, unreachable resources produce linked
  plus transport attention, and local GET/exact commit retries perform no I/O.
- Completion-only QUIC through a selected opaque relay with no direct TCP path:
  exact participant GET/POST recovery after requester apply/secret retirement,
  mailbox erasure/expiry and helper replacement; same original operation,
  separate final consent and no duplicate event/provider/key replacement.
  Wrong server pin fails before HTTP, wrong TLS participant discloses nothing,
  normal/repair/mailbox/admin routes stay unreachable through completion ALPN,
  and completion-only identities get no stream/data on normal/repair ALPN.
  Forged relay source IDs, unknown-key pressure, deadlines and aggregate pools
  cannot grow routes/workers/buffers without bound; real transport time remains
  separate from the DEC authority clock. Preserve first failures and rerun only
  failed or previously unevaluated controls.
- Preproposal migration identity preview writes/generates nothing; approval and
  restart/retry after300s preserve exactly one owned tuple/key; bound existing
  devices preserve their keys/scopes, unbound hosts need no authority signer,
  changed tuples conflict, and no proposal/provider/fence/signature is invented.
  A staged request references the same pending seed; failed staging/adoption
  preserves it and complete adoption atomically transfers its protected home.
- Exact old nonadmin device15 migration preserves that key/profile through
  fresh original/all-host approval and both requester consents; policy1 keeps
  its ordinary bounds and admin8 stays forbidden without its separate role.
  Ordinary original7 still cannot issue15; increased/different/unapproved old
  profiles cannot invoke the cutover-only rule.
- Exact evidence carrier survives Go/Rust/client outer JSON reserialization,
  key order/whitespace and accepted string escaping with identical decoded
  proposal/source/prepared/ACK/commit bytes and prepared hash. Changed decoded
  prepared bytes still conflict with an ACK/commit's exact hash. Reject old
  inline fields, duplicate/unknown fields and noncanonical Base64 before any
  approval/fence/adoption. Verify proposal/source remain mandatory on first
  import, unknown fields use literal '-' only where specified and ACK array
  order follows actual decoded host keys. Complete-M schema and inner/whole
  bounds stay unchanged; export after adoption returns the original bytes.
- Owner-local exact public migration evidence export/reimport: read repeats
  preserve every DB/clock/private-file hash, first signed proposal bytes are
  available without a daemon key export, and import supplies no local approval,
  fence/provider/adoption. Before a real signed proposal export is404; after
  adoption it remains the immutable original transition snapshot.

For preproposal migration identity, selected: a nonsigning typed record in the
existing intent table, preserving one pending device key across all retries.
Discarded: a fake proposal/root/provider, a shared `-` proposal row, a new table
and schema version for the same bounded local intent, or generating a new key
whenever a preview/review window expires. Identity approval is not delegated
signing authority; all real migration consent and authority gates stay separate.

Selected costs are explicit contact handoff/reply instead of a new global inbox;
current finite ancestry instead of mandatory online quorum; original-provider
local creation instead of a hidden device-consent bypass; local commits/outboxes
instead of global receipts; narrow formerly-admitted proof reads instead of
opening normal routes to expired/unknown keys; and explicit unchanged legacy
history/migration instead of an automatic downgrade. No status/helper success
is evidence of a globally complete history or completed model task.
