# Decentralized authority and replicated state

Status: DEC-01 shared contract candidate against
implementation main `6d3823fd3115fff247b1af8551553baf30e97f0f`, schema21.
Implementation and independent executable cases begin only after the complete
contract set is reviewed and merged, as fixed by the umbrella contract.
This document supplies recommended concrete choices,
their limitations and discarded alternatives for the delegated DEC stream.

## 1. Chosen model and honest bounds

Authority comes from exact signed network/root/person/device statements, not
from a coordinator, helper, peer's completeness assertion or successful sync.
Every delegated generation has a finite hard deadline. Learning an applicable
restriction or conflict can end authority sooner. Ordinary work needs no online
quorum.

Choose **7 days default and maximum** for administrator, person admission, host
membership, ownership binding and device management leases. Choose **24 hours
default and maximum** for access policy and group bodies. A child's signed
deadline is at most every exact parent's deadline; effective authority is the
intersection, never a new relative duration starting at each hop. Shorter
operator-selected periods are supported. Root/key identity itself is not made
uncompromisable by those durations.

These are bounds on a fixed generation, not an unconditional promise that a
revocation becomes globally effective within7 days. A still-authorized upstream
issuer can make a **new** trust decision while unaware of a remote restriction.
That new signature is not proof that no restriction exists. A partitioned
descendant cannot extend its existing parents, claim global freshness or use a
new timestamp to turn its old lease into a new upstream authorization.

Seven days tolerates ordinary travel/weekend outages while limiting a fixed
management delegation.24-hour policies/groups encourage timely resource-owner
review without requiring the original-person key for every routine refresh.
The cost is explicit: extend the network-root/admin/person/owner ancestry
periodically, normally weekly. The original holder can remain on machineA;
no key copy toB/C is introduced. DeviceB can refresh policies and approveC while
its full ancestry remains valid. Extending beyond the last hard owner ancestor
requires that ancestor's holder to sign again; if the original person key is
the ultimate available holder, it must be made available on its own machine.
The UI must show this deadline and repair path. There is no daily original-key
requirement hidden inside a24-hour policy refresh, and no indefinite automatic
device renewal disguised as convenience.

Root/private original-person key compromise has different limits. A root can
issue new root/admin/person/host authority; an original person can issue new
owner-device authority for that person. If the verifier has not learned a
restriction or competing root, those keys may issue fresh generations. Their
compromise therefore has no finite cryptographic revocation guarantee merely
because each new lease says7 days. Known restrictions still apply. Clock or
whole-state compromise has the limits in section8.

### Independent resource-owner authority

These leases gate **network-derived** self, policy, group, capability and device
authority. They do not remove a resource owner's independent owner-local or
explicit manual peer grant. Each authorization records which source justified
it. A manual-known-peer or `allow_disconnected` shortcut cannot convert an
expired/forked DEC network grant into a manual grant; the independent resource
owner must actually have selected the applicable manual permission. Conversely,
an unrelated DEC network expiry does not silently delete such a permission.
A manually known key proves identity only, not implicit execution authority.

Keep every independent resource check from PRs78/80: same-person raw-source
openlist/trusted-policy rules, per-call approvals, allowed calls, budgets,
resource bounds, target ownership and caller identity. A network lease or
membership is never a substitute for these. New queued starts, delegation
hops, handoffs and calls recheck the applicable current network-derived path
and these resource checks. Already accepted tasks and running calls retain
existing result/cancellation/side-effect semantics; expiry is not represented
as undoing work already performed. Status/result retrieval keeps its existing
identity/ownership checks, separately from permission to start new work.

## 2. Immutable context and exact signed bytes

The bootstrap descriptor is exactly:

```json
{"format":1,"protocol":"peerspan-decentralized-v1","network_id":"net_...","name":"NAME","genesis_root_public_key":"KEY"}
```

No coordinator/helper/address/clock fields occur. `network_id` remains derived
from the original genesis key. Name is a trimmed1..128-byte UTF-8 label with no
control characters. Keys are canonical Base64 Ed25519 public keys.
`context_id` is `ctx_` plus lowercase SHA256 of the following UTF-8 message,
with LF separators and **no trailing LF**:

```text
peerspan-decentralized-context-v1
peerspan-decentralized-v1
NETWORK_ID
NAME
GENESIS_ROOT_PUBLIC_KEY
```

A statement envelope has exactly these fields:

```json
{"format":1,"kind":"KIND","context_id":"ctx_...","payload_base64":"BASE64","signatures":[{"role":"ROLE","public_key":"KEY","format":"ed25519","signature":"BASE64"}]}
```

`payload_base64` decodes the exact strict JSON payload for its kind. Reject
invalid UTF-8, duplicate/unknown fields, nulls, noncanonical Base64, floats,
negative integers, out-of-range integers and incorrect primitive/array types.
Numbers declaredu64 accept the whole range, without float conversion.
Signature entries are sorted by role, roles are unique, and each kind accepts
only its declared roles. Unknown or superfluous roles fail. Empty/missing
signatures are private drafts only; public ingestion requires the complete
kind-specific signature set.

Define the unsigned statement message:

```text
peerspan-decentralized-statement-v1
KIND
CONTEXT_ID
SHA256(EXACT_DECODED_PAYLOAD_BYTES)
```

`statement_id = "ds_" + SHA256(unsigned_statement_message)`. All lease and
root-state references use this same semantic-ID prefix. IDs exclude signatures
so a private draft can fix references before all target consent signatures
exist. This ID alone never means the draft is active or complete.

Each signature signs the following role-separated message:

```text
peerspan-decentralized-signature-v1
STATEMENT_ID
ROLE
PUBLIC_KEY
```

`ed25519` is a canonical Base64 raw64-byte signature. `sshsig` is the existing
canonical Base64 binary OpenSSH SSHSIG encoding, Ed25519/SHA512 and namespace
`peerspan-person-v1`, over the same role message. Original-person and SSH-root
keys may use SSHSIG; device/host keys use raw Ed25519. This is not an arbitrary
message-signing API: local providers accept only the registered typed payload
and role after its complete pre-sign authority/consent checks.

Exact original envelope bytes remain the public evidence. A proof ID is
`dp_ + SHA256("peerspan-decentralized-proof-v1\n" + KIND + "\n" +
SHA256(exact_envelope_bytes))`. An alias is **only** another envelope/signature
encoding with identical kind, context and exact decoded payload bytes, hence
the **same ds_**. Retain every exact dp_ alias; it supplies no extra authority
or stream head. Different payload serialization has a different ds_, even when
its typed values look equal; it is a distinct statement subject to normal
stream/fork rules. A writer serializes its typed payload once, persists those
bytes and retries them exactly, never normalizes after signing. A reference
resolves its exact ds_ through any complete valid envelope alias with that ds_.
This deliberately rejects a typed-equivalence/canonicalization exception whose
head and reference behavior would be ambiguous. No alias is a policy tie-break.

Catalog exchange is exactly
`{format:1,context_id,objects:[{id,kind,body_base64}]}`, sorted by proof ID with
unique IDs. Each ordinary object's kind equals its decoded envelope kind;
the two composite exceptions below use their declared body schema. Every id is
the exact proof ID above. The set identifier, when a transport needs one, is
`cat_ + SHA256(M)`, where M is UTF-8 with no trailing LF:

```text
peerspan-decentralized-catalog-v1
CONTEXT_ID
DECIMAL_OBJECT_COUNT
SORTED_PROOF_ID_1
...
SORTED_PROOF_ID_N
```

For an empty catalog the message ends at the decimal0 line. Decimal values have
no leading zeroes. `catalog_id` is not an additional field in the catalog; a
transport that exposes it declares its own exact response shape. It identifies
the set, not latest state or absence of unseen revocation. Transcripts pin the
context, root state and **exact required statement IDs**; they do not obtain
freshness from a catalog hash.

Two public catalog kinds are composites, **not** ordinary signed envelopes:

- `activation` is exactly
  `{format:1,context_id,request,owner,selection,administrator,owner_finalization,commit}`
  under the bootstrap contract. It embeds no catalog. Its dp_ uses kind
  activation and the exact original composite body. Its separate identity is
  `da_ + SHA256(L("peerspan-decentralized-activation-v1",context_id,request_id,
  manifest_id,commit_packet_id))`, using bootstrap's exact IDs and no trailing
  LF. Full current authority and all original consent are independently checked;
  a participant outcome is never authority or a substitute for this proof.
- `migration` is exactly
  `{format:1,proposal,source_catalog_base64,source_state_base64,prepared_catalog_base64,acknowledgments,commit}`
  under the migration contract. Its dp_ uses kind migration and the exact
  original composite body. Proposal and acknowledgment statements retain their
  own ds_/dp_ identities, as does the final root commit. Catalog/proposal hashes
  do not contain themselves. Exact migration statement kinds, source-state
  endorsement and phased preparation rules are in the migration contract.

These are the only composite exceptions. A kind cannot accept both a generic
statement envelope and a composite-shaped lookalike. Catalog extraction may
index exact nested statements/packets for dependency discovery, but it retains
the enclosing original composite proof; it must not fabricate new standalone
proof bodies by JSON reserialization or treat an incomplete nested lease as
ordinary active authority.

## 3. Lease payload and issuer matrix

Kinds are `admin_lease`, `person_lease`, `host_lease`, `binding_lease`, and
`device_lease`. Every payload has exactly:

```json
{"root_state_id":"ds_...","operation_id":"-","sequence":1,"predecessors":[],"resolves":[],"retained_statement_ids":[],"subject":{"person_public_key":"-","host_public_key":"-","device_public_key":"-","member":"-","scopes":0},"issuer":{"kind":"root","person_public_key":"-"},"parents":[],"issued_at":"UTC","not_before":"UTC","not_after":"UTC"}
```

`sequence` is positiveu64. `predecessors` and `resolves` are sorted unique
statement-ID arrays under section6. `issuer.kind` is `root`, `person`, or
`device`; `issuer.person_public_key` is `-` only for root. `parents` is a sorted
array of exact `{role,id}` objects, unique by role. Allowed roles are
`issuer_admin`, `issuer_device`, `issuer_person`, `subject_binding`,
`subject_host`, and `subject_person`. Unused subject fields are exactly `-`; unused scopes are0.
Every required reference must resolve to its exact kind, subject and context.
The recursive closure, not an unverified caller-supplied summary, supplies all
ancestors. Cycles or a repeated device key within one owner-device ancestry,
or device depth above8 fail. Repeated person/host keys across their own lease
renewals are expected and are not a cycle by themselves. Sharing one exact
person node as issuer_person and subject_person is a valid DAG, not a cycle;
cycle detection examines the active recursive path, not a global seen-node set.
`retained_statement_ids` is a sorted unique exact statement-ID array with the
narrow retention semantics in section4; the first generation has an empty
array. It is not an arbitrary authority allowlist.

`operation_id` is `-` for an independently issued ordinary admin/person/host
lease or fully owner+host-signed binding, or the exact link request ID for
ceremony-bound person/host/binding components. The explicit migration exception
is an unbound host_lease with operation_id equal to the exact migration proposal
ds_: it requires issuer+host signatures and remains inert until that complete
migration. No other arbitrary ds_ or operation ID activates an ordinary lease. Every **new or renewed device**
lease requires a non-`-` operation_id and the complete reviewed requester
transcript; issuer signature or target proof-of-possession alone never activates
it. An operation-bound lease remains **inert** until the exact complete
bootstrap transcript, including owner/host/device proof-of-possession and
separate final requester consent, validates. Publishing a draft
host/person lease cannot bypass that consent. Admin leases are ordinary only.
Binding semantic IDs can be fixed before the host-role signature, but neither
the binding nor a device referencing it activates from that incomplete draft.

| Kind / subject | Who may issue | Required finite parents and ceiling | Complete signatures |
| --- | --- | --- | --- |
| `admin_lease`: person; scopes8; other subject fields `-` | Current root only. It grants the role, not ownership of the person's devices. | None for root issuance; at most issued_at+7d. Exercising it also requires the administrator's current person admission and, for a device signer, its exact owner path. | `issuer`, current-root key. |
| `person_lease`: person+member; scopes0 | Current root, or current administrator with scope8. | For a person admin: issuer_person+issuer_admin. For a device admin: those plus issuer_device. At most issued_at+7d and every parent's deadline. | `issuer`, exact authorized root/person/device key. |
| `host_lease`: host+member; person/device `-`; scopes0 | Current root, or current administrator with scope8. | Same issuer parents as person_lease; maximum7d and all parents. Membership does not establish person ownership. | Ordinary operation_id `-`: `issuer` plus raw target `host` signature over this exact lease. Ceremony-bound: `issuer` plus complete target-host requester transcript. Unbound migration host: `issuer`+`host`, plus full migration. |
| `binding_lease`: person+host; device/member `-`; scopes2 | That original person, or its device with scope2. | subject_person+subject_host+issuer_person; add issuer_device for device signing. Maximum7d and every parent. | `issuer` owner key and `host` target-host key; operation-bound completion is additionally required. |
| `device_lease`: person+host+device; member `-`; scopes1..15 | That original person, or a same-person device with delegation scope4. Network root/admin cannot mint another person's owner-device authority. | subject_person+subject_host+subject_binding+issuer_person; add issuer_device for a device parent. Each subject matches the exact target person/host. Scopes are a subset of the parent's delegable scopes. Maximum7d and **every** parent including host/binding. | `issuer`; non-`-` operation, target host/device proof of possession and final reviewed consent in the complete bootstrap transcript are mandatory. |

The issuer's key must equal the envelope issuer signature key. A person issuer
uses the original public key; a device issuer uses the exact issuer_device
lease key. For an admin device, scope8 and a current matching admin lease are
both required. Preserve scope1 policy, scope2 binding, scope4 device delegation/
revocation and scope8 network administration; membership or the label alone
supplies none of them. Each required parent role appears exactly once, and no
unlisted role is allowed. Root issuance uses issuer.kind root, issuer person
`-`, no issuer_* parents and the current root-state key. Person issuance uses
issuer.kind person and that original key; device issuance uses issuer.kind
device and the exact issuer_device key. `member` is a trimmed1..128-byte UTF-8
member label with no ASCII control/DEL characters; person and host admission
for the same stable person must have their independently verified consistent
label. Labels do not replace public-key identity or issuer authority.

Original-person authority still requires current person admission. Target host
and device consent do not create admission by themselves. The genesis root may
create its own initial person/host/admin leases. For a new person, an owner
offer can prove possession of the unadmitted original-person key, but grants
nothing. Only after an independently current root/admin has supplied the exact
operation-bound person and host leases may that same original-person key use
its pending **self** person lease to consent to its own binding/device leases
in the **same** operation. This exception does not activate that person, grant
any admin role or authorize unrelated actions; all components remain inert
until the final requester commit validates. Existing-person linking instead
requires its ordinary current finite person/owner path. No newly supplied
admission or role can establish issuer authority for other new grants.

## 4. Validity and renewal

All new timestamps are strict whole-second UTC `YYYY-MM-DDTHH:MM:SSZ`,
valid Gregorian dates in years0001..9999 with no leap-second spelling or offset.
Seven days is exactly604800 seconds and24 hours is86400 seconds. Compute checked
integer UTC differences; overflow/truncated duration conversion cannot relax a
bound. Require `issued_at <= not_before < not_after`,
`not_after - issued_at <= class maximum`, and signed
`not_after <= min(exact finite parents' not_after)`. Delaying not_before never
moves the maximum deadline later than issued_at+7d or issued_at+24h. The operation
uses `not_before <= decision_time < not_after`; equality at expiry is denied.
No positive expiry-skew grace or grace descendant is allowed. Locally signing
a new intent fixes issued_at from section8's decision time. A persisted
unsigned intent older than300s must be re-reviewed before a new signature;
this local safeguard is not proof of remote signing time or global freshness.
Late learning of an exact completed, still-valid transcript is not rejected
merely because its signatures are older than300s.

Renewal is a new statement with a greater stream sequence and new exact parent
IDs. It has the **same issuer permissions as initial issuance**. A current root
renews admin leases; current root/admin renew person/host leases; the original
person or still-valid owner ancestor renews binding/device authority under the
table above. Parent renewal does not silently reparent an existing child.
Every descendant that extends past an old deadline must be explicitly signed
against the new ancestor closure. A child may renew repeatedly only up to its
currently fixed ancestors' deadlines. No self/circular ancestor renewal.

For an exact same-person/host/device renewal, unchanged **current** person,
host and binding heads may be referenced rather than reissued. If all three
remain eligible, no new admission or binding authority is requested: the
administrator offer is `-`, owner finalization references that exact binding,
and the final commit's new binding-host-signature is `-`. The issuer still
must be the original owner or a current same-person **strict ancestor** device
with delegation scope4; an expired target or its own self-delegation cannot
renew itself. No administrator role or scope2 is needed solely to reuse
unchanged independently verified P/H/B references. The new device lease still
requires its non-`-` request operation, complete target host/device PoP, separate
requester selection and final consent, current direct parents and every old/
new hard ancestor ceiling. Extending/replacing an expired/narrowed P/H/B uses
its normal current root/admin/owner permissions and fresh consent; this exception
cannot widen identity, scopes or the frozen ancestry deadline.

An expired target can prove possession and request renewal, but its expired
lease cannot authorize issuance. A fresh authorized ancestor must approve the
exact stable person, host, device, scopes and new deadline. An exact submitted
retry returns the same fixed statement/transcript; it never re-signs with a
later timestamp. Refusal preserves identity and outcome and must not generate
a replacement original person or fall back to an original key silently.

### Current heads, retained descendants and portable admission

A current authority selection is the unique resolved maximal head of each
required stream, together with its exact signed ancestry and restrictions.
Having a larger sequence does not hide a fork. For **fresh issuance and first
admission without signed retention**, every direct issuer/subject parent slot must name that stream's current unique head,
not a lower predecessor. First learning a retained historical child instead uses the portable
retention rule below; it does not pretend that child was freshly issued under
the new heads. Its complete path may include old ancestors only under that
explicit rule. For example, a
new policy names the current person and device heads; that device's already
signed ancestry can remain valid through an explicitly retained older person
lease. This does not allow choosing an old device head after a newer narrowed
device head exists.

Renewing an ancestor does not automatically invalidate every descendant, nor
does it silently keep them all. The successor can retain exact previously
signed descendant IDs in `retained_statement_ids`. A listed descendant must:

1. Be independently valid under the immediate predecessor state before the
   transition, with all original signatures/consent/parents present, and not
   already expired, revoked, forked or inactive. Issuing the successor must not
   let an incoming new grant establish its own prior authority.
2. Have its complete dependency chain listed or otherwise remain current;
   every older dependency that would cease to be current at this transition
   must be explicitly retained too. Proofs resolve to exact original bytes;
   no newly synthesized parent or changed signature replaces them.
3. Still fit the replaced ancestor's exact role, subject and available powers.
   The retaining signer must have normal authority to replace **that ancestor**;
   it preserves a descendant's existing owner signature rather than acquiring
   permission to mint one. A changed subject cannot retain the former subject's
   descendants. Effective device scopes are intersected with every retaining
   device generation's scopes; a narrowed head cannot retain an old policy's
   removed policy bit or a child's removed effective scope. Person/host/admin
   role fields are checked by their typed role, not by interpreting their0/8
   values as device bitmasks. No unrelated authority is carried. Retention is
   not fresh issuer authority for the old generation. Retention preserves
   **only the retiring ancestor's contribution**: a root-issued person renewal
   can preserve its network-admission contribution to an existing device15
   chain while every original owner/host signature and current eligibility
   remains required. The root does not need, or gain, power to issue that whole
   owner-device chain. Narrowing a device ancestor preserves only the subset
   of its old scope contribution available in the current retaining generation;
   an administrator-only8 path cannot carry a removed policy1 contribution.
4. Keep every original signed deadline and finite ancestor ceiling. Current
   use is additionally capped by every retaining successor's own effective
   deadline and scope. An expired current head never reveals a live lower one.

Every subsequent replacement on that ancestor stream must again retain the
exact descendants/dependencies still being used. Missing retention makes them
inert. A later head cannot silently resurrect an omitted, restricted or forked
generation: restoring the power requires fresh issuance by the normal current
authority, including original-owner consent where applicable. Retention may
not name the retaining statement itself or any descendant whose alleged prior
validity depends on that retaining statement or another grant currently being
authorized. It cannot create cyclic/self-supporting authority. A cold proof
bundle may carry old descendants and their later retention together; this is
not evidence that the descendant was freshly created by that local import.
A fork resolver must satisfy the same powers/ceilings, explicitly cover all
known conflicting heads, and state the exact retained descendants; a branch's selective list is
not a resolution.

A retained child remains an already signed grant under its original parents;
it is not reparented and its issuer is not re-signed by the root. If the child
is still its own current unique head, its retained ancestry can authorize its
stated uses, including signing its permitted descendants, through its remaining
hard deadline. Fresh descendants still name the current direct parent heads
and cannot extend any retained ancestor's original deadline. This permits an
explicitly reviewed admin/root refresh to preserve working owner-device paths
without root-forged owner signatures or a full owner-resign batch.

These rules are identical for an existing host and a newly bootstrapped receiver.
A local admitted-before bit, another peer's receipt or a claimed historical
signing time is not portable retention evidence. A receiver without the exact
signed successor retention chain reports the missing IDs and grants nothing;
it can obtain that chain or have the normal current issuer reissue the exact
subject/powers under current parents. Such positive reauthorization is a new
normal lease/access generation with its ordinary signatures and consent, not
an extra generic ratification object or a change to old bytes. A root's new
admission decision cannot re-sign another person's owner-device authority.
Retained local provenance is useful for repair/history, but does not override
a newly learned narrower/unretaining head or restriction. There is no special
lower-generation authorization fallback for old versus new receivers.

### Access statements

The exact envelope kinds are `policy` and `group`. Their wrapper payloads have
exactly `root_state_id`, `operation_id`
(always `-`), `sequence`, `predecessors`, `resolves`, `issuer`, `parents`,
`issued_at`, `not_before`, `not_after`, and `body_base64`. They do not have
`retained_statement_ids`; access statements retain no child authority. There
is exactly one `issuer` signature. The unsigned body is
the existing typed policy-v2 or group-v1 body under the current product
contracts, with its version equal to sequence, network/person exact, and any
body issued/expiry fields equal to the wrapper. In this NEW signed context,
policy validity explicitly supersedes the old1-day minimum/90-day maximum:
require positive whole-second `valid_until - issued_at <= 86400`, capped by
all exact finite parents; a shorter remaining parent interval is valid and
must not be rounded up to a day. All old-context readers retain their original
window rules. Group defined_at equals wrapper issued_at and its validity is
the wrapper's finite interval. Preserve capability rules,
trusted hosts, edits, approvals and resource-bound semantics. Policy is issued
only by its original person or scope1 device; group by current root/admin8.
The same exact issuer ancestry applies, maximum24h, capped by all parents.
No root/admin privilege substitutes for another person's policy ownership.

## 5. Root states and old contexts

The exact `root_state` payload is:

```json
{"epoch":0,"predecessors":[],"resolves":[],"migration_proposal_id":"-","root_public_key":"KEY","issued_at":"UTC","retained_statement_ids":[]}
```

All ID arrays are sorted unique statement IDs. Epoch is full u64.
migration_proposal_id is `-` except for the explicitly migrated initial form.
The four allowed forms, and **only** their signature roles, are:

| Form | Payload constraints | Complete roles |
| --- | --- | --- |
| Genesis | epoch0; no predecessors/resolves/retention; key equals descriptor genesis root. | `issuer`, genesis root key. |
| Migrated initial state | No predecessors/resolves/retention; migration_proposal_id=exact accepted migration proposal ds_; epoch/key exactly equal the independently verified current legacy root epoch/key. Active only under the complete authorized migration, never by itself. | `issuer`, that current legacy root key. |
| Normal transition | Exactly one predecessor; resolves empty; migration_proposal_id `-`; epoch=predecessor epoch+1; key is chosen next root. | `issuer`, exact predecessor root; `new_root`, chosen next root. |
| Fork resolution | At least two incomparable predecessor root heads, covering **all locally known** maximal heads; resolves exactly equals predecessors; migration_proposal_id `-`; epoch=1+maximum predecessor epoch. | For each predecessor ID P, `root_branch:P`, signed by P's exact root; plus `new_root`, chosen next root. No `issuer` role. |

Each role signs section2's role message for this exact new statement. Repeated
public keys across different branch roles are allowed; each required distinct
role still has its own signature. Reject duplicate/unlisted roles, missing
branch countersignatures, arithmetic overflow and nonconsecutive normal
transitions. Root-state issued_at may not be future at first admission; it is
not a proof of no unseen branch or of global signing time.

Fresh actions use the verified current root state. A lease from an earlier
root state is current only if **every intervening transition explicitly carries
its exact ID and required ancestor closure** in retained_statement_ids, with
section4's unchanged-deadline/no-revival limits. Root retention is preservation
of existing signatures and powers, not new owner signatures or fresh authority
for the retired root. Uncarried old-state grants are historical only. A
retired root cannot create a new fresh grant or deny in the current context.

A root fork is incomparable valid branches, never the numerically largest
epoch. Freeze positive paths depending on the fork until the all-head
resolution above validates. The all-branch requirement is a chosen safety cost
for exceptional root equivocation, not an online quorum for ordinary work.
There is no implicit deleted-genesis-key recovery or arbitrary hash winner.
If a hostile branch refuses to sign, resolution in this context can be blocked;
an explicitly trusted out-of-band/new-network decision may be needed. A
retained old root key can manufacture a structurally valid alternative root
transition; no timestamp proves it was signed before retirement. Recognizing
such equivocation may freeze availability even though the old key cannot issue
fresh ordinary grants/denies. Rotation does not cryptographically remove this
root-key equivocation limit; do not claim deleted keys or global timing. A later
newly learned branch reopens the dispute. A root's permission to rotate is
separate from any person's ownership, so rotation cannot fabricate an absent
owner signature or extend a carried management deadline.

New-mode migration is explicit current legacy-root authorization plus every
known nonrevoked admitted host's acknowledgment as specified by bootstrap and
umbrella migration. Fresh complete new-mode transcripts use each owned host's
**same** original-person/host/device keys. The original person approves once
at cutover on its own machine; no original key is copied and no old90-day
device lease is silently bridged into seven-day new-mode authority. An
unavailable original holder or known host blocks migration rather than being
dropped. The migration proposal fixes the old verified chain/current epoch/key,
new descriptor and roster without referencing a final root-state ID that in
turn hashes the proposal ID; later acknowledgment/manifest pins that derived
root-state ID. No ID-reference cycle is permitted. Preserve exact old
descriptors, proof bytes, stable keys/IDs, restrictions and full-u64 high-water.
Do not remove old coordinator fields from signed messages. New-context fresh
authority is not obtained merely by feeding those old records into a new
descriptor; old-context expansion is denied. Legacy any-old-root restriction
recognition remains a historical-reader rule, **not** fresh authority for a
retired root to manufacture new restrictions in the new mode.

Public launch creation/enrollment uses the new mode. Any temporarily retained
coordinator runtime is staged development compatibility and must become
explicit history/read-only/migration functionality, not a second hidden launch
architecture. New-mode failure cannot fall back to a coordinator receipt/map.

## 6. Streams, conflicts and full-u64 state

Streams are `admin/PERSON`, `person/PERSON`, `host/HOST`,
`binding/HOST`, `device/PERSON/DEVICE`, `policy/PERSON`, and `group/NAME`,
scoped by context. Root has its separate transition DAG. Only admitted stream
candidates contribute authoritative heads and maxima. Admission requires the
current complete issuer path or the exact portable retention rules (and
current ratification for restrictions). An unseen expired/revoked delegate's
backdated signature, including a max-u64 policy/lease, is inert repair/history and cannot poison heads/maxima.
Structural verification of an old ancestor required by an independently valid
current successor supplies provenance, not independent admission of that old
object as a new competing head. Previously admitted high-water remains durable
when its body later expires or loses authority. Root alternative-transition
equivocation has the explicit exceptional limit in section5.

A first statement has sequence1 and no predecessors for a fresh network. The
migration-only first policy/group generation instead has empty predecessors
and sequence strictly greater than its inherited exact legacy high-water
floor; the complete migration authenticates that floor. A floor of max-u64
refuses fresh generation, never resets to1. Other initial migrated lease
streams start1 and do not reinterpret legacy delegation versions. A normal successor names its exact sole known
head and has a strictly greater sequence; local default generation uses
checked+1. A resolver names all known maximal conflicting heads in both
predecessors and resolves, and has sequence greater than all observed values.
The issuer must have current independent authority for that stream at NOW.
For admin role regrant or owner binding reauthorization after a known
reversible withdrawal/unbind, resolves also includes every applicable known
withdrawal/unbind statement ID as section7 specifies. Those restriction IDs
are not predecessors; predecessors remain same-stream lease heads. No such
resolution exception exists for permanent stable-key revocation.

Incomparable valid statements in one stream form a fork even when their
sequence numbers differ. Equal-version distinct bodies are never selected by
the old signed-message-hash policy tie-break. Retain all exact proofs and the
maximum observed sequence. Deny positive authority in that domain until a
valid resolver covers all locally known heads; a later higher ordinary write
on only one fork does not heal it. Learning another previously unknown branch
can reopen the conflict. Envelope/signature aliases with the exact same ds_
are not separate authority branches; differently serialized payloads are distinct statements as section2
requires.

Known inactive/expired/forked maxima remain high-water; no lower permissive
body becomes active. A current head whose not_before is still future likewise
does not reveal a lower body once that head has otherwise been validly admitted.
Highest-generation expiry does not reveal a prior policy
or group. Version2^64-1 is observable and durable; attempting a fresh default
increment returns `version_exhausted` before reservation/signing/publication.
Use the reviewed canonical SQLite INTEGER/high-half8-byte-BLOB encoding, never
float/text coercion or SQL MAX. Imported old-context maxima remain preserved
under their own context and cannot be used to truncate new-mode values.

Conflict is a per-domain projection result, not a reason to reject an entire
otherwise well-formed signed catalog. A policy fork forAlice must not prevent
an independently valid revocation byBob/root in another domain from committing.
Known restrictive evidence remains enforced within a disputed domain as well.
A fork in an issuer's required authority does prevent using that issuer to
authorize new statements; unrelated unforked issuers remain usable. A root fork
can affect every positive path rooted through it. It does not erase already
admitted restrictions or prevent independently verifiable pre-fork restrictive
history from being retained. Malformed/forged new objects still fail ingestion;
forked but valid objects must not be misclassified as malformed.

## 7. Restrictions, historical learning and proof repair

The exact envelope kinds are `admin_withdraw`, `person_remove`, `host_revoke`,
`host_unbind`, and `device_revoke`. There is **no duplicated
restriction-kind field inside the payload**. The envelope kind selects this
exact payload schema:

```json
{"root_state_id":"ds_...","issuer":{"kind":"root","person_public_key":"-"},"parents":[],"issued_at":"UTC","target":{"statement_id":"-","person_public_key":"-","host_public_key":"-","device_public_key":"-"},"kept_statement_ids":[],"ratifies":"-"}
```

Issuer and parent roles have section3's meanings; arrays are sorted unique.
There is exactly one `issuer` signature, no sequence or expiry. The target
matrix fixes every non-`-` target field. Reject any superfluous target/kept
field. A named statement must have the stated exact subject and context.

| Envelope kind | Exact target fields | Current issuer power | Effect and kept list |
| --- | --- | --- | --- |
| `admin_withdraw` | statement_id=exact admin_lease; person_public_key=that administrator; others `-` | Current root only. | That role generation and dependent administrator powers become inactive. kept_statement_ids may name only exact eligible person_lease/host_lease statements issued under that role. It grants no owner-device or group power. |
| `person_remove` | person_public_key=exact stable person; others `-` | Current root or administrator8 with current person/admin/path parents. | Permanent context ban on that person's network admission, binding/device and policy-derived authority; kept empty. It does not revoke another person's independent manual grant. |
| `host_revoke` | host_public_key=exact stable host; others `-` | Current root or administrator8. | Permanent context ban on that network host's membership and derived network actions; kept empty. |
| `host_unbind` | statement_id=exact binding_lease; person_public_key and host_public_key exactly match it; others `-` | That original person or same-person device2; current matching own binding/authority. | Retires that binding generation and dependent owner paths; host membership is separate. kept empty. A later exact owner+host binding may explicitly resolve it as below. |
| `device_revoke` | person_public_key+device_public_key=exact owner and stable target device; others `-` | That original person, or current same-person device4 that is a **strict ancestor** of the target's known activated owner path. | Permanent context ban on the target device key and every path descending through it. A device cannot revoke itself, its ancestor or an unrelated sibling; kept empty. |

`admin_withdraw.kept_statement_ids` is an explicit root endorsement of **only**
those already fully signed, completed, currently eligible person/host grants,
through their original hard deadlines and ancestor ceilings. It suppresses
only this exact role-withdrawal barrier for those grants, never another
revocation/expiry/fork or a missing original signature/consent. Include the
required retained dependency closure; an incomplete list cannot silently add
more grants. This preserves already reviewed admissions when the root chooses
plain role withdrawal, without preserving groups/admin powers or minting
owner authority. Empty kept retains nothing. Existing personal policy/owner
powers are independently checked and are not lost merely because admin scope8
was withdrawn. A later person_remove is an independent irreversible escalation.

Role withdrawal itself is generation-scoped, not a permanent ban on the
administrator's key: a new current-root admin_lease may explicitly include all
known applicable withdrawal IDs in resolves, name the current admin stream
heads, and grant a **new** role generation. It does not revive the old role or
its unkept children. Similarly, a new binding requires fresh normal owner and
host consent, current subject admission/membership, the current binding heads
and every applicable known unbind ID in resolves. It cannot revive old device
paths automatically. No lease/resolver can undo person_remove, host_revoke or
device_revoke for the stable key in this context. This irreversible-versus-
regrant distinction must be visible in reviews before signing.

`ratifies` is `-` for a new restriction, or the exact old same-kind restriction
statement ID. A ratification must include the original exact proof and have
identical target and kept list; its current issuer must have the same target
power. It does not broaden a retained list or silently reclassify an old deny.
A different new restriction/retention decision requires its own explicit review.

DEC contact/approval invitations are introductions, not bearer admission grants,
so there is no new invite_revoke authority kind or global consumed-invite table.
Each target still needs its own current reviewed host/person/device approvals.
Local cancellation can stop local pending approval but cannot erase a leaked
contact or claim globally revoked access. Keep exact legacy invite-revocation
history under its old context/migration rules; it does not become a new-mode
authority variant merely because its name is familiar.

Fresh local issuance and first local admission of a previously unseen
delegated restriction require the issuer's current complete unexpired path,
role and scope at decision_time, not just a claimed old issued_at. This blocks
an expired or revoked delegated key from manufacturing permanent denies by
backdating. Known locally admitted restrictions persist after issuer expiry,
withdrawal, rotation or context migration; retained evidence is never deleted
because its original signer later loses authority.

An unseen expired/revoked issuer's signed restriction can be stored in bounded
unverified repair storage, but does not become a new permanent deny merely
because its timestamp claims an earlier signing. A current authority with the
same required target power may explicitly ratify it, signing exact old bytes/
ID and target under current parents. Ratification is a new restrictive trust
decision, not proof of a past global commit. Imported old-context restrictions
follow explicit migration endorsement/history rules, not arbitrary new legacy
expansion. Restrictive history already admitted in the caller's durable prior
snapshot remains sticky without re-ratification on every local read.

Historical expired grants are provenance only; no checkpoint, receipt or peer
claim revives current expiry. Historical repair must be separate from a fresh
writer. It can supply exact missing ancestors, completed transcripts and
current authorized ratifications, unioning **all** known local evidence before
projection. Missing proof returns exact sorted required IDs, not a weaker
fallback. A whole-catalog hash or another host's last-sync time is not an
admission authority.

An incomplete prior projection may fetch bounded untrusted proof bytes from
an independently pinned contact solely for repair. Incoming grants cannot
establish eligibility for ordinary peer actions. Apply nothing until the
required current closure for the **affected operation/domain** verifies. A
missing legitimately admitted Alice policy body leaves Alice inactive with its
head/high-water and exact proof_required IDs retained; it does not block a
separately complete Bob/root restriction closure from being admitted. The
projection reports per-domain required_ids and grants nothing through that
incomplete domain. An action needing a missing current root/issuer/target proof
still fails that action. No incoming grant bootstraps prior issuer authority;
forged/malformed bodies do not receive this missing-proof exception. Unrelated
valid restrictions remain ingestible through their own independently complete
closure despite another domain's fork or missing selected body.
Fixed state-reader limits are16MiB exact catalog JSON,8MiB sum of decoded
top-level public object bodies,4096 top-level objects,1MiB per statement or
composite activation/migration body,256KiB decoded statement payload,4096
resolved device leases per original person, JSON nesting depth64 and owner-device
depth8. Arrays of exact IDs are at most4096 entries and also fit the enclosing
byte limits. Each nested composite must pass its own limits; wrappers do not
hide oversized contents. Bootstrap packets/manifest/selected-closure and
publication limits are additionally fixed by the bootstrap contract; each
aggregate limit applies independently. Ordinary mutation transport remains at
most1MiB unless that specific typed route declares a narrower/different bound.
Quota failure never evicts known restrictions, conflict heads or high-water.
Pagination/deltas carry sufficient closure rather than truncating a catalog.

## 8. Local decision clock

Use the local UTC clock plus a persisted per-network largest local decision
time. Schema22 table `dec_clock` has one row per network, keyed by network_id,
with exact strict JSON record
`{format:1,largest_local_time:"YYYY-MM-DDTHH:MM:SSZ"}`. Store whole seconds;
clock-state corruption fails closed rather than resetting the anchor. The row
survives authorized context migration unchanged; when importing an existing
local guard, preserve the maximum of all local guards for this network. A
context switch, renamed network or protocol mode must not reset time. When
legacy local state has no guard, initialize from the actual local clock during
its authorized migration, never from a peer's history timestamp. Never update
this guard from a peer/helper timestamp. Define
`decision_time = max(local_now, persisted_guard)`. If local_now is more than
300s behind the persisted guard, refuse new authority use/issuance/admission
with `clock_rollback` and preserve all authority state. Smaller backward steps
do not move decision_time backward or extend expiry. Future-issued objects are
not usable before their not_before; do not advance the local guard from their
issued_at. A gross future local clock can fail closed; repair is explicit.

Root states and restrictions have no not_before field: their issued_at must be
no later than decision_time before they can first affect active heads, forks or
sticky admitted restrictions. A future-issued signed object can be retained as
bounded inert evidence, but cannot advance the local clock or poison current
state. Reconsider it only at local decision_time when its independent authority
is valid; do not infer a past admission or remote signature time. Fresh local
writers set issued_at from the guarded local time and reject caller-supplied
future issuance. Historical provenance can retain its exact timestamp without
authorizing current actions.

Status/doctor/result views stay read-only and do not advance the guard. They
report unavailable/expired authority truthfully using the same decision time.
A mutating authority operation may commit **only** the monotonic clock-guard
metadata in a narrow transaction before its later main operation refuses;
that documented exception must not change keys, selection, grants, versions,
approvals, consent, events, outboxes or service state. Successful operations
commit the guard with their state transaction. Before each fresh signature
and again in the final apply/publication transaction, re-read the latest local
guard, selection/heads/restrictions and exact consent pins from one coherent
snapshot; recheck expiry at max(actual local now, latest guard). Verification
computed from an earlier snapshot cannot override an intervening guard advance
or authority change. Do not hold a DB transaction across network/SSH/user
waiting; revalidate after the wait. A newly expired intent returns structured
repair/review failure, without regenerating approved bytes or signing a new
generation automatically. Negative conformance snapshots exclude only this
named clock row; every other immutability assertion remains.

An old whole-state backup also restores its old guard and restrictions. SQLite
alone cannot remember a lost newer anchor; do not claim rollback resistance
against restoring the whole trust state. Current reliable time still bounds
old finite leases, but lost restrictions can remain unknown until repaired.
Clock tampering/freeze plus state rollback can defeat real-time bounds without
a trusted time/anti-rollback source; that stronger mechanism is not invented
here. Ordinary shutdown/restart with intact state must retain the guard.

## 9. Persistence/API consequences

Current host schema is21. Add schema22 storage for context/mode pins, exact
statements/proofs, admitted-restriction IDs, stream DAG/heads/fork state,
per-context full-u64 maxima, operation outcomes and the decision-clock guard.
Preserve schema20 approvals and schema21 bounds/gh-source state, existing
host/person/device keys, pending old transcripts, current sessions, projects,
adapter credentials and policy edits. Migration is atomic and failures roll
back. Unsupported schemas refuse before modification.

DB migration does not authorize protocol migration. A new mode pin is monotonic;
old pending operations retain their exact context/keys/deadlines and cannot
resume as new operations. Whole-transcript retries return exact prior outcomes
without overwriting a newer selected device, policy, root or reachability hint.
An old reader must not reinterpret a new lease as a permissive legacy record.
Pure readers, local APIs and bootstrap routes need explicit new protocol
versions; no fake coordinator key or legacy-array projection on the wire.

## 10. Public verification requirements

The independent author should derive exact cases from these rules before
implementation; implementers do not write matching unit tests.

- Each lease class: exact kind/issuer/parent roles, seven-day default/max from
  issued_at (including delayed not_before), every parent ceiling, exact-boundary
  expiry, scope narrowing and missing/cyclic parents. Shared person DAG nodes
  are valid; repeated device-key ancestry/cycles/depth>8 fail. Device host and
  binding expiry cap the device even when its person/issuer remain live.
- Exact same-ds_ envelope aliases retain original dp_ bytes without extra heads;
  differently serialized payloads are distinct statements subject to fork rules.
  Writer retries preserve the exact once-serialized payload and signatures.
- Daily policy/group refresh from a live device while the original key is
  offline; NEW-context policy periods below1 day when capped by a shorter
  parent, exact86400-second maximum and unchanged legacy window rules. Refuse
  at the fixed weekly ancestor deadline; new authorized ancestor renewal
  succeeds without changing old signed deadlines or keys.
- Unchanged current P/H/B renewal by original/strict-ancestor device4 without
  admin/scope2 uses no new binding/admission signature, but still requires full
  requester PoP, selection/final consent and all ceilings. Expired/narrowed
  references, target self-renewal and hidden scope expansion refuse.
- A partitioned descendant cannot extend its parent or treat a fresh local
  signature as no-unseen-revocation evidence. Independent upstream reauthorization
  is recorded as a new trust decision with its explicitly limited guarantee.
- Incomplete/op-bound host/person/binding/device drafts grant nothing; IDs stay
  stable as consent signatures are supplied; exact full transcript activates
  only the selected keys and original person. Every new/renewed device with
  operation_id `-`, missing target PoP or missing final requester consent fails.
  A new pending self-person lease authorizes only own same-operation B/D
  consent, never an unrelated action or role.
- Ancestor renewal with an exact valid retained child/dependency closure keeps
  the child's original owner signature/deadline; omission, narrowing, expiry,
  self-retention, circular retention and missing intermediate retention deny
  without lower fallback. A fresh direct slot cannot choose an old head. Cold
  receivers require the same signed retention chain, not a peer receipt or
  claimed admitted-before bit; old provenance alone cannot authorize a write.
- Policy equal-version and different-version sibling forks, inactive maxima,
  group/admin/root forks, complete resolution and later newly learned branches;
  no permissive hash winner or lower-body fallback.
- Alice policy fork plus otherwise valid Bob/root revocation commits the deny;
  a forked issuer cannot issue fresh grants. Maxu64 round-trip and no-wrap
  refusal leave all authority/reservation/outbound state unchanged.
- Known admitted deny persists after signer expiry; unseen expired/revoked
  issuer backdated deny does not poison state; fresh same-scope ratification
  applies it. Ratification preserves exact target/kept list and same target
  power. Retired-root new denies are not accepted as fresh authority. Root
  withdrawal keeps only explicit finite eligible admissions; groups lose admin
  authority; current-root explicit role regrant differs from irreversible stable
  person/host/device revocation. Owner+host unbind resolution never silently
  revives a device path.
- Root transition carries only exact unexpired leases and complete parents;
  no expiry extension, revocation revival, deleted-old-key assumption or
  highest-epoch branch selection.
- Missing-checkpoint/ancestor repair uses untrusted proof fetching, retains all
  known restrictions/high-water/forks, and cannot bootstrap ordinary peer access.
  Missing admitted Alice policy body preserves its maximum/inactive state while
  independently complete Bob/root restriction still commits. Missing a required
  current root blocks its dependent action; a malformed/forged body is not
  converted into a partial-repair success.
- Future-issued roots/restrictions remain inert and do not create an active
  fork/deny or advance local time. A backdated unseen expired-delegate max-u64
  candidate cannot poison heads. Current independent admission, positive
  reissuance or restriction ratification is required; genuine previously admitted maxima/restrictions remain sticky.
- Clock backward<=300s uses the retained time; greater rollback refuses. Guard
  survives restart and context migration; remote timestamps cannot advance it.
  Status writes nothing; only the documented guard row may change on an
  otherwise immutable refusal. Advance guard/authority between preview and
  final signature/apply and verify the latest coherent snapshot rechecks expiry
  and immutable consent without regenerating bytes or holding a network wait TX.
- An independent owner-local/manual grant stays independent, while merely
  marking a peer known or allow_disconnected cannot revive expired/forked DEC
  rights. PR78/80 per-call approvals, resource bounds, source/trust and ownership
  checks remain required. Queued/new hops recheck; accepted/running outcomes
  preserve their existing semantics.
- Explicit old-to-new migration preserves exact signed history and schema21
  approvals/bounds/gh behavior; empty-address/coordinator-failure downgrade and
  new public coordinator-based creation are refused. Whole-state rollback limits
  are reported without claiming a lost anchor still exists.

## 11. Decisions and discarded alternatives

| Choice | Reason | Discarded alternative |
| --- | --- | --- |
| Seven-day hard management ancestry /24h access bodies | Useful offline interval with an explicit periodic upstream renewal cost. |90-day owner paths described as though owner revocation were bounded by7 days. |
| New signed IDs for renewed generations | A signature from a new upstream authorization is distinguishable from old cached rights. | Recomputing not_after from NOW or silently reparenting old children. |
| Signature-independent IDs / exact same-ds_ aliases | Breaks consent-reference cycles and gives one exact head/reference rule. | Hashing final consent into its own input; typed-equivalent payload aliases that require ambiguous normalization. |
| Explicit exact retention at every ancestor replacement | Preserves reviewed old owner signatures through original bounds; new receivers verify the same evidence. | Automatically retaining every old generation, invalidating every child on routine renewal, or trusting a peer's admitted-before claim. |
| Every device activation uses the full requester transcript | Enforces target proof-of-possession and separate final consent on initial and renewal paths. | Treating an issuer-only ordinary device lease as active. |
| Role/binding regrant is explicit; stable-key bans are permanent | Keeps normal root/owner recovery powers without reviving known old authority. | Accidentally making role withdrawal a permanent person ban or allowing a resolver to undo a compromised-key revoke. |
| Same keys, fresh complete transcripts at migration | Avoids a new cross-protocol device-authority bridge while preserving identity. | Silently converting90-day legacy devices to new finite authority or copying original keys. |
| Per-domain conflict denial and explicit resolution | Converges without an arbitrary permissive winner; unrelated restrictions remain learnable. | Old policy hash tie-break, highest sequence/epoch alone, or rejecting every deny because any other stream forks. |
| Current first admission of delegated permanent denies | Stops unlimited post-expiry backdated network poison. | Treating an untrusted claimed issued_at as evidence of a past authorized commit. |
| Local persistent clock guard with named metadata exception | Handles ordinary rollback/restart honestly without a peer-time oracle. | A signed heartbeat, silent status writes, or claiming an old full backup preserves a lost newer guard. |
| New public lifecycle; exact old history/migration | Removes required infrastructure while retaining authority provenance and identities. | Shipping both coordinator architectures as hidden defaults or stripping pins from signed old bytes. |
