# Coordinator-free independent verification transport and cases

Status: shared contract candidate for root and both implementation owners to review.
2026-10-26. This is a public contract for independent, state-free verification
and subsequent contract-derived cases. It is not an executable suite, runtime
API, implementation inventory, or authorization to start implementation before
the complete DEC contract set is reviewed and merged. The umbrella contract
fixes that implementation pin. Base implementation main is
`6d3823fd3115fff247b1af8551553baf30e97f0f`, schema21.

Read this with the [authority](decentralized-authority-contract.md),
[bootstrap](decentralized-bootstrap-contract.md),
[migration](decentralized-migration-contract.md), and
[umbrella](decentralized-network-contract.md) contracts. Those documents define
signed authority. This document defines how identical public inputs and
private-caller prior-state fixtures produce comparable observations in Go and
Rust. Root must reconcile and pin their exact errors and fields together.

## 1. Independence and limits of the result

The separate author derives vectors and cases from public contracts only. The
author does not inspect either implementation, implementation inventories, or
implementer tests. Implementers supply adapters to the pinned interface; they
do not change expected case outcomes to match an implementation.

Every operation below is pure: no database, key generation, signing, network,
DNS, helper, clock-file read, filesystem mutation, or remembered state between
input lines. All keys/signatures are public. No input contains a private seed,
pairing secret, operator token, private attachment credential, or SSH agent.
The explicit `now` value models the trusted local caller's wall clock; it is
never taken from signed remote objects.

A successful decoder proves syntax/signatures/IDs only as specified. A
successful projection proves the stated cryptographic facts under the supplied
trusted context/prior; it does not establish owner-local adoption consent,
owned private keys, actual publication, globally latest state, reachability,
network-wide commitment, or live agent execution. Runtime and installed cases
remain separate gates.

## 2. JSONL carrier

Both existing verification binaries expose an explicit new
`--decentralized-verify` mode. Their existing default/stored modes and budgets
remain unchanged. Invocation paths are supplied to the eventual independent
suite; the suite does not build or locate a preferred implementation.

The mode reads UTF-8 JSON lines on stdin and returns exactly one compact JSON
object plus LF on stdout for each input line. No progress/log text goes to
stdout. A final unterminated line is processed. An empty line is `invalid`.
Malformed input returns the structured error and the next line is processed.
Usage or internal I/O failures exit nonzero; they must not masquerade as a
successful verification or ordinary invalid-vector result.

The fixed carrier cap is **64MiB per framed input or output line, including
LF**; a final unterminated line counts its actual bytes. Reject an oversized
input with `quota_exceeded`, drain it to its delimiter, and continue. This cap
accommodates a full prior catalog plus a full candidate catalog in Base64;
it does not increase any authority/bootstrap/migration object or decoded-data
budget. No caller-supplied budget, permissive parse mode, or truncation is
accepted. Each decoded object/catalog still obeys the final protocol's own
count, byte, payload, dependency, and recursion limits.

All requests have `format:1` and one `kind` below. Reject duplicate, missing,
unknown, null, or incorrectly typed fields. Base64 is canonical padded standard
Base64. An absent optional value is the literal string `"-"`, never null or an
omitted field. Unsigned integers are exact JSON u64 numbers, without float
rounding. Array ordering follows the rules below. No strings are silently
trimmed, Unicode-normalized, re-encoded, or parsed as another identifier type.

## 3. Common errors and order

Failure is exactly:

```text
{ok:false,code:CODE,required_ids:[ID,...]}
```

`required_ids` is sorted, distinct, and nonempty only when `proof_required`
has exact derivable missing references. It may be empty when the missing bytes
do not determine an ID. Never guess an ID, return a partial projection, return
an output catalog, or leak variable implementation errors on failure.

Proposed common codes, to pin with the main contracts:

| Code | Meaning |
| --- | --- |
| `invalid` | Bad encoding/type/shape/ID/signature, wrong signed context or subject, impossible exact-reference relation, or a mismatching first pending review pin. |
| `quota_exceeded` | A fixed framing/object/catalog/count/depth budget is exceeded. |
| `proof_required` | A required exact proof, ancestor, complete activation, retention, migration origin, or prior selected body is absent. |
| `state_conflict` | A remembered context/root/proposal pin conflicts, or an operation explicitly requires a single usable domain that is forked. |
| `operation_conflict` | An already known request/manifest/activation immutable tuple conflicts; an exact old outcome is not replaced. |
| `forbidden` | The exact known issuer, role, scope, target or ownership is unusable, withdrawn/unbound/removed, or cannot authorize this action. |
| `authority_would_be_invalidated` | The typed action would invalidate the exact authority needed to authorize itself, under the existing operation-specific guard. |
| `device_revoked` | The selected device's stable key or an applicable ancestor device key is known revoked. |
| `authority_expired` | An exact required finite authority path has reached its hard deadline. |
| `not_yet_valid` | The exact required authority is not yet effective at the decision time. |
| `expired` | An access-body or local honest-signing window has expired; it is not a fabricated withdrawal of complete consent. |
| `clock_rollback` | Local time is more than300s behind the retained local guard. |
| `upgrade_required` | An explicitly requested legacy/new-mode boundary refuses downgrade; never a transport-failure fallback. |

An admitted, cryptographically valid fork is normally a **projection domain
state**, not a global error: a projection can return both conflicting heads and
an independently authorized unrelated restriction. `state_conflict` is used
when a requested single action/pin cannot proceed, not to discard every other
otherwise valid domain.

Parse/budget/context/self-consistency checks precede dependency resolution;
an internally wrong signed epoch/target must not be hidden behind a fabricated
missing reference. Verify required cryptographic provenance before admitting a
new head/maximum or reporting a current-path denial. Cases with multiple
independent invalid fields assert refusal, not arbitrary error precedence,
unless the main contract specifically orders those checks. Exact-code cases
isolate one cause.

The runtime's `version_exhausted` default-generation guard is not exercised by
submitting an already encoded unsigned payload with version max-u64. A literal
max-u64 value can be valid signed evidence. This pure interface has no implicit
increment/reservation/sign operation, so default-increment overflow remains a
runtime case unless a separate exact generation-intent operation is later
explicitly contracted.

## 4. Trusted prior snapshot versus network candidates

Projection inputs distinguish a trusted **private caller's durable prior** from
untrusted candidate proof bytes. A network peer/helper/catalog can never supply
or promote these private admission, pin, maximum, or clock fields. Probe callers
can provide them only to model an actual prior verification/storage history.
This carrier is not a peer API and must never be exposed as one.

`PRIOR` is `"-"` for no remembered new-context state, or exactly:

```text
{format:1,context_id,catalog_base64,
 admitted_statement_ids:[DS,...],admitted_restriction_ids:[DS,...],
 admitted_activation_ids:[DA,...],root_head_ids:[DS,...],
 maxima:[{stream:[COMPONENT,...],sequence:U64,statement_ids:[DS,...],
          head_ids:[DS,...]}],
 migration_proposal_id,clock_guard}
```

Every ID array is sorted/distinct. `admitted_statement_ids` contains previously
admitted root/lease/access statement IDs; restrictions and complete activations
have their separate arrays. Exact proof aliases remain in the catalog and do
not create extra semantic heads. `migration_proposal_id` is `"-"` or the pinned
complete migration's exact proposal ID. `clock_guard` is `"-"` or the prior
whole-second UTC local guard. Arrays are present even when empty.

`admitted_activation_ids` records verified complete-consent provenance, not
admission or current usability of every statement in an operation. Every
statement still needs its own admission basis and current authority checks.
An activation marker cannot manufacture earlier statement admission, a
globally trusted commit time, a local participant outcome or a selected signer.

Stream keys are unambiguous tuples, rather than a slash-delimited parse:
`["root"]`, `["admin",PERSON]`, `["person",PERSON]`, `["host",HOST]`,
`["binding",HOST]`, `["device",PERSON,DEVICE]`, `["policy",PERSON]`,
or `["group",NAME]`. Sort tuples lexicographically by UTF-8 component bytes;
sort `maxima` by tuple. A maximum is positiveu64 for every ordinary lease/access
stream; **only `["root"]` permits0**, and its `sequence` field represents the
retained root epoch. A non-absent prior with an admitted/pinned root has exactly
one root maximum row, including genesis0 and max-u64. `statement_ids` identifies
the admitted exact statements at that maximum. Separate head_ids preserves ALL
independently admitted incomparable maximal heads, including a lower-sequence
fork, even when a remembered access body is missing. Root head_ids is identical
to root_head_ids. Both arrays are sorted/distinct; they are not inferred from
one another. Every head belongs to the stated stream and admitted prior history;
present bodies must agree with the retained metadata. An inherited floor with
no admitted new-context head has head_ids empty. A migration-inherited floor can
have no new-context statement ID; its complete migration must authenticate the
exact legacy floor. Such metadata never supplies an active body or fresh owner
signature. A missing remembered root body cannot erase its root epoch maximum,
reveal a lower root, or authorize a fresh genesis under the remembered network.

Validate the prior's strict shape, context, exact proof IDs, signatures and
structural provenance before use. Any present forged/malformed proof still
fails with `invalid`; a previous admission marker never forgives it or supplies
missing complete consent/structural ancestry. Current expiry/withdrawal can
make a previously admitted object inactive without erasing its admitted
history/head/maximum.

An exact prior access-body absence is an explicit unavailable-domain state.
The trusted prior maximum/statement-ID/head-ID metadata can preserve that known policy
or group head/floor while the body is missing, but supplies **no** active body,
current issuer path or signature. Preserve the maximum and known IDs, report
that stream inactive with `proof_required` and its derivable exact missing
IDs, and do not activate a lower body. This absence alone must not block an
independently verified Bob/root restriction in another domain. Exact candidate
repair may supply the missing bytes. The exception does not admit an arbitrary
candidate with an unresolved closure, excuse a forged present proof, or make a
missing activation/consent valid. Any requested action depending on unavailable
material still fails `proof_required` with its exact missing closure. A claimed
clock, admission ID, root head or maximum inside the **candidate** catalog has
no such trust.

For cold inspection, the caller independently pins the descriptor/root identity.
The candidate must prove its valid genesis or complete migrated origin; `PRIOR`
being absent is not permission to accept any context from a helper. This pure
inspection does not perform owner-local adoption on the caller's host.

`LEGACY_PRIOR` is `"-"`, or exactly:

```text
{format:1,legacy_descriptor_base64,legacy_catalog_base64,
 legacy_feature_id,legacy_epoch,legacy_root_public_key,source_state_base64,
 clock_guard,pending_operation_ids:[ID,...],
 acknowledged_proposal_id,acknowledged_prepared_sha256,
 acknowledgment_base64,adopted_context_id,adopted_proposal_id}
```

`source_state_base64` is the migration contract's exact source-state snapshot:
its network/root high-water, known admitted hosts, access maxima and admitted
restriction provenance. It does **not** embed the legacy descriptor, catalog,
feature or root chain. Those exact locally retained bytes and pins are supplied
separately by `legacy_descriptor_base64`, `legacy_catalog_base64`,
`legacy_feature_id`, `legacy_epoch` and `legacy_root_public_key`. The local
catalog must independently verify that remembered current root/lineage and
feature before it is unioned/compared with the incoming complete proof. A root
or catalog asserted only by that incoming proof is never substituted for the
local current-root pin.

Other fields model the private durable fence, known unresolved operations and
adoption pin. Absent individual pins/bytes are `"-"`; an actual legacy epoch is
a JSON u64 number and permits0. Public complete evidence cannot invent these
owner-local facts. A new/restored host without the required persisted approval
must use the explicit recovery/enrollment procedure, not set a Boolean in a
network request.

## 5. Exact request operations

### Descriptor

```text
{format:1,kind:"descriptor",descriptor_base64}
```

Success is exactly `{ok:true,context_id,network_id,genesis_root_public_key}`.
Check the complete descriptor and exact shared context message. The result
does not claim that the caller has adopted that descriptor.

### Statement

```text
{format:1,kind:"statement",descriptor_base64,statement_base64}
```

This checks the complete public envelope's strict shape, kind-specific payload,
exact semantic/proof IDs and all declared signature roles. It checks intrinsic
typed constraints; it does not invent missing external parents or claim current
authority. Structurally complete expired evidence can decode successfully.
An incomplete private binding/device draft cannot pass as a public statement.

Success is exactly:

```text
{ok:true,context_id,statement_kind,statement_id,proof_id,
 payload_base64,signers:[{role,public_key,signature_format}]}
```

Return the original exact payload Base64, never a reserialization. Signers are
sorted by role. Structural cryptographic verification may require the selected
key/reference closure; callers use projection/action/activation operations for
that complete authority check. Decoder success is not an admission result.

### Catalog

```text
{format:1,kind:"catalog",descriptor_base64,catalog_base64}
```

Check the full catalog's framing, exact object IDs/kinds/bytes, sorted unique
proof IDs and each object's structural public form. Composite activation and
migration kinds use their explicit public schemas, not a guessed ordinary
statement parser. No current admission or latest-head claim follows.

Success is exactly `{ok:true,context_id,proof_ids:[DP,...]}`.

### Clock

```text
{format:1,kind:"clock",now,clock_guard}
```

`clock_guard` is `"-"` or the trusted prior UTC value. Success is exactly
`{ok:true,decision_time,next_guard}`. Compute the maximum of local `now` and
the prior guard. At a backward step of exactly300s this succeeds; a larger
step returns `clock_rollback`. `next_guard` is the monotonic value a successful
mutating caller could persist. This operation actually writes nothing.

Pure status/read projections never advance a real guard. Runtime mutations may
use only the authority contract's named guard-row exception on later refusal;
that exception grants no authority and is tested at runtime separately. Never
advance a guard from remote `issued_at`, contact time, outcome time or history.

### Projection and heads

```text
{format:1,kind:"projection",descriptor_base64,prior:PRIOR,
 candidate_catalog_base64,now,operation:"read"|"fresh"|"repair"}
```

For `read`, candidates are `"-"` and no prior admission/guard metadata changes.
For `fresh`/`repair`, candidates are a complete catalog object; evaluate the
private union with every prior proof, pin, restriction, head and maximum.
Fresh and historical-repair rules remain distinct. A repair flag does not
admit expired new grants, backdated restrictions, missing-consent devices or
unratified cold historical claims. Admit candidates only under the final
authority contract's current/portable-retention rules. Missing closure required
to validate a new candidate or the requested whole operation returns
`proof_required` without a partial result. An unrelated exact prior access-body
absence has section4's narrow unavailable-stream behavior instead: return its
missing IDs in that stream while independently valid restrictive additions in
other domains can proceed. Valid admitted forks return domain conflicts; they
are not malformed objects.

For this pure PROJECTION operation, a structurally and cryptographically valid
unadmitted candidate whose complete closure proves it has no current admission
power is inert evidence. Return success with its semantic ID in
inert_statement_ids; it does not enter admitted IDs, heads, maxima or sticky
restrictions. This includes an ordinary grant/deny from a retired root or a
currently wrong-scope issuer. Apply the exact current and portable-retention
rules before making that determination. A missing closure is proof_required,
not permission to guess that the issuer is unauthorized. Malformed/forged
evidence is invalid. Previously admitted heads/restrictions retain their
contracted provenance even after their old issuer loses authority; mere current
inactivity does not reclassify them as unadmitted. Root-transition equivocation
has its separate explicit fork rule and is not an ordinary retired-root grant.

Unadmitted ordinary statements retained in the evaluated union are reported
once by semantic ID, irrespective of proof aliases. Recognizing them as inert
is not publication, local signing, owner adoption or a successful ACTION; an
action requiring that denied authority returns its actual denial code. Cold
inspection still requires its independently pinned valid genesis/migrated
origin. No candidate-only admission marker or metadata is a trusted prior.

In particular, an independently valid root may admit an ordinary P/H/admin
candidate, but that newly supplied P/admin does not become a pre-pass issuer
for an unrelated policy/grant in the SAME projection. That dependent candidate
is inert for this pass. A later operation with legitimately committed next_prior
may evaluate it under the then-current authority. Do not run an intra-batch
grant-as-issuer fixed point or invent prior acceptance. The explicit local
genesis, same-operation complete activation/migration and portable-retention
exceptions retain their exact separate consent/provenance rules.

The bootstrap contract's complete-activation DAG exception permits a cold
receiver to verify the exact selected components and actual packet issuer
ancestry, including complete ancestor activations, in dependency order. It
does not extend to an unrelated ordinary statement. Evaluate each selected
component's own current path independently: an expired target D is inert when
first learned and supplies no head/maximum or issuer power, while independently
live P/H/B may be admitted. An already admitted expired D keeps its prior
history under the normal rule. Complete consent is required on either path;
no timestamp or activation marker substitutes for a current issuer path.

Selected: inert complete unauthorized candidates in an untrusted state union,
with explicit action denials and separately admitted prior authority. This lets
unrelated valid restrictive updates progress. Discarded: rejecting an otherwise
complete projection solely for such an inert candidate, admitting its maxima,
and silently using a new batch grant as another fresh action's issuer.

Success is exactly:

```text
{ok:true,context_id,decision_time,
 root:{head_ids:[DS,...],maximum:U64,selected_id,conflicted,code,
       required_ids:[ID,...]},
 streams:[{stream:[COMPONENT,...],head_ids:[DS,...],maximum:U64,
           selected_id,active,code,required_ids:[ID,...]}],
 restrictions:[DS,...],inert_statement_ids:[DS,...],next_prior:PRIOR}
```

IDs/streams are sorted as above; `streams` contains only non-root domains,
because the root domain is reported by `root`. Restriction output contains
admitted exact restriction statement IDs. Root maximum0 is a valid genesis
epoch, not absence; ordinary lease/access rows have positive maxima whenever
an admitted generation/floor exists. `selected_id` is `"-"` where no single statement
can be selected. `active` never follows merely from the largest sequence.
`code` is `"-"` for no applicable denial, otherwise the specific unavailable
authority code. A fork reports all maximal heads and `state_conflict`, with no
positive selection in that domain. An expired latest body remains a head and
maximum. A root dispute supplies no current root for dependent positive paths.

Each row's `required_ids` is sorted/distinct and empty unless its code is
`proof_required`; an exact missing prior statement ID is returned when known,
otherwise no ID is guessed. For a known single head whose body is missing,
retain that exact `selected_id` and `head_ids`, set `active:false`, preserve
`maximum`, and report `proof_required`. A floor without a known new-context
head retains `selected_id:"-"` and does not invent one. An expired/inactive
lower body cannot be substituted for missing selected material. The root row
uses the same error/required-ID representation and retains its exact epoch
maximum (including0/MAX) even if its selected body is missing; its unavailable authority
cannot be bypassed by a dependent stream. This row schema is an observation,
not permission to ignore missing root/consent provenance.

A remembered pair of incomparable head_ids remains a fork even if one access
body is missing. Preserve every head and the numeric maximum, select none and
report state_conflict; missing bytes cannot collapse it to a unique lower head.
An operation requiring those missing exact bodies still returns proof_required.

`next_prior` contains the exact retained union and updated admitted metadata,
not normalized signed bytes. It preserves previously admitted maxima even when
inactive and never admits candidate-only claims of prior acceptance. In a read
it is identical to the supplied prior. In a successful fresh/repair proposal its
clock guard is the decision time. The pure adapter does not persist this value;
the actual runtime must perform its own coherent transaction/consent checks.

### Action or typed signing-intent authority

```text
{format:1,kind:"action",descriptor_base64,prior:PRIOR,
 candidate_catalog_base64,now,
 actor:{person_public_key,host_public_key,device_public_key,issuer_id},
 action_kind,unsigned_payload_base64}
```

Actor models the pure issuer identity, not local key ownership or a target-host
cosigner. Its exact mappings are:

- Original person: person_public_key is that original key; host_public_key,
  device_public_key and issuer_id are `"-"`. Independently resolve its current
  P admission and the typed payload's exact required parent references.
- Device: person_public_key, host_public_key and device_public_key match the
  exact currently activated issuer D; issuer_id is that D's ds_.
- Root: all three actor key fields are `"-"`; issuer_id is the exact current
  root_state ds_. For the explicit root-resolution check only, it can instead
  name one retained disputed branch: the proposed resolution must cover ALL
  known root heads, and this check permits only that branch's typed cosignature.
  No branch becomes current, and all other branch/new-root signatures remain
  mandatory before final application.

Reject superfluous actor identity claims. A non-`"-"` value in an unused actor
field fixed to that literal above is invalid before current-authority checks;
a correctly framed actor lacking actual power returns its authority denial.
Target keys/host consent are checked
through the typed payload and final signature roles, not inferred from actor.
Runtime selected-provider/own-host binding and private-key checks remain
additional. The unsigned
payload is the exact fixed intent for that action kind from the authority or
runtime contract. This is not arbitrary signing. Check current exact heads,
every ancestor/retention, target/role/scope, lifetime ceiling, restrictions,
self-invalidation and validity of the explicitly supplied sequence before any
proposed signing. It does not choose or increment a default sequence.
No key ownership or actual signature is asserted by the adapter.

Success is exactly:

```text
{ok:true,context_id,decision_time,issuer_id,signer_public_key,
 required_parent_ids:[DS,...],effective_not_after}
```

This operation does not admit its unsigned payload, change a stream head,
reserve an edit/sequence, or produce a signed object/catalog. Signed verification
remains mandatory after the real provider signs. Unknown action kinds are
`invalid`.

The registry is exactly the ordinary runtime action kinds: admin/person/host/
binding lease, policy, group, admin_withdraw, person_remove, host_revoke,
host_unbind, device_revoke and root_state transition/resolution. Device issuance
and migration have their dedicated complete protocols, not ordinary actions.
Response issuer_id preserves the exact mapping above. required_parent_ids is
sorted unique root_state_id plus declared parents[].id for an ordinary payload;
for a root transition/resolution it is the direct predecessor root IDs (all
known heads for a resolution). This field lists direct authority references,
not transitive proof closure, target-stream predecessor history or edit rows;
every required dependency still verifies before success.

Selected: a fixed issuer-only actor and direct-reference result, keeping the
pure authority check separate from runtime key custody and target consent.
Discarded: accepting unused actor claims or interpreting the public provider
view's original-person lease_id as a different pure actor selector.

### Complete activation

```text
{format:1,kind:"activation",descriptor_base64,prior:PRIOR,
 catalog_base64,activation_base64,now,expected:EXPECTED|"-"}
```

`EXPECTED` is exactly:

```text
{request_id,context_id,mode,person_public_key,host_public_key,device_public_key,
 renewed_device_lease_id,owner_offer_id,selection_id,administrator_offer_id,
 scopes,not_after}
```

It models private persisted reviewed pins; it is not supplied by an untrusted
packet/helper. For generic public evidence verification use `"-"`. Verify every
applicable stage and exact explicitly permitted skip, nested bytes, signature
roles, dependency closure, final binding proof, manifest and current finite
authority/retention/restrictions. In the contracted unchanged-person/host/binding
renewal variant, administrator packet/ID and commit binding-host signature are
`"-"`; owner finalization and manifest must instead pin the exact existing
complete binding proof. This is no omission exception for a changed admission
or binding, and the new device generation still requires its non-`-` operation,
target host/device possession and separate requester selection/final consent.
Later learning beyond300s is distinct from fresh honest local signing; no
participant/helper timestamp is a globally trusted commit time. A known exact
operation cannot be replaced with another manifest or become a new application.

This operation's success requires current usability of its selected D. The
projection operation can instead learn complete consent and independently
current components of an earlier activation whose D is expired, under the
bootstrap contract's narrow DAG rule; that does not make this operation succeed.
For a new binding, the nested owner-finalization draft has both canonical
signature entries and the host signature literal `"-"`. That placeholder is
invalid in a standalone public binding or its manifest-pinned final proof.

Success is exactly:

```text
{ok:true,context_id,request_id,manifest_id,activation_id,
 person_public_key,host_public_key,device_public_key,device_lease_id,
 scopes,effective_not_after,required_statement_ids:[DS,...],
 required_proof_ids:[DP,...],review_pins_matched}
```

`review_pins_matched` is false when expected is `"-"`; otherwise every pin must
match exactly or the call fails. It does not assert that keys are locally owned
or consent was newly obtained. Exact original proof aliases are compared by
required/excluded IDs and source bytes; no minimal closure or preferred alias
is inferred unless the main contract requires it.

Both required arrays are sorted/distinct and include the issued D plus every
required ancestor statement, and all manifest-pinned proof IDs, respectively.
Additional verified supplied aliases/dependencies are permitted; every returned
ID must correspond to exact verified source bytes. The activation argument can
itself supply its dp_ for this verifier observation. That does not add it to
its own signed manifest. Current outcome/helper/event/private IDs are never
authority dependencies and cannot be fabricated into either array.

### Complete migration

```text
{format:1,kind:"migration",descriptor_base64,
 legacy_prior:LEGACY_PRIOR,prior:PRIOR,migration_base64,now,
 purpose:"evidence"|"adoption",local_host_public_key}
```

Verify the exact composite form in the migration contract, including its source
state/hash, current legacy root lineage, proposal, derived staged initial root,
prepared catalog, per-host bootstrap consents, acknowledgments and final root
commit. This dedicated staging verification must not make an inert context or
staged signer usable for arbitrary actions. Check every participant's common
prepared hash, roster tuple and exact signed references. Reject competing
complete origins rather than selecting first arrival or a high timestamp.

Evidence purpose permits `legacy_prior`, `prior` and local host `"-"` for cold
portable verification. It makes no owner-local adoption claim. Adoption purpose
requires the actual trusted legacy prior and this exact local host's persisted
acknowledgment/approved proposal. Public evidence alone cannot synthesize it.
Union every known local restriction/floor and compare all remembered mode/root/
proposal/fence pins before proposing adoption. Expired prepared grants may
establish a genuine complete context origin but supply no current positive
authority. An existing newer provider/head is never rolled back by exact replay.

Success is exactly:

```text
{ok:true,context_id,proposal_id,root_state_id,prepared_catalog_sha256,
 roster_host_public_keys:[KEY,...],local_approval_matched,
 context_origin_valid:true,usable_device_lease_ids:[DS,...],
 inactive_device_lease_ids:[DS,...]}
```

`local_approval_matched` is false for evidence purpose without exact local prior
approval. Missing approval in adoption purpose is `forbidden`; conflicting
remembered proposal/mode/fence is `state_conflict`. Missing exact source/ack/
commit/dependency uses `proof_required` only with derivable IDs. No successful
migration result is an actual local adoption/event or a promise of readiness.

## 6. Proposed bounded public case groups

These are specification obligations, not executable cases. The final pinned
Verification sections choose the exact isolated cause/error for each vector.

| Group | Required independent observations |
| --- | --- |
| D01 context | Empty-config descriptor; exact protocol/context hash; wrong name/genesis/protocol; no address/helper identity in authority. |
| S01 bytes/signatures | Every statement kind/role; exact ds_/dp_; signature alias with same payload; reserialized payload is a distinct statement; wrong role/key/namespace, duplicate/unknown fields, full-u64 and invalid primitive types. |
| C01 budgets | Inclusive framing including LF; final unterminated line; every fixed decoded/object/catalog/count/depth boundary; no caller budget or partial output. |
| P01 finite parents | Every root/person/device issuer class, scope, subject relation, shared person DAG, device-only cycles/depth, seven-day/24h ceilings and exact expiry; missing complete target consent never activates. |
| P02 renewal | Original key offline daily refresh; hard ancestor deadline; explicit upstream renewal; exact retained descendant/dependency closure; cold receiver cannot substitute local admission metadata for portable retention. |
| P03 heads | Equal/different-sequence incomparable heads; inactive maxima; resolver covering all known heads; later branch reopening; retained/root transition forks; prior Alice selected body missing reports its stream's exact missing IDs/inactive preserved maximum while an independently valid Bob/root deny is admitted. |
| P04 provenance | Same signed restriction admitted while live stays sticky later; cold candidate after issuer expiry remains inert until current ratification; old candidate max-u64 never poisons authoritative maxima. |
| T01 clock | Exactly300s rollback versus301s; guard restart/migration continuity; remote future times cannot move guard; read/status no writes; advance guard/authority between intent and final authoritative transaction. |
| A01 typed actions | Exact actor/scope/path; no fallback from selected broken device; wrong target; self-invalidating action returns authority_would_be_invalidated; an action requiring Alice's missing selected body fails proof_required; a valid literal max-u64 payload is distinct from the runtime default-increment exhaustion gate; preserve capabilities78/80 and independent resource-owner permissions. |
| B01 activation | Every absent/reordered/wrong-context required stage and exact allowed renewal skip; unchanged P/H/B renewal needs no unrelated admin8 or binding2 authority but keeps its exact complete binding proof/ceilings; changed admission/binding requires the full applicable approvals; new/renew identity pins; two separate requester consents; pending self-person target exception only; complete exact late learning with live versus expired/withdrawn parents. |
| B03 consent and cold ancestry | Exact nested binding host-placeholder role/key/format versus omitted or completed host role; ordinary binding placeholder invalid; complete ancestor activation DAG learns independently live P/H/B despite expired old target D, without admitting that D or changing its heads/maxima; current selected issuer and all portable retention still required; unrelated same-pass ordinary grants remain inert; a new pure activation/application still requires usable selected D. |
| S02 typed signature formats | Original-person statement and packet authority signatures require Ed25519/SHA512 SSHSIG with the exact namespace; raw originals fail; roots may use raw Ed25519 or selected SSHSIG; host/device signatures require raw Ed25519. Format validity never supplies issuer authority. |
| B02 retry | Same request/manifest exact outcome; conflicting immutable tuple; proof aliases; earlier operation cannot replace later selected provider/root/maxima; helper outcome never replaces consent. |
| M01 migration | Before/after legacy linking; successor root without genesis private key; owned/unbound and unavailable roster hosts; exact authenticated source floors/restrictions; staged grants remain inert outside complete migration. |
| M02 adoption | Same keys and original-person approval; no silent scope increase; missing local acknowledgment; all-host prepared-hash mismatch; root final commit; competing complete proposals; late context origin with expired prepared grants. |
| M03 fence | Acknowledgment survives restart; no timeout abort/new network-derived work/positive old publication; restrictions and independent manual actions retain their own rules; failure preserves all state except named guard metadata. |

The eventual pure suite uses only fixture-owned keys and public signing codecs.
Runtime suites separately verify actual signature refusal, durable guards and
catalogs, local consent, crash barriers, exact events, helper/router isolation,
relay4 hostile inputs, NAT/helper replacement and normal installed all-four
pairings. Separate-machine/live-agent completion is recorded independently.

## 7. Decisions and discarded alternatives

| Choice | Reason | Discarded alternative |
| --- | --- | --- |
| Explicit new pure mode, old modes unchanged | Gives both languages one bounded comparison surface without weakening frozen legacy readers. | Reusing a permissive default parser or letting a caller choose verification budgets. |
| Trusted prior separated from candidate bytes | Models genuine durable admission/clock knowledge while making the network trust boundary visible. | Letting an incoming peer assert already-admitted restrictions, maxima or local consent. |
| Exact semantic IDs and exact proof aliases | Tests portable references and retries without reconstructing signed bytes. | Comparing reserialized JSON or silently treating different ds_ values as one statement. |
| Domain conflict observations in projection | Allows restrictive evidence to progress without a permissive fork winner. | Global success-by-hash or discarding every valid deny because another stream forks. |
| Pure evidence verification separated from local adoption | A public transcript can be cryptographically valid without authorizing a restored host to create local consent. | A generic import Boolean or a helper receipt that adopts a network. |
| Exact errors for isolated causes | Makes parity meaningful without requiring accidental ordering of multiple unrelated failures. | Tests that encode one implementation's internal check sequence. |
