# Coordinator-free independent verification transport and cases

Status: shared contract candidate for root and both implementation owners to review.
2026-10-26. This is a public contract for independent, state-free verification
and subsequent contract-derived cases. It is not an executable suite, runtime
API, implementation inventory, or authorization to start implementation before
the complete DEC contract set is reviewed and merged. The umbrella contract
fixes that implementation pin. Base implementation main is
`6d3823fd3115fff247b1af8551553baf30e97f0f`, schema21, was the initial baseline.
The current additive storage target is DEC23 over the merged remote MCP/OAuth22
baseline. Earlier experimental DEC22 receipts remain historical, not evidence
for the newly allocated migration.

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

Strict decoded local-known descriptor/source-state compatibility and exact
catalog-body tuple comparison follow the migration contract's known-source
rule. A separately materialized local wrapper can differ in object-key order,
whitespace or accepted string escaping without changing its exact decoded
pins/facts. Keep the proposed original bytes and declared hashes unchanged;
never substitute a typed/reserialized proof body or incoming-only root for the
independently verified local evidence. This is not semantic hashing of signed
objects or permission to omit a known local floor/host/restriction.

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

A typed signing intent's `retained_statement_ids` is the caller's explicit
selection of grants to preserve. Before returning signable success, every
selected finite grant and its actual retiring contribution must be independently
eligible both at the exact fixed transition `issued_at` and at current guarded
`now`. If a child begins only after that fixed transition, complete evidence
returns `forbidden` for this signing preparation even if it is live at `now`.
Apply the same reviewed-selection rule to root and finite successor intents.
Normal current expiry/missing-proof categories still apply. Do not drop an
ineffective selection or rewrite the fixed payload; choosing another list
requires a new explicit reviewed intent.

For all-head root resolution, use the authority contract's narrow hypothetical
per-branch retention check. It ignores ONLY the global root-fork freeze for
this proposed retention evaluation and intersects every branch/path's existing
power/closure. It creates no current root/provider or fresh action authority.
Complete all-branches-carry succeeds for a matching branch cosignature; omission,
loss of an actually required role/power or applicable restriction on any branch
refuses. Intersected surviving scopes remain retainable: nominal15 narrowed to
effective7 can preserve common policy1, never restore the lost8. Missing exact
closure remains proof_required. Issued_at/current-time checks and current
non-root stream conflicts remain intact. Signed root verification still has
its separate valid-rotation/ineffective-finite-retention semantics.

This preparation rule does not change public verification of a signed root
transition: an otherwise valid key rotation still advances the root DAG when
its finite retention is ineffective, and the selected child still conveys no
power under the authority contract. Selected: refuse a known ineffective
retention selection before local signing, while preserving independent key
rotation verification. Discarded: advertise unusable selections as preserved,
invalidate a correctly signed root rotation because its child cannot be kept,
or infer a new child grant from the list. Verification pairs an unsigned
transition prepared atT0/recheckedT1 with child.not_before=T1 (preparation
forbidden) and the same correctly signed transition's projection (root advances,
child forbidden), plus a valid eligible selection and the finite-successor case.

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
The statement-array minimum is exactly the issued D plus the signed manifest's
ancestor_statement_ids (the complete D dependency closure). An applicable
administrator packet's separate issuer path can be required for stage authority
without becoming a D ancestor when its P/H are existing independent references.
Those packet-issuer DS values are permitted additional verified dependencies,
not an extra statement-array minimum. All manifest-pinned DP values remain
mandatory, including the exact packet-issuer proof closure; every applicable
stage's current authority is still independently checked.
Selected: the signed D-ancestry minimum with all independently required proof
pins and stage checks. Discarded: extending the statement-array minimum to
separate packet-issuer paths, which are not necessarily ancestors of D.
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
| T02 fixed intent time | Pure action at issued+1s and+300s retains the exact payload and current checks; future issuance is invalid, +301s expired. Incomplete creation past its initial window needs explicit same-pin approve, never GET/resume/submission refresh; new approval changes only approved_at. Completely signed pending creation may apply later only while all exact proofs remain currently valid. Expired finite proof, changed identity or concurrent restriction refuses without a new event/provider/authority write. |
| A01 typed actions | Exact actor/scope/path; no fallback from selected broken device; wrong target; self-invalidating action returns authority_would_be_invalidated; an action requiring Alice's missing selected body fails proof_required; a valid literal max-u64 payload is distinct from the runtime default-increment exhaustion gate; preserve capabilities78/80 and independent resource-owner permissions. |
| B01 activation | Every absent/reordered/wrong-context required stage and exact allowed renewal skip; unchanged P/H/B renewal needs no unrelated admin8 or binding2 authority but keeps its exact complete binding proof/ceilings; changed admission/binding requires the full applicable approvals; new/renew identity pins; two separate requester consents; pending self-person target exception only; complete exact late learning with live versus expired/withdrawn parents. |
| B03 consent and cold ancestry | Exact nested binding host-placeholder role/key/format versus omitted or completed host role; ordinary binding placeholder invalid; complete ancestor activation DAG learns independently live P/H/B despite expired old target D, without admitting that D or changing its heads/maxima; current selected issuer and all portable retention still required; unrelated same-pass ordinary grants remain inert; a new pure activation/application still requires usable selected D. |
| B05 cold selection preparation | With no adopted network, a complete current signed existing-person owner offer and exact P/H/B/issuer closure supports selection preview without an earlier local import. Wrong binding/owner/requester pins, expired/revoked authority, missing exact bytes, known forks/high-water/restrictions and incomplete device activation still refuse. The separately specified new-original possession-only offer remains selectable under exact PoP/reviewed psi2 pins, with no authority derived from root/P placeholders. Preserve exact existing authoritative state and keep unrelated policy inert. Preview creates no consent; explicit selection fixes only its own private pending consent/packet, with no member/provider/adoption/application or final commit consent. Complete usable evidence cannot produce empty proof_required solely for lack of prior requester admission. |
| S02 typed signature formats | Original-person statement and packet authority signatures require Ed25519/SHA512 SSHSIG with the exact namespace; raw originals fail; roots may use raw Ed25519 or selected SSHSIG; host/device signatures require raw Ed25519. Format validity never supplies issuer authority. |
| S04 packet signing slots | Owner-offer, administrator and owner-finalization packet SIGNING_REQUESTs use literal role authority, exact signer_public_key/authority_signature_format and the existing exact packet M. Reject a different role, key, message or format without filling any slot. A valid external signature fills only authority_signature; the packet's own role, host signature and device_signature requirements remain independently checked. |
| R02 finite retention denial | A valid root transition remains selected when its typed finite retained-child claim is ineligible: with complete bytes, omitted required finite retention or child issued after transition makes selected child authority forbidden. Missing required proof bytes remains proof_required; a typed ineligible retained kind remains invalid; child expiry retains its own category. |
| R03 all-head retention signing | A common finite child and exact authority-contribution closure carried by every maximal root branch remains signable ONLY for the exact all-head resolver role; no ordinary action/provider is made current during the fork. Intersect narrowed surviving powers (15→7 still permits common policy1), never restore lost bits; omission, an actually missing required power, a current non-root fork, known restriction, fixed-time/current-time ineligibility or missing proof refuses with the actual cause. Preserve both root-first and descendant-first arrival controls. |
| B04 activation output bounds | With existing P/H and a separate current administrator path, minimum required_statement_ids is issued D plus manifest ancestor DS; extra verified packet-issuer DS is permitted. Every manifest DP, applicable current admin/owner stage, exact review pin and source-byte check remains required. |
| B06 current retainer proof pins | A nominal15 issuer with a required current retainer narrowing effective power to7 can issue fresh child7 but not child15. Keep the manifest DS list as its exact literal forward closure; pin known required current-retainer proofs/current issuer-consent provenance in proof_ids, verify actual retention separately, and allow the output's additional verified retainer DS. Later necessary evidence does not rewrite the signed manifest. |
| P05 imported fork resolver | With two known incomparable stream heads, an imported multi-predecessor candidate missing those IDs from resolves is invalid and cannot gain admission/head/maximum or clear the conflict. The otherwise identical explicit resolver succeeds only under actual current issuer power. A higher ordinary write on one branch alone cannot heal the fork. |
| B02 retry | Same request/manifest exact outcome; conflicting immutable tuple; proof aliases; earlier operation cannot replace later selected provider/root/maxima; helper outcome never replaces consent. |
| M01 migration | Before/after legacy linking; successor root without genesis private key; owned/unbound and unavailable roster hosts; exact authenticated source floors/restrictions; staged grants remain inert outside complete migration. |
| M04 migration possession | Exact already issuer-signed unbound H template through the dedicated owner-local route; pure preview, separately durable approval/owned-host signature, complete-only evidence round-trip and immutable retry. Wrong target/member/root/proposal/interval/role and ordinary/bound use refuse. Issuance outside the proposal window or an inactive/expired finite interval refuses before signing. Distinct later host-only versus prepared host+device ACK selectors require exact own approvals/actual keys/full prepared hash; no implicit fence/ACK/provider/key copy or arbitrary signing. |
| M02 adoption | Same keys and owned-host original-person approval; unbound hosts retain their separately reviewed host-only consent; no silent scope increase; missing local acknowledgment; all-host prepared-hash mismatch; root final commit; competing complete proposals; late context origin with expired prepared grants. |
| M03 fence | Acknowledgment survives restart; no timeout abort/new network-derived work/positive old publication; restrictions and independent manual actions retain their own rules; failure preserves all state except named guard metadata. |
| M05 source compatibility | Reopen/resume an unchanged frozen proposal across Go/Rust with accepted object-key/whitespace/string-escape differences, including valid labels containing `<`, `>` and `&`; same nonce/keys/approved review/templates/signatures/source hashes and exact exported original bytes. Changed legacy coordinator pin/new context/root/high-water/host/max/restriction or original proof body/alias is never equal; omitted local facts still block. Duplicate/unknown fields, unsorted/duplicate arrays and full-u64 loss refuse. |
| S03 additive storage allocation | Genuine schema21 and merged remote MCP/OAuth22 open into DEC23 with exact old rows/keys/files/product views. Actual22 adds exactly17 DEC tables, all4 language directions;21 additionally receives the existing OAuth22 migration's changes. Restart preserves state; old22 binary refuses23; future24 and stopped-copy malformed DEC objects/extra generated columns refuse without mutation. Pre23 reserved DEC names, including historical experimental DEC22 state, refuse rather than being silently repaired or reinterpreted. |

The eventual pure suite uses only fixture-owned keys and public signing codecs.
Runtime suites separately verify actual signature refusal, durable guards and
catalogs, local consent, crash barriers, exact events, helper/router isolation,
relay4 hostile inputs, NAT/helper replacement and normal installed all-four
pairings. Separate-machine/live-agent completion is recorded independently.

## 7. Deterministic owner-local runtime controls

Production DEC decisions use normal UTC. Independent black-box fixtures may
explicitly enable `PEERSPAN_DEC_TEST_MODE=1` on an individual daemon or CLI
process, with `PEERSPAN_DEC_TEST_CLOCK_FILE` and/or
`PEERSPAN_DEC_TEST_BARRIER_DIR`, or the schema-failure control below. Otherwise
all these controls are ignored. These are
not CLI options, persisted profiles, request fields or peer routes. A daemon
test setting never implicitly enables another CLI/process. The harness supplies
each process's environment explicitly. Legacy linking retains its separate
LINK controls; helper resource clocks/rates, relay registrations, TLS certificate
checks, QUIC and I/O/retry timeouts continue using real transport/monotonic time.

The owner-local clock file is a regular nonsymlink file containing exactly a
strict whole-second UTC timestamp (years0001..9999), optionally one final LF.
Read it for each DEC decision/snapshot and the final authoritative transaction;
it is not cached at startup or taken from remote signed time. A malformed,
missing or unreadable configured test clock fails closed with500 internal,
generic `internal error`, stage clock; never fall back to real time. Guard and
read-only rules stay unchanged. Fake local time cannot erase persisted guards,
renew a lease, supply consent or make a status read write admission metadata.

Barrier directory is fixture-owned0700, with regular nonsymlink0600 files.
An armed `<name>.arm` contains the exact public operation ID, or `-` for any
operation, optionally one final LF. Nonmatching/unarmed points do nothing.
For typed intent/approval/signature and create/action/root application points,
use that intent record's exact operation_id (create_/act_ or its migration
proposal ID), never its private dint_ lookup ID. For ceremony packet/selection/
commit/application points use the exact signed request_id (link_); migration
proposal/fence/final-commit/adoption points use exact proposal_id (ds_). A
ceremony staged for migration still uses link_ at its ceremony points. These
are the IDs already fixed in the corresponding public operation, not another
generated test identity or legacy dreq_ handle.
At a matching point write `<name>.entered` containing only that operation ID,
then wait for `<name>.continue` or process-context cancellation. The fixture
owns removal of its markers. It may kill/restart that exact fixture process
instead of continuing. Never place keys, tokens, packets, catalogs, ciphertext
or private paths in a marker. Invalid configured controls fail internal.

The literal named points are:

| Name | Actual boundary |
| --- | --- |
| dec.intent.after_commit | Fixed typed intent/templates/private preparation durably stored, before return/signing. |
| dec.approval.after_commit | Explicit approval durably stored, before further signatures/application. |
| dec.signature.after_commit | Exact submitted/generated signature batch durably stored, before subsequent application/response. |
| dec.frame.after_commit | Newly received or sealed outbound frame bytes durably stored, before dependent interpretation/publication; an acknowledgment/retry alone does not enter this point. |
| dec.request.after_commit | Exact request, keys/pins and private nonce/secret durably stored. |
| dec.owner.after_commit | Exact complete owner packet durably stored. |
| dec.selection.after_commit | Separate requester selection and exact selected pins durably stored. |
| dec.administrator.after_commit | Exact complete administrator packet/grants durably stored. |
| dec.owner_finalization.after_commit | Exact complete owner-finalization packet/draft durably stored. |
| dec.requester_commit.after_commit | Separate final requester consent and exact manifest/commit/grants durably stored before publication. |
| dec.apply.before_transaction | After preparation/signature work, before acquiring the final authority snapshot/write transaction; concurrent changes must be rechecked after continue. |
| dec.apply.after_commit | Actual create/action/activation/adoption public-state transaction committed, before this handler's response/remote attempt. |
| dec.migration_proposal.after_commit | Exact proposal/source/preparation intent durably stored. |
| dec.migration_fence.after_commit | Own exact acknowledgment and durable fence committed before exposing/publishing the acknowledgment. |
| dec.migration_commit.after_commit | Exact all-host root final commit durably stored before its response/publication. |

After-commit barriers run outside SQLite transactions/global writer locks.
Several named facts may share one atomic transaction; their markers do not
assert intermediate durable states. A participant outcome and activation facts
committed together cannot be split by a test hook. Other workers may observe
an already committed fact; no barrier implies global unobservedness. A completed
historical retry performs no new signature/application and must not revisit
those mutating barriers. Pending resume rechecks current authority and may
continue only the exact fixed operation; it cannot regenerate timestamps.

Approval-before-signature and signature-before-encryption are distinct required
durable phases for typed ceremony work, including requester selection/final
commit. At dec.approval.after_commit no new signature or frame from that stage
exists; at dec.signature.after_commit its exact signature/packet bytes exist
but no new frame encrypting them exists. At dec.frame.after_commit only the
actual persisted frame can be published/retried. Stage-specific packet facts
may share the signature transaction; application/outcome facts can share their
atomic application transaction. These permissions do not combine the three
ordered approval, signature and encryption phases into one commit. Independent
crash/restart cases inspect each phase, then verify exact continuation, both
requester consents and no repeated signature/frame/application/event.

Selected: explicitly opted-in local clock files and named real durable barriers,
using the existing public linking test-control discipline in a separate DEC
namespace. Discarded: production clock APIs, peer-controlled fault injection,
implicit process inheritance, helper-time authority, guessed implementation
checkpoints or claims that a marker proves a separate database commit.

### Schema migration rollback control

`PEERSPAN_DEC_TEST_FAIL_AFTER_SCHEMA_DDL=1` is an additional per-process opt-in
only when that same process has `PEERSPAN_DEC_TEST_MODE=1`. Only the literal1
enables it; all other values leave it disabled. It is ignored by helper
operators, processes without test mode and already-current schema23 openings.
It is never a CLI/API option, profile field, clock source or remote request.

When opening an older schema, run its normal migrations (including OAuth22 for
schema21), create every DEC23 table and validate their final shapes in the one
opening transaction. At that actual point, before the opening transaction can
commit, this control returns the fixed startup error `test schema migration
failure`. The normal error path rolls back and exits. It never waits inside a
transaction, writes a barrier marker, commits partial DDL, initializes a new
identity or retries under another schema. No daemon listener starts on this
failure. Existing private identity, rows, public facts and original schema
version are preserved. A fresh process without the control may open the exact
same state normally.

Independent verification uses stopped copies of genuine21 and OAuth22 states,
with schema/row/private-file snapshots from their owned baselines. Require a
failed controlled opening, exact original version/tables/rows/files and no
partial OAuth/DEC table additions. Then open that same copy without the flag and
verify the normal23 state. Also prove a set flag without test mode is ignored,
and a current23 open with both flags neither fails nor rewrites history. These
are late-DDL rollback checks, distinct from reserved-name preflight refusal.

Selected under the DEC delegation: an explicit immediate startup failure point
makes the required transaction boundary observable without guessing internal
SQL timing. Discarded: treating preflight refusal as post-DDL rollback evidence;
waiting on a durable barrier while holding the opening writer lock; relying on
sleep/kill timing or filesystem exhaustion to guess which migration ran.

## 8. Missing migrated-origin proof diagnostics

An isolated self-signed migrated initial root, or its signed ordinary successor,
cannot authenticate authority under a different descriptor genesis without
its verified complete migration. If that origin is absent, return proof_required
with the exact directly declared migration_proposal_id as required_ids. Do not
invent a container dp_ from missing bytes or treat a structural root signature
as an authenticated origin. This fixes the isolated diagnostic; unrelated
multiple-error ordering is still not an oracle. Selected: the direct semantic
repair reference. Discarded: an attacker-selected root, fabricated missing-proof
hash or an empty repair list when that signed direct reference is available.

## 9. Decisions and discarded alternatives

| Choice | Reason | Discarded alternative |
| --- | --- | --- |
| Explicit new pure mode, old modes unchanged | Gives both languages one bounded comparison surface without weakening frozen legacy readers. | Reusing a permissive default parser or letting a caller choose verification budgets. |
| Trusted prior separated from candidate bytes | Models genuine durable admission/clock knowledge while making the network trust boundary visible. | Letting an incoming peer assert already-admitted restrictions, maxima or local consent. |
| Exact semantic IDs and exact proof aliases | Tests portable references and retries without reconstructing signed bytes. | Comparing reserialized JSON or silently treating different ds_ values as one statement. |
| Domain conflict observations in projection | Allows restrictive evidence to progress without a permissive fork winner. | Global success-by-hash or discarding every valid deny because another stream forks. |
| Pure evidence verification separated from local adoption | A public transcript can be cryptographically valid without authorizing a restored host to create local consent. | A generic import Boolean or a helper receipt that adopts a network. |
| Exact errors for isolated causes | Makes parity meaningful without requiring accidental ordering of multiple unrelated failures. | Tests that encode one implementation's internal check sequence. |
