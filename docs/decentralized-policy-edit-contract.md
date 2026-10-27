# Coordinator-free policy edits and capability-claim references

Status: PROPOSED shared storage/runtime supplement, 2026-10-26. Review and pin
before implementing this variant. It supplements the authority, storage and
owner-local runtime contracts without changing schema23 SQL or old records.

## 1. Exact references instead of a legacy signature

Keep existing `policy_edits` primary keys `(network_id,person_id,seq)` and every
legacy row byte-for-byte. A DEC row is a distinct strict tagged JSON record;
never reinterpret an untagged legacy `start`/`signed` policy as DEC authority.
For new-mode rows, seq remains the existing positive signed-64-bit local edit
counter, checked before increment. It is not an authority-stream sequence;
policy versions remain positive full u64 from the verified DEC high-water.

The exact DEC record is:

```text
{format:2,mode:"decentralized",context_id,seq,state,
 start,signed,signed_version,dropped,reserved_at,signed_at,
 unsettled_at,closed_at,dropped_at}
```

State is exactly `reserved|settled|unsettled|closed`, preserving existing edit
semantics. Dropped is a sorted unique array of the existing stable edit-delta
keys. Every timestamp is strict whole UTC or `"-"` when absent; reserved_at is
always a timestamp. Signed_version is the exact signed policy u64 version or0
only when signed is `"-"`. Neither object nor timestamp uses JSON null. Each
record obeys the shared32MiB private-record bound.

State/field constraints are exact:

| State | start | signed/version/signed_at | unsettled_at | closed_at | dropped/dropped_at |
| --- | --- | --- | --- | --- | --- |
| reserved | frozen baseline or `-` | `-` /0 /`-` | `-` | `-` | [] /`-` |
| settled | same frozen baseline | required exact reference /its positive version /timestamp | `-` | `-` | sorted dropped keys /timestamp iff nonempty |
| unsettled | same frozen baseline | required original applied reference /its positive version /timestamp | timestamp | `-` | sorted dropped keys /timestamp iff nonempty |
| closed | same frozen baseline | required original applied reference /its positive version /timestamp | `-` | timestamp | sorted dropped keys /timestamp iff nonempty |

Signed_at is no earlier than reserved_at. Unsettled_at, when present, is no
earlier than signed_at. Closed_at is no earlier than signed_at and the actual closing decision cannot
precede its last unsettled transition. Dropped_at is no earlier than signed_at;
it can precede a later settlement/closure. Dropped additions stay dropped across
settled/unsettled transitions, rather than being restored by a new body. An abandoned never-signed
reservation stays reserved until the existing lapse/cleanup rule retires it;
it is never relabeled settled/closed with an invented signed reference. The
exact signed reference and frozen baseline do not change on later unsettled/
closed transitions. Delta keys in dropped must be additions actually present
in that frozen signed-minus-start semantic delta; arbitrary keys are invalid.
Only the existing explicit age/displacement rule can close/drop additions;
known restrictive withdrawals remain enforced as before.

Keep the newest local seq row so cleanup cannot reset its counter. Eligible
older unsigned reservations may retire after the10-minute lapse; closed rows
retain7 days. A settled row may retire only after its exact reflected policy
has actual acknowledged delivery to the locally relevant known siblings and
its dropped-item7-day display/retention window has elapsed. There is no
coordinator acknowledgment or global freshness dependency. Unknown deliveries
remain in their bounded outbox; cleanup never removes public proofs, sticky
restrictions, heads/maxima or an unsettled obligation. New policy forks still
freeze that stream and do not resurrect a permissive older body.

Start and signed are each `"-"` or exactly a POLICY_REFERENCE:

```text
{statement_id,proof_id,statement_base64,body_base64}
```

The two Base64 fields are canonical standard Base64. Statement_base64 is the
exact original complete signed DEC `policy` envelope, at most1MiB. Body_base64
is the exact unsigned policy-v2 body from that envelope, at most256KiB; it has
no fabricated legacy signature. Statement_id is its recomputed ds_. Proof_id
is the actual retained top-level dp_ in dec_objects which supplies that exact
envelope: its own standalone alias or an exact complete activation/migration
container under the existing original-container rules. The enclosing proof is
loaded from dec_objects, not duplicated or rewritten in each edit row.

On opening/using a reference, verify kind/context/network/person, exact envelope
signature/role/path provenance, actual source dp_ bytes and complete nested
consent/dependency closure. Require the exact source container to supply the
referenced original envelope bytes and exact policy-v2 body; another ds_ alias
cannot replace an explicitly frozen envelope. Decode cached body/version from
the signed wrapper and compare every duplicated field. Missing source or
required dependency yields proof_required; a forged/mismatched reference is
invalid/corrupt state, never an unsigned-body fallback.

Start must identify the independently verified selected active owner policy at
reservation time, or `"-"` when no active policy exists. Its exact historical
body remains an edit baseline after expiry; this grants no current permission.
Signed is absent until an actual local policy application settles the edit.
Its presence requires the exact policy to have a legitimate local admission
and retained provenance. An inactive signed policy remains historical edit
intent; execution still uses only the current independently active projection.
No POLICY_REFERENCE itself authorizes a grant, signature or provider.

This variant is private edit persistence only. Existing capability-create
responses keep their existing capability schema; no POLICY_REFERENCE or DEC
tag is added to a capability object by analogy. Public DEC action/claim results
retain their exact signed envelope/dp_/catalog fields from the runtime contract.
Every repeated cached body/reference, including one supplied through an atomic
create catalog, must exactly match the original signed statement and actual
source container; capability code may not normalize it into another alias.

Selected: tagged references in the existing table, with body-only delta
calculation and exact DEC proof checks. Discarded: fake legacy signature fields,
re-signing an envelope as a legacy policy, or a parallel edit table whose
reservation/withdrawal state could diverge on cross-language reopen.

## 2. Owner-local edit reservation

DEC never returns a manufactured legacy policy from the old edit projection.
Use these v2 routes, retaining old routes only for old history/migration:

`POST /v2/networks/{id}/policy-edits` takes exactly `{provider_id}`. Resolve auto
only through the actual selection; an explicit original/device has the runtime
provider rules. Validate current scope1, exact own person/host binding, root,
known restrictions/forks and decision clock. An external matching original key
needs no daemon key import for this unsigned reservation. No signature, policy
publication, selected-provider change or permission mutation occurs.

The exact200 response is:

```text
{context_id,person_public_key,policy,version,seq,created_at,expires_at}
```

Policy is POLICY_REFERENCE or `"-"` as above. Version is the retained numeric
maximum (0 only for a truly empty stream); preserve all incomparable heads
separately and refuse a fork/missing required head. Refuse version_exhausted at
maxu64 and local counter exhaustion before inserting a reservation. Seq is the
new checked local edit counter. Created_at is guarded decision time;
expires_at is created_at+the existing10-minute reservation lapse. Insert the
strict reserved record and clock atomically. Start/signed/body/ref fields are
not caller supplied. A read cannot reserve another number.

`GET /v2/networks/{id}/policy-edits` is a read-only owner edit summary exactly
`{context_id,person_public_key,edits:[{seq,state,signed_version,dropped}]}`,
seq-sorted. It preserves existing access-sync status meaning without returning
legacy signatures or claiming an inactive policy as authority.

Before any action/claim signature and again in the final transaction, enforce
the existing newest-reserved, unexpired-reservation, expected next policy
version, owner/host and edit-sequence rules against one coherent snapshot.
Policy generation consults the DEC maximum, not legacy policy/highwater rows or
an active-only selection. A stale draft never consumes a reservation, signs a
new generation automatically, or applies only a subset of an intended change.
Unsigned PolicyBody/delta helpers may be reused internally; their old signature
field and old wire verifier are not used to represent DEC evidence.

No caller-controlled reservation field is added to an ordinary action or claim.
The exact policy-v2 body's existing `edits:[{host,seq}]` line pins this host's
reserved seq. Its host is the existing derived host ID, not a display label or
a new public-key encoding. A genuinely new local edit must cite the newest
reserved sequence and use retained maximum+1. An exact automatic renewal keeps
its already-applied own edit sequence; reapply uses the stored unsettled delta
and the existing reservation/reapply rule. The final writer binds the cited
sequence to the exact policy body being committed; a claim preparation checks
it without consuming/settling it. Other hosts' edit entries remain exact signed
body content and cannot select a local reservation by alias.

### Preserve unsettled intent before a new edit

A new reservation refuses with `state_conflict` while any validated local edit
for this owner is unsettled. Before every action/claim signature and final
application, a candidate citing a reserved new sequence repeats that check.
It cannot absorb an older signed withdrawal merely by advertising a higher
own edit sequence. Exact old-sequence reapplication remains permitted under
the existing rules; neither guard rewrites its frozen references or dropped
keys. A new native command must finish reapplication, reload the actual
admitted policy, and only then compose and reserve its new change.

### Resolve a policy fork before ordinary reapplication

A complete independently verified policy fork is retained as all known
incomparable heads; it is not rejected merely because edit reconciliation has
no unique baseline. The domain stays unusable. Keep every frozen signed/start
reference and dropped marker, leave unsigned reservations unsigned, and treat
signed local intent not reflected by a unique current policy as unsettled.
Automatic renewal, new reservations and reapply-preview still refuse the fork.

The owner-local ordinary typed action path permits one narrow explicit recovery:
a `policy` resolver covering ALL locally known heads in both predecessors and
resolves, at retained maximum+1, whose content and entire edits list match ONE
exact complete admitted predecessor body except version and issued/expiry time.
Current independently established original or scope1 device authority, root,
finite bounds and all-head complete proofs remain mandatory before every
signature and application. No policy branch itself supplies issuer authority.
This is an explicitly reviewed branch choice, never a hash/order winner.

This recovery consumes no new reservation, advances no local edit counter,
creates no policy_claim, and never marks a never-signed reservation signed.
Final reconciliation compares the resolver's actual reflected own sequence
with existing signed local rows: omitted intent stays unsettled, reflected
intent may settle with its original frozen references/drops preserved. It does
not fabricate a new signed reference for an old edit. After resolution, normal
old-sequence reapplication restores the retained local withdrawal before any
new command can reserve its own change. Changed heads or a body not matching
the exact reviewed predecessor refuse before signature/application.

Selected: explicit existing-head resolution, then ordinary reapplication and
new editing in separate steps. Discarded: dropping conflict evidence on import,
weakening every unique-baseline reader, choosing a branch automatically, or
using fork resolution to absorb new edits or silently discard withdrawals.
This owner-local recovery restriction does not change verification/admission
of otherwise valid public signed resolvers under the authority contract.

## 3. Pure preparation of an exact reapplication candidate

`POST /v2/networks/{id}/policy-edits/reapply-preview` takes exactly
`{provider_id}`. This is an owner-local read, despite POST carrying its typed
provider argument. It uses one coherent read snapshot and returns200 exactly:

```text
{context_id,person_public_key,host_public_key,provider,
 payload_base64,unsettled_seqs}
```

The request has the ordinary1MiB owner-local bound and the response32MiB bound;
the decoded unsigned statement payload remains at most256KiB. Enforce the
existing policy/body/entry limits as well. Refuse quota_exceeded rather than
truncate a sequence list or candidate.

Provider is the runtime contract's exact `PROVIDER_VIEW`. Resolve auto only
through the explicit persisted selection; an explicit matching original or
owned device follows the same public current scope1, person/host, root,
restriction and proof rules as an ordinary policy action. Root is forbidden.
An external original needs no daemon private-key import or available daemon
SSH agent for this read. A broken or expired selected device cannot fall back
to an original. This preview never changes the selection.

Unsettled_seqs is the ascending unique list of actual validated unsettled
local sequences for this owner. With none, payload_base64 is exactly `"-"`.
Otherwise it is canonical standard Base64 of one exact unsigned ordinary DEC
`policy` payload. Derive its content by the existing withdrawal-wins reapply
merge of the exact retained signed-minus-start deltas and dropped keys into
the unique known current policy baseline. The baseline's complete historical
proof must verify; an inactive body is historical content only, never issuer
authority. A truly empty stream has the existing empty content. A fork,
missing head/dependency, invalid reference or unavailable current provider
refuses; do not merge guessed bodies or ignore an unsettled row.

Pin the selected root and exact current policy predecessor, use retained full
u64 maximum+1, and retain other hosts' edit entries under the existing merge
rules. This host's entry is the highest unsettled sequence being reapplied,
not a new reservation. Its issued_at is this snapshot's guarded decision time;
not_after uses ordinary finite policy and its operation-required scope1
parent/provider ceilings, without an unrelated administrator scope8 deadline
from the broader PROVIDER_VIEW summary shortening an owner's policy.
Refuse version exhaustion or an unusable ceiling. Even if the content already
reflects the old delta, a returned candidate uses that old sequence and must
pass ordinary signing and application before this path settles anything.

Preview writes nothing: no reservation, private intent, signature, policy,
edit transition, clock advance, event, outbox, provider selection, peer request
or key generation. It returns no POLICY_REFERENCE for the unsigned content.
Repeated previews may observe a later clock or state; they are not persisted
consent and never authorize signing a replacement for an approved action.

A native mutating command may submit the exact returned bytes through the
existing ordinary typed `/actions` ceremony using this same provider. It
checks the returned identity, provider and exact typed policy before invoking
the matching original key or owned device. Approval and every signature/final
transaction revalidate current authority, closure, maximum, predecessors and
the exact old-sequence merge. External original signatures stay on the CLI's
machine. Resume an approved action by its immutable action_id and fixed slots;
never regenerate its payload/time/provider on retry. A changed prerequisite
refuses before signature/application and requires a fresh reviewed operation.
After actual successful reapplication, reload before composing the requested
new mutation. Reads, status, previews and declined commands never invoke this
signing path. A concurrent new unsettled obligation is caught by the guards
above; it cannot be hidden by the earlier preview or reservation.

Selected: a pure exact candidate read plus the existing typed action lifecycle.
It supports an original held outside the daemon and leaves one immutable
signing/retry mechanism. Discarded: a daemon-only renewal dependency, returning
a fabricated merged POLICY_REFERENCE, reconstructing exact intent from the
public edit summary or version number, importing an original key, weakening
the new-edit guard, or adding another persisted action/approval protocol.

## 4. Shared dropped-addition keys

New tagged DEC rows use the following exact strings. Interpolation copies the
already validated exact policy field; it does not normalize a label or key.

| Addition | Canonical key |
| --- | --- |
| A new agent rule | `rule AGENT` |
| A new principal in an agent rule | `principal PRINCIPAL in rule AGENT` |
| A new capability rule with nonempty principals | `capability rule CAPABILITY` |
| A new principal in a capability rule | `principal PRINCIPAL in capability rule CAPABILITY` |
| A new empty-principal capability claim | `claim CAPABILITY` |

Validate keys against the actual frozen signed-minus-start addition set,
using the existing agent rule identity/settings and capability name/host
identity. A newly empty-principal capability claim uses only `claim CAPABILITY`,
never the capability-rule marker which cannot suppress that claim. A
withdrawals-only merge's output is not that set. Bounds and trusted
host merges retain their existing semantics; invent no dropped trusted-host
key. Valid nonempty dropped arrays must remain readable after closure,
settlement, displacement and cross-language reopen.

These strings are display-marker groups, not full rule identities. Distinct
agent rules with the same agent but different settings remain distinct in the
ordinary merge. If their frozen additions produce the same display marker,
that one marker suppresses EVERY represented local addition in this edit's
exact frozen delta. It never picks a rule by order, hash or settings, and never
removes a permission already independently present in the current baseline.
This may conservatively drop more than the one conflicting local addition;
the existing dropped status reports that named group. Derive its members from
the frozen references, not later policies or guessed string parsing.

Marker groups and their skip sets belong to each exact frozen edit row, never
an unrelated or later edit. Apply unsettled rows in ascending sequence from
the same untouched current baseline. Accumulate retained and newly generated
markers per row, then restart that ordered merge from the baseline with every
row's complete skip set. Repeat until no new marker is generated, within the
finite frozen addition sets; refuse a
resource limit rather than publish a partial merge. Thus a collision noticed
after a provisional addition cannot survive this pass and reappear on a later
retry. The same group suppression applies to additions inside an otherwise
new rule. No provisional content is signed or admitted before this completes.

Previously written tagged DEC rows may spell a principal key with `of` in
place of the table's `in`. Accept only an exact such alternate constructed
from an actual addition in those frozen references. It means the same dropped
addition in memory, including when checking skips on reapplication. Preserve
the stored string and all original row/reference bytes during reads; do not
globally replace substrings in labels. Existing dropped aliases remain
dropped, and a later write never appends the canonical equivalent as a second
obligation. A retained array containing both principal spellings for the same
actual display-marker group is invalid, even though the strings differ; validate semantic
uniqueness against the constructed frozen addition set. Newly dropped
additions use the canonical table. Legacy untagged
rows retain their own representation byte-for-byte.

Selected: canonical DEC keys with exact read compatibility for the two existing
principal spellings. Discarded: rewriting retained edit history, rejecting a
legitimate other-language row, treating a spelling difference as permission to
restore an addition, or changing legacy policy signatures/schema. For marker
collisions, select explicit conservative group suppression with final remerge.
Discarded: silently choosing one full rule identity or adding a new hashed-key
schema whose old ambiguous history would still need a compatibility rule.

## 5. Applied policy versus claim preparation

An ordinary committed policy stores its exact catalog/projection/maxima,
applicable edit settlement/withdrawal state, source proof references, outboxes,
clock and event in one transaction. Record signed/signed_version/signed_at from
that exact admitted envelope, with the unchanged semantic delta/start body.
Keep existing local unsettled withdrawals enforced immediately; a displaced
addition is not silently restored by an older body or a fork hash winner.

A typed `policy_claim` result is preparation only, even after every signature
exists. It may retain its private approved fixed intent/signatures, but does
not set an edit's signed reference or state, admit a policy, advance a maximum,
change a capability or enqueue delivery. Its result stays committed:false.

Atomic capability creation independently revalidates the exact signed claim
catalog, current scope/path/host/name/source/claim bounds, retained maximum and
reservation at final guarded time. Only that successful same transaction may
settle the reserved edit, admit its policy and create capability/deliveries.
Any network/claim/source refusal leaves all those changes unapplied. Exact
GET-identical capability preflight creates no reservation/signature.

Automatic renewal/reapply uses the actual selected provider and current scope1;
a present broken/expired device cannot fall back to an original key. Reapply
uses the exact retained signed/start reference bodies for delta calculation,
then rechecks the current projection/heads/maxima and existing withdrawal/
reservation rules. It produces a new ordinary DEC envelope through the typed
intent path. Preserve old bytes/references and local revocations; an inactive
old body alone supplies no signing or execution authority.

## 6. Verification

- Go/Rust reopen retains identical legacy rows and strict tagged DEC edit
  records, exact source envelope/container references and full-u64 versions.
- Forged/wrong-owner/wrong-context body caches, source alias substitution,
  missing container/dependency and fake legacy-signature substitution refuse.
- Reserve once through POST; GET is immutable. Expired/non-newest reservations,
  fork/missing-head state and max/counter overflow refuse without signatures,
  partial policy/maxima/edit/outbox changes or a new selected provider.
- Claim preparation signs only its fixed candidate and leaves edits reserved;
  one failed atomic multi-network capability create leaves every edit, policy,
  capability and delivery unchanged; successful create settles exactly once.
- Cross-host displacement/reapply and automatic renewal preserve current
  restrictions and exact owner intent, consult retained maxima, and refuse an
  unavailable selected provider without original-key fallback.
- Two siblings start from the same policy. A signed local deny/untrust is
  displaced by the sibling. New reservation and an already reserved candidate
  refuse before any signature or settlement while that withdrawal is
  unsettled. Exact old-sequence reapplication settles it without restoring
  access; only then may a new unrelated edit reserve and apply.
- Same-predecessor sibling policies are durably retained as a fork without a
  branch winner or fabricated edit settlement. An explicitly approved current
  owner resolves all heads using one exact admitted branch's content/edit
  entries and a fresh checked generation. The omitted local withdrawal remains
  unsettled under the resulting unique head; resolution consumes no new edit
  reservation, and old-sequence reapplication is required before new editing.
- Reapply-preview leaves all durable state unchanged, including empty/no-unsettled
  and refusal paths; a later read may observe a later timestamp or changed state.
  With an original unavailable to the daemon, its exact returned candidate can
  complete through external typed CLI slots, then a new native mutation starts
  from the actual resulting baseline. Changed head/root/max/provider, expired
  authority, missing exact reference and fork refuse without payload refresh.
- A local principal addition loses to a sibling's rule removal. Its legitimate
  nonempty dropped row remains readable after closure and in the other
  language. Canonical and retained alternate principal keys skip the same
  actual addition, never restore it or rewrite stored history; a forged key
  outside the frozen addition set refuses.
- Two same-agent rules with different settings add the same principal; only
  one conflicts with a sibling's removal. Its display-marker group suppresses
  both local additions in this very candidate and on later reapply/reopen,
  while retaining distinct rules and unrelated current-baseline permissions.
  Reverse rule order and retain either principal spelling: the result is the
  same, no provisional addition is signed, and dropped status names the group.
- Prepare an ordinary policy payload after its fixed issued_at whole second.
  Its actual private created_at may be later; expiry remains issued_at+300s.
  An interrupted approved action stays byte-exact when stale and cannot block
  later valid renewal merely because the two initial times differ. New
  preparation at expiry refuses; existing honest-signing age300 remains the
  separately specified inclusive boundary. No retry refreshes the payload.
