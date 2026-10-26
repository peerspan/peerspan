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

## 3. Applied policy versus claim preparation

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

## 4. Verification

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
