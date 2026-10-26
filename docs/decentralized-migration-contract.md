# Coordinator-free migration and retained history

Status: DEC-01/05 shared contract candidate, 2026-10-26. Review and merge with the
[authority](decentralized-authority-contract.md),
[bootstrap](decentralized-bootstrap-contract.md) and
[umbrella](decentralized-network-contract.md) contracts before implementation
or independent executable cases.
Opening schema23 is not permission to change a network's protocol.

## 1. Selected transition and costs

Keep stable network, host, original-person and existing device identities, exact
legacy evidence, restrictions, access maxima and all schema21 product state.
The verified current **legacy root** proposes migration; every locally known
nonrevoked admitted host explicitly acknowledges it. An unavailable host is not
silently removed. A coordinator response, current address or recent sync cannot
replace a signature or supply missing acknowledgment.

Reissue positive authority in the new context under its finite limits. For each
owned host this uses a complete new-protocol bootstrap transcript, with the same
host/person/device tuple and original-person approval on that key's existing
machine. No original private key is copied. Existing delegated90-day paths are
retained as history, not converted into new7-day authority by assertion. A host
without an existing device key may generate one after private preflight/review;
it does not generate a replacement person key. An unbound admitted host remains
unbound and may migrate host membership without inventing an owner.

This deliberately requires original-person availability once at cutover. It
avoids a second, cross-protocol delegation mechanism and its exceptional parent,
activation and expiry rules. Discarded alternatives are automatic legacy-device
bridges, resetting an identity or trust database, requiring a deleted genesis
private key, and removing offline hosts. If an original key or known host is
unavailable, show the exact missing approval and retain the old state. Recovery
or an explicitly different network is a separate decision, never automatic.

Freshly reviewed new policies/groups may be prepared with the transition.
Otherwise their new-mode network-derived permissions begin inactive until
published by an authorized owner/admin. Independent manual permissions and
already accepted work retain their own existing semantics. Reviews disclose
which new-mode permissions are ready and which require repair.

## 2. Source snapshot and preparation

The source is the exact legacy descriptor, complete sufficient legacy signed
catalog, verified root chain/current epoch, previously durable feature if any,
all known restrictions and policy/group maxima. Verify it with the existing
legacy readers for that descriptor; never edit signed coordinator fields.
Networks that did not enable linking can use their supported legacy admission,
binding, invitation and root proofs directly. Enabling linking or contacting a
coordinator merely to manufacture a migration source is not required.

Every participant unions its own durable prior evidence with the proposed
source before checking it. A missing known member, restriction, higher maximum,
incomparable root/history or unresolved potentially committed operation blocks
acknowledgment and identifies the missing/conflicting IDs. A root's signature
does not prove the snapshot globally complete. A truly unseen host/restriction
can still exist under partition; this is not consensus or global roster proof.

Derive the roster from signed admitted host membership after all known host
revocations/leaves and applicable administrator-retention rules. Unbinding or
person removal alone does not erase host membership. Include admitted unbound
hosts. An eligible source must have one unambiguous current root; forks require
legacy authorized repair before migration. The source's current root key may
be a successor of the genesis key; its verified chain supplies that authority.

Before signing its acknowledgment a host stops fresh legacy management writes,
enrollment and final-consent signing for this network. It preserves that fence
durably. Valid restrictions, retrieval/cancellation and accepted work remain
processable. No timeout/helper404 can establish that an old final commit never
escaped: settle any such known operation first using exact retained evidence.
A saved old ceremony is never resumed under the new context. This fence does
not claim that signatures already held by another machine cease to exist.

After that acknowledgment fence, refuse new network-derived message/task/call
admission, queued starts, new delegation hops and outbound publication that
could cause a new legacy admission. Existing accepted tasks and running calls
may finish; existing result/status/cancellation keep their identity checks.
Keep valid restrictive publication and the exact migration's narrow staged
signatures available. Independent manual grants remain independent and cannot
be selected automatically as a fallback. Expose `migration_pending` with the
proposal ID for blocked work. The fence survives restart and has no timed
expiry. This availability cost is part of the explicit acknowledgment review.

The portable source-state snapshot is exactly:

```text
{format:1,network_id,legacy_root_highwater,
 known_admitted_hosts:[PUBLIC_KEY],
 access_maxima:[{kind:"policy"|"group",subject,version,message_hash}],
 admitted_restrictions:[{proof_id,kind,person_public_key,host_public_key,
                         device_public_key}]}
```

Hosts and proof IDs are sorted/unique; maxima are sorted by kind then subject,
unique per stream; all arrays have at most4096 entries and the snapshot is at
most256KiB. `subject` is the exact policy owner key or group name. Versions and
legacy_root_highwater use fullu64; message_hash is the retained exact hash or
`-` when only the durable maximum remains. Restriction kind names are the exact
legacy catalog kind; unused target fields are `-`. Its exact original proof
must be present in the source catalog and pass the retained-history rules.
Missing restriction proof is repair, never permission to forget the deny.

Classify inherited restrictions through the verified retained-history rules and
the endorsed admitted-restrictions snapshot. Mere presence of correctly signed
but inactive, unkept withdrawn-administrator bytes in the source catalog does
not require a new stable-key ban. Previously locally admitted stable-key bans
remain sticky. If all exact source/prepared evidence is present but an applicable
required ban is omitted, refuse forbidden. If its exact required original proof
is absent, refuse proof_required with that proof ID; never infer permission to
omit the ban from missing evidence.

The root proposal and all host acknowledgments endorse this exact snapshot for
the new context. This is a new trust decision about inherited floors, not proof
that its numbers were globally committed in the past. Each acknowledger checks
that no local floor/restriction/member is omitted or lowered. The proposal
cannot lower even an inactive/expired local maximum. Preserve the exact source
and snapshot for future receivers, not another host's unsigned admitted bit.

### Known-source compatibility and exact endorsed bytes

Preserve the exact original proposed legacy descriptor, source catalog,
source-state snapshot, new descriptor, signed templates and all hashes and
signatures. Reopening with another implementation never normalizes, replaces,
re-hashes or re-signs those stored proposed bytes. Independently reconstructed
LOCAL views are compatibility evidence, not a replacement source envelope.

After strict bounded parsing and independent verification of the actual local
legacy root/feature/history, compare local-known representations as follows:

- Legacy descriptors compare all FIVE exact decoded fields: network_id, name,
  genesis_root_public_key, coordinator_address and coordinator_public_key.
  The old coordinator pins remain historical context identity and cannot be
  dropped merely because the target is coordinator-free.
- New descriptors compare format, protocol, network_id, name and
  genesis_root_public_key, plus their independently derived context ID. The
  proposed exact bytes remain fixed even when an ordinary local descriptor's
  serialization differs.
- Source-state snapshots compare EVERY strict field and typed row in section2,
  including exact root high-water, host set, all maxima and exact restriction
  provenance/targets. Preserve full-u64 values, literal `-` and every mandatory
  array's ordering/uniqueness. Do not coerce numbers through floating point.
- Legacy catalog wrappers compare their complete sorted sets of declared
  kind/proof-ID/exact decoded original-body tuples. Compare original proof
  bodies BYTE FOR BYTE, never by typed reserialization: their exact proof IDs,
  hashes and signed messages remain unchanged. A different signed alias is a
  different tuple, not an equivalent replacement.

This tolerates ONLY accepted JSON object-key order, insignificant wrapper
whitespace and equivalent JSON string escaping. It permits no string trimming,
Unicode normalization, case folding, duplicate/unknown fields, malformed
encoding, array permutation, missing evidence or semantic field change.
An otherwise unchanged frozen local proposal may resume across these harmless
serialization differences with its exact original nonce/keys/review/approval/
templates/signatures/source hashes. Exact export likewise returns the retained
original source, not the locally rematerialized representation.

This comparison does not demand that a participant's local catalog equal the
entire proposed source. The existing independently verified union/coverage
rules still detect omitted local hosts, restrictions, higher floors, forks and
unresolved potentially committed operations. New/different proof tuples must
pass those same rules; they are never silently discarded to manufacture
equality with a proposal. A genuine changed frozen local source conflicts or
requires the existing exact proof repair; it never inherits old consent for
changed source bytes. Hash equality is still exact wherever a signed proposal,
acknowledgment, prepared catalog or final commit actually declares that hash.

Reissue active stable-person/host bans in the prepared catalog under the
proposed root's ordinary target power. For a migrated admitted owner, that
original person explicitly ratifies its known stable-device bans under the
pending self-person rule, only for the source's exact targets. The owner review
displays the imported bans and floors. No root substitutes an owner signature.
For a permanently removed person, preserve its device-ban history and root
person ban; no positive owner path is restored. Generation-scoped withdrawals
and unbinds remain exact history and cannot revive any old generation. This
staging exception permits only those exact restrictive copies, not unrelated
new authority or a claimed global historical timestamp.

## 3. Exact proposal and migrated initial root

Use the authority contract's strict JSON, encodings, exact statement/proof IDs
and role-separated signatures. The `migration_proposal` statement has this
exact payload:

```text
{proposal_nonce,legacy_descriptor_base64,legacy_feature_id,legacy_epoch,
 legacy_root_public_key,source_catalog_sha256,source_state_sha256,new_descriptor,
 roster:[{host_public_key,member,person_public_key,device_public_key,scopes}],
 issued_at,expires_at}
```

Its envelope context is the proposed new context and its sole signature role
is `issuer`, by the independently verified current legacy root. The decoded
descriptor and source catalog remain exact bytes. `source_catalog_sha256`
hashes the exact legacy catalog bytes; the source travels separately below.
`proposal_nonce` is fresh random32 bytes in canonical standard Base64, persisted
before signing. Retrying an existing proposal preserves it and every exact byte.
`source_state_sha256` binds the exact strict JSON snapshot defined below,
including durable inactive maxima and restriction provenance outside that catalog.
`legacy_feature_id` is its exact durable feature ID or `-`, not a feature merely
found in a catalog. `new_descriptor` has the authority contract's exact fields;
network ID, name and genesis root equal the legacy descriptor. New context
derivation never includes legacy coordinator fields.

Roster entries are sorted by host public key and unique. `member` equals that
host's verified source membership label. A bound host names its same admitted
original person and selected existing device key/scopes. No prior device means
the newly reviewed device key and explicit positive scope mask. An unbound host
uses person/device `-` and scopes0. A proposal cannot silently transfer an owner,
replace an existing device key, increase an existing selected device's scopes,
remove a known admitted host or re-admit a permanently revoked stable key.
Any intentional new identity/scope decision follows its ordinary separate
approval/recovery path. Arrays and labels keep existing finite bounds.

`issued_at` is the root's decision time and `expires_at=issued_at+24h`.
The local window controls preparation/review/acknowledgment signing. At/after
expiry an incomplete participant signs nothing new. Participant timestamps do
not prove global signing time or the absence of another completed migration.

The new initial `root_state` uses the authority contract's fourth form:

```text
{epoch:legacy_epoch,predecessors:[],resolves:[],
 root_public_key:legacy_root_public_key,issued_at:PROPOSAL_ISSUED_AT,
 retained_statement_ids:[],migration_proposal_id:PROPOSAL_STATEMENT_ID}
```

Its sole `issuer` signature is by that same current legacy root. It is not an
ordinary genesis under a different genesis key. The proposal does **not** name
this derived root-state ID, avoiding a hash cycle. It is inert outside its
complete migration. Later root transitions name this exact state and use the
ordinary new-mode rules; full-u64 epoch exhaustion is not reset by migration.

## 4. Prepared authority and exact host consent

Prepare an exact new-mode catalog for this proposal. It contains the proposal,
the migrated initial root, ordinary finite root-issued administrator leases as
explicitly selected, and complete bootstrap activations for every owned roster
host. Prepare exactly one ordinary finite person lease for each stable admitted
person under the inert initial root; reuse that same head in every host's
transcript for that person. Separate sequence1 person grants in each operation
would fork and are forbidden. The migration-only self-consent exception permits
that shared pending person head only for this proposal's own transcripts.
Every activation pins this initial root, same descriptor, exact roster
tuple and ordinary new-mode lifetime/scope limits. Request mode is `new`; this
is a new-context enrollment using existing keys, not a legacy renewal. Both
default-no requester confirmations remain separate. Original-person signing
uses its own machine's typed slots, never a copied private key.

An exact already selected legacy device profile has one narrow cutover rule:
the staged original-owner offer/finalization may preserve its SAME device key
and exact nominal certificate scopes, including conditional8 when the person
currently lacks an administrator role. Independently verify the frozen source,
original legacy certificate signatures/activation and exact person/host/device/
scopes under the approved proposal. Unsigned roster claims alone do not qualify.
The owned host's approved migration_identity and actual privately retained old
selection must match before its staged request, either requester confirmation,
acknowledgment or adoption. A remote owner/admin verifies the exact approved
proposal/source proof/request/roster; it cannot assert that host's private review.

Only mode new with that exact non-`-` migration_proposal_id qualifies. This
changes only the original-owner cap that would discard the preserved nominal
conditional8. Actual current1/2/4 powers, all new finite parents/ceilings,
signatures/consent, known bans/forks/floors and fixed/current-time checks remain.
Bit8 grants no usable administration without an independently current admin
lease; migration MUST NOT create that role merely to preserve the device mask.
All staged evidence stays inert until the complete all-host/root migration.
It supplies no ordinary activation/outcome, selected provider or reusable signer.

No different key, increased scope, newly generated no-prior-device profile,
unapproved proposal, unrelated reparenting or ordinary linking path can use
this rule. No-prior-device generation keeps the normal actual-path scope cap.
Selected: explicit original-person cutover of the exact old nominal profile,
with conditional roles still independently enforced. Discarded: silently
changing that identity/mask, granting an admin role just to migrate, general
nonadmin original-owner15 issuance, an unsigned claimed old selection or a
legacy delegate signature standing in for fresh original/all-host consent.

During this preparation only, the verified legacy root may act as the proposed
initial root to sign those exact roster-bound components. The original person
may consent to its own pending new person/binding/device components under the
bootstrap self-consent rule. This creates no active context or reusable signer.
No staged admin/device can authorize unrelated staged additions. Unbound hosts
instead have a root-issued finite host lease whose exact payload is signed
both by root (`issuer`) and target (`host`); its operation ID is the proposal
statement ID and it activates only with the complete migration. Host consent
here does not fabricate person/device ownership.

For an unbound host, the root first fixes its issuer signature on the exact
proposal-bound host_lease template. Its ready host-role signing request can
carry that public partial template to the target's owner-local
`migration/host-lease` route. The target separately reviews the exact root,
member and finite interval, durably approves its sole host-role template, then
signs ONLY with its actual owned host key. The completed two-signature body
returns through ordinary migration evidence. The partial template never enters
a public catalog; no original/device/root signer is invented for the unbound
host. This is not acknowledgment and creates no fence or active membership.

All owned-host preparation uses current original-person approval. An unbound
host instead supplies only its separately reviewed actual host consent above;
it has no person/device to approve. A prior
delegated legacy signature can identify history but cannot substitute for it.
Prepared policies/groups have the exact new wrappers and new finite parents,
and only their ordinary original-owner/root issuer. Staging verifies those
exact reviewed statements under the inert proposed root/person heads solely
for this prepared catalog; it never treats those heads as ordinary current
authority. No staged device/admin can issue them. A root cannot sign another
person's policy or owner-device lease. Initial fresh policy/group sequences
must exceed that source stream's retained full-u64 high-water; preparation at
2^64-1 returns `version_exhausted`, not a reset. Absent optional policies/groups
do not hide their old maxima or revive a lower permissive body.

The prepared catalog contains no migration acknowledgment or complete migration
object. Its exact bytes are fixed before acknowledgment; no self-containing
catalog/hash is constructed. A host's `migration_ack` statement payload is:

```text
{proposal_id,root_state_id,prepared_catalog_sha256,host_public_key,
 person_public_key,device_public_key,host_lease_id,binding_lease_id,
 device_lease_id,activation_id,acknowledged_at}
```

The envelope context is the proposal's new context. It has `host` signature by
that roster host, plus `device` by its exact selected/new device for an owned
host. Unbound entries use person/device/binding/device-lease/activation `-` and
have only `host`. All references resolve to exact prepared facts for this host.
`acknowledged_at` is its local guarded decision time within the proposal window.
The host rechecks all local source evidence, current clock, reviewed tuple,
full prepared catalog and known restrictions at its final transaction boundary.
Persist the fence, approved intent, exact acknowledgment and immutable prepared
bytes before publication. One proposal has one prepared-catalog hash; a changed
catalog needs a fresh proposal and fresh reviews, not an inherited signature.

The private acknowledgment selector pins actual possession, not active staged
authority. An unbound host uses its own host-only migration intent; an owned
host uses its exact prepared device-lease selector plus actual owned host key.
Both require the full prepared catalog, exact source/proposal/own identity
approval and actual owned host key. The unbound host requires its exact completed
issuer+host signed host lease; it has no device or activation. ONLY an owned
host additionally requires its complete prepared activation and actual retained
device seed. A newly generated device seed
stays in its unique approved identity-intent home until whole adoption. No
ordinary selected provider, device administration or arbitrary signing power
arises from this narrow use. Neither a remote roster assertion nor an already
signed host-membership lease supplies acknowledgment consent.

Acknowledgment explicitly approves eventual exact adoption. It is not a generic
sign endpoint or a substitute for either requester bootstrap confirmation.
After acknowledgment, absence/timeout is unresolved; never unilaterally clear
the fence or resume old positive writes. Complete this exact transition or use
an explicitly separately approved network. Coordinated cancellation/supersession
is unavailable in this initial protocol: return `recovery_required` and retain
the fence; there is no unspecified recovery endpoint that clears it. This chosen
safety cost is shown before acknowledgment. An automated timeout is not an
abort protocol and no distributed exactly-once claim is made.

After collecting every exact acknowledgment, the same current legacy root
signs a `migration_commit` statement with exactly:

```text
{proposal_id,root_state_id,prepared_catalog_sha256,
 acknowledgment_ids,committed_at}
```

It has only the `issuer` role, same root key and new context. IDs are sorted
unique and resolve to exactly the roster's acknowledgments. The root rechecks
current legacy authority, its durable proposal/catalog pin, all signatures and
known restrictions before signing. It persists the exact commit before first
publication and never signs another prepared hash for that proposal. This
final signature authorizes the exact complete prepared state; acknowledgments
alone remain incomplete. It is a one-time migration step; ordinary new-mode
actions do not wait for this signer or an online runtime coordinator.

## 5. Complete evidence, adoption and late learning

The complete migration body is exactly:

```text
{format:1,proposal:STATEMENT,source_catalog_base64,source_state_base64,
 prepared_catalog_base64,acknowledgments:[STATEMENT],commit:STATEMENT}
```

Acknowledgments are sorted by roster host key, exactly one per roster entry.
`kind:"migration"` is a public catalog object whose `dp_` proof ID uses that
kind and the exact complete body under the common proof-ID rule. It is a
composite public proof, not an ordinary single-signature statement. The source
and prepared catalogs do not contain that complete object. The complete body is
at most1MiB, the old source catalog at most512KiB and the prepared catalog at
most1MiB; the whole proof must still fit its own cap after Base64 overhead.
Larger source sets need sufficient-proof reduction or later transport work;
this initial protocol never truncates a known roster. An oversized proof returns
`quota_exceeded`, never a truncated successful migration. Missing exact source,
acknowledgments or bootstrap dependencies returns `proof_required`.

### Exact owner-local and peer evidence handoff

The runtime's public file and owner-local/peer GET/POST evidence carrier is
exactly:

```text
{proposal_base64,source_catalog_base64,source_state_base64,
 prepared_catalog_base64,acknowledgments_base64:[BASE64,...],commit_base64}
```

Each present byte string is strict canonical standard Base64, preserving the
EXACT original decoded bytes. Bounds apply before allocation and after decoding:
proposal/each ACK/commit at most1MiB each, source catalog512KiB, source-state
256KiB, prepared catalog1MiB, at most4096 ACKs and the unchanged whole request
20MiB/owner response32MiB caps. The complete1MiB M bound still applies before an
irreversible approval/fence. Framing overhead cannot increase an inner bound.
Unknown proposal/prepared/commit fields are literal `"-"`; before a proposal
exists all byte fields are `"-"` and the ACK array is empty. Owner-local GET
before a real signed proposal remains404. First owner-local POST requires the
exact signed proposal and both source fields; those cannot be unknown once the
proposal exists. ACK array entries are present original signed statements,
sorted uniquely by independently decoded roster host key, never `"-"` holes.

Parse every decoded component under its existing typed schema and validate
source/prepared hashes against the original decoded bytes. Retain those exact
bytes, including JSON spelling/whitespace, through storage, export, retries,
client/file handoff and cross-language reopening. Outer carrier JSON key order,
whitespace and accepted string escaping may change. Old inline fields,
unknown/duplicate fields and noncanonical Base64 are invalid. A changed decoded
component never becomes compatible by reserialization or semantic comparison;
ordinary exact hash/source/operation checks and error classifications apply.
The full composite body above, statement identities/signatures, approval and
fence rules and existing shared records remain unchanged. Carrier decoding
creates no consent, authority, trust provenance, signer or adoption.

Validation phases are explicit: verify old source against durable prior state;
verify current legacy root/proposal and exact roster; derive the inert new
initial root; structurally verify the exact roster-bound prepared transcripts
under the narrow staging exception; verify every host acknowledgment and exact
root commit; then project the new context with every local restriction/high-water. Do not insert
the proposed context into ordinary authority while verifying its own ancestry.
For late complete learning, this explicit historical preparation verifier
checks exact signatures, roles, parents, interval/scopes, proposal tuple and
consent structurally even when a prepared lease is now expired. It supplies
root-origin/history evidence only. Ordinary activation first application keeps
its current unexpired-lease rules; the migration verifier cannot be selected
for an unrelated activation or used as current signing authority.

First adoption requires the source root to remain the locally verified legacy
current root, all locally known admitted hosts to be covered, no conflict with
a durable proposal/context pin, and the local participant's exact persisted
approval. A new/restored host without that approval uses authenticated explicit
recovery or a new complete enrollment after the migration; a public catalog
does not create owner-local adoption consent. Ordinary later members prove the
same root origin/migration and their own complete new-context enrollment.

Distinct fully valid migration proposals or different complete prepared hashes
for one proposal/context are a disputed root origin, even if one has a larger
legacy epoch or newer timestamp. A cold receiver seeing both grants no positive
authority; an existing receiver retains both exact histories and freezes new
positive paths. It never chooses a hash winner, silently merges prepared grants
or overwrites its adopted pin. All conflict IDs remain visible. This initial
protocol has no automatic recovery from root/all-roster equivocation; explicit
out-of-band recovery or a separately approved network may be necessary. A
locally signed acknowledgment never authorizes an alternative proposal/hash.

An exact complete transition may be learned after its local24h signing window.
The root-origin authorization and all-host consent can establish the new
context as retained history even if prepared finite grants have since expired;
those expired grants supply **no present positive authority**. Current new-mode
renewal/repair needs current authorized issuers and original-owner powers.
A timestamp/receipt cannot renew a prepared lease or prove that commit occurred
before the deadline. A known new-mode context never rolls back to a competing
legacy root or an alternative migration proposal on late learning.

Adoption atomically persists the monotonic mode/context/proposal/root pin, exact
complete evidence, all restrictions/maxima, prepared projections, selected
provider and one `network.migrated` event. Preserve keys, manual grants,
sessions, adapter credentials, projects, attachments, tasks, artifacts, sources,
capabilities and per-call approvals. Only an independently valid matching
device path may be selected. An expired prepared path stays inactive and has
repair guidance; no new person or silently substituted signer is generated.
Any failure rolls back everything except the authority contract's explicitly
allowed monotonic decision-clock update.

After adoption, reject fresh legacy mutations and any legacy-based expansion.
Keep exact late old transcripts for history/recovery without activating their
old membership or consent in the new context. A newly learned applicable old
restriction is checked through the legacy retained-history rules and current
new-mode ratification rules; raw backdated retired-key bytes are not a new deny.
Previously locally admitted stable-key bans remain sticky across migration.
Root/admin generation withdrawals and unbinds retain their exact history and
cannot revive an old generation; fresh new-mode owner/host consent is explicit.

## 6. Storage, transport and verification

Schema23 is additive over the merged OAuth22 baseline, retaining schema21
upgrades through that existing migration. Keep legacy tables/bytes and existing product
state. Add explicit mode/context pins, exact DEC objects, provenance,
restrictions, stream heads/maxima, the shared per-network monotonic clock guard,
staged migration intents/fence, outcomes and delivery outboxes. Unsupported
future schemas refuse before mutation; failed migration rolls back. Opening
the same DB with either host implementation preserves every durable state.
An older binary refuses schema23 instead of silently resuming coordinator mode.

Migration preparation/status/typed approval remain owner-local admin actions.
Authenticated peers may carry exact proposals/proofs/acks; they cannot supply
local consent or choose a signer. No bootstrap generic-import route is added.
Expose the same migration states through both native CLIs: `needs_approvals`,
`prepared`, `acknowledged`, `adopted`, `conflict`, with exact missing host/proof
IDs and expiry/repair reasons. Secrets/private key material are never returned
by status. Transport publication failure preserves the durable local state.

Independent verification covers: legacy before/after linking; successor root
without genesis private key; all four host/CLI combinations; unbound/owned and
offline roster hosts; omitted local facts, root forks and full-u64 maxima;
missing original-person approval and no copied key; both requester reviews;
late complete learning versus expired prepared authority; known escaped legacy
commits; acknowledgment fence/restart and no timeout abort; mismatched prepared
catalog/tuple/signatures; atomic failure/event deduplication; unchanged schema21
tasks/capabilities/approvals/credentials; cross-language reopening, rollback and
downgrade refusal; no old coordinator config or receipt used as new authority.
The exact preexisting nonadmin device15 profile can cut over with fresh
original/all-host consent while policy1 retains its ordinary checks and admin8
stays forbidden without its independent role. Ordinary nonmigration original7
still cannot issue15; an old7→15 increase, changed key/host/profile, missing
private contribution or unapproved proposal refuses without replacement or
staged consent. These are separate controls, not an ordinary scope relaxation.

For unbound host preparation, require a valid already fixed root issuer role,
exact actual own unbound tuple and approved proposal/source; preview is pure.
Approval, host signature and completed prepared-body publication have distinct
durable boundaries. The completed body round-trips through public evidence;
partial templates do not enter catalogs. Wrong target/member/root/context,
bound host, ordinary operation, altered interval or duplicate/extra role refuses
without signing/fencing/adoption. Same-template restart returns exact bytes;
changed approved template conflicts. A missing/wrong actual host key or completed
host lease prevents acknowledgment; an owned host additionally requires its
actual matching device seed and prepared activation, without installing a provider.
Verify distinct host-only and bound host+device acknowledgment templates,
fixed prepared hash, no external owned-key slots, no copied key and no implicit
acknowledgment from the earlier membership approval. Ordinary host/provider
actions still reject these private migration selectors.
