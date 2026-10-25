# Linking coordinator state and atomic writers

This completes the network-side runtime in the accepted
[transaction contract](machine-linking-transactions.md). The mailbox foundation
and deterministic clock/barrier controls are in
[runtime verification](linking-runtime-checks.md). All authority derives from
verified signed objects; the coordinator's indexes, addresses and timestamps are
not additional authority. The hosts independently verify every map and result.

## Upgraded transport and maps

The following fills in the registration/sync negotiation mentioned in
transaction section 2. Existing `/coord/v1` shapes stay as specified for networks
without an active linking feature. Upgraded callers use these exact new routes:

| Route | Required body |
| --- | --- |
| `POST /coord/v2/networks` | `{name, root_public_key, membership, address, candidates, linking_version: 1}` |
| `POST /coord/v2/networks/{id}/sync` | `{address, candidates, linking_version: 1}` |
| `POST /coord/v2/networks/{id}/members` | `{membership, address, candidates, join_ack, linking_version: 1}` or `{admission, address, candidates, join_ack, linking_version: 1}` |
| `POST /coord/v2/networks/{id}/moves` | `{move, catalog}` |

Before feature activation, these return the existing legacy map, which
has no `format` field; `join_ack` is `"-"`. After activation they return only the
exact format-2 map in transaction section 5 and require its exact feature's signed
join acknowledgment for every new host. Registration creates a pre-feature
network. A daemon with a durable feature pin refuses the legacy response branch.
A claimed version without a signed admission acknowledgment grants nothing.

Pre-feature v2 registration preserves the existing hosted-limit refusal:
HTTP 429 with `{code: "limit", error, limit}` and the exact limit name, including
`networks_per_ip`. Hosts retain that name in coordination errors and attention.
Active linking object quotas keep their existing structured refusal semantics.

The pre-feature v2 POST sync bridge preserves v1's registered mTLS-host gate:
the exact network/host SQL registration must exist before updating its hints.
It serves the legacy stored signed objects for the host to verify, including
forked or corrupt evidence that the host must reject without replacing its
persisted chain. It does not run the active-feature current-member projection
before that legacy response. This permits feature discovery without changing
legacy fork diagnostics or treating coordinator rows as host authority. After
durable activation, the full verified current-member gate remains mandatory;
neither a missing coordinator feature nor a legacy map can clear a host's pin.
All three pre-feature bridge responses (register, members and sync) include the
existing signed `successors` chain from the actual responding identity, just as
their v1 counterparts do. This legacy field is never added to a format-2 map.

After activation, legacy network map/sync and mutation paths return 426
`upgrade_required`. Public network creation remains available, and the existing
relay continues to use verified current membership. No old response can omit
delegated proof while appearing to be a complete current map.

The map descriptor's coordinator address is the request's actual pinned
HTTP/TLS endpoint (`HOST:PORT`), and its public key is the served TLS identity.
Clients compare both to the authenticated connection and their verified
move/successor state. HTTP Host is an untrusted endpoint hint, never proof of a
coordinator move. A ceremony never follows a move in progress.
Every v2 catalog includes the coordinator's complete actual persisted successor
chain as exact `coordinator_successor` public proof objects, from either an old
or current listener, alongside all previously retained network evidence. Do not
add a legacy `successors` field to the exact format-2 map. The existing catalog
count/byte caps apply without truncation. These signatures supply transport
evidence only; each host independently starts following from its known pin.

Merge public catalog objects by exact verified transport ID. Keep the complete
durable signed catalog, including sticky restrictions, root-chain prefix,
operation evidence and policy/group maxima. Imports cannot erase prior objects
or replace immutable objects. The selected root epoch follows the verified full
rotation chain, never an asserted map field. The fixed stored-snapshot verifier
APIs enforce 4,096 objects and 8 MiB decoded public bodies within the 16 MiB map
response cap; mutation request bounds still apply before merging stored state.

The feature proposal roster admits `join_proof_id: "-"` only for its exact hosts.
Every later host has the exact feature acknowledgment/activation proof. Current
membership and binding proof IDs resolve to the signed catalog and must agree
with verified host/person facts. Reachability fields keep existing validation.
Members are sorted by host ID. Removed or incomplete members cannot relay or
perform network mutations merely because a stale members row exists.

### Complete runtime network projection

`VerifyStoredNetworkState(CatalogFactContext, catalog)` in Go and its Rust
equivalent build the complete current network projection. They use the same
fixed stored-snapshot budgets and exact pins, verify every complete historical
activation (including activations not reached as another object's dependency),
then reapply all restrictions and retained-history rules. A pending certificate
without a complete activation stays inert. A signed catalog is never replaced
by unsigned map-member assertions. Existing stateless and stored-budget APIs
keep their narrower, unchanged behavior.

The result contains verified catalog facts and member-proof rows sorted by host
key: `{host_public_key, member, person_public_key, membership_proof_id,
binding_proof_id, join_proof_id}`. Unbound person and binding use `-`. Include
only currently admitted hosts with usable signed membership evidence and the
exact feature join capability. Resolve nested admission/binding proof IDs from
their original activation payload bytes. Prefer the lexicographically smallest
usable exact proof ID for each slot. The frozen feature roster's join proof is
`-`; other hosts require their exact join acknowledgment or complete activation.
No absent dependency is substituted with a matching label or unrelated proof.
Every retained certificate, including unused pending candidates, must pass exact
structural chain/signature validation without becoming activated. Unused
checkpoints must pass strict signature and structural signer validation; they
acquire no retention authority until the exact target/ancestor/scope checks are
needed. Operation-scoped admission/binding records must belong to an exact
verified complete activation; private incomplete drafts never enter a public
catalog. Malformed unused objects cannot poison a future semantic identity.
A fully signed, host-consented operation record missing its activation returns
`proof_required` naming the exact `link_` operation ID. If that activation exists
but does not authorize the record, return `forbidden`. Missing host consent is
`invalid`; no form establishes authority before a complete activation.
For a completed public invite redemption, membership uses that exact
`invite_redemption` object's `pf_` ID and joining capability uses the exact
`join_ack` ID. Never reconstruct a legacy host-membership object from it.

A current signed root attestation may itself supply a host membership proof
when no other currently usable membership proof exists. It must have the tip
epoch, exact host/current member label, and the required feature capability.
Renewal may reference that exact current attestation as its membership proof;
an older attestation, wrong host/label or missing feature capability cannot
satisfy renewal. Existing old-grant renewal still requires its exact matching
current attestation when the selected grant's root is stale.

Malformed/conflicting catalogs and unresolved authority fail without returning
partial replacement state. Invalid unsigned member entries are dropped by the
caller against this independently verified projection; they never add facts.
Public map retrieval, mutation and repair retain their distinct authorization
and freshness requirements.

## Feature preparation and monotonic activation

Use the exact four proposal/acknowledgment/activation routes in transaction
section 4. Only a current member can read proposals. Creating a proposal requires
the current root's exact signature, current epoch/roster, and a current issue
window. Pending candidates are separate from active public catalog facts; at
most eight pending candidates per network. Proposal IDs/bytes are immutable;
exact retries return 200 without another slot. Incomplete/stale proposals never
assert enabled support or auto-remove members.
Before preparing a fresh proposal, discard expired inactive candidates whose
24-hour window has ended; they no longer count as pending. This cleanup never
removes an active feature or public proof. It permits a new root signature after
stale candidates expire without changing any signed deadline.

An acknowledgment must be signed by its listed host and submitted by that TLS
host. Validate the proposal and exact current roster before storing it.
Activation requires one exact signature from every proposal host, unchanged
roster/current epoch, and the existing 24-hour first-activation deadline. Store
the complete feature, imported public proofs and initial access high-water in
one transaction. An identical active retry succeeds after deadline/rotation;
a different second feature conflicts. Feature support cannot be disabled by
rotation, omission, pending candidates, service restart or backup restore.

## Mutations, outcomes and recovery

All transaction section-4 network routes require pinned mTLS, exact strict JSON
and current verified membership except the narrowly authorized joining-host
operation/redemption routes. Generic statement imports cannot admit an
operation-specific linking draft without its complete activation. Every new
ordinary statement must additionally pass current typed action authority and
operation-specific state checks; historical signatures alone never authorize a
fresh write. Root/person original-key possession does not remove an operation ID.
Fresh linking operations and invitation redemptions apply the same current
statement-addition checks to their supplied dependency catalogs, against the
pre-mutation durable catalog. A valid new invitation or activation cannot carry
an unauthorized fresh restriction/grant through that separate entry route.
Historical replication uses the explicit repair/import route before a fresh
ceremony when those old dependencies are not already retained. A failed catalog
addition consumes no invitation and creates no admission, outcome or proof.
The v2 move route requires the active feature and a current mTLS member. It
verifies the exact legacy move under current root/administrator authority,
retains the supplied verified dependency catalog and all known restrictions,
and atomically returns the format-2 map with HTTP 200. A fresh move sequence
must exceed every retained move sequence; an exact already known move is an
idempotent retry. Generic statement submission enforces the same checks.
Move/successor transport records remain public proof; importing them alone does
not change a host's pin or replace the fresh-root missing-feature import step.
The whole mutation, including dependencies, is bounded to 1 MiB.
Fresh policy/group statements may jump to any strictly higher positive u64
version, while an exact already stored byte retry makes no new write. A newly
submitted version at or below the verified retained maximum conflicts; equal
message hashes and byte aliases remain valid historical observations during
repair. CLI-generated next versions and edit reservations keep their distinct
overflow and exact-increment rules.

The shared fixed-budget runtime validators add two explicit writer checks:
`VerifyStoredCheckpoint` validates every exact retained record, original person,
strict ancestor and combined required scope using the complete stored catalog;
successful `Read` alone is insufficient. `VerifyStoredFreshRedemption` checks
the exact public form and invite signatures against the state before admission,
requires `joined_at <= now < invite_expires_at`, live current issuer authority,
and current invite epoch where present. A first `admit` conflicts with an already
admitted or removed target, and `skip` requires the existing exact person label.
It returns exact consumed invite keys and target identities; the coordinator
enforces single use, TLS caller/join capability and atomic outcomes separately.
Neither helper writes state or claims transport readiness.

`VerifyStoredCatalogRepair(ctx, prior, union)` validates historical replication
of complete public evidence with the fixed stored budgets and exact known
restrictions. It validates every retained certificate and checkpoint signature,
requires complete activations for operation-scoped records, and derives the
full current network projection. It does not reinterpret a retained historical
signature as authorization to issue a fresh statement. It keeps valid older
policy/group versions and aliases as observations while selection preserves
the prior maximum. Used retention still requires the exact unaffected current
ancestor or original-person authority. The caller separately verifies its mTLS
member against the immutable union and commits proof/high-water together.

When retained state reports `proof_required`, a member may supply the missing
checkpoint/dependencies in the same mutation. Authorize that caller against the
verified union retaining every known restriction before applying the action;
this repair cannot bypass a known `forbidden` caller or erase prior proof.

`VerifyStoredFreshLegacyJoin` validates a post-feature legacy host membership or
host admission against current authority before registering its reachability.
The exact current root or admitted current administrator signs the grant; an
old root/kept withdrawn administrator cannot issue a fresh join. Memberships
require `joined_at <= now < invite_expires_at`; admissions require the tip epoch
and `admitted_at <= now`. Sticky host/invite restrictions remain authoritative.
The exact signed join acknowledgment is separately verified by the coordinator.

`link-operations` checks its submitted body against 512 KiB before merging
stored proofs, verifies the TLS host against the request, and rechecks all live
authority and state constraints in the same transaction as commit. A different
manifest under an existing request ID conflicts. An exact committed retry
returns the original signed result before deadline/current-authority checks,
including after later revocation. Retrieval permits its joining host or a
current member; stored evidence alone never restores current authority.

Precompute the result packet and sufficient request public catalog against the
1 MiB bound before mutation. A new commit atomically stores membership/address,
admission, binding, certificate activation and the immutable operation result;
renewal adds only the new certificate activation/result. Public proof/category,
operation-count and per-person certificate bounds are checked before additions.
Capacity failure leaves existing state and event/operation identity intact.
Idempotent retries create no duplicate operation, admission or event.

Successful dependency mutations in operations and invite redemptions reconcile
the signed membership projection and SQL reachability registrations in the same
transaction. Remove withdrawn registrations and candidates before checking
new-host capacity, including for a person-only redemption. A valid dependency
removal can free a slot for the same operation's replacement host; failed
authority or capacity validation changes neither registrations nor proof,
invitation-consumption or outcome state.

V2 hosted capacity refusal is HTTP 409 `quota_exceeded` in the strict linking
error/details envelope: the known operation request ID, or `"-"` when the route
has no linking request identity. Existing v1 hosted limits retain their HTTP 429
`limit` envelope.

Every previously unseen redemption or activation supplied to a fresh statements
or dependency-catalog mutation must also satisfy its direct route's first-use
time, current issuer/path/role and admission preconditions. Its own newly
supplied admission evidence cannot establish those preconditions. Evaluate it
against the candidate dependencies with newly supplied redemption/activation
proofs removed, then verify the complete exact target separately. Dependencies
that need an earlier admission must be committed first or explicitly repaired
under the separate historical workflow. Expired invitations or operation
deadlines cannot be bypassed by backdating a proof in a fresh catalog. Known
exact durable proofs and explicit historical repair retain their existing
semantics. Refusal changes no proof, registration, invite consumption or result.

Public invite-redemption retries store and return the original immutable v2 map
snapshot with 200 before first-use/expiry checks. That snapshot supplies public
evidence, never fresh authority; hosts revalidate it with current durable
restrictions/high-water. A different redemption consuming an already used invite
half returns 409 `state_conflict`. An unsuccessful `admit` precondition consumes
neither half, so an explicit subsequent `member/skip` can still use that invite.
Fresh map/actions after delegated-invite expiry require the exact paired invite
record and redemption-PF retention proof. Receipt repetition cannot replace it.

The result is signed by the request's pinned coordinator key. It contains only
`{manifest_id, activation, catalog}` as prescribed, with no code, seed or secret.
Device/person/code private keys are never coordinator state. All error details
follow the exact runtime contract shape. Backup/restore validates every schema-7
category and preserves operation/frame uniqueness and proof state.
The saved categories are cross-checked without requiring present authority:
proof IDs bind their exact body/kind and existing network; an active feature
index resolves to its exact retained complete feature and proposal. Each local
operation outcome retains the exact matching activation and result-catalog
proofs, each redemption outcome its exact redemption and snapshot proofs, and
each feature-import outcome its exact public authorization and snapshot proofs.
Local registrations marked as linking/redemption commits retain the matching
outcome. Missing required parts, altered references or malformed signed result
packets cause backup/restore refusal before replacing a target. An expired or
subsequently revoked complete result remains valid saved evidence. These checks
cannot distinguish an otherwise complete older backup from intentional history
rollback; hosts keep their existing durable restrictions and repair rules.

Independent crash checks use `coord.finalize.before_commit` after final
validation and complete result construction, before SQLite commit, and
`coord.finalize.after_commit` after SQLite commit, before response. Barriers use
the already specified opt-in test mechanism and public request ID only. Restart
and retry must expose either no mutation or the complete original result.

## Verification

Initial feature activation also validates every newly supplied legacy mutation
against the current authority in the pre-request durable catalog. This includes
dependencies retained in a pending proposal or acknowledgment. A valid
current-root feature signature, unchanged host roster and timely proposal do
not authorize an unrelated newly supplied restriction signed by a retired root.
After the first-feature checks pass, validate the candidate union (including
that exact complete feature) with the fresh catalog-additions rules before
persisting any feature or proof. Failed validation leaves the active feature,
public proofs and membership unchanged. Explicit historical repair keeps its
separate rules. A fresh original-person host binding may use person and host
admissions/memberships supplied in the same atomic request only after each such
grant independently passes current-authority and first-use checks against the
pre-request authority. This exception supplies consent targets, not issuer
authority: a newly supplied administrator delegation or admission cannot
authorize another new grant in that request. Restrictions remain effective in
the final complete projection.

A separate author, without implementation source, checks:

- Every exact route/envelope, mTLS subject, pre-feature response branch,
  signed-reader acknowledgment, old-client refusal and no downgrade.
- Feature preparation, missing acknowledgments, mixed implementations,
  eight-pending bound, roster races, clock edges, rotation and immutable retry.
- Initial current-root feature activation with retired-root person/invite
  restrictions despite an unchanged host roster: refusal without activation or
  partial proof; equivalent current-root restrictions remain supported.
- Complete owner/admin/new/renew operations against independent signed vectors,
  live issuer/state failures, all capacities and byte bounds, no partial writes.
- Exact stored result signatures/IDs, retrieval after removal, immutable-ID
  conflict, both crash barriers, restart and backup/restore.
- Sticky revocations, administrator removal/kept records, policy/group maxima,
  delegated invite first redemption and single-use state, verified v2 maps and
  required existing coordination/relay/operations regressions.

Saved redemption and feature-import maps must also retain a coherent member
reference table. Each sorted unique host ID must match its canonical host public
key. Every membership, non-sentinel binding, and non-sentinel join PF resolves
against that snapshot's own exact catalog, including exact nested records inside
a completed activation. The resolved proof must have the corresponding kind
and the same host/network subject. `join_proof_id: "-"` is valid only for a host
in that snapshot's original signed feature roster; otherwise the join proof
must name its durable feature and host. A missing, wrong-kind, wrong-host or
cross-network reference makes backup/restore refuse before replacing a target.
These are historical committed-proof consistency checks: no present-day expiry,
revocation or current-role condition is imposed on an old saved outcome. They
supply no current membership or signing authority.

For an already activated network's historical repair import, a host independently
verified as a current member in the pre-request durable catalog may publish a
complete signed union that removes that same host. Verify entry before applying
the incoming restriction, then verify/reconcile the entire union; subsequent
requests from the now removed host are refused. A host already known removed
in the prior verified catalog cannot regain entry from incoming grants. A host
unknown because an older target backup lacks its admission may still supply
complete independently verified historical membership through the existing
repair rule; unsigned identity hints supply no authority. Missing prior proof
may be repaired by the complete union, with every held restriction preserved.
First-feature root-authorized import retains its existing separate admission
requirements. No prior-member entry permits signing or a grant after removal.

During a fresh root-rotation batch, the historical pre-action verifier may retain
new-current-root signed person-admission and administrator-delegation renewals
for persons/roles independently admitted/current in the complete pre-rotation
prior projection. Verify the prior projection at its own retained epoch and the
renewals against the independently verified new current root. This only preserves
existing authority while replaying old complete activations under the new epoch;
a newly admitted person or newly delegated administrator cannot authorize another
fresh mutation in that batch. All ordinary fresh action, version, restriction,
expiry and final complete-projection checks still apply.
This renewal-only authority snapshot requires a completed feature already in
the prior catalog. Initial feature activation has no prior active issuer
projection to renew; its ordinary fresh dependency checks still run without
constructing an empty prior network state.
In particular, a legacy SSHSIG host revocation by a newly admitted/delegated
administrator supplied in that same rotation batch is `403 forbidden`: the
complete candidate proves its signature, but the signer has no pre-request
issuer role. The refusal leaves the prior rotation and catalog unchanged.
This category does not change missing-proof rules for other typed wire forms.

### Retained registration evidence during backup and restore

Every registration in an active-feature network must retain membership evidence
for its exact host and participation in that exact feature. A host in the signed
initial feature roster may use that roster; every other host needs its retained
matching signed join acknowledgment or completed activation. Legacy invite and
root-admission registrations created after activation must retain their exact original membership bytes
as public proofs even though they have no saved linking-operation outcome.
Imported and operation registrations require the same historical references.
Backup and restore check these references without requiring current issuer
roles, unexpired signing certificates or present policy authority. Missing or
wrong-host/feature evidence refuses atomically before replacing target files.

Retained membership references also retain their historical issuer provenance.
An ordinary person-record admission requires the issuer's independently signed
administrator delegation under the verified root lineage, even when it was
published directly through statements and has no saved operation outcome.
The delegation's network, epoch, person and root signature must verify; merely
retaining a delegation-shaped object is insufficient. A payload with the correct
host and a matching join acknowledgment cannot replace that issuer dependency.
Apply this check to each saved snapshot's own catalog and the retained
registration catalog, including records nested in activations. Existing exact
record, certificate and completed-operation checks remain required.

This provenance audit returns no current members, activated certificates,
freshness or signing permission. It checks historical signatures and complete
issuer delegation without requiring today's expiry or current issuer role.
Existing live
map and action verification continue to require their full current conditions.
Independent verification includes a post-feature admitted/delegated original
person publishing a host admission directly, omission of only that person's
delegation while membership and join acknowledgment remain present, and atomic
backup/restore refusal. The complete historically expired or withdrawn archive
remains acceptable and supplies no current authority.
