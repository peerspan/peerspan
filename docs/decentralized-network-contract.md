# Coordinator-free networking: implementation contract

Status: DEC-01 shared contract, initially based on implementation main
`6d3823fd3115fff247b1af8551553baf30e97f0f` (schema21). The current additive
storage target is DEC23 over merged remote MCP/OAuth22 (`ec1052fa`); the
initial experimental DEC22 storage allocation is superseded. Runtime implementation
and independent executable cases start only after this complete shared contract
and its Verification cases are reviewed and merged. That merged revision pins
the implementation contract. The owner delegated recommended decisions and documentation of their
rationale/discarded alternatives for this stream only. Both Go and Rust ship;
Rust remains recommended. The accepted product direction is in
[system-design PR 14](https://github.com/peerspan/docs-internal/pull/14).

This contract coordinates the [authority](decentralized-authority-contract.md),
[bootstrap](decentralized-bootstrap-contract.md),
[migration](decentralized-migration-contract.md),
[shared storage](decentralized-storage-contract.md),
[runtime API and CLI](decentralized-runtime-contract.md),
[independent verification](decentralized-verification-contract.md) and
[optional helper operator](decentralized-helper-contract.md) contracts. Authority specifies
exact signed state, validity, expiry, conflict and renewal rules. Bootstrap
specifies context encodings, enrollment, linking, contacts and optional helpers.
Migration specifies source-state endorsement, all-known-host consent, fresh
original-person approval and monotonic cutover. Storage fixes additive schema23
and cross-language resumption. Runtime fixes typed preparation, public routes,
consent and local commit semantics. Verification supplies the independent
public-vector interface and concrete cases; the helper contract fixes the
optional operator and its separate artifact. A contract or successful byte
reader is not evidence that the coordinator-free runtime exists.

## Scope and selected decisions

| Decision | Selected behavior and reason | Discarded alternatives |
| --- | --- | --- |
| Mandatory infrastructure | No required Peerspan-operated service or single per-network coordinator; authority and execution are verified on participating hosts. | A renamed coordinator, a single mandatory self-hosted controller, or a vendor bootstrap identity that can approve members. |
| Optional helpers | Replaceable discovery/rendezvous and encrypted relays may assist reachability. Their keys authenticate transport endpoints only. | Giving helper receipts, presence, clocks or directory responses membership/access authority. |
| Partition model | Bounded signed offline authority with fixed inherited expiry; learned restrictions apply immediately. Exact per-authority bounds and renewal issuers are specified in the authority contract. | Requiring a quorum for ordinary authorized work; allowing indefinitely usable cached authority; treating a fresh signature as proof no newer revocation exists. |
| Existing primitives | Reuse host/person/device identities, reviewed signing/encryption and QUIC where the new contexts permit. | Choosing a new cryptographic scheme, DHT, consensus service or transport library without a concrete requirement. |
| Helper implementation | Ship one optional Go transport-only operator with both Go and Rust host clients and an open wire. | Requiring helper deployment for every host or a second operator implementation without a launch requirement. |
| Protocol evolution | Explicit new signed contexts and authorized migration, preserving exact historical bytes and stable identities. | Empty/fake coordinator pins, re-signing historical bytes as though unchanged, or inferring security mode from a failed connection. |
| Public launch mode | New creation, enrollment and ordinary work use the coordinator-free lifecycle. Retained legacy machinery is for history/migration, not an alternative hidden default. | Calling a default switch complete while fresh networks still silently depend on coordinator maps, sync or receipts. |
| Accepted work | Preserve accepted-task and running-call semantics; expired/withdrawn authority denies new admission, queued starts and new delegation hops. | Reporting an already performed side effect as cancelled or claiming expiry reverses it. |

A trustworthy root/person authority can intentionally grant its stated powers.
Helper operators cannot acquire those powers by operating infrastructure. A
compromised authorized signer can misuse its existing scope until a verifier
learns a restriction or reaches an applicable hard bound. Root compromise,
clock compromise and a wholly rolled-back trust anchor require explicit threat
and recovery statements; they are not solved by signing a newer heartbeat.

## Observable lifecycle

1. Creating a network succeeds locally with no helper, coordinator address or
   coordinator identity configured. The creator establishes signed genesis and
   its own host/person proofs. A network ID remains derived from its genesis
   root key. Local success does not assert that another machine is reachable.
2. A fresh second machine obtains authenticated first contact through a private
   pairing/invitation handoff. Direct/LAN contact works where reachable;
   optional helpers can carry opaque encrypted exchange or relay traffic.
3. Membership, person ownership and resource access remain separate. An
   invitation's bearer secret can introduce a request; final admission names
   exact requester keys and requires the applicable owner/admin authority and
   requester consent. No globally consumed-token database is assumed.
4. A linked device can approve another device while its own exact authority
   chain, scopes and hard expiries permit it, with the original-key holder
   offline. Descendants cannot extend an ancestor's expiry or scope. Absence of
   renewal authority produces repair guidance, never a replacement person key.
5. Hosts exchange exact signed authority records and needed dependencies with
   authenticated peers. They independently verify, retain restrictions and
   maxima, and publish durable local changes without a central acknowledgment.
6. Resource owners continue to control tasks, messages and capabilities.
   Membership, helper reachability and permission to converse do not grant
   command execution, raw-source access or capability calls. Preserve the
   per-call approvals, resource bounds and `gh` source behavior merged in
   PRs 78 and 80.

## Authority and availability boundaries

In the new mode, recent coordinator sync, peer heartbeat, helper presence and
successful gossip are never authorization predicates. Replace every use of
the old `connected()`/last-sync predicate that affects network-derived authority,
including self access, capability calls, task admission and device signing.
The receiver uses verified current local authority, retained restrictions,
conflict state and the detailed signed expiry rules. Reaching a peer proves
reachability, not completeness of that peer's history.

Every fresh admission, policy expansion, delegation and management action is
checked against independently established prior authority. Newly supplied
admission/delegation evidence cannot authorize itself. Historical repair has an
explicit separate path and does not create fresh authority through backdating.

Known local restrictions commit before attempted publication and remain in
force while delivery is unavailable. Omission, shorter history, a lower access
version, an empty helper answer or a transport error cannot erase them.
Concurrent control histories require the authority contract's explicit fork
and resolution rules. A hash/timestamp tie-break cannot silently select a
permissive conflicting branch. Do not reject learning an otherwise valid
restriction solely because another authority domain has a conflict.

Expiry is checked per new request/start/handoff as required by each operation.
Existing accepted tasks and running calls retain their documented outcome and
cancellation semantics. Status, result retrieval and cancellation keep their
existing identity/ownership checks. A transport success is not evidence of
model execution or a completed task.

## Transport and privilege separation

Ordinary peer routes keep exact host-key authentication and per-request
authorization. Fresh unknown keys cannot gain entry merely because a bootstrap
route exists. Bootstrap uses a separate versioned TLS/QUIC protocol/router with
the narrow pairing/request capability from the bootstrap contract. Never expose
the owner administration router, local filesystem, local sockets or ordinary
peer actions through that pre-enrollment path.

Helpers forward only bounded protocol data and encrypted peer packets. They
cannot mint authority, impersonate peer TLS keys, refresh an authority expiry,
or select the user's person/device identity. Authenticate the remote peer
independently of every address, DNS response, contact hint and helper identity.
Addresses/timing remain potentially visible to transport operators; encryption
does not establish anonymity.

## Persistence, migration and compatibility

The current shared host schema is **21**, including per-call approvals and
resource-bound/`gh` state. New additive DEC storage begins at schema **22**.
Both hosts must open each other's state and resume exact durable operations.
Old/new unsupported schemas refuse before modification; failed migration rolls
back. Preserve host/person/device keys, network IDs, owner policy, restrictions,
high-water marks, selected providers, service configuration, sessions, projects,
attachments, approvals, capabilities and adapter credentials.

Protocol migration is a separate authorized operation from opening the new
database. It fixes the new context, accepted root/history and participating
roster under explicit current authority and host consent. Preserve all known
members; unavailable hosts cannot be silently removed. An old host is not
assumed to understand the new context merely because it signs a legacy proof.
The migration contract fixes exact proposal/source-state/acknowledgment/commit
bytes, conflict handling and the explicit original-person availability cost.
It supplies no automatic cross-protocol device bridge or timed abort. Its
complete review and merge remain the gate before implementation.

Keep exact old descriptors, proofs, invitations and completed transcripts as
historical evidence; never remove fields from signed bytes. A pending old
ceremony keeps its original identity, deadline and domain and cannot be resumed
as a new-domain ceremony. Learning/activating the new mode is monotonic and
cannot fall back to old coordinator maps or legacy mutation paths. Final public
setup creates new networks in the new mode; any retained compatibility behavior
is explicit and cannot be counted as coordinator-free acceptance.

## Delivery slices and review gates

| Slice | Deliverable | Required gate |
| --- | --- | --- |
| DEC-01 | Exact threat/authority/context/bootstrap/helper/migration contracts and selected/rejected decisions | Independent contract-author audit and root/Codex protocol review |
| DEC-02 | Cross-language signed readers/projections, expiry, history/fork rules and durable peer state | Independent public-vector and state-transition conformance |
| DEC-03 | Direct creation/admission/linking, immutable outcomes and crash recovery | All Go/Rust role pairings and real CLI consent/retry cases |
| DEC-04 | Contact exchange, proof repair, optional helpers and independent relay failover | Hostile helper, unavailable transport and restrictive-NAT coverage |
| DEC-05 | Complete Go/Rust runtime and authorized migration preserving schema-21 features | Shared state reopening, migration rollback/refusal, current task/capability regression gates |
| DEC-06 | Guided setup/status, packaging and removal of mandatory coordinator defaults | Normal installed packages, no-checkout install handoff and no hidden coordinator configuration |
| DEC-07 | Final independent adversarial and installed matrices, real-machine/live result and limits | Actual artifact/revision evidence, resolved findings, reviewed/merged PRs and final-main equivalence |

Do not mark the milestone complete from pure reader tests, cached-peer messaging,
a helper response or fixture readiness alone. Preserve initial failures and
attribute every passing continuation to its exact source and artifact. New
conformance comes from the independent contract-only author. Implementers do
not author tests that restate their implementation.

## Verification requirements

The detailed contracts must supply concrete cases and exact outcomes for:

- Empty-config local creation; authenticated first contact and new admission;
  both default-no requester confirmations; device B approving C while A is
  offline; no original-person key copying or implicit identity replacement.
- Every authority class's exact expiry, parent ceiling, renewal permission,
  clock rollback/restart boundary and queued-versus-accepted work behavior.
- Competing histories/target keys, equal-version policies, root/admin/group
  forks, replay, omitted restrictions, full-u64 maxima and authorized recovery.
- Reordered/missing evidence, incomplete prior projections, exact historical
  repair and learning a valid revocation despite an unrelated disputed domain.
- Crash/lost-response boundaries before/after participant signatures, final
  consent publication, durable acceptance, projection and local event emission.
- Separate bootstrap/peer/admin routers, forged/expired contacts, endpoint
  substitution, malformed/oversized helper replies, amplification and quota
  exhaustion without evicting authority history or widening access.
- Authorized old-to-new migration, unavailable/old hosts, downgrade refusal,
  cross-language reopening and exact preservation of schema-21 product state.
- Actual normal installed linking/setup across four CLI/daemon pairings with
  no coordinator process/address/key; reachable participant-only paths with all
  vendor services disabled; restrictive-NAT paths through independent helper
  operators and helper removal/replacement.
- A useful live-agent task on separate machines with checked output and access
  withdrawal. Record actual topology, packages and observations separately
  from deterministic conformance and fixture-agent readiness.
