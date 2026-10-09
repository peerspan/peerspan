# Path to production connectivity

Status: working sequence, agreed 2026-10-05. The decisions behind it are recorded in the `mesh-new` system design under "Enrollment and reachability decisions". Each milestone is a working slice in both host daemons with shared conformance, following the [host contract](host-service-contract.md) and the [known-host messaging contract](peer-messaging-contract.md).

The known-host messaging slice stores authenticated messages on hosts. It requires owners to exchange host keys and literal addresses by hand. It needs a direct TCP path, and only hosts are authenticated. This roadmap removes those limits in dependency order.

| # | Milestone | Depends on | Removes |
| --- | --- | --- | --- |
| 0 | Automatic peer certificate renewal | — | Restart needed every 30 days. Done. |
| 1 | Signed enrollment and coordination ([contract](coordination-contract.md)) | — | Manual key and address exchange. Grants no longer require `--allow-disconnected` while coordination is connected. Implemented. |
| 2a | Signed membership revocation, leaving, and root rotation | 1 | Membership cannot be withdrawn except by coordinator omission, and the root key cannot be replaced. |
| 2b | Person identity: multiple administrators and owner-managed access ([proposal](person-identity-proposal.md)) | 2a | One administrator key, and access configured per host, naming individual host IDs. Implemented: SSH-key persons with one-command join (slice 1), delegated administrators and groups (slice 2), owner-signed access policy (slice 3). Direct policy propagation among an owner's hosts is deferred. |
| 3 | QUIC peer transport, then encrypted relays ([proposal](quic-relay-proposal.md)) | 1 | Hosts behind NAT or firewalls cannot be reached. Implemented: QUIC transport (3a) and relays in `capsule-coord` (3b). |
| 4 | Direct-path discovery and NAT traversal | 1, 3 | All traffic goes through the relay when a direct path would work. Implemented: STUN candidates and signed path discovery below QUIC; NATs that allocate a port per destination on both sides stay on the relay. |
| 5 | Automatic retry of uncertain sends, owner and agent alike | — | Senders recover `unknown` outcomes by hand. |
| 6 | Task delegation, agent origin, and delegation chains ([proposal](delegation-proposal.md)) | 2b | Requests are authenticated only as hosts, so a receiver cannot tell which agent originated a request or verify that delegated authority narrowed at each hop. Implemented: agent origin (slice 1), [single-hop tasks](task-contract.md) (slice 2), [artifacts](artifact-contract.md) (slice 3), [delegation chains](delegation-chain-contract.md) (slice 4), and live acceptance (slice 5: [three Claude Code sessions over a two-link chain](results/delegation-live.json)). |
| 2c | Direct policy propagation among an owner's hosts (deferred from 2b; [contract](coordination-contract.md#direct-propagation)) | 2b | A coordinator can delay a newer policy until it expires. |
| 7 | Launch readiness: administration simplicity, status and onboarding ([proposal](launch-proposal.md), [contract](launch-contract.md)) | — | Too much administration surface for a first user. In progress: CLI shape and status (slice 1, done); service installer, default coordinator, and coordinator limits (slice 2, done); team onboarding, generated person keys, `*` rules, and self access (slice 3, done); agent directory and `person/agent` addressing (slice 4). |

Next, as agreed on 2026-10-07: milestone 6, then 2c, then 7. Agent delivery into a live session (see the [integration investigation](agent-integration-investigation.md)) is a parallel track. It does not depend on these milestones.

## 1. Signed enrollment and coordination

A network creator's host holds a network root key. Invites are one-time keys signed by the root, and a joining host signs its own key with the invite key. A separate Go `capsule-coord` service stores these chains, enforces invite single use, records advertised addresses, and serves each member a network map. Hosts verify every chain themselves before treating a member as known. They persist the verified map so that they keep working, within grant rules, when coordination is unavailable.

Coordination becomes the definition of "connected" for grants. A grant without `allow_disconnected` is usable only while the requester is a member of a network that this host synced recently.

## 2. Membership, administration, and owner-managed access

Agreed on 2026-10-06; the [access model](access-model.md) explains the roles. The network administrator controls membership only. Access stays with each agent's owner. Central management comes from owner-signed policy, not from administrator authority.

- **2a:**
  - The root key signs revocations of a host or of an unused invite, and a member signs its own departure.
  - Revocations are sticky: hosts persist them and keep enforcing them, even if a coordinator later omits them or serves an older map.
  - The root key can sign a successor root, so the root can be rotated.
- **2b:** a person identity, meaning a member key separate from host keys. Administrator keys build on it to allow multiple administrators. Owners build on it to manage access centrally: grants name members or groups, and owner-signed policy is distributed to all of an owner's hosts. It is proposed for review before it is built, because person identity also settles the open question of what a person is in the system design.

## 3. QUIC peer transport, then encrypted relays

Agreed 2026-10-06: the peer transport moves to QUIC before relays are built, the relay runs inside `capsule-coord`, and only network members may use it. A relay forwards end-to-end-encrypted peer QUIC packets addressed by host ID, so it cannot read traffic or impersonate either side. The [QUIC and relay proposal](quic-relay-proposal.md) covers the design and the decisions still to settle.

## 4. Direct-path discovery and NAT traversal

This adds STUN-observed public UDP mappings as candidate addresses, and signed path probes that both peers send at once, coordinated through the relay. A validated direct endpoint takes over a peer's traffic inside the combined socket, below QUIC, because QUIC cannot change a server's address. Relays remain the guaranteed path. See the [proposal](quic-relay-proposal.md).

## 5. Automatic retry of uncertain sends

The daemon retries every `unknown` outbound request with backoff, using the same request ID, until it is accepted, rejected, or past its deadline. This covers owner CLI sends and agent-initiated sends alike, replacing the adapter contract's earlier rule that agent sends are never retransmitted automatically (agreed 2026-10-06). Receivers deduplicate by request ID, so a retry creates no second message and consumes no extra send budget. Senders and agents still see the request ID and its final state.

## 6. Per-agent identity and delegation provenance

Task delegation and remote tools create chains: Alice's agent delegates to Bob's agent, which calls a tool on Carol's host. Carol's host must verify three things: the chain originates with Alice's agent, each hop only narrowed what is allowed, and no link has been revoked or has expired. The likely shape has two parts. A host signs an assertion of which local agent or session originated a request; that is only as strong as the host, while isolated runtimes give real per-agent separation. Each hop then signs a delegation that narrows scope, and the final receiver checks the whole chain against each owner's policy. Capability-token designs such as macaroons and biscuits are the reference reading. This milestone builds on 2b's person identity and is sequenced with the first collaboration operation, task delegation. It will be proposed for review before it is built.
