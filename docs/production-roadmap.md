# Path to production connectivity

Status: working sequence, agreed 2026-10-05. The decisions behind it are recorded in the `mesh-new` system design under "Enrollment and reachability decisions". Each milestone is a working slice in both host daemons with shared conformance, following the [host contract](host-service-contract.md) and the [known-host messaging contract](peer-messaging-contract.md).

The known-host messaging slice stores authenticated messages on hosts. It requires owners to exchange host keys and literal addresses by hand. It needs a direct TCP path, and only hosts are authenticated. This roadmap removes those limits in dependency order.

| # | Milestone | Depends on | Removes |
| --- | --- | --- | --- |
| 0 | Automatic peer certificate renewal | — | Restart needed every 30 days. Done. |
| 1 | Signed enrollment and coordination ([contract](coordination-contract.md)) | — | Manual key and address exchange. Grants no longer require `--allow-disconnected` while coordination is connected. Implemented. |
| 2 | Membership revocation and root-key management | 1 | Membership cannot be withdrawn except by coordinator omission. There is only one administrator key. |
| 3 | QUIC peer transport, then encrypted relays ([proposal](quic-relay-proposal.md)) | 1 | Hosts behind NAT or firewalls cannot be reached. |
| 4 | Direct-path discovery and NAT traversal | 1, 3 | All traffic goes through the relay when a direct path would work. |
| 5 | Automatic outbound retry schedule | — | Senders recover `unknown` outcomes by hand. |

Agent delivery into a live session (see the [integration investigation](agent-integration-investigation.md)) is a parallel track. It does not depend on these milestones.

## 1. Signed enrollment and coordination

A network creator's host holds a network root key. Invites are one-time keys signed by the root, and a joining host signs its own key with the invite key. A separate Go `capsule-coord` service stores these chains, enforces invite single use, records advertised addresses, and serves each member a network map. Hosts verify every chain themselves before treating a member as known. They persist the verified map so that they keep working, within grant rules, when coordination is unavailable.

Coordination becomes the definition of "connected" for grants. A grant without `allow_disconnected` is usable only while the requester is a member of a network that this host synced recently.

## 2. Membership revocation and root-key management

The root signs revocations of a host or of an invite. Hosts persist and enforce a revocation even when a coordinator later omits it or serves an older map. This milestone also adds root rotation and possibly multiple administrator keys, and settles administrator powers relative to member-owned hosts. Those are open questions in the system design.

## 3. QUIC peer transport, then encrypted relays

Agreed 2026-10-06: the peer transport moves to QUIC before relays are built, the relay runs inside `capsule-coord`, and only network members may use it. A relay forwards end-to-end-encrypted peer QUIC packets addressed by host ID, so it cannot read traffic or impersonate either side. The [QUIC and relay proposal](quic-relay-proposal.md) covers the design and the decisions still to settle.

## 4. Direct-path discovery and NAT traversal

This adds relay-observed public UDP mappings as candidate addresses and a simultaneous attempt coordinated through the relay. A successful attempt moves the existing QUIC connection to the direct path by connection migration. Relays remain the guaranteed path. See the [proposal](quic-relay-proposal.md).

## 5. Automatic outbound retry

The daemon retries `unknown` outbound requests with backoff until each is accepted, rejected, or past its deadline. Retries reuse the existing idempotent request ID.
