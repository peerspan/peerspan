# First peer interaction proposal

Status: implementation proposal, not an implemented API or a finalized network trust model. This slice follows the [local daemon foundation](host-service-contract.md). Its purpose is to establish an authenticated, authorized, durable exchange between two known hosts before building enrollment, discovery, or the full collaboration protocol.

## Interfaces and user workflow

| Interface | Callers | Responsibility |
| --- | --- | --- |
| Private local control socket | Local CLI and trusted local integrations | Setup, local configuration, diagnostics, and submitting work through this daemon. |
| Connection to coordination | Daemon initiates the connection | Advertise availability and receive membership, peer information, grants, and revocations. |
| Authenticated peer transport | Other daemons | Exchange collaboration requests within grants enforced on the receiving host. |

The local administration router must never become the peer router. Local account access and remote capability access have different authority. Future integration clients will need their own narrower local credentials; the current owner-local socket does not isolate multiple agents running under the same OS account.

Alice and Bob each enroll a machine, make selected agents available, and independently grant access. Bob's CLI or agent integration asks Bob's daemon to contact Alice's agent. Bob does not administer Alice's local socket. A network-facing CLI or dashboard may author membership and grants through coordination; actual collaboration still travels between daemons. Host-owned attachments and execution state remain local.

For this first experiment, owners explicitly configure peer identities, addresses, and inbound grants on each host. This is a development bootstrap path, not the intended everyday enrollment workflow. Network membership and member identities are not inferred from a host key or an agent's owner label.

## Proposed transport and authentication

Use direct HTTP/1.1 over mutually authenticated TLS 1.3 for the first exchange. Go uses its TLS implementation; Rust uses Rustls. Both prove possession of the existing Ed25519 host identity through TLS. Peers are configured with the expected host public key, verified through an independent owner-controlled exchange. An address is connection information, not proof of identity.

Certificates carry the host identity public key. Verify the exact pinned key, its derived host ID, certificate validity, and TLS handshake signatures in both directions. Renewing a certificate must preserve the pinned host key. Unknown keys, a configured ID/key mismatch, expired certificates, and failed signature verification fail closed. Disabling hostname/CA-based identity in favor of explicit key pinning must not disable TLS proof-of-possession checks. The key-pinning verifier and certificate construction need interoperability tests before enabling a network listener.

The verification hooks to assess are Go's [TLS configuration](https://pkg.go.dev/crypto/tls#Config) and Rustls's [certificate and handshake signature verifier](https://docs.rs/rustls/latest/rustls/client/danger/trait.ServerCertVerifier.html). This is a proposed implementation choice. It does not commit the project to public PKI, a Tailscale dependency, or HTTP for the eventual transport. NAT traversal, encrypted relays, and automatic peer discovery are subsequent work. The first listener is opt-in with an explicit bind address; local administration remains on its private socket.

## First grant

The receiving host owns an inbound grant with these fields:

| Field | Meaning |
| --- | --- |
| `id` | Stable local grant identifier. |
| `requester_host_id` | The host authenticated by the transport. |
| `target_agent_id` | Exactly one locally registered agent. |
| `action` | Only `message.append` in this slice. |
| `expires_at` | Required UTC expiration, checked using the receiving host's clock. |
| `max_message_bytes` | UTF-8 content limit, at most 65,536 bytes. |
| `allow_disconnected` | Explicit permission for use without coordination; false by default. |
| `revoked_at` | Local revocation takes effect immediately. |

Knowing a peer key grants no operation access. Permission in one direction creates no permission in the other. The grant is persisted and enforced on the receiver, not supplied as authority by the caller. Owners can revoke it without coordination. Active connections must not retain an earlier authorization decision for new requests.

This initial scope authenticates hosts only. It does not prove a remote member, individual agent, or delegated session identity. Any source-agent metadata is a statement by the authenticated sending host. Per-agent requester grants and multi-hop delegation require a provenance model before implementation; they cannot be inferred from strings in a request.

## Proposed message operation

An opt-in peer router accepts `POST /peer/v1/messages` with a strict JSON object:

| Field | Meaning |
| --- | --- |
| `request_id` | `request_` plus 16 random bytes encoded as lowercase hex, retained across retries. |
| `grant_id` | Identifies the receiver's grant to check. |
| `target_agent_id` | Must exactly match the grant's target. |
| `deadline` | UTC deadline checked by the receiver; must not exceed grant expiration. |
| `content` | Nonempty UTF-8 message within the grant's byte limit. |

Derive the sender from the authenticated connection. Reject unknown/null fields, malformed IDs/timestamps, expired requests, absent/revoked/expired grants, oversized bodies, and unauthorized targets. Cap the entire request body at 1 MiB independently of the content limit. Bound connection setup and request duration.

Persist the received message and its activity event in one transaction before returning a receipt. Deduplicate by `(authenticated sender host, request_id)`: identical logical fields return the existing receipt; reusing an ID with different fields returns a conflict and never overwrites the original. The original receipt identifies the sender, request, receiving host, target agent, and acceptance time. Keep deduplication records across restarts; this slice provides no deletion of them.

Persist an outbound record before sending. A lost response leaves the sender's outcome unknown until it retries or retrieves the receiver's receipt using the same request ID. A status query exposes only a receipt belonging to that authenticated sender; it remains readable after grant expiry/revocation because it does not authorize new work. Sender and receiver status must distinguish transport failure, rejection, durable acceptance, and actual integration delivery. No automatic agent execution follows acceptance in this first transport slice.

## Delivery and acceptance criteria

A receipt means the receiver durably stored the message. Agent receipt and reply are separate evidence. A later integration must recheck authorization before delivering queued messages; expiry or local revocation blocks undelivered work. Messages are agent-addressed in this slice. Session-specific delivery must be specified separately and must never silently substitute a different session.

The shared suite must exercise Go↔Go, Rust↔Rust, Go→Rust, and Rust→Go, including:

- A valid one-direction grant permits one durable exchange; the reverse direction is denied until independently granted.
- Unknown keys and wrong identity pins fail authentication. Known peers without grants fail authorization.
- Wrong targets, expiry, local revocation, and malformed/oversized requests cause no message mutation.
- A dropped acceptance response followed by a retry produces one receiver message and one acceptance event.
- A changed payload under the same request ID returns a conflict.
- Receiver restart preserves receipts and grants; a sender can recover an unknown outcome.
- Failure to write activity rolls back message acceptance.
- Explicit permission for disconnected operation allows reachable configured peers to communicate without coordination. The test bootstrap must explicitly model the disconnected state; absence of a coordinator must not imply permission.

After transport acceptance passes, demonstrate an actual agent receiving the message and returning a response. The [integration investigation](agent-integration-investigation.md) records the existing-session candidate and its limits. That demonstration is required before calling this agent collaboration.

## Decisions still to validate

Validate the TLS key-pinning approach in both libraries, including rotation and certificate validity. Define the public CLI names, peer/grant administration endpoints, database migration, outbound retry schedule, and behavior when a host's clock changes. Keep enrollment, policy signatures/distribution, multi-hop delegation, session routing, and execution isolation explicit future decisions. The proposed host-only grant is deliberately insufficient for remote shell or filesystem operations.
