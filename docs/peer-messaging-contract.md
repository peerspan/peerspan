# Known-host messaging contract

Go and Rust implement the same first peer transport slice. A host can persist a message addressed to a local registered agent and return a durable receipt. This does not deliver the message into a live agent, execute work, or implement a conversation/task lifecycle. The [system proposal](peer-messaging-proposal.md) describes the broader direction; this document specifies the implemented behavior.

## Start and configure

`capsule-host [--state DIR] run [--peer-listen IP:PORT]` starts the daemon. `serve` remains an alias. Without `--peer-listen`, it exposes only owner-local administration on `admin.sock`. A peer bind is explicit and uses UDP; port zero chooses an available port, printed in daemon logs. The peer router contains only message acceptance and sender-scoped receipt lookup. It cannot reach local administration endpoints.

Owners configure peers through the private socket, providing an independently verified host ID/public key and a literal IP address with a nonzero port. Peer addresses do not use DNS. Signed enrollment and membership are specified separately in the [coordination contract](coordination-contract.md); that contract allows a DNS name only for a pinned coordinator address. Discovery, NAT traversal, and relays are not implemented. Knowing a host key does not grant operation access. The local socket still trusts its OS account; scoped credentials for individual local integrations are future work.

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `peer add --id HOST --public-key BASE64 --address IP:PORT` | `POST /v1/peers` | Persist or update a peer's address; verify that its ID matches the key. Returns 200. |
| `peer list` | `GET /v1/peers` | Return peers sorted by ID. |
| `grant create --peer HOST --agent ID --expires-at TIME [--max-message-bytes N] [--allow-disconnected]` | `POST /v1/grants` | Create an inbound grant to the configured host for the local agent. Returns 201. |
| `grant list` | `GET /v1/grants` | Return grants sorted by ID. |
| `grant revoke ID` | `POST /v1/grants/{id}/revoke` | Persist immediate local revocation, idempotently. |
| `message send --peer HOST --grant ID --agent ID --deadline TIME --content TEXT [--request ID]` | `POST /v1/outbound` | Persist an outbound request, attempt the peer exchange, and return its durable outcome. |
| `message inspect --peer HOST ID` | `GET /v1/outbound/{peer}/{id}` | Return the saved outbound request and outcome. |
| `message retry --peer HOST ID` | `POST /v1/outbound/{peer}/{id}/retry` | Resubmit the exact persisted request. |
| `message refresh --peer HOST ID` | `POST /v1/outbound/{peer}/{id}/refresh` | Query its remote receipt without resubmitting work. |
| `message list [--after N] [--limit N]` | `GET /v1/messages?after=N&limit=N` | Read a page in local insertion order. |

All local reads/actions return 200 unless noted. CLI outcomes are JSON. A successfully submitted send can return `unknown` or `rejected`; inspect its `state`, rather than treating CLI exit zero as remote acceptance. Invalid local input/storage errors return the usual HTTP error and nonzero CLI exit. Peer/grant inputs are flat strict JSON objects; their fields are shown below. The CLI supplies the documented defaults.

## Transport identity

Peers use HTTP/1.1 over QUIC version 1 (RFC 9000) on UDP, with mutually authenticated TLS 1.3. The design and its alternatives are in the [QUIC and relay proposal](quic-relay-proposal.md). TLS certificates carry the installation's existing Ed25519 public key; both sides check the exact owner-configured key, its host ID, certificate validity, and handshake signatures. Host IDs remain `host_` plus the SHA256 hex digest of the 32-byte public key. Configured keys use canonical standard Base64. Certificates renew without changing host identity.

Public CA and DNS hostname verification are replaced by explicit host key pinning. Go keeps its standard TLS handshake signature verification. Rust's custom pin verifier delegates handshake signature verification to Rustls's cryptographic provider. Unknown inbound keys and incorrect outbound identity pins fail authentication. 0-RTT and session resumption are disabled, so each connection proves identity. A certificate's subject text does not confer membership or user ownership. Servers ignore the TLS server name; clients may send any or none.

Peer certificates expire 30 days after creation. A listening daemon reuses its certificate until less than 15 days of validity remain, then serves a newly generated certificate for the same host key to new handshakes, without a restart; established connections are unaffected. Verification and authorization use the host's wall clock; this slice does not protect against clock rollback.

### QUIC wire format

- **Handshake:** ALPN is exactly `capsule-peer/1`; a connection offering anything else fails. The server requires a client certificate.
- **Streams:** each request uses one client-initiated bidirectional stream. The client writes one HTTP/1.1 request with a `Content-Length` body, or none, and then finishes its send side. The server writes one HTTP/1.1 response and finishes its side. A stream never carries a second request. The server keeps processing the request after the client's FIN, and does not treat the read side closing as a cancelled request. Unidirectional streams and QUIC datagrams are not used: the advertised unidirectional stream limit is zero, so a peer that opens one fails with a connection error.
- **Per-request authentication:** the connection's authenticated key determines the sender. Each request checks again that this key is still a known host (a configured peer or a verified network member), so a host removed while its connection stays open cannot submit or query anything further.
- **Connection reuse:** a client may keep one connection per peer for reuse. It must not reuse a connection after that peer's pinned key or dial address changes.
- **Restarts:** each daemon derives its QUIC stateless-reset key from its host key: HMAC-SHA256 keyed with the 32-byte Ed25519 seed, over the ASCII message `capsule-peer stateless reset`. Both implementations use 4-byte connection IDs, so a restarted daemon of either language can promptly reset connections its predecessor held. Stateless reset tokens are the first 16 bytes of HMAC-SHA256 over the connection ID with that key, as both QUIC libraries compute them. If a request on a reused connection fails at the connection level before any response arrives, the client discards that connection and retries the same request exactly once on a fresh connection. It never retries after receiving a response, or when the failed connection was fresh. This is safe because receivers deduplicate by sender and request ID. Otherwise a lost response surfaces after the 8-second request bound as `unknown`.
- **Limits:** a handshake must complete within 5 seconds, and a connection idle for 30 seconds closes. A server allows at most 64 concurrent connections and 16 concurrent bidirectional streams per connection. Request bodies are limited to 1 MiB and responses to 1 MiB plus headers. A client bounds each request to 8 seconds.
- **Relayed paths:** a connection can also run through the network coordinator's relay. The peer wire format and every check above are identical; only the packet path differs (see Relay in the [coordination contract](coordination-contract.md)).
- **Socket:** one UDP socket per daemon serves inbound connections and dials outbound ones. The Rust implementation disables UDP segmentation offload (GSO): with it enabled, a Rust client stalled after the handshake with a Go server on loopback. The cause is not yet isolated, so this is an implementation note, not a wire requirement.
- **Request bodies:** a request with a body carries `Content-Length`; a bodyless request may omit it. Responses may use `Content-Length` or chunked encoding.

`--peer-listen IP:PORT` and advertised addresses keep their syntax but name a UDP port. The coordinator API (see the [coordination contract](coordination-contract.md)) stays HTTPS over TCP, and local administration and the adapter socket are unchanged. This is an incompatible peer protocol change: hosts from before it speak TLS over TCP and cannot exchange messages with hosts after it. Database schemas are unchanged.

### Path discovery

Roadmap milestone 4. It applies to relay-capable peers: members a host addresses through its synthetic relay address (see Relay in the [coordination contract](coordination-contract.md)). Peers reached by an advertised or configured direct address are unchanged. Path discovery never changes what QUIC sees. QUIC always addresses the peer by its synthetic address, and the combined socket decides per packet whether that means the relay or a validated UDP endpoint.

**Demultiplexing.** Every datagram on the peer UDP socket, or carried in a relay frame, is classified by its leading bytes:
- QUIC, if the first byte has the fixed bit (`0x40`) set;
- STUN, if bytes 4–7 are the magic cookie `0x2112A442`;
- path discovery, if it starts with the 8-byte magic `00 63 61 70 64 69 73 63` (`\0capdisc`).

Anything else is dropped.

**Messages.** A path discovery message is the magic, one type byte, the sender's 32-byte raw host ID, a 12-byte random transaction ID, a 8-byte big-endian Unix time in milliseconds, a type-specific body, and an Ed25519 signature by the sender's host key over all preceding bytes.

| Type | Body | Sent |
| --- | --- | --- |
| `0x01` ping | empty | to a candidate endpoint over UDP, or through the relay |
| `0x02` pong | the ping's transaction ID (12 bytes), then the ping's observed source as an endpoint | back to the ping's source, by the same route it arrived on |
| `0x03` call-me-maybe | a count byte, then up to 8 endpoints | through the relay only |

An endpoint is a family byte (`4` or `6`), then 4 or 16 address bytes, then a 2-byte big-endian port. A receiver accepts a message only if all of the following hold:
- the sender is a known host;
- the signature verifies with that host's pinned key;
- the time is within 30 seconds of its clock;
- the transaction ID has not been seen from that sender in the last 60 seconds.

**Procedure.**
- **Triggering:** when a host sends QUIC packets to a peer over the relay, it sends that peer a call-me-maybe through the relay, listing its own published candidates. It sends at most one every 10 seconds per peer. It also pings each of the peer's candidates from the map, and the endpoints the peer listed in its own call-me-maybe, every 2 seconds for 10 seconds.
- **Answering:** a host that receives a call-me-maybe pings the listed endpoints the same way. That opens its own NAT toward the caller. A host that receives a valid ping replies with a pong to the ping's source.
- **Validating:** a pong that answers one of this host's own pings, received over UDP from endpoint E, validates E for that peer and measures its round trip. Only a host's own completed ping/pong exchange validates an endpoint. A received ping never does, so a replayed or forged message cannot redirect traffic.
- **Using:** while a peer has a validated endpoint, the combined socket sends that peer's QUIC packets to the endpoint with the lowest measured round trip. It presents QUIC packets arriving from a validated endpoint to QUIC as coming from the peer's synthetic address. Packets through the relay are still accepted at all times.
- **Keeping:** while a direct path is in use, the host pings it every 5 seconds. If it receives no pong for 15 seconds, it drops the endpoint and sends that peer's packets through the relay again, then retries discovery after 30 seconds.

**Inspection.** `peer path HOST` (`GET /v1/peers/{host}/path` on the owner-local socket) returns `{host_id, path, endpoint, rtt_ms}`. `path` is `direct`, `relay`, or `none`; `endpoint` and `rtt_ms` are null unless the path is direct. It reports state only and grants nothing.

## Grants and disconnected operation

Grant checks stay on the receiving host. A grant with `allow_disconnected: true` permits a new append without a recent coordination sync. The [coordination contract](coordination-contract.md) defines the other path: a grant without that flag permits a new append only while the requester is a verified member of a network this host synced recently. Absence of a coordinator never implies permission. Persisted grants remain locally enforceable across daemon restarts. Grant creation and revocation require the private owner-local socket and do not travel through the peer router.

A grant response contains `id` (`grant_` plus 16 random bytes in lowercase hex), `requester_host_id`, `target_agent_id`, fixed `action: "message.append"`, `expires_at`, `max_message_bytes`, `allow_disconnected`, and nullable `revoked_at`. Creation accepts `requester_host_id`, `target_agent_id`, `expires_at`, `max_message_bytes`, and optional `allow_disconnected` (false when omitted). Expiration must be in the future. The byte limit is 1–65,536; CLI default is 65,536. Both the requester peer and local agent must exist.

The receiver checks its own grant on every append, including retries: requester, target, action, revocation, expiration, content size, and disconnected permission. A grant in one direction creates no reverse grant. This slice authenticates only the sending host; it does not establish a member identity, remote agent identity, or delegation chain. Message permission does not expose a shell/file tool or trigger execution.

## Messages and receipts

`POST /peer/v1/messages` accepts exactly `request_id`, `grant_id`, `target_agent_id`, `deadline`, and `content`. IDs have their fixed lowercase hex shapes; request IDs use the `request_` prefix with 16 random bytes. Content is nonempty UTF-8, at most 65,536 bytes and within the grant's limit. Deadline is RFC3339, must be in the future at the receiver, and cannot exceed grant expiration. The full JSON body is limited to 1 MiB. Unknown fields, null values, malformed JSON/UTF-8, invalid IDs/times, and oversized content return 400. A missing, expired, revoked, or mismatched grant returns 403 with code `forbidden`. A grant that passes every other check, sent by a verified member of a network this host has not synced recently, returns 503 with code `unavailable` instead, because syncing can restore it. A connected-only grant from a host that is not a member of any network stays 403. The sender records `unknown` and can retry the same request once the receiver syncs again (see the [coordination contract](coordination-contract.md)).

The authenticated connection determines the sender. A successful append returns 200 with `sender_host_id`, `request_id`, `receiver_host_id`, `target_agent_id`, and `accepted_at`. Acceptance means the receiver transaction committed both the message and its activity event. The local message list contains objects with `sequence`, `request`, and `receipt`. `sequence` is a durable local message cursor, independent of the activity sequence. Page defaults are `after=0`, `limit=100`; limits are 1–1,000. Pages stop at the requested count or 900,000 encoded JSON bytes so the CLI can read even maximally escaped content. Continue after the last returned sequence until a page is empty. The byte bound can yield different page lengths across language JSON encoders without changing message order or cursors.

The key `(sender_host_id, request_id)` identifies a received request. While authorization remains valid, retrying with identical field values returns the original receipt without a second message/event. Changed field values under that key return 409. Fields, including timestamp spellings, are compared exactly after JSON decoding. Deduplication records persist across restarts and have no deletion API in this slice.

`GET /peer/v1/receipts/{request_id}` returns only a receipt for the authenticated sender, or 404. Receipt lookup remains available to that known sender after grant revocation/expiration because it authorizes no new work. It does not expose content or other senders' receipts.

## Outbound recovery and persistence

The local send body contains `peer_host_id` plus the five message fields. `request_id` may be omitted or empty for daemon generation. Persist the immutable request and `message.queued` event before attempting any network send. Reusing its `(peer_host_id, request_id)` with different fields is a local 409 conflict.

Outbound records contain `peer_host_id`, `request`, `state`, nullable `receipt`, and nullable `error`:

- `unknown`: prepared or unconfirmed. A transport failure, timeout, malformed receipt, remote server error, or lost response does not establish whether the receiver accepted the request.
- `rejected`: the authenticated peer returned 400, 403, 404, or 409 for the append attempt.
- `accepted`: a matching peer receipt was received and saved. Further local retries return this record without another send, and concurrent failed attempts cannot downgrade it.

Retries are explicit, using the saved request. After a restart, inspect an unknown record, then retry or refresh it. Refresh queries only the receipt; a missing receipt leaves the outcome unknown. A queued request interrupted before transmission is also safe to retry. Exactly-once host acceptance does not establish exactly-once agent delivery or execution.

Database version 2 atomically adds `peers`, `grants`, `received_messages`, and `outbound_messages` to version 1 while preserving identity, registrations, sessions, and activity. Records are JSON stored alongside indexed primary keys, with one connection/transaction owner per daemon. The two implementations can reopen each other's v2 state, but cannot open the same directory simultaneously. Older binaries must reject v2 rather than downgrade it.

New local activity kinds are `peer.configured`, `grant.created`, `grant.revoked`, `message.queued`, `message.accepted`, and `message.rejected`. A local `message.accepted` can refer to receiver acceptance or the sender recording a receipt; its subject contains the other host ID and request ID. No duplicate event is emitted for idempotent revocation or received-request retries. Message acceptance/receipt updates and their activity events commit atomically.

## Verification and next slice

`conformance/peer_messaging.py` uses isolated hosts and Python's standard library. Its raw-wire cases use `capsule-peer-probe`, a small Go test client that speaks the QUIC wire format with a disposable host's own key but performs no pin check. A UDP proxy that stops forwarding the receiver's packets once the message is committed produces lost responses. It tests all four Go/Rust pairings, including independent grants, disconnected denial, malformed requests, authentication failure, rollback, lost responses, crash recovery, revocation, sender-scoped receipts, and opening the other implementation's state. The local conformance suite also exercises v1→v2 migration. Language tests check certificate validity, key pins, ALPN, and per-request re-authentication on a reused connection; Go additionally checks that a pinned certificate signed in the TLS handshake by another private key fails.

Enrollment, coordination, relays, and NAT traversal follow the [production connectivity roadmap](production-roadmap.md); the first of those is specified in the [coordination contract](coordination-contract.md). In parallel, the next delivery slice is an adapter with scoped local credentials and observable delivery/reply into an opted-in existing agent session. It must recheck authorization before delivering queued content and expose uncertain delivery rather than silently starting a replacement session. See the [integration investigation](agent-integration-investigation.md).
