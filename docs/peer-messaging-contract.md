# Known-host messaging contract

Go and Rust implement the same first peer transport slice. A host can persist a message addressed to a local registered agent and return a durable receipt. This does not deliver the message into a live agent, execute work, or implement a conversation/task lifecycle. The [system proposal](peer-messaging-proposal.md) describes the broader direction; this document specifies the implemented behavior.

## Start and configure

`capsule-host [--state DIR] run [--peer-listen IP:PORT]` starts the daemon. `serve` remains an alias. Without `--peer-listen`, it exposes only owner-local administration on `admin.sock`. A peer bind is explicit; port zero chooses an available port, printed in daemon logs. The peer router contains only message acceptance and sender-scoped receipt lookup. It cannot reach local administration endpoints.

Owners configure peers through the private socket, providing an independently verified host ID/public key and a literal IP address with a nonzero port. DNS, enrollment, membership, discovery, NAT traversal, and relays are not implemented. Knowing a host key does not grant operation access. The local socket still trusts its OS account; scoped credentials for individual local integrations are future work.

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

Peers use HTTP/1.1 over mutually authenticated TLS 1.3. TLS certificates carry the installation's existing Ed25519 public key; both sides check the exact owner-configured key, its host ID, certificate validity, and handshake signatures. Host IDs remain `host_` plus the SHA256 hex digest of the 32-byte public key. Configured keys use canonical standard Base64. Certificates renew on restart without changing host identity.

Public CA and DNS hostname verification are replaced by explicit host key pinning. Go retains its standard TLS handshake signature verification. Rust's custom pin verifier delegates handshake signature verification to Rustls's cryptographic provider. Unknown inbound keys and incorrect outbound identity pins fail authentication. Session resumption is disabled so each connection proves identity. A certificate's subject text does not confer membership or user ownership.

Peer certificates expire 30 days after creation. The receiving daemon currently needs a restart to renew its certificate; automatic renewal remains future work. Outbound connections construct a current certificate. Verification and authorization use the host's wall clock; this slice does not protect against clock rollback. Requests, handshakes, and response bodies have bounded duration/size. Rust additionally bounds concurrent peer connections to 64.

## Grants and disconnected operation

No coordination client is implemented. Daemons explicitly operate in disconnected mode; the absence of coordination never implies permission. A grant without `allow_disconnected: true` rejects new messages. Persisted grants remain locally enforceable across daemon restarts. Grant creation and revocation require the private owner-local socket and do not travel through the peer router.

A grant response contains `id` (`grant_` plus 16 random bytes in lowercase hex), `requester_host_id`, `target_agent_id`, fixed `action: "message.append"`, `expires_at`, `max_message_bytes`, `allow_disconnected`, and nullable `revoked_at`. Creation accepts `requester_host_id`, `target_agent_id`, `expires_at`, `max_message_bytes`, and optional `allow_disconnected` (false when omitted). Expiration must be in the future. The byte limit is 1–65,536; CLI default is 65,536. Both the requester peer and local agent must exist.

The receiver checks its own grant on every append, including retries: requester, target, action, revocation, expiration, content size, and disconnected permission. A grant in one direction creates no reverse grant. This slice authenticates only the sending host; it does not establish a member identity, remote agent identity, or delegation chain. Message permission does not expose a shell/file tool or trigger execution.

## Messages and receipts

`POST /peer/v1/messages` accepts exactly `request_id`, `grant_id`, `target_agent_id`, `deadline`, and `content`. IDs have their fixed lowercase hex shapes; request IDs use the `request_` prefix with 16 random bytes. Content is nonempty UTF-8, at most 65,536 bytes and within the grant's limit. Deadline is RFC3339, must be in the future at the receiver, and cannot exceed grant expiration. The full JSON body is limited to 1 MiB. Unknown fields, null values, malformed JSON/UTF-8, invalid IDs/times, and oversized content return 400. A missing, expired, revoked, or mismatched grant returns 403 with code `forbidden`.

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

`conformance/peer_messaging.py` uses isolated hosts, Python's standard library, and OpenSSL for disposable raw-wire client fixtures. It tests all four Go/Rust pairings, including independent grants, disconnected denial, malformed requests, authentication failure, rollback, lost responses, crash recovery, revocation, sender-scoped receipts, and opening the other implementation's state. The local conformance suite also exercises v1→v2 migration. Language tests check certificate validity and key pins; Go additionally checks that a pinned certificate signed in the TLS handshake by another private key fails.

The next slice is an adapter with scoped local credentials and observable delivery/reply into an opted-in existing agent session. It must recheck authorization before delivering queued content and expose uncertain delivery rather than silently starting a replacement session. See the [integration investigation](agent-integration-investigation.md).
