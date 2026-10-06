# Signed enrollment and coordination contract

Status: specification for roadmap milestone 1 ([roadmap](production-roadmap.md)). The Go and Rust host daemons implement the host side, and a Go-only `capsule-coord` binary implements coordination. This builds on the [known-host messaging contract](peer-messaging-contract.md). Manual `peer add` remains supported, and nothing here changes the peer router.

## Trust model

A network is identified by its **root key**, an Ed25519 key generated on the creator's host and stored only in that host's database. Membership is a signed chain that every host verifies itself:

```text
root key ──signs invite statement──▶ invite key (one-time) ──signs member statement──▶ host key
```

The coordinator stores chains, enforces single use of each invite key, records advertised addresses, and serves maps. It is trusted for availability only. It can withhold members, serve stale maps, or refuse service. It cannot introduce a host, because it never sees an invite private key. Hosts reject any map entry whose chain does not verify against the network root they hold. If two different host keys appear under one invite key, the host rejects all of them, so even a coordinator that obtained a leaked invite cannot reuse it silently.

Membership does not grant access. Grants remain receiver-owned and local, as in the messaging contract. Membership replaces manual key and address exchange, and it defines the connected state for grants. The `member` label is the name an administrator gives an invitee. It is signed but descriptive, and it authorizes nothing.

Invite expiry is enforced by the coordinator at join time and by the joining host. A host that verifies a chain later also requires `joined_at` ≤ `invite_expires_at`, but `joined_at` is asserted by the joiner. Membership revocation is roadmap milestone 2. Until then, a member removed by the coordinator simply disappears from maps.

## Encodings and signed statements

- Public keys and seeds: canonical standard Base64 of 32 bytes. Signatures: canonical standard Base64 of 64 bytes. Decoders reject non-canonical encodings.
- `network_id` is `net_` followed by the lowercase hex SHA-256 of the root public key. Coordinator IDs are `coord_` followed by the lowercase hex SHA-256 of the coordinator public key. Host IDs are unchanged.
- Labels (`name`, `member`) must already be trimmed, contain 1–128 UTF-8 bytes, and contain no control characters (U+0000–U+001F, U+007F).
- Times are UTC RFC3339. A signature covers the exact signed string, and verifiers never re-spell it.

A signed statement is its lines, encoded as UTF-8 and joined with a single `\n`, with no trailing newline:

| Statement | Signed by | Lines |
| --- | --- | --- |
| Invite | root key | `capsule-invite-v1`, `network_id`, `invite_public_key`, `member`, `invite_expires_at` |
| Member | invite key | `capsule-member-v1`, `network_id`, `invite_public_key`, `host_public_key`, `joined_at` |

A **membership** is a strict JSON object with exactly these fields: `network_id`, `member`, `invite_public_key`, `invite_expires_at`, `invite_signature`, `host_public_key`, `joined_at`, and `host_signature`. To verify it against a root public key:

1. Check that `network_id` is derived from the root key.
2. Verify `invite_signature` over the invite statement with the root key.
3. Verify `host_signature` over the member statement with the invite key.
4. Check that `joined_at` ≤ `invite_expires_at`.

The member's host ID is derived from `host_public_key`.

### Test vectors

Ed25519 is deterministic. Both implementations must reproduce these exactly:

| Item | Value |
| --- | --- |
| Root seed / public | `AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=` / `iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=` |
| Network ID | `net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e` |
| Invite seed / public | `AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=` / `gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=` |
| Host seed / public | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=` / `7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=` |
| Host ID | `host_b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709` |
| Member, expiry, joined | `alice`, `2026-11-01T00:00:00Z`, `2026-10-05T12:00:00Z` |
| `invite_signature` | `3WTE8i0clTO4PNMXiWiCgVkYWUzS8nCySGhYZWXDwBmz7K416+cmh5Qb6mSrCU+MNDuSudNWXklbsCc8m+Y4Cw==` |
| `host_signature` | `YD6gwCNa6yQT1ofoSqCR4iDpvG4887BtCcZsGXebPSfX4siZx6z6XnzY2AYM5GoAzdX1SsNIAG4I/kkkIQLWCg==` |

### Invite token

A token is `capsule-invite-v1.` followed by unpadded base64url of a strict JSON object. The object has exactly these fields: `network_id`, `network_name`, `root_public_key`, `coordinator_address`, `coordinator_public_key`, `member`, `invite_public_key`, `invite_seed`, `invite_expires_at`, and `invite_signature`. The token is a bearer secret, because it contains the invite private seed. Owners deliver it out of band. Before contacting the coordinator, a joining host checks five things: the network ID matches the root key, the invite signature verifies, the seed matches `invite_public_key`, the invite has not expired, and the coordinator key is canonical. A failed check returns local 400 and makes no network contact.

## Coordinator service: `capsule-coord`

`capsule-coord [--state DIR] run --listen HOST:PORT` serves coordination in the foreground. `capsule-coord [--state DIR] info` prints `{id, public_key}` and works while the service is running. State defaults to `$XDG_STATE_HOME/capsule/coord`, or `$HOME/.local/state/capsule/coord`. The private-directory, file-mode, and single-process rules are the same as for hosts. The coordinator generates its Ed25519 identity once and keeps it across restarts. Its database schema is internal.

Transport is HTTP/1.1 over TLS 1.3. The coordinator presents a self-signed Ed25519 certificate for its own key, built the same way as host certificates and renewed the same way. It requires a client certificate that proves possession of an Ed25519 key, and the caller's host ID is derived from that key. Hosts pin the coordinator public key from network creation or the invite token. `coordinator_address` is `HOST:PORT`, where HOST may be an IP literal or a DNS name. DNS is safe here because the key is pinned. Peer addresses remain IP literals.

Request bodies are strict flat JSON (nested only where shown), at most 1 MiB. Unknown or null fields are rejected. Errors use the usual `{code, error}` bodies. Advertised `address` is either `""` (not directly reachable) or a literal `IP:PORT` with a nonzero port. `candidates` is an array of at most 8 distinct literal `IP:PORT` strings with nonzero ports (path-discovery hints, see below), possibly empty. A host verifying a map drops invalid candidates rather than the member.

| Endpoint | Body | Behavior |
| --- | --- | --- |
| `POST /coord/v1/networks` | `name`, `root_public_key`, `membership`, `address`, `candidates` | Register a network. `membership` must verify under the root, and its host key must be the caller. Returns 201 with the map. If the network exists and the caller is already a member, returns 200 with the map. Any other existing network ID returns 409. |
| `POST /coord/v1/networks/{network_id}/members` | `membership`, `address`, `candidates` | Join. Returns 404 for an unknown network and 400 for a chain that does not verify. Returns 403 if the host key is not the caller or the invite has expired by the coordinator's clock. If this host already used the invite key, returns 200 with the map and keeps the originally stored membership. If another host used it, returns 409. Otherwise returns 201 with the map. |
| `POST /coord/v1/networks/{network_id}/sync` | `address`, `candidates` | The caller must be a member, otherwise 403, including for unknown networks. Records the address and candidates and returns 200 with the map. |

A **map** is `{network_id, name, root_public_key, members}`. `members` is an array of `{host_id, membership, address, candidates, updated_at}` sorted by `host_id`, and `updated_at` is the coordinator's time of that member's last join or sync. Registration never checks invite expiry, so a network that stayed unregistered for a while can still register. On join, reuse by the same host is checked before expiry, so a retried join succeeds after expiry. Every listed body field is required. Abuse limits on registration are deferred and listed below.

## Host changes

### Persistence

Database version 3 atomically adds these tables to version 2:

```sql
CREATE TABLE networks (id TEXT PRIMARY KEY, record TEXT NOT NULL, root_seed BLOB);
CREATE TABLE network_members (network_id TEXT NOT NULL, host_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, host_id));
PRAGMA user_version = 3;
```

`root_seed` is non-null only on the creator's host, and `administrator` is derived from it rather than trusted from a record. `networks.record` holds the network view below. `network_members` holds one member view per row, including this host's own row, which carries its own membership. Readers tolerate extra record fields. Records are JSON. Either implementation can open the other's version 3 state. Older binaries reject version 3. Invite seeds are never stored.

### Local API and CLI

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `network create --name NAME --member LABEL --coordinator HOST:PORT --coordinator-key BASE64` | `POST /v1/networks` | Generate a root key and a self-membership whose invite expires 30 days after creation, persist them with `network.created`, then attempt registration once. Returns 201 even if registration fails, because the sync loop retries it. |
| `network invite --network ID --member LABEL --expires-at TIME` | `POST /v1/networks/{id}/invites` | Administrator only, otherwise 403 `forbidden`. Expiry must be in the future and at most 30 days ahead. Returns 201 `{network_id, member, invite_public_key, invite_expires_at, token}` and records `network.invite_issued`. |
| `network join --token TOKEN` | `POST /v1/networks/join` | Verify the token. Returns 409 if this network has already been joined. Sign the membership and call the coordinator. Only after it accepts and its map verifies, persist the network, its members, and `network.joined` together. A host already in the network through another invite gets 409. Coordinator 400/403/404/409 map to the same local status. A returned map that omits this host or does not match the network returns 503; unreachable or 5xx return 503 `unavailable`, and nothing is persisted. |
| `network list` | `GET /v1/networks` | Networks sorted by ID. |
| `network members ID` | `GET /v1/networks/{id}/members` | Verified members, including this host, sorted by host ID. |
| `network sync ID` | `POST /v1/networks/{id}/sync` | Register or sync now. Returns 200 with the network record; a failure appears in `last_sync_error`. |

A network record is `{id, name, root_public_key, member, coordinator_address, coordinator_public_key, administrator, last_sync_at, last_sync_error}`. The last two are nullable, and `last_sync_at` is the time of the last successful sync. A member record is `{host_id, public_key, member, address, candidates, updated_at, membership}`.

`run` gains `--advertise IP:PORT`, which requires `--peer-listen`. It defaults to the bound peer address when that IP is not unspecified, and otherwise to `""`. `run` also gains `--coordination-interval SECONDS`, from 1 to 3600 with a default of 30. Each interval, the daemon registers each unregistered administered network (one with no `last_sync_at`) and syncs every other network. Registration and sync send the current advertised address.

### Applying a map

A host applies a map only if all of the following hold: its network ID and root key match the stored network, its own host appears with its own membership, and the request completed over the pinned coordinator. It drops any entry whose chain fails or whose `host_id` does not match its key, and every entry that shares an invite key with a different host key. It then replaces that network's member set in one transaction. Its own entry may carry any validly signed membership for its key, because the coordinator keeps the original membership on a re-join. An entry with an invalid address is kept with address `""`, and all entries sharing a `host_id` are dropped. Member events exclude this host. A join records `network.joined` followed by one `network.member_added` for each other member. That transaction updates `last_sync_at` and records `network.member_added` / `network.member_removed` (subject: host ID) only for actual changes. A failed sync leaves the members untouched and records `last_sync_error`, without an event. Members persist across restarts, so known peers keep working while coordination is unavailable.

### Peer resolution and grants

- A host is **known** if it is a manually configured peer or a verified member of any network, other than this host. Inbound TLS authentication, `grant create`, and the peer router accept known hosts. `peer list` still shows only manually configured peers.
- For outbound dialing, a manual peer's address takes precedence. Otherwise the daemon uses the nonempty address of the member entry with the latest `updated_at`. A member with no address can authenticate inbound but cannot be dialed. A send to it records `unknown` with an error.
- The **connected** state for a grant: a grant without `allow_disconnected` permits a new append only if the requester is currently a member of some network whose `last_sync_at` is within three coordination intervals of now. Otherwise only `allow_disconnected` grants work, as before. The receiver checks the final grant bounds first. If only the connected state fails and the requester is a verified member of a network this host has not synced recently, it returns 503 `unavailable` rather than 403, so the sender records `unknown` and may retry the same request ID later. A requester that is not a member of any network gets 403, because that does not recover. Adapter handoff leaves such a message queued, and a reply to already-delivered content needs only the final bounds (see the [adapter contract](agent-adapter-contract.md)). Receipt lookup is unchanged.

New activity kinds are `network.created`, `network.joined`, `network.invite_issued`, `network.member_added`, and `network.member_removed`.

Hosts give each coordinator call an 8-second timeout and accept responses up to 16 MiB.

## Relay

Roadmap milestone 3b ([proposal](quic-relay-proposal.md)). Every `capsule-coord` relays peer QUIC packets between members of the networks it serves. It relays on its existing TLS listener and address, under its existing pinned key, so the network map needs no relay fields. A relay forwards already-encrypted QUIC packets addressed by host ID. It cannot read them, and it cannot impersonate either host, because the end-to-end peer TLS pins still apply.

### Connection

A host connects over TCP to the coordinator address and completes TLS 1.3 with its host certificate as the client certificate, pinning the coordinator key as for the coordination API. It offers ALPN `capsule-relay/1`; the coordination API negotiates `http/1.1`, and the coordinator dispatches on the negotiated protocol. The caller's host ID is derived from its client key. The coordinator allows 10 seconds for the TLS handshake before routing the connection by ALPN. A caller that is not a member of any network on this coordinator is refused: the connection closes after the handshake, before any frame is processed. One relay connection per host is current. A new connection from the same host replaces the older one, which the coordinator closes.

### Frames

After the handshake, both directions carry frames: one type byte, a 2-byte big-endian payload length, then the payload. A host ID in a frame is the 32 raw bytes of the SHA-256 digest that the `host_` form spells in hex.

| Type | Direction | Payload | Meaning |
| --- | --- | --- | --- |
| `0x01` send | host → relay | destination host ID, then one QUIC datagram | Forward this datagram. |
| `0x02` receive | relay → host | source host ID, then one QUIC datagram | A datagram from that host. |
| `0x03` unreachable | relay → host | destination host ID | The destination has no current relay connection, or the two hosts share no network. Sent at most once per second per destination. |
| `0x04` ping | either | empty | Keepalive; ignored on receipt. |

A datagram is 1 to 1,500 bytes; a host drops a larger outgoing datagram locally instead of sending it. A send frame addressed to the sender itself is treated as unreachable. An unknown frame type, an oversized or truncated frame, or a frame of a type invalid for its direction closes the connection. Hosts send a ping after 15 seconds without sending any frame. The coordinator closes a relay connection after 45 seconds without receiving one.

### Forwarding and limits

The coordinator forwards a send frame only if both the source and the destination are currently members of a common network it serves. It checks that against its own member records, on every frame or from a cache refreshed at least every 5 seconds. Forwarding is best effort, with datagram semantics: frames may be dropped, but are never reordered within one source→destination pair or modified. The coordinator drops frames when a destination's outbound buffer exceeds 1 MiB. It also drops frames from a source that exceeds 8 MiB/s, using a token bucket with an 8 MiB burst. It allows at most 4,096 concurrent relay connections. A dropped frame produces no error frame, since QUIC recovers loss.

### Host behavior

- A host that runs with `--peer-listen` and is a member of at least one network keeps one relay connection to each of its networks' coordinators. It opens that connection as soon as it creates or joins a network, rather than waiting for a periodic refresh, so a newly joined host is reachable at once. It reconnects with backoff from 1 to 30 seconds. Through these connections it accepts inbound peer QUIC connections, the same way as on its UDP socket.
- A host without `--peer-listen` never accepts inbound peer connections. It may open a relay connection on demand to dial out, and receives only datagrams for the connections it initiated.
- Each relay connection carries packets for the host's single peer QUIC endpoint. Relayed peers appear to that endpoint as synthetic addresses, one per peer host ID, that are never sent on the real UDP socket. The synthetic scheme is internal to each implementation; for example, Rust uses IPv4 addresses in the reserved 240.0.0.0/4 block, because `quinn` rejects IPv6 destinations on an IPv4 socket.
- A host closes its relay connection to a coordinator that no longer serves any of its networks. An on-demand relay connection closes after 60 seconds with no relayed peer connection using it, and reopens on the next demand. The peer protocol is unchanged: every peer TLS check and per-request authentication applies to relayed connections.
- **Path choice:**
  - For a manual peer or a member with a nonempty address, the dialer first tries the direct UDP address. The handshake bound is 2 seconds when a relay fallback exists, and the usual 5 seconds when it doesn't.
  - It falls back to the relay of a coordinator for a network both hosts belong to, choosing the lowest network ID, after a failed direct attempt or immediately for a member with an empty address.
  - A peer that shares no network has no relay path.
  - The 8-second request bound covers the whole request: the direct attempt, waiting up to 2 seconds for an on-demand relay connection, and the relayed handshake. A host may fail a pending relayed dial early when it receives `unreachable` for that destination.
  - A relayed connection stays on the relay until it closes. Moving it to a direct path is milestone 4.
- **Return path:** a relayed connection's packets return through the relay connection on which that peer's datagrams arrived.

## Direct paths through NAT

Roadmap milestone 4. The relay keeps every pair reachable. Hosts also try to open a direct UDP path between relayed peers and move their traffic onto it below QUIC (see Path discovery in the [messaging contract](peer-messaging-contract.md)). The [proposal](quic-relay-proposal.md) explains why QUIC's own connection migration cannot do this.

### Reflexive addresses

`capsule-coord` also listens for UDP on the same IP and port as its TLS listener. It answers STUN Binding requests (RFC 8489): the 20-byte header with magic cookie `0x2112A442` and a 12-byte transaction ID. The success response carries `XOR-MAPPED-ADDRESS` with the request's observed source address and port. It ignores every other datagram, sends no other attributes, and does not authenticate. A forged or wrong mapping can only cause a failed path attempt, because peer TLS pins still apply.

A host with a peer socket sends a Binding request from that socket to each of its coordinators. It sends at startup, after creating or joining a network, and at least once per coordination interval. It accepts a response only with a matching transaction ID from the coordinator address it asked. The mapped address is its reflexive candidate for that network.

### Published candidates

A host reports `candidates` on registration, join, and sync. If it runs with `--peer-listen`, candidates are its reflexive address and its non-loopback interface addresses paired with its bound peer port, in that order, up to 8. Otherwise the list is empty. The coordinator stores and serves them unchanged. Candidates are hints for path discovery, not dial addresses: `address` keeps its meaning, and a host still never dials a candidate as an ordinary peer address.

## Verification

Language tests must reproduce the test vectors, reject each tampered field, and reject non-canonical encodings. `conformance/coordination.py` runs one Go coordinator with Go and Rust hosts in every creator/joiner pairing:

- create, invite, and join;
- message exchange without `peer add`, using a grant without `allow_disconnected`;
- rejected invite reuse, locally expired invites, and tampered tokens (no network contact; the token points at a closed port and must fail with 400 rather than 503). Coordinator-side expiry is covered by Go unit tests, since the suite shares one clock;
- a member row injected directly into the coordinator database, simulating a compromised coordinator, which hosts must ignore;
- coordinator outage: connected-only sends get 503 and `unknown` after three intervals and succeed on retry after reconnection, while `allow_disconnected` grants still work; a reply to already-delivered content succeeds during the outage;
- host restart with persisted members;
- coordinator restart, after which syncing resumes.

`conformance/relay.py` runs the Go coordinator with Go and Rust hosts in every pairing. It covers:

- two members that advertise no direct address exchange messages, receipts, and adapter replies through the relay;
- a dead direct address falls back to the relay;
- a non-member's relay connection is refused;
- forwarding is refused between hosts that share no network;
- hosts reconnect after a coordinator restart, and relayed exchanges resume;
- a host without `--peer-listen` can send through the relay but accepts no inbound connections.

`conformance/nat_lab.py` needs root. It places each host behind its own nftables NAT router in Linux network namespaces, with no route between the private networks, and runs every pairing behind three kinds of NAT: port-preserving masquerade, fully random masquerade, and masquerade that drops all forwarded UDP. In each, both directions exchange messages through the relay. A negative control shows no path exists while the coordinator is stopped, and the same request succeeds once it restarts.

For milestone 4, `nat_lab.py` also checks path discovery in each pairing:
- **Port-preserving NAT on both sides:** `peer path` reports `direct` within 15 seconds of the first relayed exchange. A send under an `allow_disconnected` grant then succeeds with the coordinator stopped, which proves the traffic no longer depends on the relay.
- **Fully random NAT on both sides, and UDP blocked:** the path stays `relay`, and messages still flow.

Language tests cover message encoding, signature and freshness checks, replayed transaction IDs, the rule that only one's own pong validates an endpoint, falling back after 15 seconds without pongs, and STUN encoding.

## Deferred

Membership and invite revocation, root rotation, and multiple administrators (milestone 2). Registration rate limits and quotas on the coordinator. Long-poll or streamed map updates in place of interval polling. Port prediction for NATs that allocate a new port per destination, so two such NATs stay on the relay. Path discovery for peers reached by an advertised direct address. IPv6 candidates beyond what interfaces and STUN report. Per-network relay selection and relays other than the network's coordinator.
