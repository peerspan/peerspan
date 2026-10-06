# QUIC peer transport and relays

Status: proposal for review, covering roadmap milestones 3 and 4 ([roadmap](production-roadmap.md)). Agreed on 2026-10-06:
- the peer transport moves to QUIC before relays are built;
- the relay runs inside `capsule-coord`;
- only network members may use it.

Everything else here is proposed. The decisions to settle before implementation are listed under [Decisions to settle](#decisions-to-settle).

## Why move to QUIC first

Peers currently speak HTTP/1.1 over mutually authenticated TLS 1.3 over TCP. Relays could splice TCP streams, but NAT traversal over TCP depends on simultaneous open, which works far less reliably than UDP hole punching. Moving the peer transport to QUIC first gives every later path one design:
- direct UDP;
- relayed packets;
- hole-punched UDP.

QUIC connection migration can then move an established connection from the relay to a direct path without a new handshake or new application state.

## Milestone 3a: QUIC peer transport (direct paths only)

**Identity is unchanged.** QUIC carries TLS 1.3. The daemon presents its existing self-signed Ed25519 certificate from the renewing cache. Both sides keep the current checks:
- the exact pinned key;
- the derived host ID;
- certificate validity;
- the handshake signature.

Go `quic-go` takes a `crypto/tls` configuration, so the existing `VerifyConnection` pin check carries over. Rust `quinn` 0.11 builds on `rustls` 0.23, the version already in use, so the existing `Pins` verifier carries over. 0-RTT and session resumption stay disabled, so every connection proves identity.

**The application protocol stays HTTP/1.1.** Each QUIC bidirectional stream carries exactly one HTTP/1.1 request and response, under ALPN `capsule-peer/1`. These stay as they are today:
- the peer router;
- routes, statuses, and error bodies;
- body limits and strict JSON;
- receipt semantics.

Rust serves each stream with `hyper`'s HTTP/1 connection handling, which accepts any byte stream. Go wraps each stream as a `net.Conn`, accepts it through a `net.Listener`, and passes it to the existing `http.Server`. One QUIC connection per peer is reused across requests, with idle timeout and stream limits replacing today's per-request TCP connections.

HTTP/3 would be the standard choice. It is not recommended now because the Rust `h3` crate is pre-1.0 and has had no release since May 2025. Moving to it later is an ALPN change, because the routes would not change.

**Addresses and flags:**
- `--peer-listen IP:PORT` and advertised addresses keep their syntax but now name a UDP port.
- Peer records, membership maps, and database schemas do not change.
- One UDP socket per daemon serves inbound connections and dials outbound ones. Hole punching needs that later: the mapping a NAT creates for outbound traffic must be the one peers reach.

**What stays on TCP:**
- the coordinator API stays HTTPS over TCP: it is control traffic that is not latency sensitive, and it works through UDP-blocking networks;
- local administration and the adapter socket do not change.

**Cutover:** this is a hard switch with no dual-stack period, since nothing is deployed yet. Older binaries cannot talk to newer ones; the contract records this as an incompatible peer protocol version.

**Conformance:**
- `peer_messaging.py` keeps its behavioral checks.
- Its raw-wire fixtures use OpenSSL over TCP, and Python's standard library has no QUIC. A small Go probe built for the suite replaces them; it covers unknown keys, wrong pins, a handshake signed by another key, and malformed requests.
- `coordination.py` and the adapter suites need no transport-specific changes.

## Milestone 3b: relays inside capsule-coord

The coordinator gains a relay listener. The network map names it with an address, a public key (the coordinator's own key), and the networks it serves. A member host keeps one persistent registration connection to its network's relay.

**Carrier, recommended:** framed peer QUIC packets over the coordinator's TLS-over-TCP listener, as Tailscale's DERP does with WireGuard packets.
- Each frame holds a destination or source host ID and one QUIC packet.
- The relay forwards a frame only if both hosts are verified members of a network it serves.
- It only ever sees QUIC packets that the end-to-end peer connection has already encrypted. It cannot read, alter undetected, or impersonate either side, because the peer TLS pins still apply end to end.
- TCP reaches hosts on networks that block UDP, which is exactly when a relay is needed.
- TCP avoids nesting QUIC packets inside QUIC datagrams with a smaller payload.
- It costs head-of-line blocking on the relayed path only.

**Host side:**
- Each daemon gives its QUIC endpoint a combined socket: real UDP for direct addresses and a virtual packet path through the relay connection for relayed peers. Go `quic-go` accepts a custom `net.PacketConn`, and Rust `quinn` accepts a custom `AsyncUdpSocket`.
- A relayed peer appears to the QUIC endpoint as a synthetic address keyed by host ID.
- The dialer first tries the advertised direct address with a short timeout and falls back to the relay. A host with no reachable address advertises `""` and is reachable only by relay.

**Relay access control:**
- The relay authenticates registering hosts by TLS client key, as the coordinator API does.
- It forwards only between members of a common network it serves, using the membership it already stores.
- It cannot add members. Hosts still verify every peer chain themselves, so a relay that forwards for a non-member only delivers packets that fail the peer handshake.
- It applies per-host rate and byte limits.

**Conformance:** `relay.py` will check that two hosts with no direct addresses exchange messages and replies through the relay in every Go/Rust pairing. It will also check:
- a non-member cannot register or send;
- a relay cannot complete a peer handshake as another host;
- relay restart and reconnection;
- falling back from a dead direct address.

## Milestone 4: direct paths through NAT

This builds on 3a and 3b:
- **Reflexive addresses:** the relay learns each host's public UDP mapping from a UDP probe on the host's peer socket and returns it, much as STUN does. The coordinator publishes these as additional candidates in the map.
- **Simultaneous attempt:** coordinated through the relay connection. Both sides send to each other's candidates from their peer socket.
- **Migration:** a successful probe moves the existing peer QUIC connection off the relay by path migration. Relays remain the guaranteed fallback.

The exact candidate format, probe timing, and how long the relay path is retained are left to that milestone.

## Decisions to settle

| Decision | Recommendation | Alternative |
| --- | --- | --- |
| Application protocol over QUIC | HTTP/1.1, one request per bidirectional stream, ALPN `capsule-peer/1` | HTTP/3 (`quic-go/http3`, Rust `h3` 0.0.x) |
| Relay carrier | Framed QUIC packets over TLS/TCP (DERP-style) | QUIC datagrams over a QUIC connection to the relay; this cannot reach UDP-blocked hosts and needs a smaller inner MTU |
| Cutover | Hard switch, incompatible peer protocol version | Serve TCP and QUIC side by side for one release |
| Coordinator API | Stays on HTTPS/TCP | Also move to QUIC |
| New dependencies | Go `github.com/quic-go/quic-go`; Rust `quinn` with its `rustls` integration | — |

## Delivery

The work ships as three PRs, each a working slice with both host implementations and shared conformance:
1. QUIC direct transport (3a).
2. Relays in `capsule-coord` (3b).
3. Reflexive addresses, hole punching, and migration (4).

Each PR updates the peer-messaging and coordination contracts for the behavior it adds.
