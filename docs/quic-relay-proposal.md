# QUIC peer transport and relays

Status: proposal for review, covering roadmap milestones 3 and 4 ([roadmap](production-roadmap.md)). Agreed on 2026-10-06:
- the peer transport moves to QUIC before relays are built;
- the relay runs inside `capsule-coord`;
- only network members may use it.

Everything else here is proposed. The decisions to settle before implementation are listed under [Decisions to settle](#decisions-to-settle).

## How this design was reached

The project started from a WireGuard- or Tailscale-like connectivity model. QUIC came in later, so the path from one to the other is recorded here.

1. **The original design was WireGuard.** The issue 7 design in `mesh-new` (commit `087cd42`, 2026-10-02) recorded as decided "the same split of roles as a WireGuard mesh with a coordination server". It was to be built from scratch, with no `tsnet` and no Headscale. It proposed WireGuard as the tunnel between dataplanes, and a relay that "forwards ciphertext addressed by public key and cannot read it". It left one question open: does a session need live IP reachability between capsules, or only messages and artifacts? If only messages and artifacts, a relay with pinned keys would be enough, and the direct-path and hole-punching steps could wait.
2. **The design reset removed it.** The later reset (`mesh-new` commit `6a068af`) replaced that document. The current `design.md` treats Tailscale only as a reference for separating coordination from locally enforced peer communication, and says the reference "does not commit this project to Tailscale code, WireGuard, or any specific provider". Peer transport, trust, and relay operation became open decisions again.
3. **The first peer slice went application-level.** The known-host messaging work (#13) chose HTTP/1.1 over mutually authenticated TLS 1.3 over TCP, with hosts pinned by their Ed25519 key and grants enforced on every request. That answered the open question for the current product: what crosses hosts is authorized messages, receipts, and replies, not IP packets.
4. **The roadmap followed from that.** It described relays as a TCP splice carrying the end-to-end peer TLS, and noted that NAT traversal would need a UDP transport such as QUIC. It left that transport decision for the NAT milestone.
5. **The relay questions settled it.** For the relay carrier, the options were a TCP splice of the existing peer TLS (recommended) or moving the peer transport to QUIC now. The decision was to move to QUIC now. It avoids building a TCP relay and then reworking it for UDP hole punching. This proposal builds on that choice.

## Relation to WireGuard and Tailscale

At the architecture level the design remains Tailscale-like. QUIC takes the place WireGuard holds in Tailscale:

| Tailscale | This proposal |
| --- | --- |
| WireGuard node key, distributed by the control server | Ed25519 host key, distributed by `capsule-coord` and verified by every host through the signed membership chain |
| WireGuard tunnel over UDP | QUIC with mutual TLS 1.3 over UDP |
| DERP relays forwarding already-encrypted WireGuard packets by key, over TCP/HTTPS | A relay in `capsule-coord` forwarding already-encrypted QUIC packets by host ID, over TCP/TLS |
| Disco messages and hole punching, then a path upgrade | Relay-observed addresses and hole punching, then QUIC connection migration |
| Packet filter, plus application capabilities read through `WhoIs` | Grants enforced per request by the receiving daemon |

The difference is the layer the transport provides. WireGuard provides an IP tunnel: peers become reachable at IP addresses. The daemons would still need their own authenticated application protocol on top to enforce grants and return receipts. QUIC provides an authenticated, encrypted, multiplexed connection directly between the daemons, with no IP network in between. That matches what the host service exchanges today.

## Why QUIC fits now, and when WireGuard would

QUIC fits the current message-level product for three reasons:
- **No privileges or network stack.** A WireGuard tunnel needs either a kernel interface, which requires root, or a userspace network stack inside the daemon to carry TCP or HTTP: `wireguard-go` with gVisor's netstack in Go, or `boringtun` with a stack such as `smoltcp` in Rust. QUIC runs as an ordinary userspace UDP socket in both implementations.
- **Identity carries over.** QUIC uses TLS 1.3, so it reuses the existing Ed25519 host certificates, key pinning, and verifier code in both languages. WireGuard uses Curve25519 static keys. That needs either a second key per host, bound to the host key, or a conversion between the two key types. The TLS layer would also stay on top for per-request authorization.
- **Connection migration.** QUIC can move an established connection from a relayed path to a direct one without a new handshake or new application state. WireGuard roams between endpoints too, but anything carried inside the tunnel would still need its own connection management.

WireGuard becomes the better fit if capsules need **IP reachability**. Examples are a Firecracker guest that must reach a service on another host by address, or arbitrary TCP and UDP traffic between runtimes. That is the question the original design left open. The three collaboration capabilities do not require it: task delegation, peer conversations, and remote tools and resources can all run as authorized requests between daemons. If IP reachability becomes a near-term requirement, WireGuard should be reconsidered before the transport is built. The choice is then between a userspace WireGuard tunnel carrying the existing HTTP/TLS peer protocol, and QUIC. A WireGuard tunnel could also be added later beside QUIC for runtime networking, without replacing the message transport.

The transport choice, and the condition under which it would change, should also be recorded as a product decision in the `mesh-new` system design.

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
| Peer transport | QUIC (agreed 2026-10-06) | Userspace WireGuard tunnel carrying the existing HTTP/TLS protocol. Revisit if capsules need IP reachability; see [Why QUIC fits now, and when WireGuard would](#why-quic-fits-now-and-when-wireguard-would) |
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
