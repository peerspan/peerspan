# Capsule agent host daemon

Capsule connects agents across developer-owned machines, with task delegation, peer conversations, and remote tools/resources as the collaboration goals. Go and Rust implementations develop together in this repository against one architecture and external contract. Which implementation to release as OSS remains open.

## Repository structure

```text
capsule/
├── go/              Go host daemon, coordinator, and module
├── rust/            Rust host daemon and crate
├── integrations/    Shared adapters for existing agent sessions
├── docs/            Shared contracts and implementation proposals
├── conformance/     Common binary checks and build measurements
└── legacy/          Earlier prototype, retained separately
```

Each implementation has its own dependency manifest and lock/checksum files. The shared contract and tests change alongside the implementations. The broader system design remains in the `mesh-new` design repository.

## Implemented behavior

Both host daemons provide a durable local identity, registered agents, separate session attachment records, and a transactional activity log. They start without coordination and expose owner-local administration over a private Unix socket.

The [shared contract](docs/host-service-contract.md) defines the common behavior. An attachment is registry metadata; an opted-in Claude Code session can receive messages and reply through a scoped adapter, but hosts do not launch agent processes. Capability names and owner labels are metadata, not access grants or verified network identities. Known hosts can now exchange agent-addressed messages over QUIC with mutually authenticated TLS, using receiver-owned grants and durable receipts. Hosts can also enroll in a network through signed invites and a separate `capsule-coord` coordination service. Every host verifies membership itself, so coordination can withhold members but cannot add them ([coordination contract](docs/coordination-contract.md)). The coordinator also relays already-encrypted peer QUIC packets between members, so hosts without a reachable address can still exchange messages. The three full collaboration operations, membership revocation, NAT traversal, and runtime execution are subsequent milestones; see the [production connectivity roadmap](docs/production-roadmap.md).

The [known-host messaging contract](docs/peer-messaging-contract.md) specifies the peer transport slice. The [peer messaging proposal](docs/peer-messaging-proposal.md) records its broader direction, and the [existing-agent integration investigation](docs/agent-integration-investigation.md) describes the next delivery experiment.

## Build and run

From the repository root:

```bash
go -C go build -o /tmp/capsule-host-go ./cmd/capsule-host
go -C go build -o /tmp/capsule-coord ./cmd/capsule-coord
go -C go build -o /tmp/capsule-peer-probe ./cmd/capsule-peer-probe
cargo build --locked --manifest-path rust/Cargo.toml
```

`capsule-coord` is the coordination service. It is a separate Go binary used by both host implementations. `capsule-peer-probe` is a test client the conformance suites use for raw peer requests; it is not part of a deployment.

Run each daemon in its own terminal with a separate state directory:

```bash
/tmp/capsule-host-go --state /tmp/capsule-go-state run
./rust/target/debug/capsule-host --state /tmp/capsule-rust-state run
```

`run` starts the daemon in the foreground; `serve` remains a compatibility alias. The private `admin.sock` socket is its local control interface, used by the CLI. The opt-in peer listener uses its own authenticated router. Coordination is a third interface: the daemon dials `capsule-coord`, and that connection is neither the admin socket nor the peer router.

Both expose the same commands:

```bash
/tmp/capsule-host-go --state /tmp/capsule-go-state info
/tmp/capsule-host-go --state /tmp/capsule-go-state agent register --name bob --owner bob --capability conversation
/tmp/capsule-host-go --state /tmp/capsule-go-state agent list
/tmp/capsule-host-go --state /tmp/capsule-go-state session attach --agent AGENT_ID --integration test
/tmp/capsule-host-go --state /tmp/capsule-go-state session list
/tmp/capsule-host-go --state /tmp/capsule-go-state activity
```

Use the Rust binary and its state directory for the same commands. Without `--state`, both default to `$XDG_STATE_HOME/capsule/host` or `$HOME/.local/state/capsule/host`. Existing state directories must be private (0700). Agent identities survive restarts; previous session attachments become detached and remain inspectable. A bound adapter can recover its original attachment with its live process-instance secret.

See the [Go guide](go/README.md) and [Rust guide](rust/README.md) for implementation details. Current implementations require Unix; validation has been run on Linux.

## Try known-host messaging

Start two daemons with separate state directories and explicit peer addresses (UDP ports; peers speak QUIC):

```bash
/tmp/capsule-host-go --state /tmp/capsule-bob run --peer-listen 127.0.0.1:7401
./rust/target/debug/capsule-host --state /tmp/capsule-alice run --peer-listen 127.0.0.1:7402
```

Read each daemon's `info`, then independently verify and configure the other's `id` and `public_key`. The examples below use placeholders for those values:

```bash
/tmp/capsule-host-go --state /tmp/capsule-bob peer add --id ALICE_HOST_ID --public-key ALICE_PUBLIC_KEY --address 127.0.0.1:7402
./rust/target/debug/capsule-host --state /tmp/capsule-alice peer add --id BOB_HOST_ID --public-key BOB_PUBLIC_KEY --address 127.0.0.1:7401
./rust/target/debug/capsule-host --state /tmp/capsule-alice agent register --name alice --owner alice
./rust/target/debug/capsule-host --state /tmp/capsule-alice grant create --peer BOB_HOST_ID --agent ALICE_AGENT_ID --expires-at FUTURE_RFC3339_TIME --allow-disconnected
/tmp/capsule-host-go --state /tmp/capsule-bob message send --peer ALICE_HOST_ID --grant GRANT_ID --agent ALICE_AGENT_ID --deadline EARLIER_FUTURE_RFC3339_TIME --content "hello"
./rust/target/debug/capsule-host --state /tmp/capsule-alice message list
```

The grant expiration and request deadline must be in the future, with the deadline no later than expiration. Manually configured peers are not network members, so their grants require explicit `--allow-disconnected`. Inspect the send's JSON `state`: `accepted` means durable host storage; `unknown` requires recovery; `rejected` means the peer rejected the attempt. Use `message retry` or `message refresh` with the original request ID. Delivery into an opted-in session uses the scoped adapter described below.

## Connect an existing Claude Code session

The [Claude Code channel](integrations/claude-channel/README.md) connects one opted-in interactive session to either daemon. Owners issue an expiring session credential and define named outbound destinations with byte and lifetime message limits. The adapter uses a separate private `adapter.sock` interface to receive messages, initiate scoped sends, and reply. The daemon automatically retrieves responses to agent-initiated messages and returns them to the originating session. Owner-CLI sends use `message reply`. Unknown handoffs persist without automatic redelivery.

The [adapter contract](docs/agent-adapter-contract.md) and [outbound extension](docs/adapter-outbound-contract.md) define scope, budgets, handoff, reply, and restart behavior. A [live experiment](docs/results/agent-exchange-live.json) verified two running Claude Code sessions initiating messages and observing automatic replies in both directions over Go↔Rust. Full conversations, tasks, remote tools, and host-managed sessions remain subsequent work.

The [recovery extension](docs/adapter-recovery-contract.md) adds connection leases, recovery by the original running adapter after daemon restart, and token rotation that preserves authorization and budgets. `adapter connection ID` distinguishes registered, ready, offline, and withdrawn access. The [live recovery experiment](docs/results/agent-recovery-live.json) restarts each originating daemon and rotates its token while keeping the same two Claude sessions running.

The [cross-host acceptance runner](integrations/claude-channel/README.md#acceptance-on-two-machines) runs the experiment on two SSH targets with signed enrollment, coordinator outage, pending restarts, and grant revocation. Its deterministic MCP mode validates the setup without model calls; real Claude runs record model-observed replies separately.

If an adapter has exited and its lease has expired, the owner can authorize a fresh session through `adapter create` without first detaching the old session. Creation retires the old authorization atomically; its existing work stays bound to its original session. Live leases remain protected, and previously bound, recoverable adapters get a 15-second reconnect window after daemon startup before replacement is allowed.

## Verify both implementations

```bash
go -C go test -race ./internal/... ./cmd/...
go -C go vet ./internal/... ./cmd/...
cargo fmt --check --manifest-path rust/Cargo.toml
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
python3 conformance/host_service.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host
python3 conformance/peer_messaging.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host --probe /tmp/capsule-peer-probe
python3 conformance/coordination.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host --coord /tmp/capsule-coord
python3 conformance/relay.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host --coord /tmp/capsule-coord --probe /tmp/capsule-peer-probe
sudo python3 conformance/nat_lab.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host --coord /tmp/capsule-coord
python3 conformance/agent_adapter.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host --node NODE_BINARY --probe /tmp/capsule-peer-probe
python3 conformance/adapter_outbound.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host --node NODE_BINARY --coord /tmp/capsule-coord
python3 conformance/adapter_recovery.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host --node NODE_BINARY
```

`nat_lab.py` needs root. It builds Linux network namespaces with nftables NAT routers between each host and the coordinator, and runs every Go/Rust pairing behind port-preserving, fully random, and UDP-blocking NATs. It removes everything it creates.

The shared suites use temporary state directories. They check local persistence/migration and all four Go/Rust peer pairings, including authentication, grants, atomic acceptance, retry deduplication, dropped receipts, restart, and revocation. Peer raw-wire fixtures use the `capsule-peer-probe` QUIC test client, and the lost-receipt cases use a UDP proxy.

## Try signed enrollment

Hosts can now discover one another through a network and need no `peer add`. Start a coordinator, read its public key, and start hosts with `--peer-listen`:

```bash
/tmp/capsule-coord --state /tmp/capsule-coord-state run --listen 127.0.0.1:7400
/tmp/capsule-coord --state /tmp/capsule-coord-state info
/tmp/capsule-host-go --state /tmp/capsule-alice network create --name team --member alice --coordinator 127.0.0.1:7400 --coordinator-key COORD_PUBLIC_KEY
/tmp/capsule-host-go --state /tmp/capsule-alice network invite --network NETWORK_ID --member bob --expires-at FUTURE_RFC3339_TIME
./rust/target/debug/capsule-host --state /tmp/capsule-bob network join --token TOKEN
```

The token is a bearer secret, so deliver it out of band. Every host verifies the signed chain from root key to invite to host itself, so the coordinator cannot add hosts. While coordination has synced recently, grants work without `--allow-disconnected`. See the [coordination contract](docs/coordination-contract.md) and the [roadmap](docs/production-roadmap.md).

## Compare build times

```bash
python3 conformance/build_timings.py --go-repo go --rust-repo rust --output /tmp/capsule-build-timings.json
```

This uses disposable source copies and isolated build caches, with dependencies already downloaded. The [initial measurements](conformance/results/host-foundation-linux.json) compare this small implementation milestone, dependency choices, and compiler profiles rather than language performance in general.

## Compare peer transport performance

```bash
go -C go build -o /tmp/capsule-host-go ./cmd/capsule-host
cargo build --release --locked --manifest-path rust/Cargo.toml
python3 conformance/peer_transport_bench.py --go /tmp/capsule-host-go --rust rust/target/release/capsule-host --label "DESCRIPTION" --output /tmp/capsule-peer-bench.json
```

This runs all four Go/Rust pairings over loopback with small and 64 KiB messages. It measures durable sends, a read-only reply lookup that is dominated by the transport, and throughput with concurrent senders. Results compare these implementations and transports on one machine; they do not establish general protocol or language performance. Recorded runs are in `conformance/results/peer-transport-*.json`.

## Earlier prototype

[legacy/README.md](legacy/README.md) documents the earlier prototype. It has its own Go module and separate namespace/Firecracker test requirements. Its combined coordination and execution model is not the foundation for the new host daemon.
