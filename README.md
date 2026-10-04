# Capsule agent host daemon

Capsule connects agents across developer-owned machines, with task delegation, peer conversations, and remote tools/resources as the collaboration goals. Go and Rust implementations develop together in this repository against one architecture and external contract. Which implementation to release as OSS remains open.

## Repository structure

```text
capsule/
├── go/             Go host daemon and module
├── rust/           Rust host daemon and crate
├── docs/           Shared contracts and implementation proposals
├── conformance/    Common binary checks and build measurements
└── legacy/         Earlier prototype, retained separately
```

Each implementation has its own dependency manifest and lock/checksum files. The shared contract and tests change alongside the implementations. The broader system design remains in the `mesh-new` design repository.

## First working milestone

Both host daemons provide a durable local identity, registered agents, separate session attachment records, and a transactional activity log. They start without coordination and expose owner-local administration over a private Unix socket.

The [shared contract](docs/host-service-contract.md) defines the common behavior. An attachment is registry metadata only: this milestone does not operate an existing Claude Code session or launch agent processes. Capability names and owner labels are metadata, not access grants or verified network identities. Peer networking, scoped sharing, the three collaboration operations, and runtime execution are subsequent milestones.

The next slice is described in the [peer messaging proposal](docs/peer-messaging-proposal.md), with a separate [existing-agent integration investigation](docs/agent-integration-investigation.md). These documents describe proposed work; peer messaging is not implemented yet.

## Build and run

From the repository root:

```bash
go -C go build -o /tmp/capsule-host-go ./cmd/capsule-host
cargo build --locked --manifest-path rust/Cargo.toml
```

Run each daemon in its own terminal with a separate state directory:

```bash
/tmp/capsule-host-go --state /tmp/capsule-go-state run
./rust/target/debug/capsule-host --state /tmp/capsule-rust-state run
```

`run` starts the daemon in the foreground; `serve` remains a compatibility alias. The private `admin.sock` socket is its local control interface, used by the CLI. Coordination and peer communication will use separate interfaces.

Both expose the same commands:

```bash
/tmp/capsule-host-go --state /tmp/capsule-go-state info
/tmp/capsule-host-go --state /tmp/capsule-go-state agent register --name bob --owner bob --capability conversation
/tmp/capsule-host-go --state /tmp/capsule-go-state agent list
/tmp/capsule-host-go --state /tmp/capsule-go-state session attach --agent AGENT_ID --integration test
/tmp/capsule-host-go --state /tmp/capsule-go-state session list
/tmp/capsule-host-go --state /tmp/capsule-go-state activity
```

Use the Rust binary and its state directory for the same commands. Without `--state`, both default to `$XDG_STATE_HOME/capsule/host` or `$HOME/.local/state/capsule/host`. Existing state directories must be private (0700). Agent identities survive restarts; previous session attachments become detached and remain inspectable.

See the [Go guide](go/README.md) and [Rust guide](rust/README.md) for implementation details. Current implementations require Unix; validation has been run on Linux.

## Verify both implementations

```bash
go -C go test -race ./internal/host ./cmd/capsule-host
go -C go vet ./internal/host ./cmd/capsule-host
cargo fmt --check --manifest-path rust/Cargo.toml
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
python3 conformance/host_service.py --go /tmp/capsule-host-go --rust rust/target/debug/capsule-host
```

The shared suite checks the running binaries, including crash recovery, process exclusivity, concurrent duplicate registration, and atomic activity recording. It uses temporary state directories.

## Compare build times

```bash
python3 conformance/build_timings.py --go-repo go --rust-repo rust --output /tmp/capsule-build-timings.json
```

This uses disposable source copies and isolated build caches, with dependencies already downloaded. The [initial measurements](conformance/results/host-foundation-linux.json) compare this small implementation milestone, dependency choices, and compiler profiles rather than language performance in general.

## Earlier prototype

[legacy/README.md](legacy/README.md) documents the earlier prototype. It has its own Go module and separate namespace/Firecracker test requirements. Its combined coordination and execution model is not the foundation for the new host daemon.
