# Rust agent host daemon

This directory contains the Rust implementation of Peerspan’s host daemon, developed alongside the [Go implementation](../go/README.md). Both follow the [shared contract](../docs/host-service-contract.md) and repository-level conformance suite; the implementation to release as OSS remains undecided. The commands below run from this directory.

## Run the foundation

The daemon owns a durable local identity, registered agents, session attachment records, and a transactional activity log. It can start with no coordinator configured. Owner-local administration uses HTTP over a private Unix socket. The current implementation requires Unix; validation has been run on Linux.

```bash
cargo build --locked
./target/debug/peerspan-host --state /tmp/peerspan-rust-state run
```

From another terminal:

```bash
./target/debug/peerspan-host --state /tmp/peerspan-rust-state info
./target/debug/peerspan-host --state /tmp/peerspan-rust-state agent register --name bob --owner bob --capability conversation
./target/debug/peerspan-host --state /tmp/peerspan-rust-state agent list
./target/debug/peerspan-host --state /tmp/peerspan-rust-state session attach --agent AGENT_ID --integration test
./target/debug/peerspan-host --state /tmp/peerspan-rust-state session list
./target/debug/peerspan-host --state /tmp/peerspan-rust-state activity
```

Without `--state`, state lives in `$XDG_STATE_HOME/peerspan/host` or `$HOME/.local/state/peerspan/host`. Use separate explicit directories when running both implementations. An existing state directory must have private permissions (0700).

Agent identity survives restarts. Session attachments become detached on restart and remain inspectable; the original running adapter can recover its bound attachment under a new connection lease. An attachment is registry metadata; the shared [Claude channel adapter](../integrations/claude-channel/README.md) connects an explicitly opted-in session, including scoped outbound sends and automatic replies. Hosts do not launch agent processes. Capability names and owner labels are metadata, not access grants or verified network identities. Known-host TLS messaging and inbound grants are specified in the [peer contract](../docs/peer-messaging-contract.md). Signed enrollment is specified in the [coordination contract](../docs/coordination-contract.md); the coordinator itself is the Go `peerspan-coord` binary. Membership revocation, the full collaboration operations, and runtime execution remain subsequent milestones.

## Source structure

```text
src/main.rs        Executable, owner-local client, and daemon lifecycle
src/cli.rs         Clap command definitions and local request construction
src/model.rs       Agent, session, identity, and activity records
src/store.rs       Private local persistence, schema migration, and registry operations
src/api.rs         Owner-local HTTP administration
src/peer.rs        TLS identity pins, peer transport, and message interfaces
src/peer_store.rs  Persisted peers, grants, requests, and receipts
src/membership.rs  Signed invites, memberships, and tokens
src/network.rs     Coordination client, member map, and network administration
src/adapter.rs     Session credentials, incoming handoff, and final replies
src/adapter_outbound.rs  Owner-defined destinations and automatic session replies
src/adapter_connection.rs  Instance binding, leases, recovery, and token rotation
tests/store.rs     Persistence and filesystem boundary checks
tests/cli.rs       CLI parsing checks
```

There are no empty modules for future runtime features. The SQLite connection runs on blocking workers rather than the async executor. Private state files and an exclusive process lock protect local installation state. Peer authentication and receiver-owned message grants use the separate TLS interface. Verified network membership comes from the coordination client. Agent authentication and delegation provenance remain future work.

## Verify

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 ../conformance/host_service.py --rust ./target/debug/peerspan-host
```

`host_service.py` checks the running binary, including crash recovery, process exclusivity, concurrent duplicate registration, and atomic activity recording. Peer and enrollment checks need the Go binaries as well: `peer_messaging.py` and `coordination.py` from the repository root. `docs/host-service-contract.md` defines the initial common behavior; the peer and coordination contracts extend it.

The Cargo lockfile is tracked for reproducible dependency resolution. Build timings can be compared with `conformance/build_timings.py` at the repository root, which uses disposable source copies and isolated caches.
