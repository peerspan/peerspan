# Rust agent host daemon

This directory contains Peerspan’s host daemon. It follows the [shared contract](../docs/host-service-contract.md) and the repository-level conformance suites. The Go implementation is maintained separately at [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go). The commands below run from this directory.

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

Without `--state`, state lives in `$XDG_STATE_HOME/peerspan/host` or `$HOME/.local/state/peerspan/host`. Use separate explicit directories when running several hosts on one machine. An existing state directory must have private permissions (0700).

Agent identity survives restarts. Session attachments become detached on restart and remain inspectable; the original running adapter can recover its bound attachment under a new connection lease. An attachment is registry metadata; the shared [Claude channel adapter](../integrations/claude-channel/README.md) connects an explicitly opted-in session, including scoped outbound sends and automatic replies. Hosts do not launch agent processes. Capability names and owner labels are metadata, not access grants or verified network identities. Known-host TLS messaging and inbound grants are specified in the [peer contract](../docs/peer-messaging-contract.md). Networks are coordinator-free ([spec](../docs/decentralized-spec.md)); the earlier [coordination contract](../docs/coordination-contract.md) describes the retired coordinator-based enrollment. Membership revocation, the full collaboration operations, and runtime execution remain subsequent milestones.

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
```

Black-box behaviour is checked by the [slim conformance suites](../conformance/slim/), which CI runs; see the [developer guide](../docs/developer-guide.md). `docs/host-service-contract.md` defines the initial common behavior; the peer and coordination contracts extend it.

The Cargo lockfile is tracked for reproducible dependency resolution.
