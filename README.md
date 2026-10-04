# Rust agent host service

This is the Rust implementation of the agent host service, developed alongside the Go implementation in `capsule`. `capsule-rs` is a provisional repository name. Both follow the shared design and conformance suite in `mesh-new`; the implementation to release as OSS remains undecided.

## Run the foundation

The service owns a durable local identity, registered agents, session attachment records, and a transactional activity log. It starts without coordination. Owner-local administration uses HTTP over a private Unix socket. The current implementation requires Unix; validation has been run on Linux.

```bash
cargo build --locked
./target/debug/capsule-host --state /tmp/capsule-rust-state serve
```

From another terminal:

```bash
./target/debug/capsule-host --state /tmp/capsule-rust-state info
./target/debug/capsule-host --state /tmp/capsule-rust-state agent register --name bob --owner bob --capability conversation
./target/debug/capsule-host --state /tmp/capsule-rust-state agent list
./target/debug/capsule-host --state /tmp/capsule-rust-state session attach --agent AGENT_ID --integration test
./target/debug/capsule-host --state /tmp/capsule-rust-state session list
./target/debug/capsule-host --state /tmp/capsule-rust-state activity
```

Without `--state`, state lives in `$XDG_STATE_HOME/capsule/host` or `$HOME/.local/state/capsule/host`. Use separate explicit directories when running both implementations. An existing state directory must have private permissions (0700).

Agent identity survives restarts. Session attachments become detached on restart and remain inspectable. An attachment is registry metadata only: this milestone does not operate a live Claude Code session or launch a process. Capability names and owner labels are metadata, not access grants or verified network identities. Peer networking, scoped sharing, the three collaboration operations, and runtime execution are subsequent milestones.

## Source structure

```text
src/main.rs     Executable, owner-local client, and daemon lifecycle
src/model.rs    Agent, session, identity, and activity records
src/store.rs    Private local persistence and transactional registry operations
src/api.rs      Owner-local HTTP administration
tests/store.rs  Persistence and filesystem boundary checks
```

There are no empty modules for future networking or runtime features. The SQLite connection runs on blocking workers rather than the async executor. Private state files and an exclusive process lock protect local installation state; peer authentication is a separate future concern.

## Verify

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 ../mesh-new/conformance/host_service.py --rust ./target/debug/capsule-host
```

The shared suite checks the running binary, including crash recovery, process exclusivity, concurrent duplicate registration, and atomic activity recording. Build the Go binary to run the suite with both `--go` and `--rust`. `mesh-new/docs/host-service-contract.md` defines the initial common behavior.

The Cargo lockfile is tracked for reproducible dependency resolution. Build timings can be compared with `mesh-new/conformance/build_timings.py`, which uses disposable source copies and isolated caches.
