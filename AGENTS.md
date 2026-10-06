# Implementation instructions

The Go and Rust host services develop together in this repository, in `go/` and `rust/`. Shared specifications are in `docs/`; shared binary tests and build measurements are in `conformance/`. The broader architecture is maintained in the `mesh-new` design repository. Which implementation to release as OSS remains open.

The earlier prototype lives in `legacy/` with its own Go module. Do not extend its combined control-plane and execution model for the new host service.

Coordination remains outside the collaboration data path. Hosts enforce permissions and own execution and local state. Agent identities are distinct from sessions. Membership, ownership, and access are separate.

The administration API is owner-local over a private Unix socket. The opt-in peer API has a separate router and authenticates host keys over mutual TLS; never expose local administration through it. Peers receive only explicitly granted message access. Owner labels, capabilities, and registry attachments do not establish network authority or integration readiness.

Maintain behavior parity without mechanically translating module structure between languages. Implement working slices rather than empty packages. Record shared external behavior in `docs/host-service-contract.md`; record broader product decisions in the system design.

From the repository root, run the appropriate language checks:

- Go: `go -C go test -race ./internal/... ./cmd/...` and `go -C go vet ./internal/... ./cmd/...`. This covers the host daemon, the `capsule-coord` coordinator, the `capsule-peer-probe` test client, and their shared `membership` and `tlsid` packages.
- Rust: `cargo fmt --check --manifest-path rust/Cargo.toml`, `cargo test --locked --manifest-path rust/Cargo.toml`, and `cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings`.

Build both binaries and run the appropriate shared conformance suites when external behavior changes. Peer changes require `conformance/peer_messaging.py` across all Go/Rust pairings, with `--probe` pointing at a built `capsule-peer-probe`; enrollment and coordination changes require `conformance/coordination.py` and `conformance/revocation.py` with the Go coordinator across all creator/joiner pairings; peer or coordination changes also require `conformance/relay.py` across all pairings, and `conformance/nat_lab.py` (needs root for network namespaces) where root is available; local changes require `conformance/host_service.py`. The earlier prototype's namespace and Firecracker tests have separate execution requirements.

Session-adapter changes require `conformance/agent_adapter.py` (also with `--probe`), `conformance/adapter_outbound.py`, and `conformance/adapter_recovery.py` across all Go/Rust pairings, with the Node adapter and Go coordinator. Live Claude experiments are separate from deterministic conformance; record model-observed behavior and limitations without claiming model execution from notification acknowledgments alone.
