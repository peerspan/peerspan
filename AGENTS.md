# Implementation instructions

The Go and Rust host services develop together in this repository, in `go/` and `rust/`. Shared specifications are in `docs/`; shared binary tests and build measurements are in `conformance/`. The broader architecture is maintained in the `mesh-new` design repository. Which implementation to release as OSS remains open.

The earlier prototype lives in `legacy/` with its own Go module. Do not extend its combined control-plane and execution model for the new host service.

Coordination remains outside the collaboration data path. Hosts enforce permissions and own execution and local state. Agent identities are distinct from sessions. Membership, ownership, and access are separate.

The current API is owner-local administration over a private Unix socket. Do not expose it as an authenticated peer API. Owner labels, capabilities, and registry attachments do not establish network authority or integration readiness.

Maintain behavior parity without mechanically translating module structure between languages. Implement working slices rather than empty packages. Record shared external behavior in `docs/host-service-contract.md`; record broader product decisions in the system design.

From the repository root, run the appropriate language checks:

- Go: `go -C go test -race ./internal/host ./cmd/capsule-host` and `go -C go vet ./internal/host ./cmd/capsule-host`.
- Rust: `cargo fmt --check --manifest-path rust/Cargo.toml`, `cargo test --locked --manifest-path rust/Cargo.toml`, and `cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings`.

Build both binaries and run the shared conformance suite when external behavior changes. The earlier prototype's namespace and Firecracker tests have separate execution requirements.
