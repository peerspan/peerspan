# Implementation instructions

The active work is the Go host service in `cmd/capsule-host` and `internal/host`. The earlier prototype in `cmd/capsule` and the other `internal` packages is retained separately. Do not extend its combined control-plane and execution model for the new host service.

Develop the Go and Rust implementations against the same design and external contract. Shared specifications and conformance tests live in the `mesh-new` repository. `capsule-rs` is the provisional sibling Rust implementation; its internal storage and module organization need not dictate this implementation's layout.

Coordination remains outside the collaboration data path. Hosts enforce permissions and own execution and local state. Agent identities are distinct from sessions. Membership, ownership, and access are separate.

The current API is owner-local administration over a private Unix socket. Do not expose it as an authenticated peer API. Owner labels, capabilities, and registry attachments do not establish network authority or integration readiness.

Implement working slices rather than empty packages for future modules. New protocol and product decisions should be recorded in the shared design rather than inferred from a language choice.

For host-service changes, run `go test -race ./internal/host ./cmd/capsule-host`, `go vet ./internal/host ./cmd/capsule-host`, and the shared binary conformance suite when the external behavior changes. The old prototype's namespace and Firecracker tests have separate execution requirements.
