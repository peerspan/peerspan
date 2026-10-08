# Implementation instructions

The Go and Rust host services develop together in this repository, in `go/` and `rust/`. Shared specifications are in `docs/`; shared binary tests and build measurements are in `conformance/`. The broader architecture is maintained in the `mesh-new` design repository. Which implementation to release as OSS remains open.

The earlier prototype lives in `legacy/` with its own Go module. Do not extend its combined control-plane and execution model for the new host service.

Coordination remains outside the collaboration data path. Hosts enforce permissions and own execution and local state. Agent identities are distinct from sessions. Membership, ownership, and access are separate.

The administration API is owner-local over a private Unix socket. The opt-in peer API has a separate router and authenticates host keys over mutual TLS; never expose local administration through it. Peers receive only explicitly granted message access. Owner labels, capabilities, and registry attachments do not establish network authority or integration readiness.

Maintain behavior parity without mechanically translating module structure between languages. Implement working slices rather than empty packages. Record shared external behavior in `docs/host-service-contract.md`; record broader product decisions in the system design.

## Tests

Tests come from the specification, not from an implementation. Agent-written tests that restate an implementation add cost without catching errors.

- **No new unit tests by default.** Implementers do not add unit or integration tests unless the contract or the owner asks for a specific one. Existing tests stay, and implementers keep running them.
- **Conformance cases come from the contract.** Each contract's Verification section lists the cases, settled with the owner along with the rest of the spec. Write concrete cases there when intent is subtle.
- **A separate author writes each new suite.** The suite's author works from the contract alone, never from either implementation, and is neither implementer. Ambiguities go back to the contract, not into one implementation's choices.
- **End-to-end checks stay.** Live runs and installed-bundle checks are separate from this rule.

From the repository root, run the appropriate language checks:

- Go: `go -C go test -race ./internal/... ./cmd/...` and `go -C go vet ./internal/... ./cmd/...`. This covers the host daemon, the `capsule-coord` coordinator, the `capsule-peer-probe` test client, and their shared `membership` and `tlsid` packages.
- Rust: `cargo fmt --check --manifest-path rust/Cargo.toml`, `cargo test --locked --manifest-path rust/Cargo.toml`, and `cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings`.

Build both binaries and run the appropriate shared conformance suites when external behavior changes. Peer changes require `conformance/peer_messaging.py` across all Go/Rust pairings, with `--probe` pointing at a built `capsule-peer-probe`; enrollment and coordination changes require `conformance/coordination.py`, `conformance/revocation.py`, `conformance/persons.py`, `conformance/admins.py`, and `conformance/policy.py` (the last three need OpenSSH: `ssh-agent`, `ssh-add`, `ssh-keygen`) with the Go coordinator across all creator/joiner pairings; policy propagation changes (sibling pushes and syncs, the acceptance rule, the delivery queue, or `access sync`) also require `conformance/policy_sync.py` (also with `--probe` and OpenSSH) with the Go coordinator across all Go/Rust combinations of the owner's two hosts; peer or coordination changes also require `conformance/relay.py` across all pairings, and `conformance/nat_lab.py` (needs root for network namespaces) where root is available; outbound send or retry changes require `conformance/send_retry.py` across all pairings; task changes (task peer routes, task adapter routes and MCP tools, grant/policy/route actions, or task persistence) require `conformance/tasks.py` across all Go/Rust pairings, with `--probe`, the Go coordinator, and `--node` for the MCP cases (its policy cases need OpenSSH); artifact changes (manifests, artifact peer and adapter routes, transfer, quota, retention, `max_artifact_bytes`, or artifact persistence) also require `conformance/artifacts.py` with the same arguments; delegation chain changes (links, chain verification, `task.delegate`, forwarding, propagated cancellation, or the originator fields in MCP meta) also require `conformance/delegation.py` with the same arguments, across its default Go/Rust mixes that put each implementation in every chain position; local changes require `conformance/host_service.py`. The earlier prototype's namespace and Firecracker tests have separate execution requirements.

Session-adapter changes require `conformance/agent_adapter.py` (also with `--probe`), `conformance/adapter_outbound.py`, and `conformance/adapter_recovery.py` across all Go/Rust pairings, with the Node adapter and Go coordinator. Live Claude experiments are separate from deterministic conformance; record model-observed behavior and limitations without claiming model execution from notification acknowledgments alone.

CLI shape, expiry, credential renewal, or status changes (help, network defaulting, `--expires-in` and defaults, renewable credentials and following routes, or `GET /v1/status` and `status`) require `conformance/launch_cli.py` across all Go/Rust CLI/daemon pairings, with `--probe` and the Go coordinator; packaging changes require `conformance/installed_bundle.py` for both implementations (it needs Python 3.12 or newer).

Integration setup or diagnostic changes also require `conformance/claude_setup.py` and `conformance/harness_setup.py` across all Go/Rust CLI/daemon pairings. The latter tests a non-Claude integration with Node absent from PATH, optional launch, and cross-CLI profile/recovery behavior. Claude checks use an explicit executable fixture and real MCP consumers; live model checks use `conformance/live_cross_host_agents.py --setup-flow` separately.
