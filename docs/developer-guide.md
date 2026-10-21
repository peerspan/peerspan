# Developer guide

This is the source-checkout path. For the user path, follow the [quick start](quick-start.md). Both hosts implement one external contract; use separate state directories when running them side by side.

## Build the hosts and coordinator

From the repository root:

```sh
cargo build --locked --manifest-path rust/Cargo.toml
go -C go build -o /tmp/peerspan-host-go ./cmd/peerspan-host
go -C go build -o /tmp/peerspan-coord ./cmd/peerspan-coord
go -C go build -o /tmp/peerspan-peer-probe ./cmd/peerspan-peer-probe
```

`peerspan-coord` serves both host implementations. The peer probe is a conformance fixture, not a deployment binary. The [architecture map](architecture-onboarding.md) identifies the daemon, CLI, storage, transport, and adapter entry points.

## Package both release choices

```sh
scripts/package-release.sh rust VERSION
scripts/package-release.sh go VERSION
```

The script currently packages native Linux builds, bundles pinned Node integrations, and writes an archive plus checksum under `dist/`. It requires Node.js 22 or later. The Rust bundle records the builder's glibc baseline in `RELEASE.json`. The [quick start](quick-start.md) describes installing a bundle; the [installed-bundle check](../conformance/installed_bundle.py) exercises its contents.

## Verify a change

The [implementation instructions](../AGENTS.md) map each changed contract or CLI surface to its required checks. The common language checks are:

```sh
go -C go test -race ./internal/... ./cmd/...
go -C go vet ./internal/... ./cmd/...
cargo fmt --check --manifest-path rust/Cargo.toml
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
```

Shared [conformance suites](../conformance/) run the Go and Rust binaries in every relevant pairing. Changes to the documented launch path also require `conformance/launch_acceptance.py`, which packages both implementations and runs clean-user solo, pair, and team paths. Its environment requirements are in [AGENTS.md](../AGENTS.md). Recorded acceptance is in [launch-acceptance.json](results/launch-acceptance.json).

## Explore a subsystem

- [Manual agent testing](manual-agent-testing.md) covers explicit sessions, routes, and local fixtures.
- [Coordination contract](coordination-contract.md) and [peer messaging contract](peer-messaging-contract.md) explain enrollment and transport.
- [Connectivity evaluation](connectivity-evaluation.md) explains the controlled network benchmarks and their limits.
- [Build timing script](../conformance/build_timings.py) and [peer transport benchmark](../conformance/peer_transport_bench.py) provide reproducible measurements.

The [earlier prototype](../legacy/README.md) has its own Go module and test requirements. It is historical code, separate from the current hosts.
