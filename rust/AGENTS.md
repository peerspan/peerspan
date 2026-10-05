# Implementation instructions

This directory contains the Rust host service, developed alongside the Go implementation in `../go`. The implementation to release as OSS is undecided.

Shared external behavior and conformance tests live in this repository’s `docs/` and `conformance/` directories. The broader architecture lives in the `mesh-new` design repository. Maintain behavior parity without mechanically translating Go module structure into Rust. Record protocol and product decisions in the shared design.

Coordination remains outside the data path. Hosts own execution, local state, and permission enforcement. Agent identity is distinct from sessions. Membership, ownership, and access are separate.

Administration uses a private Unix socket; the opt-in peer API uses a separate mutual TLS router. Never serve the administration router on the peer listener. Unknown identity keys and absent grants must fail closed. Owner labels, capability names, and session attachment records do not establish network authority or integration readiness.

Implement working slices rather than empty modules. SQLite operations belong on blocking workers. Keep the Cargo lockfile tracked, and avoid adding dependencies without a concrete need.

Use Clap with typed commands and arguments for the Rust CLI. Keep parsing separate from daemon lifecycle and local request execution. Preserve the shared command contract when extending the CLI.

Run `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --locked --all-targets -- -D warnings`. When external behavior changes, run the shared suite that covers it: `conformance/host_service.py` for local administration, `conformance/peer_messaging.py` for peer transport, and `conformance/coordination.py` with the Go `capsule-coord` binary for enrollment. Rust has no coordinator binary.
