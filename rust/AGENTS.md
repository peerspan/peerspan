# Implementation instructions

This directory contains the Rust host service, developed alongside the Go implementation in `../go`. The implementation to release as OSS is undecided.

Shared external behavior and conformance tests live in this repository’s `docs/` and `conformance/` directories. The broader architecture lives in the `mesh-new` design repository. Maintain behavior parity without mechanically translating Go module structure into Rust. Record protocol and product decisions in the shared design.

Coordination remains outside the data path. Hosts own execution, local state, and permission enforcement. Agent identity is distinct from sessions. Membership, ownership, and access are separate.

The current API is owner-local administration over a private Unix socket. It is not a peer API. Owner labels, capability names, and session attachment records do not establish network authority or integration readiness.

Implement working slices rather than empty modules. SQLite operations belong on blocking workers. Keep the Cargo lockfile tracked, and avoid adding dependencies without a concrete need.

Use Clap with typed commands and arguments for the Rust CLI. Keep parsing separate from daemon lifecycle and local request execution. Preserve the shared command contract when extending the CLI.

Run `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --locked --all-targets -- -D warnings`. Run the shared binary conformance suite when external behavior changes.
