# Implementation instructions

The Rust host service in `rust/` is the only host implementation in this repository ([DEC-OWN5](docs/decision-log.md)). The Go implementation is maintained separately at https://github.com/peerspan/peerspan-go and is not built, tested or packaged here. Shared specifications are in `docs/`; binary tests and build measurements are in `conformance/`. The broader architecture is maintained in the `mesh-new` design repository.

The earlier prototype lives in `legacy/` with its own Go module. Do not extend its combined control-plane and execution model for the new host service.

Coordination remains outside the collaboration data path. Hosts enforce permissions and own execution and local state. Agent identities are distinct from sessions. Membership, ownership, and access are separate.

The administration API is owner-local over a private Unix socket. The opt-in peer API has a separate router and authenticates host keys over mutual TLS; never expose local administration through it. Peers receive only explicitly granted message access. Owner labels, capabilities, and registry attachments do not establish network authority or integration readiness.

Implement working slices rather than empty packages. Record shared external behavior in `docs/host-service-contract.md`; record broader product decisions in the system design.

## Coordinator-free redesign stream

For DEC-01 through DEC-07 only, the owner delegated completion on 2026-10-26.
Choose the recommended options, document each decision, rationale and discarded
alternatives, and continue through concrete contracts, Rust implementation,
independent conformance and reviewed PRs without routine clarification requests.
Reuse the Rust agent and the separate contract-only conformance author.
This delegation is specific to this work stream and does not change other
tracks. Existing authority boundaries and independent-test requirements remain.

## Tests

Tests come from the specification, not from an implementation. Agent-written tests that restate an implementation add cost without catching errors.

- **No new unit tests by default.** Implementers do not add unit or integration tests unless the contract or the owner asks for a specific one. Existing tests stay, and implementers keep running them.
- **Conformance cases come from the contract.** Each contract's Verification section lists the cases, settled with the owner along with the rest of the spec. Write concrete cases there when intent is subtle.
- **A separate author writes each new suite.** The suite's author works from the contract alone, never from the implementation, and is not the implementer. Ambiguities go back to the contract, not into the implementation's choices.
- **End-to-end checks stay.** Live runs and installed-bundle checks are separate from this rule.

From the repository root, run the language checks (CI runs the same):

- `cargo fmt --check --manifest-path rust/Cargo.toml`, `cargo test --locked --manifest-path rust/Cargo.toml`, and `cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings`.

Conformance is the [slim suites](conformance/slim/) ([DEC-OWN6](docs/decision-log.md), DEC-OWN9, DEC-OWN10): one small black-box suite per area, written from the spec by a separate author who never reads the implementation, each under 2 minutes. CI builds `peerspan-host`, `peerspan-peer-probe` and `peerspan-helper` once and runs every suite in parallel (`.github/workflows/conformance.yml`). When external behavior changes, run the suite for that area locally with the debug binaries in one directory, for example `python3 conformance/slim/join.py --bin DIR`:

- `join`: create, invite, join, link, stages and their time limits (spec 6, 8).
- `policy`: allow, deny, block, bans, policy edits and capability claims (spec 5, 12).
- `work`: messages, tasks, delegation chains, agent lookup.
- `renewal`: leases, automatic renewal, retention, root offline, expiry (spec 7); uses the debug-build test clock.
- `sync`: propagation and repair between hosts (spec 10).
- `delivery`: first-contact listener, mailboxes, QUIC completion, the helper and relay (spec 9).
- `root`: root rotation, root split and reinvite (spec 13, 14.2).
- `live`: live delivery (readiness, seen, redelivery, adoption, pending work).
- `capabilities`: sources, sharing, calls, approval, bounds, remote MCP servers and the built-in `gh` source.
- `basics`: info, status, errors, storage and restart (spec 14 to 17).

A product gap is a strict expected failure (`XFAIL`) with its reason; a fix makes the case pass, CI reports `XPASS` and fails, and the fix removes that marker. Never weaken a case to make it pass.

Packaging changes require `conformance/installed_bundle.py` against a freshly packaged bundle (Python 3.12 or newer; the Draft Linux release workflow runs it) and `conformance/test_package_release.py`. Live runs with real models are separate manual checks.
