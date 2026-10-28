# Developer guide

This is the source-checkout path. For the user path, follow the [quick start](quick-start.md). This repository contains the Rust host only ([DEC-OWN5](decision-log.md)); the Go implementation is maintained separately at [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go). Use separate state directories when running several hosts side by side.

## Build the host and test probes

From the repository root:

```sh
cargo build --locked --manifest-path rust/Cargo.toml --bins
```

This builds `peerspan-host` (the daemon and CLI, also installed as `peerspan`), the optional `peerspan-helper`, and the `peerspan-peer-probe` and `peerspan-link-probe` conformance fixtures under `rust/target/debug/`. The probes are test clients, not deployment binaries. The [architecture map](architecture-onboarding.md) identifies the daemon, CLI, storage, transport, and adapter entry points.

## Package a release bundle

```sh
scripts/package-release.sh rust VERSION
scripts/package-helper.sh VERSION
```

The host script currently packages native Linux builds, bundles pinned Node integrations, and writes an archive plus checksum under `dist/`. It requires Node.js 22 or later and records the builder's glibc baseline in `RELEASE.json`. The [quick start](quick-start.md) describes installing a bundle; the [installed-bundle check](../conformance/installed_bundle.py) exercises its contents.

## Verify a change

The [implementation instructions](../AGENTS.md) map each changed contract or CLI surface to its required checks. The language checks, as run in CI, are:

```sh
cargo fmt --check --manifest-path rust/Cargo.toml
cargo test --locked --manifest-path rust/Cargo.toml
cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
```

CI also runs the [slim conformance suites](../conformance/slim/) (one small black-box suite per area, written from the spec; DEC-OWN6, DEC-OWN9, DEC-OWN10) against the Rust host and peer probe, in parallel. To run one locally after building the binaries, put `peerspan-host` and `peerspan-peer-probe` in one directory and run, for example:

```sh
python3 conformance/slim/join.py --bin DIR
```

The large earlier conformance suites were deleted in favour of the slim suites ([DEC-OWN10](decision-log.md)). Verification sections of older contracts and proposals still name them as history; the slim suites are what CI and reviewers use now. `conformance/installed_bundle.py` remains for checking packaged bundles.

## Test clock (debug builds only)

Debug builds let a suite move the host's clock forward or back, so a test of a 7-day lease, a 1-hour invite or a 10-minute idle stop takes seconds ([DEC-OWN9](decision-log.md), DEC.impl16). Release builds compile this out and ignore both variables.

- `PEERSPAN_TEST_CLOCK_OFFSET`: a signed duration added to the time for the whole process.
- `PEERSPAN_TEST_CLOCK_OFFSET_FILE`: a file holding a signed duration, re-read every time the host reads the clock, and added to the first. A missing file counts as zero. To advance running processes, rewrite the file atomically (write a temporary file, then rename it over the old one).

A duration is an optional `+` or `-` followed by one or more `<digits><unit>` groups, with unit `s`, `m`, `h` or `d`: `+3d`, `-2h`, `90s`, `1d12h`. Surrounding whitespace in the file is ignored. An invalid value makes the process panic.

Set the same variables on every process in a test (daemons, CLI invocations and `peerspan-helper`): the CLI computes expiry times, and hosts compare each other's signed times. Leases, renewal, invite, request and join-stage windows, policy and group leases, call deadlines and capability idle stop all follow the shifted clock; a periodic worker notices a jump on its next pass (lease renewal every 10 seconds, call deadlines, including a running call's, and idle stop every 250 ms). TLS certificate validity, discovery ping freshness and transport retry timing keep the real time.

```sh
export PEERSPAN_TEST_CLOCK_OFFSET_FILE=/tmp/peerspan-clock
echo +4d > /tmp/peerspan-clock.new && mv /tmp/peerspan-clock.new /tmp/peerspan-clock
```

## Timing log (debug builds only)

With `PEERSPAN_TIMING=1`, a debug build prints one `timing #N KIND WHAT MS` line on standard error for each CLI request to the daemon (`cli`) and each whole command (`total`), each request the daemon serves on the local or peer API (`serve`) and each it sends to a peer (`peer`), and the daemon's costly steps (`step`: snapshot loads and reuses, projection builds, catalog reads and reuses, and waits of more than 5 ms for the store lock). `#N` numbers the served request a line belongs to; `#0` is work outside one, such as background sync. Set it on the daemon and the CLI. Release builds ignore it.

## Explore a subsystem

- [Manual agent testing](manual-agent-testing.md) covers explicit sessions, routes, and local fixtures.
- [Coordination contract](coordination-contract.md) and [peer messaging contract](peer-messaging-contract.md) explain enrollment and transport.
- [Connectivity evaluation](connectivity-evaluation.md) explains the controlled network benchmarks and their limits.
- `PEERSPAN_TIMING=1` in debug builds prints per-request timings (see above), and the ignored Rust connectivity benchmarks in `rust/src/quic/` can be run on demand.

The [earlier prototype](../legacy/README.md) has its own Go module and test requirements. It is historical code, separate from the current hosts.
