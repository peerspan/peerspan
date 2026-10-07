# Owning and evaluating Capsule connectivity

Decision recorded 2026-10-06: own Capsule's connectivity story and evaluate our
implementation against iroh. Building on iroh is acceptable. Ownership means
understanding the mechanisms and controlling identity, admission, discovery,
deployment, observability, and recovery, with the ability to change or replace
the implementation. Maintaining that control is an accepted tradeoff. After
reviewing the completed comparison on 2026-10-07, the decision is to retain the
in-house transport and scope an iroh migration in the future if needed.
This does not claim that an iroh comparison informed the original implementation.

## Completed comparison and interpretation

The full controlled matrix completed **108/108 passing trials**: 72 Capsule
Go/Rust trials, 18 iroh native trials, and 18 iroh bounds-control trials. The
[compact report](../conformance/results/connectivity-suite-linux.json) includes
every trial, successful latency distributions, failure counts, recovery times,
resource samples, and the evidence-bundle hash/location. A separate post-run check
found no recorded recovery time exceeding the claimed scenario bounds. Raw
samples, source snapshots, logs, and bounded packet captures are retained in
the [downloadable evidence bundle](../conformance/results/connectivity-suite-linux-artifacts.tar.gz);
fixture keys and executable files are excluded. The
[validation logs](../conformance/results/connectivity-validation-linux-artifacts.tar.gz)
retain the language checks and production conformance results.

These measurements used the source commit and exact helper snapshots recorded
in each report. The publication branch also contains later harness fixes:
request-local Go control errors, a bound check on successful final recovery
attempts, and stricter resume validation. Those fixes passed focused tests and
a fresh routed-IPv4 smoke run; they do not rewrite the historical measurements.

All profiles passed the laboratory's direct IPv4/IPv6, loss/delay, reduced-MTU,
NAT, outage, restart, rebinding, expiry, and address-change checks. Both
transports established direct paths through the port-preserving and nested
fixtures. UDP-blocked and random-port fixtures retained a usable local relay;
stopping that relay failed the checked negative control and restarting it
restored delivery. This establishes tested fixture behavior, not a real-world
hole-punching rate or complete production equivalence.

### The initial speed gap was substantially configuration-dependent

The [GSO-only control](../conformance/results/connectivity-controls-linux.json)
uses identical optimized binaries, with only iroh's segmentation offload
disabled in the second cohort. Three rotated runs contribute 6,000 sequential
samples per backend and payload in each cohort:

| Loopback backend/configuration | 16 B sequential p50, ms | 64 KiB sequential p50, ms | 64 KiB concurrent requests/s, median of runs |
| --- | ---: | ---: | ---: |
| Capsule Go, first cohort | 0.142 | 1.203 | 1,158 |
| Capsule Rust, first cohort | 0.108 | 1.007 | 1,465 |
| Iroh native GSO, first cohort | 0.115 | 0.538 | 1,976 |
| Capsule Go, second cohort | 0.156 | 1.122 | 1,180 |
| Capsule Rust, second cohort | 0.103 | 0.979 | 1,495 |
| Iroh GSO disabled, second cohort | 0.110 | 1.265 | 1,293 |

This demonstrates a substantial offload effect on this host. The original
large-payload advantage does not establish that iroh's complete architecture is
inherently faster. It gives Capsule a concrete optimization target: its Rust
GSO is disabled for Go interoperability, and its combined sockets should be
profiled for batching/offload correctness. Turning it on without mixed-host
conformance would be premature. The two cohorts were sequential and the host
was shared; all per-run values and host load are retained. This is not a general
speed ranking or a deployed-agent workload measurement.

### Recovery behavior also differs

Across the configured laboratory adapters, Capsule's peer-restart recovery was
24–946 ms (median 67 ms); iroh native was usually about 8 seconds, with its
configured-address-change case taking about 36 seconds. The bounds control
showed similar behavior. Capsule's four configured-address-change cases took
28–45 ms. Public-IP rebinding recovered in about 1–15 seconds for Capsule and
about 20 seconds for both iroh profiles. These are observations, including our
eight-second operation bound and adapter cache/dial behavior. They do not prove
that iroh cannot be configured or integrated to recover faster.

Capsule deliberately derives its stateless-reset key from the persisted host
key and uses compatible connection IDs across Go/Rust, with explicit reused-
connection recovery. Those are concrete parts of the connectivity contract we
own. A migration should preserve or deliberately revise that contract, rather
than importing defaults and assuming equivalent behavior. We have not isolated
a single cause for every observed recovery difference.

### Admission and the current decision

The [separate relay-admission check](../conformance/results/iroh-relay-admission-linux.json)
passed for both iroh profiles. The receiver explicitly trusted an outsider's
key, UDP was blocked, and the relay's allowlist excluded that endpoint. Delivery
failed; adding the same key to the relay allowlist enabled a checked exchange.
This isolates relay admission from endpoint rejection and demonstrates owned
policy on top of iroh. It is not Capsule's signed multi-network governance model.

Production Capsule conformance also passed all four pairings for peer identity,
grants, malformed wire input, durable acceptance/deduplication, relay restrictions,
signed/sticky revocation, and the three existing NAT scenarios. The new helper
checks passed unknown/removed peers, wrong pins, malformed HTTP, administration
isolation, and stream backpressure. Go race/vet, Capsule Rust tests/fmt/clippy,
iroh helper checks and the cancellation regression, and Python evidence-integrity
tests passed. Bounded traffic checks and passing tests do not constitute a
security audit.

**There is no measured need to migrate solely because of the initial loopback
result.** Retaining the in-house layer is defensible given the decision to
understand and control the mechanisms, its tested fixture coverage,
and its explicit interoperability/recovery contract. The maintenance obligation
remains real. Iroh is also a viable foundation for an owned connectivity story:
the policy, deployment, diagnostics, and application semantics can remain ours,
while its path mechanisms become an inspected/pinned dependency. The decision
should turn on that boundary and maintenance cost, not a claim that Capsule has
unique encryption, self-hosting, or generally superior performance.

Future performance work can profile Capsule's batching/offload interoperability.
If a migration becomes necessary, scope iroh's signed multi-network relay
integration, cache/address lifecycle, Go support, and platform coverage first.
This evaluation does not commit to either project before launch work.
Real WAN/cellular/corporate-network evidence remains outside this local suite.

## Explanation for reviewers

Capsule owns a connectivity protocol tailored to its host contract. It
uses established QUIC and TLS implementations rather than implementing those
primitives. We control how signed network membership admits hosts to our relay,
how existing host keys authenticate peers, how discovery information is
distributed, and how paths fail over. The coordinator and relay ship together,
and independent Go and Rust hosts implement one externally tested contract.
Owning that boundary lets us change and debug it on our own schedule. We accept
the cost of maintaining traversal, interoperability, and security-sensitive
integration code. We compare against iroh to find gaps and decide whether that
cost remains justified.

This is the rationale for keeping the implementation now. The original sequence
was incremental: pinned TCP/TLS messaging, then QUIC, relay forwarding, and path
discovery. [The transport proposal](quic-relay-proposal.md) records that history.
There is no recorded prior evaluation rejecting iroh, so we should not invent one.

## What ownership buys, and what it costs

| Choice | Concrete benefit | Cost or counterargument |
| --- | --- | --- |
| Own the host wire protocol | Existing Ed25519 host keys, certificate pins, ALPN, and stream limits are under one contract. | We maintain certificate renewal, pin verification, and protocol compatibility. Iroh also authenticates endpoint keys. |
| Relay integrated with signed membership | `capsule-coord` forwards only between members of a common network, including our revocation rules. Operators deploy the existing coordinator. | We maintain relay registration, reconnects, limits, and abuse handling. An iroh relay could be integrated with our policy; this is an integration choice, not an impossibility. |
| Independent native Go and Rust implementations | No Rust runtime or FFI is required by the Go daemon; mixed hosts provide interoperability checks independent of language. | Two implementations duplicate maintenance. Iroh's documented Go bindings are community maintained via FFI. Third-party native Go implementations also exist; retaining ours needs a maintenance/interoperability assessment, not a claim that Go cannot use iroh. |
| Explicit discovery and deployment | The signed network map and network's pinned coordinator determine where hosts connect. We control metadata exposure and infrastructure. | Iroh supports self-hosted relays and replacement or disabled address lookup. Self-hosting and avoiding public infrastructure do not uniquely require our implementation. |
| Bounded product scope | We can focus on authenticated host requests and measured path recovery needed by Capsule. | Networks still have broad failure modes. Keeping a narrow API does not make NAT traversal, denial-of-service resistance, or cryptographic integration easy. |

Membership, owner grants, durable receipts, deduplication, automatic request
retry, and delivery to agent sessions are above the connectivity layer. They
would remain necessary on iroh. They explain Capsule's product, but do not alone
justify building a transport. Encryption and offline direct communication are
also shared capabilities, not differentiators.

Relevant primary sources, consulted 2026-10-06:

- [Iroh 1.3.0 endpoint and transport API](https://docs.rs/iroh/1.3.0/iroh/).
- [Iroh language support](https://docs.iroh.computer/languages): Rust official; documented Go bindings community maintained.
- [Third-party native Go iroh implementation](https://github.com/tmc/go-iroh): an additional integration option, not exercised by the first baseline.
- [Iroh enterprise network configuration](https://docs.iroh.computer/configuring-networks): self-hosted infrastructure, explicit discovery, proxies, and portmapper control.
- [Iroh relay deployment source](https://github.com/n0-computer/iroh/tree/main/iroh-relay): check the pinned release before integrating its access controls.

## First reproducible baseline

Run from the Capsule repository root:

```sh
python3 conformance/connectivity_bench.py \
  --artifacts /tmp/capsule-vs-iroh-001 \
  --count 500 --cold 30 --warmup 30 --concurrency 8 --repeats 3
```

The artifact directory must be new. The runner builds optimized helpers before
measurement, pins iroh at 1.3.0 in a separate Cargo project and lockfile, and
rotates backend order across runs. It records environment, compiler versions,
source state, source and binary hashes, per-run logs, raw seconds, nearest-rank
percentiles, and throughput. A failed measured run marks its report failed and
retains earlier samples; a build failure leaves build logs and no completed
report. Dependency downloads need network access; benchmark endpoints use only
explicit IPv4 loopback addresses and no public lookup or relay infrastructure.

Each backend binds both endpoints in one process. Go uses `GOMAXPROCS=4`; both
Rust helpers use four Tokio workers (background/blocking workers may differ).
The Capsule helpers use production combined sockets, host identity verifiers,
connection setup, and HTTP stream clients. Test-only HTTP echo servers avoid
durable writes and never add a route to shipped daemons. Iroh uses its Minimal
preset, default crate features, an explicit loopback socket, disabled portmapper,
and zero cached TLS tickets. Capsule already disables resumption and 0-RTT.

Measured workloads:

- **Cold first echo:** discard the previous connection, then time a fresh
  authenticated dial plus one verified 16-byte HTTP echo. Endpoints and host
  databases already exist; Capsule's per-dial certificate/configuration work
  is included. This is not pure handshake time. Prior endpoint state and
  reachability knowledge can persist between cold connections, particularly in
  iroh; process startup and address discovery are not measured.
- **Warm sequential echo:** one POST/response per bidirectional stream over a
  reused connection, with 16-byte and 65,536-byte deterministic bodies echoed in
  full. Every byte and HTTP success status must match.
- **Concurrent echo:** the same verified exchanges at a fixed concurrency,
  reporting individual latency and complete-workload requests per second.
  Payload MiB/s is reported separately for each direction, excluding headers.

Capsule Rust and iroh share the workload and Hyper echo server; Capsule Rust uses
its production HTTP client, while iroh uses an equivalent bounded HTTP client.
Go uses its production stream client and the standard Go HTTP server. HTTP
header choices, TLS identity representation, QUIC libraries/configuration,
allocation, and runtime scheduling differ. Results compare these configured
implementations; they do not isolate the path manager's cost, prove general
language rankings, or represent deployed agent messaging. Native QUIC defaults
are retained, including Capsule's disabled Rust GSO and its stream limits.

The existing [peer application benchmark](../conformance/peer_transport_bench.py)
separately measures durable sends and read-only lookups across all four Go/Rust
pairings. Its results must not be directly compared with iroh's echo latency:
the operations and persistence costs differ.

### Recorded first run

The [result and provenance](../conformance/results/connectivity-loopback-linux.json)
and [raw samples, logs, and source snapshots](../conformance/results/connectivity-loopback-linux-artifacts.tar.gz)
record three rotated runs, with 30 cold connections, 30 warmups, and 2,000
requests per workload in each run. Each backend contributes 90 cold samples
and 6,000 sequential/concurrent samples per payload size. All exchanges passed
status and byte verification. The machine was an Intel i7-7700 Linux host,
using Go 1.27.1 and Rust 1.99.0, with four configured runtime workers.

| Backend | Cold first echo p50, ms | Warm 16 B p50, ms | Warm 64 KiB p50, ms | Concurrent 64 KiB requests/s, median of runs |
| --- | ---: | ---: | ---: | ---: |
| Capsule Go | 2.204 | 0.145 | 1.122 | 1,221 |
| Capsule Rust | 1.210 | 0.091 | 0.977 | 1,539 |
| Iroh Rust 1.3.0 | 1.380 | 0.114 | 0.508 | 2,601 |

The useful finding is workload dependence: Capsule Rust had slightly lower
small-message latency, while iroh completed the larger sequential echo in about
half the time and had higher large-payload throughput. Capsule Go was slower
than both in these sequential workloads. These are observations about the
configured builds on this host, not a general ranking or a causal explanation.

The host was shared and busy: its recorded one-minute load average ranged from
about 11.5 to 17.3. For example, Capsule Rust's large-payload concurrent rate
ranged from 1,031 to 1,841 requests/s. Treat the table as a preliminary baseline;
raw per-run rates and tail latencies are in the report. Reproduce on a quiet
machine before setting regression budgets or publishing performance claims.

Next performance investigation: profile the 64 KiB exchanges and compare a
control with matched segmentation offload, stream/flow-control settings, and
HTTP client behavior. Capsule's production Rust GSO is disabled for existing
Go interoperability; iroh retains its native defaults. This is a possible
contributor to investigate, not an established explanation for the measured gap.
Measure the full Capsule application separately before deciding whether the
gap affects real agent workloads.

## Connectivity evaluation matrix

Loopback and the controlled network fixtures are now measured. Compare like
infrastructure; a local Capsule relay versus a public iroh relay across the
Internet would conflate the transport with deployment and geography.

| Scenario | Required observations | Current comparison status |
| --- | --- | --- |
| Direct IPv4 loopback | Cold first exchange; warm p50/p90/p99; concurrency and payload throughput | Measured, including GSO-only control |
| Separate endpoint processes and routed IPv6 | Same workloads, RTT, packet loss, CPU, RSS, packet evidence | Passed locally; physical LAN/WAN hosts unmeasured |
| Forced local relay, UDP blocked | Successful authenticated exchange; prove relay dependency; throughput and tail latency | Passed three fresh fixtures per profile |
| Port-preserving stateful NATs | Relay-first exchange; elapsed time to direct path; fresh exchange with relay stopped | Passed three fresh fixtures per profile |
| Random-port mapping fixture | Selected path and verified availability across repeated fresh fixtures | Passed with relay fallback. Fully random masquerade is not every real-world symmetric NAT. |
| Relay restart or outage | Direct exchange survives; relay-only failure visible; reconnection after restart | Passed all relevant local profiles |
| Peer restart, address change, idle mapping expiry | Checked recovery and connection lifecycle | Passed specified restart, address-change, rebinding, and injected-expiry tests; application duplicates checked separately by Capsule conformance |
| Delay/loss, constrained MTU, nested NAT and asymmetric filtering | Checked exchanges, recovery, selected-path evidence | Passed local fixtures without pre-punching peers |
| Unknown/removed peer, malformed traffic, resource pressure | Rejection, administration isolation, resource observations | Bounded rejection/backpressure checks passed; full adversarial exhaustion and security review unmeasured |

For network tests retain seeds/configuration, logs, path snapshots, exact binary
hashes, and the start/finish times of fresh application exchanges. Do not infer
connectivity solely from a transport's reported path. A stopped-relay test must
receive a fresh, checked payload, and a relay-only negative control must fail.
Track success counts and timeout/censored attempts alongside percentiles; do not
drop failures from latency summaries or call a passing laboratory fixture a
real-world hole-punching success rate.

## Full controlled comparison

```sh
python3 conformance/connectivity_suite.py \
  --artifacts /tmp/connectivity-full-001 --count 100 --nat-repeats 3
```

This executes 108 fresh trials: twelve scenarios across Go→Go, Go→Rust,
Rust→Go, Rust→Rust, iroh native defaults, and an iroh bounds control. Cone,
random-port, and UDP-blocked cases have three independent fixtures per profile;
the remaining scenarios have one. The scenarios are routed IPv4, routed IPv6,
20 ms ±2 ms delay on both routers plus 1% loss, MTU 1280, port-preserving NAT,
random-port NAT, UDP blocked, one-direction UDP blocked, nested NAT, public-IP
rebinding, injected mapping expiry after 35 seconds idle, and peer address change.
These are Linux laboratory profiles, not a survey of routers in the wild.

Every trial uses separate endpoint processes. Relay cases use only a local TLS
relay: Capsule's real coordinator with signed host enrollment, or pinned
iroh-relay with an owned endpoint admission callback and a local certificate.
Programs perform their own discovery and traversal; the runner does not punch
sockets. Fresh full-payload echoes prove connectivity in both directions.
Established direct paths must exchange fresh data with the relay stopped.
Relay-only paths must fail that negative control, then recover after restart.
All cases restart the peer with its original key, without clearing the sender's
cache by hand. Rebinding, expiry, and configured-address changes have additional
recovery observations. Unknown/removed keys, wrong identity pins, malformed HTTP,
administration isolation, and 32-worker stream backpressure run in routed IPv4.

The bounds control disables iroh GSO, sets 16 incoming bidirectional streams and
zero unidirectional streams, and uses a 30-second connection idle timeout. Other
defaults remain native, including NAT/multipath behavior and flow-control
windows. This is not complete parameter equivalence. To isolate GSO alone:

```sh
python3 conformance/connectivity_bench.py \
  --artifacts /tmp/connectivity-gso-off-001 \
  --count 2000 --cold 30 --warmup 30 --repeats 3 --iroh-disable-gso
```

Network workloads use 16-byte and 64 KiB echoes at concurrency 1 and 8, usually
100 each (20 under delay/loss). Small batches checkpoint observations and stop a
positive workload on failure: attempted failures, requested counts, and
unattempted requests remain separate. Successful-only percentiles are labelled;
negative controls are marked as expected failures. A failed case stops its later
phases, which therefore remain unexecuted. This prevents an unavailable path
from turning a long control timeout into missing evidence.

The report retains per-request durations and verification, selected-path
snapshots, process CPU time/RSS/high-water RSS, interface byte/packet counters,
helper binary hashes, source snapshots, and bounded packet captures. CPU includes
the test/control machinery and payload generation, with `/proc` tick resolution;
it does not account for every kernel networking cost. RSS is the helper process
footprint and includes test code/shared pages; summing RSS is not physical-memory
accounting. Network counters include coordination and discovery traffic. Captures
use 128-byte snapshots and a 2 MB ring per role; early packets can be overwritten
and `any` captures can duplicate frames. These limitations are part of the evidence.

Private state uses short temporary paths to avoid Linux's Unix-socket length
limit and is deleted after processes and namespaces are stopped. Runtime keys
are not exported. Logs, source snapshots, samples and captures remain in the
artifact directory. A resume can reuse completed passing trials only with the
same helper and harness hashes, workload parameters, and capture profile; only
trials from the requested matrix are reused. Their original evidence paths
and report provenance are preserved. Failed or interrupted trials are rerun.

### Adapter obligations and migration gaps

The iroh test adapter owns its key, local admission rules, and connection cache.
During development we found that a cancelled request could leave a dead cached
connection in our adapter. The cache now evicts/closes on cancellation, with a
live-endpoint regression test. Configured address changes also invalidate the
adapter's cache. Those were adapter obligations, not evidence against iroh.
Discarded smoke runs remain available as development diagnostics.

Iroh's relay access callback admits endpoint registrations. This harness uses a
single fixture-network allowlist; it does not integrate Capsule's signed
membership chains, sticky revocation, or common-network checks on each forwarded
pair. A production migration must assess per-network relays, custom forwarding
integration, or an owned/upstream change before claiming policy equivalence.
Capsule's existing production conformance separately checks those rules.

The SDK comparison uses official Rust iroh. The documented Go FFI bindings and
the third-party native Go port are integration options, not validated replacements
for the Go daemon here. The laboratory does not establish real WAN/cellular/
corporate-firewall coverage, proxy support, platform portability, multi-network
governance equivalence, or security under adversarial resource exhaustion. The
bounded rejection/backpressure tests are not a security audit. Those remain
decision gates if we choose a migration or make production claims.

## Conditions for retaining the implementation

Ownership remains the chosen direction; the mechanism may be ours or iroh's.
The evaluation should still be capable
of finding against our implementation. Review the measured gap when Capsule
cannot reach a tested network iroh can, cannot recover within its documented
bounds, incurs unacceptable workload-specific CPU or relay costs, or needs more
maintenance than we can sustain. First distinguish a fixable defect from a
structural limitation. Keep using established QUIC/TLS libraries, preserve mixed
Go/Rust conformance, and budget for independent security review before production
claims. Passing benchmarks does not establish security.

Do not publish claims of superior performance, security, NAT coverage, or
operational simplicity until the corresponding scenario has supporting evidence.
