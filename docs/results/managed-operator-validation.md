# Managed operator preview validation

Validated on 2026-11-11 UTC on Linux under WSL, with Node 24.22.2 and Windows
Edge for browser checks. The upstream host baseline is commit `3a19521c`
(`Fix docs that fell behind 0.2.0 (#164)`). The release commit containing this
report contains the operator sources and independent conformance suite tested.

## Results

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed all seven JavaScript entry/source checks. |
| `node managed/conformance/acceptance.mjs` | 6/6 passed in 62.3 seconds. |
| Actual two-host Peerspan transport smoke | 1/1 passed in 12.0 seconds. |
| `cargo fmt --check` | Passed. |
| `cargo test --locked` | 173 passed, 0 failed, 2 ignored. |
| `cargo clippy --locked --all-targets -- -D warnings` | Passed. |
| Desktop browser at 1440 x 1050 | Login, live observations and rendering passed; no horizontal overflow. |
| Mobile browser at 390 x 844 | Rendering and visible sign-out passed; no horizontal overflow. |
| Browser runtime | No page errors; authenticated snapshot and logout passed at `http://localhost:4310`. |
| Windows helper | `managed.ps1 status` passed using the Linux login environment. |
| Supervised local service | Enabled and running; restart and loopback health verified. |

The independent suite was written by a separate author from the operator contract,
without access to the managed implementation. Its six cases cover authentication,
schema/privacy, exact readiness, target exclusion, crash/replay, genuine one-minute
recurrence, persistent dispatch caps, failure pause, read-only external observation,
private file permissions and simultaneous crash-restart process locking. It uses
explicitly fake transport and temporary state, never model output. The acceptance
runner and fake executable total 718 lines; the separate actual-transport smoke
adds 143 lines. The managed CI job remains below its five-minute limit in local
measurement.

Recovery also checks status preceding its terminal output event: an event-read
failure, process crash, temporarily absent events and eventual recovery must retain
the same task without premature completion, target release or replacement dispatch.

The real transport smoke uses the existing upstream conformance harness and built
Rust binaries. It creates two isolated hosts, genuine network membership and signed
task access, acknowledges a scripted adapter's readiness, and checks dispatch,
acceptance, completion and exact output retained from actual task events:

```sh
python3 managed/conformance/real-peerspan-smoke.py --bin /path/to/built/binaries
```

No model was called. This proves transport compatibility and result retention,
not model reasoning or artifact quality. Existing user daemons were not modified
by conformance. The live dashboard observed two existing external programs without
dispatching managed work or taking over their controllers.

Browser review found and fixed a hidden mobile sign-out control. Real transport
review established two upstream requirements now reflected in the contract:
explicit global `--json` on CLI calls, and final output read from task events.
It also distinguished user-service supervision from a standalone daemon's actual
verified channel readiness. The revised independent suites passed after those fixes.

Hosted provisioning, tenant isolation, model-session lifecycle and billing are
outside this preview and were not tested or claimed.
