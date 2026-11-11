# Managed operator validation

## Revision 2

Validated on 2026-11-11 UTC on Linux under WSL 2 (Ubuntu 24.04), with Node 24.22.2,
against Rust host binaries built from upstream commit `3a19521c`
(`Fix docs that fell behind 0.2.0 (#164)`). The Rust host is unchanged by this
work; its checks were not rerun for revision 2.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| `node managed/conformance/acceptance.mjs` (cases 1 to 6) | 6/6 passed in 63 seconds. |
| `node managed/conformance/operations.mjs` (cases 7 to 10) | 5/5 passed in 16 seconds. |
| `node managed/conformance/visibility.mjs` (cases 11 and 12) | 6/6 passed in 42 seconds. |
| `real-peerspan-smoke.py` against built binaries | 2/2 passed in 31 seconds. |
| Console in headless Chrome 157 | Desktop 1440 and 1360, tablet 900 and phone 390 pixels wide, light and dark: no horizontal overflow and no page errors. Pause, resume, edit, cancel, the release acknowledgement and sign-out exercised by script. |

The revision 2 suites were written from [the contract](../managed-contract.md)
by a separate author who did not read `managed/lib/` or `managed/public/`. Where
a case exposed a gap, the contract was clarified and the suite kept; the
clarifications are revision 2's sections 1, 3, 4, 7 and 13 and decision MGD-6.
The suites use an explicitly fake Peerspan executable and throwaway state, and
check every response body for fixture paths, the access token and upstream
attention text. Together with the revision 1 suite they are 2,670 lines.

The real-transport smoke creates two throwaway hosts, a network, a second person
and signed task access, and drives a scripted adapter; no model is called. Its
second case, new in revision 2, registers the worker by agent name, checks that
a sender which is the worker host itself is refused, sends instructions that
begin with a hyphen, follows a progress event into the run timeline, and cancels
through actual transport: the run stays running until the adapter confirms, then
ends `cancelled` without counting as a failure.

### Found against the real CLI

- **Hyphen-leading instructions.** Revision 1 passed the input as a separate
  `--input TEXT` argument. The upstream parser reads a value that begins with a
  hyphen as an option and exits 2, so such instructions could never be sent and
  the run looked like a transport problem. The input is now one `--input=TEXT`
  argument (contract section 4).
- **A host cannot task itself.** A submission whose sender host is the worker
  host is answered "not found", the same as a missing task, so revision 1 would
  have replayed it forever. Readiness now reads the sender's status as well and
  reports `sender_is_worker`; `connect` refuses that setup (section 3 and 7).
- **CLI older than `--json`.** The Peerspan executable installed on the
  validation machine predates the global flag, which made every worker silently
  unready. Readiness reports `peerspan_incompatible` and `doctor` names it.

### Review findings on the first preview

An automated review of the first commit on the upstream pull request reported
three problems, all addressed in revision 2:

- A malformed request target such as `//[` terminated the controller. Request
  targets are now parsed inside the guarded handler and answered with 400.
- Two connections naming one sender state in two ways could hold one agent
  twice. The reservation is now the worker agent itself, whichever sender
  (MGD-6), enforced by a unique index.
- A malformed nested observation field could stop the console from rendering.
  Observation summaries are normalized to plain strings and numbers before
  they leave the controller, and the console renders every value as text.

### Independent code review of revision 2

A reviewer who had not written the code read `managed/` against the contract and
confirmed its findings with probes against the real store and engine. All ten
were fixed before publication, and the suites above were rerun afterwards:

- **A run could stay unresolved forever (high).** The status record and the
  task events are two reads. When a task finished between them, the final event
  was stored with the earlier record's state and its output dropped, and no
  later read fetched it again. Events newer than the record are now left for the
  next read, and every final state waits until its own event is retained.
- **Version 1 state could fail to migrate (high).** Revision 1 let one agent
  hold two unresolved runs through two senders, which the new per-agent unique
  index refused. Both runs are now kept and reconciled, and the agent stays
  reserved until both are resolved.
- **Operator requests during a slow pass (medium).** A request waited for a pass
  blocked on a hanging Peerspan call. Cancellations and dispatch now run beside
  the pass at once, with the readiness already known.
- Smaller fixes: a final `cancelled`, `expired` or `rejected` state no longer
  becomes final when its event fetch fails; a stopped storage worker makes later
  calls fail at once and the controller exit for its supervisor to restart; a
  released run is not inspected again while it waits for its turn; final events
  are fetched alone when a long task's event window is too large; a released run
  does not count as unattended; the console ignores snapshots that arrive after
  sign-out or out of order; and editing a workflow whose worker was disconnected
  no longer moves it to the first listed worker.

### This machine's clock

The WSL clock on the validation machine steps backwards by seconds several times
an hour. That broke the ordering of recorded times during development and led to
the rule in contract section 1: recorded times never decrease across a step back
of less than ten minutes. The revision 2 suites measure durations on the
monotonic clock and report steps they observed.

## Revision 1

Validated on 2026-11-11 UTC on Linux under WSL, with Node 24.22.2 and Windows
Edge for browser checks, on upstream commit `3a19521c`.

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
| Supervised local service | Enabled and running; restart and loopback health verified. |

Browser review found and fixed a hidden mobile sign-out control. Real transport
review established two upstream requirements reflected in the contract: explicit
global `--json` on CLI calls, and final output read from task events. It also
distinguished user-service supervision from a standalone daemon's verified
channel readiness. No model was called; hosted provisioning, tenant isolation,
model-session lifecycle and billing were outside the preview and not claimed.
