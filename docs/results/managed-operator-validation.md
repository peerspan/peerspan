# Managed operator validation

## Revision 6

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04), with Node 24.22.2,
against the same host binaries as revision 5 (this branch with upstream
`ad5d7993`). The store is still version 4.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The eight suites, cases 1 to 21 | 46/46 passed in about 4.5 minutes in sequence: acceptance 6/6 (67 s), operations 5/5 (50 s), visibility 6/6 (42 s), remote 4/4 (65 s), schedules 5/5 (11 s), reviewers 8/8 (19 s), runtime-agents 4/4 (10 s), capacity 8/8 (13 s, new). |
| `real-peerspan-smoke.py` against the same binaries | 5/5 passed in 146 seconds; the runtime case now also runs two workflows at once. |
| Console in headless Chrome 157 | The Workers page with a runtime agent's capacity and active tasks, desktop and phone: no horizontal overflow and no page errors. |

The new suite, `capacity.mjs` (cases 20 and 21), was written from the contract by
the same separate author, who did not read the implementation, and found no
defects. In its first run one case of 21 timed out waiting for the slow host's
`status` call to begin; it passed in the eleven runs since, ten before the
review fixes below and one after, and its fixture was made clearer by giving the slow worker a
host of its own. The cause was not found. With the harness and the fake, the eight
suites are 5,364 lines.

The real-transport runtime case now also creates two workflows on a runtime agent
whose launch profile allows two runs at once: both runs are dispatched before
either ends, each on its own fork holding its own write, and the connection then
reports a capacity of 2 and no active tasks.

### Independent review of revision 6

The reviewer of revisions 4 and 5 read revision 6 against the contract and probed
it with a fake and the real binaries. It confirmed three defects, all fixed
before publishing:

- **Medium:** background work shared a limit of eight jobs at once, so eight
  slow calls, which a runtime agent's capacity makes easy to reach, queued every
  other worker's checks, submissions and cancels behind them: with ten hanging
  `task inspect` calls a healthy run was submitted after 9.2 seconds and a cancel
  sent after 7.9. A job that outlasts the pass wait now gives its slot back; the
  same probes measured 32 and 114 milliseconds.
- **Low-medium:** a pass waited for work still running from earlier passes, so
  one hung call made every pass take 2 seconds, which also broke section 1's
  pace under `MANAGED_CLOCK_FILE` (largest gap between passes 2.2 seconds; now
  0.2). A pass now waits only for work it started, at most one interval, and
  passes start one interval apart; the contract says both.
- **Low:** the Workers page said "One task" for an agent holding more tasks than
  a capacity that had just fallen.

From its unconfirmed notes, a CLI process that outlasts its time limit is now
killed with SIGKILL rather than SIGTERM, and a failure of background work stays
reported until that work succeeds instead of flickering between passes. It also
confirmed the capacity limit in every case it tried, including a fall from 3 to
1 with three tasks held, review tasks, migrated duplicate targets and a remote
connection to the same agent; that a hanging connection or task never gets a
second call; that operator actions answer in milliseconds with every slot
hanging; and that shutdown with twelve hanging calls takes 25 milliseconds.

## Revision 5

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04), with Node 24.22.2,
against host binaries rebuilt from this branch after merging upstream `main`
through `ad5d7993`, which implements runtime agents (`b270c1b6`); the managed
work changes nothing in the host, and its checks were not rerun. The store is
version 4, unchanged, so no migration was needed.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The seven suites, cases 1 to 19 | 38/38 passed in about 3.5 minutes in sequence: acceptance 6/6 (63 s), operations 5/5 (17 s), visibility 6/6 (41 s), remote 4/4 (65 s), schedules 5/5 (10 s), reviewers 8/8 (10 s), runtime-agents 4/4 (10 s, new). |
| `real-peerspan-smoke.py` against the rebuilt binaries | 5/5 passed in 150 seconds; the fifth case is new. |
| Upstream `conversations_tools` `help` against the rebuilt binaries | Passed. |
| Console in headless Chrome 157 | The Workers page with a runtime agent, desktop and phone, light and dark: no horizontal overflow, no page errors, and no launch-profile path in any response. |

The new suite, `runtime-agents.mjs` (case 19), was written from the contract by
the same separate author, who did not read the implementation; it found no
defects, and its three questions (which profile counts when two match, a profile
listing that rejects `--json`, and `runtime` for codes before the runtime rows)
were settled in the contract (`7bbc9047`). With the harness and the fake, the
seven suites are 5,028 lines.

The real-transport smoke's fifth case runs a real host with upstream's own fake
runtime (`conformance/slim/fake_runtime.py`), which serves a peerfs space and
acts as the agent. An agent registered with `--agent` is `session_not_ready`
without a profile, `runtime_credential_missing` once its owner sets a launch
profile, with the profile summarized in readiness and no path in any response,
and `ready_runtime` once a credential is stored, without any session. A
workflow's run then executes on the fork `codex.TASK_ID` of `main`, which holds
the agent's write while `main` is unchanged, and the run's `branch` is that fork
at its commit, read from the real host's output line. Switching the runtime off
makes the agent `runtime_disabled`. No model is called.

The fork's CI on `35a153cb` (revision 4) failed once in upstream's `conversations_run_fixes` suite, in `order_cursor_follows_print`, and passed when rerun; that suite covers host code this work does not change.

Upstream's runtime agents confirmed the open question of MGD-12: on `b270c1b6`, a
runtime agent with a profile, a credential and a running runtime is listed in
its host's `status` with no sessions and in the sender's `agents` directory as
not `connected`. Readiness for a runtime agent on another machine therefore
waits for upstream's answer on PR #186.

### Independent review of revision 5

The reviewer of revision 4 read revision 5 against the contract, probed it with a
fake and with the real binaries, and confirmed four defects, all fixed before
publishing:

- **Medium-low:** with its runtime process stopped, upstream's `runtime show`
  waits up to 35 seconds; the controller's 15-second command limit then slowed
  every scheduler pass, for every worker, to about 15 seconds. `runtime show` now
  has 5 seconds, after which the agent is `runtime_unavailable`, and the
  contract says so. A pass that meets a stuck runtime still waits those 5
  seconds; reading slow checks beside dispatch, as a hanging `status` would also
  need, is left for later.
- **Low:** the runtime summary rounded short time limits, showing 20 seconds as
  0 minutes.
- **Low:** the activity log called an unreadable launch-profile listing an
  unreadable host status.
- **Low:** before a check reached the launch profiles, the Workers page said an
  agent-mode worker followed its sessions.

It also confirmed the order of the four codes, every failure mode of both
commands, that no path leaves the controller, that a change of only the
profile summary is a readiness change, that file and remote mode never run the
new commands, and that each check adds exactly one profile listing. It noted
that a new CLI talking to an older daemon still running cannot read launch
profiles; the operator guide now says to restart the daemon after upgrading.

## Revision 4

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04), with Node 24.22.2,
against the same Rust host binaries as the 0.2.1 run below (upstream `67e20797`).
Upstream `main` was merged again (through `d8123611`, the runtime agent contract);
that merge changed only upstream documents and conformance scripts, not the host.
The Rust host is unchanged by this work; its checks were not rerun.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| `node managed/conformance/acceptance.mjs` (cases 1 to 6) | 6/6 passed in 67 seconds. |
| `node managed/conformance/operations.mjs` (cases 7 to 10) | 5/5 passed in 31 seconds. |
| `node managed/conformance/visibility.mjs` (cases 11 and 12) | 6/6 passed in 42 seconds. |
| `node managed/conformance/remote.mjs` (case 13) | 4/4 passed in 66 seconds. |
| `node managed/conformance/schedules.mjs` (cases 14 and 15) | 5/5 passed in 8 seconds, using the conformance clock. |
| `node managed/conformance/reviewers.mjs` (cases 16 to 18) | 8/8 passed in 10 seconds (new). |
| `real-peerspan-smoke.py` against built binaries | 4/4 passed in 142 seconds; the fourth case is new. |
| Version 3 state migrated by revision 4 | Passed; see below. |
| Console in headless Chrome 157 | Desktop 1440 and 1360 and phone 390 pixels wide, light and dark: no horizontal overflow and no page errors. The workflow form's Results section (with the worker's own agent disabled as reviewer), the reviewer states on run pages (waiting, checking, fallback, verdict, rework), the review task's answer, input and timeline, branches and run strips exercised by script. |

The new suite, `reviewers.mjs`, was written from [the contract](../managed-contract.md)
by a separate author who did not read `managed/lib/` or `managed/public/`; that
author also brought the shared checks of `harness.mjs` up to revision 4 and
taught the fake to script an agent's answers by input. Its ambiguities were
settled in the contract (`9843e709`): which truncation governs `branch`, the
order of `review/abandon`'s errors, a reviewer switch with a reviewer in the same
body, a restored workflow whose reviewer was removed, and the case of the
verdict line. With the harness and the fake, the six suites are 4,710 lines and
take about four minutes in sequence.

The suite found one defect, fixed before publishing: a task whose final output
was an empty string never finished, because the controller waited for a
non-empty output, and it held its agent meanwhile. Upstream never sends an empty
output, but an empty review answer must fall back to the operator. It predates
revision 4.

The real-transport smoke's fourth case, new in revision 4, attaches two scripted
agents to one worker host, registers one as the worker and the other as its
reviewer, and creates a workflow reviewed by an agent with one rework allowed.
The reviewer receives the review task through actual transport with the exact
input of contract section 15.1 and rejects the result with reasons; the worker
then receives the rework with the exact input of section 15.2 at once, and the
reviewer accepts the second attempt. The case checks the verdicts, notes,
attempt, `reworkOf`, statistics and the upstream record of the review task. No
model is called.

### Independent review of revision 4

A reviewer who had not written the code read revision 4 against the contract,
probed it against a scratch fake and against version 2 and 3 state built by the
earlier controllers, and confirmed four defects, all fixed before publishing:

- **Medium-low:** a NUL character in a worker's result, in review criteria or in
  a verdict note made the review or rework task impossible to start, because a
  command-line argument cannot carry it, and the task was retried forever while
  holding its agent. Results now lose their NUL characters where they are
  inserted into another task's input, and the API refuses NUL in instructions,
  criteria and notes; the contract says both.
- **Low:** the contract required a reviewer to be a connection that is not
  removed, yet allowed removing the reviewer of an archived workflow and
  restoring it. The rule now applies when a request sets the reviewer, and the
  restored workflow's results fall back to the operator.
- **Low:** the run strip on workflow cards said a result waited for the operator
  while a reviewer agent was still checking it.
- **Low:** the activity log said a rejected result was sent back when its rework
  had only become due.

The reviewer also confirmed with probes that review tasks share the run's
reconciliation path without one-task-per-run assumptions, hold the reviewer's
agent, go before new runs and oldest first, survive a restart under their task
ID, and lose cleanly to the operator's verdict; that the review and rework inputs
match the contract byte for byte and their 65,536-byte cut is maximal and lands
on a character boundary; and that 24 branch lines and 18 verdict lines parse as
sections 10.1 and 15.1 say. Counting the limits of notes and criteria in code
points, as agents' notes are cut, came from its notes as well.

### Migration from version 3

The live state on the validation machine holds only two observations, so the
migration was rehearsed on version 3 state built by the revision 3 controller
itself (with its fake Peerspan): a workflow on a schedule with operator review,
one result accepted with a note and one still waiting, a result ending with a
runtime agent's branch line, a workflow with a run left `running`, an edited
paused workflow and an archived one. Opening it with revision 4 kept every row
and every compared value, including statistics and verdicts, wrote
`managed.v3-backup.sqlite` with the same counts, gave workflows no reviewer,
criteria or rework, kept the earlier verdict as the operator's, read the branch
line into `branch`, and let the operator decide the waiting result. The run left
`running` was then completed by the fake and retained by revision 4 under its
task ID, with one submission in all. The independent reviewer repeated the
version 2 and 3 migrations with its own state and found them intact.

### Upstream's runtime agents

Upstream specified runtime agents (`docs/runtime-agent-contract.md`, RUN-8 to
RUN-11) while this revision was in progress: an agent whose tasks the host runs
itself, each in a microVM on a fork of a peerfs branch, ending its output with a
`Branch:` line. Revision 4 reads that line (section 10.1) from outputs that
follow it; the host side is not implemented upstream yet, so no real runtime
agent was run. How upstream's `status` and `agents` will present an agent that
runs without an attached session is not yet specified, and the operator's
readiness for such agents waits for that.

## Revision 3

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04), with Node 24.22.2,
against the same Rust host binaries as revision 2 (upstream `3a19521c`). The Rust
host is unchanged by this work; its checks were not rerun.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| `node managed/conformance/acceptance.mjs` (cases 1 to 6) | 6/6 passed in 64 seconds. |
| `node managed/conformance/operations.mjs` (cases 7 to 10) | 5/5 passed in 16 seconds. |
| `node managed/conformance/visibility.mjs` (cases 11 and 12) | 6/6 passed in 41 seconds. |
| `node managed/conformance/remote.mjs` (case 13) | 4/4 passed in 65 seconds; one case waits for the second directory refresh, a minute after the first. |
| `node managed/conformance/schedules.mjs` (cases 14 and 15) | 5/5 passed in 9 seconds, using the conformance clock. |
| `real-peerspan-smoke.py` against built binaries | 3/3 passed in 114 seconds. |
| Version 2 state migrated by revision 3 | Passed; see below. |
| Console in headless Chrome 157 | Desktop 1440 and 1360 and phone 390 pixels wide, light and dark: no horizontal overflow and no page errors. The schedule editor, the review form and its "next result" flow, and the remote worker panel exercised by script; a draft review note kept its text, focus and caret through four live refreshes. |

The two new suites were written from [the contract](../managed-contract.md) by a
separate author who did not read `managed/lib/` or `managed/public/`. Revision 3
deliberately changes shapes that the revision 2 suites checked exactly (the
schema version, new run, workflow and readiness fields, new codes and kinds), so
that author also brought the shared checks of `harness.mjs` up to the revision 3
contract; no case was weakened. With the harness and the fake, the suites are
now 3,583 lines and take about three and a half minutes in sequence.

One acceptance run hit a 403 in `durableRecovery` while a
reviewer's probe controllers were running on the same machine: the fixture
chooses a free port before `serve` binds it, and another process can take it in
between. The case passed in every other run, before and after.

The real-transport smoke's third case, new in revision 3, registers a worker
with `--remote` from the sender host's directory alone, without naming any
state of the worker host. It waits for readiness from that directory, creates a
workflow on a wall-clock schedule with operator review, makes it due with "run
now", delivers the task through actual transport to a scripted adapter, checks
that the success waits for review and counts only after it is accepted, checks
that the next run is the next scheduled slot, and then stops the adapter's lease
renewal: the controller's once-a-minute directory refresh reports
`session_not_ready` about a minute later. No model is called.

### Upstream 0.2.1 and the repository README

After revision 3, upstream `main` (`67e20797`, release 0.2.1) was merged into
this work without conflicts or changes under `managed/`, and the host binaries
were rebuilt from the merged tree (`peerspan-host 0.2.1-dev`). Against them the
real-transport smoke passed 3/3 in 129 seconds. In one earlier run its third case failed
before any managed code ran: upstream's own join helper, in the third join of
that run, got `link admit --network` exiting 1 with `error: host daemon:
invalid`. The same case then passed in two reruns and in the full run above.

The fork's CI showed that upstream's `conversations_tools` suite failed its
`help` case on this branch: it requires `README.md` to list the conversation
commands, and the fork had replaced `README.md` with its own page. `README.md` is
upstream's text again, with one section about `managed/`; `help` passes against
the 0.2.1 binaries.

### Independent review of revision 3

A reviewer who had not written the code read revision 3 against the contract,
probed it, and confirmed six defects, all fixed before publishing:

- **High:** a workflow whose window held only successes without review reported
  `stats.failed` as null, because SQL treats a comparison with a null review as
  null. The suite author found the same defect independently.
- **Medium:** the console rebuilt the run page on every live update and emptied
  a review note being typed. Typed text, focus and the caret now survive
  refreshes; the draft is kept per run, so it never follows the operator to the
  next result.
- **Medium:** with `MANAGED_CLOCK_FILE`, a moved clock reached a scheduler pass
  only at the next tick, up to ten seconds later. Passes now start at least once
  a second while the variable is set.
- **Low:** directory refreshes stopped after the controller's clock was stepped
  back. Sixty seconds now count by elapsed time or by the clock, whichever comes
  first.
- **Low:** `directoryAt` passed the upstream text through and the reason labelled
  a non-UTC time as UTC; it is now rewritten as a UTC time, and a change of it
  alone counts as a readiness change.
- **Low:** bare offsets such as `+05:30` passed as time zone names.

The reviewer also checked the schedule arithmetic against an independent
brute-force reference: 3,840 cases around every 2026 transition in 16 zones,
including Lord Howe's half-hour change, Chatham, Troll and Casablanca, with no
mismatch, plus the days Apia and Kiritimati skipped.

### Migration from version 2

The live state on the validation machine had only two observations, so the
migration was also rehearsed on richer version 2 state built by the revision 2
controller itself (with its fake Peerspan): one connection, an observation, an
archived workflow with a finished run and its timeline, a workflow with a run
left `running`, and an edited, paused workflow. Opening it with revision 3 kept
every row (connections, observations, workflows, runs, tasks, task events and
activity) and every compared value, wrote `managed.v2-backup.sqlite` with the
same counts, gave workflows `schedule` null and `review` `none`, and left runs
needing no review. The run left `running` was then completed by the fake and
retained by revision 3 under its task ID, with one submission in all.

### Found against the real CLI

- **Only addressable agents are in the directory.** Upstream `agents` lists an
  agent only when its name is addressable (lowercase letters, digits, `.`, `_`
  and `-`); others appear in the directory by ID only and not in `agents`. The
  first smoke run used an agent named in capitals and could not register it.
  The contract and README now say so, and the refusal names the rule.
- **A new policy reaches the sender by sync.** After the worker's owner allows
  the sender, the sender's directory lists the agent only once that policy has
  synced to it, a few seconds later. Registration therefore refreshes the
  directory, and the smoke waits for the listing before it registers.
- **A lapsed lease can look connected.** In the smoke's throwaway network, the
  sender's directory still showed the agent `connected` 20 seconds after its
  adapter stopped renewing, until a refresh. The controller's own refresh, at
  most once a minute, bounds how stale remote readiness can be, and the console
  shows the directory's time.

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
