# Managed operator validation

## Revision 10 (0.11.0)

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04) with Node
24.22.2, against the host binaries of revision 7. The store is version 7.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The eleven suites, cases 1 to 31 | 73/73 passed in about 7 minutes in sequence, at a load average of 33 to 42 from other work: acceptance 6/6 (65 s), operations 5/5 (29 s), visibility 6/6 (42 s), remote 4/4 (66 s), schedules 5/5 (33 s), reviewers 8/8 (31 s), runtime-agents 4/4 (14 s), capacity 11/11 (29 s), checks 6/6 (12 s), handoffs 9/9 (13 s), alerts 9/9 (47 s); 7,746 lines with the harness and the fake. |
| `real-peerspan-smoke.py` | 5/5 passed in 208 seconds. After merging upstream's release 0.2.2 (`8819c85f`: held polls for running tasks, RUN-14, and Claude without nonessential traffic, RUN-15), 5/5 again in 212 seconds against binaries rebuilt from the merged tree. |
| Version 6 state built by 0.10.0, opened by 0.11.0 | Every row and compared value kept, among them a pending handoff and a rejection by checks; the backup `managed.v6-backup.sqlite` written; a run left running reconciled with one submission and a rework due before the upgrade sent after it; alerts set on the migrated state. The reviewer also took versions 4 and 5 to 7, and 0.10.0 refuses version 7 unchanged. |
| A live controller with a local webhook | A worker made unready raised one alert with the exact body; its recovery sent "Resolved"; a receiver answering 500 turned `meta.alerts.failing` and the `alerts_failing` item on; the webhook's secret path and token appeared nowhere in the snapshot, activity, logs or CLI output. |

### Alerts

`node managed/cli.mjs alerts --url URL` (or `--url -` from standard input) sets
a webhook, and the controller announces each attention item that needs the
operator when it appears and when it clears (section 8.1, MGD-19). The body
carries `text` and `content` for chat services and the item itself. Deliveries
are retried with backoff for a day, keep one item's alerts in order and survive
restarts without duplicates. A failing webhook shows in the console as
`alerts_failing`. The URL is a secret: it is set only on the machine and never
shown beyond its host. The console's sidebar says where alerts go.

The suite author wrote `alerts.mjs` from the contract, with a local receiver
whose answers are scripted. It has 9 concurrent cases and covers:

- configuration and its refusals, including a refused URL that leaves an older
  store untouched;
- privacy of the secret parts of the URL;
- exact bodies;
- `info` items never announced;
- restarts and the `checking` rule;
- non-2xx, redirect and slow answers;
- the retry schedule and both 24-hour give-ups, moved with the clock file;
- order when an item comes back.

### Independent review of revision 10

The reviewer found URL validation and privacy sound in every probe, across 36
URL forms, redirects, timeouts, logs and errors. It confirmed seven defects,
all fixed and re-checked with its probes:

- **Quiet controllers.** Attention was read again only when the revision
  changed, so a source that went stale over time was never announced. It is now
  also read every 30 seconds; a stale source was announced 29 seconds in.
- **Order when an item came back.** An item that came back while its cleared
  alert was being retried was raised again first, so the last word the
  receiver saw was "Resolved". An alert now waits for an older alert of its
  item.
- **A URL changed mid-evaluation.** A URL changed by the CLI during an
  evaluation could send that start-over's alerts to the old URL and record them
  as delivered. Each step now names the URL it read and does nothing after a
  change.
- **Slow webhooks.** A webhook answering 2xx slowly held each evaluation, so a
  new item waited behind ten slow deliveries. Deliveries now start only within
  2 seconds of an evaluation.
- **Restarts.** An alert delivered just as the controller stopped was sent again
  after the restart.
- **Response bodies.** They were read in full: a 1 GB answer took the
  controller's memory from 48 to 1,134 MB. Now nothing is read.
- **Refused URLs.** A refused URL still migrated an older store and wrote a
  backup.

Its second round found the 30 seconds stretching to 35 when reading the
attention items was slow, now counted from when the read begins. Two suspicions
were fixed too:

- Alerts waited for a successful scheduler pass, so a controller whose every
  pass failed never announced `controller_error`.
- The URL stood in the process list and shell history; `--url -` now reads it
  from standard input.

## Revision 9 (0.10.0)

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04) with Node
24.22.2, against the host binaries of revision 7. The store is version 6.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The ten suites, cases 1 to 28 | 64/64 passed in about 6 minutes in sequence: acceptance 6/6 (69 s), operations 5/5 (38 s), visibility 6/6 (42 s), remote 4/4 (66 s), schedules 5/5 (11 s), reviewers 8/8 (38 s), runtime-agents 4/4 (28 s), capacity 11/11 (32 s), checks 6/6 (19 s), handoffs 9/9 (16 s); 7,005 lines with the harness and the fake. The machine carried a load average of 50 to 84 from other work: a first pass lost acceptance, operations, visibility and remote cases to timeouts (a CLI call killed after 8 seconds, `/health` late), and all four passed in full when run again. |
| `real-peerspan-smoke.py` | 5/5 passed in 263 seconds. Over real transport, a workflow chained after a reviewed one received the accepted rework's result in exactly the contract's input. |
| Version 5 state built by 0.9.0, opened by 0.10.0 | Every row and compared value kept, among them a check's rejection still read as `checks`. The backup `managed.v5-backup.sqlite` was written. Workflows have `after` and `handoffPending` null and runs `handoffFrom` null. A run left running was reconciled with one submission. A rework due before the upgrade went out afterwards with the exact failed checks, and a migrated workflow was then made to run after another. |
| Console in headless Chrome, 390 and 1440 px, light and dark | The third "When it runs" mode was exercised with its cycle guard, which disables a workflow that already runs after the one being edited. Also exercised: the chain on both workflow pages, the input link of a handoff run, and the "Waiting for input" status. No overflow or page errors. |

### Handoffs

A workflow can run after another one (section 14.1, MGD-18). Each result of the
other workflow that counts as a success becomes its next input, in a fixed
`INPUT` block after its instructions. A result counts once it succeeded with no
review needed and passed its checks, or once it was accepted. A newer result
replaces one not yet dispatched, a rework goes first, and the input is capped at
half a task's input so that a rework can repeat it. Chains cannot form cycles,
and an `after` workflow has no `nextRunAt`. In the console it is the third
"When it runs" mode. The upstream workflow lists the workflows it hands off to,
and a handoff run links its input.

The suite author wrote `handoffs.mjs` from the contract: 8 concurrent cases,
covering:

- the exactly-one rule and cycles;
- every review mode;
- "latest wins";
- pause, archive, rework, daily cap, and a chain of three;
- the exact input and its cut;
- `run`, and the rework of a handoff run.

The shared harness now checks the revision 9 shapes on every snapshot. The
author's questions settled five points in the contract text:

- `run` records only `run_requested`;
- "latest" means by the moment a result counted;
- repointing `after` clears a pending handoff;
- a PATCH with two ways to run is refused;
- the rule for the `…` edge case.

Checking the console against the contract found one more: an `after` workflow
without input showed its busy worker as the reason, not that it waits for
input. The contract now says which reason applies, and the code follows it.

### Independent review of revision 9

The reviewer probed the rules against the model directly and through the real
server, and confirmed three defects, all fixed and re-checked with its probes:

- **Starvation on a shared worker.** Dispatch ordered due workflows by
  `nextRunAt`, and the store sorts a null `nextRunAt` first. A workflow that
  runs after another, with fresh input, therefore always took a shared worker
  ahead of an interval workflow that had been due for longer. Over three
  cycles the interval workflow never ran. An `after` workflow now ranks by the
  moment its input counted (section 4). The probe now gives the worker to the
  interval workflow due at 6 seconds before the handoff that counted at 110.
- **The console's cycle guard and archived workflows.** The guard could not
  see archived workflows' `after`, so it offered an upstream that the
  controller then refused. Archived entries in the snapshot now carry `after`.
- **An archived upstream with no other workflow.** A workflow whose upstream
  was archived could not be saved when no other workflow existed, not even to
  rename it. The editor now always offers the current upstream, named and
  marked archived.

It confirmed the rest sound:

- the exactly-one rule and cycles of two to four workflows;
- every switch with its `nextRunAt`;
- when a result counts, under every review mode and after a fallback;
- "latest wins", two downstream workflows, pause, archive and abandon;
- rework before handoff, and the rework of a handoff run;
- the exact input with its cut at a character boundary, including
  instructions that leave room only for `…`;
- the blocked reason;
- the due-time rule with handoffs;
- migration from versions 1 to 5 with row order kept;
- twelve rounds of six concurrent opens.

A remaining nit: two results accepted at the same recorded instant, as while a
held clock keeps one time, may make the automatic handoff and `run` pick
different ones of the two.

## Revision 8 (0.9.0)

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04) with Node
24.22.2, against the host binaries of revision 7. The store is version 5.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The nine suites, cases 1 to 25 | 55/55 passed in about 5 minutes in sequence: acceptance 6/6 (68 s), operations 5/5 (37 s), visibility 6/6 (42 s), remote 4/4 (70 s), schedules 5/5 (14 s), reviewers 8/8 (25 s), runtime-agents 4/4 (14 s), capacity 11/11 (32 s), checks 6/6 (15 s); 6,247 lines with the harness and the fake. Six of those runs saw the WSL clock step back, by 7.5 to 20 seconds in all. |
| `real-peerspan-smoke.py` | 5/5 passed in 246 seconds. Over real transport, a result that failed its checks was rejected without a review task, the rework carried the exact failed checks, and the passing rework went to the reviewer agent. On a real runtime agent, the branch check passed a committed fork and rejected a run that committed nothing. |
| Version 4 state built by 0.8.1, opened by 0.9.0 | Every row and compared value kept, the backup `managed.v4-backup.sqlite` written, workflows with `resultChecks` `[]` and runs with `checks` null; a run left running was reconciled under its task ID with one submission. The reviewer also took versions 2 and 3 straight to 5. |
| Six processes opening a version 4 store at once | No failed open in 10 rounds; before the fix below, 3 rounds of 10 had one. |
| Console in headless Chrome, 390 and 1440 px, light and dark | The checks editor, a run rejected by checks with its rework, the workflow page and a recipe with checks exercised by script. No overflow or page errors, and stored checks that were not touched survive a save byte for byte. |

### Result checks

A workflow can list up to eight checks that the controller applies to each
succeeded result itself, before any review (section 15.3, MGD-17): text it must
or must not contain, a length, JSON keys, or a committed branch. A failed check
rejects the result at once with `reviewedBy` `checks`, whatever review the
workflow asks for. No reviewer is asked, and with rework the agent receives the
failed checks. The console edits checks in the workflow form and lists each
check's outcome on the run page, and two recipes come with checks of their own.

The suite author wrote `checks.mjs` from the contract: 6 concurrent cases, 25
scripted results with exact messages, the interplay with every review mode, and
the rework input. The author's questions about whitespace, code fences, field
order and repeated checks were settled in the contract text. The shared harness
now checks every snapshot's rejections by checks.

### Independent review of revision 8

The reviewer confirmed two defects, both fixed and re-checked with its own
probes:

- A check whose `kind` was a one-element array, such as `["contains"]`, passed
  validation, because an object key accepts the array as the same string.
  Applying the check then failed when the result was retained, so the run never
  resolved and its worker stayed held. Releasing the run was the only way out.
  The kind must now be a string, and case 23 refuses that form.
- The console rebuilt every check from its form fields on any save. That dropped
  line breaks from a text, which an input field cannot hold, and split keys at
  commas, so renaming a workflow could silently change a check set through the
  API. A check the operator leaves alone is now sent back exactly as stored.

It also found a defect from revision 2: several processes opening an old store
at once could fail. The first read happened before the lock timeout was set,
and two openers could race to write the backup. The timeout is now set first,
and a backup another opener has just written counts as written.

The reviewer confirmed the rest:

- the messages and quoting;
- code-point lengths;
- `jsonKeys` with fences, branch lines, a BOM and prototype-like keys;
- validation limits;
- that no review task, `review_pending` item or operator verdict follows a
  rejection by checks;
- the statistics and the failure count;
- migrations;
- the console's escaping;
- the cost: eight checks on a 262,144-character result take 9 to 36 ms.

## Revision 7.1 (0.8.1)

Validated on 2026-11-12 UTC like revision 7 below. Revision 7.1 of the contract
changes section 3 (a ready verdict from one moment) and one rule of section 4;
the store is still version 4.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The eight suites, cases 1 to 22 | 49/49 passed in about 4 minutes in sequence: acceptance 6/6 (63 s), operations 5/5 (17 s), visibility 6/6 (41 s), remote 4/4 (70 s), schedules 5/5 (9 s), reviewers 8/8 (18 s), runtime-agents 4/4 (12 s), capacity 11/11 (25 s); 5,613 lines with the harness and the fake. Five of those runs saw the WSL clock step back, by 2.5 to 15 seconds in all; visibility also passed four times in a row on its own, each run with a step back. |
| Case 22 against 0.8.0 | Both parts fail at the first change: a ready verdict from two moments and a run sent. |
| Acceptance's readiness case, six copies at once with every CPU busy | 30/30 passed; 0.8.0 passed 24/24 and the first form of this revision 16/18. |
| `real-peerspan-smoke.py` against the binaries of revision 7 | 5/5 passed in 174 seconds: ready verdicts kept their facts across both reads against real hosts. |

### Work held back by a held clock

The prompt-pass case of the visibility suite failed once in a run during which
the WSL clock stepped back 2.46 seconds. A resume made while the controller
holds its clock is recorded at the same time as the check that the resume
starts, and since revision 7 an equal time does not count as after, so the run
waited for the next periodic pass: up to six seconds in that case, and up to
ten at the default interval. A dispatch now reports which ready connections
held work back for a fresher check. A recheck of only those connections, then a
dispatch, follows as soon as such a check can start: when the connection's
running check ends, or once the clock moves past the time it holds (note to
MGD-15). A probe can step the controller's clock back only through
`MANAGED_CLOCK_FILE`, which also makes passes start every second, so it cannot
show the saving: it measured 1.2 to 2.1 seconds with 0.8.1 and about 2.1 with
0.8.0. The visibility case, at a six-second interval with the real clock, passed
in every run since, most of them with a step back.

The independent reviewer found that the first form of this change, which moved
the whole next pass forward, ran failing passes every 20 ms (94 passes in 6
seconds against 6 with 0.8.0, with a store that refused to reserve) and would
have spent a full pass on every reviewed result finishing during a pass. Both
are fixed: the list of connections is emptied before each dispatch and after a
failed recheck, and a recheck checks only the connections concerned. Its
second review found a check that could not record its verdict (a store that
refused the write) rechecked every 20 ms, 62 checks in 6 seconds against 6; a
connection whose latest check failed is now left to the passes until a check
of it succeeds.

### A ready verdict from reads of two moments

The loaded stress run of the acceptance suite's readiness case (six copies at
once, every CPU busy) failed 2 times in 18 with `changed status host
dispatched`. The case changes the fake host in one step from "identity right,
verified without a time" to "a time, but another host". A file-mode check read
`status` and `adapter connection` in parallel, so it could take the identity
from before the change and the verification from after it: a ready verdict
that described no single moment. The defect dates from revision 1; 0.8.0 passed
the same stress 24 times in 24, so it is rare without help. Two probes give it
help, by delaying the slow read 300 ms and holding each state about a second
(longer than a check, so that no check sees a state come back):

| Probe | 0.8.0 | 0.8.1 |
| --- | --- | --- |
| File mode: status before the change, the adapter's report after it | A run sent on the first change | No run in 40 changes |
| Runtime agent: the launch profile's credential before the change, `runtime show` after it | A run sent on the second change | No run in 30 changes |

A ready verdict now stands only when what was read before its last read reads
the same after it (section 3, MGD-16). The facts compared are the file's
identity, the host, the agent, the verified session, the sender host, and in
agent mode the launch profile or its absence. In file mode, the adapter report
now follows the status that made its session a candidate. The reviewer's
probes found the first form missing the sender (a run on the first change) and
a profile's absence (a run after four changes); both are compared now.

### Statistics at scale

A probe seeded stores of 100,000 runs (300,000 events) and timed the console's
reads through the real server. The snapshot was dominated by the seven-day
statistics, which joined every task finished in the window to its run. Two
covering indexes, created when a store is opened, replace the finished-time
index; they add no table or column, so the store stays version 4 and 0.8.0 can
still open it.

| Store | Snapshot, 0.8.0 | Snapshot, 0.8.1 | Size |
| --- | --- | --- | --- |
| 50 workflows, 2,000 runs each over 21 days | 97 to 114 ms | 79 to 113 ms | 224 to 242 MB |
| 400 workflows, 250 runs each, all within the window | 470 to 476 ms | 252 to 270 ms | 225 to 243 MB |

Run pages, the run detail and activity pages stayed at 3 to 7 ms. The
statistics still read every run of the window, about 2 microseconds per run, so
100,000 runs a week (one every 6 seconds) cost 200 ms per snapshot; at 10,000
runs a week the snapshot stays within tens of milliseconds.

Validated on 2026-11-12 UTC on Linux under WSL 2 (Ubuntu 24.04), with Node 24.22.2,
against host binaries rebuilt from this branch after merging upstream `main`
through `048b9506`, which adds Claude Code as a second runtime harness and an
image per launch profile. The store is still version 4.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The eight suites, cases 1 to 21 | 47/47 passed in about 4 minutes in sequence: acceptance 6/6 (65 s), operations 5/5 (15 s), visibility 6/6 (41 s), remote 4/4 (65 s), schedules 5/5 (9 s), reviewers 8/8 (12 s), runtime-agents 4/4 (10 s), capacity 9/9 (17 s); 5,482 lines with the harness and the fake. |
| `real-peerspan-smoke.py` against the rebuilt binaries | 5/5 passed in 138 seconds; the runtime case now also runs Claude Code on an image. |

A runtime agent's readiness summary now carries its `harness` (`codex` or
`claude`) and `image`, and the Workers page names the agent program and its
image. The real-transport runtime case switches its agent's launch profile to
the `claude` harness on `python:3.12-slim`, checks that readiness reports both,
and runs a task on a fork with it, through upstream's fake runtime.

### Equal times on a held clock

While running the suites under heavy load, the suite author saw
`case21_slowCheck` send one run on readiness from a check that began before the
run was requested, which the rule above forbids. That run coincided with a
2.45-second step back of the system clock. During a step back the controller
keeps its newest time, so the check's start and the operator's request could
record the same time, and the comparison let the tie through. A first fix made
the clock strictly increasing; the independent reviewer showed that it then ran
ahead of the wall clock under bursts of calls (11 seconds after 10,000 calls in a
row, and back by 10 minutes after enough of them), so it was replaced: the clock
keeps its newest time as before, and a check whose recorded start equals a due
time no longer counts as having begun after it, so a held clock only delays
dispatch until it moves on. The reviewer also found that work due before a
deliberate correction of the clock (a step back of more than ten minutes) waited
silently until the corrected clock reached its old due time; such a time now
counts as the moment of the correction, which the clock records. The contract
says both, in sections 1 and 4. The case was also made harder, with a round in which the change comes
just after the in-flight check reported ready, and the fake now logs when each
delayed call wakes, so a failure says which side of the change the check read.

### Independent review of revision 7

The reviewer of the earlier revisions read the due-time rule, the clock changes
and revision 7, and probed them with real controllers and the clock file. Besides
the two findings above, it confirmed one more, fixed before publishing: a check
that began before a deliberate correction carries a start time from the old,
later clock, so it could pass as newer than work requested after the correction
(3 of 3 runs of its probe sent a run that way). A verdict recorded later than the
current time now reserves nothing until a check begun after the correction has
ended. It also confirmed that every way a workflow becomes due still dispatches
within a pass or two (creation, an elapsed interval, a schedule slot, `run`,
`resume` and `restore`), that slow checks and repeated edits never starve a run
or a review, that a check held at the same recorded time as a run request sends
nothing, and that the clock stays within milliseconds of the wall clock under
2,000 concurrent requests. While a step back holds the clock, newly requested
work waits until it moves on, up to the length of the step back.

## Console 0.7 and a revision 6 correction

Validated on 2026-11-12 UTC like revision 6 below, with the same binaries.

| Check | Result |
| --- | --- |
| `npm --prefix managed run check` | Passed: every JavaScript source of `managed/`. |
| The eight suites, cases 1 to 21 | 47/47 passed in about 4 minutes in sequence: acceptance 6/6 (62 s), operations 5/5 (13 s), visibility 6/6 (41 s), remote 4/4 (66 s), schedules 5/5 (13 s), reviewers 8/8 (15 s), runtime-agents 4/4 (10 s), capacity 9/9 (14 s); 5,420 lines with the harness and the fake. |
| `real-peerspan-smoke.py` | 5/5 passed in 175 seconds. |
| Console in headless Chrome 157 | Recipes, result comparison and notifications exercised by script on desktop and phone, light and dark; no horizontal overflow and no page errors. |

### A dispatch on stale readiness

After revision 6 was published, a regression run of the suites failed once in
`acceptance.mjs`: `readinessAndTargetExclusion` saw a run sent to a worker whose
pinned identity had just changed. Revision 6 dispatched with the readiness each
connection had last recorded, and its review fix had capped a pass's wait at one
interval (100 ms in the suites), so a check that began before the change could
still give the verdict for a run requested after it. A first correction, using
only verdicts from checks that ended since the previous decision, passed locally
but failed the same way in the fork's CI (`045f62e1`), which also showed it was
not enough: a check can begin before the change and end after the request.

Work is now reserved only on readiness from a check that began after the work
became due: a run after its `nextRunAt`, its rework or the operator's latest
change of the workflow, whichever is latest; a review task after its run ended.
A change made before a run is requested is then always seen. To check it, the
case was run six at a time with every CPU kept busy, which imitates a slow
machine: it failed 5 of 18 runs on the published code, 11 of 18 on revision 5,
whose pass timing had kept the same race out of normal runs, and 0 of 18 with
the rule. The suite author also added `case21_slowCheck`, which makes one
worker's checks slower than a pass, makes it unready while a check is in flight
and requests a run; it fails against the code before the first correction. Under
that load revision 5 also failed once at an earlier step of the case, where a
check read the worker's status before a change and its adapter after it; that
two-call view is inherent to file mode, did not occur with the rule, and is
noted here as a limit.

The fork's CI then failed once in `capacity.mjs` on a timing assumption of the
suites rather than of the controller: a suite finished a run that was still
`submitting`, before the fake had written the task's record. The suites now wait
for that record before writing a remote result; a submission forced to take 1.2
seconds reproduced the CI error before that change and passes after it.

### Recipes, comparison and notifications

The console gained three features over the existing routes, with no API or
contract change: a choice of six recipes when creating a workflow, each filling
the form for the operator to adapt; a line-by-line comparison of a finished
result with the workflow's previous one; and opt-in browser notifications of new
items that need the operator. The comparison uses Myers' algorithm with bounds:
in 3,000 random trials against an independent reference it reproduced both texts
with the minimal number of edits, the worst cases within its bounds took 12 to 18
milliseconds, two 262,144-character results compared in 54 milliseconds, and
texts too long or too different are declined at once.

The reviewer of revisions 4 to 6 reviewed the batch and confirmed four defects,
all fixed and then checked again by that reviewer:

- **Medium:** an opened comparison, like the reviewer's answer and the review
  task's timeline, closed by itself on every live refresh. Opened sections and
  scrolled text now keep their state across refreshes.
- **Medium-low:** moving quickly between run pages could leave the page on
  "Loading…", because a slower load of the page just left replaced the one
  shown. Loads for a page no longer shown are dropped.
- **Low:** "Notify me" disappeared, taking focus with it, when the browser's
  permission prompt was denied. It now stays, disabled, with the reason.
- **Low:** a truncated result had no comparison and no explanation. It now says
  so, and a truncated earlier result is skipped for the one before it.

From its other notes, more than three new items now end with an "and N more"
notification, an item absent for less than two minutes, as during a controller
restart, does not notify again, and the toggle keeps one label with a pressed
state. It found no way for text to reach the page as HTML.

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
