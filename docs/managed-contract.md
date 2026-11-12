# Managed operator contract

Revision 6. Revision 1 defined the first local slice: the console, recurring
dispatch, readiness, recovery and the observation bridge. Revision 2 kept every
revision 1 behavior and added worker discovery, workflow editing and archiving,
run cancellation and release, run timelines, the activity log, attention items,
reliability statistics, live updates and an indexed store. Revision 3 kept every
revision 2 behavior and added workers on other machines (section 7.1), wall-clock
schedules (section 14) and operator review of results (section 15). Revision 4
kept every revision 3 behavior and added reviewer agents (section 15.1), rework of
rejected results (section 15.2) and the workspace branches of runtime agents
(section 10.1). Revision 5 kept every revision 4 behavior and added readiness for
runtime agents whose host runs on this machine (section 3.1). Revision 6 keeps
every revision 5 behavior and adds a capacity per worker agent, so that a
runtime agent works on several tasks at once, and scheduler passes that never
wait for a slow Peerspan call (section 4). The store of revisions 5 and 6 is
version 4, unchanged. Additions are marked "(rev 2)" to "(rev 6)" where they
extend an earlier section. Fork decisions are recorded in
[managed-decisions.md](managed-decisions.md) and cited as `MGD-n`.

## 1. Process and persistence

Node 24 is required. `node managed/cli.mjs serve --state DIR --port PORT`
starts one loopback HTTP console and scheduler. Defaults are
`~/.local/state/peerspan-managed` and port 4310. State is private, SQLite lives
outside Git and is accessed on a worker thread. A process lock refuses a second
writer to the same state directory. Restart keeps connections, workflows, task
IDs, immutable submission payloads and results. State permissions are 0700/0600.

The CLI supports `serve`, `token --state DIR`, `status --state DIR`, `connect`,
`disconnect`, `observe`, `unobserve` and `doctor` (section 7). Connection
configuration is operator-local only: no HTTP route registers, changes or removes
a connection or an observation. Configuration commands may run while the
controller is serving; a change takes effect at the next scheduler tick without a
restart. Secrets are never returned by HTTP. `PEERSPAN_BIN` selects an
executable; invocation uses argument arrays, never a shell. `MANAGED_TICK_MS` may
shorten polling for acceptance tests (minimum 100 ms; default 10000 ms).
Production task execution uses Peerspan only.

(rev 2) On SIGTERM or SIGINT the controller stops scheduling, closes the listener
and every open stream, abandons Peerspan subprocesses it is still waiting for, and
exits 0 within 5 seconds. Work interrupted this way is reconciled after the next
start under the same task identities (section 4).

(rev 2) Times the controller records never decrease while the system clock is
stepped back by less than ten minutes, as a time sync or a resumed virtual
machine does: the controller keeps using the newest time it has recorded,
across a restart too, until the system clock passes it. A larger step back is
taken as a deliberate correction and followed.

(rev 3) For conformance only, `MANAGED_CLOCK_FILE=PATH` names a file holding a
whole number of milliseconds, possibly negative, that the controller adds to the
system clock for every time it uses: recorded times, `nextRunAt`, schedules,
deadlines and the daily cap's UTC day. The controller reads the file again at
least every 100 milliseconds; a change takes effect at the next scheduler pass,
which starts within one second: while the variable is set, passes start at
least once a second whatever `MANAGED_TICK_MS` says. A missing or unreadable file, or content other
than an optional `-` and 1 to 15 digits with optional surrounding whitespace,
means 0. The rule above about steps back applies to the adjusted clock.

(rev 2) The store carries a schema version. (rev 4) The current version is 4, and
version 4 state is created directly. Version 1 state (section 13) and version 2
and 3 state are migrated in place, in one transaction, the first time a revision 4
command opens them; connections, observations, workflows, runs, task IDs,
submission payloads, results and the activity log are retained with their IDs.
Before it migrates, the command saves a copy of the database as
`managed.vN-backup.sqlite`, N being the version it found, in the state
directory, with the same private permissions. Migrated workflows from version 1
or 2 have `schedule` null and `review` `none`; migrated workflows have
`reviewerId` and `reviewCriteria` null, `reworkLimit` 0 and `reworkPending` null;
migrated runs have `attempt` 1 and `reworkOf` null, need no review unless version
3 recorded that they do, and need no agent review; a verdict that version 3
recorded has `reviewedBy` `operator`. State written by a newer
schema is refused with a nonzero exit and is not modified.

## 2. HTTP contract

The server binds 127.0.0.1. Host must be localhost or 127.0.0.1 with the configured
port; unexpected Host is 403. All responses are no-store and noindex. The console
requires the private access token from `token`. `POST /api/login` accepts
`{token}` from the same Origin and sets an HttpOnly SameSite=Strict session
cookie; invalid token is 401. The token itself is not put in URLs, logs or Git.
Bearer authentication with that token also permits API operations. Browser
mutations require exact same Origin; disallowed Origin is 403 even with a valid
cookie. The authenticated root is a static console; unauthenticated root shows
only the sign-in form. Assets contain no customer state. JSON body max 64 KiB.
Requests with unknown fields or invalid values receive 400. No CORS access.

(rev 2) A request to `/api/` whose `Sec-Fetch-Site` header is `cross-site` or
`same-site` is 403, with or without credentials. Errors are JSON `{error}`: 400
for an invalid body, query or request target, 401 without authentication, 403 for a refused Host,
Origin or fetch site, 404 for an unknown route or record, 409 when the record's
current state does not permit the operation, and 413 for an oversized body.

`GET /health` returns `{ok:true}` without state. Authenticated endpoints:

- `GET /api/snapshot`: `{connections,workflows,runs,observed,attention,activity,
  archived,meta}` (section 8).
- `POST /api/workflows`: JSON `{name,connectionId,instructions,intervalMinutes,
  maxRunsPerDay,acceptanceMinutes,enabled}`; name 1–100 chars, instructions 1–12000
  chars, interval 1–10080 minutes, cap integer 1–1000, acceptance 1–1440 minutes,
  enabled boolean. Returns 201 with the created workflow object. Paused by
  default if enabled omitted. Unknown connection is 400. (rev 3) The body may
  also have `schedule` (section 14) and `review` (section 15). Exactly one of
  `intervalMinutes` and a non-null `schedule` is required: both, or neither, is
  400. At creation, `schedule` null beside `intervalMinutes` means no schedule.
  (rev 4) The body may also have `reviewerId`, `reviewCriteria` (section 15.1)
  and `reworkLimit` (section 15.2). Instructions that contain NUL (U+0000) are
  400, because they travel as one command-line argument, which cannot carry it.
- `POST /api/workflows/:id/pause`: prevents new dispatch, does not interrupt an
  active task. `resume` enables dispatch and resets failure circuit. `run` sets
  next eligible time to now but never bypasses paused state, caps or readiness.
  Each accepts an empty JSON object and returns the workflow object, 404 if absent.
- (rev 2) `PATCH /api/workflows/:id`, `POST /api/workflows/:id/archive` and
  `restore`: section 9.
- (rev 2) `GET /api/runs`, `GET /api/runs/:id`, `POST /api/runs/:id/cancel` and
  `abandon`: section 10. (rev 3) `POST /api/runs/:id/review`: section 15. (rev 4)
  `POST /api/runs/:id/review/cancel` and `POST /api/runs/:id/review/abandon`:
  section 15.1.
- (rev 2) `GET /api/activity`: section 11. `GET /api/events`: section 12.
- `POST /api/logout`: removes the console session cookie.

There is no `DELETE` route. Workflows are archived, never deleted, so run history
and daily dispatch counts keep their references (MGD-3).

## 3. Readiness

Every Peerspan subprocess must request machine-readable output using the global
`--json` flag, including adapter connection, task submission and inspection.
Readiness requires `peerspan --state WORKER_HOST_DIR --json status` reporting a
responding daemon, matching host and agent, and a matching session/adapter with
connection ready; `adapter connection ADAPTER` must report the same adapter and
session, state ready, channel verified and nonempty channel_verified_at. A valid
JSON status with exit code 1 may still be used because attention can be historical.
An error or changed pinned identity blocks new dispatch and remains visible.
Upstream `service.active` describes the installed user-service supervisor, not
whether the selected daemon answers. A verified standalone daemon remains ready
when this value is false; the readiness reason must then include an advisory that
the user service is inactive. A nonresponding daemon (status exit 2), malformed
status or an unverified channel always blocks dispatch. This distinction follows
the upstream CLI status contract and applies equally to private test hosts.

(rev 2) Readiness is `{ready,code,reason,checkedAt,since,hints}`. `reason` is a
sentence for the operator; `code` is stable and is the first row below that
applies. `since` is when `ready` last changed (the first check after a start
counts as a change only when the value differs from the one last recorded).
(rev 3) Readiness also has `directoryAt`, which is null except for remote
connections. The table and the rules below apply to file and agent mode; a
remote connection, whose worker host is on another machine, is checked as
section 7.1 says instead.

| `code` | `ready` | Applies when |
| --- | --- | --- |
| `worker_state_invalid` | false | File mode only: the worker state file is missing, unreadable or not the documented JSON. |
| `identity_changed` | false | The worker state file names another host, agent or host directory than the registration, or the status `host_id` differs from the pinned host. |
| `peerspan_unavailable` | false | The Peerspan executable cannot be started. |
| `peerspan_incompatible` | false | The executable rejects the global `--json` flag: exit 2 with `unexpected argument '--json'` on stderr. |
| `daemon_not_running` | false | Any other status exit 2. |
| `status_invalid` | false | Status exits with another code than 0 or 1, is not JSON, or lacks `host_id`, a boolean `service.active`, an `attention` array or an `agents` array. |
| `sender_unavailable` | false | The sender host's status cannot be read: any outcome other than exit 0 or 1 with valid status JSON. |
| `sender_is_worker` | false | The sender status `host_id` is the pinned worker host. A Peerspan host cannot submit a task to itself: it answers that submission as not found. |
| `agent_missing` | false | The pinned agent is not in `agents`. |
| `runtime_disabled` | false | (rev 5) Agent mode, a runtime agent (section 3.1): the worker host's runtime switch is off. |
| `runtime_unavailable` | false | (rev 5) Agent mode, a runtime agent: the worker host's runtime does not answer, or its report cannot be read. |
| `runtime_credential_missing` | false | (rev 5) Agent mode, a runtime agent: its launch profile has no credential. |
| `ready_runtime` | true | (rev 5) Agent mode, a runtime agent: none of the rows above applies. |
| `session_not_ready` | false | No candidate session of the agent has `connection` `ready`. |
| `channel_unverified` | false | A candidate is ready in status, but no candidate's `adapter connection` reports the same adapter and session, `state` `ready`, `channel` `verified` and a nonempty `channel_verified_at`; or that command fails. |
| `ready_service_inactive` | true | All evidence holds and `service.active` is false. |
| `ready` | true | All evidence holds and `service.active` is true. |

Dispatch needs the sender host as well as the worker. Every check also reads
`status` of the connection's sender state (with no `--state` argument when the
connection has none), together with the worker's status. Only its `host_id` is
used; sender attention items are not hints.

In file mode the only candidate is the session and adapter named by the worker
state file, and its `status` and `adapter connection` are read together, so
that both describe the same moment. In agent mode (section 7) every session of
the pinned agent that has an `adapter_id` is a candidate; there `adapter
connection` is invoked only for candidates whose status `connection` is
`ready`, in ascending session ID order, for at most four of them, stopping at
the first that is verified.

Until a connection's first check after a start has finished, its readiness is
`{ready:false,code:"checking",checkedAt:null,hints:[],directoryAt:null}`, (rev 5)
with `runtime:null`, with the
`since` last recorded (null for a new connection); `checking` raises no attention
item and records no activity.

`hints` lists at most ten upstream attention items of the worker host's status,
in the order status reports them, as `{kind,command}`. `kind` is the upstream
attention kind when it matches `^[a-z_]{1,64}$` (other items are skipped).
`command` is the upstream suggested command when it starts with `peerspan `, is
at most 200 printable ASCII characters and contains no `/` or `\`; otherwise it
is null. The upstream `detail` and `subject` texts are never returned. Hints are
advice: they never change `ready`. They are an empty array whenever status could
not be read.

### 3.1 Runtime agents (rev 5)

A **runtime agent** of the upstream [runtime agent contract](runtime-agent-contract.md)
is a registered agent with a launch profile: its host runs each of its tasks in
the host's runtime, in a microVM on a fork of a peerfs branch, and never hands
them to an attached session (MGD-13). Such an agent has no session to check, so
in agent mode readiness follows its launch profile and the host's runtime
instead. Senders submit to it, and the controller dispatches, recovers and
cancels its runs, exactly as for any agent.

In agent mode, once the rows of section 3 up to `agent_missing` do not apply,
every check also runs `agent runtime show` with the global `--json` flag and no
agent argument against the worker host state: the host's launch profiles, as a
JSON array. Then:

- An exit 0 with a JSON array that has an entry whose `agent_id` is the pinned
  agent makes the agent a runtime agent, with the first such entry as its
  launch profile. The check then runs `runtime show` with
  the global `--json` flag against the worker host state, and `code` is the first
  of these that applies: `runtime_disabled` when that command exits 0 with a JSON
  object whose `enabled` is false; `runtime_unavailable` when it exits otherwise,
  its output is not such an object, `enabled` is not a boolean, or `runtime` is
  not an object without an `error` field, which includes a `runtime show` that has
  not exited within 5 seconds (upstream waits up to 35 seconds for a runtime that
  does not answer, and a check must not hold the scheduler that long);
  `runtime_credential_missing` when the
  profile's `credential` is not true; and otherwise `ready_runtime`. Sessions are
  not read and `adapter connection` is not invoked for a runtime agent.
- An exit 0 with a JSON array that has no entry for the pinned agent, or an exit
  2 with `unrecognized subcommand` on stderr (an executable older than runtime
  agents), means the agent is not a runtime agent: readiness follows the session
  rows of section 3, as before.
- Any other outcome is `status_invalid`, with a reason that says the host's
  launch profiles could not be read; that includes an exit 2 with `unexpected
  argument '--json'`, which cannot happen after the same executable's `status`
  accepted the flag.

The `reason` of `ready_runtime` says that tasks run in the host's runtime; when
the worker status's `service.active` is false, it also carries the advisory of
section 3, and the code stays `ready_runtime`. Hints are the worker host's, as
for any agent-mode connection.

Readiness gains `runtime`, which is null except with the four codes of this
section, for which it is
`{fromBranch,network,cpus,memoryMib,timeoutSeconds,maxRuns}` from its launch
profile (`from_branch`, `network`, `cpus`, `memory_mib`, `timeout_seconds` and
`max_runs`), each value as the profile gives it when it is a string or an
integer, and null otherwise. No other profile field, and never a path, is
returned. A change of `runtime` is a readiness change.

File mode always follows its worker state file. Remote mode (section 7.1) is not
changed: upstream's directory does not tell a sender whether an agent runs in a
runtime, and it lists a runtime agent without a session as not `connected`, so a
remote runtime agent is `session_not_ready`.

(rev 6) While a runtime agent is `ready_runtime`, it may hold as many unresolved
tasks as its launch profile's `max_runs` (section 4), because its host runs
each of them in its own microVM on its own fork. Their output ends with the
branch line of section 10.1.

## 4. Dispatch and recovery

One unresolved run per workflow and one per target worker agent across
managed workflows. A run is unresolved while submitting, queued or running.
New dispatch requires an enabled due workflow, capacity under its UTC-day cap,
and a verified worker. Each new reserved run counts toward the cap, including
failed submissions. Pausing never abandons an unresolved run.

(rev 2) The target is the worker agent: its host and agent. Revision 1 also
keyed it by the sender state location, so two connections that reached one agent
through different senders, or named one sender state in two ways, could hold
that agent twice. Sender state no longer distinguishes targets (MGD-6).

(rev 2) When several due workflows share a free target, the one whose
`nextRunAt` is oldest is dispatched first. Both exclusion rules are enforced by
the store itself, so no interleaving of operator requests and scheduler work can
reserve a second unresolved run for a workflow or a target. An operator request
never waits for a Peerspan subprocess: every route answers from stored state,
and the effect of `run`, `resume`, `cancel` and an enabled creation is picked up
by a scheduler pass that starts within one second.

(rev 6) **Capacity.** A target's capacity is how many unresolved tasks, runs and
review tasks together, its worker agent may hold at once. It is 1, except for a
runtime agent (section 3.1) whose connection's readiness is `ready_runtime` and
whose `runtime.maxRuns` is an integer from 1 to 64: then it is that number
(MGD-14). A target is free while it holds fewer unresolved tasks than its
capacity, and the store still enforces the limit, so no interleaving can reserve
more. When several connections name one worker agent, the capacity is the
largest any of them reports while it is ready. Tasks that a target already
holds are never affected when its capacity falls, as when the profile changes or
the agent stops being ready: they finish as before, and no new task is reserved
for that target until it holds fewer than its capacity. One unresolved run per
workflow stays the rule whatever the capacity.

(rev 6) **Slow Peerspan calls.** A scheduler pass waits at most 2 seconds, or one
scheduler interval when that is shorter, for the readiness checks,
reconciliations and submissions it starts itself, and never for one still
running from an earlier pass. It then dispatches with the readiness each
connection last recorded, but reserves a workflow's run only on readiness from a
check that began after the run became due: after its `nextRunAt`, its rework
becoming due, and the operator's latest change of the workflow (creation, edit,
`resume`, `run` or `restore`), whichever is latest. A review task is likewise
reserved only on readiness from a check that began after its run finished. A
change made before a run is requested is therefore always seen, and a worker
whose check is still running gets no new task, keeping its blocked reason,
until such a check has ended. A check or reconciliation still running
goes on beside later passes; no second one for the same connection or task
starts until it has ended. A slow or hanging Peerspan call therefore delays only its own
connection or task, however many such calls there are: never another
connection's readiness, another task's reconciliation, a cancellation, or
dispatch to a ready worker. Each pass starts one interval after the previous
one started, or as soon as it ends when it took longer. Until a connection's
first check after a start has ended its readiness stays `checking` (section 3).

Before any submission, persist a task ID (`task_` plus 32 hex digits) and exact
input, peer, agent, deadline and sender state. Submit using `task submit --peer
HOST --agent AGENT --task ID --input=TEXT --deadline RFC3339`. The deadline bounds
acceptance, not already-running execution. Poll with `task inspect --peer HOST ID`.
(rev 2) The input travels as the single argument `--input=TEXT`. The upstream
parser reads a separate value that begins with a hyphen as an option and exits
2, so revision 1's `--input TEXT` could never send instructions such as
`- first step`. Every other value keeps its own argument.
On uncertain delivery or restart inspect the same ID first. Only a genuine
not-found inspection permits resubmitting the SAME ID and exact payload. Other
inspection errors retain the run and show a problem, never create replacement
work. A run already queued/running is never resubmitted merely because inspect
temporarily fails. Recovery does not require the worker to still be ready.

(rev 2) A run is submitted once without a preceding inspection: in the scheduler
pass that reserved it, where its task ID was just created and no earlier
submission can exist. Every later attempt for that run, in the same process or
after a restart, inspects first.

Accepted remote states queued/running/succeeded/failed/cancelled/rejected/expired
are retained. A submit_state rejected is a terminal rejected result. Successful
completion resets failure count; any other terminal result increments it. After
three consecutive failures the workflow pauses with a visible failure reason.
Completion schedules the next run after the interval, with failure delay at least
one minute. A successful run is only the remote agent's report, not human approval.
No automatic cancellation or task redirection.

(rev 2) Two terminal results leave the failure count unchanged, because they
record an operator's decision rather than a worker's failure (MGD-1, MGD-2): a
run that ends `cancelled` after the operator requested its cancellation, and an
`abandoned` run (section 10). Both still schedule the next run after the
interval, at least one minute later.

(rev 3) A workflow with a `schedule` takes its next run time from its schedule
instead of an interval, as section 14 says; every other rule of this section,
the caps and the failure circuit included, applies to it unchanged. An operator's
review verdict (section 15) never changes the failure count, `nextRunAt` or
dispatch. (rev 4) A rejection may make a rework due (section 15.2); it still
changes neither the failure count nor `nextRunAt`.

(rev 4) A run's review task (section 15.1) is a Peerspan task of its own. It is
persisted before it is sent, submitted, inspected, recovered, cancelled and
released by the rules of this section and section 10, under its own task ID,
and its result is final only with its final event, as for a run. Its target is
the reviewer's worker agent, so the target rule covers it too: a worker agent
holds at most one unresolved task, whether that task is a run or a review task
(rev 6: at most its capacity).
A review task does not hold its run's workflow, is not counted by the daily cap,
and never changes the failure count, `nextRunAt` or dispatch of the workflow.
Review tasks are reserved before runs in each scheduler pass, so that results
already produced are checked before new work starts.

## 5. Observation bridge

`observe --state DIR --name NAME --directory DIR` registers a private external
controller directory containing config.json, state.json and events.jsonl. Only
config.enabled and state cycle/phase/lastTickAt/error/task/lastBatch summaries are
read. HTTP exposes no filesystem paths. Observed controllers have no action
buttons or mutation endpoints; their files and services are never changed. Missing
or malformed sources are visible as unavailable, not healthy. The bridge is local
configuration, excluded from Git, and does not claim ownership of external tasks.

## 6. Wire fixtures for conformance

Status JSON uses `{host_id,service:{active:true|false},attention:[],agents:[{id,name,
sessions:[{id,adapter_id,connection:"ready"}]}]}`. Adapter connection uses
`{adapter_id,session_id,state:"ready",channel:"verified",channel_verified_at:
RFC3339}`. Other upstream fields may be present. Status exit 1 requires a valid
attention array (possibly populated with historical errors); malformed JSON is
never readiness. All IDs in fixtures follow upstream host_ plus 64 hex and
agent_/adapter_/session_ plus 32 hex conventions.

(rev 2) The fake answers `status` for the sender state directory with another
`host_id` than the worker's, and no agents. An attention item is
`{kind,subject,detail,command}`, all strings. A
status that cannot reach its daemon exits 2 and prints `{"daemon":"not running",
"state":PATH,"service":{...}}`. An executable older than the global flag exits 2
with `error: unexpected argument '--json' found` on stderr and nothing on stdout.

(rev 3) `agents [--network ID] [--refresh]` with the global `--json` prints the
sender host's directory, as in the upstream [launch contract](launch-contract.md):
`{network_id,refreshed_at,reachable,mine,inbound,hosts}`. `reachable` entries are
`{address,host_id,agent_id,connected,host_state,actions,endpoint,description}`,
`mine` entries are `{address,host_id,agent_id,connected,endpoint,description}`,
and `hosts` entries are `{host_id,person_id,person_label,state,refreshed_at,
error}`, where `state` is `ok`, `error`, `unsupported` or `pending` and
`refreshed_at` is null or RFC 3339. `connected` is true only when the agent has an
attached session whose adapter holds a valid lease and whose channel is verified.
`actions` lists action names such as `message.append` and `task.submit`. A
directory keeps a host's previous agents when a refresh of that host fails, so
`connected` can be stale while that host's `state` is `error`. A host in no
network, or in several when `--network` is omitted, exits 1 with an `error:` line
on stderr. Other upstream fields may be present.

(rev 5) `agent runtime show` with the global `--json` flag and no agent argument
prints a JSON array of the host's launch profiles in agent ID order, each
`{agent_id,harness,harness_dir,from_branch,network,cpus,memory_mib,
timeout_seconds,max_runs,credential}`, where `harness_dir` is an absolute path and
`credential` a boolean. `runtime show` with the global `--json` flag prints
`{enabled,socket,runtime,rule}`: `enabled` is a boolean, `socket` a path or null,
and `runtime` null while the switch is off, the runtime's report
`{version,image,max_cpus,max_memory_mib,max_seconds,max_concurrent_runs,running,
peerfs,max_network}` when it answers, or `{error}` with a sentence when it does
not. An executable older than runtime agents exits 2 for `agent runtime show`
with `error: unrecognized subcommand 'runtime'` on stderr and nothing on stdout.
Other upstream fields may be present.

Submission and inspection return `{peer_host_id,request:{task_id,target_agent_id,
input,deadline},submit_state:"accepted",status:{state:"running",last_event:2},
error:null}`. Status may be null while submit_state is unknown. As defined in
the upstream [task contract](task-contract.md), status records contain no output.
Completion output comes from `task events --peer HOST ID --after N`, which returns
an array of `{sequence,kind,state,message,output,created_at}`. The terminal
succeeded/failed event contains the actual output string. Status can run ahead
of locally stored events: retry missing or unavailable output under the same
task identity, including after restart. Do not finalize a succeeded/failed run,
release its target reservation, increment failure count, or schedule its successor
until its matching final output event is retained. Fetching after last_event - 1
is permitted to avoid scanning an unbounded progress history. Genuine missing
task is CLI exit 1 and stderr
`error: host daemon: not found\n`. Other nonzero exits are transport/inspection
failure. A fake process may log argument arrays to a private fixture directory
to establish byte-identical replay without reading the implementation database.

(rev 2) `task cancel --peer HOST ID` returns the same record with `cancel_state`
(`null`, `"unknown"` or `"sent"`); its status record carries `cancel_requested`.
Event kinds are `queued`, `accepted`, `rejected`, `progress`, `cancel_requested`,
`succeeded`, `failed`, `cancelled` and `expired`. A `progress` event's and a
`rejected` event's `message` is text; `output` is null except on `succeeded` and
`failed`. A record's `error` is null or a string.

Observation entries are `{id,name,available,enabled,cycle,phase,lastTickAt,error,
task,lastBatch}`. task is null or `{id,key,state,lane}`; lastBatch is null or
`{key,status,articlesAdded,dossiersAdded}` where counts are numbers. Configuration
paths and reportPath are not returned. Unavailable entries use available false,
phase "unavailable", with a generic error. An empty console has empty arrays;
connections expose id, name, hostId, agentId and readiness. HTTP auth failures are
401 JSON and mutating validation failures are 400 JSON. CLI connect/observe
print JSON with the newly registered id; token prints only the token plus newline.

## 7. Workers and local commands (rev 2)

A connection names one worker agent and the sender host state used to submit to
it. In file and agent mode the worker's Peerspan host has its state directory on
this machine; (rev 3) in remote mode (section 7.1) it is on another machine and
only the sender's state is read. Host and agent are pinned when connecting;
changing either requires a new connection.

`connect --name NAME --worker-state FILE [--sender-state DIR]` is file mode, as
in revision 1. The worker state JSON contains host_dir, host_id, agent_id,
adapter_id and session_id; session and adapter may change only for the same
identities.

`connect --name NAME --agent AGENT [--host-state DIR] [--sender-state DIR]` is
agent mode (MGD-4). It runs `status` once against `--host-state` (omitted: the
Peerspan default state, with no `--state` argument) and accepts exit 0 or 1 with
valid status JSON. AGENT matches an agent's `id` or its `name` exactly. No match,
or two agents with that name, is an error that registers nothing; the message
tells the operator to pass the agent ID. The registration pins the status
`host_id` and the agent ID and stores no session or adapter: readiness then
follows whichever session of that agent is ready and verified (section 3), so an
attachment may change without operator action. Exactly one of `--worker-state`
and `--agent` is required; `--host-state` is valid only with `--agent`.

Both forms also read the sender host's status once. When it is readable and
reports the worker's own `host_id`, the registration is refused: sender and
worker must be two hosts. A sender whose status cannot be read is accepted, and
readiness reports it as `sender_unavailable` until it answers.

Both forms print `{id,name,hostId,agentId,mode}` with `mode` `file` or `agent`.
NAME is 1 to 100 characters after trimming. (rev 3) Exactly one of
`--worker-state`, `--agent` and `--remote` (section 7.1) is required.

`disconnect --id ID` removes a connection. It is refused, with a nonzero exit and
nothing changed, while a workflow that is not archived uses the connection or one
of its runs is unresolved. Retained runs keep their history. (rev 4) A workflow
uses a connection as its worker or as its reviewer, and a review task on the
connection that is unresolved refuses it as a run does. `unobserve --id ID`
removes an observation registration and never touches the observed directory.
Both print `{id,removed:true}`; an unknown ID is a nonzero exit.

`doctor` prints one line per check, each starting with `ok ` or `problem `, and
exits 0 only when no line starts with `problem `. It checks, in order: Node 24 or
later; Linux; the `flock` utility; the state directory and its files being
private (0700/0600) when they exist; the Peerspan executable starting; and that
executable accepting the global `--json` flag. The last two are one probe,
`--json status` with no `--state` argument: any exit status shows that the
executable starts, and only exit 2 with `unexpected argument '--json'` on
stderr fails the `--json` check, so a daemon that is not running is not a
problem here. It creates no state, starts no daemon, changes nothing and never
prints the access token. A failing check does not stop the later ones, except
that the `--json` check is reported as a problem when the executable did not
start.

Every local command prints errors on stderr as one line, with exit 1; a second
writer refused by the process lock exits 73.

### 7.1 Workers on other machines (rev 3)

`connect --name NAME --remote AGENT [--network ID] [--sender-state DIR]` is
remote mode (MGD-7). It registers a worker agent whose host is on another
machine, using only what the sender host knows: its directory of reachable
agents. Nothing of the worker host is read. `--host-state` is not valid with
`--remote`, and `--network` is valid only with it.

Upstream `agents` lists only agents whose names are addressable (lowercase ASCII
letters, digits, `.`, `_` and `-`, as `attach` creates them), so only such an
agent can be registered or checked in remote mode.

Registration reads the sender's `status` and runs `agents --refresh`, with
`--network ID` when given, both against the sender state. The status must exit 0
or 1 with valid status JSON (section 3), and `agents` must exit 0 with the
directory JSON of section 6; otherwise the command fails and registers nothing.
AGENT matches each `reachable` and `mine` entry whose `address` or `agent_id`
equals it exactly; entries with the same `host_id` and `agent_id` are one match.
A directory without the arrays of section 6 is refused. No match is an error that tells the operator to run
`peerspan agents` and pass an address or agent ID it lists; more than one match
is an error that asks for the agent ID; a match on the sender's own host (its
`host_id` is the sender status `host_id`) is refused, as in agent mode, because
sender and worker must be two hosts. The registration pins the entry's
`host_id` and `agent_id` and the directory's `network_id`, and prints
`{id,name,hostId,agentId,mode}` with `mode` `remote`.

A check of a remote connection reads the sender's `status` and runs `agents
--network NETWORK_ID` with the pinned network, both against the sender state and
together. The connection's first check after a start passes `--refresh` to
`agents`, and so does any check that begins at least 60 seconds after the start
of that connection's previous check that passed it; no other check passes it.
A connection registered while the controller serves gets its first check, which
passes `--refresh`, at the next scheduler tick. The 60 seconds have passed when
either the elapsed time or the controller's clock of section 1 has advanced by
60 seconds, so that a step back of the clock never suspends refreshes.
`code` is the first row that applies:

| `code` | `ready` | Applies when |
| --- | --- | --- |
| `peerspan_unavailable` | false | The Peerspan executable cannot be started. |
| `peerspan_incompatible` | false | Either invocation exits 2 with `unexpected argument '--json'` on stderr. |
| `sender_unavailable` | false | The sender's status cannot be read, as in section 3. |
| `sender_is_worker` | false | The sender status `host_id` is the pinned worker host. |
| `directory_unavailable` | false | `agents` exits other than 0, or its output is not JSON whose `network_id` is the pinned network and whose `reachable`, `mine` and `hosts` are arrays. |
| `agent_missing` | false | No `reachable` or `mine` entry has the pinned `host_id` and `agent_id`. |
| `host_unreachable` | false | `hosts` has no entry for the pinned host, or that entry's `state` is not `ok`: the sender could not reach the worker host when it last tried. |
| `not_authorized` | false | The matching entry is in `reachable` and its `actions` does not contain `task.submit`. A `mine` entry is another host of the sender's own person, which reaches every agent. |
| `session_not_ready` | false | The matching entry's `connected` is not true. |
| `ready` | true | All of the above hold. |

When a `reachable` and a `mine` entry both match, the `reachable` entry is used.
(rev 5) A remote connection's readiness has `runtime` null.
`directoryAt` is the `refreshed_at` of the pinned host's `hosts` entry in the
directory of the pinned network that the check read, whatever the `code`,
written as an RFC 3339 UTC time; it is null when there is no such entry or no
such directory, or when that value is not an RFC 3339 time.
`reason` for `session_not_ready` and `ready` says that the evidence is the
sender's directory as of that time. `hints` are the sender host's attention
items, by the rules of section 3, because the worker host's status is not
available on this machine; they are empty when the sender's status could not be
read.

Remote readiness is weaker evidence than file or agent mode: a directory entry
is the sender's latest view, which upstream refreshes when the worker host
announces a presence change, every 5 minutes, and on demand. A task sent to an
agent whose session has just gone waits at the worker host until it is accepted
or its acceptance deadline passes. Dispatch, recovery, cancellation, `abandon` and
`disconnect` work for remote connections exactly as for the other modes, with the
same `task` commands against the sender state.

## 8. Snapshot (rev 2)

`GET /api/snapshot` returns the following. No response of any route contains a
filesystem path, the access token, a session cookie value, a state directory
location, or upstream attention `detail` or `subject` text.

- `connections`: `{id,name,hostId,agentId,mode,readiness}` for each connection
  that is not removed, oldest first. (rev 3) `mode` is `file`, `agent` or
  `remote`. (rev 6) Connections also have `capacity`, the capacity this
  connection's readiness gives its worker agent (section 4; 1 unless it is
  `ready_runtime` with a `runtime.maxRuns` from 1 to 64), and `activeTasks`, how
  many unresolved tasks, runs and review tasks of every workflow, its worker
  agent holds.
- `workflows`: every workflow that is not archived, oldest first, as
  `{id,name,connectionId,instructions,intervalMinutes,maxRunsPerDay,
  acceptanceMinutes,enabled,nextRunAt,failureStreak,blockedReason,createdAt,
  updatedAt,pausedBy,recent,stats}`, (rev 3) with `schedule` and `review`
  (sections 14 and 15), (rev 4) and with `reviewerId`, `reviewCriteria`,
  `reworkLimit` and `reworkPending` (sections 15.1 and 15.2). `intervalMinutes`
  is null for a workflow with a schedule,
  and `schedule` is null for one with an interval. `pausedBy` is null while
  enabled, and otherwise `operator` (created paused, paused, or restored) or
  `failures` (the failure circuit). `recent` is the workflow's latest 20 runs,
  newest first, as `{id,state,createdAt,finishedAt}`, (rev 3) with the run's
  `review`.
- `stats` covers the trailing 7 days (168 hours): `{windowDays:7,runs,succeeded,
  failed,successRate,averageSeconds,interventions,unattendedRuns}`, (rev 3) with
  `awaitingReview`. `runs` counts
  runs created in the window. `succeeded` and `failed` count runs that finished
  in the window, `failed` being every terminal state other than `succeeded`,
  except the two operator results of section 4. (rev 3) A `succeeded` run whose
  `review` is `pending` is in neither count, and one whose `review` is
  `rejected` counts as `failed`. `successRate` is
  succeeded/(succeeded+failed), or null when that sum is 0. `averageSeconds` is
  the mean of finishedAt minus createdAt over the window's runs that count as
  succeeded, in
  whole seconds, or null. `interventions` counts the window's operator activity
  entries for the workflow other than `workflow.created` (rev 3) and
  `run.reviewed`, because reviewing a result is the expected work of a reviewed
  workflow, not a correction. `unattendedRuns` counts
  the workflow's terminal runs, of all time, that finished after its latest such
  intervention (after its creation when there is none). (rev 3) `awaitingReview`
  counts the workflow's runs, of all time, whose `review` is `pending`.
- `runs`: the newest 100 runs of all workflows, archived ones included, newest
  first, as `{id,workflowId,workflowName,taskId,state,output,outputTruncated,
  error,reason,progress,cancelRequestedAt,createdAt,updatedAt,startedAt,
  finishedAt}`. In a snapshot `output` is at most its first 2,000 characters, and
  `outputTruncated` says whether the retained output is longer; the retained
  output is in the run's detail (section 10). `error` is null or a fixed sentence
  about a delivery or status problem. `reason` is null or what the sender daemon
  or the receiver stated for a `rejected`, `expired`, `failed` or `cancelled`
  submission: the record's `error` or the terminal event's `message`, at most
  2,000 characters, with control characters removed. `progress` is null or the
  latest `progress` event's message, at most 300 characters. `startedAt` is null
  until the task is known to be running, and is the `accepted` event's time when
  that event is retained, kept between the run's `createdAt` and the time the
  controller observed it, because that event carries another host's clock.
  `finishedAt` is null until the run is terminal, and is then the time the
  controller retained the terminal result. (rev 3) Runs also have `review`,
  `reviewedAt` and `reviewNote` (section 15). (rev 4) Runs also have
  `reviewedBy`, `reviewTask` and `reviewFallback` (section 15.1), `attempt` and
  `reworkOf` (section 15.2), and `branch` (section 10.1). A run's `state`,
  `output`, `error`, `reason`, `progress`, times and `cancelRequestedAt` are
  always those of its own task, never of its review task.
- `observed`: section 6.
- `attention`: what needs the operator, as `{kind,severity,subject:{type,id,name},
  message,since}`; `severity` is `action`, `warning` or `info`, and entries are
  ordered by severity in that order and then by `since`, oldest first. `message`
  is a sentence for the operator. `since` is an RFC 3339 time, or null when the
  controller does not know it; null sorts last.

  | `kind` | `severity` | `subject.type` | Present while |
  | --- | --- | --- | --- |
  | `controller_error` | `action` | `controller` | The scheduler's last pass failed. `subject.id` and `name` are `controller`. |
  | `workflow_auto_paused` | `action` | `workflow` | `pausedBy` is `failures`. |
  | `worker_unready` | `action` when an enabled workflow that is not archived uses the connection, (rev 4) as its worker or its reviewer, or a run waits for a review task on it that is not yet reserved; otherwise `warning` | `connection` | Its readiness is not ready. `message` is the readiness reason and `since` its `since`. |
  | `run_problem` | `warning` | `run` | An unresolved run has a non-null `error`, (rev 4) or a run's unresolved review task has a non-null `reviewTask.error`. `subject.name` is the workflow name; `since` is when the problem first appeared. |
  | `observed_unavailable` | `warning` | `observation` | An observed entry has `available` false. |
  | `observed_problem` | `warning` | `observation` | An available observed entry has a non-null `error`. |
  | `daily_limit_reached` | `info` | `workflow` | An enabled workflow is blocked only by its daily cap. |
  | `review_pending` | `action` | `workflow` | (rev 3) A workflow, archived or not, has a run whose `review` is `pending` (rev 4) and that waits for the operator: a run that needs no agent review, or one whose agent review fell back (`reviewFallback` not null). A run that waits for its reviewer agent does not raise it. One item per workflow; `message` gives the number of such runs, the ones that wait for the operator, and `since` is the earliest of their `finishedAt`. |

- `activity`: the newest 30 activity entries (section 11), newest first.
- `archived`: `{id,name,archivedAt}` for each archived workflow, newest first.
- `meta`: `{name,version,mode,revision,schemaVersion,lastTickAt,tickSeconds,
  error,modelCostAvailable:false,modelCost,cloudProvisioning:false}`. `modelCost`
  says that model cost is unavailable. `revision` is an opaque string that
  changes whenever stored state or a readiness changes; clients compare it for
  equality only.

## 9. Editing and archiving workflows (rev 2)

`PATCH /api/workflows/:id` accepts a JSON object with at least one of `name`,
`connectionId`, `instructions`, `intervalMinutes`, `maxRunsPerDay` and
`acceptanceMinutes`, (rev 3) `schedule` and `review`, (rev 4) `reviewerId`,
`reviewCriteria` and `reworkLimit`, validated as at creation (with the
combination rules of section 15.1); any other field, `enabled`
included, is 400. It returns the workflow. An edit never changes a run that was
already reserved: its submission payload is immutable. When `intervalMinutes`
changes and the workflow has a terminal run, `nextRunAt` becomes its latest
terminal run's `finishedAt` plus the new interval; otherwise `nextRunAt` is
unchanged.

(rev 3) A body with both `intervalMinutes` and `schedule`, or with `schedule`
null, is 400. Setting `intervalMinutes` on a workflow that has a schedule
switches it to that interval (its `schedule` becomes null) by the rule above;
setting `schedule` switches it to the schedule (its `intervalMinutes` becomes
null) by the rule of section 14. Such a switch changes both values, so its
`workflow.edited` entry lists both `intervalMinutes` and `schedule`. A
`schedule` is compared after normalization (section 14), so one that lists the
same days in another order equals the current one. Changing `review` applies to
runs reserved afterwards; a run keeps the review requirement it was reserved
with. (rev 4) So does changing `reviewerId`: a run keeps the reviewer it was
reserved with. `reviewCriteria` is read when a review task is reserved, and
`reworkLimit` when a review becomes `rejected`.

`pause` and `resume` do not change `nextRunAt`: a resumed workflow runs when its
schedule says so, or when the operator also sends `run`. Every accepted `pause`,
`resume` and `run` request records its activity entry (section 11), whether or
not the workflow's state changed.

`POST /api/workflows/:id/archive` accepts `{}`. It is 409 while the workflow has
an unresolved run. It disables the workflow, removes it from `workflows`, lists
it in `archived` and keeps its runs. (rev 4) It also sets `reworkPending` to
null: no rework is dispatched for an archived workflow. Reviews of its runs go
on (section 15.1). An archived workflow is never dispatched,
and `pause`, `resume`, `run`, `PATCH` and `archive` on it are 409.
`POST /api/workflows/:id/restore` accepts `{}`, is 409 unless the workflow is
archived, and returns it paused with `pausedBy` `operator`, a failure count of 0
and its other fields as they were.

## 10. Runs (rev 2)

`GET /api/runs?workflowId=ID&before=CURSOR&limit=N` pages run history, newest
first, as `{runs,nextBefore}` with the snapshot's run shape. `limit` is 1 to 200
(default 50). `nextBefore` is null on the last page, and otherwise the `before`
value of the next page. `workflowId` is optional. An invalid query value is 400.

`GET /api/runs/:id` returns `{run,events}`. `run` has the snapshot's shape with
the retained `output` in full: at most 262,144 characters, `outputTruncated`
saying whether the remote output was longer. It also has `instructions`, the
exact input that was submitted for this run, which later edits of the workflow
do not change. `events` is the retained timeline,
ascending, as `{sequence,kind,state,message,at}` from the upstream task events;
`message` is at most 2,000 characters and `output` is never repeated there. The
controller retains events as it observes them, at most 500 per run, keeping the
newest; it may skip older `progress` events of a long task, but never the
terminal event: a run takes any final state only once that state's event, the
record's `last_event`, is retained. Events newer than the record the controller
read are left for the next read, so a final event is always taken together with
the record that reports it. A timeline fetch that fails while the task is not final is not a
run problem.

(rev 4) The detail also has `reviewEvents`, the review task's retained timeline
by the same rules, or an empty array when the run has no review task, and
`run.assignment`, the workflow's `instructions` when the run was reserved: equal
to `instructions` for a run with `attempt` 1, and without the revision request
for a rework (section 15.2). In the detail, a non-null `run.reviewTask` also has
`input`, the exact input of the review task or null before it is reserved, and
`output` and `outputTruncated`, the review task's retained output in full and
whether the remote output was longer, by the rules for a run's output: `output`
is null and `outputTruncated` false until there is an output.

`POST /api/runs/:id/cancel` accepts `{}` and asks the worker to stop an
unresolved run (MGD-1). It is 404 for an unknown run and 409 for a terminal one.
It records `cancelRequestedAt` once and returns the run; a repeat returns the run
unchanged. A cancel request never sets a terminal state by itself. The
controller then acts under the same task identity:

- It inspects the task first. For a run still `submitting`, a genuine not-found
  inspection means the sender daemon never held the task, so the run becomes
  `cancelled` and the task is never submitted. A cancel-requested run is never
  submitted or resubmitted.
- Otherwise it invokes `task cancel --peer HOST ID`, and repeats that on later
  passes until one invocation exits 0. After that it only inspects.
- The run takes its terminal state from the remote record alone: `cancelled`
  when the agent confirms, or the agent's own result when it finishes anyway.

`POST /api/runs/:id/abandon` accepts exactly `{"confirm":TASK_ID}` and releases
an unresolved run that can no longer be resolved, for example because its
worker host no longer exists (MGD-2). It is 404 for an unknown run, 409 for a
terminal one, and 400 unless `confirm` equals the run's task ID. The run becomes
`abandoned`, a terminal state that only this route sets. Its workflow and target
reservations are released, and the controller never again submits, inspects or
cancels that task. The identity stays retained and is never reused. The response
is the run. Abandoning does not stop remote work that may still be running: the
console must say so before it sends the request.

(rev 4) `cancel` and `abandon` act on the run's own task only: a run that is
terminal is 409 even while its review task is unresolved. Section 15.1 has the
routes for a review task.

### 10.1 Workspace branches (rev 4)

A runtime agent of the upstream [runtime agent contract](runtime-agent-contract.md)
works on its own peerfs branch and ends its output with a line naming that branch
(upstream RUN-11). A run's `branch` is null, or that line read as
`{name,outcome,commit,from,error}` (MGD-12). It is read from the run's retained
output when the run is `succeeded` or `failed` and the controller retained the
whole remote output (the run detail's `outputTruncated` is false), and it is null
in every other case. A snapshot's `outputTruncated`, which is also true when only
the preview is cut, does not change `branch`.

The output, without its trailing whitespace, must end with an LF, an empty line
and a last line L: that is, with `\n\nL`, where L has no LF. L is matched against
these forms in this order, and the first that matches gives `branch`; when none
matches, `branch` is null.

| L | `branch` |
| --- | --- |
| `Branch: none` | `{name:null,outcome:"none",commit:null,from:null,error:null}` |
| `Branch: NAME at commit ID`, ID being 66 lowercase hex digits | `{name:NAME,outcome:"committed",commit:ID,from:null,error:null}` |
| `Branch: NAME, unchanged from FROM` | `{name:NAME,outcome:"unchanged",commit:null,from:FROM,error:null}` |
| `Branch: NAME, not committed: ERROR` | `{name:NAME,outcome:"not_committed",commit:null,from:null,error:ERROR}` |

NAME and FROM are 1 to 255 characters without `/` or control characters, and
ERROR is 1 to 1,024 characters without control characters; a line whose parts
break these rules does not match its form. Where a form could match in more than
one way, NAME is the longest text that makes it match. The run's `output` is
unchanged: the branch line stays in it. `branch` describes the worker host's
peerfs state as the agent reported it; the controller reads no peerfs state.

## 11. Activity (rev 2)

The controller keeps an append-only activity log, newest 5,000 entries. An entry
is `{seq,at,actor,kind,workflowId,runId,connectionId,data}`: `seq` increases by
one per entry, `actor` is `operator` or `system`, absent references are null,
and `data` is null or a small object of the fields listed below. A `workflow.*`
entry carries its workflow's ID, a `run.*` entry its run's and that run's
workflow's, and a `connection.*` or `worker.*` entry its connection's.

| `actor` | `kind` | `data` |
| --- | --- | --- |
| `operator` | `workflow.created`, `workflow.paused`, `workflow.resumed`, `workflow.run_requested`, `workflow.archived`, `workflow.restored` | null |
| `operator` | `workflow.edited` | `{fields}`: the names of the fields whose values changed, sorted. An edit that changes no value records nothing. |
| `operator` | `run.cancel_requested`, `run.abandoned` | null. A repeated cancel request records nothing. |
| `operator` | `run.reviewed` | (rev 3) `{verdict}`: `accepted` or `rejected`. |
| `system` | `run.reviewed` | (rev 4) `{verdict}`: a reviewer agent's verdict (section 15.1). |
| `operator` | `review.cancel_requested`, `review.abandoned` | (rev 4) null. A repeated cancel request records nothing. |
| `system` | `review.dispatched` | (rev 4) null: a review task reserved. |
| `system` | `review.finished` | (rev 4) `{state}`: a review task's terminal state. |
| `system` | `review.fallback` | (rev 4) `{cause}`: the run's `reviewFallback`. |
| `system` | `workflow.rework_due` | (rev 4) `{attempt}`: the attempt the rework will be (section 15.2). The entry's `runId` is the rejected run. |
| `operator` | `connection.added`, `connection.removed`, `observation.added`, `observation.removed` | null |
| `system` | `run.dispatched` | null |
| `system` | `run.finished` | `{state}` |
| `system` | `run.problem`, `run.recovered` | null: a run's `error` appearing, and clearing while the run is still unresolved. (rev 4) `{task:"review"}` for its review task's `error`. |
| `system` | `workflow.auto_paused` | `{failureStreak}` |
| `system` | `worker.ready`, `worker.unready` | `{code}`: recorded when a connection's `ready` value changes, and for a new connection's first check. A restart alone records nothing. |

(rev 4) A `review.*` entry carries the reviewed run's ID and that run's
workflow's, as a `run.*` entry does. `review.cancel_requested` and
`review.abandoned` are interventions (section 8); a verdict of either actor is
not.

`GET /api/activity?before=SEQ&limit=N` pages the log, newest first, as
`{activity,nextBefore}`; `limit` is 1 to 200 (default 50) and `nextBefore` is
null on the last page.

## 12. Live updates (rev 2)

`GET /api/events` is an authenticated `text/event-stream`. It sends `retry: 3000`
and one `change` event immediately, then a `change` event whenever the snapshot's
`meta.revision` changes, at most four per second, and a comment line at least
every 20 seconds. The data of a `change` event is `{"revision":VALUE}` and
carries no other state. At most 16 streams are open at once; another request is
503. The console refetches the snapshot on a change and keeps polling at a slow
interval, because observed sources have no change signal.

## 13. Version 1 state (rev 2)

Version 1 state is `managed.sqlite` with `PRAGMA user_version` 0 and one table,
`records(kind TEXT NOT NULL, id TEXT PRIMARY KEY, body TEXT NOT NULL)`, whose
`body` is a JSON object that repeats `id`:

- `kind` `connection`: `{id,name,workerState,hostDir,hostId,agentId,senderState}`
  (file mode; `senderState` may be null).
- `kind` `observation`: `{id,name,directory}`.
- `kind` `workflow`: `{id,name,connectionId,instructions,intervalMinutes,
  maxRunsPerDay,acceptanceMinutes,enabled,nextRunAt,failureStreak,blockedReason,
  createdAt}`.
- `kind` `run`: `{id,workflowId,taskId,state,target,createdAt,updatedAt,output,
  error,retryAt,finishedAt,submission:{peer,agent,senderState,input,deadline}}`,
  `finishedAt` present only on terminal runs. Insertion order is creation order.

Migration keeps every record's ID and values, with two exceptions. A run's
`target` is not copied: the target that reserves its worker is derived from the
submission's peer and agent, as for a new run. Revision 1 let one agent hold two
unresolved runs through two senders; such runs are all kept and reconciled, and
no new run is dispatched to that agent until every one of them is resolved. A workflow's
`blockedReason` is the scheduler's current explanation, not a setting: the first
scheduler pass after migration rewrites it, as every pass does. Version 1 IDs
are UUIDs; every route accepts any ID of 1 to 64 letters, digits, `_` or `-`
and answers 404 for one it does not hold. An unresolved version 1 run is
reconciled after migration under its task ID and exact payload, as after any
restart. A disabled migrated workflow whose `failureStreak` is 3 or more has
`pausedBy` `failures`; any other disabled one has `operator`. Migration records
no activity entries for the past.

## 14. Schedules (rev 3)

A workflow runs either every `intervalMinutes` (section 4) or on a `schedule`
(MGD-8), which is `{timeZone,days,times}`:

- `timeZone` is a time zone name the runtime knows, of 1 to 64 characters,
  starting with a letter, such as `UTC`, `Europe/London` or `America/New_York`;
  another value, a bare offset such as `+05:30` included, is 400. A canonical
  name is returned unchanged.
- `days` is an array of 1 to 7 distinct names from `mon`, `tue`, `wed`, `thu`,
  `fri`, `sat` and `sun`, returned in that order.
- `times` is an array of 1 to 24 distinct local times written `HH:MM` with two
  digits each, from `00:00` to `23:59`, returned in ascending order.
- A missing field, or any other field, is 400.

A schedule's slots are the instants at which the local time in `timeZone` is one
of `times` on a date whose weekday in that zone is one of `days`. A local time
that a date skips, because the clocks move forward past it, takes place later by
the length of the change: in a zone that moves from 02:00 to 03:00, 02:30 takes
place at 03:30. A local time that occurs twice, because the clocks move back,
takes place at its first occurrence. Two times that fall on one instant make one
slot.

A scheduled workflow's `nextRunAt` is:

- at creation, and when a `PATCH` changes `schedule` (switching an interval
  workflow to a schedule included): the first slot after the time of the
  request. A `PATCH` whose `schedule` equals the current one changes nothing,
  as section 11 says of edits that change no value;
- when one of its runs becomes terminal, `abandoned` included: the first slot at
  least one minute after that run's `finishedAt`;
- after `run`: now, as for an interval workflow (section 9).

Nothing else changes it: not `pause`, `resume` or `restore`, not another field's
edit, and not a review verdict. Slots that pass while the workflow has an
unresolved run, is paused, is blocked by readiness or its daily cap, or while the
controller is stopped, are not made up one by one. A workflow whose `nextRunAt`
has passed is due; it runs once when it can be dispatched, and its next slot
follows that run's finish. The daily cap still counts the UTC day (section 4).
Clients compare times as instants, not as strings.

## 15. Reviewing results (rev 3)

A workflow's `review` is `none`, the default, `operator`, or (rev 4) `agent`
(section 15.1). With `operator`, each
of its runs that ends `succeeded` waits for the operator's verdict before it
counts as a success (MGD-9). A run keeps the review requirement that its workflow
had when the run was reserved.

A run's `review` is null while it is unresolved, when it ends in any state other
than `succeeded`, and when it needs no review. A run that needs review and ends
`succeeded` has `review` `pending` until the operator's verdict, and then
`accepted` or `rejected`. `reviewedAt` is null or the time of the verdict, and
`reviewNote` is null or the verdict's note.

`POST /api/runs/:id/review` accepts `{verdict}` or `{verdict,note}`. `verdict` is
`accepted` or `rejected`; `note` is a string of at most 2,000 characters as sent,
stored trimmed, and an empty trimmed note is stored as null. Any other field or value is
400. An unknown run is 404, and a run whose `review` is not `pending` is 409: a
verdict is final. The response is the run. Each verdict records `run.reviewed`
(section 11).

A verdict changes only the run's review fields and what sections 8 and 11 derive
from them. It never changes the run's `state`, the failure count, `nextRunAt` or
dispatch: a pending review does not hold back the workflow's next run, and a
rejected result is not sent back to the agent. (rev 4) Except that a rejection
makes a rework due when the workflow asks for one (section 15.2).

(rev 4) A run's `reviewedBy` is null while its `review` is null or `pending`, and
then `operator` or `agent`: who gave the verdict. The operator's verdict through
this route is accepted for every run whose `review` is `pending`, whether it
waits for the operator or for a reviewer agent.

### 15.1 Reviewer agents (rev 4)

A workflow whose `review` is `agent` has another worker agent check each result
(MGD-10). Its `reviewerId` names the reviewer: a connection whose worker agent is
not the workflow's own, that is, whose `hostId` or `agentId` differs from those of
the connection named by `connectionId`. Each run of such a workflow that ends
`succeeded` has `review` `pending`, as in section 15, and the controller asks the
reviewer for the verdict with a **review task**. The operator is the fallback:
whenever the reviewer gives no verdict, the run waits for the operator's, and the
operator may give a verdict at any time while the review is `pending`.

**Fields.**

- `reviewerId` is null, or the ID of a connection that is not removed when the
  request sets it. It is not null exactly when `review` is `agent`. At creation, `review` `agent` without a
  `reviewerId`, a non-null `reviewerId` with another `review`, an unknown
  connection, and a reviewer whose worker agent is the workflow's are 400;
  `reviewerId` null beside another `review` means no reviewer.
- In a `PATCH`, setting `review` to `none` or `operator` also sets `reviewerId` to
  null, unless the same body gives a non-null `reviewerId`, which is 400. The
  workflow that results must follow the rules above, so `review`
  `agent` without a reviewer, a non-null `reviewerId` on a workflow whose
  `review` stays `none` or `operator`, `reviewerId` null on a workflow whose
  `review` stays `agent`, an unknown connection, and a `connectionId` or
  `reviewerId` that puts one worker agent on both sides, are 400. These rules
  are checked when a body has `review`, `reviewerId` or `connectionId`. When a
  switch clears `reviewerId`, its `workflow.edited` entry lists both `review` and
  `reviewerId`.
- A reviewer connection can be removed while every workflow naming it is
  archived. Such a workflow keeps its `reviewerId` when it is restored, and its
  results fall back with `reviewer_removed` (below) until a `PATCH` gives it
  another reviewer or another `review`.
- `reviewCriteria` is null, or a string of at most 2,000 characters as sent,
  without NUL, stored trimmed; an empty trimmed string is stored as null. It
  tells the reviewer agent, and the operator in the console, what a good result
  must do. It is valid with every `review`.
- (rev 4) Wherever this contract limits or cuts text by characters, a character
  is a Unicode code point. A verdict's `note` (section 15) is also refused with
  400 when it contains NUL, because it may be sent to the worker with a rework.

**The run's review task.** `reviewTask` is null for a run that needs no agent
review. A run reserved while its workflow's `review` was `agent` keeps that
requirement and that reviewer, and once it ends `succeeded` its `reviewTask` is
`{connectionId,taskId,state,error,reason,cancelRequestedAt,createdAt,
finishedAt}`: `connectionId` is the reviewer it was reserved with, and the other
fields are null until the review task is reserved and then follow its task as a
run's fields follow the run's task (section 8). While the run is unresolved, or
when it ends in another state than `succeeded`, `reviewTask` is null.

In a scheduler pass the controller reserves the review task of each run whose
`review` is still `pending`, whose `reviewTask.taskId` is null and whose
`reviewFallback` is null, when the reviewer connection is ready and its worker
agent holds no unresolved task. Runs waiting for one reviewer agent are served in
the order of their `finishedAt`, oldest first. Whether the run's workflow is
paused, blocked or archived does not matter: those stop new runs, not reviews.
Reserving persists the task ID, the input below, the reviewer connection's host,
agent and sender state, and a deadline of the reservation time plus the
workflow's current `acceptanceMinutes`, and records `review.dispatched`. The
task is then submitted with `task submit --peer HOST --agent AGENT --task ID
--input=TEXT --deadline RFC3339` against the reviewer connection's sender state,
and handled as section 4 says. A run gets at most one review task: the
controller never reserves a second one, whatever became of the first.

**The review input** is these lines joined by LF, with no LF after the last:

```
Review the result below, which an agent produced for the assignment that follows it. Decide whether the result does what the assignment asks.
Begin your answer with one line that says exactly VERDICT: ACCEPT or VERDICT: REJECT. Then give your reasons briefly: the operator reads them, and after a rejection the agent may receive them with the assignment.

ASSIGNMENT
<the run's assignment>

CRITERIA
<the workflow's reviewCriteria>

RESULT
<the run's output>
```

The run's assignment is its `assignment` (section 10), its output is the retained
output without any NUL characters, which a command-line argument cannot carry,
and `reviewCriteria` is read when the review task is reserved. When
`reviewCriteria` is null, the three lines `CRITERIA`, its text and the empty line
after it are left out. An input longer than 65,536 bytes of UTF-8 has the output
cut at a character boundary and ended with `…` (U+2026), keeping as much of the
output as lets the whole input fit in 65,536 bytes.

**The verdict.** When the review task ends `succeeded`, the verdict is in the
first line of its output that has a character other than whitespace. With
whitespace and the characters `*`, `_`, `#`, `>`, `` ` `` and `.` removed from
both its ends, that line must be `VERDICT:`, optional spaces, and `ACCEPT` or
`REJECT`, and nothing else; the letters of all three words may be in any case,
so `verdict: accept` is a verdict line. `ACCEPT` makes the run's
`review` `accepted` and `REJECT` makes it `rejected`, with `reviewedBy` `agent`,
`reviewedAt` the time the controller retained the review task's result, and
`reviewNote` the reviewer's reasons: the text after the verdict line, without a
final branch line (section 10.1; it is removed with the empty line before it
when the review task's output has one), with control characters other than LF
and tab removed, trimmed, and cut to its first 1,999 characters followed by `…`
when longer than 2,000; null when empty. `run.reviewed` is recorded with actor
`system`. A rejection may then make a rework due (section 15.2).

**Fallback.** The run's review stays `pending`, now waiting for the operator, and
its `reviewFallback` becomes one of these causes, recorded as `review.fallback`:

| `reviewFallback` | When |
| --- | --- |
| `failed`, `rejected`, `expired`, `cancelled` or `abandoned` | The review task ended in that state. |
| `no_verdict` | The review task ended `succeeded`, but its output has no verdict line. |
| `reviewer_removed` | The reviewer connection was removed before the review task was reserved. The controller notices it at its next pass. |

`reviewFallback` is null otherwise, and once set it never changes, also after
the operator's verdict. The run's `review_pending` item (section 8) appears once
it falls back.

**The operator's verdict** (section 15) ends the agent review. Given before the
review task is reserved, no review task is reserved. Given while the review task
is unresolved, that task goes on to its end under the rules of section 4, and its
state and output are kept in `reviewTask`, but its end changes nothing else: no
verdict, no fallback and no `review.fallback` entry. `review.finished` is
recorded for every review task that ends, with its final state, `abandoned`
included.

**Cancelling and releasing a review task.** `POST /api/runs/:id/review/cancel`
accepts `{}`. It is 404 for an unknown run and 409 unless the run has an
unresolved review task. It records the review task's `cancelRequestedAt` once,
with `review.cancel_requested`, and returns the run; the controller then acts on
the review task as section 10 says for a run's task. `POST
/api/runs/:id/review/abandon` accepts exactly `{"confirm":TASK_ID}`, where
TASK_ID is the review task's ID. A body that is not an object with exactly a
string `confirm` is 400 first, as for `abandon`; then it is 404 for an unknown
run, 409 unless the run has an unresolved review task, and 400 unless `confirm`
equals that task's ID.
The review task becomes `abandoned`, its reviewer agent is released, the
controller never again submits, inspects or cancels that task, and
`review.abandoned` is recorded; the run falls back as the table says unless the
operator has already given a verdict. The response is the run.

### 15.2 Rework (rev 4)

A workflow's `reworkLimit` is an integer from 0, the default, to 3 (any other
value, null included, is 400): how many times
a rejected result is sent back to the worker agent with its review (MGD-11). A
run's `attempt` is 1 for a run reserved for the workflow's interval, schedule or
`run`, and one more than the rejected run's for a rework; its `reworkOf` is null,
or for a rework the ID of the rejected run.

When a run's `review` becomes `rejected`, by the reviewer agent or by the
operator, its workflow becomes due for a rework when all of these hold: the run's
`attempt` is at most the workflow's `reworkLimit` at that moment; no later run of
the workflow has been reserved; and the workflow is not archived. The workflow's
`reworkPending` then becomes the rejected run's ID, and `workflow.rework_due` is
recorded with the coming attempt. Otherwise the rejection only counts, as in
section 15.

While `reworkPending` is not null, the workflow is due whatever its `nextRunAt`
says; every other dispatch rule of section 4 applies (enabled, the daily cap, a
ready and free worker). The next run reserved for the workflow is the rework: its
`attempt` is the rejected run's plus one, its `reworkOf` the rejected run's ID,
and `reworkPending` becomes null. A `pause` keeps `reworkPending`, so the rework
is dispatched after `resume`; `archive` clears it. A rework is a run like any
other: it counts toward the daily cap and the statistics, its own result sets the
failure count and `nextRunAt`, and its review requirement and reviewer are the
workflow's when it is reserved.

**The rework input** is these lines joined by LF, with no LF after the last:

```
<the workflow's instructions>

REVISION REQUESTED
A reviewer rejected your previous result for this assignment. Do the assignment again in full, addressing the review.

REVIEW
<the rejected run's reviewNote>

PREVIOUS RESULT
<the rejected run's output>
```

The workflow's `instructions` are read when the rework is reserved, and they are
the rework's `assignment`. A null `reviewNote` is written `The reviewer gave no
reasons.` The previous result is the rejected run's retained output without any
NUL characters, as in section 15.1. An input longer than 65,536 bytes of UTF-8 has the previous result cut
at a character boundary and ended with `…`, keeping as much of it as lets the
whole input fit in 65,536 bytes.

## 16. Independent conformance cases

A separate author reads this contract only and implements bounded black-box
suites under `managed/conformance/` using an explicitly named fake Peerspan binary
and throwaway private state. Fixtures must never appear as real customer runs.
Each suite stays under two minutes and about 1,000 lines; the cases are split by
area, not by revision.

`acceptance.mjs` (revision 1 behavior):

1. Authentication, wrong Host/Origin, body size, field validation, and path/token
   non-disclosure. Real endpoint availability and empty state.
2. Paused creation, enabled due dispatch, positive readiness evidence, unverified
   channel and changed identity blocking dispatch. Exit-1 valid status is usable.
3. Pause with an active run, manual run honoring caps, and two workflows sharing
   a target never executing unresolved work concurrently.
4. Lost submit response with remote acceptance, process restart, exact same task
   ID/payload recovery, no duplicate dispatch; transient inspect error cannot
   manufacture replacement work. Unknown remote state remains unresolved.
5. Success/result retention, recurring dispatch, daily cap across restart,
   three-failure circuit and explicit resume.
6. Read-only observed workflow, malformed observation visible, second writer
   refusal, source state unmodified, and no secret or local path in snapshot.

`operations.mjs` (revision 2 behavior):

7. Workers: agent-mode registration by name and by ID, the no-match and duplicate
   name refusals, a registration refused when sender and worker are one host,
   `sender_unavailable` and `sender_is_worker` blocking dispatch, readiness following a replaced session without operator action,
   every readiness `code` of section 3 that a fake can produce, hints with a
   usable command, a refused command and no `detail` text, `disconnect` refused
   while in use and accepted afterwards, `unobserve`, and `doctor` with a working
   and with a missing executable.
8. Workflows: instructions that begin with a hyphen submitted byte-identically
   in one `--input=TEXT` argument, `PATCH` validation, an edit leaving a
   reserved run's payload byte-identical while the next dispatch uses the new
   values, the `nextRunAt` rule, `resume` leaving `nextRunAt` unchanged, archive
   refused with an unresolved run, archived workflows absent from
   dispatch and `workflows` but present in `archived` and run history, the 409s,
   and restore.
9. Cancellation: a queued or running run cancelled through `task cancel`, state
   unchanged until the remote reports, the agent finishing anyway, a failing
   cancel invocation repeated, a never-sent submission cancelled without any
   submit, the unchanged failure count, and 409 on a terminal run.
10. Abandon: the confirmation rule, reservations released, no later Peerspan call
    for that task, the unchanged failure count, and a new run able to dispatch.
11. Timeline, history and activity: progress visible in the snapshot and the
    detail, the terminal event retained, snapshot output truncated at 2,000
    characters with the detail complete, paging of runs and activity, the listed
    activity kinds with their actors, statistics including interventions and
    `unattendedRuns`, and every attention kind a fake can produce.
12. Live updates and boundaries: the immediate `change` event, a `change` after a
    mutation, an unauthenticated stream refused, the fetch-site rule, an operator
    request answered within one second while a Peerspan call is hanging, shutdown
    within 5 seconds with a hanging call, version 1 state migrated with a
    retained unresolved run reconciled under its task ID, and a newer schema
    refused unmodified.

`remote.mjs` (revision 3 workers):

13. Remote workers: registration by address and by agent ID, from `reachable`
    and from `mine`, with `--network` passed through; the no-match,
    several-match, sender's own host, unreadable sender status and failing
    directory refusals; the pinned network in every check; `--refresh` on the
    first check after a start and not again within 60 seconds; every remote
    readiness `code` a fake can produce, `directoryAt`, sender hints and no
    `detail` text; a dispatched run's submission, inspection and completion
    through the sender state with no argument naming a worker host's state;
    and a restart reconciling a remote run under its task ID.

`schedules.mjs` (revision 3 scheduling and review):

14. Schedules, with `MANAGED_CLOCK_FILE`: validation and normalization of
    `schedule`, the exactly-one rule at creation and in `PATCH`, `nextRunAt` at
    creation in at least three time zones, a skipped and a repeated local time
    across a daylight-saving change, dispatch at a slot, the next slot after a
    completion at least one minute later, missed slots run once, switching
    between interval and schedule by `PATCH`, and the daily cap on the UTC day.
15. Review: a reviewed workflow's succeeded run `pending` and its failed run
    null, the verdict route's 400, 404 and 409 rules, the stored note,
    `run.reviewed` activity, the statistics (`awaitingReview`, a rejected run
    counted as failed, a pending one in neither count, `interventions`
    unchanged by verdicts), the `review_pending` item, dispatch not held back
    by a pending review, and a run reserved before a `PATCH` of `review`
    keeping its requirement.

`reviewers.mjs` (revision 4 reviewer agents, rework and branches):

16. Reviewer agents: the `reviewerId` rules at creation and in `PATCH`, including
    one agent on both sides and a switch that clears the reviewer, and
    `reviewCriteria` limits and trimming; instructions, criteria and a verdict
    note containing NUL refused, and a result containing NUL reviewed and
    reworked with it left out; a succeeded run's review task
    submitted to the reviewer through its sender state with the exact input,
    with and without criteria, and with a long output cut to 65,536 bytes; a
    verdict line accepted with decoration and in lower case, and the reasons
    stored as the note without a final branch line; each `reviewFallback` a fake
    can produce; the operator's verdict before the review task is reserved and
    while it is unresolved, the review task's end then changing nothing; a
    review task holding its reviewer agent against a run of another workflow
    whose worker is that agent, and reviews served before runs and oldest
    first; reviews of a paused workflow going on; `review/cancel` and
    `review/abandon` with their 400, 404 and 409 rules; a restart reconciling a
    review task under its task ID; `review_pending` raised only once a run
    waits for the operator, `worker_unready` as an action for a reviewer, a
    review task's problem as `run_problem`; the `review.*` activity entries and
    a system `run.reviewed`; and `disconnect` refused for a reviewer in use.
17. Rework: a rejection by the reviewer agent and one by the operator each
    making a rework due, the rework's exact input with and without a note and
    with a long previous result cut, its `attempt`, `reworkOf` and
    `assignment`; no further rework once the limit is reached, when a later run
    exists, or for an archived workflow; a paused workflow keeping its rework
    until `resume`; a rework due before `nextRunAt`; and the rework counted by
    the daily cap and the statistics.
18. Workspace branches: each form of section 10.1 read from a `succeeded` and a
    `failed` run, and `branch` null for an output without the empty line before
    its last line, a commit ID of another length or case, a name with `/`, and
    a run that is not `succeeded` or `failed`.

`runtime-agents.mjs` (revision 5 runtime agents):

19. Runtime agents, in agent mode: an agent with a launch profile and a
    credential `ready_runtime` without any session, with `runtime` from its
    profile and no path anywhere in a response; `runtime_disabled`,
    `runtime_unavailable` (a failing `runtime show`, a report with `error`, and
    malformed output) and `runtime_credential_missing`, each blocking dispatch;
    `ready_runtime` with an inactive user service; an agent without a profile,
    and an executable without `agent runtime`, following their sessions as
    before; a failing profile listing as `status_invalid`; a runtime agent
    becoming one, and ceasing to be one, without operator action; file and
    remote mode never running `agent runtime show`; a run dispatched to a
    runtime agent, completed with a branch line; and the `checking` readiness
    with `runtime` null.

`capacity.mjs` (revision 6 capacity and slow calls):

20. Capacity: a `ready_runtime` agent with `maxRuns` 3 holding three runs of
    three workflows at once, and a fourth workflow waiting until one ends;
    review tasks counted against a reviewer's capacity; an agent that is not a
    runtime agent, a `maxRuns` of null, 0 or 65, and a runtime agent that is not
    ready all holding one; a capacity that falls below the tasks held leaving
    them unresolved and dispatching nothing until fewer are held; two
    connections to one agent; and `capacity` and `activeTasks` in the snapshot.
21. Slow calls: with one connection's `status`, a runtime agent's
    `runtime show`, one task's `task inspect` or one submission hanging, another
    ready connection's workflow still dispatched and its run reconciled within a
    few seconds, the other connections' `checkedAt` advancing, no second call
    for the hanging connection or task, and shutdown within 5 seconds.

Version 2 and version 3 state are not described by this contract, so their
migration is checked by the implementer against copies of real state of those
versions and recorded with the validation results, not by these suites.

Real Peerspan compatibility is a separate local smoke check. Do not claim a fake
adapter test validates model execution or the upstream transport.
