# Managed operator contract

Revision 2. Revision 1 defined the first local slice: the console, recurring
dispatch, readiness, recovery and the observation bridge. Revision 2 keeps every
revision 1 behavior and adds worker discovery, workflow editing and archiving,
run cancellation and release, run timelines, the activity log, attention items,
reliability statistics, live updates and an indexed store. Sections 7 to 13 are
new; sections 1 to 6 mark their additions with "(rev 2)". Fork decisions are
recorded in [managed-decisions.md](managed-decisions.md) and cited as `MGD-n`.

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

(rev 2) The store carries a schema version. Version 2 state is created directly.
Version 1 state (section 13) is migrated in place, in one transaction, the first
time a revision 2 command opens it; connections, observations, workflows, runs,
task IDs, submission payloads and results are retained with their IDs. Before
it migrates, the command saves a copy of the version 1 database as
`managed.v1-backup.sqlite` in the state directory, with the same private
permissions. State written by a newer schema is refused with a nonzero exit and
is not modified.

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
  default if enabled omitted. Unknown connection is 400.
- `POST /api/workflows/:id/pause`: prevents new dispatch, does not interrupt an
  active task. `resume` enables dispatch and resets failure circuit. `run` sets
  next eligible time to now but never bypasses paused state, caps or readiness.
  Each accepts an empty JSON object and returns the workflow object, 404 if absent.
- (rev 2) `PATCH /api/workflows/:id`, `POST /api/workflows/:id/archive` and
  `restore`: section 9.
- (rev 2) `GET /api/runs`, `GET /api/runs/:id`, `POST /api/runs/:id/cancel` and
  `abandon`: section 10.
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
`{ready:false,code:"checking",checkedAt:null,hints:[]}` with the `since` last
recorded (null for a new connection); `checking` raises no attention item and
records no activity.

`hints` lists at most ten upstream attention items of the worker host's status,
in the order status reports them, as `{kind,command}`. `kind` is the upstream
attention kind when it matches `^[a-z_]{1,64}$` (other items are skipped).
`command` is the upstream suggested command when it starts with `peerspan `, is
at most 200 printable ASCII characters and contains no `/` or `\`; otherwise it
is null. The upstream `detail` and `subject` texts are never returned. Hints are
advice: they never change `ready`. They are an empty array whenever status could
not be read.

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

A connection names one worker agent on a Peerspan host whose state directory is
on this machine, and the sender host state used to submit to it. Host and agent
are pinned when connecting; changing either requires a new connection.

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
NAME is 1 to 100 characters after trimming.

`disconnect --id ID` removes a connection. It is refused, with a nonzero exit and
nothing changed, while a workflow that is not archived uses the connection or one
of its runs is unresolved. Retained runs keep their history. `unobserve --id ID`
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

## 8. Snapshot (rev 2)

`GET /api/snapshot` returns the following. No response of any route contains a
filesystem path, the access token, a session cookie value, a state directory
location, or upstream attention `detail` or `subject` text.

- `connections`: `{id,name,hostId,agentId,mode,readiness}` for each connection
  that is not removed, oldest first.
- `workflows`: every workflow that is not archived, oldest first, as
  `{id,name,connectionId,instructions,intervalMinutes,maxRunsPerDay,
  acceptanceMinutes,enabled,nextRunAt,failureStreak,blockedReason,createdAt,
  updatedAt,pausedBy,recent,stats}`. `pausedBy` is null while enabled, and
  otherwise `operator` (created paused, paused, or restored) or `failures` (the
  failure circuit). `recent` is the workflow's latest 20 runs, newest first, as
  `{id,state,createdAt,finishedAt}`.
- `stats` covers the trailing 7 days (168 hours): `{windowDays:7,runs,succeeded,
  failed,successRate,averageSeconds,interventions,unattendedRuns}`. `runs` counts
  runs created in the window. `succeeded` and `failed` count runs that finished
  in the window, `failed` being every terminal state other than `succeeded`,
  except the two operator results of section 4. `successRate` is
  succeeded/(succeeded+failed), or null when that sum is 0. `averageSeconds` is
  the mean of finishedAt minus createdAt over the window's succeeded runs, in
  whole seconds, or null. `interventions` counts the window's operator activity
  entries for the workflow other than `workflow.created`. `unattendedRuns` counts
  the workflow's terminal runs, of all time, that finished after its latest such
  intervention (after its creation when there is none).
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
  controller retained the terminal result.
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
  | `worker_unready` | `action` when an enabled workflow that is not archived uses the connection, otherwise `warning` | `connection` | Its readiness is not ready. `message` is the readiness reason and `since` its `since`. |
  | `run_problem` | `warning` | `run` | An unresolved run has a non-null `error`. `subject.name` is the workflow name; `since` is when the problem first appeared. |
  | `observed_unavailable` | `warning` | `observation` | An observed entry has `available` false. |
  | `observed_problem` | `warning` | `observation` | An available observed entry has a non-null `error`. |
  | `daily_limit_reached` | `info` | `workflow` | An enabled workflow is blocked only by its daily cap. |

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
`acceptanceMinutes`, validated as at creation; any other field, `enabled`
included, is 400. It returns the workflow. An edit never changes a run that was
already reserved: its submission payload is immutable. When `intervalMinutes`
changes and the workflow has a terminal run, `nextRunAt` becomes its latest
terminal run's `finishedAt` plus the new interval; otherwise `nextRunAt` is
unchanged.

`pause` and `resume` do not change `nextRunAt`: a resumed workflow runs when its
schedule says so, or when the operator also sends `run`. Every accepted `pause`,
`resume` and `run` request records its activity entry (section 11), whether or
not the workflow's state changed.

`POST /api/workflows/:id/archive` accepts `{}`. It is 409 while the workflow has
an unresolved run. It disables the workflow, removes it from `workflows`, lists
it in `archived` and keeps its runs. An archived workflow is never dispatched,
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
| `operator` | `connection.added`, `connection.removed`, `observation.added`, `observation.removed` | null |
| `system` | `run.dispatched` | null |
| `system` | `run.finished` | `{state}` |
| `system` | `run.problem`, `run.recovered` | null: a run's `error` appearing, and clearing while the run is still unresolved. |
| `system` | `workflow.auto_paused` | `{failureStreak}` |
| `system` | `worker.ready`, `worker.unready` | `{code}`: recorded when a connection's `ready` value changes, and for a new connection's first check. A restart alone records nothing. |

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

## 14. Independent conformance cases

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

Real Peerspan compatibility is a separate local smoke check. Do not claim a fake
adapter test validates model execution or the upstream transport.
