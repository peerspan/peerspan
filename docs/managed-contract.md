# Managed operator contract

## Process and persistence

Node 24 is required. `node managed/cli.mjs serve --state DIR --port PORT`
starts one loopback HTTP console and scheduler. Defaults are
`~/.local/state/peerspan-managed` and port 4310. State is private, SQLite lives
outside Git and is accessed on a worker thread. A process lock refuses a second
writer to the same state directory. Restart keeps connections, workflows, task
IDs, immutable submission payloads and results. State permissions are 0700/0600.

The CLI supports `connect --state DIR --name NAME --worker-state FILE
--sender-state DIR` (sender-state optional for the upstream default), `token
--state DIR`, `status --state DIR`, and `serve`. Connection configuration is
operator-local only. The worker state JSON contains host_dir, host_id, agent_id,
adapter_id and session_id. Agent/host identity is pinned at registration; session
and adapter may change only for the same identities. Secrets are never returned
by HTTP. `PEERSPAN_BIN` selects an executable; invocation uses argument arrays,
never a shell. `MANAGED_TICK_MS` may shorten polling for acceptance tests (minimum
100 ms; default 10000 ms). Production task execution uses Peerspan only.

## HTTP contract

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

`GET /health` returns `{ok:true}` without state. Authenticated endpoints:

- `GET /api/snapshot`: `{connections,workflows,runs,observed,meta}`. Connection
  readiness is `{ready,reason,checkedAt}` with no private path or credential.
  Runs are newest first and include id, workflowId, taskId, state, output,
  error, createdAt, updatedAt. Meta explicitly says model cost is unavailable.
- `POST /api/workflows`: JSON `{name,connectionId,instructions,intervalMinutes,
  maxRunsPerDay,acceptanceMinutes,enabled}`; name 1–100 chars, instructions 1–12000
  chars, interval 1–10080 minutes, cap integer 1–1000, acceptance 1–1440 minutes,
  enabled boolean. Returns 201 with the created workflow object. Paused by
  default if enabled omitted. Unknown connection is 400.
- `POST /api/workflows/:id/pause`: prevents new dispatch, does not interrupt an
  active task. `resume` enables dispatch and resets failure circuit. `run` sets
  next eligible time to now but never bypasses paused state, caps or readiness.
  Each accepts an empty JSON object and returns the workflow object, 404 if absent.
- `POST /api/logout`: removes the console session cookie.

Workflow snapshots include id, name, connectionId, instructions, intervalMinutes,
maxRunsPerDay, acceptanceMinutes, enabled, nextRunAt, failureStreak, blockedReason.
No workflow edit/delete API is included in the first slice.

## Dispatch and recovery

One unresolved run per workflow and one per target sender/host/agent across
managed workflows. A run is unresolved while submitting, queued or running.
New dispatch requires an enabled due workflow, capacity under its UTC-day cap,
and a verified worker. Each new reserved run counts toward the cap, including
failed submissions. Pausing never abandons an unresolved run.

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

Before any submission, persist a task ID (`task_` plus 32 hex digits) and exact
input, peer, agent, deadline and sender state. Submit using `task submit --peer
HOST --agent AGENT --task ID --input TEXT --deadline RFC3339`. The deadline bounds
acceptance, not already-running execution. Poll with `task inspect --peer HOST ID`.
On uncertain delivery or restart inspect the same ID first. Only a genuine
not-found inspection permits resubmitting the SAME ID and exact payload. Other
inspection errors retain the run and show a problem, never create replacement
work. A run already queued/running is never resubmitted merely because inspect
temporarily fails. Recovery does not require the worker to still be ready.

Accepted remote states queued/running/succeeded/failed/cancelled/rejected/expired
are retained. A submit_state rejected is a terminal rejected result. Successful
completion resets failure count; any other terminal result increments it. After
three consecutive failures the workflow pauses with a visible failure reason.
Completion schedules the next run after the interval, with failure delay at least
one minute. A successful run is only the remote agent's report, not human approval.
No automatic cancellation or task redirection.

## Observation bridge

`observe --state DIR --name NAME --directory DIR` registers a private external
controller directory containing config.json, state.json and events.jsonl. Only
config.enabled and state cycle/phase/lastTickAt/error/task/lastBatch summaries are
read. HTTP exposes no filesystem paths. Observed controllers have no action
buttons or mutation endpoints; their files and services are never changed. Missing
or malformed sources are visible as unavailable, not healthy. The bridge is local
configuration, excluded from Git, and does not claim ownership of external tasks.

## Independent conformance cases

A separate author reads this contract only and implements a bounded black-box
suite under `managed/conformance/` using an explicitly named fake Peerspan binary
and throwaway private state. Fixtures must never appear as real customer runs.

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

Real Peerspan compatibility is a separate local smoke check. Do not claim a fake
adapter test validates model execution or the upstream transport.

## Wire fixtures for conformance

Status JSON uses `{host_id,service:{active:true|false},attention:[],agents:[{id,name,
sessions:[{id,adapter_id,connection:"ready"}]}]}`. Adapter connection uses
`{adapter_id,session_id,state:"ready",channel:"verified",channel_verified_at:
RFC3339}`. Other upstream fields may be present. Status exit 1 requires a valid
attention array (possibly populated with historical errors); malformed JSON is
never readiness. All IDs in fixtures follow upstream host_ plus 64 hex and
agent_/adapter_/session_ plus 32 hex conventions.

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

Observation entries are `{id,name,available,enabled,cycle,phase,lastTickAt,error,
task,lastBatch}`. task is null or `{id,key,state,lane}`; lastBatch is null or
`{key,status,articlesAdded,dossiersAdded}` where counts are numbers. Configuration
paths and reportPath are not returned. Unavailable entries use available false,
phase "unavailable", with a generic error. An empty console has empty arrays;
connections expose id, name, hostId, agentId and readiness. HTTP auth failures are
401 JSON and mutating validation failures are 400 JSON. CLI connect/observe
print JSON with the newly registered id; token prints only the token plus newline.
