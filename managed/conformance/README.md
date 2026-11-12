# Managed contract conformance

Independent black-box Node 24 suite authored from `AGENTS.md` and
`docs/managed-contract.md`, without reading the managed implementation.
It launches the documented CLI and uses HTTP, an explicitly fake Peerspan
executable, and private throwaway Linux directories. It never reads the managed
database. Fixture names, instructions, results and binary are explicitly fake.

From this repository in Linux with Node 24:

```sh
node managed/conformance/acceptance.mjs
node managed/conformance/operations.mjs
node managed/conformance/visibility.mjs
node managed/conformance/remote.mjs
node managed/conformance/schedules.mjs
node managed/conformance/reviewers.mjs
node managed/conformance/runtime-agents.mjs
node managed/conformance/capacity.mjs
```

On the configured Windows editing machine:

```powershell
wsl.exe -d Ubuntu-24.04 -u matt -- bash -lc 'cd /mnt/c/Users/Owner/dev/peerspan-managed && node managed/conformance/acceptance.mjs'
```

`acceptance.mjs` (contract section 16, cases 1 to 6): six concurrent cases cover
authentication/schema/privacy, readiness/target exclusion, crash/replay, real
one-minute recurrence/caps, failure circuit and read-only observation/process
locks. The suite is bounded to 115 seconds; normal duration is around 70 seconds.

`operations.mjs` (cases 7 to 10) and `visibility.mjs` (cases 11 and 12) are the
revision 2 suites; `remote.mjs` (case 13) and `schedules.mjs` (cases 14 and 15)
are the revision 3 suites; `reviewers.mjs` (cases 16 to 18) is the revision 4
suite, `runtime-agents.mjs` (case 19) the revision 5 suite and `capacity.mjs`
(cases 20 and 21) the revision 6 suite. They are split by area to stay near
1,000 lines each
and share `harness.mjs`: the fixture, HTTP and event-stream helpers, the fake's
logs, the `MANAGED_CLOCK_FILE` test clock, and the exact revision 6 shapes of
contract sections 3, 3.1, 4, 7.1, 8, 10, 10.1, 11, 14, 15 and 15.1 (readiness with
`runtime` and the runtime codes of agent mode; each connection's `capacity`,
derived from its readiness, and `activeTasks`, equal for connections to one
agent), which are checked on
every snapshot, run page and run detail any of them fetches: among them the
attention items derived from the snapshot (`worker_unready` for reviewers,
`run_problem` for review tasks, `review_pending` only for runs that wait for the
operator) and each complete output's `branch`, read by the forms of section 10.1.
Every response body is also checked for fixture paths, the access token and
`PRIVATE-` markers (section 8).

- `operations.mjs`: local commands and worker registration, every readiness code
  and hints, workflow editing/archiving, cancellation, abandon. Five concurrent
  cases, about 15 seconds.
- `visibility.mjs`: timeline/history/activity/statistics/attention, the event
  stream and fetch-site rule, hanging Peerspan calls and shutdown, prompt
  scheduler passes, version 1 migration and a newer schema. Six concurrent
  cases, about 40 seconds; the longest waits are a 21-second open stream (the
  20-second comment line) and a controller with a six-second tick.

- `remote.mjs`: remote registration and its refusals, every remote readiness
  code with `directoryAt` and sender hints, `--network` and `--refresh` on
  checks, and a remote run's dispatch, cancellation and restart recovery through
  the sender state. Four concurrent cases, about 70 seconds: one case waits for
  the second `--refresh`, 60 seconds after the first.
- `schedules.mjs`: schedule validation and normalization, `nextRunAt` in six
  zones and across daylight-saving changes, dispatch at slots, missed slots, the
  UTC-day cap, and operator review with its statistics, attention and activity.
  Five concurrent cases, about 10 seconds. A fixture created with
  `{clock: INSTANT}` starts the controller's clock there through
  `MANAGED_CLOCK_FILE`; `f.clockAt(INSTANT)` moves it forward and waits for a
  scheduler pass on it (`meta.lastTickAt`).
- `reviewers.mjs`: reviewer agents (the `reviewerId` and `reviewCriteria` rules,
  NUL refused in instructions, criteria and notes, limits counted in code points,
  the exact review input with and without criteria, without the result's NUL
  characters and cut to 65,536 bytes, the
  verdict line and the note, every fallback, the operator's verdict before and
  while a review task runs, review tasks holding their agent and served before
  runs and oldest first, paused and archived workflows, `review/cancel` and
  `review/abandon`, a review task's problem, a restart, attention and activity),
  rework (the exact input with and without a note and cut, `attempt`, `reworkOf`,
  `assignment`, the limit, a later run, archive, pause, `nextRunAt` and the daily
  cap) and workspace branches (every form of section 10.1 and the null cases).
  Eight concurrent cases, about 20 seconds; the fake plays the worker and
  reviewer agents of one worker host, in agent mode through a second sender state.
- `runtime-agents.mjs`: runtime agents in agent mode (`ready_runtime` without a
  session, the commands it runs, `runtime` from the launch profile, no path in a
  response, the inactive-service advisory, every runtime code blocking dispatch
  and the order of the codes), agents without a profile and an older executable
  following their sessions, a failing profile listing, agents becoming and
  ceasing to be runtime agents, file and remote mode never reading profiles, a
  run completed with a branch line and the `checking` readiness. Four concurrent
  cases, about 15 seconds.
- `capacity.mjs`: a runtime agent's capacity (three runs of three workflows at
  once and a fourth waiting, review tasks counted against a reviewer, capacity 1
  for a session agent, a `maxRuns` of null, 0, 65 or a string and an agent that
  is not ready, a falling capacity, one run per workflow, two connections to one
  agent, `capacity` and `activeTasks`) and slow calls (one connection's `status`,
  a `runtime show`, one task's `task inspect` or one submission hanging while
  another connection's workflow is dispatched and reconciled, `checkedAt`
  advancing, no second call for the hanging connection or task, and shutdown
  within 5 seconds; a worker whose slow check reports it unready getting no task
  on the verdict of the check before). Nine concurrent cases, about 15 seconds.

All are bounded to 115 seconds, and CI (`.github/workflows/managed.yml`) runs
them one after another. `KEEP_FAKE_MANAGED_FIXTURES=1` retains explicitly
fake temporary directories for diagnosing a failed run. Real Peerspan/model and
upstream transport compatibility require separate smoke checks.

## The fake Peerspan executable

`fake-peerspan.mjs` reads `config.json` in `FAKE_PEERSPAN_FIXTURE` on every
invocation and appends its argument array to `calls.jsonl` (with `at`, the wall
clock, and `mono`, the system monotonic clock in milliseconds), its exit status to
`outcomes.jsonl`, and a call that is made to hang to `hanging.jsonl`. Task records
live in `remote/TASK_ID.json`, written whole once the sender has received the
submission; a suite appends events there as the remote agent would, waiting for
the record first, since a run or review task can be seen `submitting` before it
exists. `task submit` takes the input as one `--input=TEXT` argument and refuses a
separate `--input` value with exit 2, as upstream does for a value that begins
with a hyphen. Configuration keys (all revision 2 keys are optional):

| Key | Meaning |
| --- | --- |
| `hostId`, `agentId`, `adapterId`, `sessionId`, `active`, `ready`, `verified`, `verifiedAt` | The single worker of revision 1: status and `adapter connection` answers. |
| `statusExit`, `statusMalformed` | Worker status exit code; output that is not JSON. |
| `submitMode` | `normal`, `lost-accepted`, `lost-missing`, `rejected`. |
| `inspectMode`, `eventsMode`, `remoteState` | `normal`/`error`/`error-after-submit`; `normal`/`error`/`missing`; the state of a new task. |
| `agents` | Replaces the status `agents` array: `[{id,name,sessions:[{id,adapter_id,connection}]}]`. |
| `adapters` | `adapter connection ADAPTER` answers by adapter ID: `{session_id,state,channel,channel_verified_at}` (an `adapter_id` here overrides the reported one), or `{exit:N}` to fail. An adapter that is not listed is not found. |
| `attention` | Replaces the status `attention` array: `[{kind,subject,detail,command}]`. |
| `statusMode: "daemon-not-running"` | Status prints `{"daemon":"not running","state":PATH,"service":{...}}` and exits 2. |
| `statusOmit` | Top-level status fields to leave out, for example `["agents"]`. |
| `rejectJson` | `true`: every invocation with `--json` exits 2 with `error: unexpected argument '--json' found` and prints nothing on stdout. Revision 3: a list of command names (`status`, `agents`, `adapter`, `submit`, ...) limits this to those commands. |
| `senderStates` | State directories that are sender hosts (default: `PRIVATE-sender` in the fixture directory). `status` for one of them answers as another host with no agents. Revision 3: the entry `"default"` makes a call without `--state` a sender call. |
| `networks` | Revision 3, `agents [--network ID] [--refresh]`: a map from network ID to that network's directory fields (`refreshed_at`, `reachable`, `mine`, `inbound`, `hosts`; missing ones default to null or `[]`). `agents` prints `{network_id,...}` for `--network ID`, or for the only network when it is omitted; an unknown network, no network, or several without `--network` exit 1 with an `error:` line. A `network_id` inside a directory overrides the printed one. The directories are static: `--refresh` is only logged. |
| `agentsExit`, `agentsMalformed`, `agentsOmit` | Revision 3: `agents` exits with this code and an `error:` line; prints output that is not JSON (exit 0); leaves out these top-level directory fields. |
| `senderHostId`, `senderStatusExit`, `senderAttention` | That host's `host_id` (set it to `hostId` for "sender is the worker"); exit code (2 prints the daemon-not-running object); attention items. |
| `cancelMode` | `normal`: `task cancel` sets `cancel_requested` and `cancel_state: "sent"` and records a `cancel_requested` event, once, never changing the state. `error`: exit 2, nothing changed. |
| `recordShape: "rev2"` | New task records carry `cancel_state: null` and `status.cancel_requested: false` from the start. |
| `hang` | Command names (`status`, `agents`, `adapter`, `submit`, `inspect`, `events`, `cancel`) that hang without doing anything until the key no longer lists them, the fixture directory is removed, or `hangSeconds` (default 60) pass; they then exit 2. |
| `scripts` | Revision 4, scripted agents: a list of `{agent,input,submit,state,output,message,progress}`. The first entry whose `agent` (when given) is the submission's `--agent` and whose `input` (when given) is a substring of its input applies to that submission. `submit` (`lost-accepted`, `lost-missing`, `rejected`) replaces `submitMode` for it; a rejected submission's `error` is `message` when given. On a newly created, accepted task with a `state`, the agent then works at once: `accepted` (not for `expired` or `rejected`), one `progress` event per `progress` message, and a terminal event in `state` with `message`, and with `output` (default `FAKE STATE output`) for `succeeded` and `failed`; a `state` of `running` stops after the progress. |
| `profiles`, `runtimeShow` | Revision 5: `agent runtime show` prints `profiles` (default `[]`: no runtime agents), the host's launch profiles `{agent_id,harness,harness_dir,from_branch,network,cpus,memory_mib,timeout_seconds,max_runs,credential}`; `runtime show` prints `runtimeShow` (default: switch on, a report and private paths). |
| `runtimeMode`, `profilesMode`, `profilesExit`, `runtimeShowMode` | Revision 5: `runtimeMode: "older"` makes both commands exit 2 with `error: unrecognized subcommand 'runtime'` and nothing on stdout. `profilesMode` and `runtimeShowMode` make one command fail (`error`: an `error:` line, exiting with `profilesExit` or 1), print output that is not JSON (`malformed`), or, for the profiles, print a JSON object instead of an array (`object`). `hang` takes `agent-runtime` and `runtime`. |
| `delayWhen` | Revision 6.1: slow calls that do not hang, each `{command,state,ms}`: a call of that command (named as in `hang`) whose `--state` is `state` (when given) waits `ms` milliseconds, then reads `config.json` again and answers, so it reports the host as it is when it answers. |
| `hostIds` | Revision 6: a map from a worker state directory to the `host_id` its `status` reports instead of `hostId`, for a second worker host. |
| `hangWhen` | Revision 6: single calls that hang as `hang` says, each `{command,state,agent,task}`: a call of that command (`status`, `agent-runtime`, `runtime`, `submit`, `inspect`, ...) whose `--state` is `state` (`"default"` without one), whose agent is `agent` (its `--agent`, or for a task command the agent its task was submitted to) and that names `task`, for each key given. `hanging.jsonl` entries carry `mono`, as `calls.jsonl` does. |
| `inspectErrorAgents` | Revision 4: agent IDs whose tasks (by the `--agent` of their logged submission) cannot be inspected: `task inspect` exits 2, while other tasks are inspected normally. |

`real-peerspan-smoke.py` is that separate compatibility smoke. It creates two
throwaway actual Peerspan hosts, a network and signed task access, verifies a
scripted adapter, and checks one managed task through actual transport and back
to its retained output. It calls no model and touches no existing daemon:

```sh
python3 managed/conformance/real-peerspan-smoke.py --bin /path/to/built/binaries
```
