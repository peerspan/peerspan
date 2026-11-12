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
are the revision 3 suites. They are split by area to stay near 1,000 lines each
and share `harness.mjs`: the fixture, HTTP and event-stream helpers, the fake's
logs, the `MANAGED_CLOCK_FILE` test clock, and the exact revision 3 shapes of
contract sections 3, 7.1, 8, 10, 11, 14 and 15, which are checked on every
snapshot any of them fetches. Every response body is also checked for fixture
paths, the access token and `PRIVATE-` markers (section 8).

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

All are bounded to 115 seconds. `KEEP_FAKE_MANAGED_FIXTURES=1` retains explicitly
fake temporary directories for diagnosing a failed run. Real Peerspan/model and
upstream transport compatibility require separate smoke checks.

## The fake Peerspan executable

`fake-peerspan.mjs` reads `config.json` in `FAKE_PEERSPAN_FIXTURE` on every
invocation and appends its argument array to `calls.jsonl` (with `at`, the wall
clock, and `mono`, the system monotonic clock in milliseconds), its exit status to
`outcomes.jsonl`, and a call that is made to hang to `hanging.jsonl`. Task records
live in `remote/TASK_ID.json`; a suite appends events there as the remote agent
would. `task submit` takes the input as one `--input=TEXT` argument and refuses a
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

`real-peerspan-smoke.py` is that separate compatibility smoke. It creates two
throwaway actual Peerspan hosts, a network and signed task access, verifies a
scripted adapter, and checks one managed task through actual transport and back
to its retained output. It calls no model and touches no existing daemon:

```sh
python3 managed/conformance/real-peerspan-smoke.py --bin /path/to/built/binaries
```
