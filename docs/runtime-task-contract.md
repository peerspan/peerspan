# Runtime task contract

A **runtime task** is a task whose receiver is the receiving host's runtime rather than an
agent: the host runs the task's command in a microVM and streams its output back. The design
is in the [runtime task proposal](runtime-task-proposal.md), and its decisions are RUN-1 to
RUN-5 in the [decision log](decision-log.md#run-1-to-run-5-runtime-tasks-2026-10-27-and-2026-10-31),
with RUN-6 and RUN-7 for [peerfs workspaces](decision-log.md#run-6-and-run-7-peerfs-workspaces-2026-11-02).
This contract extends the [task contract](task-contract.md) and the
[artifact contract](artifact-contract.md); what it
does not change is as specified there. The runtime is the separate `peerspan-runtime` binary
in `peerspan/runtime`; this contract fixes its local API with the daemon, not its internals.

Membership, policies and their signing are those of the
[coordinator-free spec](decentralized-spec.md) and its
[wire appendix](decentralized-wire-formats.md). Runtime tasks work only in coordinator-free
networks; legacy coordinator networks are read-only history (spec section 14) and authorize
nothing. The Rust host at the repository root is the only host (DEC-OWN5).

Not in this contract: guest network access, choosing a guest image, stdin, grants for
runtime tasks, delegating a runtime task onward, and agents in the VM.

## Requests

`POST /peer/v1/tasks` accepts runtime tasks. A runtime task has exactly `task_id`,
`executor`, `run`, `deadline`, `input`, `policy`, optional `origin`, and optional `artifacts`.
- `executor` is `"runtime"`. A request without `executor` is an agent task, as today; an
  explicit `"agent"` is the same. Any other value is 400.
- A runtime task has no `target_agent_id`, `grant_id`, `self` or `delegation` (the chain); any
  of them, or any other field not listed here, is 400 naming it.
- `input` is as for tasks: the purpose shown to the owner and in activity.
- The whole request, `run` included, is part of idempotency by `(sender, task_id)`.

`run` has exactly these fields; all but `argv` may be omitted:

| Field | Rules |
| --- | --- |
| `argv` | 1 to 256 strings, each 1 to 4,096 bytes of UTF-8 without NUL; at most 65,536 bytes summed. |
| `cwd` | An absolute path of at most 4,096 bytes without NUL. Default `/workspace`. |
| `env` | An object of at most 64 entries. Names match `^[A-Za-z_][A-Za-z0-9_]{0,255}$`; values are at most 4,096 bytes of UTF-8 without NUL. |
| `workspace` | `{"archive": SHA256}`, `{"peerfs": NAME}`, or null (the default), which gives an empty `/workspace`. `NAME` is 1 to 255 bytes of UTF-8, not `.` or `..`, without `/` or NUL. |
| `resources` | An object with optional `cpus` (1 to 64), `memory_mib` (128 to 262,144) and `timeout_seconds` (1 to 86,400). |
| `results` | `none`, `output` (the default) or `changes`. |

A workspace archive is an input artifact: its digest must appear in the request's
`artifacts` manifest with media type `application/x-tar` or `application/gzip`, or the request
is 400. It is fetched before the run as inputs are today, and is subject to the artifact
limits and the rule's `max_artifact_bytes`.

A **peerfs workspace** is a workspace of the [peerfs](https://github.com/peerspan/peerfs) space
the receiving host's runtime serves. The command runs on that workspace's files at
`/workspace`, and what it changes stays there, in the workspace's history, for later runs
and for the host's owner. Its `results` is `none` or `output`; `changes` is 400, since the
run result names the snapshot instead (The run result, below). `max_artifact_bytes` does not
bound a peerfs workspace, which is the receiving host's own storage.

Failures of these rules return 400 `invalid` with the field named in `error`.

## Authorization

Runtime tasks are authorized by a **runtime rule** in the receiving host's owner's policy and
by the host's **local switch**. Both must hold.

### Runtime rules

A runtime rule is `{host, principals, max_cpus, max_memory_mib, max_seconds,
max_output_bytes, max_artifact_bytes, peerfs_workspaces, allow_disconnected}`. It grants its
principals the action `runtime.run` on the host it names. A receiving host honours only rules naming itself.

| Field | Range |
| --- | --- |
| `host` | A host ID; it need not be a current member when signed. |
| `principals` | 1 to 64, as for rules. |
| `max_cpus` | 1 to 64. |
| `max_memory_mib` | 128 to 262,144. |
| `max_seconds` | 1 to 86,400. |
| `max_output_bytes` | 0 to 67,108,864. |
| `max_artifact_bytes` | 0 to 1,073,741,824, as for task rules; it bounds the workspace archive and the result artifacts together. |
| `peerfs_workspaces` | 0 to 64 distinct workspace names, each as for `{"peerfs": NAME}`, in ascending byte order: the peerfs workspaces its principals may run on (RUN-6). Empty allows none. |
| `allow_disconnected` | `true` or `false`, as for capability rules: with `true`, a sender whose membership lapsed still matches while the policy is current (Checks, step 2). |

At most 64 runtime rules per policy, and at most one per host; two rules naming one host are
400.

**Policy body.** Runtime rules amend the `peerspan-policy-v2` body that a person's `policy`
statement carries (spec section 5, wire appendix section 5). The body gains `runtime_rules`,
after `capability_rules`, omitted when empty, so a policy without runtime rules has the same
body as before. Each rule is an object with exactly these keys, in this order: `host`,
`principals`, `max_cpus`, `max_memory_mib`, `max_seconds`, `max_output_bytes`,
`max_artifact_bytes`, `peerfs_workspaces`, `allow_disconnected`. For example:

```json
"runtime_rules":[{"host":"host_aaaa…","principals":["person:person_7245…"],"max_cpus":4,"max_memory_mib":8192,"max_seconds":3600,"max_output_bytes":1048576,"max_artifact_bytes":104857600,"peerfs_workspaces":["agent"],"allow_disconnected":false}]
```

- **Reading.** A host admits a policy statement whose body has the existing fields with or
  without `runtime_rules`. It refuses the statement as `invalid` when `runtime_rules` is
  present but empty, a rule has a missing, unknown or duplicate key, or a value is out of
  range.
- **Renewal and edits.** Automatic policy renewal copies `runtime_rules` unchanged. An edit
  that does not touch runtime rules copies them too. When unsettled edits are re-applied
  (spec section 12.1), each host's rule is one unit, and a withdrawal wins.
- **Compatibility.** Hosts built before this contract, v0.1.0 included, refuse a policy whose
  body has `runtime_rules`, as they refuse any unknown field. They keep the person's previous
  policy until it expires, at most 24 hours later, and then hold no current policy for that
  person, so every request they make under it to that person's hosts is refused. An owner
  adds a runtime rule only once every host in the network runs software that implements this
  contract. `runtime enable` says so before it signs (RUN-5).

### The local switch

The daemon's runtime is enabled when it is started with `run --runtime-socket PATH` (alias
`serve`), or when the owner sets it with `runtime enable` (below). It is stored only on this
host, as `runtime.json` (mode 0600) in the state directory, and never in policy, so a machine
holding the person key cannot enable another machine's runtime.

### Checks

At submission the receiver checks, in order:
1. the local switch: off is 403 `runtime_disabled`;
2. policy authorization as for capability rules: the request cites P's policy
   (`{person_id, version}`), and P's current policy in a coordinator-free network this host
   and the sender share has a runtime rule naming this host whose principals match the
   sender, with the deadline at most that policy's `valid_until`. Without
   `allow_disconnected`, the sender must also be a current member of that network: its host
   grant and the grant's chain are current and not banned (spec section 5). Failure is 403 as
   for tasks; a cited version newer than this host holds is 503;
3. the rule's bounds: each of `resources` at most the rule's maximum, the input manifest
   within `max_artifact_bytes`, and a peerfs workspace named in `peerfs_workspaces`; failure
   is 403.

The task is then persisted `queued` as today. Before the run starts the host rechecks 1 to 3;
a final failure records `rejected` with the reason, and a recoverable one leaves the task
queued. The bounds of the rule that authorized the start are stored in the received task's
record, never served, and govern the run. Revocation after the run starts does not stop it;
cancellation does. So, as for any accepted work (spec section 5), the sender's grants
expiring, a ban, or P's policy lapsing stops a queued start but not a started run, which may
outlast the 24-hour policy that authorized it.

The `runtime.run` action is valid only in runtime rules. Rules and grants refuse it, and
`task.submit` never authorizes a runtime task.

## Running

A queued runtime task starts when its workspace archive, if any, is stored and the runtime
has a free slot. The host starts runtime tasks in `created_at` order, passing over one whose
peerfs workspace another of its runtime tasks, dispatched or running, is using: runs on one
workspace take turns. Missing `resources` take the
rule's maximum.

The host **dispatches** a run when it sends `POST /v1/runs`. It records the dispatch in the
received task's record before sending, so a restarted daemon treats an unanswered start as
dispatched. A dispatched task stays `queued` until the runtime reports `started` or `exited`,
and from then on the runtime, not the host, decides how it ends: the deadline no longer
applies, and a cancellation is forwarded. A definite refusal clears the dispatch, because no
run exists: after a 429 the task is an ordinary queued task again, so its deadline applies and
authorization is rechecked before the next start; a 422 ends it `rejected`. A runtime
answers 429 too when another of its runs holds the task's peerfs workspace. Only a start that
was accepted (201 or 200) or whose answer is unknown keeps the task dispatched.

| Transition | Event | When |
| --- | --- | --- |
| `queued` to `running` | `accepted` | The runtime reports `started`. |
| `queued` to `rejected` | `rejected` | The local switch is off at start, the rule lapsed, or the runtime refused the run (422 below); `message` gives the reason. |
| `queued` to `expired` | `expired` | Not dispatched by `deadline`. |
| `queued` to `failed` | `failed` | The runtime reports `exited` without `started`: the run failed before the command started, for example on a refused archive entry, or a peerfs workspace that does not exist or is held outside the runtime. The run result has `exit_code` null, `duration_ms` 0 and `error` set. |
| `running` to `succeeded` | `succeeded` | The command exited 0. |
| `running` to `failed` | `failed` | Any other exit, a signal, the timeout, or the loss of the run. |
| `queued` to `cancelled` | `cancelled` | A cancellation request arrived before dispatch, or after dispatch and the runtime then reported `exited` without `started`, or answered 404. |
| `running` to `cancelled` | `cancelled` | A cancellation request arrived while running and the runtime stopped the run. |

Unlike an agent, the host always honours a cancellation request. For a queued task not yet
dispatched it ends the task `cancelled` at once, with `output` null. For a dispatched or
running one it forwards the request with `POST /v1/runs/{run_id}/cancel`, and the task ends
`cancelled` when the runtime reports `exited`, even if the command had just exited, with the
run result as `output`. If `started` arrives first, the task moves to `running` with
`accepted` before it ends.
- **A start in flight.** The host forwards a cancellation only once no `POST /v1/runs` for
  that run is outstanding: while one is in flight, it waits for the answer first. A 201 or
  200 means the run exists, and the cancellation is then forwarded. A 429, a 422, or a start
  that never reached the runtime means no run exists, and the task ends `cancelled` with
  `output` null.
- **404.** With no start outstanding, a runtime that answers 404 to the cancellation never
  created the run, or lost it, and the task ends `cancelled` with `output` null. A restarted
  daemon has no start outstanding, and it does not resend the start of a task whose
  cancellation was requested.

### Output events

A runtime task's events gain the nullable field `chunk`; an agent task's events are unchanged,
so older submitters keep reading them. A new event kind, `output`, carries
`chunk: {stream, data}`, where `stream` is `stdout` or `stderr` and `data` is standard base64
of 1 to 16,384 bytes. Every other event of a runtime task has `chunk: null`. `output` events occur only while
`running` and carry state `running`.
- The host emits an `output` event when it holds 16,384 bytes of one stream, or 250 ms after
  the first byte it holds, whichever is first.
- Order is kept within each stream, not between them.
- Once a task has streamed `max_output_bytes` in total, the host emits no more `output`
  events for it: it streams exactly that many bytes, cutting the last chunk, and
  `output_truncated` is true when the command wrote more. With `max_output_bytes` 0, it emits
  none, and `output_truncated` is true if the command wrote anything.
- `output` events record no activity.

### The run result

The final `succeeded` or `failed` event's `output` is the run result, a JSON object written
as text, with exactly these keys in this order:

| Key | Meaning |
| --- | --- |
| `exit_code` | The command's exit status, or null if it was killed by a signal, timed out or never started. |
| `signal` | The signal number that ended it, or null. A timeout is null here. |
| `timed_out` | Whether the run hit `timeout_seconds`. |
| `duration_ms` | From `started` to exit. 0 if it never started. |
| `stdout_bytes`, `stderr_bytes` | Bytes the command wrote. |
| `output_truncated` | Whether streaming stopped at `max_output_bytes`. |
| `results_dropped` | Result artifact names that did not fit `max_artifact_bytes` or the per-artifact limit, in the order below; usually `[]`. |
| `results_same` | An object mapping each result artifact name left out because its content equals an earlier attached one's to that earlier name; usually `{}`. |
| `snapshot` | For a peerfs workspace, the peerfs snapshot the runtime took after the command, its peerfs object ID of 66 lowercase hex digits, or null when the command changed no source path or never started (RUN-7). Null for every other run. |
| `error` | A short text when the run failed outside the command, such as `the runtime restarted`; otherwise null. |

The `cancelled` event of a task that was running has the run result as `output` too, with
`signal` 9.

**Snapshots.** For a peerfs workspace the runtime snapshots the workspace before the command
starts and again after it ends, by exit, signal, timeout or cancellation, so `snapshot`
holds only what the run changed: earlier changes are in the snapshot before it, which
`peerfs ws snapshots` lists next. Snapshots are peerfs's own: unsigned, kept on the
receiving host, and taking source paths only, never derived or secret ones. The owner
commits, restores or discards them with peerfs; this contract does not.

### Result artifacts

The final event's `artifacts` lists, by `results`:
- `none`: nothing;
- `output`: `stdout.log` and `stderr.log` (`text/plain`), the full streams, each cut at
  104,857,600 bytes;
- `changes`: those two, then `changes.tar` (`application/x-tar`), the regular files under
  `/workspace` that are new or whose content differs from the workspace archive, and
  `deleted.txt` (`text/plain`), one removed path per line, both relative to `/workspace`.
  Not for a peerfs workspace.

The host takes them in that order and attaches each one whose size, added to the inputs and
the results already attached, fits the rule's `max_artifact_bytes`; one that does not fit is
named in `results_dropped`, and the later ones are still tried. A dropped result never fails
the task.
- **Per-artifact limit.** A `changes.tar` over 104,857,600 bytes, the artifact contract's
  limit for one file, is dropped.
- **Together.** `deleted.txt` is never attached without `changes.tar`: when `changes.tar` is
  dropped, `deleted.txt` is dropped with it.
- **Empty files.** An empty result file is never attached, and is not a drop. The runtime always
  makes `changes.tar` a valid tar, never an empty file, so it is attached even when no file
  changed. An empty log
  shows as `stdout_bytes` or `stderr_bytes` 0, and `changes.tar` without `deleted.txt` means
  nothing was removed.
- **Identical files.** Digests are unique within a manifest (artifact contract), so a result
  file whose content equals one already attached is left out and named in `results_same`,
  mapped to the earlier name: for example `{"stderr.log": "stdout.log"}` when both streams
  wrote the same bytes. It is not a drop. Results are served, fetched, retained and pruned as task results are today.

## Submitter

### Peer events

`GET /peer/v1/tasks/{task_id}/events` accepts `wait=S`, 0 (the default) to 10: when no event
after `after` exists, the receiver holds the request up to `S` seconds until one does. It
applies to every task. The bound is that of a held call status request, within the peer
transport's 15-second serve bound.

The submitter polls a runtime task that is `running` with `wait=10`, immediately again after
each response, using one of its 4 polling slots. Other states keep the task contract's
schedule.

### CLI and local API

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `task run --peer HOST [--workspace DIR \| --peerfs-workspace NAME] [--results none\|output\|changes] [--cpus N] [--memory-mib N] [--timeout DURATION] [--env NAME=VALUE ...] [--cwd PATH] [--input TEXT] [--deadline TIME] [--detach] -- COMMAND...` | `POST /v1/tasks` with `executor` and `run` | Packs the workspace (below), uploads it, cites the target's policy, and submits; with `--peerfs-workspace` it sends `{"peerfs": NAME}` and uploads nothing, and `--results changes` is refused. `--input` defaults to the command line joined with spaces, cut at 65,536 bytes. Without `--detach` it follows the local events, writes each `output` chunk to its own stdout or stderr, saves result artifacts into `./peerspan-results/TASK_ID/` when `--results changes`, writing a name in `results_same` as a copy of the file it maps to, and exits with `exit_code`, 128 + `signal`, 124 for a timeout, or 125 when the task ended otherwise, `cancelled` included. With `--detach` it prints the local record. |
| `task inspect`, `task events`, `task cancel`, `task artifact` | as today | Records and events show `executor`, `run` and `chunk`. |

`POST /v1/tasks` takes `executor: "runtime"` and `run` in place of `target_agent_id`; the
other fields are as for tasks, without `grant_id`.

**Packing.** The CLI, and the adapter for agents, pack the workspace as an uncompressed tar
in the pax format, with directories, regular files with their mode, and symbolic links, and
nothing else. Inside a git working tree, the paths are those of `git ls-files --cached
--others --exclude-standard -z` from the workspace root, so ignored files stay behind;
otherwise the whole directory. Paths are relative, with no `..` component.

### Agents

Routes accept the action `runtime.run`. A `runtime.run` route names a host, not an agent,
and cites the host owner's policy.

| Adapter API | Behavior |
| --- | --- |
| `POST /adapter/v1/runs` with `{destination, task_id, run, input?, workspace_archive?}` | Submits a runtime task through the named `runtime.run` route; `workspace_archive` is a digest the adapter uploaded. Ownership, repeats and the deadline follow `POST /adapter/v1/delegations`. Returns the local record. |

MCP **`run_task`** takes `{destination, argv, workspace_path?, peerfs_workspace?, cwd?, env?,
resources?, results?, input?}`, with at most one of `workspace_path` and `peerfs_workspace`.
The adapter packs `workspace_path` under the agent's own permissions, uploads it, submits, and
returns the task ID; `peerfs_workspace` names a workspace of the destination's space and
uploads nothing. `POST /adapter/v1/runs` takes `{"peerfs": NAME}` in `run.workspace`.
`task_status` and `artifact_save` work for
runtime tasks.

**Output notifications.** For runtime tasks, the daemon creates a task-update notification
for an `output` event only when none was created for that task in the previous second, or
when it is the last `output` event before a final event. Such a notification's MCP event
carries `meta.output`, the text of every `output` chunk since the previous one notified,
decoded as lossy UTF-8, with `stdout` and `stderr` interleaved in event order and cut to the
last 65,536 bytes. Every other event notifies as today; the final one carries the run result
and the result manifest.

## Runtime administration

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `runtime enable --socket PATH [--person-key PATH] [--for PRINCIPAL ...] [--max-cpus N] [--max-memory-mib N] [--max-seconds N] [--max-output-bytes N] [--max-artifact-bytes N] [--peerfs-workspace NAME ...] [--allow-disconnected] [--network ID]` | `PUT /v1/runtime` with `{socket}`, then the policy routes | Checks that `GET /v1/runtime` answers on `PATH`, stores the switch, then adds or replaces this host's runtime rule in the person's policy for the selected network and signs the next version through the network's provider, as a policy edit with a version check (spec section 12.1): a policy that changed meanwhile fails with `state_conflict` and the CLI reloads and starts again, and an unsettled edit refuses it. Before signing it states that hosts on software without runtime rules will stop accepting this person's policy (RUN-5). `--network` is optional when this host belongs to exactly one coordinator-free network. `--for` defaults to `person:` this host's person, the person its binding grant names. The maximums default to 2 vCPUs, 2,048 MiB, 3,600 seconds, 1,048,576 output bytes and 104,857,600 artifact bytes, and may not exceed what the runtime reports. `--peerfs-workspace` fills `peerfs_workspaces` (default none) and is refused when the runtime reports `peerfs` false. |
| `runtime disable [--network ID] [--person-key PATH]` | `DELETE /v1/runtime`, then the policy routes | Clears the switch and removes this host's runtime rule, signing as for `runtime enable`. Running tasks finish; queued ones are rejected at start. |
| `PUT /v1/runtime`, `DELETE /v1/runtime` | | Set or clear only the switch, never the policy. `PUT` takes `{socket}`, an absolute path whose runtime answers `GET /v1/runtime` (otherwise 503), and returns the runtime's report; `DELETE` returns `{"enabled": false}`. Both answer 200. |
| `runtime show [--json]` | `GET /v1/runtime` | `{enabled, socket, runtime, rule}`: the switch, the runtime's own report or `{error}`, and this host's runtime rule with its `network_id` added, from the first coordinator-free network by ID whose current policy of this host's person has one, or null. |

`run --runtime-socket PATH` sets the switch at start and overrides the stored value.

## The runtime's local API

`peerspan-runtime serve --socket PATH` serves the daemon over a Unix socket that only the
daemon's user can reach, with the `admin.sock` conventions: HTTP/1.1, JSON, `{code, error}`
error bodies, unknown fields rejected. The daemon never boots VMs or opens a run's files
other than those below.

| Route | Behavior |
| --- | --- |
| `GET /v1/runtime` | `{version, image, max_cpus, max_memory_mib, max_seconds, max_concurrent_runs, running, peerfs}`, where `peerfs` says whether the runtime serves a peerfs space. |
| `POST /v1/runs` with `{run_id, argv, cwd, env, resources, workspace_archive, peerfs_workspace, results}` | Starts a run. `resources` is complete; `workspace_archive` is an absolute path the daemon can read, or null; `peerfs_workspace` is a workspace name or null, and at most one of the two is set. 201 with the run record `{run_id, state, created_at}`; 200 with the same record for an identical repeat; 409 for a reused `run_id` with different fields; 429 when every slot is busy or another run holds the peerfs workspace; 422 when `resources` exceed the runtime's maximums, or when a peerfs workspace is asked of a runtime that serves no peerfs space. |
| `GET /v1/runs/{run_id}/events?after=N&wait=S&limit=L` | Events with `sequence` after `N`, at most `L` (1 to 1,000; without `limit`, all), waiting up to `S` (0 to 25) seconds for the first. Each is `{sequence, kind, ...}`: `started`; `stdout` or `stderr` with `data` (base64, 1 to 16,384 bytes); `exited` with `result`, the run result above without `output_truncated`, `results_dropped` and `results_same` (`snapshot` included); then `results` with `artifacts`, a list of `{name, path, size, sha256, media_type}` in the order above. `results` is last. |
| `POST /v1/runs/{run_id}/cancel` | Stops the run. It then ends with `exited`, `signal` 9. A finished run is unchanged. |
| `DELETE /v1/runs/{run_id}` | Deletes the run and its files; 200 with `{}`. |
| any unknown `run_id` | 404. |

The run record's `state` is `running` until the run has exited, then `exited`. The events
response is a JSON array of events. Error codes are `invalid` (400), `not_found` (404),
`conflict` (409), `too_large` and `unavailable` (422), and `busy` (429); `unavailable` is a
peerfs workspace asked of a runtime that serves no peerfs space. A run that never started still ends
with `exited` then `results`.

`run_id` is `run_` followed by the lowercase hex SHA-256 of `<sender host ID>/<task_id>`.

The runtime guarantees that:
- the archive is unpacked **inside the VM** into an empty `/workspace`; an entry that is
  absolute, contains `..`, or is not a directory, regular file or symbolic link fails the run
  before the command starts, with `error` naming the entry;
- every host file access for the workspace stays within the run's own workspace directory,
  whatever the archive's symbolic links point at;
- a peerfs workspace is served by a confined process of the run's own that reaches only
  that workspace and the space's stored history; the space's server refuses other changes
  to the workspace until the run ends, and the runtime snapshots it before and after the
  command (Snapshots, above);
- the guest has no network;
- `timeout_seconds` is enforced from `started`.

The daemon copies each result file into its artifact store, verifying size and digest, then
deletes the run. A restarted daemon reattaches to its runs by `run_id` and resumes from its
last stored runtime event.
- **An unanswered start.** For each dispatched task still `queued`, a restarted daemon first
  sends the identical `POST /v1/runs` again: 200 resumes a run the runtime already has, and
  201 starts one it never received. Because the host had stored no `started`, the command
  starts from the beginning, in a fresh VM without network. A 429 or 422 clears the dispatch,
  as at a first start.
- **A lost run.** Otherwise, a run the runtime does not know (404) fails the task with
  `error: "the runtime restarted"`: from `running` as above, and from a dispatched `queued`
  task through `queued` to `failed`, with the run result of a run that never started. A lost
  run's peerfs workspace keeps what the command wrote, without a snapshot after it.

## Persistence

The host schema version increments by one, with no new tables: it is the next free version on
`main` when the implementing PR merges (`main` is at 24 today). No `dec_*` table changes.
Received and outbound task records of runtime tasks gain `executor` and `run`, and have no
`target_agent_id`; agent tasks' records are unchanged; received ones also gain the
internal `run_id`, whether the run was dispatched, the authorizing bounds, and the last stored
runtime event sequence. Event
records gain `chunk`.
Route records accept `runtime.run`. The runtime switch is the `runtime.json` file above, not a
table.
Older binaries reject the new version. New activity kinds are `task.run_started` and
`task.run_exited` on the receiving side, and `runtime.enabled` and `runtime.disabled`.

## Verification

The runtime suites and `conformance/slim/fake_runtime.py` are written from this contract by a
separate author who does not read `src/`, `tests/` or `integrations/` (DEC-OWN6, DEC-OWN9).
They are split by area, with shared helpers in `conformance/slim/runtime_common.py`:
`runtime` (requests, the switch, checks), `runtime_policy` (rules, routes and administration),
`runtime_renewal` (lapsed senders and renewal), `runtime_runs` (running, output, cancel and
restarts), `runtime_results` (workspaces, result artifacts, the CLI, the adapter and MCP) and
`runtime_peerfs` (RUN-6 and RUN-7). They drive two or three real Rust hosts through the CLI,
the owner API and the adapter socket with `conformance/slim/harness.py` and its test clock,
without KVM and without model calls. Each stays under 2 minutes and runs as its own job in
the second tier, `.github/workflows/conformance-full.yml` (DEC-OWN15). Cases that do not fit in that time go to Rust tests
that drive the binaries.

**The fake runtime** implements the local API with no VM. It reads `argv` as steps separated
by the argument `;`:
- `echo TEXT...` writes the words and a newline to stdout; `stderr TEXT...` to stderr;
- `bytes N` writes `N` bytes of `x` to stdout;
- `cat PATH` writes a workspace file, relative to `/workspace`, to stdout;
- `write PATH TEXT` and `rm PATH` change the workspace;
- `sleep SECONDS` waits, and `exit CODE` and `kill SIGNAL` end the run.

It unpacks the archive into a private directory, refusing the entries this contract
refuses, computes results as specified, and reports `max_concurrent_runs` 1 and fixed
maximums unless told otherwise on its command line. A command-line delay holds each run
before `started`; a run cancelled during it ends with `exited`, `signal` 9 and no `started`.
Workspace names given on its command line are its peerfs workspaces, each a directory kept
across runs, and it reports `peerfs` true only when given some. Its snapshot is `01` and the
lowercase hex SHA-256 of the workspace's sorted paths and contents after the command, or
null when they are those it had before; it answers 429 for a workspace one of its runs
holds, and fails a run on a name it was not given before `started`.

The suite covers:
- the policy body: a policy with runtime rules admitted by the owner's other host and by a
  host of another person; a policy without them unchanged; an empty `runtime_rules`, an
  unknown key and two rules for one host refused; `runtime_rules` kept across an automatic
  renewal (test clock); and `runtime.run` refused in rules and routes for agents;
- authorization: the switch off (403 `runtime_disabled`), no rule, a rule naming another
  host, a principal that does not match, a `task.submit`-only rule, a grant or
  `target_agent_id` on a runtime task (400), resources over the rule's maximum (403), and a
  sender whose grants lapsed (test clock), refused without `allow_disconnected` and accepted
  with it;
- rechecks at start: the switch turned off and the rule withdrawn while queued, each ending
  `rejected`; resources over the runtime's maximums ending `rejected`;
- the lifecycle: queued, accepted, output, succeeded with the run result; failure by exit
  code, signal and timeout; expiry before start; start order with one slot;
- output: chunks in order per stream, the 16,384-byte bound, `max_output_bytes` and
  `output_truncated`, and `max_output_bytes` 0;
- cancellation while running ending `cancelled` with a run result, while queued ending
  `cancelled` at once without one, and after dispatch but before `started` (the fake
  runtime told to delay its start) ending `cancelled` with no command run;
- a failure before the command started (a refused archive entry) ending `queued` to `failed`
  with `exit_code` null and `duration_ms` 0;
- the workspace: an archive fetched before start and readable by the run; a missing manifest
  entry or wrong media type (400); a refused archive entry failing the run with `error`;
- peerfs workspaces: `peerfs_workspaces` in the policy body, admitted, kept across a renewal,
  and refused when unsorted, duplicated or holding an invalid name; a run on a named
  workspace seeing an earlier run's write and returning `snapshot`, and `snapshot` null when
  it changed nothing; a workspace the rule does not name (403); `{"peerfs": NAME}` with
  `results` `changes` and an invalid name (400); a workspace the runtime does not have
  failing the run before `started`; two tasks on one workspace with two runtime slots
  running one after the other, while a task on another workspace starts beside the first; `runtime enable --peerfs-workspace` refused when the
  runtime reports `peerfs` false; `task run --peerfs-workspace` and MCP `run_task` with
  `peerfs_workspace`;
- results: `none`, `output` and `changes`, including deletions, and the drops under a small
  `max_artifact_bytes` and under 0; a command with no output attaching no logs; identical
  stdout and stderr giving `results_same`; and `deleted.txt` left out when nothing was
  removed. A `changes.tar` over the per-artifact limit is a Rust test, not a suite case;
- peer events with `wait`, returning early when an event arrives;
- restarts: the daemon during a run, reattaching and finishing; the daemon after dispatch and
  before `started`, resending the start and finishing; the fake runtime during a run, and
  during its start delay, each failing the task with `the runtime restarted`;
- `task run` exit codes and `--detach`; `runtime enable`, `disable` and `show`;
- MCP `run_task` with a workspace path, output notification coalescing and `meta.output`;
- opening a database of the previous schema version.

A live run of the proposal's story 1 on two machines, with `peerspan-runtime` and real VMs,
records the agent-facing experience separately.
