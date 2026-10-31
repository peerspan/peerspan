# Runtime task contract

A **runtime task** is a task whose receiver is the receiving host's runtime rather than an
agent: the host runs the task's command in a microVM and streams its output back. The design
is in the [runtime task proposal](runtime-task-proposal.md), and its decisions are RUN-1 to
RUN-5 in the [decision log](decision-log.md#run-1-to-run-5-runtime-tasks-2026-10-27-and-2026-10-31).
This contract extends the [task contract](task-contract.md) and the
[artifact contract](artifact-contract.md); what it
does not change is as specified there. The runtime is the separate `peerspan-runtime` binary
in `peerspan/runtime`; this contract fixes its local API with the daemon, not its internals.

Membership, policies and their signing are those of the
[coordinator-free spec](decentralized-spec.md) and its
[wire appendix](decentralized-wire-formats.md). Runtime tasks work only in coordinator-free
networks; legacy coordinator networks are read-only history (spec section 14) and authorize
nothing. The Rust host in `rust/` is the only host (DEC-OWN5).

Not in this contract: guest network access, choosing a guest image, stdin, grants for
runtime tasks, delegating a runtime task onward, peerfs workspaces, and agents in the VM.

## Requests

`POST /peer/v1/tasks` accepts runtime tasks. A runtime task has exactly `task_id`,
`executor`, `run`, `deadline`, `input`, `policy`, optional `origin`, and optional `artifacts`.
- `executor` is `"runtime"`. A request without `executor` is an agent task, as today; an
  explicit `"agent"` is the same. Any other value is 400.
- A runtime task has no `target_agent_id`, `grant_id` or `chain`; any of them is 400.
- `input` is as for tasks: the purpose shown to the owner and in activity.
- The whole request, `run` included, is part of idempotency by `(sender, task_id)`.

`run` has exactly these fields; all but `argv` may be omitted:

| Field | Rules |
| --- | --- |
| `argv` | 1 to 256 strings, each 1 to 4,096 bytes of UTF-8 without NUL; at most 65,536 bytes summed. |
| `cwd` | An absolute path of at most 4,096 bytes without NUL. Default `/workspace`. |
| `env` | An object of at most 64 entries. Names match `^[A-Za-z_][A-Za-z0-9_]{0,255}$`; values are at most 4,096 bytes of UTF-8 without NUL. |
| `workspace` | `{"archive": SHA256}` or null (the default), which gives an empty `/workspace`. |
| `resources` | An object with optional `cpus` (1 to 64), `memory_mib` (128 to 262,144) and `timeout_seconds` (1 to 86,400). |
| `results` | `none`, `output` (the default) or `changes`. |

A workspace archive is an input artifact: its digest must appear in the request's
`artifacts` manifest with media type `application/x-tar` or `application/gzip`, or the request
is 400. It is fetched before the run as inputs are today, and is subject to the artifact
limits and the rule's `max_artifact_bytes`.

Failures of these rules return 400 `invalid` with the field named in `error`.

## Authorization

Runtime tasks are authorized by a **runtime rule** in the receiving host's owner's policy and
by the host's **local switch**. Both must hold.

### Runtime rules

A runtime rule is `{host, principals, max_cpus, max_memory_mib, max_seconds,
max_output_bytes, max_artifact_bytes, allow_disconnected}`. It grants its principals the
action `runtime.run` on the host it names. A receiving host honours only rules naming itself.

| Field | Range |
| --- | --- |
| `host` | A host ID; it need not be a current member when signed. |
| `principals` | 1 to 64, as for rules. |
| `max_cpus` | 1 to 64. |
| `max_memory_mib` | 128 to 262,144. |
| `max_seconds` | 1 to 86,400. |
| `max_output_bytes` | 0 to 67,108,864. |
| `max_artifact_bytes` | 0 to 1,073,741,824, as for task rules; it bounds the workspace archive and the result artifacts together. |
| `allow_disconnected` | `true` or `false`, as for capability rules: with `true`, a sender whose membership lapsed still matches while the policy is current (Checks, step 2). |

At most 64 runtime rules per policy, and at most one per host; two rules naming one host are
400.

**Policy body.** Runtime rules amend the `peerspan-policy-v2` body that a person's `policy`
statement carries (spec section 5, wire appendix section 5). The body gains `runtime_rules`,
after `capability_rules`, omitted when empty, so a policy without runtime rules has the same
body as before. Each rule is an object with exactly these keys, in this order: `host`,
`principals`, `max_cpus`, `max_memory_mib`, `max_seconds`, `max_output_bytes`,
`max_artifact_bytes`, `allow_disconnected`. For example:

```json
"runtime_rules":[{"host":"host_aaaa…","principals":["person:person_7245…"],"max_cpus":4,"max_memory_mib":8192,"max_seconds":3600,"max_output_bytes":1048576,"max_artifact_bytes":104857600,"allow_disconnected":false}]
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
host and never in policy, so a machine holding the person key cannot enable another machine's
runtime.

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
3. the rule's bounds: each of `resources` at most the rule's maximum, and the input manifest
   within `max_artifact_bytes`; failure is 403.

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

A queued runtime task starts when its workspace archive is stored and the runtime has a free
slot. The host starts runtime tasks in `created_at` order. Missing `resources` take the
rule's maximum.

| Transition | Event | When |
| --- | --- | --- |
| `queued` to `running` | `accepted` | The runtime reports `started`. |
| `queued` to `rejected` | `rejected` | The local switch is off at start, the rule lapsed, or the runtime refused the run (422 below); `message` gives the reason. |
| `queued` to `expired` | `expired` | Not started by `deadline`. |
| `running` to `succeeded` | `succeeded` | The command exited 0. |
| `running` to `failed` | `failed` | Any other exit, a signal, the timeout, a failure before the command started, or the loss of the run. |
| `queued` to `cancelled` | `cancelled` | A cancellation request arrived before the run started. |
| `running` to `cancelled` | `cancelled` | A cancellation request arrived while running and the runtime stopped the run. |

Unlike an agent, the host always honours a cancellation request. For a queued runtime task it
ends the task `cancelled` at once, with `output` null. For a running one it forwards the
request to the runtime, and the task ends `cancelled` when the runtime reports the stop, even
if the command had just exited.

### Output events

Events gain the nullable field `chunk`. A new event kind, `output`, carries
`chunk: {stream, data}`, where `stream` is `stdout` or `stderr` and `data` is standard base64
of 1 to 16,384 bytes. Every other event has `chunk: null`. `output` events occur only while
`running` and carry state `running`.
- The host emits an `output` event when it holds 16,384 bytes of one stream, or 250 ms after
  the first byte it holds, whichever is first.
- Order is kept within each stream, not between them.
- Once a task has streamed `max_output_bytes` in total, the host emits no more `output`
  events for it. With `max_output_bytes` 0, it emits none.
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
| `results_dropped` | Result artifact names that did not fit `max_artifact_bytes`, in the order below; usually `[]`. |
| `error` | A short text when the run failed outside the command, such as `the runtime restarted`; otherwise null. |

The `cancelled` event of a task that was running has the run result as `output` too, with
`signal` 9.

### Result artifacts

The final event's `artifacts` lists, by `results`:
- `none`: nothing;
- `output`: `stdout.log` and `stderr.log` (`text/plain`), the full streams, each cut at
  104,857,600 bytes;
- `changes`: those two, then `changes.tar` (`application/x-tar`), the regular files under
  `/workspace` that are new or whose content differs from the workspace archive, and
  `deleted.txt` (`text/plain`), one removed path per line, both relative to `/workspace`.
  `changes.tar` and `deleted.txt` are attached together or not at all.

The host attaches them in that order while the input and result sizes together fit the rule's
`max_artifact_bytes`, and names the rest in `results_dropped`. A dropped result never fails
the task. Results are served, fetched, retained and pruned as task results are today.

## Submitter

### Peer events

`GET /peer/v1/tasks/{task_id}/events` accepts `wait=S`, 0 (the default) to 25: when no event
after `after` exists, the receiver holds the request up to `S` seconds until one does. It
applies to every task.

The submitter polls a runtime task that is `running` with `wait=25`, immediately again after
each response, using one of its 4 polling slots. Other states keep the task contract's
schedule.

### CLI and local API

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `task run --peer HOST [--workspace DIR] [--results none\|output\|changes] [--cpus N] [--memory-mib N] [--timeout DURATION] [--env NAME=VALUE ...] [--cwd PATH] [--input TEXT] [--deadline TIME] [--detach] -- COMMAND...` | `POST /v1/tasks` with `executor` and `run` | Packs the workspace (below), uploads it, cites the target's policy, and submits. `--input` defaults to the command line joined with spaces, cut at 65,536 bytes. Without `--detach` it follows the local events, writes each `output` chunk to its own stdout or stderr, saves result artifacts into `./peerspan-results/TASK_ID/` when `--results changes`, and exits with `exit_code`, 128 + `signal`, 124 for a timeout, or 125 when the task ended otherwise. With `--detach` it prints the local record. |
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

MCP **`run_task`** takes `{destination, argv, workspace_path?, cwd?, env?, resources?,
results?, input?}`. The adapter packs `workspace_path` under the agent's own permissions,
uploads it, submits, and returns the task ID. `task_status` and `artifact_save` work for
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
| `runtime enable --socket PATH [--for PRINCIPAL ...] [--max-cpus N] [--max-memory-mib N] [--max-seconds N] [--max-output-bytes N] [--max-artifact-bytes N] [--allow-disconnected] [--network ID]` | `PUT /v1/runtime` with `{socket}`, then the policy routes | Checks that `GET /v1/runtime` answers on `PATH`, stores the switch, then adds or replaces this host's runtime rule in the person's policy for the selected network and signs the next version through the network's provider, as a policy edit with a version check (spec section 12.1): a policy that changed meanwhile fails with `state_conflict` and the CLI reloads and starts again, and an unsettled edit refuses it. Before signing it states that hosts on software without runtime rules will stop accepting this person's policy (RUN-5). `--network` is optional when this host belongs to exactly one coordinator-free network. `--for` defaults to `person:` this host's person, the person its binding grant names. The maximums default to 2 vCPUs, 2,048 MiB, 3,600 seconds, 1,048,576 output bytes and 104,857,600 artifact bytes, and may not exceed what the runtime reports. |
| `runtime disable [--network ID]` | `DELETE /v1/runtime`, then the policy routes | Clears the switch and removes this host's runtime rule, signing as for `runtime enable`. Running tasks finish; queued ones are rejected at start. |
| `runtime show [--json]` | `GET /v1/runtime` | `{enabled, socket, runtime, rule}`: the switch, the runtime's own report or its error, and this host's runtime rule, if any. |

`run --runtime-socket PATH` sets the switch at start and overrides the stored value.

## The runtime's local API

`peerspan-runtime serve --socket PATH` serves the daemon over a Unix socket that only the
daemon's user can reach, with the `admin.sock` conventions: HTTP/1.1, JSON, `{code, error}`
error bodies, unknown fields rejected. The daemon never boots VMs or opens a run's files
other than those below.

| Route | Behavior |
| --- | --- |
| `GET /v1/runtime` | `{version, image, max_cpus, max_memory_mib, max_seconds, max_concurrent_runs, running}`. |
| `POST /v1/runs` with `{run_id, argv, cwd, env, resources, workspace_archive, results}` | Starts a run. `resources` is complete; `workspace_archive` is an absolute path the daemon can read, or null. 201 with the run record `{run_id, state, created_at}`; 200 with the same record for an identical repeat; 409 for a reused `run_id` with different fields; 429 when every slot is busy; 422 when `resources` exceed the runtime's maximums. |
| `GET /v1/runs/{run_id}/events?after=N&wait=S` | Events with `sequence` after `N`, waiting up to `S` (0 to 25) seconds for the first. Each is `{sequence, kind, ...}`: `started`; `stdout` or `stderr` with `data` (base64, 1 to 16,384 bytes); `exited` with `result`, the run result above without `output_truncated` and `results_dropped`; then `results` with `artifacts`, a list of `{name, path, size, sha256, media_type}` in the order above. `results` is last. |
| `POST /v1/runs/{run_id}/cancel` | Stops the run. It then ends with `exited`, `signal` 9. A finished run is unchanged. |
| `DELETE /v1/runs/{run_id}` | Deletes the run and its files. |
| any unknown `run_id` | 404. |

`run_id` is `run_` followed by the lowercase hex SHA-256 of `<sender host ID>/<task_id>`.

The runtime guarantees that:
- the archive is unpacked **inside the VM** into an empty `/workspace`; an entry that is
  absolute, contains `..`, or is not a directory, regular file or symbolic link fails the run
  before the command starts, with `error` naming the entry;
- every host file access for the workspace stays within the run's own workspace directory,
  whatever the archive's symbolic links point at;
- the guest has no network;
- `timeout_seconds` is enforced from `started`.

The daemon copies each result file into its artifact store, verifying size and digest, then
deletes the run. A restarted daemon reattaches to its runs by `run_id` and resumes from its
last stored runtime event. A run the runtime does not know (404) while the task is `running`
fails it with `error: "the runtime restarted"`.

## Persistence

The host schema version increments by one, with no new tables: it is the next free version on
`main` when the implementing PR merges (`main` is at 24 today). No `dec_*` table changes.
Received and outbound task records gain `executor` and `run`; received ones also gain the
internal `run_id`, the authorizing bounds, and the last stored runtime event sequence. Event
records gain `chunk`.
Route records accept `runtime.run`. The runtime switch is stored in the daemon's settings.
Older binaries reject the new version. New activity kinds are `task.run_started` and
`task.run_exited` on the receiving side, and `runtime.enabled` and `runtime.disabled`.

## Verification

`conformance/slim/runtime.py` and `conformance/slim/fake_runtime.py` are written from this
contract by a separate author who does not read `rust/` or `integrations/` (DEC-OWN6,
DEC-OWN9). The suite drives two or three real Rust hosts through the CLI, the owner API and
the adapter socket with `conformance/slim/harness.py` and its test clock, without KVM and
without model calls. It stays under 2 minutes and runs as its own `runtime` job in
`.github/workflows/conformance.yml`. Cases that do not fit in that time go to Rust tests
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
maximums unless told otherwise on its command line.

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
- cancellation while running ending `cancelled` with a run result, and while queued ending
  `cancelled` at once without one;
- the workspace: an archive fetched before start and readable by the run; a missing manifest
  entry or wrong media type (400); a refused archive entry failing the run with `error`;
- results: `none`, `output` and `changes`, including deletions, and the drops under a small
  `max_artifact_bytes` and under 0;
- peer events with `wait`, returning early when an event arrives;
- restarts: the daemon during a run, reattaching and finishing; the fake runtime during a
  run, failing the task with `the runtime restarted`;
- `task run` exit codes and `--detach`; `runtime enable`, `disable` and `show`;
- MCP `run_task` with a workspace path, output notification coalescing and `meta.output`;
- opening a database of the previous schema version.

A live run of the proposal's story 1 on two machines, with `peerspan-runtime` and real VMs,
records the agent-facing experience separately.
