# Runtime tasks: running a task's commands in a microVM

Status: proposed 2026-10-27; nothing here is decided or implemented. The decisions to settle
are under [Decisions](#decisions), each with a recommendation. When they are settled, the
accepted parts become `docs/runtime-task-contract.md`.

This is the first slice of the system design's runtime ("Runtime" in `docs/runtime.md` in
`docs-internal`): user story 1, one person running a delegated task's commands in a microVM
on another of their own machines. Story 3, the same across two owners, uses the same contract
with a different rule's principals. It extends the [task contract](task-contract.md) and the
[artifact contract](artifact-contract.md). The runtime itself is a separate binary,
`peerspan-runtime`, in the public `peerspan/runtime` repository; its `run` command already
boots a libkrun microVM with a workspace attached and runs one command.

## Story 1

Priya is in Claude Code on her laptop. She says "run the integration suite on my
workstation". Her agent calls `run_task` with the workstation as destination, `make
test-integration` as the command, and its working directory as the workspace. The laptop
submits a task to the workstation. The workstation boots a microVM with the workspace at
`/workspace`, runs the command, and streams its output back as task events, which reach her
session as `task_update` events. The task ends with the exit code; files the run changed come
back as a result. If the laptop sleeps, the task finishes anyway and the laptop catches up
from the event cursor, as for any task.

## Goals and non-goals

**Goals:**
- A task whose receiver is a host's runtime rather than an agent: durable submission, events,
  cancellation and results exactly as for tasks today.
- Streaming of the command's output, and a structured result: exit code, signal, timeout.
- A workspace sent with the task, and the files the run changed sent back.
- Owner control on the serving host: runtime use is off unless the owner allows it in policy
  **and** the host enables its runtime locally.
- Resource bounds the owner sets and the requester can only narrow: vCPUs, memory, run time.
- A local contract between the daemon and `peerspan-runtime`, so both daemons drive one
  runtime, and conformance can run against a fake runtime without KVM.

**Non-goals for this slice:**
- **Network access from the guest.** Runs have none.
- **Choosing a guest image.** Each host runs one image its owner configures.
- **Agents inside the VM** (story 2), and therefore runtime agent keys (`docs/runtime.md`,
  decision 4). The run is attributed to the submitting agent through `origin`.
- **Stdin and interactive commands.**
- **Delegating a runtime task onward.** A runtime task is a leaf of any delegation chain.
- **peerfs workspaces** until peerfs replicates between hosts (peerfs milestone 3); see
  decision 2.
- **macOS serving hosts**, until `peerspan-runtime` runs there.

## Design

### Requests

A **runtime task** is a task with `executor: "runtime"` and a `run` object instead of a
`target_agent_id`. Existing tasks are `executor: "agent"`, the default when the field is
absent, so current peers and records are unchanged.

`POST /peer/v1/tasks` for a runtime task carries exactly `task_id`, `executor`, `run`,
`deadline`, `input`, optional `origin`, optional `artifacts`, and `policy` (decision 1 rules
out grants for now). `input` stays required, as a short human-readable purpose ("integration
suite for PR 418"), shown in activity and in the owner's view; the command is in `run`.

`run` is:

| Field | Type | Rules |
| --- | --- | --- |
| `argv` | array of strings | 1 to 256 entries, each 1 to 4,096 bytes of UTF-8 without NUL; at most 65,536 bytes together. `argv[0]` is looked up on the guest's `PATH` when it contains no `/`. |
| `cwd` | string | Absolute guest path; default `/workspace`. |
| `env` | object of string to string | At most 64 entries. Names match `[A-Za-z_][A-Za-z0-9_]*`; values at most 4,096 bytes without NUL. `PATH` defaults to the image's. |
| `workspace` | object or null | Decision 2. Null runs with an empty `/workspace`. |
| `resources` | object | `{cpus, memory_mib, timeout_seconds}`, each optional and defaulting to the rule's maximum; each above the rule's maximum returns 403. |
| `results` | string | `none`, `output` (the default), or `changes`; decision 3. |

The whole request is part of idempotency by `(sender, task_id)`, as today.

### States and events

States are those of tasks; the receiving host's runtime plays the agent's part:

| Transition | When |
| --- | --- |
| `queued` | The host persisted the task. Input artifacts are fetched as today; the task waits for them and for a free runtime slot (`max_concurrent_runs`, default 1). |
| `queued` to `running`, event `accepted` | The runtime started the command in a booted VM. |
| `queued` to `rejected` | The host cannot run it: the runtime is not enabled, the rule lapsed (as today), or the runtime refused it (image missing, resources above the host's own caps). The reason says which. |
| `queued` to `expired` | Not started before `deadline`. |
| `running` to `succeeded` / `failed` | The command exited 0 / anything else, was killed by a signal, timed out, or the VM failed. |
| `running` to `cancelled` | After a cancellation request, the runtime stopped the VM. Unlike an agent, the runtime always honors a request it receives while the command runs. |

`deadline` bounds the wait to start; `resources.timeout_seconds` bounds the run.

A new event kind, **`output`**, carries a chunk of the command's output while `running`:
`chunk: {stream, data}`, where `stream` is `stdout` or `stderr` and `data` is base64 of at
most 16,384 bytes. Events gain the nullable field `chunk`; every other kind has `chunk: null`.
The host coalesces output into chunks at most every 250 ms. Order is kept within each stream,
not between them. A rule's `max_output_bytes` (default 1 MiB, at most 64 MiB) caps the bytes
streamed per task; past it the host stops emitting `output` events and the final result
records `output_truncated: true`. Output events record no activity.

The final `succeeded` or `failed` event's `output` is the **run result**, a JSON object
serialized as text:

```json
{"exit_code": 1, "signal": null, "timed_out": false, "duration_ms": 41873,
 "stdout_bytes": 52114, "stderr_bytes": 311, "output_truncated": false,
 "error": null}
```

`exit_code` is null when a signal ended the command (`signal` is its number), when it timed
out, or when it never started; `error` is a short text for a runtime failure ("the VM exited
before the command reported"), otherwise null. Result artifacts are in decision 3.

### Authorization and the local switch

Decision 1. A runtime task is authorized by the serving host's owner policy and by a local
switch on that host, and the run uses the bounds of the rule that authorized it, checked at
submission and rechecked when the run starts, as task acceptance is today. Revocation after
the run starts does not stop it; cancellation does.

### Submitter

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `task run --peer HOST [--workspace DIR] [--results none\|output\|changes] [--cpus N] [--memory-mib N] [--timeout DURATION] [--env NAME=VALUE ...] [--cwd PATH] [--input TEXT] [--deadline TIME] [--detach] -- COMMAND...` | `POST /v1/tasks` with `executor` and `run` | Packs `--workspace` (decision 2), uploads it as an input artifact and submits. Without `--detach` it follows the task's events, writes `output` chunks to its own stdout and stderr, saves result artifacts when `--results changes`, and exits with the command's exit code (125 if the task did not run, 124 on timeout, 128 + signal). `--input` defaults to the command line. |
| `task inspect`, `task events`, `task cancel` | as today | Unchanged; events show `chunk`. |

Agents use a route whose action is `runtime.run`. The adapter gains MCP **`run_task`**
`{destination, argv, workspace_path?, cwd?, env?, resources?, results?, input?}`. The adapter,
not the daemon, reads and packs `workspace_path`, under the agent's own permissions, as it
does for artifacts. `task_update` events for `output` events carry the decoded text in
`meta.chunk` (lossy UTF-8) and are coalesced per session to at most one notification per
second, so a chatty command cannot flood the agent's context; the final event carries the run
result and any result manifest.

### Daemon and runtime: the local contract

The daemon never boots VMs. It talks to `peerspan-runtime serve` over a Unix socket, using the
`admin.sock` conventions: HTTP/1.1 and JSON under `/v1`, `{code, error}` error bodies, unknown
fields rejected, the socket mode 0600 in a directory of mode 0700. The daemon is configured
with `--runtime-socket PATH`; without it, runtime tasks are rejected with `runtime not
enabled`.

| Runtime API | Behavior |
| --- | --- |
| `GET /v1/runtime` | `{version, image, max_cpus, max_memory_mib, max_concurrent_runs, running}`: what this runtime can do now. |
| `POST /v1/runs` with `{run_id, argv, cwd, env, resources, workspace_archive, results}` | Starts a run; `workspace_archive` is a path to a file the daemon owns (decision 2) or null. 201 with the run record; 409 for a reused `run_id` with different fields; 429 when all slots are busy; 422 when resources exceed the runtime's caps. |
| `GET /v1/runs/{run_id}/events?after=N&wait=SECONDS` | Events after `N`, waiting up to `wait` (at most 30) for the first. Kinds: `started`, `stdout`, `stderr` (`data` base64), `exited` (the run result), `changes` (`{path, size, sha256}` of the result archive). |
| `POST /v1/runs/{run_id}/cancel` | Stops the VM; the run then ends with `exited`, `signal: 9`. |
| `DELETE /v1/runs/{run_id}` | Releases the run's files once the daemon has stored what it needs. |

`run_id` is the daemon's `<sender>/<task_id>` digest, so a restarted daemon reattaches to its
runs. If the runtime restarts, its runs are lost and the daemon fails the task with `error:
"the runtime restarted"`. The daemon owns task state; the runtime owns only the VM and its run
directory.

### Persistence

The received task's record gains `executor`, `run`, the `run_id`, and the authorizing rule's
bounds (internal, never served), as `max_artifact_bytes` is stored today. `output` events are
stored like other events. The database version increments; route records gain the
`runtime.run` action. New activity kinds: `task.run_started` and `task.run_exited` on the
receiving side.

## Decisions

### 1. Who may run, and how a host opts in

**Recommendation.** Two gates, as for raw sources on a person's own machines (capabilities
contract, "The open list"):

1. **A runtime rule in the owner's signed policy.** A new rule kind,
   `{runtime: HOST_ID, principals, actions: ["runtime.run"], max_cpus, max_memory_mib,
   max_seconds, max_output_bytes, max_artifact_bytes}`, that names the serving host, so a
   receiving host honours only rules naming itself, as capability rules do. Principals work as
   in other rules: the owner's own hosts for story 1, another person for story 3.
2. **The local switch.** The serving host's daemon has `--runtime-socket` configured, which
   only its local owner can do. A person key alone therefore never turns a machine into a
   place others run code.

`peerspan runtime enable [--for PRINCIPAL ...]` does both on the serving machine: it installs
and starts the runtime, configures the socket, and adds the rule (by default for the person's
own hosts).

**Not chosen.** Grants for runtime tasks in this slice: rules give the two-sided gate and the
bounds in one signed place, and grants can follow if wanted. Reusing `task.submit`: running
commands on a host is different authority from asking an agent, and an owner who allows one
should not get the other. Policy alone: anyone with the person key could make every machine
of that person an executor.

**Dependency.** The rule's signed statement depends on the policy format, which the
coordinator-free work (#140) may still change; the runtime rule follows whatever format that
settles.

### 2. How the workspace reaches the VM

**Recommendation.** Define `workspace` as one of two variants, and implement the first now:

- `{"archive": SHA256}`: an input artifact, a tar archive (`application/x-tar`, optionally
  gzip, `application/gzip`), within the artifact limits (100 MiB per file, the rule's
  `max_artifact_bytes`). It is **unpacked inside the VM** into an empty workspace, never on
  the host, so a hostile archive meets the guest's kernel and the workspace server's
  confinement rather than the host's filesystem. The CLI and adapter pack a git working tree
  with `git ls-files --cached --others --exclude-standard`, so ignored files (`node_modules`,
  `target/`) stay behind, and any other directory whole.
- `{"peerfs": {"space", "commit"}}`: a peerfs commit the serving host fetches by hash, once
  peerfs replicates (milestone 3). The runtime then attaches peerfs's own `vhost-user-fs`
  server instead of a directory.

**Not chosen.** Waiting for peerfs before shipping story 1: it would gate the runtime on
peerfs milestone 3. A `git clone` URL: it needs network and credentials in the guest, which
this slice rules out.

### 3. What comes back

**Recommendation.** The submitter chooses with `results`:
- `none`: the run result only.
- `output` (default): also `stdout.log` and `stderr.log` as result artifacts, each the full
  output up to the per-artifact limit, so a long log survives the streaming cap.
- `changes`: also `changes.tar`, the regular files in `/workspace` that are new or differ
  from the input archive, and `deleted.txt`, the paths that were removed.

Result artifacts count toward the rule's `max_artifact_bytes`. With a bound of 0, `output`
and `changes` downgrade to `none` and the run result says so (`results_dropped: true`),
rather than failing a run that already happened. With peerfs, `changes` becomes a commit on
a task branch instead.

**Not chosen.** The whole workspace back: large, and mostly what the submitter already has.
Streaming only, with no artifacts: a long log would be lost past the streaming cap.

### 4. The fake runtime for conformance

**Recommendation.** `conformance/fake_runtime.py` implements the local contract without
VMs, written from the contract by the separate conformance author: `argv` is a small script
language (`echo`, `fail CODE`, `sleep SECONDS`, `write PATH TEXT`), enough for every state
and result. Daemon conformance across Go/Rust pairings uses it; real VMs are tested in
`peerspan/runtime`'s CI and in a separate live end-to-end run of story 1.

**Not chosen.** Real VMs in daemon conformance: it would need KVM on every conformance host
and would test the runtime rather than the daemons.

## Verification sketch

`conformance/runtime_tasks.py`, every Go/Rust pairing, against the fake runtime:
- refusal without a runtime rule, with a rule naming another host, and with the local switch
  off; refusal under a `task.submit`-only rule; a `runtime.run` route versus a
  `task.submit` route;
- resources above the rule's maximum (403) and above the runtime's caps (`rejected`);
- the lifecycle: queued, accepted, output, succeeded; failure with an exit code, a signal and
  a timeout; expiry before start;
- output chunks in order per stream, the `max_output_bytes` cap and `output_truncated`;
- cancellation while running ending `cancelled`;
- the workspace archive fetched before start, and `results` `none`, `output` and `changes`,
  including the downgrade under `max_artifact_bytes: 0`;
- daemon restart while running, reattaching by `run_id`; runtime restart failing the task;
- MCP `run_task` with `task_update` coalescing;
- migration from the previous database version.

A live run of story 1 on two machines with real VMs records the agent-facing experience.
