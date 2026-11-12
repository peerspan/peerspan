# Runtime agent contract

A **runtime agent** is a registered agent of this host whose tasks the host runs itself, each
in its own microVM, rather than handing them to an attached session. The owner gives the agent
a **launch profile**: the agent program (the harness), the peerfs branch it works from, its
resources, and its model credential. Senders send it ordinary agent tasks under the ordinary
task authorization. They cannot tell, and need not care, that it runs in a VM. Each task runs on
a fork of the profile's branch, and the result names the fork's branch.

This is story 2 of the runtime: the design is decision 6 of `runtime.md` in the internal design
repository, and its decisions are RUN-8 to RUN-11 in the
[decision log](decision-log.md#run-8-to-run-11-runtime-agents-2026-11-12). This contract extends
the [task contract](task-contract.md) and the [runtime task contract](runtime-task-contract.md).
Where it doesn't say otherwise, those contracts apply. It changes nothing for senders: the
peer routes, the authorization of `task.submit`, the status record and the events are as in the
task contract.

There are two harnesses, each with its provider's API key:
- **Codex** (`codex exec`), with an OpenAI API key;
- **Claude** (Claude Code's `claude -p`), with an Anthropic API key (RUN-12, RUN-13).

Not in this contract:
- input artifacts on a runtime agent's tasks (refused, below) and result artifacts;
- talking to a running agent (messages, progress, delegation from inside the VM);
- per-tool-call snapshots;
- a credential proxy, which keeps the key out of the VM;
- subscription logins. Only API keys are supported.

## The launch profile

A profile is local configuration of this host, owned by its owner, like the runtime switch. It
is stored only on this host, in `runtime-agents.json` (mode 0600) in the state directory, never
in policy. It is not policy either: who may send the agent tasks stays governed by grants and
policy rules for `task.submit`.

| Field | Rules | Default |
| --- | --- | --- |
| `agent_id` | A registered agent of this host whose name is addressable (1 to 64 characters of lowercase ASCII letters, digits, `.`, `_` and `-`, starting with a letter or digit). | Required |
| `harness` | `codex` or `claude`. | `codex` |
| `harness_dir` | An absolute path to a directory readable by the runtime, which the owner installs. For `codex` it holds the Codex release's `codex` and `codex-code-mode-host` binaries. For `claude` it holds Claude Code's Linux x64 `claude` binary. | Required |
| `image` | An OCI image reference to boot, such as `python:3.12-slim`: 1 to 1,024 bytes of printable ASCII without whitespace. Null boots the runtime's own image. Claude Code's binary needs glibc, so a `claude` profile needs a glibc image; Codex's is static and runs on any. | null |
| `from_branch` | A peerfs branch name of the runtime's space: 1 to 255 bytes of UTF-8, not `.` or `..`, without `/` or NUL. | `main` |
| `network` | `none` or `internet`. | `internet` |
| `cpus` | 1 to 64. | 2 |
| `memory_mib` | 128 to 262,144. | 2,048 |
| `timeout_seconds` | 1 to 86,400. | 3,600 |
| `max_runs` | 1 to 64: how many of this agent's tasks may be dispatched or running at once. | 3 |

The agent's **credential**, its harness's API key (OpenAI for `codex`, Anthropic for `claude`), is
stored apart from the profile in
`credentials/AGENT_ID` (mode 0600) in the state directory. It is 1 to 4,096 bytes of printable
ASCII with no whitespace; a trailing newline in the input is dropped. It is never written to
policy, a task record, an event, activity, a log or any response.

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `agent runtime set AGENT --harness-dir DIR [--harness codex\|claude] [--image REF] [--from-branch BRANCH] [--network none\|internet] [--cpus N] [--memory-mib N] [--timeout DURATION] [--max-runs N]` | `PUT /v1/agents/{agent_id}/runtime` with the profile's fields but `agent_id` | Creates or replaces the profile. `AGENT` is an agent ID or a local agent's name. It needs the runtime switch on and a runtime that reports `peerfs` true (otherwise 409 `runtime_unavailable`). The resources and `network` may not exceed what the runtime reports, `max_network` included (otherwise 422 `too_large`). An `image` needs a runtime that reports `images` true (otherwise 409 `runtime_unavailable`); whether the image exists is found out at the first run. An agent whose name is not addressable is 400 `invalid`. `--timeout` takes a duration as `task run --timeout` does. An omitted field takes its default, not its previous value. Returns the profile, with `agent_id`, `image` (null when it is not set) and without `credential`. Activity `runtime.agent_set`. |
| `agent runtime show [AGENT] [--json]` | `GET /v1/agents/{agent_id}/runtime`, `GET /v1/agents/runtime` | One profile, or a JSON array of all profiles in agent ID order, each with `credential: true\|false` added. 404 for an agent without a profile. |
| `agent runtime clear AGENT` | `DELETE /v1/agents/{agent_id}/runtime` | Removes the profile, and returns `{}`. Tasks already dispatched or running finish; queued ones are rejected at start. Activity `runtime.agent_cleared`. |
| `agent credential set AGENT --from-file PATH` | `PUT /v1/agents/{agent_id}/credential` with `{value}` | Stores the key, replacing any earlier one. Returns `{agent_id, credential: true}`. Activity `runtime.credential_set`, without the key. |
| `agent credential clear AGENT` | `DELETE /v1/agents/{agent_id}/credential` | Removes the key. Returns `{agent_id, credential: false}`. Activity `runtime.credential_cleared`. |

Removing an agent removes its profile and its credential.

## Receiving a task

A task whose `target_agent_id` is an agent with a profile is received, authorized, persisted
and expired exactly as an agent task is today, with one exception:
- **No input artifacts in this version.** A request with a non-empty `artifacts` manifest is
  refused with 400 `invalid` naming `artifacts`, before it is persisted, so a sender is never
  told that files it attached reached the agent when they did not. Staging input files into
  the VM is later work.

Then:
- It is never offered to an adapter session. `POST /adapter/v1/tasks/next` passes it over, and no
  session can accept, reject, progress, complete or cancel it. Sessions of the agent may still
  attach, and they send and receive messages as before.
- A task that arrived before its agent had a profile stays with the adapter path. A task that
  arrived while the agent had one stays with the runtime, even if the profile is cleared later.
  Whether a received task is a runtime agent's is stored in its record when it is received.

## Running

A queued task of a runtime agent starts when all of these hold:
- the runtime has a free slot;
- fewer than the profile's `max_runs` of that agent's tasks are dispatched or running.

Tasks start in `created_at` order, across all runtime agents and runtime tasks. Before the start
the host rechecks the task's authorization, as at adapter handoff, and then makes the checks
below in their order. A recoverable failure (503
for messages) leaves the task queued. A final failure records `rejected` with the reason
`authorization lapsed before acceptance`, as the task contract specifies.

At the start, the host also checks the following. Each failure ends the task `rejected`, and
`message` gives the reason:
- the runtime switch is on: `the runtime is disabled`;
- the agent still has a profile: `the agent has no launch profile`;
- it still has a credential: `the agent has no credential`.

The host then dispatches the run as for a runtime task (runtime task contract, Running). It
records the dispatch before sending, keeps the dispatch rules for 429 and 422, and resends an
unanswered start after a restart. A 422 ends the task `rejected`, with the runtime's error as
the reason.
- **The request is stored.** The dispatch record holds the whole `POST /v1/runs` body built
  from the profile at that moment, with the secret's path but never the key. Every resend uses
  exactly that body, never the current profile. A profile replaced or cleared after dispatch
  therefore changes nothing for that run, and a resend never meets the runtime's 409 for a
  changed request.
- **A 429 or 422 clears the stored body** with the dispatch. The next start builds a new one
  from the profile as it is then, after the checks above.
- **The credential is read at each start.** A resend reads the credential file at the stored
  path when the runtime starts the run. If it was cleared meanwhile, the run fails before
  `started`, and the task ends `failed` with `Branch: none`.

**The run.** The host sends `POST /v1/runs` with:
- `run_id` as for runtime tasks, from the sender host ID and the task ID;
- `argv` the harness command (below);
- `cwd` `/workspace`;
- `env` `{}`;
- `resources` from the profile;
- `network` the profile's;
- `workspace_archive` null, and `results` `none`;
- `peerfs_workspace` the fork's name, and `peerfs_fork_from` the profile's `from_branch`;
- `peerfs_agent` the agent's name, `peerfs_commit` true, and `peerfs_commit_message`
  `TASK_ID from SENDER_HOST_ID`;
- `stdin` the task's `input`;
- `harness` the profile's `harness_dir`;
- `image` the profile's `image`, left out when it is null;
- `secrets` `{SECRET: PATH}`, the path of the agent's credential file, where SECRET is
  `openai_api_key` for `codex` and `anthropic_api_key` for `claude`.

The **fork's name** is the agent's name, `.`, and the task ID: for example
`codex.task_0123456789abcdef0123456789abcdef`. A sender that reuses another sender's task ID
for the same agent gets a run that fails before it starts, because the runtime refuses to fork
onto an existing name. It never reaches the other task's fork.

**The harness command** for Codex is `["/bin/sh", "-c", SCRIPT]`, where SCRIPT:
1. sets `HOME` to `/root` and `CODEX_HOME` to `/root/.codex`, and creates that directory;
2. sets `CODEX_API_KEY` from `/run/secrets/openai_api_key`;
3. runs `/opt/peerspan/harness/codex exec --json --skip-git-repo-check
   --dangerously-bypass-approvals-and-sandbox --output-last-message FILE -` in `/workspace`,
   with the prompt on its stdin, and its stdout sent to stderr;
4. writes FILE to stdout once Codex exits, and exits with Codex's status.

So the run's stdout is Codex's final message, and its stderr is Codex's event stream and logs.
The VM is the sandbox, so Codex's own sandbox is off. `HOME` lives in the VM's throwaway root,
so Codex's session state ends with the VM.

**The harness command** for Claude is `["/bin/sh", "-c", SCRIPT]`, where SCRIPT:
1. exits 127, writing `the image has no glibc, which Claude Code needs` to stdout, when
   `/lib64/ld-linux-x86-64.so.2` does not exist;
2. sets `HOME` to `/root`, `IS_SANDBOX` to `1`, and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`
   to `1` (RUN-15);
3. sets `ANTHROPIC_API_KEY` from `/run/secrets/anthropic_api_key`;
4. runs `/opt/peerspan/harness/claude -p --dangerously-skip-permissions --output-format text
   --no-session-persistence` in `/workspace`, with the prompt on its stdin, and exits with its
   status.

Its stdout is Claude's final message, or its error, such as an invalid key; its stderr is Claude's
logs. As for Codex, the VM is the sandbox, so Claude's permission checks are off. Claude Code
refuses to skip them as root unless `IS_SANDBOX` is set, and the command runs as root in its own
VM (RUN-13). Without nonessential traffic, Claude Code sends no telemetry or error reports
from the VM, and starts about 1 s sooner; its model calls are unchanged. On an image without glibc the shell starts but Claude Code cannot, so the run
starts and the task ends `failed`. Its output is the message of step 1 and the branch line of a
run that started, `Branch: NAME, unchanged from FROM`. The script's text is fixed by the host release, not
by this contract.

**Transitions.** They are those of a runtime task, with the run result replaced by the
agent's output:

| Transition | Event | When |
| --- | --- | --- |
| `queued` to `running` | `accepted` | The runtime reports `started`. |
| `queued` to `rejected` | `rejected` | A check at start failed, or the runtime refused the run (422). |
| `queued` to `expired` | `expired` | Not dispatched by `deadline`. |
| `queued` to `failed` | `failed` | The runtime reports `exited` without `started`: for example, the fork's name or branch exists already, or `from_branch` does not exist. |
| `running` to `succeeded` | `succeeded` | The command exited 0, and the run result has no `error`. |
| `running` to `failed` | `failed` | Any other exit, a signal, the timeout, or the loss of the run. Also a run result with `error` after the command ran, such as a snapshot or commit that failed, even when the command exited 0. |
| `queued` or `running` to `cancelled` | `cancelled` | As for a runtime task. |

A runtime agent's tasks have no `output` events, and their events have no `chunk` field: they
are agent task events, as in the task contract. The host emits no `progress` events in this
version.

### The output

The final event's `output` is plain text: the agent's message, a blank line, then one last line
naming the branch (RUN-11).
- **The message** is the run's stdout, decoded as lossy UTF-8, with trailing whitespace
  removed. It is cut at a UTF-8 character boundary so that the whole output fits in 65,536
  bytes, and a cut message ends with `…`.
- **An empty message** gives one in its place, by how the run ended: `exit N`, `signal N`,
  `timed out`, `cancelled`, or the run result's `error`.
- **The last line** is exactly one of:
  - `Branch: NAME at commit ID`, where ID is the commit the runtime made (66 lowercase hex
    digits);
  - `Branch: NAME, unchanged from FROM`, when the run changed nothing;
  - `Branch: NAME, not committed: ERROR`, when the run started but the result has `commit`
    null and `error` set, with ERROR being that error on one line, cut to 1,024 bytes. What the
    command wrote stays in the workspace `NAME`, for the owner to commit or discard;
  - `Branch: none`, when the run never started.

  The trailer is chosen in that order of precedence: a result with `error` never reports a
  commit or `unchanged`, so an error stays visible even when the message is not empty.

A run the runtime lost (runtime task contract, restarts) has the empty-message rule's `error`,
so its output is `the runtime restarted`, a blank line, and `Branch: NAME, not committed: the
runtime restarted`; what the command wrote stays in the workspace `NAME`.

The stdout and stderr logs are not attached and not served. The output of a `cancelled` task
follows the same rules. A task cancelled before dispatch has `output` null, as in the runtime
task contract.

**The branch.** For a run that started, the runtime snapshots the fork before and after the
command, attributing both snapshots to the agent. It then commits the fork to its branch as one
commit, signed by the space's key, with the message `TASK_ID from SENDER_HOST_ID` and the
agent's name as the commit's agent. It does this however the command ended, so a failed or
cancelled task's partial work is kept. The owner compares and merges the branches with peerfs
(`peerfs log`, `ws merge`). Until peerfs replicates across hosts, the branches stay on the
receiving host.

## The runtime's local API

`POST /v1/runs` gains these optional fields. Each defaults to its value for a runtime task, and
runtime tasks never set them. The runtime refuses anything else with 400.

| Field | Rules |
| --- | --- |
| `network` | `none` (the default) or `internet`. 422 `too_large` above the runtime's maximum. |
| `stdin` | Standard base64 of at most 65,536 bytes, given to the command as its standard input; null (the default) gives it an empty one. |
| `harness` | An absolute path of a directory the runtime mounts read-only at `/opt/peerspan/harness`, or null. |
| `secrets` | An object of at most 16 entries mapping a name (1 to 64 characters of `A-Z`, `a-z`, `0-9`, `_`, `.` and `-`, not `.` or `..`) to an absolute path of a file of at most 65,536 bytes. Each file is read when the run starts, and its content is given to the guest at `/run/secrets/NAME`, readable only by root, in memory, and never in the workspace, its history, the run's files or the logs. A file that cannot be read fails the run before `started`. |
| `peerfs_fork_from` | A branch name, with `peerfs_workspace` set. The runtime first creates a branch named `peerfs_workspace` at this branch's head, then a workspace of that name following it. A workspace or branch of that name that exists already, or a `from` branch that does not, fails the run before `started`, changing nothing. |
| `peerfs_agent` | An addressable agent name, with `peerfs_workspace` set: the agent recorded on the run's snapshots and commit. Default `peerspan-runtime`. |
| `peerfs_commit` | `true` or `false` (the default), with `peerfs_workspace` set. With `true`, once the run has ended and been snapshotted, the runtime commits the workspace to its branch: one commit, with the message `peerfs_commit_message`. |
| `peerfs_commit_message` | 1 to 4,096 bytes of UTF-8. Required with `peerfs_commit` true. |
| `image` | An OCI image reference, as for a profile, or null (the default). The run boots it in place of the runtime's own image, with the image's environment merged under `env` as for the runtime's own. The runtime pulls an image it does not have into its image cache when the run starts. A reference it cannot parse is 400, and one it cannot pull fails the run before `started`, with `error` saying why. A runtime that reports `images` false answers a run naming one with 422 `unavailable`. |

The `exited` event's result gains `commit`: the commit's peerfs object ID, or null when there
was no commit to make (nothing changed, the run never started, or `peerfs_commit` was false). A
commit that fails sets `error` and leaves `commit` null. The task's run result for runtime
tasks (runtime task contract, The run result) does not gain it.

`GET /v1/runtime` gains `max_network`, `none` or `internet`, and `images`: true when runs may
name an `image`.

With these fields, the runtime task contract's guarantee "the guest has no network" holds when
`network` is `none`.

## Persistence

The host schema version increments by one, with no new tables: it is the next free version on
`main` when the implementing PR merges. The received task record of a runtime agent's task gains
`runtime_agent: true` and the internal run fields that a runtime task has: `run_id`, whether the
run was dispatched, and the last stored runtime event sequence. While dispatched, it also holds
the stored `POST /v1/runs` body (Running, above), which never contains the key. The fork's name
is derived, not stored. Profiles are the `runtime-agents.json` file, and credentials are the `credentials/`
directory, neither a table. Older binaries reject the new version.

New activity kinds are `runtime.agent_set`, `runtime.agent_cleared`, `runtime.credential_set`
and `runtime.credential_cleared`. A runtime agent's tasks record `task.run_started` and
`task.run_exited` on the receiving side, as runtime tasks do, in place of `task.accepted` and
`task.completed`.

## Verification

A new suite, `runtime_agents`, is written from this contract by a separate author who does not
read `src/`, `tests/` or `integrations/` (DEC-OWN6, DEC-OWN9). It uses
`conformance/slim/runtime_common.py`, and it drives two real Rust hosts through the CLI, the
owner API and the adapter socket with `conformance/slim/harness.py` and its test clock, without
KVM and without model calls. It stays under 2 minutes and runs in the second tier with the other
runtime suites.

**The fake runtime** gains the new fields:
- It checks each one as above, and reports `max_network` (`internet` unless told otherwise on
  its command line) and `images` (true unless told otherwise).
- It records `image` with the rest of the request, and fails the run before `started` for an
  image named on its command line as one it cannot pull.
- With `harness` set, it ignores `argv` and acts as the agent. It reads its stdin, the prompt,
  and fails the run before `started`, with an `error` naming the secret, unless exactly one of
  `secrets.openai_api_key` and `secrets.anthropic_api_key` is given and its file is readable.
- It then runs the prompt as steps, in the same language that `argv` uses for runtime tasks, so
  `write PATH TEXT ; echo done` changes the fork and answers `done`.
- `peerfs_fork_from` copies the named workspace directory of its command line, or an earlier
  fork's, to a new one, and refuses an existing name.
- A commit's ID is `01` followed by the lowercase hex SHA-256 of the workspace's sorted paths and
  contents and the commit message, or null when nothing changed since the fork.
- A command-line flag makes every commit fail, giving `commit` null and `error` set.
- It records each request's fields, `secrets` paths but never their contents, in a file named on
  its command line, so the suite can check what the host sent.

The suite covers:
- **Profiles:** `agent runtime set` with defaults and with every option; replacing a profile;
  `show` with and without a credential; `clear`; refusal with the runtime switch off, for a
  runtime reporting `peerfs` false, for resources over the runtime's maximums, for an
  `image` on a runtime reporting `images` false, and for an agent whose name is not
  addressable. `agent credential set` and `clear`, with the key never
  appearing in any response, task record, event, activity or log.
- **Receiving:** a task to a runtime agent, sent by the owner's other host (citing `self`) and by
  another person's host under a grant, never offered to an attached session of the agent. A task
  received before the profile was set stays with the adapter path. A task with an input artifact
  refused with 400 naming `artifacts`, and nothing persisted.
- **Running:** the request the host sends. It has the harness `argv` beginning `/bin/sh -c`, the
  task's `input` as `stdin`, the profile's resources and network, and the fork name
  `NAME.TASK_ID` from `from_branch`. It has `peerfs_agent`, `peerfs_commit` true with the message `TASK_ID from SENDER_HOST_ID`, the harness
  directory, and a secret path whose file holds the stored key. A `claude` profile with an
  `image`: the `argv` runs `claude -p`, the secret is `anthropic_api_key`, and `image` is the
  profile's; a profile without one sends no `image`.
- **An image that cannot be pulled:** the task fails before `started`, with `Branch: none`.
  (A `claude` profile on an image without glibc fails after `started`. That is a live check, not
  a suite case, since the fake runtime runs no shell.)
- **Lifecycle:** queued, accepted, then succeeded with the output `MESSAGE\n\nBranch: NAME at
  commit ID`. The fork holds the agent's write, and `from_branch` is unchanged.
- **Failure and empty output:** a failing exit with its message and branch line. An empty message
  replaced by `exit N`. A run that changed nothing, giving `unchanged from FROM`.
- **Before the start:** a missing secret file failing the task before `started` with `Branch:
  none`. A clash with an existing fork name failing the same way, leaving that fork untouched.
  A message over the output bound, cut with `…`.
- **Concurrency:** `max_runs` 1 with two tasks and two runtime slots running one after the
  other. Two agents, each with `max_runs` 1, running side by side.
- **Checks at start:** the profile cleared while a task is queued, and the credential cleared,
  each ending `rejected` with its reason. The runtime switch turned off ending `rejected`.
  Authorization withdrawn while queued ending `rejected` with `authorization lapsed before
  acceptance`.
- **Cancellation:** while running, ending `cancelled` with an output and a branch line.
  Before dispatch, ending `cancelled` with `output` null.
- **Restarts:** the daemon during a run, reattaching and finishing. The fake runtime during a
  run, failing the task with `the runtime restarted`. The daemon restarted after dispatch but
  before `started`, with the profile replaced and then cleared meanwhile: the resent request is
  byte-identical to the first one, and the task finishes.
- **Result delivery (RUN-14):** two tasks at once whose prompts sleep 8 seconds before
  answering each reach the sender's local record as `succeeded` within 2 seconds of the receiver
  storing it.
  The RUN-15 variable is not a suite case: the script's text is the host release's.
- **A failed commit:** with the fake runtime told to fail commits, a command that exits 0
  ending `failed` with its message and the `not committed:` trailer.
- **Migration:** opening a database of the previous schema version.

A **live acceptance** run, story 2 in `runtime.md`, uses an installed release, `peerspan-runtime`
with real VMs, and a real key. Three tasks from the owner's laptop to `codex` on the owner's
server, with no open session there, run concurrently on three forks. Each returns a message and
a branch, and the owner merges one. With per-run snapshots (RUN-10), each branch's history holds
the before and after snapshots and the commit, all attributed to the agent, rather than one
snapshot per tool call. The run also records memory per agent VM, wall time and tokens per task.
The same run with a `claude` profile on a glibc image, and a real Anthropic key, is the
acceptance for the second harness.
`conformance/live_runtime_agents.py` runs this on one machine, with both hosts there: a manual check that
needs KVM, a Codex release and a real key.
