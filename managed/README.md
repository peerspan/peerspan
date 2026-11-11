# Peerspan Managed operator preview

A local console and durable scheduler for agent sessions that are already
attached to Peerspan. It dispatches recurring assignments as Peerspan tasks,
keeps every task identity and result across restarts, and shows what needs you.
The Peerspan daemon and each owner's access rules stay the authority for
execution: this application only invokes the owner CLI on this machine.

![The console's overview: attention items, workflows with their latest runs, a followed program, runs and activity](assets/console-overview.png)

The picture shows scripted demonstration data, not real agent work.

It needs Node 24, Linux or WSL, and an installed Peerspan CLI that accepts the
global `--json` flag. There are no npm dependencies and no build step.

## Start

```sh
node managed/cli.mjs doctor        # checks Node, flock, state permissions and the Peerspan CLI
node managed/cli.mjs serve
# In another terminal, print your private sign-in token:
node managed/cli.mjs token
```

Open http://localhost:4310 and paste the token. The server binds loopback only
and is not a hosted service. Runtime state lives in
`~/.local/state/peerspan-managed`, never in the repository; pass
`--state /absolute/dir` to every command for an independent workspace.

On Windows, `./managed.ps1 doctor`, `token` and `status` run the same commands
in WSL (Ubuntu-24.04 by default; `-Distro NAME -LinuxUser NAME` override that),
and `start` and `stop` control the user service described below.

## Connect a worker

A worker is one agent on a Peerspan host whose state directory is on this
machine, with a running model session that has acknowledged its Peerspan channel.
Prepare it with the upstream quick start and grant the sender host task access
to it. The scheduler never grants access and never starts a model session.

```sh
node managed/cli.mjs connect --name "Repository maintainer" --agent maintainer
```

`--agent` is the agent's name as `peerspan agents` shows it, or its agent ID.
The registration pins the host and the agent; readiness then follows whichever
session of that agent is attached and verified, so re-attaching the agent needs
no change here. Options:

- `--host-state DIR`: the worker host's Peerspan state, when it is not the default.
- `--sender-state DIR`: the Peerspan state of the host that submits the tasks,
  when it is not the default. Sender and worker are two hosts.
- `--worker-state FILE` instead of `--agent`: the revision 1 form, a private JSON
  file naming `host_dir`, `host_id`, `agent_id`, `adapter_id` and `session_id`,
  for setups where a supervisor already maintains that file.

Use a dedicated agent. The scheduler never puts two of its own runs on one
agent, but it cannot reserve an agent against other dispatchers.

`disconnect --id ID` removes a worker once no workflow uses it. The Workers page
shows each worker's readiness with its reason, and what the worker host's own
`peerspan status` says needs attention, with the command Peerspan suggests.

## Workflows

Create a workflow in the console: a bounded assignment, the worker, how often it
repeats, a daily dispatch limit and an acceptance window. New workflows are
paused unless you enable them.

- **Pause and resume.** Pausing stops new dispatch and lets the run in progress
  finish. Resuming does not run at once: the schedule decides, or "Run now".
- **Edit.** Changes apply from the next dispatch. A run that was already
  reserved keeps the exact instructions it was sent.
- **Archive and restore.** An archived workflow never dispatches and leaves the
  list; its runs stay in the history. There is no delete.
- **Failure circuit.** Three consecutive failed runs pause the workflow until
  you resume it.

The interval counts from the end of the previous run. Daily limits count
dispatches per UTC day, including failed ones; they are not cost limits, and
model usage is billed by your provider.

## Runs

Every run has a page with the worker's reported result, the instructions that
were actually sent, and a timeline of the task's events, progress messages
included.

- **Cancel** asks the worker to stop. The run ends when the worker confirms, or
  with the worker's own result if it finishes anyway. A run that was never sent
  is cancelled without being sent. A cancellation does not count as a failure.
- **Release** is for a run that can no longer be resolved, for example because
  its worker host is gone. It frees the workflow and the worker here and stops
  all further calls for that task. It does not stop the worker.

A succeeded run is the worker's own report. Nothing in this preview checks the
output, downloads artifacts or approves anything on your behalf.

## Recovery

- A task ID and its exact payload are stored before anything is sent. After a
  lost reply or a restart the controller inspects that same task first and
  resubmits the same ID and payload only when the sender daemon has never held
  it. It never invents replacement work.
- One unresolved run per workflow and per worker, enforced by the store.
- A stopped controller exits within seconds; work it was waiting for is picked
  up again under the same identities at the next start.
- The Activity page records what you did and what the controller did. Each
  workflow shows how many runs it has finished since you last stepped in.

## Follow existing programs

```sh
node managed/cli.mjs observe --name "Existing research program" \
  --directory /absolute/private/controller/continuous
```

The directory must contain `config.json` and `state.json` in the documented
controller format. Observation is read only: it cannot pause, resume, dispatch
to or repair the external program, whose history stays with its own controller.
`unobserve --id ID` stops following it.

## Supervised operation

Create a user systemd service with absolute paths for your machine:

```ini
[Unit]
Description=Peerspan Managed local operator
After=network.target

[Service]
Type=simple
WorkingDirectory=/absolute/path/to/peerspan-managed
ExecStart=/absolute/path/to/node managed/cli.mjs serve --port 4310
Environment=PEERSPAN_BIN=/absolute/path/to/peerspan
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=default.target
```

Enable it with `systemctl --user enable --now peerspan-managed.service`. Linux
needs a persistent user manager; Windows with WSL also needs the distribution
started after logon. A process lock refuses a second scheduler for the same
state directory. Nothing here replaces the Peerspan host service.

## Upgrading from the first preview

The first command of this version that opens an existing state directory
migrates it in place, after saving a copy as `managed.v1-backup.sqlite` beside
it. Connections, observations, workflows, runs, task IDs and results keep their
IDs; a run that was unresolved is reconciled under its task ID as after any
restart. Restart the service after updating the checkout.

## Develop

```sh
npm --prefix managed run check                  # syntax check of every source
node managed/conformance/acceptance.mjs         # contract cases 1 to 6
node managed/conformance/operations.mjs         # contract cases 7 to 10
node managed/conformance/visibility.mjs         # contract cases 11 and 12
# Actual two-host transport with a scripted adapter, no model:
python3 managed/conformance/real-peerspan-smoke.py --bin /path/to/built/binaries
```

The suites are written from the [operator contract](../docs/managed-contract.md)
by a separate author who does not read this implementation; they use an
explicitly fake Peerspan executable and throwaway state. The code is small:
`lib/model.mjs` holds every state transition as one SQLite transaction,
`lib/engine.mjs` owns timing and all Peerspan calls, `lib/server.mjs` is the
HTTP boundary, and `public/` is the console.

The [product plan](../docs/managed-product.md) covers the path to managed
sessions, hosted workers and teams, and [managed-decisions.md](../docs/managed-decisions.md)
records the choices made so far. This is an unofficial Apache-2.0 fork, not an
upstream Peerspan hosted product.
