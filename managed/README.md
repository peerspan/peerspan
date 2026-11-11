# Peerspan Managed operator preview

A local console and durable scheduler for existing Peerspan agent sessions. Node
24, Linux or WSL, and an installed Peerspan CLI are required. No npm dependencies.
The original daemon and peer permissions remain the authority for execution.

## Start

```sh
node managed/cli.mjs serve
# In another terminal, print your private local sign-in token:
node managed/cli.mjs token
```

Open http://localhost:4310 and paste the token. Keep the token private. The server
binds loopback only and is not a public hosted service. Use `--state /absolute/dir`
on every command for an independent workspace. Default runtime state is
`~/.local/state/peerspan-managed`, never the repository.

On Windows, `./managed.ps1 token` and `./managed.ps1 status` use the default user
of Ubuntu-24.04. Override those choices with `-Distro NAME -LinuxUser NAME`.
The helper uses the Linux login environment to find Node. `start` and `stop`
control the user service after it is installed as described below.

## Connect an agent

Prepare a dedicated Peerspan agent using the upstream quick start, paired hosts,
and the owner's actual task permissions. The agent must already have a running
model session and acknowledge its current Peerspan hello. The managed scheduler
does not grant access or start a model session.

Save the attachment identities in a private JSON file. Its exact fields are:

```json
{
  "host_dir": "/absolute/private/receiver-host-state",
  "host_id": "host_ followed by the actual 64 hex digits",
  "agent_id": "agent_ followed by the actual 32 hex digits",
  "adapter_id": "adapter_ followed by the actual 32 hex digits",
  "session_id": "session_ followed by the actual 32 hex digits"
}
```

Get these from `peerspan --state DIR info`, `agent list`, `session list`, and
`adapter list`. A supervisor can keep this file current across attachment changes.
Host and agent are pinned when connecting; changing either requires a new
connection. Real identifiers are required; the text above is a schema example.

```sh
node managed/cli.mjs connect --name "Repository maintainer" \
  --worker-state /absolute/private/worker.json \
  --sender-state /absolute/private/sender-host-state
```

Omit sender-state to use Peerspan's normal local owner state. Then create a
workflow in the console. Specify a bounded assignment, interval, acceptance
window, and daily dispatch cap. New workflows are paused unless explicitly enabled.
Use a dedicated agent: the scheduler prevents collisions among its own workflows,
but cannot reserve agents against other independent dispatchers.

A responding standalone daemon can be ready without an installed user service.
The console shows an advisory in that case. Readiness still requires the exact
host, agent, session and adapter plus the adapter's verified live channel.

## Recovery and operational limits

- One unresolved run per workflow and per sender/host/agent target.
- Submission identity and payload are saved before external calls. Restart and
  uncertain replies reconcile the same task rather than inventing another one.
- Daily limits count dispatches in UTC, persist across restart, and include failed
  submissions. They are not model-cost limits. Model usage and costs are unavailable.
- Pause stops new dispatch while active work continues. Three consecutive terminal
  failures pause the workflow. Resume is an explicit operator action.
- A task success is the receiver's report. Inspect artifacts and apply any required
  review separately. This preview retains result text and task IDs, not artifact
  file downloads or automatic result validation.
- Polling, storage and all connection configuration remain local. Do not expose
  the console through a proxy or public interface as if it had tenant isolation.

## Follow existing programs

```sh
node managed/cli.mjs observe --name "Existing research program" \
  --directory /absolute/private/controller/continuous
```

The source directory must contain config.json and state.json in the documented
controller format. Observation reads only. It cannot pause, resume, dispatch to,
or repair the external program, and its run history stays with its controller.

## Supervised operation

Create a user systemd service with absolute Node/repository paths for your machine:

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

Enable that service with `systemctl --user enable --now peerspan-managed.service`.
Linux needs a persistent user manager; Windows/WSL additionally needs its distro
started after logon. A process lock prevents two schedulers for the same state.
No installation command replaces the existing Peerspan host service.

## Develop

```sh
npm --prefix managed run check
# Independent contract-derived suite, fake transport and temporary state only:
node managed/conformance/acceptance.mjs
# Actual two-host transport with a scripted adapter, no model:
python3 managed/conformance/real-peerspan-smoke.py --bin /path/to/built/binaries
```

The [product plan](../docs/managed-product.md) defines the path to managed hosted
workers, billing and agency workspaces. The [operator contract](../docs/managed-contract.md)
defines this release and independent acceptance cases. This is an unofficial
Apache-2.0 fork, not an upstream Peerspan hosted product.
