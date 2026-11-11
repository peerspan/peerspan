# Peerspan Managed

An unofficial Peerspan fork for managed, always-on agent teams.

Run recurring assignments against existing agents, retain task history across
restarts, and see which workers or workflows need attention. The first release
is a **single-owner local operator preview**, with a product path toward hosted
teams and customer-supplied model access.

<p align="center">
  <img src="managed/assets/console-overview.png" width="860" alt="The Peerspan Managed console: attention items, workflows with their latest runs, workers and activity. Scripted demonstration data." />
</p>

## Available now

- An authenticated loopback console, updated live: what needs attention,
  workflows with their latest runs, workers, run history and an activity log.
- Durable recurring assignments through the Peerspan CLI, using existing host
  permissions and genuinely verified channels. Workers are registered by agent
  name; readiness follows the agent's current session and explains itself.
- Exact submission identity retained through uncertain replies and restart.
- Pause, resume, edit and archive; daily dispatch caps; one unresolved
  assignment per workflow and per worker, enforced by the store; automatic
  pause after three failed runs.
- Run pages with the reported result, the instructions actually sent and the
  task's progress timeline; cancellation through Peerspan; an explicit release
  for runs that can no longer be resolved.
- Reliability figures per workflow: success rate, duration, operator actions,
  and runs finished since the operator last stepped in.
- A read-only bridge for existing controllers, SQLite persistence on a
  dedicated storage thread with in-place migration, private local credentials,
  a `doctor` command and a supervised Linux/WSL service recipe.

## Run locally

Requires Node 24 and an existing Peerspan installation on Linux or WSL.

```sh
node managed/cli.mjs serve
# In another terminal, get the private console access token:
node managed/cli.mjs token
```

Open **http://localhost:4310**, sign in, and connect a dedicated worker:

```sh
node managed/cli.mjs connect --name "Repository maintainer" --agent AGENT
```

The [operator guide](managed/README.md) covers the rest. No npm install is
needed for this application. On Windows, `./managed.ps1 start`, `token` and
`doctor` provide the WSL entry points.

## Product direction

Start with engineering teams and agencies that already use agents and need less
manual supervision. Offer free local operation, then hosted execution and team
administration with separately metered compute. The proposed $99–299 team price
is an experiment, not validated willingness to pay.

Read the [product specification](docs/managed-product.md),
[operator contract](docs/managed-contract.md), the
[decisions](docs/managed-decisions.md) behind it, and the
[upstream Peerspan documentation](README_UPSTREAM.md).

Ongoing work is tracked in [upstream draft PR #186](https://github.com/peerspan/peerspan/pull/186).
This repository is the working copy; `maschad96/peerspan:managed` is its upstream
review branch. The draft carries the current implementation and a short milestone
overview. It stays open while the product develops.

## Current limits

This release does not provision cloud machines or model sessions, isolate SaaS
tenants, meter model costs, bill customers, or certify the quality of agent
output. Daily caps limit assignment count, not dollars. Existing observed
programs keep their original controllers and cannot be controlled from this UI.
A worker's Peerspan host must have its state directory on this machine, and the
sender must be a second local host: a Peerspan host cannot task itself.

The scheduler supervises task delivery and reconciliation; dedicated agent
session lifecycle is the next product slice. Do not expose this local preview as
a public hosted service.

## Upstream and license

Forked from [peerspan/peerspan](https://github.com/peerspan/peerspan), retaining its
Rust host, protocols, integrations and Apache-2.0 license. This fork is not an
official Peerspan service. `upstream` tracks the original project; `origin` is
[maschad96/peerspan-managed](https://github.com/maschad96/peerspan-managed).

The operator product is contained in `managed/`. Its contract-derived acceptance
suites are independently authored under `managed/conformance/`. Upstream host
implementation and release installers are unchanged.
