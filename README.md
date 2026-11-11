# Peerspan Managed

An unofficial Peerspan fork for managed, always-on agent teams.

Run recurring assignments against existing agents, retain task history across
restarts, and see which workers or workflows need attention. The first release
is a **single-owner local operator preview**, with a product path toward hosted
teams and customer-supplied model access.

## Available now

- Authenticated loopback dashboard with live workflow and worker state.
- Durable recurring assignments through the Peerspan CLI, using existing host
  permissions and genuinely verified channels.
- Exact submission identity retained through uncertain replies and restart.
- Pause/resume, daily dispatch caps, one unresolved assignment per target, and
  automatic pause after three failed runs.
- Actual task result history and a read-only bridge for existing controllers.
- SQLite persistence on a dedicated storage thread, private local credentials,
  and a supervised Linux/WSL service recipe.

## Run locally

Requires Node 24 and an existing Peerspan installation on Linux or WSL.

```sh
node managed/cli.mjs serve
# In another terminal, get the private console access token:
node managed/cli.mjs token
```

Open **http://localhost:4310**, sign in, and follow the
[operator guide](managed/README.md) to connect a dedicated worker. No npm install
is needed for this application. On Windows, `./managed.ps1 start` and
`./managed.ps1 token` provide the WSL entry points.

## Product direction

Start with engineering teams and agencies that already use agents and need less
manual supervision. Offer free local operation, then hosted execution and team
administration with separately metered compute. The proposed $99–299 team price
is an experiment, not validated willingness to pay.

Read the [product specification](docs/managed-product.md),
[operator contract](docs/managed-contract.md), and
[upstream Peerspan documentation](README_UPSTREAM.md).

## Current limits

This release does not provision cloud machines or model sessions, isolate SaaS
tenants, meter model costs, bill customers, or certify the quality of agent
output. Daily caps limit assignment count, not dollars. Existing observed
programs keep their original controllers and cannot be controlled from this UI.

The scheduler supervises task delivery and reconciliation; dedicated agent
session lifecycle is the next product slice. Do not expose this local preview as
a public hosted service.

## Upstream and license

Forked from [peerspan/peerspan](https://github.com/peerspan/peerspan), retaining its
Rust host, protocols, integrations and Apache-2.0 license. This fork is not an
official Peerspan service. `upstream` tracks the original project; `origin` is
[maschad96/peerspan-managed](https://github.com/maschad96/peerspan-managed).

The operator product is contained in `managed/`. Its contract-derived acceptance
suite is independently authored under `managed/conformance/`. Upstream host
implementation and release installers are unchanged.
