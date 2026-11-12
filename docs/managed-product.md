# Peerspan Managed

## Product decision

This fork turns Peerspan into an operator product for persistent agent teams.
The first customers are small engineering teams and automation agencies already
using coding agents and spending time supervising recurring work. The promise is
to keep assigned work moving, retain its history, and make blocked work visible.

The first release is a single-owner local operator preview. It connects existing
Peerspan workers, schedules bounded assignments, persists submission identities
before delivery, reconciles runs after restart, and exposes an authenticated
loopback console. Its second revision makes that slice complete enough to run
unattended: workers registered by agent, editing and archiving, cancellation,
run timelines, an activity log, and a measure of how often the operator steps in. Its third revision reaches agents on other machines through the sender
host's directory, runs workflows on wall-clock schedules, and lets the operator
review results before they count. It does not provision cloud machines, launch
model sessions, bill customers, or guarantee that an agent's answer is correct. These limits are
visible in the console and documentation.

The original host, peer protocol, grants, adapters and license remain upstream
components. The fork adds `managed/` as a separate Node 24 application. It never
exposes the upstream owner socket to peers or changes host permissions. Existing
workflows can be observed without taking control of their queues or processes.

## Commercial direction

Offer free local use, then a managed subscription with separately metered compute
and customer-supplied model access. Test $99–299 per team per month as a pricing
hypothesis. Sell reliability and saved operator time. Do not charge for model
tokens without accounting, or label run-count limits as dollar spending limits.

Acquire initial users through working recurring maintenance and research recipes,
an installable local console, and agency client workspaces. Measure useful runs,
manual interventions, repeat weekly use and paid retention.

## Release sequence

1. Local operations: durable queue, recurring schedules, exact worker readiness,
   pause/resume, daily dispatch caps, failure circuit, task history and results.
   Implemented, with editing, archiving, cancellation, timelines, activity and
   reliability figures (revision 2), and workers on other machines, wall-clock
   schedules and operator review of results ([contract](managed-contract.md)
   revision 3). Still open in this step: results checked by a reviewer agent.
2. Worker lifecycle: managed dedicated harness sessions, repository workspaces,
   health repair, approvals and independently checked result contracts.
3. Hosted pilot: persistent sandbox provider integration, storage and restore,
   per-tenant secrets and isolation, account authentication, actual cost telemetry.
4. Paid teams: billing, client workspaces, organization administration, service
   commitments after measured production reliability and operational ownership.

The hosted product should initially use an existing compute provider. Peerspan's
early runtime and peerfs are candidates for later integration, not dependencies
that this preview claims to operate.

## First release acceptance

An operator can connect an existing worker, local or reachable through the
sender host's directory, create a bounded recurring assignment, pause and resume dispatch, see why
dispatch is blocked, and inspect actual remote results. Restarting the controller
does not create a replacement ID for unresolved work. Unverified workers receive
no new assignments. Existing external controllers remain observation-only.

The console must distinguish real task execution from fixtures, dispatch caps
from cost accounting, and source connectivity from channel readiness. No model
cost, fabricated work, false uptime guarantee or automatic human approval.

See [the operator contract](managed-contract.md) for executable acceptance cases.
