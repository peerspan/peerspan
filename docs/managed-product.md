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
review results before they count. Its fourth revision lets a reviewer agent
check each result first, with the operator as the fallback, sends a rejected
result back to the worker with the review, and shows the branch a runtime agent
worked on. Later revisions run runtime agents as workers, several tasks at once,
and (revision 8) check each result's shape before any review, at no model cost.
It does not provision cloud machines, launch
model sessions, bill customers, or guarantee that an agent's answer is correct;
a reviewer agent's verdict is another agent's judgment, not a guarantee either. These limits are
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
   schedules and operator review of results (revision 3), and reviewer agents
   with rework of rejected results ([contract](managed-contract.md) revision 4).
2. Worker lifecycle: managed dedicated harness sessions, repository workspaces,
   health repair, approvals and independently checked result contracts.
   Upstream's runtime agents (one microVM per task on a peerfs fork, from a
   host-local launch profile) are the intended basis for sessions and
   workspaces. Revision 4 shows the branch such an agent reports, and revision 5
   makes a runtime agent whose host runs on this machine a ready worker without
   any session; remote runtime agents wait for upstream to say how its
   directory presents them. Revision 8 adds a first form of checked result
   contracts: checks the controller applies to each result itself, before any
   review and with no model call, such as required text, a length, JSON keys
   or a committed branch. A result that fails them is rejected and can be sent
   back with the failed checks.
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
