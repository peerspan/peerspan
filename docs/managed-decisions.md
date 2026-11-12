# Managed operator decisions

Decisions for the managed operator under `managed/`, in the form of the upstream
[decision log](decision-log.md): one entry per decision, a stable `MGD-n` ID, the
options considered, the choice and the reason. These are the fork maintainer's
decisions for this preview. They are not upstream owner decisions and do not
change the host, the peer protocol or any upstream contract. The specification
stays [managed-contract.md](managed-contract.md).

## MGD-1. Cancelling a run (2026-11-11)

- **Question.** What does the console's cancel do to a run, and does a cancelled
  run count against the failure circuit?
- **Options.**
  - (a) Mark the run cancelled locally at once and release its reservations.
  - (b) Send the upstream `task cancel` and take the terminal state from the
    remote record only; a submission that the sender daemon never held is
    cancelled without ever being sent.
- **Chosen.** (b). An operator-requested cancellation leaves the failure count
  unchanged.
- **Reason.** Upstream cancellation is a request: "the agent either confirms
  `cancelled` or finishes anyway". Option (a) would report a state the worker
  never confirmed and would free a target that may still be working. The sender
  daemon persists an outbound task before it submits it, so a genuine not-found
  inspection is evidence that nothing was sent. The failure circuit exists to
  stop a workflow whose worker keeps failing; an operator stopping a run is not
  that evidence.
- **Contract.** Sections 4 and 10.

## MGD-2. Releasing a run that cannot be resolved (2026-11-11)

- **Question.** A run stays unresolved for as long as the remote record is not
  final. When the worker host is gone for good, its workflow and target stay
  reserved forever. How does an operator get them back?
- **Options.**
  - (a) Time out unresolved runs automatically.
  - (b) An explicit operator release (`abandon`) that names the task ID, sets a
    local terminal state, and stops every later call for that task.
  - (c) Nothing; the operator edits the state database.
- **Chosen.** (b).
- **Reason.** A timeout would be the controller inventing a result, and it could
  put a second assignment on an agent that is still working. The decision needs
  knowledge the controller does not have (that the worker is not coming back),
  so the operator makes it, by typing nothing but confirming the exact task ID.
  The state is named `abandoned` so that it is never mistaken for a remote
  result, and the task identity is retained so that it is never reused.
- **Contract.** Section 10.

## MGD-3. Archive instead of delete (2026-11-11)

- **Question.** How does a workflow that is no longer wanted leave the console?
- **Options.**
  - (a) Delete it, with its runs.
  - (b) Delete it and keep orphaned runs.
  - (c) Archive it: disabled, out of the workflow list, runs kept, restorable.
- **Chosen.** (c). There is no `DELETE` route.
- **Reason.** Run history is the product's record of what agents were asked and
  what they reported; deleting it with a click loses evidence, and orphaned runs
  lose their names and their part in the daily dispatch count.
- **Contract.** Sections 2 and 9.

## MGD-4. Registering a worker by agent (2026-11-11)

- **Question.** Revision 1 registered a worker through a JSON file naming its
  host, agent, adapter and session, which a supervisor had to rewrite whenever
  the agent was attached again. How should an operator register a worker?
- **Options.**
  - (a) Keep the file only.
  - (b) Add registration by agent name or ID: pin host and agent, and let
    readiness follow whichever session of that agent is ready and verified.
  - (c) Let the browser register workers.
- **Chosen.** (b), keeping (a). Registration stays a local command.
- **Reason.** The host and the agent are the identity an assignment is sent to;
  sessions and adapters come and go, and upstream `status` already lists the
  current ones. Following them removes a file that was wrong after every
  re-attach. Readiness evidence is unchanged: a candidate still needs a ready
  connection and a verified channel. Registration names local state
  directories, which the contract keeps out of HTTP, so (c) was not taken.
- **Contract.** Sections 3 and 7.

## MGD-5. Snapshot output is a preview (2026-11-11)

- **Question.** Revision 1 returned every retained output, up to 262,144
  characters for each of 100 runs, in a snapshot that the console polls.
- **Options.**
  - (a) Keep full outputs in the snapshot.
  - (b) Return the first 2,000 characters with a truncation flag, and the full
    output from the run's own route.
- **Chosen.** (b).
- **Reason.** The snapshot is fetched every few seconds; a full one could reach
  tens of megabytes. A list needs a preview; the detail view fetches the rest.
- **Contract.** Sections 8 and 10.

## MGD-6. One assignment per worker agent, whichever sender (2026-11-11)

- **Question.** Revision 1 allowed one unresolved run per "sender/host/agent".
  Review of the first slice found that two connections naming the same sender
  state in two ways (omitted, and the default directory written out) produced
  two different keys for one agent. What is the reservation key?
- **Options.**
  - (a) Keep the sender in the key and canonicalize its path.
  - (b) Key the reservation by the worker agent alone: host and agent.
- **Chosen.** (b).
- **Reason.** The rule exists because an agent session works on one assignment
  at a time. Which host submitted the assignment does not change that, so two
  senders must not hold one agent either, and (a) would still allow it. Without
  the sender there is no path to canonicalize.
- **Contract.** Section 4.

## MGD-7. Workers on other machines (2026-11-12)

- **Question.** Revisions 1 and 2 read the worker host's own `status` and
  `adapter connection`, so the worker host's state directory had to be on the
  operator's machine. How can the operator use an agent on another machine?
- **Options.**
  - (a) Copy or mount the worker host's state, or run a helper on the worker
    machine that reports to the operator.
  - (b) Use what the sender host already knows: its directory of reachable
    agents, with `connected`, the host's last refresh state and the actions the
    worker's owner granted.
  - (c) Dispatch without readiness and let the acceptance deadline catch
    unreachable workers.
- **Chosen.** (b), with the directory refreshed on the connection's first check
  and at most once a minute after that.
- **Reason.** The directory is the upstream answer to "which agents can I reach";
  its `connected` is true only for a leased adapter with a verified channel, the
  same evidence that file and agent mode require, seen from the other side. It
  needs no access to another person's machine, which (a) does, and it keeps the
  rule that unready workers get no new work, which (c) drops. It is a view as of
  the sender's last refresh, not a live read, so the console shows its time and
  the contract says what happens when it is stale: the task waits at the worker
  host until it is accepted or its acceptance deadline passes. Refreshing on
  every ten-second check would query every member of the network that often.
- **Contract.** Sections 3 and 7.1.

## MGD-8. Wall-clock schedules (2026-11-12)

- **Question.** Interval workflows drift: a daily run that finished at 09:40
  runs next at 09:40 the next day. How does an operator say "weekdays at 09:00"?
- **Options.**
  - (a) Cron expressions.
  - (b) A small structure: a time zone, weekdays and local times.
  - (c) Run every missed slot after a pause or an outage.
- **Chosen.** (b), with missed slots run once, not one by one.
- **Reason.** Weekdays and times cover the recurring work this preview serves
  and validate to clear messages; cron's month and step fields add syntax
  without a use yet, and a later revision can add them. One run per workflow at
  a time already means a slot can pass during a run; running the backlog after
  an outage would send an agent the same assignment several times in a row for
  no new information. Daylight-saving gaps and repeats follow the common
  calendar rule (later by the gap, the first of two), so a slot is never lost
  or doubled. The daily cap stays on the UTC day so that a cap means the same in
  every schedule.
- **Contract.** Section 14.

## MGD-9. Operator review of results (2026-11-12)

- **Question.** A succeeded run is the agent's own report. How does an operator
  say whether results were actually good, and what does a rejection do?
- **Options.**
  - (a) A per-workflow review setting: succeeded runs wait for a verdict, and
    only accepted ones count as successes.
  - (b) As (a), and hold the next run until the previous result is reviewed.
  - (c) As (a), and send a rejected result back to the agent.
- **Chosen.** (a).
- **Reason.** The reliability figures should not count unchecked reports as
  successes when the operator has asked to check them. Holding the schedule (b)
  would turn every unanswered review into a stopped workflow, which is the
  operator's choice to make with `pause`, not a side effect. Sending results
  back (c) is a new assignment with its own instructions and belongs with
  reviewer agents, which a later revision can add. Verdicts are final so that
  the figures do not change under a reader, and they are not counted as
  interventions, because reviewing is the work a reviewed workflow asks for.
- **Contract.** Sections 8 and 15.
