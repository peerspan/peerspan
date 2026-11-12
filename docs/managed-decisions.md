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

## MGD-10. Reviewer agents (2026-11-12)

- **Question.** Operator review (MGD-9) makes the figures honest, but every
  result then waits for a person. How can another agent check results first,
  with the operator as the fallback?
- **Options.**
  - (a) A reviewer agent per workflow, asked by an ordinary Peerspan task whose
    input holds the assignment, optional criteria and the result, and whose
    answer starts with a fixed verdict line. Anything else hands the result to
    the operator.
  - (b) As (a), but retry a review that failed or gave no verdict, or ask a
    second reviewer.
  - (c) Judge results in the controller itself, with a model call or rules.
- **Chosen.** (a). The review task is a sub-task of the run, not a run of its
  own, so the run's state, history and figures stay those of the work; it
  holds the reviewer's agent like any task, and the controller sends at most
  one per run.
- **Reason.** Peerspan already delivers, authorizes and recovers tasks between
  agents, so a reviewer is any agent the operator can reach, on this machine or
  another, under the owner's grants, and it needs no new transport, credential
  or model access in the controller, which (c) would add. A fixed first line is
  the smallest answer format an agent follows reliably and a person can read;
  everything after it is the reasons, shown to the operator and, on a
  rejection, available to the worker. Retrying (b) turns a broken or confused
  reviewer into repeated work and cost; one attempt and then the operator keeps
  every result's path short and visible. The operator may still decide at any
  time, because a reviewer that is offline must not hold a result hostage. The
  reviewer must be another agent than the worker: an agent checking its own
  result is not a review.
- **Contract.** Sections 4, 8, 11 and 15.1.

## MGD-11. Sending a rejected result back (2026-11-12)

- **Question.** MGD-9 left a rejection with no effect on the work. Once a
  reviewer gives reasons, should the worker get them and try again?
- **Options.**
  - (a) An opt-in limit of 0 to 3 reworks per workflow: a rejection of the
    workflow's latest run makes the next run a rework, whose input is the
    current instructions, the review and the previous result.
  - (b) Rework every rejection, including of older runs.
  - (c) Leave reworks to the operator, who can edit the instructions and run
    again.
- **Chosen.** (a), with the rework due at once, outside the interval or schedule,
  and subject to every other dispatch rule.
- **Reason.** A rejection with reasons is the most useful feedback a worker can
  get, and sending it back is what a team lead would do; (c) makes the operator
  copy text between screens. Only the latest run is reworked, because a later
  run of a recurring assignment has already done that work again, so (b) would
  redo stale work. The limit keeps a worker and a reviewer that disagree from
  looping: each rework is a run that counts toward the daily cap and the
  figures, so the cost stays visible and bounded. The input repeats the
  instructions in full because a worker session may not remember the previous
  attempt, and a runtime agent never does.
- **Contract.** Sections 4, 9 and 15.2.

## MGD-12. Branches of runtime agents (2026-11-12)

- **Question.** Upstream's runtime agents (runtime agent contract, RUN-8 to
  RUN-11) run each task on its own peerfs fork and end the output with a line
  such as `Branch: codex.task_… at commit 01…`. What should the operator do
  with it?
- **Options.**
  - (a) Show the output as it is.
  - (b) Also read the documented forms of that last line into a `branch` field
    that the console shows with the result.
  - (c) Read the branch from peerfs on the worker host.
- **Chosen.** (b). The output is kept unchanged, and a line that does not
  follow one of the documented forms exactly gives no branch.
- **Reason.** RUN-11 chose the text line so that "scripts parse the last line";
  the operator is such a script, and the branch is where the work is, so it
  belongs beside the result. (c) needs access to the worker host's storage,
  which a remote worker never gives, and the controller does not otherwise
  depend on peerfs. Readiness is not changed for runtime agents: upstream has
  not yet implemented them, and its contracts do not yet say how `status` and
  the `agents` directory present an agent that runs without an attached
  session, which is what readiness reads.
- **Contract.** Section 10.1.

## MGD-13. Runtime agents as workers (2026-11-12)

- **Question.** Upstream now runs a runtime agent's tasks in its host's runtime,
  one microVM per task on a peerfs fork, with no attached session. Section 3
  readiness asks for a ready session with a verified channel, so such an agent
  could never be ready. What evidence should the operator use instead?
- **Options.**
  - (a) For an agent whose host runs on this machine, read the host's own launch
    profiles (`agent runtime show`) and runtime switch and report
    (`runtime show`): a profile with a credential, the switch on and a runtime
    that answers are the conditions under which the host starts the agent's
    tasks.
  - (b) Treat any agent with a profile as ready, without the runtime checks.
  - (c) Wait for upstream to say how `status` and `agents` present runtime
    agents, and change nothing until then.
- **Chosen.** (a), for agent mode only. File mode keeps its session file, and
  remote mode is unchanged.
- **Reason.** These are the same checks the host makes at the start of each of
  the agent's tasks (runtime agent contract, Running): a task sent while one of
  them fails is rejected at start, so (b) would turn a disabled runtime into a
  failed run and, three times over, a paused workflow. The commands are
  owner-local and already used the same way as `status`, so (a) needs nothing
  new from upstream, whereas (c) leaves an implemented upstream feature unusable.
  A sender on another machine cannot run them: on upstream `b270c1b6` the
  sender's directory lists a runtime agent without a session as not
  `connected`, so remote readiness waits for upstream's answer, asked on
  PR #186. The operator still sends one task at a time per agent, as MGD-6
  says, even though a launch profile may allow several runs at once; using
  that capacity is a later change.
- **Contract.** Sections 3.1 and 6.

## MGD-14. A runtime agent's capacity (2026-11-12)

- **Question.** MGD-6 holds each worker agent to one managed task at a time,
  because an attached session works on one assignment at a time. A runtime
  agent's host runs each task in its own microVM on its own fork, up to the
  launch profile's `max_runs` at once. Should the operator use that capacity?
- **Options.**
  - (a) Keep one task per agent.
  - (b) Let a `ready_runtime` agent hold up to `max_runs` tasks, across
    workflows, with one run per workflow as before.
  - (c) Also let one workflow have several runs at once.
- **Chosen.** (b). The capacity comes from the latest readiness, and anything
  else, a session agent, a remote agent or a runtime agent that is not ready,
  keeps a capacity of 1.
- **Reason.** Running several assignments side by side is what runtime agents
  are for: each run starts from the branch and works on a fork of its own, so
  two runs cannot disturb each other, and `max_runs` is the owner's own limit,
  which the host enforces anyway. (a) would leave a team of workflows queued
  behind one VM at a time. (c) changes what a recurring assignment means:
  overlapping runs of one workflow would compete for the same result, and the
  schedule, the cap and rework all assume one run at a time. The store keeps
  enforcing the limit by giving each extra concurrent task a numbered slot of its
  agent's target, so the exclusion rule stays a constraint, not a check that a
  race could pass.
- **Contract.** Sections 3.1, 4 and 8.

## MGD-15. Passes never wait for a slow call (2026-11-12)

- **Question.** A scheduler pass waited for every readiness check and
  reconciliation before it dispatched, so one hanging Peerspan call, such as a
  `runtime show` waiting 35 seconds for a stopped runtime, slowed dispatch and
  readiness for every worker.
- **Options.**
  - (a) Shorter command limits only.
  - (b) Wait a bounded time each pass, dispatch with the readiness last
    recorded, and let slow calls finish beside later passes, at most one per
    connection or task.
- **Chosen.** (b), with a 2-second wait, and the 5-second limit for
  `runtime show` kept.
- **Reason.** A limit short enough to keep passes quick would also cut off
  calls that are only slow, such as a busy daemon's `task events`, and would
  still multiply across connections. With (b) a slow call delays only its own
  connection or task. Dispatch uses the readiness each connection last
  recorded, which a slow check would have returned late anyway, and a check
  never runs twice at once, so a hanging host gets one call in flight, not one
  per pass.
- **Contract.** Section 4.

Note to MGD-15 (2026-11-12, revision 6.1): the first form of (b) dispatched
with the readiness each connection had last recorded. Once the wait was also
capped at one interval, so that passes keep their pace, a check that began
before an operator's change could still end, ready, just after the operator
requested a run, and the acceptance suite caught a run sent to a worker whose
pinned identity had just changed. A first correction, using only verdicts from
checks that ended since the previous decision, narrowed that window but did not
close it, and CI caught it again. Work is now reserved only on readiness from a
check that began after the work became due (the run's due time, a rework, or
the operator's latest change of the workflow; for a review task, its run's
end), so a change made before a run is requested is always seen, whatever the
timing; a worker with a slow check waits for its own next verdict.

Note to MGD-15 (2026-11-12, revision 7.1): with that rule, work held back for a
fresher verdict waited for the next periodic pass. Under WSL the system clock
often steps back about 2.5 seconds during a suite run, and while the controller holds
its clock every check records the same time as the operator's change, so a
resume made then waited a full interval; the prompt-pass case of the visibility
suite caught it once locally. A dispatch now reports which ready connections
held work back. A recheck follows as soon as a check that began late enough can
start: when that connection's running check ends, or once the held clock has
moved past the time it holds, and never sooner than 20 ms. The recheck
dispatches with what is known, checks only those connections whose verdict is
still too old, and dispatches again.

A first form moved the whole next pass forward instead. The independent
reviewer showed two problems with it. A pass that failed before or during its
dispatch kept the old list and ran again every 20 ms, about 94 passes in 6
seconds against 6. And every reviewed result that finished during a pass would
have cost another full pass, with every check and inspection. The list is now
emptied before each dispatch and after a failed recheck, and a recheck touches
only the connections concerned. Its second review found one more loop: a check
that fails to record its verdict leaves the old one, still too old, so the
connection stayed stale and was checked every 20 ms. A connection whose latest
check failed is now left to the passes until a check of it succeeds.

The alternative, ordering checks against changes by an in-memory counter instead
of recorded times, would not cover changes recorded by other processes or
restarts, and would make two rules where the store's one rule now decides.

## MGD-16. A ready verdict from one moment (2026-11-12)

- **Question.** A readiness check reads several things one after another: the
  worker state file, the worker's `status`, then the adapter's `adapter
  connection` report, or for a runtime agent its launch profile and `runtime
  show`. Each read can see a different moment. Under load the acceptance suite
  sent a run while the fake host was changing in one step from "identity right,
  channel verified without a time" to "a time, but another host". The check had
  taken the identity from before the change and the verification from after it,
  a ready combination that never existed. A probe that delays the adapter's
  report by 300 ms reproduced it with 0.8.0 on the first such change, and the
  same with a runtime agent's credential and runtime switch.
- **Options.**
  - (a) Read everything at once. Separate commands cannot do that.
  - (b) Make every check twice and compare. This doubles every call, including
    a slow `runtime show`.
  - (c) After a ready verdict, read again what was read before its last read,
    and keep the verdict only when the facts it rests on are unchanged.
- **Chosen.** (c). The adapter report now follows the status that made its
  session a candidate. A mismatch makes the whole check again, once. A second
  mismatch gives `status_invalid`.
- **Reason.** If the facts read before and after the last read are equal, they
  held throughout, unless they changed and changed back, so the whole verdict
  held at the moment of the last read. (c) adds the worker's and the sender's
  `status` calls, and in agent mode one `agent runtime show`, only to checks
  that come out ready. The facts compared are the ones the verdict uses: the
  file's identity, the host, the agent, the verified session, the sender host,
  and in agent mode the launch profile or its absence. Attention items and other
  sessions are not compared, so a host whose unrelated fields change does not
  lose its readiness. Ending a second mismatch in `status_invalid`, rather than
  checking until the facts settle, keeps a check bounded; the next pass checks
  again.
- **Review.** The first form compared neither the sender's status nor, for a
  session in agent mode, the absence of a launch profile. The independent
  reviewer's probes still sent runs through both gaps, with the sender failing
  and with a profile appearing in the same step as the channel's time; both
  are now among the facts compared.
- **Contract.** Section 3.
