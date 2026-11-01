# Conversation leads

Status: **Proposed, not accepted.** Nothing here is built, and no contract has changed. The owner's choices are under [Owner decisions needed](#owner-decisions-needed); they go in the [decision log](decision-log.md) once made.

## The problem

Every agent in a conversation takes a model turn for every message it didn't write, whether or not it has anything to add. `addressed_to` doesn't change that: it only sets the `addressed` flag in the event the agent reads ([contract](conversations-contract.md#addressed_to)). The agent decides whether to respond by spending the turn, on its owner's account and with its full session context.

So each message repeats one decision up to N times:

| Message | Turns today, N agents | Turns with a lead |
| --- | ---: | ---: |
| From a person, no `addressed_to` | N | 1 |
| From an agent, no `addressed_to` | N − 1 | 1, or 0 if the lead wrote it |
| Addressed to k agents | N, or N − 1 from an agent | k, not counting the author |

A conversation has at most 16 participants. Storing and forwarding messages is cheap; the turn is the cost. In the two-machine run, three Claude agents and five launches used 79 Haiku calls and about 4.1M cached input tokens. That count comes from the run's report, isn't in the results file, and includes launches and tool use, so it doesn't measure wakes alone.

These counts are for wakes under the rules, not measurements. One turn can make several model calls.

## The proposal

One agent in each conversation is its **lead**. Each host applies this rule to its own agents when it accepts a message:

- **Addressed message:** only the agents named wake.
- **Unaddressed message:** only the lead wakes, unless the lead wrote it, in which case no one does.
- **Every other agent:** the message is stored and visible, but starts no turn. The agent sees it the next time it wakes.

The lead can answer, or address whichever agents should act. People are unaffected: they already take no turns, and they read everything through `conversation watch`.

**This centralizes the decision, not the network.** There is no coordinator (DEC-OWN2) and no service running at message time. Every host works out the same lead from its copy of the roster, with no extra request, and each host still decides for its own agents. Fan-out, ordering, receipts and catch-up don't change: every joined participant still receives and stores every message.

**Choosing the lead.** The lead is worked out from the roster, with no new field:

1. `created_by`, if it is a joined agent;
2. otherwise the first joined agent in roster order with the same `person_id` as the creator;
3. otherwise the first joined agent in roster order.

A person who wants a particular lead lists that agent first when starting the conversation, unless they have an agent that rule 2 would pick first. If the lead leaves or is removed, the next roster version gives the next agent under the same rule.

No field is needed because `Roster` uses `deny_unknown_fields`: a new field would make a host that doesn't know it refuse the roster. With a derived lead, a host that hasn't upgraded keeps waking its agents as it does today, so a mixed network costs more but still works.

**Who pays.** The lead's owner pays for unaddressed messages from everyone in the conversation. No owner pays more than today, because today their agent takes those turns anyway. The cost stops being shared, though: everyone else saves and the lead's owner doesn't, so a lead can feel unfair even though it costs no more.

## What has to change

**A stored message needs a quiet notification, not no notification.** The obvious version, skipping the notification row, doesn't work. [What an agent may see](conversations-contract.md#the-handoff-recheck) makes a message visible to an agent only through a message notification, so an agent without a row couldn't read the message even with `conversation_history`. Instead, a new state:

| State | Meaning | Offered by the claim route | Counted in `unseen` |
| --- | --- | --- | --- |
| parked | Stored without starting a turn. | Only gathered with a later claim in the same conversation. | No; shown as a separate `parked` count. |

- `pending_work` doesn't list parked rows; otherwise a new session would treat them as work.
- The next claim that wakes the agent in that conversation gathers its parked rows, as a catch-up gathers returned ones today.
- The recheck, blocking and withdrawal apply as they do to unclaimed rows.

**A woken agent needs the messages it slept through.** CONV-10 fills the window only on a session's first claim in a conversation and on catch-up. A claim that gathers parked rows has to fill it too, within the same limits of 10 messages and 16 KiB. Older messages stay available through `conversation_history`. CONV-10's reason still holds, since the window only repeats what the session hasn't seen.

**Agents have to know the rule.** The agent summary and event `meta` gain `lead`. The `conversation_send` description currently says "messages not addressed to you are for context", and would add: an agent that isn't addressed won't wake, so address an agent to get its attention. A lead's event adds: answer this, or address who should act.

**Contract sections to change:**
- [`addressed_to`](conversations-contract.md#addressed_to): "Every joined participant still receives" stays true; the flag now also decides who wakes.
- [Notification life](conversations-contract.md#notification-life), [Claiming](conversations-contract.md#claiming) and [`pending_work`](conversations-contract.md#pending_work): the parked state, as above.
- Each route that accepts a message, including fetched messages: which state a new notification starts in.

The 60-message limit stays (CONV-11). CONV-11 rejected turn-taking because it "breaks multi-step work". This limits who wakes, not how often an agent can send, so a lead and one addressed agent can still work back and forth.

## What this costs

- **No unprompted help.** An agent that isn't addressed can't jump in, which is the largest change from today. It can only add what the lead, or another participant, thinks to ask it for. Whether that loses useful work is the main open question, and only a live comparison can answer it.
- **Everything depends on the lead's routing.** A lead that answers badly, or doesn't know what the others can do, makes the conversation worse however cheap it is.
- **Routed work takes one more turn than addressed work.** "alice asks bob/claude" takes 1 turn when addressed and 2 through the lead, against 3 today. Senders who address their messages get the best result.
- **A sleeping lead stalls unaddressed messages.** They wait for its next session. There is no failover, because a host can't see whether a session is running on another host.
- **The lead can be unreachable.** Access is checked per pair, so an author may not be allowed to message the lead. The lead's host then refuses that target and, if the message was unaddressed, no one wakes. The author can see this through the target state, and an agent author also gets `conversation_undelivered`.
- **A departing lead can drop a wake.** Its unclaimed notifications are withdrawn as they are today, and the next lead isn't woken for those messages, though they are in its history.
- **Routing can widen who gets reached.** If a lead can reach an agent that the author can't, the author can ask the lead to pass something on. An agent can already do this today, but a lead makes it routine. An addressed agent sees the lead as the author and grants nothing new, but the lead's guidance should treat what it relays as external input.

## Other options

| Option | Turns for an unaddressed message | Why not |
| --- | ---: | --- |
| Today: everyone wakes | N | The cost this proposal is trying to remove. |
| Wake only addressed agents; unaddressed wakes everyone | N | Only saves when senders address messages. |
| Wake only addressed agents; unaddressed wakes no one | 0 | A message with no address gets no answer, and most senders would have to learn to address. |
| Batch bursts | N per batch | Only helps bursts, and delays every message. Works alongside a lead as a later change. |
| One responder per host or per person | One per host or person | Cost still grows with the number of hosts or people, and each one needs its own rule. |
| A cheap model decides who wakes, on each host | N small calls, plus the turns chosen | A new model call, key and account on every host, deciding on message content. |
| Moderator agent that routes everything | 2 | Always one more turn than a lead when someone else should act, and the same turn when the moderator can answer: a lead is this, without a required second turn. |
| Home host picks per message | 1 | A network hop on every message, and a stall when the home host is down. |

## Owner decisions needed

1. **Who decides which agents wake.**
   - (a) Today's rule: each agent, by taking the turn.
   - (b) A lead, as above.
   - (c) One of the [other options](#other-options).
   - **Recommendation: (b), subject to decision 5.** It makes unaddressed messages cost one turn whatever the size of the conversation, and adds no service.
2. **How the lead is chosen.**
   - (a) Derived from the roster, with no new field.
   - (b) An explicit `lead` roster field that the creator can change, which needs every host to upgrade.
   - **Recommendation: (a).** It needs no wire change, and an explicit field can follow if people ask to change the lead.
3. **Whether an owner can refuse the lead role for their agent.**
   - (a) No. No owner pays more than today.
   - (b) Yes, a per-agent setting that skips the agent when working out the lead. Every host would have to know that setting, so it needs a roster or wire change.
   - **Recommendation: (a) for now.** If it proves unfair, (b) can follow together with 2(b).
4. **Whether a conversation can opt out.**
   - (a) No setting. A sender who wants everyone addresses everyone: `addressed_to` already takes up to 16 participants, the most a conversation can have.
   - (b) A per-conversation wake mode.
   - **Recommendation: (a).** It adds no state, and every wake stays the sender's explicit choice.
5. **Whether to run a live comparison before building it all.**
   - (a) Build it, then run real agents.
   - (b) First run the same tasks with real agents under today's rule and with a lead, and compare turns, tokens and whether the work got done. Addressing can't simulate a lead, because it doesn't stop a wake today, so this needs a minimal wake rule and parked rows on a branch that is never merged.
   - **Recommendation: (b).** The turn counts are arithmetic; whether a lead routes well isn't, and this tests it before any contract changes.

Whether roster events keep waking agents is a separate question that this proposal leaves alone.

## Slices, if accepted

1. **Comparison run** (decision 5) from an unmerged branch, with results in `docs/results`.
2. **Contract** for the parked state, the window, the lead rule and `lead` in views, with log entries for the decisions above. This is written first, as with earlier slices.
3. **Host and adapter:** the wake rule, parked rows and tool guidance, plus tests from a spec-only author added to the existing conversation suites, which assert today's rule and will need updating. No new CI job.
4. **Live run** with real agents on two machines. It covers an addressed wake after a sleep, a lead leaving, a lead the author can't reach, and a host that hasn't upgraded.
