# Lead comparison: pre-registration

Written and committed before any model run. It implements decision 5(b) of `docs/conversations-lead-proposal.md`.

## Arms

One binary and one adapter. `today`: `PEERSPAN_EXPERIMENT_WAKE` unset. `lead`: `PEERSPAN_EXPERIMENT_WAKE=lead` for both daemons and the agents. Under `lead`, the lead is `api`, by the proposal's rule 2.

## Setup

Two hosts on one machine (CONV-27 allows this), loopback QUIC. alice's host has `api`. bob's host has `db` and `release`. alice is the only person who sends. Claude Code on `claude-haiku-5-5`. Each agent's project is a copy of `experiment/fixtures/NAME`, so `CLAUDE.md` is the same across arms and only that agent holds its facts. The `CLAUDE.md` doesn't say which agent holds what beyond its own notes. Names are the only routing hint.

## Sets

Six sets, alternating: today, lead, today, lead, today, lead. Each set has fresh host state, fresh sessions and fresh project directories. Tasks run in the order T1, T2, T3, T4, each in its own new conversation with all three agents. Each task is one unaddressed message from alice, identical across arms, with no follow-up.

## Tasks and rubric

The rubric is checked against messages in the conversation, from any agent. Text an agent didn't send doesn't count. "Pass" patterns are case-insensitive.

| Task | alice's message | Correct when a message contains | Holder |
| --- | --- | --- | --- |
| T1 | What Retry-After value does POST /orders send when it is throttled? | `37` | api |
| T2 | What is the vacuum window for warehouse-7? | `Sunday` and `02:40` | db |
| T3 | What is the latest time on Friday we can begin a full invoice-archive restore and still have it finished before the code freeze? | `05:00` or `5:00` or `5 am` | db and release |
| T4 | Plan: on Tuesday we ship the gallery thumbnail change, which makes POST /image-resize use a width of 640. Question: is 640 within the largest width that endpoint allows? | answer: `1024`. Blocker surfaced: `Thursday` or `CDN` or `Wednesday` | api, and release for the blocker |

T4 has two scores. The answer is what was asked. The blocker is the unprompted-help probe, and the main score for that task.

A result is **ambiguous** when a pattern matches but the message is hedged or contradicted, or when no pattern matches but a message seems to give the answer in another form. An ambiguous result is scored by the rubric alone, by a fresh model process that sees only the conversation text with arm names, lead lines and wake details removed. `db` or `release` saying "not mine" is not a wrong answer.

## Timeouts

A task ends when the conversation has had no new message and no agent transcript has grown for 60 seconds, or after 420 seconds. The next task starts then. No retry, no nudging.

## Metrics, per task and arm

- Wakes: message and roster notifications claimed, from each host's database. Parked rows that were never claimed.
- Model calls, and input, cache-read, cache-write and output tokens, from Claude Code transcripts by timestamp. Launch, before T1's conversation starts, is separate.
- Rubric score. Wall time from alice's message to the first correct message.
- Messages sent by agents. Stalls: no correct message by the task's end. Misroutes: under `lead`, an address to an agent that holds nothing relevant, or no address to one that does.
- What the lead did when it couldn't answer, verbatim.

Results are ranges and means over three sets per arm, and no significance is claimed.

## Stop and discard rules

Stop and report at 40M cache-read input tokens in total, or on a rate limit, counting launches, pilots and failed attempts. A partial result is fine. A set is discarded only for a documented harness failure, such as an agent never becoming ready or a daemon failing, and is then rerun and listed. A model's bad answer, silence or slowness is never a harness failure.

## Pilot

Before the sets, one pilot launch to prove the harness, using only the message "Pilot: say hello in one line." and none of the tasks. Its usage counts toward the ceiling, and its results are not used.
