# Wake comparison 2: pre-registration

Written and committed before any model run of this comparison. Everything not stated here is as in `PREREGISTRATION.md`: setup, fixtures, tasks, rubric, timeouts, scripted alice with no follow-up, model, `--setting-sources project,local` and auto memory off. Arms are compared with run 1's `today` and `lead` numbers in `docs/results/conversations-lead-comparison.json`, which aren't rerun. Any difference in Claude Code version from run 1 (2.1.314) is recorded as a threat to the comparison.

## Arms

One binary and one adapter; `PEERSPAN_EXPERIMENT_WAKE` selects the arm for both daemons and the agents. Sets 7 to 12 alternate: quiet, route, quiet, route, quiet, route.

**quiet:** today's wake rule, everyone wakes. The `conversation_send` description and every conversation event add:

> If you have nothing to add, do not post anything: do not say that you don't know, that a message isn't for you, or that someone else should answer.

**route:** the lead rule, as run 1's `lead` arm, including its `Wake rule:` event line. The `conversation_send` description adds run 1's sentence and:

> If you are a conversation's lead and what you hold doesn't fully answer a message, you must send a message with addressed_to set to the agents likely to hold what is missing. Naming an agent in the text without addressing it doesn't reach it.

The lead's event, in place of run 1's lead line, adds:

> You are the lead. If you are a conversation's lead and what you hold doesn't fully answer a message, you must send a message with addressed_to set to the agents likely to hold what is missing. Naming an agent in the text without addressing it doesn't reach it.
> Agents' areas: alice/api: API; bob/db: database; bob/release: release process

The labels are at the level an owner would plausibly write, and hint at no task's answer. No such field exists in the product, so they reach the adapter through `PEERSPAN_EXPERIMENT_LABELS`.

## Metrics

Run 1's metrics, per task and arm, computed the same way, plus:

- **Text seen:** from each set's transcripts, the tool description in `api-request-shape` records or tool-search results, and the event text in queued channel messages, for each agent where they appear.
- **Blind score:** every task of every set is scored against the rubric by one fresh process that sees only conversation messages, with arm names, wake and lead lines, labels and sets removed and tasks in shuffled order. Disagreements with the script are reported, and the script's score stays the primary one, as in run 1.
- **Cost on completed tasks:** per task and arm, calls and cache-read tokens over tasks that passed the answer rubric, reported separately from all tasks.
- **Useless posts:** agent messages that give no fact from the agent's notes and no answer, such as "not in my notes". Counted in every arm, by script pattern and review.
- **route:** whether the lead named an agent without addressing it, misroutes as in run 1, and in T4 whether `release` was addressed and, if so, whether the blocker surfaced.

## Stop and discard rules

As in `PREREGISTRATION.md`: 40M cache-read tokens in total for this comparison, or a rate limit. A partial result is fine. A set is discarded only for a documented harness failure, and is then rerun and listed. There is no tuning after a task result is seen.

## Pilot

One launch using only "Pilot: say hello in one line." on each arm, to check plumbing. It sees no task, its usage counts toward the ceiling, and any change it forces is listed.
