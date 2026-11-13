# Peerbox gates: promoting contributions by a measured result

Status: **proposal, 2026-11-13; not accepted.** Nothing here is specified or implemented. It
extends the [peerbox contract](peerbox-contract.md) (PBX-1 to PBX-8), which must be
implemented first (its slices A to C). The [decisions](#decisions) below need the owner.

A **gate** is an optional, owner-configured evaluator on a peerbox. Every contribution to a
gated peerbox is run against the evaluator on the home host, in a microVM, from the
contribution's exact tree; one that passes and beats the protected branch's current score by
a set margin fast-forwards the protected branch automatically, and the decision, with the
scores, is recorded and shown to the contributor. The protected branch becomes a frontier:
each promoted contribution is the next baseline for everyone.

This is the shape of a public challenge (one objective, a verifier, each promoted result the
next baseline), and of the [Playbox](https://github.com/Epistetechnician/playbox) project's
"Commons" merge gate, whose README reports, on one machine and not yet in a live room, four
of six submissions rejected (including a memoizing cheat caught by a sealed holdout) and a
2.84x speedup promoted. Peerboxes already provide what that needs underneath: contributions
on their own refs, runs from an exact tree in a microVM on another person's machine, and a
fast-forward-only accept. The runtime's Story 2 (three agents in parallel VMs on forks
across two machines, the fastest merged by hand) is the manual version of this loop.

Without a gate, a peerbox is unchanged: the owner reviews every contribution.

## Story

Alice wants her project's test suite to run faster without changing its results. She creates
a peerbox and adds a gate:

- the **evaluator**: a command run in the VM, `python3 .gate/score.py`, with files she keeps on
  her machine and never shares, including a held-out set of inputs and expected outputs;
- the **direction and margin**: lower wall time is better, by at least 5%;
- the **budget**: 4 vCPUs, 8 GiB, 15 minutes per evaluation.

The gate measures `main` once: that is the frontier. Bob's and Carol's agents fetch, try
changes and submit. Each submission is evaluated against the frontier in turn. Carol's
memoizes the public examples and fails the held-out set: rejected, with the reason. Bob's is
6.1% faster with identical outputs: promoted, `main` fast-forwards, and his score is the new
frontier. Everyone's next attempt starts from Bob's commit. Alice can pause the gate, review
by hand at any time, and read every decision with its scores.

## Design sketch

### The gate

A gate belongs to one peerbox and is local configuration on its home host, like the runtime's
local switch and like review (decision 1). `peerbox gate set PEERBOX --evaluator-dir DIR
--command ARGV... --direction lower|higher --min-gain PERCENT [--repeats N] [--cpus N]
[--memory-mib N] [--timeout DURATION]` sets it; `peerbox gate pause|resume|clear|show`
manage it. Readers of the peerbox see that it is gated, the command, the direction, the
margin and the frontier score, through `list` and `status`; never the evaluator's files.

### An evaluation

For each contribution, in submission order and one at a time (decision 6), the home host:

1. builds the workspace from the contribution's tree as a peerbox run does (never `git
   archive`, no attribute or configuration applied), and adds the evaluator's files under
   `.peerbox-gate/`, replacing anything the contribution put there (decision 2);
2. runs the command on the home host's own runtime under the gate's bounds, `repeats` times,
   and does the same for the current frontier commit in the same evaluation, so that both
   scores come from the same machine at the same time (decision 4);
3. reads each run's result from the last line of its stdout,
   `PEERBOX-GATE {"pass": BOOL, "score": NUMBER, "reason": TEXT}`; a run without that line, or
   that fails, timed out or was cancelled, counts as not passing;
4. promotes when every candidate run passes and the candidate's worst score beats the
   frontier's best score by at least the margin in the gate's direction; otherwise rejects,
   with the reason;
5. promotes as a review accept does (fast-forward only, compare-and-swap on the head, a clean
   worktree): `not_fast_forward` and `head_moved` reject the contribution, and its
   contributor rebases and submits again (decision 3).

The decision record gains the gate's part: `{gate_version, evaluator_sha256, frontier,
frontier_scores, candidate_scores, runs}`, and `decided_by` is `gate`. A promotion makes the
candidate's score the frontier.

### What the contributor sees

The verdict, both sides' scores, the reason and the gate version, through `status`. **Never**
the evaluation's output, logs or result artifacts: those can reveal the held-out files, and
they stay with the owner. One number and a short reason per evaluation are what a contributor
learns about the holdout, which bounds the leak; `max_pending` and the queue bound limit how
often they can probe (decision 2).

### Cost and order

Evaluations use the home host owner's runtime, under the gate's bounds, not the contributor's
runtime rule: the contributor asked for a review, not a run. Contributions wait in the review
queue; the gate takes them oldest first and evaluates one at a time, so every decision is
measured against the frontier it would replace. A contribution that arrives while the gate is
paused waits; the owner can still accept or reject it by hand.

### Out of this proposal

Credit split along commit lineage; a gate shared across several peerboxes; a signed,
hash-chained receipt log (decision 5); evaluators running anywhere but the home host;
non-numeric objectives beyond pass and fail; parallel evaluation.

## Decisions

### 1. Where the gate lives

**Recommendation.** (a) Local configuration on the home host, shown to the peerbox's readers.
Review is already the home host owner's local act, and the home host runs the evaluator
either way, so signing the gate into the policy would not let anyone check what it ran.

**Not chosen.** (b) A signed field of the owner's policy, next to the peerbox rule: hosts on
earlier software would refuse the policy (RUN-5), for no added assurance.

### 2. Keeping the evaluator's held-out files secret

**Recommendation.** (a) The files live on the home host and are added to each evaluation's
workspace under `.peerbox-gate/`; the contributor receives only the verdict, the scores and
the reason, never output or artifacts. The candidate's code can read the files while it
runs, but the VM has no network and nothing it writes reaches the contributor.

**Not chosen.** (b) Evaluators only from the repository itself: no secret, so a memoizing
change passes. (c) Running the evaluator outside the candidate's VM: needs a second VM per
evaluation and a channel between them, which the runtime does not have.

### 3. What happens on a pass

**Recommendation.** (a) The gate promotes automatically (fast-forward only) and records the
decision; the owner can pause the gate and can always review by hand.

**Not chosen.** (b) The gate only recommends and the owner accepts: keeps a person in every
merge, which is the default without a gate anyway.

### 4. Noisy measurements

**Recommendation.** (a) Measure the frontier and the candidate in the same evaluation,
`repeats` times each (default 1, at most 5), and compare the candidate's worst against the
frontier's best.

**Not chosen.** (b) A frontier score measured once and pinned: cheaper, but drifts with the
machine's load and with runtime upgrades. (c) Statistical tests over many repeats: needs more
runs than a microVM budget allows for most projects.

### 5. Receipts

**Recommendation.** (a) Durable, unsigned decision records now, as for review; a signed,
hash-chained receipt log, which the peerbox contract already defers, follows as its own
proposal.

**Not chosen.** (b) Signed receipts in this slice: they only show that the home host signed
what it says it ran, and they double the work before anything is usable.

### 6. Order of evaluation

**Recommendation.** (a) One at a time, oldest first, each against the current frontier.

**Not chosen.** (b) Several at once, then re-checking each winner against the new frontier:
faster on a big machine, but every promotion invalidates the others' comparisons.

## Verification sketch

A `peerbox_gate` suite, written from the contract by the separate author, with the fake
runtime scripted to print `PEERBOX-GATE` lines: a pass with enough gain promoted and the
frontier moved; below the margin, failing, missing the line, timed out, each rejected with
its reason; the evaluator's files present in the workspace and never in anything the
contributor can read; a contribution's own `.peerbox-gate/` replaced; `not_fast_forward` and
`head_moved`; pause, resume and manual review while paused; order of evaluation; the decision
record's gate fields; restart during an evaluation. A live run on two machines with the real
runtime and real agents records the experience, as Story 2 did.
