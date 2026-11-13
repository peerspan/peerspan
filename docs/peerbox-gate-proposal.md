# Peerbox gates: promoting contributions by a measured result

Status: **accepted on 2026-11-13.** The owner chose the recommendation of each of the six
[decisions](#decisions) it was proposed with, recorded as
[PBX-9 to PBX-14](decision-log.md#pbx-9-to-pbx-14-peerbox-gates-2026-11-13); review then
showed that decision 2 lets a candidate forge the verdict, and the owner chose
[decision 7](#7-separating-the-checker-from-the-candidate), PBX-15, which supersedes it. The
[peerbox contract's Gates section](peerbox-contract.md#gates) specifies the result; nothing is
implemented yet. It extends the
[peerbox contract](peerbox-contract.md) (PBX-1 to PBX-8), whose slices A to C come first.

A **gate** is an optional, owner-configured evaluator on a peerbox. Every contribution to a
gated peerbox is run against the evaluator on the home host, in a microVM, from the
contribution's exact tree; one that passes and beats the protected branch's current score by
a set margin fast-forwards the protected branch automatically, and the decision, with the
scores, is recorded and shown to the contributor. The protected branch becomes a frontier:
each promoted contribution is the next baseline for everyone.

This is the shape of a public challenge: one objective, a verifier, and each promoted result
the next baseline, with a held-out set that catches a submission which only memorizes the
public examples. Peerboxes already provide what that needs underneath: contributions
on their own refs, runs from an exact tree in a microVM on another person's machine, and a
fast-forward-only accept. The runtime's Story 2 (three agents in parallel VMs on forks
across two machines, the fastest merged by hand) is the manual version of this loop.

Without a gate, a peerbox is unchanged: the owner reviews every contribution.

## Story

Alice wants her project's test suite to run faster without changing its results. She creates
a peerbox and adds a gate:

- the **task**: the command a candidate runs, `./run-suite .peerbox-gate/inputs
  .peerbox-gate/out`, on held-out inputs she keeps on her machine;
- the **checker**: her own script, run in a separate VM, that compares the candidate's
  outputs with held-out expected outputs that never reach a candidate's VM;
- the **score and margin**: the candidate run's wall time as the runtime measures it, lower
  is better, by at least 5%;
- the **budget**: 4 vCPUs, 8 GiB, 15 minutes per evaluation.

The gate measures `main` once: that is the frontier. Bob's and Carol's agents fetch, try
changes and submit. Each submission is evaluated against the frontier in turn. Carol's
memoizes the public examples, so its outputs for the held-out inputs are wrong: the checker
rejects it, with its reason. Bob's is
6.1% faster with identical outputs: promoted, `main` fast-forwards, and his score is the new
frontier. Everyone's next attempt starts from Bob's commit. Alice can pause the gate, review
by hand at any time, and read every decision with its scores.

## Design sketch

### The gate

A gate belongs to one peerbox and is local configuration on its home host, like the runtime's
local switch and like review (decision 1). `peerbox gate set PEERBOX --inputs-dir DIR
--command ARGV... --checker-dir DIR --checker ARGV... --score time|checker --direction
lower|higher --min-gain PERCENT [--repeats N] [--cpus N] [--memory-mib N] [--timeout
DURATION]` sets it; `peerbox gate pause|resume|clear|show` manage it. Readers of the peerbox
see that it is gated, the candidate command, the score source, the direction, the margin and
the frontier score, through `list` and `status`; never the inputs, the checker or its files.

### An evaluation

For each contribution, in submission order and one at a time (decision 6), the home host:

1. **Candidate run.** Builds the workspace from the contribution's tree as a peerbox run does
   (never `git archive`, no attribute or configuration applied), adds the held-out inputs
   under `.peerbox-gate/inputs/`, replacing anything the contribution put under
   `.peerbox-gate/`, and runs the candidate command on the home host's own runtime under the
   gate's bounds, with `results: changes`. The outputs are the files it wrote under
   `.peerbox-gate/out/`; everything else it wrote, printed or returned is ignored. Its time is
   the runtime's own `duration_ms`, which the candidate's code cannot report or change (decision 7).
2. **Check run.** In a separate run with its own VM, the home host builds a workspace from the
   checker's files, the held-out expected outputs and the candidate's outputs (under
   `.peerbox-gate/out/`), and runs the checker command. No candidate code runs there. The
   checker's result is the last line of its stdout,
   `PEERBOX-GATE {"pass": BOOL, "score": NUMBER, "reason": TEXT}`, with `reason` at most 200
   bytes; a check run without that line, or that fails or times out, counts as not passing,
   and so does a candidate run that fails, times out or is cancelled.
3. **Score.** With `--score time`, the candidate run's `duration_ms`; with `--score checker`,
   the checker's `score`. Both runs are repeated `repeats` times, for the candidate and for the
   current frontier commit in the same evaluation, so that both sides' scores come from the
   same machine at the same time (decision 4).
4. **Verdict.** Promotes when every candidate check passes and the candidate's worst score
   beats the frontier's best score by at least the margin in the gate's direction; otherwise
   rejects, with the checker's reason or the run failure;
5. promotes as a review accept does (fast-forward only, compare-and-swap on the head, a clean
   worktree): `not_fast_forward` and `head_moved` reject the contribution, and its
   contributor rebases and submits again (decision 3).

The decision record gains the gate's part: `{gate_version, inputs_sha256, checker_sha256,
frontier, frontier_scores, candidate_scores, runs}`, with each run's task IDs, and `decided_by`
is `gate`. A promotion makes the
candidate's score the frontier.

### What the contributor sees

The verdict, both sides' scores, the checker's reason and the gate version, through `status`.
**Never** either run's output, logs or result artifacts: they stay with the owner. Nothing the
candidate's code writes reaches the verdict, the score or the reason: the time comes from the
runtime, and the pass, the checker score and the reason come from the owner's checker in a VM
where no candidate code runs. The candidate's code can read the held-out inputs while it runs,
but never the expected outputs. What a contributor learns about the holdout is one verdict,
one number and the checker's bounded reason per evaluation; `max_pending` and the queue bound
limit how often they can probe (decisions 2 and 7).

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

Superseded by [decision 7](#7-separating-the-checker-from-the-candidate) (PBX-15): with the
evaluator and the candidate in one VM, the candidate's code can forge the verdict.

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

### 7. Separating the checker from the candidate

Raised in review after decision 2 was taken: when the evaluator imports or runs the
candidate's code in the same VM, that code can print its own final `PEERBOX-GATE` line with a
winning score, and can put held-out contents into `reason`. Nothing inside one VM protects the
evaluator from code running there as the same user.

**Recommendation.** (a) "Two runs": a candidate run on the contribution's tree with the
held-out inputs only, timed by the runtime itself, then the owner's checker in a separate VM
comparing the candidate's outputs with the held-out expected outputs, which never enter a
candidate's VM. Only the runtime's time and the checker's pass, score and reason are trusted.
It costs two VMs per evaluation; the runtime already chains them, since a run's `changes`
artifacts can become the next run's workspace, which decision 2 (c) wrongly said it could not.

**Not chosen.** (b) "Keep one run, document": keep decision 2 and say that a gate is only as
trustworthy as the evaluator's own isolation of candidate code, never returning `reason`.
Cheaper, but any evaluator that runs candidate code can be forged.

## Verification sketch

A `peerbox_gate` suite, written from the contract by the separate author, with the fake
runtime scripted to print `PEERBOX-GATE` lines: a pass with enough gain promoted and the
frontier moved; a candidate that prints its own `PEERBOX-GATE` line or writes outside
`.peerbox-gate/out/` changing nothing; the expected outputs never in a candidate run's
workspace; `--score time` taken from the runtime's `duration_ms`; below the margin, failing, missing the line, timed out, each rejected with
its reason; the evaluator's files present in the workspace and never in anything the
contributor can read; a contribution's own `.peerbox-gate/` replaced; `not_fast_forward` and
`head_moved`; pause, resume and manual review while paused; order of evaluation; the decision
record's gate fields; restart during an evaluation. A live run on two machines with the real
runtime and real agents records the experience, as Story 2 did.
