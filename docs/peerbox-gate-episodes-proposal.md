# Peerbox gates for collaborative reinforcement learning

Status: **proposed on 2026-11-14.** Nothing is decided or implemented. It extends the
[gate proposal](peerbox-gate-proposal.md) and the
[peerbox contract's Gates section](peerbox-contract.md#gates) (PBX-9 to PBX-15), and needs a
change to the [runtime task contract](runtime-task-contract.md) and to the separate Peerspan
runtime (decision 2). Decisions 6 to 8 apply to every gate, not only to reinforcement
learning.

Peerboxes are meant for two kinds of collaboration: coding agents improving a program, and
people's agents improving a policy that acts in an environment (reinforcement learning,
planning, game bots, robotics in simulation). Today's gate serves the first and only part of
the second.

## The problem

Collaborative reinforcement learning on a gate needs five things. Today's gate has the
first.

1. **A reward the candidate cannot forge.** The environment that produces the reward runs
   where candidate code cannot reach it. PBX-15 provides this for outputs: the candidate run
   writes files, and the owner's checker judges them in a separate VM.
2. **A closed loop with candidate code.** Most policies worth contributing are code: a
   planner, a search, a bot, a network with custom layers. They must react to observations
   while the episode runs. Today the only ways to judge a policy are an action trace (which
   needs a deterministic environment fully visible in the inputs) or a policy as data that
   the checker loads (weights). A real game server, a stochastic simulator or hidden seeds
   rule out the first; code rules out the second, since running it in the checker is what
   PBX-15 forbids. The runtime has no path between two VMs (no network, no stdin), so the
   gate cannot express the loop.
3. **Generalization, not memorization.** A policy must be judged on episodes it never saw.
   Today's held-out snapshot is fixed until the owner sets the gate again, so every
   evaluation reuses it, and each verdict, score and reason a contributor gets back is
   another query against the same set. With enough submissions an agent can climb the
   holdout itself. `max_pending` only slows that down.
4. **Decisions that survive noise.** Returns in a stochastic environment vary from episode to
   episode far more than a timing measurement varies from run to run. Today's rule, the
   candidate's worst of at most 5 repeats against the frontier's best, suits timing; for
   returns it rejects most real gains and gives no statement of confidence.
5. **An evaluation contributors can audit.** In a challenge between owners, contributors need
   to know that the holdout and the environment did not change under them. Today readers see
   the gate's version but no commitment to what the version contains.

## Story

Alice runs a voxel treasure-run environment: a grid world with mineable blocks, ladders,
slippery ice that sometimes slides a step further, three items and an exit, generated from a
seed. She creates a peerbox for the bot's repository and sets an **episode gate**:

- the **environment**: her own server in the checker's VM. For each evaluation it derives
  200 fresh episode seeds from the evaluation's secret, plays them against whatever
  connects, and prints a `PEERBOX-GATE` line with each episode's ticks;
- the **candidate command**: `./bot --connect /run/peerbox-gate/env.sock`;
- the **comparison**: paired by episode, lower is better, promoted when the gain is at least
  3% with 95% confidence.

Readers see that the gate exists, its command, its comparison and its **commitment**, a
digest of Alice's environment and settings that she can open after the challenge.

Bob's agent replaces greedy pathfinding with an ordering search over the three items. In his
evaluation, `main` and his bot play the same 200 episodes; his bot needs 6.8% fewer ticks on
average, with a 95% lower bound of 4.1%, and is promoted. Carol's agent submits five times
in a row, tuning against each score it gets back. It learns nothing about the episodes: each
evaluation draws 200 new ones. A change that hardcodes routes for the public seeds in the
repository fails on every fresh episode. Neither of them sees a seed or an observation;
each sees the verdict, the gain, its bound and the reason.

After the challenge closes, Alice publishes her environment, the gate's salt and the
evaluations' secrets. Anyone can check them against the commitment and the digests recorded
with each decision, and replay any evaluation.

The same gate takes a real game server as the environment and an off-the-shelf bot library
as the candidate: the environment scores the episode live, so the server's nondeterminism no
longer matters. The cost is the server's start-up in every measurement.

## Design sketch

### Three ways to judge a policy

The gate record gains `mode`:

- `outputs` (today's gate, the default): candidate run, then check run on its outputs. This
  also covers a **policy as data**: the candidate run writes weights or a plan under
  `.peerbox-gate/out/`, and the checker loads it and runs the environment itself. The
  checker's loader is then the trust boundary: a format that can execute code on load
  (Python pickle, for example) puts candidate code in the checker. The gate guide says so.
- `outputs` with a **generator** (decision 6): for an action trace, the candidate needs
  fresh inputs to plan from, not a fixed snapshot; the generator produces them.
- `episode`: the candidate run and the **environment run** start together and are linked by
  one byte stream. The environment run's workspace is the checker snapshot and the
  evaluation's secret; it gets no candidate tree or outputs. Its last stdout line is the
  `PEERBOX-GATE` result, with the same rules as a check run's.

### The link

The runtime starts the two runs as a **linked pair** and connects them with one
bidirectional, ordered byte stream, a Unix stream socket at `/run/peerbox-gate/env.sock` in
each guest: the environment listens, the candidate connects. Nothing else changes about the
guests: no network, no other path out. The stream carries at most `link_bytes` in each
direction (default 64 MiB); the runtime closes it on that bound, on either run's exit, or at
the timeout. The protocol on it is the owner's; Peerspan never parses it.

The runtime reports linked-pair support and `max_concurrent_runs` of at least 2 in
`GET /v1/runtime`; `peerbox gate set --mode episode` is refused with `runtime_unsupported`
otherwise.

The environment must treat every byte from the link as hostile, as a parser of submitted
files must. The gate guide says so.

### Fresh episodes for every evaluation

At the start of every evaluation the home host draws a 32-byte **evaluation secret**. It is
written to `.peerbox-gate/secret` in the workspace of every run on the owner's side: the
environment run, the check run and the generator run. It never enters a candidate run's
workspace. The frontier and the candidate measurements of one evaluation share it, so they
face the same episodes; the next evaluation has a new one. An environment or checker derives
its episodes, seeds or test cases from the secret; one that ignores it keeps a fixed
holdout, as today.

A gate may also have a **generator**, `--generator JSON_ARGV`: once per evaluation, before
the first measurement, the home host runs it on the checker snapshot and the secret, with
`results: changes`. The files it writes under `.peerbox-gate/inputs/` become the candidate
runs' inputs for that evaluation, replacing the inputs snapshot. The check runs can derive
their expected results from the same secret, or from what the generator wrote outside
`.peerbox-gate/inputs/`, which the home host adds to their workspace under
`.peerbox-gate/generated/` and never gives a candidate. A generator that fails pauses the
gate with `generator_failed`, as a frontier failure does.

Because the frontier is measured again in every evaluation (PBX-12), fresh episodes change
no comparison. The public frontier score becomes the latest evaluation's, and varies with
the episodes; the gain is what compares across evaluations.

### Paired comparison with a confidence bound

The gate gains `compare`: `worst_best` (today's rule, the default) or `paired`. With
`paired`, the checker's or environment's line also carries `samples`, an array of 30 to
10,000 positive finite numbers, one per episode or test case, in an order the secret fixes,
so sample *i* of the frontier and of the candidate come from the same episode. `score` stays
required and is shown as before.

For each repeat *r*, the frontier's and the candidate's samples pair by index; the pairs of
all repeats pool. With *f* and *c* the paired scores and *d* = *f* − *c* for `lower` (*c* − *f*
for `higher`), the candidate is promoted when

    mean(d) − 1.645 · sd(d) / √n  ≥  (min_gain / 100) · mean(f)

with `sd` the sample standard deviation and *n* the number of pairs: a one-sided 95% lower
bound on the gain clears the margin. Pairing removes the variance that comes from the
episodes themselves, so far fewer episodes are needed than for two independent means. A
candidate measurement whose sample count differs from its paired frontier measurement is
`check_failed`. Failing the bound is `below_margin`. The public result gains `{pairs,
mean_gain_percent, lower_bound_percent}`; the samples themselves stay with the owner.

### Commitment

At `peerbox gate set` the home host draws a 32-byte **salt** and computes the gate's
**commitment**, SHA-256 of a fixed domain string, the salt, the inputs and checker snapshot
digests, and the commands, mode, comparison and bounds in a canonical encoding. The public
summary gains `commitment`; every decision's public result gains `secret_sha256`, the
SHA-256 of that evaluation's secret. The salt and the secrets are in `gate show --json` for
the owner only. Publishing them, and the snapshots, is the owner's choice, made outside
Peerspan, typically after a challenge closes; anyone can then recompute the commitment,
check each evaluation's secret against its decision and replay it.

The commitment shows that the owner did not change the holdout, the environment or the
rules within a gate version. It does not show that the home host ran them honestly: that
needs signed receipts (PBX-13, deferred).

### Measurement and verdict in episode mode

A measurement in `episode` mode is one linked pair, repeated and ordered as today (frontier,
candidate, ...). `score` must be `checker`; `time` is refused, because the environment paces
the episode. Failures keep today's attribution:

- the environment run fails, times out, or ends without a valid line: `check_failed`, as a
  check run does today. During a frontier measurement this pauses the gate with
  `frontier_failed`; during a candidate measurement it rejects the candidate (decision 5);
- the candidate run fails or exits early: the environment decides, from what it saw, how
  that episode scores; the candidate run's exit code does not reject on its own;
- either side exceeds `link_bytes`: the link closes and the environment decides.

### Bounds and configuration

Both modes gain separate bounds for the owner's side, `--checker-cpus` and
`--checker-memory-mib`, defaulting to the candidate's: an environment such as a game server
needs more memory than the policy. One timeout covers a linked pair. `peerbox gate set` gains
`--mode outputs|episode`, `--generator JSON_ARGV`, `--compare worst_best|paired` and
`--link-bytes N`. The public summary gains `mode`, `compare` and `commitment`; never the
generator command, the salt or a secret.

### Training

Contributors train on their own machines and submit the policy, as code, weights or both.
That is safe because no contributor sees an evaluation's episodes: fresh episodes make
training against the holdout impossible, not merely against the rules. Training inside the
gate is possible within a candidate run's timeout and bounds, which suits small policies only.

### Out of this proposal

GPUs in the runtime; policies or outputs above the runtime's 100 MiB per-artifact limit;
several candidates playing one environment together (multi-agent, self-play, leagues); an
environment that keeps state between evaluations; rendering replays for contributors;
signed, hash-chained receipts (PBX-13) and credit along commit lineage, which a public
challenge needs and which follow as their own proposals.

## Decisions

### 1. Which loops the gate supports

**Recommendation.** (a) All three: a policy as data on today's `outputs` gate, documented;
action traces with a generator; and an `episode` mode for policies that are code. Coding
agents keep the gate they have.

**Not chosen.** (b) Policy as data only: no runtime change, but excludes planners, search,
bots on libraries and any policy whose code is the contribution, which is most of what
agents would write. (c) Episodes only, replacing outputs: forces every coding gate to run an
environment it does not need.

### 2. Where the link lives

**Recommendation.** (a) In the runtime: it starts the pair and bridges one stream socket
between the guests (for example over vsock). Latency is local, so episodes of thousands of
steps work, and the guests still have no network.

**Not chosen.** (b) The home host relays through the run events route and a new input route:
no VM-to-VM path in the runtime, but the events route is a long poll of up to 25 seconds,
far too slow for an episode, and stdin is outside the runtime contract. (c) A private network
between the two guests: lets TCP clients connect unchanged, but it is a much larger surface
(addresses, DNS, ports) and ends "the guest has no network". A TCP client reaches the socket
through a small forwarder in the candidate's repository.

### 3. The shape of the link

**Recommendation.** (a) One ordered byte stream with a byte bound each way; the owner's
environment defines the protocol. Protocols differ by environment, and anything Peerspan
defined would be wrong for most of them.

**Not chosen.** (b) Framed observation and action messages with a gate-defined schema: lets
the host count steps and bound messages, but makes Peerspan a reinforcement learning
framework.

### 4. The score of an episode

**Recommendation.** (a) Only the environment's score (`score: checker`); `time` is refused
in `episode` mode.

**Not chosen.** (b) Allow `time` as the candidate run's `duration_ms`: the environment paces
the episode, so the time measures the environment as much as the policy.

### 5. Attributing an environment failure

**Recommendation.** (a) As for a check run today: on the frontier it pauses the gate; on a
candidate it rejects with `check_failed`. The candidate's bytes may have crashed the
environment, and a gate that let a crash pass would promote it.

**Not chosen.** (b) Pause the gate on any environment failure: protects contributors from a
fragile environment, but lets one hostile contribution stop the gate for everyone until the
owner acts.

### 6. How often the held-out episodes change

**Recommendation.** (a) A new secret for every evaluation, shared by its frontier and
candidate measurements, with an optional generator for candidates' inputs. Every verdict is
measured on episodes no earlier query touched, so probing the gate teaches nothing about the
next evaluation; the frontier is measured again each time anyway, so no comparison breaks.

**Not chosen.** (b) A new secret only on each promotion: keeps the public frontier score
stable, but every rejected submission between two promotions queries the same episodes,
which is exactly how an agent climbs a holdout. (c) A fixed holdout, as today: simplest, and
an agent with enough submissions overfits it.

### 7. What readers can check about the gate

**Recommendation.** (a) A salted commitment to the snapshots and settings in the public
summary, and each evaluation's secret digest in its decision; the owner may publish the salt,
the secrets and the snapshots later, and anyone can then verify and replay.

**Not chosen.** (b) The plain snapshot digests in the public summary: a digest of a small
holdout lets a contributor confirm a guess of its contents. (c) Nothing beyond the version,
as today: contributors cannot tell whether the holdout changed under them.

### 8. Comparing noisy scores

**Recommendation.** (a) Add `compare: paired`: per-episode samples paired by the shared
secret, promoted on a one-sided 95% lower confidence bound of the gain. Keep `worst_best` as
the default for timing. Pairing on the same episodes makes a few hundred episodes enough for
most environments.

**Not chosen.** (b) Raise the repeat limit and keep worst against best: needs a VM pair per
sample and still states no confidence. (c) Replace `worst_best` with the bound everywhere: a
time measurement gives one number per run, too few samples for a bound, and today's coding
gates would change behavior.

## Verification sketch

The fake runtime gains linked pairs: it runs both scripted sides, connects them through a
real socket pair and enforces `link_bytes`. Cases for a `peerbox_gate` suite:

- an episode gate promoting with the environment's score and moving the frontier; `time`
  refused with `episode`; `gate set --mode episode` refused when the runtime reports no
  linked pairs;
- the environment's workspace without any candidate tree or outputs; the candidate's
  workspace without the checker snapshot, the secret or anything generated outside
  `.peerbox-gate/inputs/`;
- a candidate that prints its own `PEERBOX-GATE` line changing nothing;
- the environment failing on the frontier pausing the gate and on a candidate rejecting it; a
  candidate exceeding `link_bytes` closing the link and the environment deciding;
- the same secret in every owner-side run of one evaluation and a different one in the next;
  `secret_sha256` in each decision matching the owner's `gate show`;
- generator outputs under `.peerbox-gate/inputs/` as the candidate's inputs, the rest under
  `.peerbox-gate/generated/` for the check run only; a failing generator pausing the gate with
  `generator_failed`;
- `paired`: a promotion and a `below_margin` at known samples on both sides of the bound, for
  each direction; fewer than 30 or mismatched sample counts as `check_failed`; the public
  result's `pairs`, `mean_gain_percent` and `lower_bound_percent`;
- the commitment recomputed from the salt and settings, unchanged across evaluations, changed
  by `gate set`; `mode`, `compare` and `commitment` in the public summary, and never the
  generator, the salt or a secret;
- the checker-side bounds applied to the environment, check and generator runs.

A live run with the real runtime, a stochastic voxel environment and two people's agents
records the experience, as the gate proposal's live run does.
