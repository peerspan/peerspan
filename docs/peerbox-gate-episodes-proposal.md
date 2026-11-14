# Peerbox gates for collaborative reinforcement learning

Status: **proposed on 2026-11-14.** Nothing is decided or implemented. It extends the
[gate proposal](peerbox-gate-proposal.md) and the
[peerbox contract's Gates section](peerbox-contract.md#gates) (PBX-9 to PBX-15), and needs a
change to the [runtime task contract](runtime-task-contract.md) and to the separate Peerspan
runtime (decision 2). Decisions 7 to 9 apply to every gate, not only to reinforcement
learning. The story uses a real, off-the-shelf game server as the environment.

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

Alice runs a treasure run in a 3D sandbox game. Her **environment** is the game's own server
with a small plugin of hers, all in the gate's checker snapshot with her own copy of the
server, booted
in a Java image. For each evaluation the plugin derives 60 arenas from the evaluation's
secret: terrain to dig through or climb, water, drops, three marked items and an exit. It lets
up to 10 bots in at once, one per arena, counts each run's game ticks on the server from spawn
until the bot stands on the exit holding all three items, and enforces the game's movement
rules on every move a client sends. When the arenas are done it prints a `PEERBOX-GATE` line
with each arena's ticks.

She creates a peerbox for the bot's repository, a bot on an open-source client library, and sets an **episode
gate**:

- the **candidate command**: `node bot.js --host 127.0.0.1 --port 7000 --bots 10`, in a Node
  image with the challenge's dependencies;
- the **link**: port 7000, so the bot connects to the server as it would on any machine;
- the **comparison**: paired by arena (`paired_normal`), lower is better, promoted when the
  gain is at least 3% by an approximate 95% bound. Each arena's ticks are capped at 60
  seconds of game time, so no single arena can dominate the result.

Readers see that the gate exists, its command, its images, its comparison and its
**commitment**, a digest of Alice's environment and settings that she can open after the
challenge.

Bob's agent replaces the baseline's walk-to-nearest with an ordering search over the three
items and digs through stone where that is shorter than walking round. In his evaluation,
`main` and his bot play the same 60 arenas; his bot needs 6.8% fewer ticks on average, and the
bound puts his gain at least 1.1 points above the 3% margin, so it is promoted. Carol's agent
submits five times in a row, tuning against each score it gets back. It learns nothing about the arenas: each evaluation draws 60
new ones. A change that sends position packets faster than a player can move is refused by the
server's movement checks and finishes no arena. Neither of them sees an arena or an
observation; each sees the verdict, the gain, its bound and the reason.

After the challenge closes, Alice publishes her plugin, the gate's salt and the evaluations'
secrets. Anyone can check them against the commitment and the digests recorded with each
decision, and replay any evaluation on their own server. Alice keeps her replays, recorded
by the plugin, for the video.

The server's nondeterminism (tick timing, chunk loading, physics) does not matter: the
environment scores each episode live, on the server, rather than replaying it. What a real
game costs is time. The game runs at 20 ticks a second, so a 30-second arena is 30
seconds of wall time, and the server's start takes about as long again. Ten bots at once bring
60 arenas to about four minutes a measurement, and an evaluation with one repeat to under ten.

## Design sketch

### Three ways to judge a policy

The gate record gains `mode`:

- `outputs` (today's gate, the default): candidate run, then check run on its outputs. This
  also covers a **policy as data**: the candidate run writes weights or a plan under
  `.peerbox-gate/out/`, and the checker loads it and runs the environment itself. The
  checker's loader is then the trust boundary: a format that can execute code on load
  (Python pickle, for example) puts candidate code in the checker. The gate guide says so.
- `outputs` with a **generator** (decision 7): for an action trace, the candidate needs
  fresh inputs to plan from, not a fixed snapshot; the generator produces them.
- `episode`: the candidate run and the **environment run** start together and are joined by
  a link port. The environment run's workspace is the checker snapshot and the
  evaluation's secret; it gets no candidate tree or outputs. Its last stdout line is the
  `PEERBOX-GATE` result, with the same rules as a check run's.

### The link

The runtime starts the two runs as a **linked pair** and joins them with a **link port**, a
TCP port on loopback in both guests: the environment listens on `127.0.0.1:PORT` in its
guest, and every connection the candidate opens to `127.0.0.1:PORT` in its own guest reaches
it. Nothing else changes about the guests: no network, no other path out. Clients and servers
that speak TCP, such as a game server and its bot library, work unchanged.

Underneath, the runtime already gives each guest one vsock port mapped to a Unix socket on the
host, for its own agent channel. A link adds one more mapping in each VM, connecting in the
candidate's and listening in the environment's, and the runtime splices each connection from
one to the other; guest init forwards the loopback port to the vsock port on each side.

The link takes at most `link_connections` connections at once (default 16) and carries at
most `link_bytes` in each direction over the pair's life (default 256 MiB); a connection
beyond the first bound is refused, and the second bound closes every connection. Both runs'
exits and the timeout close it too. The protocol on it is the owner's; Peerspan never parses
it.

The runtime reports linked-pair support and `max_concurrent_runs` of at least 2 in
`GET /v1/runtime`; `peerbox gate set --mode episode` is refused with `runtime_unsupported`
otherwise.

The environment must treat every byte from the link as hostile, as a parser of submitted
files must. That includes the game's own rules: a game server that trusts its clients'
positions lets a candidate fly or teleport to the exit, so the environment enforces movement,
reach and inventory on the server side. The gate guide says so.

### Images

A gate's runs may name OCI images, as runtime agents' runs do
([runtime agent contract](runtime-agent-contract.md)): `--image REF` for candidate runs and
`--checker-image REF` for environment, check and generator runs, each a reference with a
digest (`name@sha256:...`), so that the commitment covers what ran. A Java image for a game
server and a Node image for its bots, or one image of the owner's with the challenge's
dependencies installed, means a contribution carries only its own code, within the bundle
limit. A gate naming an image needs a runtime that reports `images` true (otherwise
`runtime_unsupported`); the runtime pulls the image on the home host, so the guests still need
no network.

Proprietary files, such as a game's server, belong in the checker snapshot, which never
leaves the home host. Their license is the owner's to follow; Peerspan neither ships nor
fetches them.

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

The gate gains `compare`: `worst_best` (today's rule, the default), `paired_normal` or
`paired_bounded`. With either paired mode, the checker's or environment's line also carries
`samples`, an array of 30 to 10,000 positive finite numbers, one per episode or test case, in
an order the secret fixes, so sample *i* of the frontier and of the candidate come from the
same episode. `score` stays required and is shown as before.

Every repeat of an evaluation uses the same secret, so sample *i* is the same episode in
every repeat. Repeats are therefore not new episodes, and are never pooled as if they were:
counting a repeated episode again would shrink the bound without testing anything new. The
home host first averages each episode over the repeats, giving one frontier score *f*ᵢ and
one candidate score *c*ᵢ per episode. With *d*ᵢ = *f*ᵢ − *c*ᵢ for `lower` (*c*ᵢ − *f*ᵢ for
`higher`), each episode's **margin-adjusted gain** is

    eᵢ = dᵢ − (min_gain / 100) · fᵢ

The margin is subtracted per episode, not compared with `mean(f)` afterwards, so that the
bound accounts for the frontier's own variation and its covariance with the gain; a margin
against a frontier mean treated as exact would promote too often. *n* is the number of
episodes, not of measurements, and `sd` is the sample standard deviation of *e*. Both modes
assume what the environment has to provide: episodes drawn independently from one
distribution, which a secret-derived set of episodes is when the environment samples each
one afresh from it. Then:

- **`paired_normal`**, an approximate bound. The candidate is promoted when

      mean(e) − 1.645 · sd(e) / √n  ≥  0

  This is a normal approximation, and its 95% is approximate: it is close for scores without
  rare extreme outcomes, and can be far off when they occur. A candidate that is slightly
  better in most episodes and much worse in a rare one can pass every time those episodes are
  missed from the sample; with 30 episodes and a 2% chance of a large loss, that is more than
  half the time. It suits scores capped per episode, such as ticks with a time limit, and the
  gate guide says to cap them.
- **`paired_bounded`**, a guaranteed bound. The gate declares the score range, `--score-range
  LO HI`; a sample outside it is `check_failed`. With *R* = (2 + min_gain / 100) · (HI − LO),
  the width of the range of *e*, and *L* = ln(2 / 0.05), the candidate is promoted when

      mean(e) − √(2 · sd(e)² · L / n) − 7 · R · L / (3 · (n − 1))  ≥  0

  an empirical Bernstein bound, which holds with probability at least 95% for any
  distribution of scores within the range. It costs episodes: the last term shrinks only as
  *R* / *n*, so a wide range needs hundreds to thousands of episodes to show a gain of a few
  percent. A tight range, such as a per-episode cap near the typical score, keeps it
  practical.

Repeats only reduce the noise within each episode; more episodes per measurement are what
tighten either bound. The same rules hold for an environment that ignores the secret and
replays a fixed set, except that the bound then speaks about that set, not about new
episodes. Pairing removes the variance that comes from the episodes themselves, so far fewer
episodes are needed than for two independent means. A measurement whose sample count differs
from the evaluation's first frontier measurement is `check_failed`: on a frontier measurement
it pauses the gate, on a candidate's it rejects the candidate. Failing the bound is
`below_margin`. The public result gains `{episodes, mean_gain_percent, margin_bound_percent}`:
the mean of *d* and the lower bound of mean(*e*), each as a percentage of mean(*f*), the
second at least 0 on a promotion. The public summary shows the mode and, for
`paired_bounded`, the score range. The samples themselves stay with the owner.

### Commitment

At `peerbox gate set` the home host draws a 32-byte **salt** and computes the gate's
**commitment**, SHA-256 of a fixed domain string, the salt, the inputs and checker snapshot
digests, the image references, and the commands, mode, comparison, link and bounds in a
canonical encoding. The public
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
  `frontier_failed`; during a candidate measurement it rejects the candidate (decision 6);
- the candidate run fails or exits early: the environment decides, from what it saw, how
  that episode scores; the candidate run's exit code does not reject on its own;
- either side exceeds `link_bytes`: the link closes and the environment decides; a connection
  beyond `link_connections` is refused and the episodes go on.

### Bounds and configuration

Both modes gain separate bounds for the owner's side, `--checker-cpus` and
`--checker-memory-mib`, defaulting to the candidate's: an environment such as a game server
needs more memory than the policy. One timeout covers a linked pair. `peerbox gate set` gains
`--mode outputs|episode`, `--generator JSON_ARGV`, `--compare worst_best|paired_normal|paired_bounded`, `--score-range LO HI`, `--image
REF`, `--checker-image REF`, `--link-port N`, `--link-connections N` and `--link-bytes N`. A
real-time environment needs a longer timeout than the default 15 minutes, up to what the
runtime reports. The public summary gains `mode`, `compare`, `score_range` (null unless
`paired_bounded`), `image`, `link_port` and `commitment`; never the checker image, the generator command, the salt or a secret.

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

**Recommendation.** (a) In the runtime: it starts the pair and splices connections between
the guests over vsock. The runtime already maps one vsock port per guest to a Unix socket on
the host for its agent channel (`krun_vsock_device_add_unix_port`, which takes a listen
flag), so a link is one more mapping on each side. Latency is local, so episodes of thousands
of steps work, and the guests still have no network.

**Not chosen.** (b) The home host relays through the run events route and a new input route:
no VM-to-VM path in the runtime, but the events route is a long poll of up to 25 seconds,
far too slow for an episode, and stdin is outside the runtime contract. (c) A private network
between the two guests: lets TCP clients connect unchanged, but it is a much larger surface
(addresses, DNS, ports) and ends "the guest has no network".

### 3. The shape of the link

**Recommendation.** (a) A loopback TCP port in both guests, with up to `link_connections`
connections at once and a byte bound each way; the owner's environment defines the protocol.
Game servers, simulators and their client libraries speak TCP and open several connections
(one per bot, or a reconnect after a death or a kick), and protocols differ by environment,
so anything Peerspan defined would be wrong for most of them.

**Not chosen.** (b) One Unix stream socket in each guest: simpler to bound, but every TCP
client needs a forwarder, and one connection cannot carry several bots or a reconnect. (c)
Framed observation and action messages with a gate-defined schema: lets
the host count steps and bound messages, but makes Peerspan a reinforcement learning
framework.

### 4. Images for the gate's runs

**Recommendation.** (a) A candidate image and a checker image, each pinned by digest and
covered by the commitment, as runtime agents' runs already name images. A game server needs
Java and its bots need Node with their libraries, which neither the runtime's minimal image
nor a contribution within the bundle limit can carry.

**Not chosen.** (b) The runtime's own image, with runtimes and dependencies in the inputs and
checker snapshots: works with no contract change, but every owner rebuilds a toolchain inside
a snapshot, and the snapshot sizes grow with it. (c) Tags without digests: an image could
change under a gate version, which the commitment exists to rule out.

### 5. The score of an episode

**Recommendation.** (a) Only the environment's score (`score: checker`); `time` is refused
in `episode` mode.

**Not chosen.** (b) Allow `time` as the candidate run's `duration_ms`: the environment paces
the episode, so the time measures the environment as much as the policy.

### 6. Attributing an environment failure

**Recommendation.** (a) As for a check run today: on the frontier it pauses the gate; on a
candidate it rejects with `check_failed`. The candidate's bytes may have crashed the
environment, and a gate that let a crash pass would promote it.

**Not chosen.** (b) Pause the gate on any environment failure: protects contributors from a
fragile environment, but lets one hostile contribution stop the gate for everyone until the
owner acts.

### 7. How often the held-out episodes change

**Recommendation.** (a) A new secret for every evaluation, shared by its frontier and
candidate measurements, with an optional generator for candidates' inputs. Every verdict is
measured on episodes no earlier query touched, so probing the gate teaches nothing about the
next evaluation; the frontier is measured again each time anyway, so no comparison breaks.

**Not chosen.** (b) A new secret only on each promotion: keeps the public frontier score
stable, but every rejected submission between two promotions queries the same episodes,
which is exactly how an agent climbs a holdout. (c) A fixed holdout, as today: simplest, and
an agent with enough submissions overfits it.

### 8. What readers can check about the gate

**Recommendation.** (a) A salted commitment to the snapshots and settings in the public
summary, and each evaluation's secret digest in its decision; the owner may publish the salt,
the secrets and the snapshots later, and anyone can then verify and replay.

**Not chosen.** (b) The plain snapshot digests in the public summary: a digest of a small
holdout lets a contributor confirm a guess of its contents. (c) Nothing beyond the version,
as today: contributors cannot tell whether the holdout changed under them.

### 9. Comparing noisy scores

**Recommendation.** (a) Add two paired modes, both on per-episode samples paired by the
shared secret, with the margin subtracted per episode: `paired_normal`, an approximate 95%
bound that is cheap in episodes and documented as approximate, and `paired_bounded`, an
empirical Bernstein bound over a declared score range that holds for any distribution in
that range but needs many more episodes. The owner chooses per gate, trading episodes
against a guarantee; the public summary shows which. Keep `worst_best` as the default for
timing.

**Not chosen.** (b) `paired_normal` only: cheap, but its 95% fails for scores with rare
extreme outcomes, and nothing tells contributors so. (c) `paired_bounded` only: a real
guarantee, but a real-time environment of a few dozen episodes per measurement could never
promote. (d) Raise the repeat limit and keep worst against best: needs a VM pair per sample
and still states no confidence. (e) Replace `worst_best` with the bound everywhere: a
time measurement gives one number per run, too few samples for a bound, and today's coding
gates would change behavior.

## Verification sketch

The fake runtime gains linked pairs: it runs both scripted sides, connects them through a
real loopback port and enforces `link_connections` and `link_bytes`. Cases for a `peerbox_gate` suite:

- an episode gate promoting with the environment's score and moving the frontier; `time`
  refused with `episode`; `gate set --mode episode` refused when the runtime reports no
  linked pairs;
- the environment's workspace without any candidate tree or outputs; the candidate's
  workspace without the checker snapshot, the secret or anything generated outside
  `.peerbox-gate/inputs/`;
- a candidate that prints its own `PEERBOX-GATE` line changing nothing;
- the environment failing on the frontier pausing the gate and on a candidate rejecting it; a
  candidate exceeding `link_bytes` closing the link and the environment deciding; a
  connection beyond `link_connections` refused while the others go on;
- several candidate connections reaching the environment's listener on the link port, and
  nothing else reachable from either guest;
- a gate naming an image refused on a runtime that reports `images` false, and a reference
  without a digest refused; both images in the runs' requests; the checker image never in the
  public summary;
- the same secret in every owner-side run of one evaluation and a different one in the next;
  `secret_sha256` in each decision matching the owner's `gate show`;
- generator outputs under `.peerbox-gate/inputs/` as the candidate's inputs, the rest under
  `.peerbox-gate/generated/` for the check run only; a failing generator pausing the gate with
  `generator_failed`;
- `paired_normal` and `paired_bounded`: a promotion and a `below_margin` at known samples on
  both sides of each bound, for each direction; `paired_bounded` refused without
  `--score-range`, a sample outside the range `check_failed`, and rare-large-loss samples
  that `paired_normal` promotes rejected by `paired_bounded`; a case where the gain beats the margin against `mean(f)` taken as exact
  but not per episode, rejected; fewer than 30 or mismatched sample counts as `check_failed`; with
  `repeats` above 1, each episode averaged over the repeats and *n* the episode count, so
  identical repeats leave the bound unchanged; the public result's `episodes`,
  `mean_gain_percent` and `margin_bound_percent`;
- the commitment recomputed from the salt and settings, unchanged across evaluations, changed
  by `gate set`; `mode`, `compare` and `commitment` in the public summary, and never the
  generator, the salt or a secret;
- the checker-side bounds applied to the environment, check and generator runs.

A live run with the real runtime, the game environment of the story and two people's
agents records the experience, as the gate proposal's live run does.
