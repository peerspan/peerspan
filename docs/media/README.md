# Media

## `collaborative-hillclimb-demo-720p.mp4` and `collaborative-hillclimb-demo.gif` (64 s, no sound)

Two owners' coding agents improve one bot together, in a peerbox.

What the video shows:

- **The task.** A Minecraft RL-style task: each episode the bot starts with nothing in a fresh
  arena and has two minutes. The game server pays a reward for each milestone reached, from the
  first log to a stone pickaxe, and more for reaching it sooner.
- **One turn.** One owner's agent writes a change and practises it in its own microVM. The other
  owner's agent reviews it in its own microVM and may patch it. The peerbox gate (the verifier)
  plays 60 episodes of the current bot and 60 of the new one on the same arenas, and merges the
  change only if it beats the current bot by a 2 % margin.
- **The run.** 8 turns in about 5 hours 40 minutes: 3 merged, 3 rejected by the gate, 2 where the
  agent submitted nothing. The mean score was 28.3 at the start and 86.1 at the last merge; the
  same bot scored 82.0 when the next evaluation measured it again on fresh arenas.

What ran:

- **Peerspan hosts.** Five host daemons: bob's, and a desk and a machine each for alice and
  carol. They carried the author, review and revision tasks between owners under grants, and
  bob's host ran the peerbox: fetch, submit and the gate.
- **[peerfs](https://github.com/peerspan/peerfs).** Each agent worked in a peerfs workspace.
  Branches, and the notebook both agents read, moved between alice's and carol's machines with
  `peerspan fs share` and `peerspan fs pull`.
- **The [runtime](https://github.com/peerspan/runtime).** Every agent step ran in a microVM, and
  so did every gate episode, without a network.

What to know when reading it:

- The agents are Claude Code, each run by the Peerspan runtime in a microVM with a peerfs
  workspace. They wrote every change to the bot; the starting bot was written by hand.
- All hosts (three people's) ran on one machine over loopback.
- A script stood in for steps the product does not do yet: moving trees between peerfs and Git,
  choosing an agent's starting branch per task, and writing the shared notebook.
- Quotes are the agents' own words, shortened; "…" marks omitted text.
- The gameplay is a replay recorded outside the gate, on arenas from the same pool, and is sped
  up as marked on screen.

NOT AN OFFICIAL MINECRAFT PRODUCT. NOT APPROVED BY OR ASSOCIATED WITH MOJANG OR MICROSOFT.
