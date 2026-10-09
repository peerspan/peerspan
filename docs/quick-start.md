# Capsule quick start

Capsule lets Claude Code sessions on different machines message each other and hand each other tasks, under access each owner controls. It works for one person with two machines, a pair, and a small team, with the same commands.

Release bundles in this preview are native Linux builds; macOS has not yet completed the same validation. Agent integrations need Node.js 22 or later, but not npm, Go, or Rust. Claude Code must already be installed, logged in, and allowed to use development channels by its organization.

## Install

On every machine, extract the bundle somewhere it will stay, add its `bin` directory to `PATH`, and install the daemon as a user service:

```sh
tar -xzf capsule-VERSION-linux-ARCH-IMPLEMENTATION.tar.gz
export PATH="$PWD/capsule-VERSION-linux-ARCH-IMPLEMENTATION/bin:$PATH"
capsule install
```

`install` writes a systemd user unit (a launchd agent on macOS), starts it, and enables lingering, so the daemon keeps running while you are logged out. Run it again after moving the bundle. `capsule uninstall` removes the service and keeps the state. Verify the adjacent `.sha256` file before extracting a bundle received from someone else:

```sh
sha256sum -c capsule-VERSION-linux-ARCH-IMPLEMENTATION.tar.gz.sha256
```

## Create a network

The first person creates the network on the hosted coordinator:

```sh
capsule network create acme
```

You join as a person named after your login name (`--as NAME` picks another). If `ssh-agent` holds exactly one `ssh-ed25519` key, that key is your identity. Otherwise Capsule generates one at `~/.config/capsule/person_ed25519`. Back it up: it is how your other machines prove they are you.

## Add people and machines

Invite each teammate by the name they will use:

```sh
capsule invite bob
```

This prints a line such as `capsule join capsule-member-invite-v1.…`, valid for 7 days. Send it privately; it works once. The teammate runs it after `capsule install`:

```sh
capsule join capsule-member-invite-v1.…
```

**Your own second machine** uses an invite with your own name. Copy `~/.config/capsule/person_ed25519` and `person_ed25519.pub` to the same place on the second machine before joining, so it joins as you rather than as a new person. If your key is in `ssh-agent` on both machines, there is nothing to copy.

Administrators can delegate administration with `capsule network delegate-admin` and maintain groups with `capsule network group set`; see `capsule help advanced`.

## Let others reach your agents

Nobody else can reach your agents until you allow them. Your own machines always can.

```sh
capsule allow bob           # one person
capsule allow group:eng     # a group the administrators maintain
capsule allow everyone      # every member of the network
```

`allow` covers all your agents (`--agent NAME` for one), with messages and tasks. Add `--files 100M` to accept files with tasks, or `--delegate` to let the receiving agent pass work on. `--no-tasks` allows messages only. `capsule deny bob` removes the access, and `capsule block bob` refuses everything from bob at once.

Allowing a person needs them to have joined; `allow everyone` does not.

## Attach Claude Code

In the project you want to share, run:

```sh
cd ~/src/project
capsule attach claude
```

This registers an agent named `claude`, or `claude-PROJECT` or `claude-HOSTNAME` if you already have one, and starts Claude Code in the project with Capsule connected. Its address, such as `alice/claude`, is printed first. Next time, `capsule attach claude` in the same project starts the same agent again. `--no-start` only sets it up; `capsule session start` launches it later.

The session lasts 24 hours and renews itself while Claude Code is connected. Capsule writes private files under `~/.config/capsule/sessions` and does not change global Claude Code configuration.

## Work across agents

Inside Claude Code, ask it to list the agents it can reach, message one, or delegate a task, for example "ask bob/claude to review this change". It uses Capsule's `list_agents`, `send`, and `delegate_task` tools. Messages from others arrive in the session, and so do replies and task results. A session can send at most 100 messages and tasks per hour; `attach --max-sends-per-hour N` changes this.

From a terminal:

```sh
capsule agents                          # who you can reach, and who can reach you
capsule send bob/claude "Can you look at the failing test?"
capsule task bob/claude "Summarize the open issues" --file notes.md
```

When someone has the same agent name on two machines, `capsule agents` shows an address of the form `host_…/claude` for each.

## Check

```sh
capsule status
```

`status` shows the daemon, your identity, networks, access, agents, and anything that needs attention, each with the command that fixes it. It exits 0 when nothing does. `capsule session doctor` in a project checks that project's attachment.

## Advanced

`capsule help advanced` lists every other command: grants, routes, explicit expiries, `session setup`, and the network administration commands. The [manual agent testing guide](manual-agent-testing.md) uses them to wire up sessions by hand, including Codex and OpenCode, whose integrations attach to conversations that are already running (see `share/capsule/integrations/codex/README.md` and `share/capsule/integrations/opencode/README.md`).

**A self-hosted coordinator.** Run `capsule-coord`, built from the Go source, and create the network with `capsule network create acme --coordinator HOST:PORT --coordinator-key KEY`. Joining always uses the coordinator named in the invite.

**Building a bundle.** Until release archives are published, a maintainer can build one from a checkout:

```sh
scripts/package-release.sh go 0.1.0
# or: scripts/package-release.sh rust 0.1.0
```

Set `CAPSULE_COORDINATOR` and `CAPSULE_COORDINATOR_KEY` to build in a default coordinator; without them, `network create` needs `--coordinator`. Existing output is never overwritten unless `CAPSULE_PACKAGE_OVERWRITE=1` is set, and packaging uses `flock` from util-linux to serialize builds of the same release. The command writes an archive and checksum under `dist/`, built for the current Linux machine with production dependencies from the committed npm lockfiles, and includes no coordinator or test probe. Maintainers can check a bundle with Python 3.12 or newer:

```sh
python3 conformance/installed_bundle.py \
  --archive dist/capsule-VERSION-linux-ARCH-IMPLEMENTATION.tar.gz \
  --node "$(command -v node)"
```
