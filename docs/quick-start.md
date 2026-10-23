# Peerspan quick start

Peerspan lets Claude Code sessions on different machines message each other and hand each other tasks, under access each owner controls. It works for one person with two machines, a pair, and a small team, with the same commands.

Release bundles in this preview are native Linux builds; macOS has not yet completed the same validation. Agent integrations and the archive installer need Node.js 22 or later, but not npm, Go, or Rust. The installer also needs Bash, tar, and `flock`. Private release downloads need GitHub CLI (`gh`) authenticated for the repository. Claude Code must already be installed, logged in, and allowed to use development channels by its organization.

## Install

From a source checkout, put a matching release archive and its `.sha256` file in `dist/` on each machine (maintainer build instructions are below). Then run:

```sh
scripts/install-release.sh VERSION --from dist
```

Rust is the recommended default. Add `--implementation go` to install the supported Go host instead. The installer verifies the checksum and release metadata, stores the bundle under `~/.local/share/peerspan/releases/` by default, links `~/.local/bin/peerspan`, and runs `peerspan install`. It refuses to replace an unrelated command or switch an existing host between Go and Rust in place. Obtain the archive, checksum, and installer from a trusted source; the checksum detects corruption but does not authenticate its publisher.

After a private `peerspan/peerspan-internal` release is published, a collaborator can install without a source checkout. Authenticate once with `gh auth login`, then download and verify the installer from that release:

```sh
version=VERSION
gh release download "v$version" --repo peerspan/peerspan-internal \
  --pattern install-release.sh --pattern install-release.sh.sha256
sha256sum -c install-release.sh.sha256
bash install-release.sh "$version" --from-github peerspan/peerspan-internal
```

The installer fetches only the matching archive and checksum for this machine. Its local `--from` option remains available before the first private release and for offline installs.

If `~/.local/bin` is not already on your `PATH`, add it once for this shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

The service installer writes a systemd user unit, starts it, and enables lingering, so the daemon keeps running while you are logged out. Run the archive installer again for a new release. `peerspan uninstall` removes the service and keeps the state. The [release procedure](releasing.md) describes review and publication of private bundles; macOS installer validation remains pending.

## Create a network

The first person creates the network on the hosted coordinator:

```sh
peerspan network create acme
```

You join as a person named after your login name (`--as NAME` picks another). If `ssh-agent` holds exactly one `ssh-ed25519` key, that key is your identity. Otherwise Peerspan generates one at `~/.config/peerspan/person_ed25519`. Back it up: it is how your other machines prove they are you.

## Add people and machines

Invite each teammate by the name they will use:

```sh
peerspan invite bob
```

This prints a line such as `peerspan join peerspan-member-invite-v1.…`, valid for 7 days. Send it privately; it works once. The teammate runs it after `peerspan install`:

```sh
peerspan join peerspan-member-invite-v1.…
```

**Your own second machine** uses an invite with your own name. Copy `~/.config/peerspan/person_ed25519` and `person_ed25519.pub` to the same place on the second machine before joining, so it joins as you rather than as a new person. If your key is in `ssh-agent` on both machines, there is nothing to copy.

Administrators can delegate administration with `peerspan network delegate-admin` and maintain groups with `peerspan network group set`; see `peerspan help advanced`.

## Let others reach your agents

Nobody else can reach your agents until you allow them. Your own machines always can.

```sh
peerspan allow bob           # one person
peerspan allow group:eng     # a group the administrators maintain
peerspan allow everyone      # every member of the network
```

`allow` covers all your agents (`--agent NAME` for one), with messages and tasks. Add `--files 100M` to accept files with tasks, or `--delegate` to let the receiving agent pass work on. `--no-tasks` allows messages only. `peerspan deny bob` removes the access, and `peerspan block bob` refuses everything from bob at once.

Allowing a person needs them to have joined; `allow everyone` does not.

## Attach Claude Code

In the project you want to share, run:

```sh
cd ~/src/project
peerspan attach claude
```

This registers an agent named after the machine, such as `claude-laptop`, and starts Claude Code in the project with Peerspan connected. A second project on the same machine gets `claude-laptop-PROJECT`, and a second machine with the same host name gets a short host ID suffix, such as `claude-laptop-5c12`. Its address, such as `alice/claude-laptop`, is printed first. `--name` picks a name yourself. Next time, `peerspan attach claude` in the same project starts the same agent again. `--no-start` only sets it up; `peerspan session start` launches it later.

The session lasts 24 hours and renews itself while Claude Code is connected. Peerspan writes private files under `~/.config/peerspan/sessions` and does not change global Claude Code configuration.

## Work across agents

Inside Claude Code, ask it to list the agents it can reach, message one, or delegate a task, for example "ask bob/claude-laptop to review this change". It uses Peerspan's `list_agents`, `send`, and `delegate_task` tools. Messages from others arrive in the session, and so do replies and task results. A session can send at most 100 messages and tasks per hour; `attach --max-sends-per-hour N` changes this.

From a terminal:

```sh
peerspan agents                          # who you can reach, and who can reach you
peerspan send bob/claude-laptop "Can you look at the failing test?"
peerspan task bob/claude-laptop "Summarize the open issues" --file notes.md
```

When someone has the same agent name on two machines, `peerspan agents` shows an address of the form `host_…/NAME` for each.

## Check

```sh
peerspan status
```

`status` shows the daemon, your identity, networks, access, agents, and anything that needs attention, each with the command that fixes it. It exits 0 when nothing does. `peerspan session doctor` in a project checks that project's attachment.

## Advanced

`peerspan help advanced` lists every other command: grants, routes, explicit expiries, `session setup`, and the network administration commands. The [manual agent testing guide](manual-agent-testing.md) uses them to wire up sessions by hand, including Codex and OpenCode, whose integrations attach to conversations that are already running (see `share/peerspan/integrations/codex/README.md` and `share/peerspan/integrations/opencode/README.md`).

**A self-hosted coordinator.** Run `peerspan-coord`, built from the Go source, and create the network with `peerspan network create acme --coordinator HOST:PORT --coordinator-key KEY`. Joining always uses the coordinator named in the invite.

**Building a bundle.** Until release archives are published, a maintainer can build one from a checkout:

```sh
scripts/package-release.sh rust 0.1.0
# supported alternative: scripts/package-release.sh go 0.1.0
```

Set `PEERSPAN_COORDINATOR` and `PEERSPAN_COORDINATOR_KEY` to build in a default coordinator; without them, `network create` needs `--coordinator`. Existing output is never overwritten unless `PEERSPAN_PACKAGE_OVERWRITE=1` is set, and packaging uses `flock` from util-linux to serialize builds of the same release. The command writes an archive and checksum under `dist/`, built for the current Linux machine with production dependencies from the committed npm lockfiles, and includes no coordinator or test probe. Maintainers can check a bundle with Python 3.12 or newer:

```sh
python3 conformance/installed_bundle.py \
  --archive dist/peerspan-VERSION-linux-ARCH-IMPLEMENTATION.tar.gz \
  --node "$(command -v node)"
```
