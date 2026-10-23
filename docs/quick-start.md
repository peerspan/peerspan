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

## Start your first machine

In the project you want to connect, run:

```sh
cd ~/src/project
peerspan up claude --create acme
```

`up` checks prerequisites, reuses or starts the user service, creates the network,
and attaches Claude Code to this project. It prints your agent address before
starting Claude. Accept Claude's channel dialog; `peerspan status` reports the
actual connection and delivery readiness afterward. Preparation alone does not
mean the agent can receive work.

You join as a person named after your login name (`--as NAME` picks another).
Peerspan reuses its existing `~/.config/peerspan/person_ed25519` key, otherwise
uses the only `ssh-ed25519` key in `ssh-agent`, or generates a key when none is
available. With several agent keys, select one using `--person-key PATH`.
Back up a generated key: it is how your other machines prove they are you. The trust and capability
call prompts default to no. Trusting a machine permits capability calls under
existing policy; a host holding your person private key can also sign a policy
that marks itself trusted.

## Add people and machines

Keep the agent running and open another terminal for network administration.
Invite each teammate by the name they will use:

```sh
peerspan invite bob
```

The output includes a token and an explicit `peerspan join ...` command. The
invite is valid for 7 days and works once for a new host. Send it privately. The
teammate installs Peerspan, changes into their project, then gives that token to
`up`:

```sh
cd ~/src/project
peerspan up claude --join TOKEN
```

**Your own second machine** uses an invite with your own person name. Make the
same person key available on that machine before running `up`: use the same key
in `ssh-agent`, or copy `~/.config/peerspan/person_ed25519` and its `.pub` file to
the same private configuration directory there. Approved machine linking is
still a later milestone.

If a host joins but its person cannot be bound, `up` stops before attaching an
agent and prints the identity repair step. Keep the joined network, make the
original key available, run the suggested `network bind` command, then rerun
`up`. A retry reuses existing membership and does not redeem an invite again.

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

## Return to a project

Run `peerspan up` again in the same project to reuse its network, identity,
agent, and attachment profile. It infers the integration from the profile and
starts the same agent again after a session ends. An existing running session
keeps its attachment. Use `peerspan up claude --no-start` to prepare without
launching; the result gives the command to start it later.

The default agent name includes the machine name, such as `claude-laptop`. A
second project on the same machine gets a project suffix; name conflicts across
your machines get a host-ID suffix. `--name` chooses a name explicitly. The
session lasts 24 hours and renews while connected. Private attachment files live
under `~/.config/peerspan/sessions`; the Claude integration does not change global
Claude Code configuration.

The guided path supports one network per host. With several networks, use the
explicit `network`, `attach`, and `session` commands; `up` lists the memberships
and stops before changing them or the project attachment.

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

`peerspan help advanced` lists every other command: grants, routes, explicit expiries, `session setup`, and the network administration commands. The [manual agent testing guide](manual-agent-testing.md) uses them to wire up sessions by hand, including Codex and OpenCode. `peerspan up codex` and `peerspan up opencode` ask for the existing conversation inputs at a terminal, or accept them with `--option KEY=VALUE`; their integrations attach to conversations that are already running (see `share/peerspan/integrations/codex/README.md` and `share/peerspan/integrations/opencode/README.md`).

**A self-hosted coordinator.** Run `peerspan-coord`, built from the Go source, and start with `peerspan up claude --create acme --coordinator HOST:PORT --coordinator-key KEY`. Joining always uses the coordinator named in the invite.

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
