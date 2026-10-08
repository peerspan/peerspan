# Capsule local attachment quick start

Capsule connects explicitly opted-in agent sessions across developer-owned
machines. Release bundles in this preview are native Linux builds. macOS has not
yet completed the same validation. The release bundle requires Node.js 22 or
later for agent integrations, but recipients do not need npm, Go, or Rust.

This guide prepares one local attachment. Claude Code must already be installed,
authenticated, and allowed to use development channels by its organization.
Cross-host messaging additionally requires an opted-in peer listener, network
membership or verified peer pins, receiver-owned access, and an owner-configured
outbound destination; local attachment alone creates none of those permissions.

## Install

Extract the archive somewhere that will not move while sessions are attached,
then add its `bin` directory to `PATH`:

```sh
tar -xzf capsule-VERSION-OS-ARCH-IMPLEMENTATION.tar.gz
export CAPSULE_HOME="$PWD/capsule-VERSION-OS-ARCH-IMPLEMENTATION"
export PATH="$CAPSULE_HOME/bin:$PATH"
node --version
```

The archive keeps `bin/capsule-host` and `share/capsule/integrations` together.
`capsule-host` discovers those integrations automatically; do not move only the
binary or move the installation after creating an attachment profile. Verify the
adjacent `.sha256` file before extracting an archive received from someone else.
`RELEASE.json` records the selected implementation, source revision, platform,
and runtime requirement. Go and Rust archives expose the same CLI name and
external behavior; the explicit archive suffix does not select the permanent
OSS implementation.

```sh
(cd /path/to/downloads && sha256sum -c capsule-VERSION-OS-ARCH-IMPLEMENTATION.tar.gz.sha256)
```

## Create the local host

Start the private local daemon in one terminal:

```sh
capsule-host run
```

The default state directory is `$XDG_STATE_HOME/capsule/host` or
`$HOME/.local/state/capsule/host`. In another terminal, inspect the host and
register the durable local agent that sessions will use:

```sh
capsule-host info
capsule-host agent register --name my-agent --owner me --capability conversation
capsule-host agent list
```

Keep the returned agent ID. Registering an agent does not expose it to peers.

## Join an existing network

If an administrator gave you an expiring invite, join with:

```sh
printf 'Invite token: '
read -r invite_token
capsule-host network join --token "$invite_token"
unset invite_token
```

Treat the invite as a bearer secret and avoid storing it in shell history where
possible. Joining provides authenticated discovery; it does not grant another
person access to your agent. Agent owners configure inbound access separately.

## Attach an agent session

Choose a bounded lifetime and a new private setup directory. This example starts
a new, explicitly opted-in Claude Code session:

```sh
capsule-host session setup --harness claude-code \
  --directory "$HOME/.local/state/capsule/sessions/claude-code" \
  --agent AGENT_ID --expires-in 24h
capsule-host session start \
  --directory "$HOME/.local/state/capsule/sessions/claude-code" \
  --workspace /absolute/path/to/project
```

Relative lifetimes use whole minutes or hours from `1m` to `720h`; `--expires-at`
remains available for an explicit future RFC3339 timestamp. Capsule prints the resolved expiration,
creates private profile and credential files, and does not edit global Claude
configuration. Stop the foreground attachment with Ctrl-C.

Codex and OpenCode attach to already-running conversations rather than creating
replacements. Their required conversation selectors are documented in
`share/capsule/integrations/codex/README.md` and
`share/capsule/integrations/opencode/README.md`.

## Check the attachment

Run the read-only diagnostic from another terminal:

```sh
capsule-host session doctor \
  --directory "$HOME/.local/state/capsule/sessions/claude-code"
```

The diagnostic distinguishes local configuration and adapter readiness from
remote acceptance and model execution. A successful diagnostic does not claim
that a remote agent consumed a message. Use an explicit message and correlated
reply to verify the complete round trip.

Without `--expires-in` or `--expires-at`, setup issues a renewable credential:
it lasts 24 hours and the daemon extends it to 24 hours ahead while the adapter
stays connected, recording an `adapter.renewed` activity at most hourly. An
explicit expiry is fixed and never renewed. Either way, an expired credential
stays expired; create a fresh owner-authorized setup when needed. Revoking the
adapter or detaching the session ends it at once. `capsule-host status` shows
each session's expiry. Keep the original attached process running across daemon
restarts so it can recover its bound session.

## Build a shareable bundle

Until release archives are published, a maintainer can build one from a checkout:

```sh
scripts/package-release.sh go 0.1.0
# or: scripts/package-release.sh rust 0.1.0
```

Existing output is never overwritten implicitly. Set
`CAPSULE_PACKAGE_OVERWRITE=1` only when intentionally replacing a local test
bundle with the same version. Packaging uses `flock` from Linux util-linux to
serialize builds of the same release name, including explicit replacements.

The command writes an archive and checksum under `dist/`. It builds for the
current Linux machine, installs production dependencies from the committed npm
lockfiles into fresh staging, and includes no coordinator or test probe. Network
administrators currently build `capsule-coord` separately from the Go source,
regardless of the selected host implementation.

Maintainers can verify relocation and installed integration discovery with
Python 3.12 or newer (or an older release with `tarfile.data_filter` backported).
The check requires safe archive extraction and reports a clear error if the
interpreter lacks it:

```sh
python3 conformance/installed_bundle.py \
  --archive dist/capsule-VERSION-linux-ARCH-IMPLEMENTATION.tar.gz \
  --node "$(command -v node)"
```

Capsule does not yet include a per-user service installer. Run `capsule-host run`
under a service manager only after preserving its private state directory and
normal shutdown behavior.
