# Manual agent testing

Start with two conversations on one machine. This walkthrough uses Codex for A
and OpenCode for B. Two Capsule daemons give the test separate host identities,
so you can exercise peer messaging over loopback. A daemon can normally register
multiple agents; one daemon per agent is not a deployment requirement.

## Terminal layout

Use eight terminal tabs, SSH sessions, or tmux panes **on the same machine**. If
using `192.0.2.10`, every tab connects to that box. Existing Codex and OpenCode
conversation tabs can serve as Tabs 7 and 8.

| Tab | Name | What runs here |
| --- | --- | --- |
| 1 | Coordinator | Foreground coordination service |
| 2 | Host A | Foreground Capsule daemon A, UDP port 7401 |
| 3 | Host B | Foreground Capsule daemon B, UDP port 7402 |
| 4 | Setup | Build, configuration, and diagnostic commands |
| 5 | Attachment A | Foreground Capsule sidecar for conversation A |
| 6 | Attachment B | Foreground Capsule sidecar for conversation B |
| 7 | Codex conversation A | Native Codex CLI; prompts and `/status` run here |
| 8 | OpenCode conversation B | Native OpenCode TUI; prompts run here |

**Every configuration command runs in Tab 4.** Its variables belong to that tab
only. Tabs 1–3 and 5–6 use explicit paths and need no variable setup. Their
foreground commands keep running without returning a shell prompt; leave them
open and return to Tab 4 for the next step.

## Tab 4 prepare the checkout

Use Go 1.26+, Node 22+, Python 3, Codex 0.160.0+ and OpenCode 1.18.31+.
These commands place the checkout at `~/capsule-test`. If yours is elsewhere,
replace that path in the guide. Skip cloning if this checkout already exists.

```sh
git clone git@github.com:Cerebral-Systems/capsule-v0.git ~/capsule-test
cd ~/capsule-test
mkdir -p bin
go -C go build -o "$PWD/bin/capsule-host" ./cmd/capsule-host
go -C go build -o "$PWD/bin/capsule-coord" ./cmd/capsule-coord
npm ci --ignore-scripts --prefix integrations/codex
npm ci --ignore-scripts --prefix integrations/opencode
```

Define these path variables **once, in Tab 4**. A and B have separate state,
attachment profiles, and destination files:

```sh
CAPSULE="$HOME/capsule-test"
HOST="$CAPSULE/bin/capsule-host"
LAB_ROOT="$HOME/.local/state/capsule-manual"
A_STATE="$LAB_ROOT/a/host"
B_STATE="$LAB_ROOT/b/host"
A_PROFILE="$LAB_ROOT/a/profile"
B_PROFILE="$LAB_ROOT/b/profile"
BINDINGS="$LAB_ROOT/opencode-bindings"
```

The authorization commands below refresh `$EXPIRES` just before use. Each deadline
is two hours from that command, so a pause during setup does not leave the next
command using an old timestamp.

On Apple Silicon, the Go host and coordinator compile; macOS runtime validation
is still needed. Start with Go on the Mac and either daemon on Linux.

## Tabs 1 to 3 start the services

**Tab 1 — Coordinator:**

```sh
~/capsule-test/bin/capsule-coord --state ~/.local/state/capsule-manual/coord \
  run --listen 127.0.0.1:7400
```

**Tab 2 — Host A:**

```sh
~/capsule-test/bin/capsule-host --state ~/.local/state/capsule-manual/a/host \
  run --peer-listen 127.0.0.1:7401
```

**Tab 3 — Host B:**

```sh
~/capsule-test/bin/capsule-host --state ~/.local/state/capsule-manual/b/host \
  run --peer-listen 127.0.0.1:7402
```

Both daemons create their own private state directories and identities. Return
to **Tab 4** for every command below, until the attachment tabs are named.

## Tab 4 create and join a network

Replace uppercase placeholders such as `NETWORK_ID` with values returned by the
preceding commands. `$A_STATE` and `$B_STATE` select the daemon being configured;
you do not switch shells or redefine a shared `LAB` variable.

Read the coordinator's `public_key`, then create the network through A:

```sh
EXPIRES=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())')
"$CAPSULE/bin/capsule-coord" --state "$LAB_ROOT/coord" info
"$HOST" --state "$A_STATE" network create --name manual-test --member alice \
  --coordinator 127.0.0.1:7400 --coordinator-key COORD_PUBLIC_KEY --no-person
"$HOST" --state "$A_STATE" network invite --network NETWORK_ID --member bob \
  --host-only --expires-at "$EXPIRES"
```

Join through B with the returned token, then sync both hosts:

```sh
"$HOST" --state "$B_STATE" network join --token JOIN_TOKEN --no-person
"$HOST" --state "$A_STATE" network sync NETWORK_ID
"$HOST" --state "$B_STATE" network sync NETWORK_ID
"$HOST" --state "$A_STATE" network members NETWORK_ID
"$HOST" --state "$B_STATE" network members NETWORK_ID
```

Both member lists should contain A and B. `--no-person` keeps this first test
focused on connectivity. Invite tokens are bearer secrets; keep them out of
repository files. SSH-backed membership and owner policies have their own
[workflow](../README.md#try-signed-enrollment).

## Tab 4 grant access in both directions

Read the two host IDs and register one agent per host:

```sh
"$HOST" --state "$A_STATE" info
"$HOST" --state "$B_STATE" info
"$HOST" --state "$A_STATE" agent register --name alice --owner me
"$HOST" --state "$B_STATE" agent register --name bob --owner me
```

A grants B access to A's agent; B grants A access to B's agent. Record the returned
grant IDs as `A_GRANT_ID` and `B_GRANT_ID`, respectively:

```sh
EXPIRES=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())')
"$HOST" --state "$A_STATE" grant create --peer B_HOST_ID --agent A_AGENT_ID \
  --expires-at "$EXPIRES" --allow-disconnected
"$HOST" --state "$B_STATE" grant create --peer A_HOST_ID --agent B_AGENT_ID \
  --expires-at "$EXPIRES" --allow-disconnected
```

These expiring grants explicitly allow communication during a coordinator outage.
Refreshing `$EXPIRES` does not extend grants already created. If they expire during
your walkthrough, create new grants with a fresh deadline and use their new IDs
in the destination files below.
Create A's destinations using **B's** host, agent, and grant IDs, then B's using
**A's** IDs. Replace the placeholders before running:

```sh
cat > "$LAB_ROOT/a/destinations.json" <<'JSON'
[{"name":"remote","peer_host_id":"B_HOST_ID","target_agent_id":"B_AGENT_ID","grant_id":"B_GRANT_ID","max_messages":6}]
JSON
cat > "$LAB_ROOT/b/destinations.json" <<'JSON'
[{"name":"remote","peer_host_id":"A_HOST_ID","target_agent_id":"A_AGENT_ID","grant_id":"A_GRANT_ID","max_messages":6}]
JSON
```

For person/group policies, follow the owner policy workflow instead of issuing
per-peer grants. Policy-authorized destinations omit `grant_id`.

## Tab 4 prepare the attachments

Before starting sidecars, give each native conversation a different phrase to
remember. Keep both conversations running in Tabs 7 and 8; Capsule attaches to
those existing conversations.

Replace `A_AGENT_ID` and `B_AGENT_ID` with the IDs returned by `agent register`,
rather than the agent names. If setup reports "use a registered agent ID and a
future RFC3339 expiry", check the agent ID and rerun the `$EXPIRES` assignment
immediately before the setup command.

### Codex on A

In **Tab 7**, use the Codex CLI conversation you want to attach. If you need a
new test conversation, start it in your project:

```sh
cd /path/to/your/test-project
codex
```

Send your phrase to remember, then enter `/status` **inside Codex**. Copy the UUID
on the **Session** line; this is the value for `EXISTING_THREAD_UUID` below. If
the Session line is absent, send a short message first and run `/status` again.

Return to **Tab 4** and run `codex app-server daemon version`. Its `socketPath`
supplies `EXISTING_SOCKET`; this command does not list conversation IDs. Substitute
both values in the setup command:

```sh
codex app-server daemon version
EXPIRES=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())')
"$HOST" --state "$A_STATE" session setup --harness codex \
  --integrations "$CAPSULE/integrations" --runner "$(command -v node)" \
  --option executable="$(command -v codex)" --option socket=EXISTING_SOCKET \
  --option thread=EXISTING_THREAD_UUID --directory "$A_PROFILE" \
  --agent A_AGENT_ID --expires-at "$EXPIRES" --routes "$LAB_ROOT/a/destinations.json"
```

Use a shared-daemon CLI conversation first. Desktop attachment requires an exposed
socket from the backend serving that conversation; embedded backends are currently
unsupported. See the [Codex attachment guide](../integrations/codex/README.md).

### OpenCode on B

If OpenCode has no provider login, sign in through its built-in OpenAI provider.
Use this on the headless Linux box; choose browser login on a Mac:

```sh
opencode auth login --provider openai --method 'ChatGPT Pro/Plus (headless)'
```

OpenCode supports [ChatGPT subscription login](https://opencode.ai/docs/providers/#openai).
Claude subscriptions work through native Claude Code; Anthropic access through
OpenCode needs separate API access. See [Anthropic credential guidance](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use).

Install the Capsule plugin once by editing OpenCode's configuration file. In
**Tab 4**, open the global config (or edit the project/custom config you already
use). OpenCode accepts both `opencode.json` and `opencode.jsonc` (JSON with
comments). Edit your existing file; the command below opens `opencode.jsonc` if
present, otherwise `opencode.json`:

```sh
mkdir -p ~/.config/opencode
if [ -f ~/.config/opencode/opencode.jsonc ]; then
  nano ~/.config/opencode/opencode.jsonc
else
  nano ~/.config/opencode/opencode.json
fi
```

Use your preferred text editor if Nano is unavailable. The block below is **file
contents**, not a shell command. For a new file, paste the whole block. In an
existing file, add the Capsule entry to its `plugin` array, preserving other
plugins, settings, and comments; add the array if it is absent.

`ABSOLUTE_CAPSULE` means the repository checkout path (`$CAPSULE` in Tab 4).
`ABSOLUTE_LAB_ROOT` means the test state path (`$LAB_ROOT`). You can print both in
Tab 4 with `printf '%s\n' "$CAPSULE" "$LAB_ROOT"`. Substitute their full paths in
the JSON; shell variables and `~` are not expanded there.

```json
{
  "plugin": [
    ["file:///ABSOLUTE_CAPSULE/integrations/opencode/plugin.mjs", {
      "bindings": "ABSOLUTE_LAB_ROOT/opencode-bindings"
    }]
  ]
}
```

In Nano, save with **Ctrl+O**, Enter, then exit with **Ctrl+X**. See OpenCode's
[configuration locations](https://opencode.ai/docs/config/#locations) if you use a
different config file.

Load the configuration through OpenCode while idle. If starting a new native TUI,
use **Tab 8** and start it in your test project:

```sh
cd /path/to/your/test-project
opencode --hostname 127.0.0.1 --port 4096
```

Choose a model with `/models` and send a baseline prompt before attaching. Return
to **Tab 4**, set `OPENCODE_PROJECT` to the full directory path used in Tab 8, and
list its sessions:

```sh
OPENCODE_PROJECT=/absolute/path/to/your/test-project
(cd "$OPENCODE_PROJECT" && opencode session list --format json --max-count 10)
```

Session listing is scoped to the current project. An empty result from the
Capsule checkout does not mean the conversation is missing. For example, if
OpenCode started in `/root`, use `OPENCODE_PROJECT=/root`. The subshell above
preserves Tab 4's working directory. Match the conversation title and copy its
`id` (starting with `ses_`) into `EXISTING_SESSION_ID` below:

```sh
EXPIRES=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())')
"$HOST" --state "$B_STATE" session setup --harness opencode \
  --integrations "$CAPSULE/integrations" --runner "$(command -v node)" \
  --option server=http://127.0.0.1:4096 --option session=EXISTING_SESSION_ID \
  --option directory="$OPENCODE_PROJECT" --option bindings="$BINDINGS" \
  --directory "$B_PROFILE" --agent B_AGENT_ID \
  --expires-at "$EXPIRES" --routes "$LAB_ROOT/b/destinations.json"
```

`OPENCODE_PROJECT` is the workspace of that OpenCode conversation. See the
[OpenCode attachment guide](../integrations/opencode/README.md) for HTTP
authentication and stale binding recovery.

To use two conversations from the same harness, repeat its setup command for the
other host with that host's state, agent, profile, and destinations file. Select a
different conversation ID. Two OpenCode conversations on the same server use the
same configured `$BINDINGS` directory; each receives its own session binding.

## Tabs 5 and 6 start the sidecars

**Tab 5 — Attachment A:**

```sh
~/capsule-test/bin/capsule-host session start \
  --directory ~/.local/state/capsule-manual/a/profile
```

**Tab 6 — Attachment B:**

```sh
~/capsule-test/bin/capsule-host session start \
  --directory ~/.local/state/capsule-manual/b/profile
```

Leave both tabs running. `session start` starts a Capsule sidecar. It uses the
profile prepared in Tab 4 and does not require Tab 4's variables in its shell.

## Check the behavior

1. In A's native conversation, ask it to list Capsule destinations, send to
   `remote` requesting B's remembered phrase, and check the returned request ID
   with the Capsule send status tool.
2. B must call the Capsule reply tool. Confirm A's model reports B's exact phrase,
   then repeat in the other direction.
3. Try an unrelated conversation and exceed a destination budget. Both must be
   denied. Native tool approvals must still behave as configured.
4. Restart a daemon in Tab 2 or 3 while keeping both sidecars and native
   conversations alive. Verify recovery. Stop the coordinator in Tab 1 and verify
   already-established direct peers still communicate.
5. In Tab 4, revoke a grant on its issuing host with `grant revoke GRANT_ID`.
   New sends must fail. Stop a sidecar with Ctrl-C; its native conversation remains.

Run diagnostics in **Tab 4**, explicitly selecting the profile or host:

```sh
"$HOST" session doctor --directory "$A_PROFILE"
"$HOST" session doctor --directory "$B_PROFILE"
"$HOST" --state "$A_STATE" activity
"$HOST" --state "$B_STATE" activity
```

A ready adapter or persisted input does not prove model consumption. The phrase
exchange checks that separately. Keep test state separate from your usual state.

## Move the test onto separate machines

Run A's commands on A's machine and B's commands on B's machine. Build the checkout
on each; use a setup tab on each for its local configuration. Carry public IDs
and the invite token between them explicitly.

Bind the coordinator on a server with `--listen 0.0.0.0:7400`, and replace the
loopback coordinator address with that server's reachable IP. TCP 7400 must be
reachable. For a publicly reachable peer, change its daemon command to
`--peer-listen 0.0.0.0:7401 --advertise REAL_SERVER_IP:7401`; different machines can
use the same port. Public UDP 7401 allows direct traffic.

For a Mac behind NAT, use `--peer-listen 0.0.0.0:7401` without inventing a public
address. Signed enrollment supplies discovery and relay access. Relay-dependent
peers need a working relay during coordinator outage. The native OpenCode server
and Capsule's private admin socket remain local to their machine.
