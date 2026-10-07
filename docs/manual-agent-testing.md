# Manual agent testing

Connect existing conversations, send messages in both directions, and check that
history and permissions survive attachment. Start with two sessions on one
machine, then repeat between the Linux servers and between your Mac and a server.
Codex and OpenCode can use the same network, including mixed harness pairs.

## Prepare the Mac

Use Go 1.26+, Node 22+, Python 3, Codex 0.160.0+ and OpenCode 1.18.31+.
The Go host and coordinator compile for Apple Silicon; macOS runtime validation
is still needed. Start with Go on the Mac and either daemon on Linux.

Clone main into a separate test checkout:

```sh
git clone https://github.com/Cerebral-Systems/capsule-v0.git capsule-test
cd capsule-test
mkdir -p bin
go -C go build -o "$PWD/bin/capsule-host" ./cmd/capsule-host
go -C go build -o "$PWD/bin/capsule-coord" ./cmd/capsule-coord
npm ci --ignore-scripts --prefix integrations/codex
npm ci --ignore-scripts --prefix integrations/opencode
```

For OpenCode, sign in separately through its built-in OpenAI provider:

```sh
opencode auth login --provider openai
```

Choose ChatGPT browser login on the Mac. On a headless server, use:

```sh
opencode auth login --provider openai --method 'ChatGPT Pro/Plus (headless)'
```

OpenCode supports [ChatGPT subscription login](https://opencode.ai/docs/providers/#openai).
Claude subscriptions work through native Claude Code; they do not provide
Anthropic API access for OpenCode. See [Anthropic credential guidance](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use).

## Start the test hosts

Choose two participants, A and B. These can be two state directories on your Mac,
the two Linux servers, or your Mac and one server. Each terminal needs its own
absolute `HOST`, `CAPSULE` and `LAB` paths:

```sh
CAPSULE="$PWD"
HOST="$CAPSULE/bin/capsule-host"
LAB="$HOME/.local/state/capsule-manual-a"
EXPIRES=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=2)).isoformat())')
```

For B on the same machine, use `capsule-manual-b` and port 7402. On different
machines each host can use port 7401. Run each daemon in a separate terminal:

```sh
"$HOST" --state "$LAB/host" run --peer-listen 127.0.0.1:7401
```

For a server reachable over the public network, bind UDP and advertise its actual
address, for example:

```sh
"$HOST" --state "$LAB/host" run --peer-listen 0.0.0.0:7401 --advertise 192.0.2.10:7401
```

For a Mac behind NAT, use `--peer-listen 0.0.0.0:7401` without inventing a public
address. Signed enrollment supplies discovery and relay access. Only the private
admin socket administers a host.

## Create and join a network

Run one coordinator in another terminal. For local testing, bind `127.0.0.1:7400`.
For multiple machines, run it on a server with `--listen 0.0.0.0:7400` and use that
server's reachable IP as `COORD_ADDRESS`. TCP 7400 must be reachable; public UDP
7401 allows direct peer traffic. Peers can otherwise use the relay.

```sh
"$CAPSULE/bin/capsule-coord" --state "$LAB/coord" run --listen 127.0.0.1:7400
```

Read the coordinator's `public_key`, then run on A:

```sh
"$CAPSULE/bin/capsule-coord" --state "$LAB/coord" info
"$HOST" --state "$LAB/host" network create --name manual-test --member alice \
  --coordinator COORD_ADDRESS --coordinator-key COORD_PUBLIC_KEY --no-person
"$HOST" --state "$LAB/host" network invite --network NETWORK_ID --member bob \
  --host-only --expires-at "$EXPIRES"
```

Run on B using the returned token, then repeat with a new invite for the third
machine when needed:

```sh
"$HOST" --state "$LAB/host" network join --token JOIN_TOKEN --no-person
```

On each participant, sync and confirm that both hosts appear before creating grants:

```sh
"$HOST" --state "$LAB/host" network sync NETWORK_ID
"$HOST" --state "$LAB/host" network members NETWORK_ID
```

`--no-person` keeps this first test focused on host connectivity. SSH-backed person
membership and administrator delegation have their own workflows. Invite tokens
are bearer secrets; keep them out of repository files.

## Grant access in both directions

On each participant, read its host ID, register an agent, and grant the other host
access to that agent. These examples use expiring per-peer grants, including
explicit permission to continue during a coordinator outage. Substitute the IDs
returned by each command:

```sh
"$HOST" --state "$LAB/host" info
"$HOST" --state "$LAB/host" agent register --name my-agent --owner me
"$HOST" --state "$LAB/host" grant create --peer OTHER_HOST_ID \
  --agent MY_AGENT_ID --expires-at "$EXPIRES" --allow-disconnected
```

Create `destinations.json` inside your private lab directory on each machine. Its
IDs identify the **other** host, the other agent, and the grant issued by that host:

```json
[{"name":"remote","peer_host_id":"OTHER_HOST_ID","target_agent_id":"OTHER_AGENT_ID","grant_id":"OTHER_GRANT_ID","max_messages":6}]
```

For access by person or group, use the [owner policy workflow](../README.md#try-signed-enrollment)
with SSH-backed membership. Policy-authorized destinations omit `grant_id`.

## Attach Codex

Keep the native Codex conversation open. Run `codex app-server daemon version` and
use the returned `socketPath`, plus that conversation's existing thread UUID:

```sh
"$HOST" --state "$LAB/host" session setup --harness codex \
  --integrations "$CAPSULE/integrations" --runner "$(command -v node)" \
  --option executable="$(command -v codex)" --option socket=EXISTING_SOCKET \
  --option thread=EXISTING_THREAD_UUID --directory "$LAB/codex-profile" \
  --agent MY_AGENT_ID --expires-at "$EXPIRES" --routes "$LAB/destinations.json"
"$HOST" session start --directory "$LAB/codex-profile"
```

Use a shared-daemon CLI conversation first. Desktop attachment needs the backend
serving that conversation to expose a socket; embedded backends are currently
unsupported. See the [Codex attachment guide](../integrations/codex/README.md).

## Attach OpenCode

Install the plugin once in the OpenCode configuration you use, preserving existing
entries. Substitute absolute paths:

```json
{"plugin":[["file:///ABSOLUTE_CAPSULE/integrations/opencode/plugin.mjs",{"bindings":"ABSOLUTE_LAB/opencode-bindings"}]]}
```

Load that configuration through OpenCode while idle. For a new native TUI test,
`opencode --hostname 127.0.0.1 --port 4096` gives it a known local server address.
Choose an OpenAI model with `/models` and send a baseline prompt. Select that
conversation's ID with `opencode session list`. Capsule attaches to the same
server and conversation:

```sh
"$HOST" --state "$LAB/host" session setup --harness opencode \
  --integrations "$CAPSULE/integrations" --runner "$(command -v node)" \
  --option server=http://127.0.0.1:4096 --option session=EXISTING_SESSION_ID \
  --option directory=ABSOLUTE_PROJECT --option bindings="$LAB/opencode-bindings" \
  --directory "$LAB/opencode-profile" --agent MY_AGENT_ID \
  --expires-at "$EXPIRES" --routes "$LAB/destinations.json"
"$HOST" session start --directory "$LAB/opencode-profile"
```

Keep each sidecar in its own terminal. `session start` starts Capsule's sidecar;
the native harness stays running. See the [OpenCode attachment guide](../integrations/opencode/README.md)
for HTTP authentication and stale binding recovery.

## Check the behavior

1. Before attaching, give each conversation a different phrase to remember.
2. Ask A to list its Capsule destinations, send to `remote` requesting B's phrase,
   and check the returned request ID with the Capsule send status tool.
3. B must call the Capsule reply tool. Confirm A's model reports B's exact phrase.
   Repeat in the other direction, then with a Codex/OpenCode pair.
4. Try an unrelated conversation and exceed a destination budget. Both must be
   denied. Native tool approvals must still behave as configured.
5. Restart a Capsule daemon while keeping its sidecar and native conversation
   alive. Verify recovery. Stop the coordinator and verify already-established
   **direct** peers still communicate; relay-dependent peers need a working relay.
6. Revoke a grant with `grant revoke GRANT_ID` on its issuing host. New sends must
   fail. Stop the sidecar with Ctrl-C and verify the native conversation remains.

Use `session doctor --directory PROFILE` and `activity` for diagnostics. A ready
adapter or persisted input does not prove model consumption; the phrase exchange
checks that separately. Keep test state separate from your usual Capsule state.
