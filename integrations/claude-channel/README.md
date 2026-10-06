# Claude Code channel

One Node.js adapter connects an opted-in Claude Code session to either the Go or Rust host daemon. It uses the official MCP SDK over stdio and calls only the credential-scoped `adapter.sock` interface.

## Configure one session

Install Node.js 22 or later, then install the adapter dependencies:

```bash
cd integrations/claude-channel
npm ci --ignore-scripts
```

With your daemon running, register an agent and attach a session using the existing CLI. Create a private credential file for that session; use an absolute path and a future RFC3339 expiration:

```bash
capsule-host --state STATE session attach --agent AGENT_ID --integration claude-channel
umask 077
capsule-host --state STATE adapter create --session SESSION_ID --expires-at FUTURE_TIME > /absolute/credential.json
```

Configure an MCP server named `capsule` in your Claude Code project. Replace the paths with your actual Node executable, adapter, daemon state, and credential file:

```json
{
  "mcpServers": {
    "capsule": {
      "command": "/absolute/path/to/node",
      "args": [
        "/absolute/path/to/integrations/claude-channel/channel.mjs",
        "--socket", "/absolute/STATE/adapter.sock",
        "--credential-file", "/absolute/credential.json"
      ]
    }
  }
}
```

Start the interactive session with the development opt-in for this locally built channel:

```bash
claude --dangerously-load-development-channels server:capsule
```

Claude Code presents its development-channel confirmation. This is a [research preview](https://code.claude.com/docs/en/channels-reference#test-during-the-research-preview), subject to authentication and organization policy. Configure a credential for each intended session; do not reuse it to silently substitute another process. Plain MCP registration alone does not enable incoming channel messages.

Use your Claude executable's full path if it is not on your shell PATH.

## Allow the agent to initiate messages

After configuring the peer or enrolling both hosts in a network, the receiving owner grants access to its target agent. The sending owner then creates a named destination for this session's adapter credential:

```bash
capsule-host --state RECEIVER_STATE grant create --peer SENDER_HOST_ID --agent TARGET_AGENT_ID --expires-at GRANT_EXPIRY --allow-disconnected
capsule-host --state SENDER_STATE adapter route add --adapter ADAPTER_ID --name bob --peer RECEIVER_HOST_ID --agent TARGET_AGENT_ID --grant GRANT_ID --expires-at ROUTE_EXPIRY --max-message-bytes 4096 --max-messages 20
capsule-host --state SENDER_STATE adapter route list --adapter ADAPTER_ID
```

Use `--allow-disconnected` for manually configured peers or when explicitly permitting work during a coordination outage. A recently synced enrolled peer can use a grant without it. Choose `ROUTE_EXPIRY` no later than the credential and grant expirations, and a byte bound within the receiver's grant. Configure each direction independently if both agents should initiate messages.

Ask the opted-in agent to list its Capsule destinations and send a message to `bob`. Its `list_destinations` and `send` tools expose only the owner's named routes. The daemon persists the request before sending; replies return to the same session automatically as `kind: "reply"` events carrying the original request ID. These response events have no delivery ID for the final-reply tool. A follow-up uses another authorized `send`.

For incoming `kind: "message"` events, the `reply` tool stores one final response addressed to the original sender. The owner CLI can also send a message and inspect its reply:

```bash
capsule-host --state SENDER_STATE message reply --peer RECEIVER_HOST_ID REQUEST_ID
capsule-host --state RECEIVER_STATE delivery list
```

`adapter revoke ADAPTER_ID`, owner session detachment, or credential expiry stop adapter access. Grants are checked again at handoff and reply. An uncertain handoff is retained for inspection and is never automatically sent again or moved to another session. `forwarded` confirms a notification write, not model execution. See the [adapter contract](../../docs/agent-adapter-contract.md).

`adapter route revoke ROUTE_ID` stops further sends through that route. Replies to earlier sends can still return while the original credential is valid. An uncertain send reports its request ID, and the daemon retries it automatically with that same ID until it is accepted, rejected, or past its deadline. The agent follows it with `send_status`. Only a send the host never recorded (`send_status` reports `not_recorded`) needs an explicit retry, with the same ID and identical destination/content. Each new persisted request uses one lifetime budget unit, including failed or rejected attempts; automatic and explicit retries of the same request use none. See the [outbound contract](../../docs/adapter-outbound-contract.md).

The adapter exposes `list_destinations`, `send`, `send_status`, and `reply`, and omits permission-relay capability. Message access does not give a peer shell or filesystem access through Capsule; the existing agent still has whatever local permissions its owner granted it.

## Connection recovery and token rotation

The adapter binds a random process-instance secret kept in memory and renews a 15-second lease every five seconds. Inspect connectivity with `adapter connection ADAPTER_ID`: `registered` means no adapter has connected; `ready` means its lease is valid; `offline` means a bound adapter needs to reconnect. Detachment, revocation, and expiration are reported separately. These describe the adapter connection, not whether the model is busy or has executed a message.

Restarting the daemon invalidates leases. Previously bound, recoverable adapters get 15 seconds to reconnect before `adapter create` can replace them. This window does not grant a live lease. The same running adapter reconnects with its instance secret and recovers its original attachment, requests, and replies. Replacing the adapter subprocess requires an explicitly authorized fresh attachment; an existing credential file alone cannot take over its instance. Owner detachment also stops recovery when the daemon has already marked that session detached.

If the old adapter has exited, attach a fresh session and issue its credential using the setup commands above. Once the old lease has expired (at most 15 seconds after its last renewal) and any startup reconnect window has ended, `adapter create` retires the old authorization atomically and reports `replaced_adapter_ids`. It does not require a separate `session detach`. To replace it immediately during the window, explicitly detach its old session or revoke its credential first. The old adapter loses reconnect access; its pending work and outbound routes remain with its original session. Configure destinations for the new session explicitly. A still-valid lease or an authorization that has never connected remains protected; the conflict explains how to proceed.

Owners can rotate the token while keeping the original authorization ID, expiry, instance, routes, and budgets. Replace the private credential file atomically:

```bash
capsule_credential_next=$(mktemp /absolute/.capsule-credential.XXXXXX)
capsule-host --state STATE adapter rotate ADAPTER_ID > "$capsule_credential_next" &&
  mv "$capsule_credential_next" /absolute/credential.json
```

The running adapter reloads only the same authorization and session. The old token immediately loses access; the adapter allows up to 30 seconds for its replacement file. Rotation does not extend authorization lifetime. Inspect an agent-originated request with `message origin --peer HOST REQUEST_ID`, including an uncertain reply-notification handoff. See the [recovery contract](../../docs/adapter-recovery-contract.md).

## Verify

From the repository root:

```bash
npm --prefix integrations/claude-channel test
python3 conformance/agent_adapter.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
python3 conformance/adapter_outbound.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --coord COORD_BINARY
python3 conformance/adapter_recovery.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
```

The Python suite uses a deterministic MCP client and temporary host state. The separate `conformance/live_claude_channel.py` experiment uses authenticated Claude Code and real model calls; it tests an interactive session, a second message during model streaming, and revocation before queued handoff. Its PTY driver requires Linux:

```bash
python3 conformance/live_claude_channel.py --sender GO_BINARY --receiver RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --output /tmp/capsule-live.json
python3 conformance/live_agent_exchange.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --output /tmp/capsule-exchange-live.json
python3 conformance/live_agent_exchange.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --restart-pending --output /tmp/capsule-recovery-live.json
```

The second experiment uses two interactive Claude sessions to initiate messages in both directions and confirm automatic replies in their model output, without owner CLI send/fetch commands. Both experiments create temporary host and MCP configuration. Claude records each test workspace's trust/session information through its normal account state. Existing sessions and MCP configurations are not selected or reconfigured. Noninteractive stream-json mode connected to MCP but did not consume channel events in the tested installation; use the interactive path for this slice. Recorded results are in the [ingress report](../../docs/results/claude-channel-live.json) and [two-agent exchange report](../../docs/results/agent-exchange-live.json).

`--restart-pending` additionally restarts each originating daemon with the other implementation and rotates its token while waiting for a reply. The [recovery report](../../docs/results/agent-recovery-live.json) records the same two Claude processes completing those exchanges without duplicate sends or replacement sessions.

## Acceptance on two machines

[`live_cross_host_agents.py`](../../conformance/live_cross_host_agents.py) runs the experiment through two SSH accounts. Each machine needs this checkout, Python 3, the built host binaries, Node 22+, and the channel's installed npm dependencies. Alice also needs `capsule-coord`. For a model run, each account needs an authenticated Claude Code installation with channels available. The runner creates isolated test state and two opted-in sessions; it enables only Capsule tools. Existing daemons, workspaces, and grants are not used. Claude records these test sessions in its normal account history.

Configure SSH aliases with normal host-key verification. Each advertised peer port must be reachable over UDP for the coordinator-outage phases; Alice's coordinator port must be reachable over TCP. The daemons can use the coordinator's relay while it is running, but stopping that coordinator also stops its relay. SSH controls the workers; peer payloads use end-to-end QUIC. Build both hosts from the same protocol revision: the earlier TCP peer transport cannot communicate with QUIC peers. Save a configuration like this outside the repository, replacing the addresses and absolute paths:

```json
{
  "alice": {
    "ssh": "alice-dev",
    "repo": "/home/alice/capsule",
    "host_binary": "/tmp/capsule-host-go",
    "replacement_binary": "/home/alice/capsule/rust/target/debug/capsule-host",
    "node": "/usr/bin/node",
    "claude": "/home/alice/.local/bin/claude",
    "listen": "0.0.0.0:7443",
    "advertise": "10.0.0.10:7443",
    "coord_binary": "/tmp/capsule-coord",
    "coord_listen": "0.0.0.0:7444",
    "coord_advertise": "10.0.0.10:7444"
  },
  "bob": {
    "ssh": "bob-dev",
    "repo": "/home/bob/capsule",
    "host_binary": "/home/bob/capsule/rust/target/debug/capsule-host",
    "replacement_binary": "/tmp/capsule-host-go",
    "node": "/usr/bin/node",
    "claude": "/home/bob/.local/bin/claude",
    "listen": "0.0.0.0:7443",
    "advertise": "10.0.0.11:7443"
  }
}
```

`replacement_binary` is optional; omit it to restart the same implementation.

If this controller runs on Alice's machine, replace Alice's `"ssh"` entry with `"local": true`. Her paths then refer to this machine, while Bob still runs over SSH. The distinct-installation check remains enabled.

First run deterministic MCP consumers, which make no model calls:

```sh
python3 conformance/live_cross_host_agents.py --config /tmp/capsule-hosts.json --fixture --output /tmp/capsule-cross-host-fixture.json
```

Then omit `--fixture` for the real Claude experiment:

```sh
python3 conformance/live_cross_host_agents.py --config /tmp/capsule-hosts.json --output /tmp/capsule-cross-host-live.json
```

The runner verifies signed enrollment without manual peer pins, independently scoped grants, sends and automatic replies in both directions, collaboration after coordination stops, original-session recovery and token rotation during pending exchanges, and revocation before queued delivery. It pauses only its own receiving consumer to make the pending and queued cases deterministic. Arrival checks correlate request IDs. An uncertain send must recover through the daemon's automatic retries; the runner makes no further send calls. Invite and adapter secrets stay out of the report. Closing the workers stops their test processes and removes temporary state.

Add `--send-status` to stop each receiving daemon during the first two exchanges. The sending Claude session must call `send_status`, observe `unknown`, then observe `accepted` for the same request after the receiver returns, and receive its reply. The runner checks tool results and model text in its own session transcripts, with exactly one `send` call and one budget unit per message. `--send-status-only` runs just these two recovery exchanges:

```sh
python3 conformance/live_cross_host_agents.py --config /tmp/capsule-hosts.json --send-status-only --output /tmp/capsule-send-status-live.json
```

The [send-status live report](../../docs/results/send-status-two-host-live.json) records the full `--send-status` experiment passing with Claude Code 2.1.291, Go→Rust and Rust→Go, on separate machines. After the two receiver-outage exchanges, the original sessions also completed the coordinator-outage, originating-daemon replacement, token-rotation, and queued-revocation cases.

The report distinguishes MCP observations from model-observed replies and records each host's identity, machine fingerprint, session, versions, and grants. `--local` validates the runner on one machine; `--allow-same-machine` permits an SSH smoke test on one installation. Both report the shared machine accurately and provide no evidence of separate physical hosts. Different machine IDs identify installations, not developer identity or physical hardware.

The [two-host fixture report](../../docs/results/cross-host-runner-two-host-fixture.json) records all four Go/Rust pairings on separate installations, including coordinator outage, original-session recovery, token rotation, and queued revocation. A separate check forced Go↔Rust exchanges through the coordinator's relay by advertising closed UDP ports. These checks used deterministic MCP consumers and made no model calls.

The [two-host live report](../../docs/results/cross-host-runner-two-host-live.json) records two real Claude Code 2.1.291 sessions passing the full experiment on separate machines, with model-observed replies in both directions. Developer identities and the remaining task, conversation, and remote-tool capabilities were not tested.
