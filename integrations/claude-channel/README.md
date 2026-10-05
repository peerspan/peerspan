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

`adapter revoke ADAPTER_ID`, session detachment, credential expiry, or daemon restart stop adapter access. Grants are checked again at handoff and reply. An uncertain handoff is retained for inspection and is never automatically sent again or moved to another session. `forwarded` confirms a notification write, not model execution. See the [adapter contract](../../docs/agent-adapter-contract.md).

`adapter route revoke ROUTE_ID` stops further sends through that route. Replies to earlier sends can still return while the original credential is valid. An uncertain send reports its request ID: an explicit retry must reuse that ID and identical destination/content. Each new persisted request uses one lifetime budget unit, including failed or rejected attempts. See the [outbound contract](../../docs/adapter-outbound-contract.md).

The adapter exposes `list_destinations`, `send`, and `reply`, and omits permission-relay capability. Message access does not give a peer shell or filesystem access through Capsule; the existing agent still has whatever local permissions its owner granted it.

## Verify

From the repository root:

```bash
npm --prefix integrations/claude-channel test
python3 conformance/agent_adapter.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
python3 conformance/adapter_outbound.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --coord COORD_BINARY
```

The Python suite uses a deterministic MCP client and temporary host state. The separate `conformance/live_claude_channel.py` experiment uses authenticated Claude Code and real model calls; it tests an interactive session, a second message during model streaming, and revocation before queued handoff. Its PTY driver requires Linux:

```bash
python3 conformance/live_claude_channel.py --sender GO_BINARY --receiver RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --output /tmp/capsule-live.json
python3 conformance/live_agent_exchange.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --output /tmp/capsule-exchange-live.json
```

The second experiment uses two interactive Claude sessions to initiate messages in both directions and confirm automatic replies in their model output, without owner CLI send/fetch commands. Both experiments create temporary host and MCP configuration. Claude records each test workspace's trust/session information through its normal account state. Existing sessions and MCP configurations are not selected or reconfigured. Noninteractive stream-json mode connected to MCP but did not consume channel events in the tested installation; use the interactive path for this slice. Recorded results are in the [ingress report](../../docs/results/claude-channel-live.json) and [two-agent exchange report](../../docs/results/agent-exchange-live.json).
