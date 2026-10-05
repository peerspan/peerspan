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

Send an authorized peer message using the existing `message send` command. The running session receives a channel event containing a delivery ID, authenticated sender host, and request ID. Its `reply` tool stores one final response addressed only to the original sender. That sender retrieves it with:

```bash
capsule-host --state SENDER_STATE message reply --peer RECEIVER_HOST_ID REQUEST_ID
capsule-host --state RECEIVER_STATE delivery list
```

`adapter revoke ADAPTER_ID`, session detachment, credential expiry, or daemon restart stop adapter access. Grants are checked again at handoff and reply. An uncertain handoff is retained for inspection and is never automatically sent again or moved to another session. `forwarded` confirms a notification write, not model execution. See the [adapter contract](../../docs/agent-adapter-contract.md).

The adapter exposes only the reply tool and omits permission-relay capability. Message access does not give a peer shell or filesystem access through Capsule; the existing agent still has whatever local permissions its owner granted it.

## Verify

From the repository root:

```bash
npm --prefix integrations/claude-channel test
python3 conformance/agent_adapter.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
```

The Python suite uses a deterministic MCP client and temporary host state. The separate `conformance/live_claude_channel.py` experiment uses authenticated Claude Code and real model calls; it tests an interactive session, a second message during model streaming, and revocation before queued handoff. Its PTY driver requires Linux:

```bash
python3 conformance/live_claude_channel.py --sender GO_BINARY --receiver RUST_BINARY --node NODE_BINARY --claude CLAUDE_BINARY --output /tmp/capsule-live.json
```

The live experiment creates temporary host and MCP configuration. Claude records the test workspace's trust/session information through its normal account state. Existing sessions and MCP configurations are not selected or reconfigured. Noninteractive stream-json mode connected to MCP but did not consume channel events in the tested installation; use the interactive path for this slice. Recorded results are in [the live report](../../docs/results/claude-channel-live.json).
