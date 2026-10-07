# Attach an existing OpenCode conversation

Capsule's sidecar connects to a selected session in an already-running OpenCode
HTTP server. It creates no OpenCode process or conversation and changes no model,
agent, native permissions, or OpenCode configuration. Requires Node 22+ and
OpenCode 1.18.31+.

## Install the plugin once

```sh
npm ci --ignore-scripts --prefix integrations/opencode
```

Add the local plugin to the OpenCode configuration you already use, preserving
existing entries. Choose a private, account-owned directory for bindings:

```json
{
  "plugin": [[
    "file:///absolute/capsule/integrations/opencode/plugin.mjs",
    { "bindings": "/absolute/private/capsule-opencode-bindings" }
  ]]
}
```

Load the plugin through OpenCode's normal configuration/reload workflow while
idle. Keep `shared/` alongside the integration bundles. This installation enables
four tools: `capsule_list_destinations`, `capsule_send`, `capsule_send_status`, and
`capsule_reply`. A conversation receives no Capsule authority until an owner
attaches it. The plugin uses OpenCode's trusted `context.sessionID` and honors
native tool permission decisions. Model arguments cannot select another session.

OpenCode's MCP requests in this version omit caller session identity, so a plain
MCP registration cannot safely fence multiple conversations. The native plugin
provides that identity without relying on model-supplied IDs.

## Connect the conversation

Use the server URL and workspace of the existing TUI/server, and select its
existing conversation ID. Starting `opencode serve` separately creates a different
server; Capsule does not do that for you.

```sh
capsule-host --state STATE session setup --harness opencode \
  --integrations /absolute/capsule/integrations --runner /absolute/node \
  --option server=http://127.0.0.1:4096 \
  --option session=EXISTING_OPENCODE_SESSION_ID \
  --option directory=/absolute/project \
  --option bindings=/absolute/private/capsule-opencode-bindings \
  --directory /absolute/opencode-attachment --agent AGENT_ID \
  --expires-at FUTURE_RFC3339_TIME --routes /absolute/destinations.json
capsule-host session start --directory /absolute/opencode-attachment
capsule-host session doctor --directory /absolute/opencode-attachment
```

Only literal loopback HTTP addresses are supported. If the existing server uses
basic authentication, add `--option auth-file=/absolute/auth.json`; this private
0600, account-owned file contains `{"username":"opencode","password":"..."}`.
Secrets never appear in command arguments or gateway requests.

The sidecar publishes a private per-session binding to its Unix tool gateway.
Other conversations have no binding and cannot exercise the attachment. Duplicate
bindings are refused. Ctrl-C removes its binding and closes Capsule's gateway;
OpenCode keeps running. A crash can leave a stale binding: inspect the previous
sidecar before removing that session's binding file and authorizing a new setup.

Incoming messages use the existing session's asynchronous prompt API, preserving
its latest recorded model and agent. Capsule confirms the exact generated message
ID and content in OpenCode's store before marking `forwarded`; HTTP 204 alone is
insufficient. This confirms persisted input, not model consumption. Ambiguous
submissions are never automatically repeated. Models call `capsule_reply`
explicitly, and Capsule returns peer replies to the originating conversation.

The original sidecar reconnects after Capsule daemon restarts and reloads tokens
rotated for the same adapter/session. Grants, expiry, revocation, destination
budgets, and original-work ownership remain enforced by the daemon. Doctor performs
only read-only checks; model availability and consumption remain unverified.

## Verification

```sh
node --test integrations/opencode/*.test.mjs integrations/shared/*.test.mjs
python3 conformance/opencode_integration.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
python3 conformance/opencode_runtime.py --go GO_BINARY --rust RUST_BINARY \
  --node NODE_BINARY --opencode OPENCODE_BINARY
```

The shared suite uses pre-existing HTTP backend fixtures and the real plugin/sidecar
across all Go/Rust pairings. The runtime suite uses real OpenCode processes and an
explicit deterministic model fixture; it performs no real inference. Account-based
live inference remains separate. OpenCode's free provider rejected API-driven turns
in the tested installation, so it does not establish a working live model exchange.

See the official [server API](https://opencode.ai/docs/server/) and
[plugin API](https://opencode.ai/docs/plugins/).
