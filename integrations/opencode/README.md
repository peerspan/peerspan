# Attach an existing OpenCode conversation

Peerspan's sidecar connects to a selected session in an already-running OpenCode
HTTP server. It creates no OpenCode process or conversation and changes no model,
agent, native permissions, or OpenCode configuration. Requires Node 22+ and
OpenCode 1.18.31+.

## Install the plugin once

A Peerspan release bundle already contains the pinned production dependencies.
In a source checkout only, install them with:

```sh
npm ci --ignore-scripts --prefix integrations/opencode
```

Open the OpenCode configuration file you already use. Global configuration lives
in `~/.config/opencode/opencode.json` or `opencode.jsonc`; project configuration
lives in `opencode.json` or `opencode.jsonc` in the project root. JSONC supports
comments. Edit the existing file, preserving its comments and settings. See
[configuration locations](https://opencode.ai/docs/config/#locations).

The JSON below belongs in that file. Add the Peerspan entry to its `plugin` array,
preserving other plugins and settings; create the array if absent. Choose a
private, account-owned directory for bindings and substitute full absolute paths:

```json
{
  "plugin": [[
    "file:///absolute/peerspan/integrations/opencode/plugin.mjs",
    { "bindings": "/absolute/private/peerspan-opencode-bindings" }
  ]]
}
```

Load the plugin through OpenCode's normal configuration/reload workflow while
idle. Keep `shared/` alongside the integration bundles. This installation enables
the shared tools with a `peerspan_` prefix: `peerspan_list_destinations`, `peerspan_send`,
`peerspan_send_status`, `peerspan_reply`, and the task tools (`peerspan_task_accept`,
`peerspan_task_reject`, `peerspan_task_progress`, `peerspan_task_complete`,
`peerspan_task_cancelled`, `peerspan_delegate_task`, `peerspan_task_status`, and
`peerspan_artifact_save` for [task artifacts](../../docs/artifact-contract.md)). A conversation receives no Peerspan authority until an owner
attaches it. The plugin uses OpenCode's trusted `context.sessionID` and honors
native tool permission decisions. Model arguments cannot select another session.

Because the tools use the plugin API rather than MCP, the sidecar reports
`opencode-plugin-VERSION` (the server version from `/global/health`) as the
adapter connection's `protocol_version`.

OpenCode's MCP requests in this version omit caller session identity, so a plain
MCP registration cannot safely fence multiple conversations. The native plugin
provides that identity without relying on model-supplied IDs.

## Connect the conversation

Use the server URL and workspace of the existing TUI/server, and select its
existing conversation ID. Starting `opencode serve` separately creates a different
server; Peerspan does not do that for you.

Run `opencode session list --format json --max-count 10` from the native
conversation's project directory. The list is scoped to that project, so running
it from a different checkout can return nothing. Match the title and use its `id`
(starting with `ses_`); use that conversation's `directory` for `--option directory`.

```sh
peerspan-host --state STATE session setup --harness opencode \
  --integrations /absolute/peerspan/integrations --runner /absolute/node \
  --option server=http://127.0.0.1:4096 \
  --option session=EXISTING_OPENCODE_SESSION_ID \
  --option directory=/absolute/project \
  --option bindings=/absolute/private/peerspan-opencode-bindings \
  --directory /absolute/opencode-attachment --agent AGENT_ID \
  --expires-at FUTURE_RFC3339_TIME --routes /absolute/destinations.json
peerspan-host session start --directory /absolute/opencode-attachment
peerspan-host session doctor --directory /absolute/opencode-attachment
```

Only literal loopback HTTP addresses are supported. If the existing server uses
basic authentication, add `--option auth-file=/absolute/auth.json`; this private
0600, account-owned file contains `{"username":"opencode","password":"..."}`.
Secrets never appear in command arguments or gateway requests.

The sidecar publishes a private per-session binding to its Unix tool gateway.
Other conversations have no binding and cannot exercise the attachment. Duplicate
bindings are refused. Ctrl-C removes its binding and closes Peerspan's gateway;
OpenCode keeps running. A crash can leave a stale binding: inspect the previous
sidecar before removing that session's binding file and authorizing a new setup.

Incoming messages use the existing session's asynchronous prompt API, preserving
its latest recorded model and agent. Peerspan confirms the exact generated message
ID and content in OpenCode's store before marking `forwarded`; HTTP 204 alone is
insufficient. This confirms persisted input, not model consumption. Ambiguous
submissions are never automatically repeated. Models call `peerspan_reply`
explicitly, and Peerspan returns peer replies to the originating conversation.

The native TUI shows a short Peerspan request, reply, or task header followed by
the peer's content. Protocol instructions are separate per-turn system input.
Correlation metadata is a synthetic text part: available to the model and kept
in conversation history, but hidden by the native TUI. Peerspan confirms both
parts and the system instructions were persisted before acknowledging delivery.

The original sidecar reconnects after Peerspan daemon restarts and reloads tokens
rotated for the same adapter/session. Grants, expiry, revocation, destination
budgets, and original-work ownership remain enforced by the daemon. Doctor performs
only read-only checks; model availability and consumption remain unverified.

## Verification

After a sidecar crash or reboot, run `peerspan attach opencode` again with the
same conversation options once the previous lease/reconnect protection lapses.
The new gateway reclaims its owned dead socket and matching stale binding;
manual file deletion is unnecessary. A live bridge or unrelated binding is
retained. A previously bound credential still requires fresh attachment.

```sh
node --test integrations/opencode/*.test.mjs integrations/shared/*.test.mjs
python3 conformance/opencode_integration.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
python3 conformance/opencode_runtime.py --go GO_BINARY --rust RUST_BINARY \
  --node NODE_BINARY --opencode OPENCODE_BINARY
```

The shared suite uses pre-existing HTTP backend fixtures and the real plugin/sidecar
across all Go/Rust pairings. The runtime suite uses real OpenCode processes and an
explicit deterministic model fixture; it performs no real inference. A separate
[live check](../../docs/results/opencode-existing-sessions-live.json) used OpenAI
ChatGPT login with two existing OpenCode server conversations. Models exchanged
pre-attachment phrases in both directions, including after daemon replacement
and token rotation, with unchanged session IDs and permissions. This was one
Linux machine; native TUI interaction and macOS execution remain separate checks.

To check two already-running, authenticated test conversations with real models:

```sh
python3 conformance/live_opencode_agents.py --go GO_BINARY --rust RUST_BINARY \
  --node NODE_BINARY --server-a http://127.0.0.1:PORT_A --session-a EXISTING_SESSION_A \
  --directory-a /absolute/project-a --bindings-a /absolute/bindings-a \
  --server-b http://127.0.0.1:PORT_B --session-b EXISTING_SESSION_B \
  --directory-b /absolute/project-b --bindings-b /absolute/bindings-b \
  --output /absolute/opencode-live.json
```

Both conversations must already have a selected model and recorded message. The
runner adds private validation phrases before attaching, then verifies scoped
sends, model-observed replies, daemon replacement and token rotation. It starts
only disposable Peerspan daemons and sidecars; the native servers stay running.
Optional `--auth-file-a` and `--auth-file-b` select private HTTP server auth files.

See the official [server API](https://opencode.ai/docs/server/) and
[plugin API](https://opencode.ai/docs/plugins/).
