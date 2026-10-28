# Attach an existing Codex session

Connect one already-running Codex conversation to either Peerspan daemon. The
sidecar joins its existing local app-server socket and preserves the thread,
history, model, sandbox and normal tool approvals. Requires Node 22+ and Codex
CLI/backend 0.160.0+.

Release bundles already contain the pinned production dependencies. In a source
checkout, install them before attaching a session:

```sh
npm ci --ignore-scripts --prefix integrations/codex
peerspan-host --state STATE session setup --harness codex \
  --integrations /absolute/peerspan/integrations --runner /absolute/node \
  --option executable=/absolute/codex \
  --option socket=/absolute/app-server-control.sock \
  --option thread=EXISTING_CODEX_THREAD_UUID \
  --directory /absolute/codex-attachment --agent AGENT_ID \
  --expires-at FUTURE_RFC3339_TIME --routes /absolute/destinations.json
peerspan-host session start --directory /absolute/codex-attachment
peerspan-host session doctor --directory /absolute/codex-attachment
```

Use the socket of the backend serving that conversation. For the shared local
Codex daemon, `codex app-server daemon version` reports `socketPath`. Inside the
native Codex CLI conversation, enter `/status` and copy the **Session** UUID for
`--option thread`. If that line is absent, send a message and run `/status` again.
The daemon version command does not list conversation IDs. Peerspan refuses stored
but unloaded threads, rather than starting a replacement. The desktop/TUI continues running;
`session start` starts only Peerspan's sidecar. Optional `-- --json` produces JSONL
progress. Ctrl-C stops the sidecar and disconnects Peerspan, leaving Codex running.

Setup writes only private Peerspan artifacts. Doctor reads prerequisites and the
selected thread without connecting an adapter, changing Codex configuration,
renewing leases or consuming messages. Keep the sibling `shared/` directory with
the integration bundles.

## Tools and delivery

On attachment, Peerspan registers a uniquely named local MCP server in the
backend's user configuration and requests a live MCP reload. It preauthorizes
only the shared Peerspan tools: `list_destinations`, `send`, `send_status`, `reply`,
and the task tools `task_accept`, `task_reject`, `task_progress`, `task_complete`,
`task_cancelled`, `delegate_task`, `task_status`, and `artifact_save`. Native configuration
versions protect concurrent edits; shutdown removes its entry if it still matches.
If cleanup cannot be confirmed, the bridge reports that and owners can inspect
its `peerspan_SESSION_SUFFIX` entry. A crashed bridge may leave a stale entry;
its dead private socket provides no new access.

Codex supplies the caller's `threadId` in MCP metadata. Every call must match the
selected conversation before reaching the sidecar's private tool socket. Other
conversations may discover the server's tools but cannot exercise its attachment.
The MCP server sends the protocol revision it negotiated with Codex along with each
call, and the sidecar reports the selected thread's revision to the daemon as
`protocol_version`. Tokens and process-instance secrets remain in the sidecar; the MCP consumer
receives neither credentials nor access to Peerspan administration.

Incoming messages and return replies enter Codex's durable user-message queue.
The sidecar starts its own queued item only when Codex is idle, using Codex's
atomic idle check; active work and native approval requests remain under the
existing client. Ambiguous submission is never automatically repeated.
`forwarded` means Codex accepted the queued input, not that a model consumed it.
Replies require an explicit `reply` tool call.

Queued input shows a short Peerspan request, reply, or task header and the peer's
content. The protocol instructions come from the attachment's MCP server instead
of being repeated in each message. A compact footer names that server and retains
the event's correlation metadata. This footer remains visible in Codex because
the queue API exposes plain text input.

The original sidecar recovers after Peerspan daemon restarts and reloads rotated
tokens for the same adapter/session. Receiver grants, expiry, revocation and
route budgets remain daemon-enforced. Restarting the sidecar cannot adopt a
previously bound attachment; authorize a fresh setup after its old lease expires.
Already-queued input remains in Codex if Peerspan disconnects.

After a crash, `peerspan attach codex` can reclaim the matching private socket
once it confirms the old gateway has no listener. It retains live sockets and
unrelated files, and still follows the daemon's lease/replacement rules.

## Limits and verification

This targets Codex's experimental 0.160.0 protocol. It requires an exposed local
backend socket. Embedded CLI backends (including some `--profile`, `-c`, and
`--no-daemon` invocations) cannot be attached through this API. An already-running
CLI connected to the shared daemon or an explicit socket is supported. The native
CLI path is live-tested; the desktop UI path is not separately live-tested.
See [Codex app-server](https://learn.chatgpt.com/docs/app-server).

```sh
node --test integrations/codex/*.test.mjs integrations/shared/*.test.mjs
python3 conformance/codex_integration.py --go GO_BINARY --rust RUST_BINARY --node NODE_BINARY
python3 conformance/live_codex_agents.py --go GO_BINARY --rust RUST_BINARY \
  --node NODE_BINARY --codex CODEX_BINARY --socket EXISTING_SOCKET \
  --thread-a TEST_THREAD_A --thread-b TEST_THREAD_B --output /tmp/codex-live.json
```

`GO_BINARY` is a `peerspan-host` built from [peerspan/peerspan-go](https://github.com/peerspan/peerspan-go); these suites still take one until Rust-only conformance replaces them.

Deterministic tests use pre-existing backend fixtures and real MCP consumers
against all Go/Rust pairings. The opt-in live runner uses two caller-selected,
already-running test conversations and verifies pre-attachment phrases in model
output, including daemon replacement and token rotation. It never starts Codex.
Its local run does not establish cross-host connectivity.
