# Reliable delivery into live sessions

Status: implemented; decisions settled with the owner on 2026-10-10 (see [Decisions](#decisions)). This is roadmap milestone 9, the live-session delivery track. The [live delivery contract](live-delivery-contract.md) specifies it.

## Problem

Peerspan delivers messages and tasks into a running Claude Code session through a channel: an MCP server that pushes `notifications/claude/channel` events ([agent integration investigation](agent-integration-investigation.md)). Claude Code acknowledges nothing. If it has not registered Peerspan as a channel, it drops events silently ([channels reference](https://code.claude.com/docs/en/channels-reference#notification-format)). That happens:
- when an organization has not enabled `channelsEnabled` (the default for claude.ai Team and Enterprise);
- on Bedrock, Vertex, or Foundry;
- with an MCP SDK that negotiates revision 2026-07-28 on the v2 client runtime.

Today Peerspan then marks each message `forwarded`, shows the agent as `connected`, and `session doctor` reports `adapter_ready`. Senders keep sending into a session that never sees anything.

The same lack of acknowledgment causes four smaller losses:
- **Lost on exit.** Events queued inside Claude Code are lost when it exits, and the messages stay `forwarded`.
- **Orphaned tasks.** A running task stays bound to a session that no longer exists, because a disconnect never fails a task, so delegation chains can hang.
- **Lost IDs.** `/clear` and compaction can drop the delivery and task IDs the model needs, and no tool lists them again.
- **Silent stop.** An adapter that stops on a fatal error does so silently.

Two smaller problems sit alongside these:
- **Cut-off instructions.** The adapter's instructions (2,266 characters) exceed the 2,048-character cap of Claude Code 2.1.84 to 2.1.295.
- **No version check.** `session doctor`'s version probe accepts any version.

## Goals and non-goals

**Goals:**
- No silent loss: an agent counts as connected only after its session has proved it receives events.
- Work a model never saw goes to the agent's next session, and running tasks survive a session's replacement.
- A model can always list the work it still owes.
- `status` and `session doctor` name the cause of a failed attach.

**Non-goals:**
- Headless (`-p`) or SDK sessions. Development channels are ignored there, and only an Anthropic-listed or organization-allowlisted plugin works ([channels](https://code.claude.com/docs/en/channels)). Getting Peerspan's plugin listed is a separate, non-code step.
- Claude Code's cross-session messaging socket, until its wire format is documented.
- Exactly-once model execution. "Seen" means the model called a Peerspan tool naming the item, not that it acted on it.

## Design

1. **Readiness handshake.** After MCP connects, the adapter sends one `hello` channel event with a nonce. It claims no work until the model calls `peerspan_ready` with that nonce. The daemon records the session's channel as verified. The directory reports an agent as `connected` only when a verified session holds its lease. `status` and `session doctor` report an unverified channel with its likely causes.
2. **Seen.** A delivery is seen when the model calls `reply` or `mark_seen` with its ID. A task is seen when the model calls `task_accept` or `task_reject` with its ID. When an authorization ends, its forwarded but unseen deliveries and tasks return to the agent's queue for its next session, before their deadlines, marked as redelivered.
3. **Adoption.** When the same agent's new session is verified, it adopts the running and cancel-requested tasks of the agent's replaced sessions and is told about each one.
4. **Pending work.** A `pending_work` tool lists unanswered deliveries and owed tasks. A `SessionStart` hook, passed in launch-time settings, injects it after `/clear`, compaction, and resume.
5. **Hygiene:**
   - Instructions under 2,048 characters, with the detail moved into tool descriptions.
   - A minimum Claude Code version in `session doctor`.
   - The launch environment sets `MCP_PROTOCOL_NEGOTIATION=legacy`.
   - A fatal adapter stop sends a last event and exits.
   - Agent sends by address and route sends get 1 hour instead of 5 minutes.

## Slices

1. **Readiness and diagnostics:** the handshake, `connected` semantics, status item 13, doctor checks, instructions, fatal stops, protocol negotiation, and the 1-hour deadline.
2. **Seen, redelivery, adoption, and pending work.**

Each slice is implemented in Go and Rust, plus the Node adapter. Its shared conformance suite is written from the contract by an independent author, and a live Claude Code run follows.

## Decisions

Settled with the owner on 2026-10-10:
- **Readiness:** a handshake at launch, costing one brief model turn, rather than heuristics alone.
- **Orphans:** the same agent's new session adopts running tasks.
- **Redelivery:** work the model provably never saw goes to the next session.
- **Deadline:** agent sends wait 1 hour, as CLI sends and delegations do.

Settled with the owner on 2026-10-25:
- **Protocol revision for every integration.** Codex and OpenCode adapters report `protocol_version`, as Claude Code does ([`mcp_protocol`](live-delivery-contract.md#doctor)):
  - **OpenCode:** it has no MCP session with Peerspan, so it reports `opencode-plugin-VERSION`, the server version from `GET /global/health`, rather than a separate field.
  - **Codex:** `mcp.mjs` sends its negotiated MCP revision with each `POST /tool`. The sidecar accepts it only from calls whose `_meta.threadId` is the selected thread.
  - **Reporting:** the adapter connects again as soon as the value changes, before its next daemon request.
  - **Doctor:** the `2026-07-28` failure applies to the Claude Code harness (`claude-code`) only, and a missing value is not a failure.

## Open

- An official-marketplace listing, or organization allowlisting through `allowedChannelPlugins`, for Peerspan's channel plugin. Either one removes the development-channel dialog and enables headless agents.
