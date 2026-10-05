# Existing agent integration investigation

Checked against official documentation and live Claude Code 2.1.289 on 2026-10-05. The [adapter contract](agent-adapter-contract.md), [setup guide](../integrations/claude-channel/README.md), and [live results](results/claude-channel-live.json) distinguish implemented behavior from remaining acceptance work.

## Existing interactive session candidate

Claude Code documents [channels](https://code.claude.com/docs/en/channels) as MCP integrations that can push events into a running session and expose a tool for replies. This is the most directly relevant documented candidate for the existing-session goal. Channels are a research preview with authentication and organization-policy restrictions; custom channels require the documented development opt-in or applicable plugin approval. Availability and protocol behavior need verification on the supported Claude Code versions.

The [channel reference](https://code.claude.com/docs/en/channels-reference) describes a local MCP subprocess communicating with Claude Code over stdio, declaring `claude/channel`, sending `notifications/claude/channel`, and optionally exposing reply tools. An ordinary MCP tool integration by itself does not establish incoming event delivery. A session must be launched with the appropriate channel opt-in; the documentation does not establish arbitrary attachment to any already-running, unconfigured process. The [MCP reference](https://code.claude.com/docs/en/mcp#push-messages-with-channels) also documents a current protocol-negotiation limitation for channel delivery on the v2 MCP runtime.

The implemented adapter connects an opted-in local session to its host daemon using a session-scoped credential and separate private socket. The host authorizes and persists messages, then rechecks the grant before handoff. The adapter forwards channel notifications and exposes one final reply tool; the original sender retrieves replies through the peer interface. It declares no permission-relay capability.

The [outbound extension](adapter-outbound-contract.md) adds `list_destinations` and `send`. Owners define each direction's destinations and limits. Daemon workers retrieve replies to session-originated messages and return them automatically to that originating session.

## Host-managed session candidate

[Programmatic Claude Code](https://code.claude.com/docs/en/headless) and the [Agent SDK session documentation](https://code.claude.com/docs/en/agent-sdk/sessions) describe prompting an agent and continuing/resuming persisted conversations. These are relevant to host-managed sessions. Resuming a conversation does not prove delivery into the same already-running interactive process; do not implement existing-session attachment by silently launching another process with its transcript ID.

## Live evidence

Both Go→Rust and Rust→Go experiments used one real interactive Claude Code process, authenticated through claude.ai, with MCP revision 2025-11-25. The same session returned two correlated replies through Capsule, including a second message sent during model streaming before the first reply was saved. Pausing only the test adapter, accepting another message, revoking its grant, and resuming the adapter produced a blocked handoff and no reply. All built-in tools were disabled; only the Capsule reply tool was allowed.

The noninteractive stream-json runs connected to MCP and the adapter wrote its notification, but Claude did not register or consume channel events on this installation. The interactive run explicitly registered channel notifications and replied. This is an observed version/mode limitation, not a general claim about all headless Claude versions.

The [two-agent experiment](results/agent-exchange-live.json) kept two opted-in Claude Code sessions running against Go↔Rust daemons. Alice used the destination and send tools, Bob replied, and Alice's model output confirmed its automatic response event. Bob independently initiated the reverse exchange and observed Alice's response. Neither exchange used owner CLI send/fetch commands. Only the three Capsule tools were enabled; built-in tools and permission relay were disabled.

These were separate daemon state directories connected over loopback, not separate physical machines. Deterministic conformance covers all four Go/Rust pairings, scope, rollback, expiry/revocation, and reopening each other's state without redelivering uncertain handoffs. Model-driven adapter/host restart recovery and the full two-developer, three-capability acceptance scenario remain to be demonstrated.

## Acceptance experiment checklist

1. Record the Claude Code version, MCP protocol revision, authentication mode, and whether channels are enabled. Use an isolated test workspace and an explicitly opted-in adapter.
2. Establish one attachment to the actual running session. Send a bounded message through the host daemon and observe it arrive in that session.
3. Have the agent reply through an adapter tool. Correlate the reply with the original operation and authenticate the attachment rather than accepting an arbitrary claimed agent/session ID.
4. Repeat while the session is busy. Record whether the event is queued, interrupts work, or is rejected; expose that behavior to callers.
5. Disconnect and restart the adapter. Confirm that the daemon distinguishes durable acceptance from delivery and exposes any uncertain delivery outcome. Do not claim exactly-once agent execution from a host receipt.
6. Revoke the grant before delivering a queued message. Verify that the daemon blocks delivery. Confirm that message permission does not expose a remote command or file tool, and document any local actions the existing agent can still take in response to a message under its own permissions.

Transport conformance can use a deterministic test consumer. That validates host messaging, not the real agent integration. The recorded live experiment proves existing-session ingress and replies; the broader acceptance scenario and remaining checklist items still require evidence.
