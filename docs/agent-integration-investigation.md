# Existing agent integration investigation

Checked against official Claude Code documentation on 2026-10-05. This is a documentation investigation; no live Claude Code session was tested in this workspace, where the `claude` executable is unavailable.

## Existing interactive session candidate

Claude Code documents [channels](https://code.claude.com/docs/en/channels) as MCP integrations that can push events into a running session and expose a tool for replies. This is the most directly relevant documented candidate for the existing-session goal. Channels are a research preview with authentication and organization-policy restrictions; custom channels require the documented development opt-in or applicable plugin approval. Availability and protocol behavior need verification on the supported Claude Code versions.

The [channel reference](https://code.claude.com/docs/en/channels-reference) describes a local MCP subprocess communicating with Claude Code over stdio, declaring `claude/channel`, sending `notifications/claude/channel`, and optionally exposing reply tools. An ordinary MCP tool integration by itself does not establish incoming event delivery. A session must be launched with the appropriate channel opt-in; the documentation does not establish arbitrary attachment to any already-running, unconfigured process. The [MCP reference](https://code.claude.com/docs/en/mcp#push-messages-with-channels) also documents a current protocol-negotiation limitation for channel delivery on the v2 MCP runtime.

A candidate Capsule adapter would connect the opted-in local session to its host daemon. The daemon would authorize and persist inbound messages, the adapter would forward eligible messages into that particular session, and a reply tool would return responses through the daemon. This is a proposed design, not implemented behavior. Keep adapter credentials scoped to one attachment rather than granting it unrestricted access to the owner-local administration API. Declaring permission-relay capabilities is outside this first message integration.

## Host-managed session candidate

[Programmatic Claude Code](https://code.claude.com/docs/en/headless) and the [Agent SDK session documentation](https://code.claude.com/docs/en/agent-sdk/sessions) describe prompting an agent and continuing/resuming persisted conversations. These are relevant to host-managed sessions. Resuming a conversation does not prove delivery into the same already-running interactive process; do not implement existing-session attachment by silently launching another process with its transcript ID.

## Required integration experiment

1. Record the Claude Code version, MCP protocol revision, authentication mode, and whether channels are enabled. Use an isolated test workspace and an explicitly opted-in adapter.
2. Establish one attachment to the actual running session. Send a bounded message through the host daemon and observe it arrive in that session.
3. Have the agent reply through an adapter tool. Correlate the reply with the original operation and authenticate the attachment rather than accepting an arbitrary claimed agent/session ID.
4. Repeat while the session is busy. Record whether the event is queued, interrupts work, or is rejected; expose that behavior to callers.
5. Disconnect and restart the adapter. Confirm that the daemon distinguishes durable acceptance from delivery and exposes any uncertain delivery outcome. Do not claim exactly-once agent execution from a host receipt.
6. Revoke the grant before delivering a queued message. Verify that the daemon blocks delivery. Confirm that message permission does not expose a remote command or file tool, and document any local actions the existing agent can still take in response to a message under its own permissions.

Transport conformance can use a deterministic test consumer. That validates host messaging, not the real agent integration. The live experiment remains required for the acceptance scenario.
