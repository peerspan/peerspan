# Session adapter contract

This slice connects an explicitly opted-in Claude Code session to either host implementation. It adds a credential-scoped local interface; the owner-local admin socket and authenticated peer interface retain their separate authority.

The [outbound extension](adapter-outbound-contract.md) adds owner-defined destinations, agent-initiated sends, and automatic replies bound to the originating session.

## Credentials and routing

An owner attaches a session and runs `adapter create --session ID --expires-at TIME`. The response contains a random 256-bit bearer token returned only on creation. The database stores its SHA256 digest, session, expiry, and revocation state. An agent can have only one unexpired, unrevoked credential on an attached session. Owners can list, inspect, and revoke credentials. Credentials never confer administration, arbitrary outbound messaging, shell, filesystem, or tool-approval authority.

Adapters call only `adapter.sock`, a private Unix socket with its own router. Every request requires `Authorization: Bearer TOKEN` and an attached session with a valid credential. Detach, credential revocation/expiry, and daemon restart invalidate access. The existing owner-local OS-account trust boundary remains: these credentials do not isolate a malicious process with full access to that same account and its state directory.

## Handoff and reply

| Adapter request | Behavior |
| --- | --- |
| `GET /adapter/v1/session` | Inspect only the credential's attached session. |
| `POST /adapter/v1/next` with `{}` | Claim the oldest unclaimed message for this session's agent, or return `null`. Recheck its receiver-owned grant, deadline, content bounds, and connected or disconnected permission. |
| `POST /adapter/v1/deliveries/{id}/forwarded` with `{}` | Record that the adapter successfully wrote the channel notification. Idempotent; this is not proof the model read or executed it. |
| `POST /adapter/v1/deliveries/{id}/reply` with `{ "content": "..." }` | Save one bounded final reply for this claimed message. Recheck the grant, credential, and session. Identical retries return the saved reply; changed content conflicts. |

Before handing content to an adapter, persist the delivery and an activity event in one transaction. Its initial state is `unknown`: a lost response or crash can obscure whether the adapter received or forwarded it. The unique original sender/request pair prevents automatic redelivery, including to another session. Successful notification writes yield `forwarded`; a persisted reply yields `replied`. Messages denied at handoff for a final reason are recorded as `blocked`. A message whose only failing check is the connected state stays unclaimed instead (see below). Owners can inspect these records; resolving unknown handoffs or explicitly rerouting them is future work.

Authorization at the handoff transaction is the boundary for starting delivery. Revocation blocks later handoffs, but cannot withdraw content already handed to an adapter. The adapter has no local message queue and forwards each claimed message immediately. Replies require a still-valid grant, but may follow the original delivery deadline. Reply size is bounded by the grant and 65,536 UTF-8 bytes. Permission to send a message does not constrain every action the existing agent can take under its own local permissions.

## Return path and persistence

The authenticated original sender retrieves the saved reply at `GET /peer/v1/replies/{request_id}`. Other senders receive 404. Lookup remains available after revocation/expiry because it authorizes no new work. No reverse grant or arbitrary recipient is introduced: this is a bounded response to a previously accepted message. Pending replies return 404.

`message reply --peer HOST REQUEST_ID` asks the sender's local daemon to fetch and persist the matching reply. Session-originated sends use daemon workers to fetch and return replies automatically; owner-CLI sends still use this command. A pending result has `state: "pending"`; transport failure has `state: "unknown"`; a stored reply has `state: "replied"`. Both unknown and pending can be checked again safely. Once saved, the reply remains locally inspectable even if the peer is unreachable. This adds no conversation or task lifecycle.

Database version 4 adds credential, delivery, received-reply, and outbound-reply tables atomically. Existing identities, grants, messages, receipts, and network membership (version 3) remain intact. Both implementations share this schema and can reopen each other's state. Unknown deliveries and replies survive restart; old session attachments remain detached and are never silently substituted.

Version 5 adds outbound routes and originating-session bindings, preserving version 4 state. See the outbound extension for budgets and reply-notification states.

## Claude Code adapter

The adapter uses the official MCP SDK over stdio, declares only `claude/channel`, and exposes `list_destinations`, `send`, and a correlated `reply` tool. It reads its credential from a private file, calls only the adapter socket, and never logs the token or message contents. It starts polling after MCP initialization and stops on authentication failure or an uncertain handoff. Writing an MCP notification is distinct from receiving a model reply.

Claude Code [Channels](https://code.claude.com/docs/en/channels) are a research preview requiring explicit session opt-in and applicable organization policy. The [reference](https://code.claude.com/docs/en/channels-reference) describes development loading, message notifications, and reply tools. An unconfigured running process is not automatically attachable. Record the actual Claude version, negotiated MCP revision, observed behavior while busy, and live-test result separately from deterministic conformance.

## Grant predicate

Wire acceptance, adapter handoff, and reply share the host's grant checks. The final bounds are requester, target, action, revocation, expiration, deadline (not checked for replies), and content size. Wire acceptance and handoff also check the connected state from the coordination contract: a grant without `allow_disconnected` needs the original sender to be a member of a network this host synced within three coordination intervals. The checks run again at handoff and reply, so authorization that lapses after acceptance stops delivery.

The checks fall into two kinds. The final bounds: once one fails it never recovers, so handoff records the delivery as `blocked`. The connected state can recover when syncing resumes, but only while the sender is still a verified member of a network this host has not synced recently. A message failing only in that recoverable way therefore gets no delivery record or event. If the sender is no longer a member of any network, handoff records `blocked`. It stays unclaimed, and later claims skip past it to deliverable messages. It is handed off once the sender counts as connected again, or recorded as `blocked` once its deadline passes. While messages wait this way, handoff order is not strictly oldest-first. Each claim examines at most the 100 oldest unclaimed messages for the agent, so a larger backlog of waiting messages delays newer ones until syncing resumes. A reply answers content this host already delivered, so it needs only the final bounds: a coordination outage does not strand it, but revocation or expiry still stops it. On the wire, a message denied only for that recoverable connected state gets 503 `unavailable`, not 403, so the sender can retry the same request.
