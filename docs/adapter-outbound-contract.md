# Agent-initiated messages and automatic replies

This extends the [session adapter](agent-adapter-contract.md). An owner grants a session named outbound destinations. The agent can send within those bounds, and its daemon retrieves replies and hands them back to that same session. Remote grants and peer authentication continue to apply; local session binding does not establish a separately authenticated remote agent identity.

## Owner-defined destinations

`adapter route add --adapter ID --name NAME --peer HOST --agent TARGET --grant GRANT --expires-at TIME [--max-message-bytes N] [--max-messages N]` creates an immutable route. `adapter route list --adapter ID` inspects routes; `adapter route revoke ID` stops further sends. A route binds exactly one credential/session, peer, target agent, and receiver-owned grant. Names are unique per adapter and use 1–64 lowercase ASCII letters, digits, dots, underscores, or hyphens, starting with a letter or digit. Expiration cannot exceed the credential's expiration. Content defaults to 65,536 UTF-8 bytes; the lifetime message budget defaults to 100, with a maximum of 10,000. No route is created implicitly.

Each new durable outbound request consumes one budget unit, even if transmission fails or the receiver rejects it. Identical retries use the original request and do not consume another unit. Revocation/expiration are checked on retries too. Routes cannot be edited or reassigned. Remote grant IDs identify a receiver policy; they are not bearer credentials or proof the receiver will accept a request.

Choose a route expiry no later than the remote grant's expiry and a byte bound no larger than its bound. The receiver enforces its own policy independently. Sending to Bob does not authorize Bob to initiate messages to Alice; the owners configure each direction separately.

## Scoped send

| Adapter API | Behavior |
| --- | --- |
| `GET /adapter/v1/destinations` | Return active destination names, expiration, byte bound, and remaining budget for this credential. |
| `POST /adapter/v1/send` | Accept exactly `destination`, `request_id`, and `content`. Resolve all peer/target/grant fields from the owner-defined route. |
| `POST /adapter/v1/replies/next` with `{}` | Claim one cached reply for this credential's original session, or return `null`. |
| `POST /adapter/v1/replies/{id}/forwarded` with `{}` | Acknowledge the reply notification write without implying model execution. |

The daemon assigns a delivery deadline of five minutes or the route's expiry, whichever comes first. It commits the immutable outbound request, origin binding, budget consumption, and activity before transmission. An existing request owned by another adapter or the owner CLI cannot be adopted. Reusing an ID with another destination or content conflicts. Origin bindings survive restart and cannot be redirected to another session.

The MCP `send` tool generates a request ID before calling the daemon and reports it even if the response is lost. The daemon retries an uncertain send automatically, with the same request ID, as specified under Outbound recovery in the [messaging contract](peer-messaging-contract.md); retries consume no extra budget. An explicit retry supplies that same ID and identical destination/content. The same credential cannot reuse that ID at another destination, including on another peer. An uncertain send is never given a new ID; the daemon's automatic retries reuse the original one.

`GET /adapter/v1/sends/{request_id}` returns `{request_id, destination, state, attempts, next_attempt_at, error}` for a send made with this credential, and 404 for any other request. The MCP adapter exposes it as the `send_status` tool, so an agent can follow an uncertain send to its final state without owner commands.

## Automatic return path

Bounded daemon workers poll only replies to session-originated requests, using authenticated sender-scoped peer lookup. They never resubmit a message. Pending/transport failures are rescheduled; verified replies and their activity are persisted through the existing reply store. Polling is limited to active attached credentials and four concurrent lookups per daemon, with persistent scheduling so a restart does not cause a burst. Owner-CLI messages are not claimed or polled by these workers.

Reply handoff commits a unique notification record and activity before returning content. Its state is initially `unknown`, then `forwarded` after the adapter confirms its notification write. A lost response stays uncertain without automatic redelivery. Only the original authorization, session, and bound instance may claim or acknowledge it under a valid lease. Token rotation preserves these bindings. Expired/revoked credentials and owner-detached sessions stop access; daemon restart requires recovery by the original instance, without substituting a new attachment. See the [recovery extension](adapter-recovery-contract.md).

Revoking a route stops new sends. Replies to previously authorized sends may still be retrieved and returned while the originating credential remains valid; revoke that credential or detach its session to stop its reply handoffs. Cached replies remain available to the host owner.

## Channel behavior and validation

The Claude adapter adds `list_destinations` and `send` tools. Incoming request events use `kind: "message"` with a delivery ID for the existing final `reply` tool. Automatic response events use `kind: "reply"`, with the original request and peer IDs and a separate notification ID. Reply events cannot be answered with the final-reply tool; a subsequent message requires another authorized send. This prevents an implicit reply loop.

Schema v5 adds route and origin/notification records atomically, preserving v4 state. Both daemon implementations share the schema. Conformance must cover every pairing, limits, revocation, request ownership, duplicate sends, reply isolation, rollback, migration/restart, and registered network peers. A live experiment must show two interactive Claude sessions using the send/reply tools and receiving automatic response events, without owner CLI send/fetch commands.

The [live report](results/agent-exchange-live.json) records this experiment using two running Claude Code sessions and Go↔Rust daemons over loopback. Model text in each session confirmed receipt of its automatic response. The [recovery report](results/agent-recovery-live.json) extends it with daemon restarts and token rotation while exchanges are pending. Separate physical hosts remain subsequent work.
