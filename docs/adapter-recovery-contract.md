# Adapter liveness and recovery

This extends the session adapter and outbound contracts. A registry attachment is distinct from a live adapter connection. A daemon restart invalidates connection leases, while the original running adapter can recover its existing authorization and session.

## Connection authority

Schema v6 adds `adapter_connections`: one record per adapter authorization with a process-instance secret digest, lease expiry, last-seen time, and an explicit recovery flag. Existing v5 authorizations start unbound. A newly attached session is registered but not ready to receive work until its adapter connects.

`POST /adapter/v1/connect` accepts exactly `{ "adapter_id": "ID", "session_id": "ID", "instance_id": "instance_<64 lowercase hex digits>" }`, with the session credential as its bearer token. The daemon verifies that the token identifies these exact authorization and session IDs before changing state. The first connection binds that authorization to this instance. Reconnecting or renewing a lease with the same instance is idempotent; another instance conflicts, even after the lease expires. Leases last at most 15 seconds and never exceed the authorization's expiry. The adapter renews every five seconds. All other adapter requests require the bearer token, `X-Peerspan-Instance`, the bound instance, an attached session, and a valid lease, checked in the same transaction as the operation.

The Claude subprocess generates its random instance secret in memory. It is not saved in the credential file or returned by inspection. A daemon restart can therefore be recovered by the same running subprocess; a replacement subprocess requires an explicitly authorized fresh attachment. This proves continuity of the adapter within the existing owner-local OS-account trust boundary, not a separately authenticated model identity. Resuming a transcript does not establish the same running session.

On daemon startup, registry sessions become detached and all leases are invalidated. Only sessions with a previously bound connection and retained recovery flag can reconnect. Owner detachment clears that flag even if the registry session is already detached. Revocation and expiration independently stop recovery.

Those previously bound, recoverable instances receive a 15-second reconnect window on each startup, measured with a monotonic clock. Fresh-session creation conflicts during that window and reports its end time. The window reserves the agent; it grants no lease or adapter API access. It is held in the daemon, requires no schema change, and does not apply to bindings first established after startup. Explicit owner detachment or revocation still permits an immediate fresh setup, and expired credentials do not reserve an agent. A responsive surviving adapter can reconnect during this window; expiry of the window does not prove that its process exited.

## Replacing an offline adapter

When an adapter has previously connected but its lease is no longer valid and its startup reconnect window has ended, the owner can attach a fresh session and run the usual `adapter create --session NEW_SESSION --expires-at TIME`. Creation atomically revokes the old authorization, clears its recovery flag and lease, detaches its session, and issues the fresh credential. Its response includes `replaced_adapter_ids`; activity records include `adapter.replaced` and `session.detached`. There is no separate cleanup command or wait for the old credential's expiry. If creation fails, the old authorization and session remain unchanged.

A valid lease still blocks replacement and the conflict reports its expiry. An authorization that has never connected also reserves its setup; the owner can revoke or detach it explicitly to abandon that setup. Replacement requires a different session ID. A reused credential file or a competing adapter instance cannot perform it: this is an owner-local authorization operation.

Lease expiry alone does not revoke a recoverable authorization. The original instance may reconnect until the owner authorizes a replacement. During the startup window, creation cannot win a race against that reconnect. After the window, reconnection and replacement serialize: either the original instance renews its lease and creation conflicts, or creation revokes it and later reconnects fail. A fresh credential that has not connected yet is protected from another concurrent setup replacing it.

Old deliveries, outbound requests, cached replies, notification records, routes, and consumed budgets stay bound to the old authorization and session. They are not redelivered, reassigned, or copied to the replacement. The owner can still inspect them; the new session requires its own outbound destinations. New agent-addressed requests may use the newly authorized session.

## Credential rotation

`adapter rotate ID` is owner-local and returns a new private credential once. It replaces the bearer-token digest atomically while keeping the authorization ID, session, original expiry, instance binding, routes, budgets, requests, and handoff records. The old token immediately loses access. Rotation cannot revive revoked/expired authorizations or owner-detached sessions.

Write the result to a private temporary file, then atomically replace the adapter's credential file. The running adapter may reload only a file with the same authorization and session IDs. It never extends expiry or chooses another session. A lost rotation response is recovered by another owner rotation, not by returning a stored token. Extending the authorization's lifetime is a separate owner policy decision, outside this slice.

## Recovery behavior

Connection establishment and lease renewal may retry with bounded backoff. An uncertain send is retried automatically by the daemon with the same request ID (see Outbound recovery in the messaging contract); the adapter still reports that request ID, and `send_status` reports progress. The daemon's unique delivery records continue to prevent redelivery of claimed requests or reply notifications. After a lost claim response, the adapter reconnects and can poll for unclaimed work; it does not forward that uncertain content again. A notification already written to MCP is not repeated because its acknowledgement failed. Acknowledgement retries are idempotent and contain no message content.

The adapter stops access on owner withdrawal or credential expiry. During token replacement it can wait briefly for the same authorization's updated private file, with all daemon operations still denied under the old token. Lease inspection is owner-local through `adapter connection ID`, reporting `registered`, `ready`, `offline`, `detached`, `revoked`, or `expired`, with last-seen and lease times. These describe adapter connectivity, not model availability, busy state, or execution.

`message origin --peer HOST REQUEST_ID` exposes the original authorization, session, route, and saved reply-notification state for an adapter-originated request over the owner-local interface. A lost notification response remains `unknown` and inspectable here. It grants no redelivery or reassignment authority.

Acceptance requires both implementations to preserve authorization, limits, original sessions, and uncertain records through restart; protect the startup reconnect window without granting liveness; allow immediate explicit owner withdrawal and replacement after the window; reject competing instances, stale tokens, owner-detached sessions, and lease-expired operations; and prove a pending exchange completes in the same two running Claude sessions after a daemon restart.
