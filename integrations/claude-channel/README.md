# Claude Code channel

One Node.js adapter connects an opted-in Claude Code session to the Peerspan host daemon. It uses the official MCP SDK over stdio and calls only the credential-scoped `adapter.sock` interface.

## Configure one session

Install Node.js 22 or later. A Peerspan release bundle already contains the pinned
production dependencies. In a source checkout only, install them with:

```bash
cd integrations/claude-channel
npm ci --ignore-scripts
```

With your daemon running and your agent registered, prepare and start one explicitly opted-in session:

```bash
peerspan-host --state STATE session setup --harness claude-code --directory /absolute/session-setup --agent AGENT_ID --expires-at FUTURE_TIME --integrations /absolute/peerspan/integrations
peerspan-host session start --directory /absolute/session-setup --workspace /absolute/project
peerspan-host session doctor --directory /absolute/session-setup
```

`setup` creates the session, expiring credential, and optional destinations in one daemon transaction. It writes `profile.json`, `credential.json`, and `mcp.json` into a new private directory (0700; files 0600). Existing configuration is never overwritten. `--expires-at` is a future RFC3339 time. Use `--runner /absolute/node` and `--option executable=/absolute/claude` if the executables are outside PATH. Both native CLIs select the Claude integration through its `integration.json` manifest; its `provider.mjs` implements Claude checks and MCP/launch configuration. Install the complete integration directory. The [harness contract](../../docs/harness-integration-contract.md) defines the common lifecycle and local helper interface.

`start` launches Claude in the foreground using that private MCP configuration and opts in to `server:peerspan`, with `MCP_PROTOCOL_NEGOTIATION=legacy` in Claude Code's environment (set through `env`). It allows the scoped Peerspan tools; normal Claude project settings and permissions apply. Add Claude arguments after `--`, for example `-- --name collaboration`. Arguments cannot replace the prepared MCP configuration, `--settings`, or channel selection. At each launch it also writes `claude-settings.json` (0600) into the session directory and passes it with `--settings`. The file adds only a `SessionStart` hook for `clear|compact|resume` that runs the launching `peerspan` executable (absolute path, single-quoted) as `session pending --hook`, which wraps the list as hook `additionalContext`, so after `/clear`, compaction, or resume the model's context again lists the messages, replies, and tasks it still owes. No global or project Claude configuration is edited.

After MCP initialization the adapter connects and sends one `kind: "hello"` channel event with a random `meta.nonce`. It claims no messages or tasks until the model calls `peerspan_ready` with that nonce, which makes the adapter report `POST /adapter/v1/ready`; if the model has not done so within 60 seconds, the adapter sends the same hello once more. The daemon counts the agent as connected only after this verification, so a session that never receives channel events is reported rather than silently fed. The adapter also reports the MCP protocol revision it negotiated as `protocol_version` on connect. If it stops polling for good (a final refusal or a replaced instance), it sends a `kind: "disconnected"` event saying to run `peerspan attach claude` in the project, writes the reason to stderr, and exits with status 1. See the [live delivery contract](../../docs/live-delivery-contract.md).

Claude Code presents its development-channel confirmation. Channels are a [research preview](https://code.claude.com/docs/en/channels), subject to authentication and organization policy. Setup checks Node, installed dependencies, Claude launch flags, the Claude Code version (`claude_version`: `claude --version` must be at least 2.1.187), and `claude auth status`; `claude_account` warns, without failing, when the API provider is not first-party or a Team or Enterprise organization must enable channels. Organization policy is checked by Claude at launch. This flow starts an opted-in session; it cannot add a channel to an arbitrary already-running Claude process. Plain MCP registration does not enable incoming messages.

## Diagnose and recover

`doctor` prints JSON and exits zero when prerequisites, private configuration, credential, authorization, and the original adapter's lease pass inspection. Immediately after setup it exits nonzero with `registered`: configuration exists but no adapter has connected. It identifies unavailable daemons, changed host identity, missing or stale credentials, expired leases, detached sessions, and revoked or expired authorization. Destinations show remaining lifetime message budgets and expiry/revocation status. Remote reachability and grant acceptance remain unverified.

Inspection never connects an adapter, renews a lease, hands off a message, or changes permissions. `adapter_ready` refers to the adapter lease, local configuration, and a verified channel (the model called `peerspan_ready`). `model_availability: "unknown"` and `message_consumption: "unverified"` remain explicit even with a live lease. Check a live exchange separately to establish model consumption.

If setup loses the daemon response or fails while saving the credential, retain its private directory and run `session setup --directory DIR`. A `preparing` profile records the exact requested session and scopes before submission. Recovery reuses that session and original expiry/destinations, rotating its token if necessary. It refuses an attachment that has already connected or changed. Known setup refusals roll back all daemon changes and remove the new preparing directory; ambiguous failures retain it. `doctor` reports interrupted setup without completing it.

Once an adapter has connected, `start` will not adopt its authorization for another process. Keep the original Claude process during daemon recovery. For a closed session, choose a fresh setup directory; the existing offline replacement policy applies. Live leases, unbound setups, and the startup reconnect window still conflict. Explicit owner detach or revoke withdraws an unused setup. Authorization expiry requires a fresh owner-authorized setup; token rotation does not extend expiry. Keep credential files private and never commit them.

The existing `session attach`, `adapter create`, and `adapter route add` commands remain available for manual integrations. The generated `mcp.json` documents the required stdio channel arguments.

## Allow the agent to initiate messages

After configuring the peer or enrolling both hosts in a network, the receiving owner grants access to its target agent:

```bash
peerspan-host --state RECEIVER_STATE grant create --peer SENDER_HOST_ID --agent TARGET_AGENT_ID --expires-at GRANT_EXPIRY --allow-disconnected
```

The sending owner can pass `--routes /absolute/destinations.json` to `session setup`. The file is a JSON array:

```json
[
  {
    "name": "bob",
    "peer_host_id": "RECEIVER_HOST_ID",
    "target_agent_id": "TARGET_AGENT_ID",
    "grant_id": "GRANT_ID",
    "expires_at": "ROUTE_EXPIRY",
    "max_message_bytes": 4096,
    "max_messages": 20
  }
]
```

Setup creates at most 100 destinations. Omitted limits default to 65536 bytes and 100 lifetime messages; omitted route expiry defaults to credential expiry. An invalid destination rolls back the whole setup. Setup grants no inbound access and creates no peer membership. For an already prepared attachment, add or inspect routes with the existing commands:

```bash
peerspan-host --state SENDER_STATE adapter route add --adapter ADAPTER_ID --name bob --peer RECEIVER_HOST_ID --agent TARGET_AGENT_ID --grant GRANT_ID --expires-at ROUTE_EXPIRY --max-message-bytes 4096 --max-messages 20
peerspan-host --state SENDER_STATE adapter route list --adapter ADAPTER_ID
```

Use `--allow-disconnected` for manually configured peers or when explicitly permitting work during a coordination outage. A recently synced enrolled peer can use a grant without it. Choose `ROUTE_EXPIRY` no later than the credential and grant expirations, and a byte bound within the receiver's grant. Configure each direction independently if both agents should initiate messages.

Ask the opted-in agent to list its Peerspan destinations and send a message to `bob`. Its `list_destinations` and `send` tools expose only the owner's named routes. The daemon persists the request before sending; replies return to the same session automatically as `kind: "reply"` events carrying the original request ID. These response events have no delivery ID for the final-reply tool. A follow-up uses another authorized `send`.

For incoming `kind: "message"` events, the `reply` tool stores one final response addressed to the original sender. The owner CLI can also send a message and inspect its reply:

```bash
peerspan-host --state SENDER_STATE message reply --peer RECEIVER_HOST_ID REQUEST_ID
peerspan-host --state RECEIVER_STATE delivery list
```

`adapter revoke ADAPTER_ID`, owner session detachment, or credential expiry stop adapter access. Grants are checked again at handoff and reply. An uncertain handoff is retained for inspection and is never automatically sent again or moved to another session. `forwarded` confirms a notification write, not model execution. See the [adapter contract](../../docs/agent-adapter-contract.md).

`adapter route revoke ROUTE_ID` stops further sends through that route. Replies to earlier sends can still return while the original credential is valid. An uncertain send reports its request ID, and the daemon retries it automatically with that same ID until it is accepted, rejected, or past its deadline. The agent follows it with `send_status`. Only a send the host never recorded (`send_status` reports `not_recorded`) needs an explicit retry, with the same ID and identical destination/content. Each new persisted request uses one lifetime budget unit, including failed or rejected attempts; automatic and explicit retries of the same request use none. See the [outbound contract](../../docs/adapter-outbound-contract.md).

The adapter exposes `peerspan_ready`, `mark_seen`, `pending_work`, `list_destinations`, `send`, `send_status`, and `reply`, plus the [task](../../docs/task-contract.md) tools `task_accept`, `task_reject`, `task_progress`, `task_complete`, `task_cancelled`, `delegate_task` (through a route added with `--action task.submit`), `task_status`, and `artifact_save`, and omits permission-relay capability. Tasks arrive as `kind: "task"` events, cancellation requests as `kind: "task_cancel_requested"`, and updates on delegated tasks as `kind: "task_update"`. [Task artifacts](../../docs/artifact-contract.md), when the receiving owner allows them, are listed in `meta.artifacts` of task events and final updates (as JSON text, since Claude Code requires string meta values; null fields are omitted); `delegate_task` and `task_complete` take `artifacts` file paths, which the adapter reads with the session's own permissions and uploads, and `artifact_save` writes a received file to a new path. `mark_seen` reports events the model will not otherwise answer; when a session ends, the host redelivers items it never saw to the agent's next session with `meta.redelivered` (as `"true"`), and that session adopts the agent's running tasks, announced as `kind: "task"` events with `meta.adopted`, `meta.state`, and `meta.progress`. `pending_work` lists owed deliveries, replies, and tasks. Message access does not give a peer shell or filesystem access through Peerspan; the existing agent still has whatever local permissions its owner granted it.

## Connection recovery and token rotation

The adapter binds a random process-instance secret kept in memory and renews a 15-second lease every five seconds. Inspect connectivity with `adapter connection ADAPTER_ID`: `registered` means no adapter has connected; `ready` means its lease is valid; `offline` means a bound adapter needs to reconnect. Detachment, revocation, and expiration are reported separately. These describe the adapter connection, not whether the model is busy or has executed a message.

Restarting the daemon invalidates leases. Previously bound, recoverable adapters get 15 seconds to reconnect before `adapter create` can replace them. This window does not grant a live lease. The same running adapter reconnects with its instance secret and recovers its original attachment, requests, and replies. Replacing the adapter subprocess requires an explicitly authorized fresh attachment; an existing credential file alone cannot take over its instance. Owner detachment also stops recovery when the daemon has already marked that session detached.

If the old adapter has exited, attach a fresh session and issue its credential using the setup commands above. Once the old lease has expired (at most 15 seconds after its last renewal) and any startup reconnect window has ended, `adapter create` retires the old authorization atomically and reports `replaced_adapter_ids`. It does not require a separate `session detach`. To replace it immediately during the window, explicitly detach its old session or revoke its credential first. The old adapter loses reconnect access; its pending work and outbound routes remain with its original session. Configure destinations for the new session explicitly. A still-valid lease or an authorization that has never connected remains protected; the conflict explains how to proceed.

Owners can rotate the token while keeping the original authorization ID, expiry, instance, routes, and budgets. Replace the private credential file atomically:

```bash
peerspan_credential_next=$(mktemp /absolute/session-setup/.credential.XXXXXX)
peerspan-host --state STATE adapter rotate ADAPTER_ID > "$peerspan_credential_next" &&
  mv "$peerspan_credential_next" /absolute/session-setup/credential.json
```

The running adapter reloads only the same authorization and session. The old token immediately loses access; the adapter allows up to 30 seconds for its replacement file. Rotation does not extend authorization lifetime. Inspect an agent-originated request with `message origin --peer HOST REQUEST_ID`, including an uncertain reply-notification handoff. See the [recovery contract](../../docs/adapter-recovery-contract.md).

## Verify

From the repository root:

```bash
npm --prefix integrations/claude-channel test
```

End-to-end behaviour through the host (delivery, readiness, redelivery, tools) is covered by the [slim conformance suites](../../conformance/slim/), mainly `live`, `work` and `capabilities`, which CI runs. The earlier Python integration and live-run suites were removed ([DEC-OWN10](../../docs/decision-log.md)); live runs with real models are manual checks.

Installation must preserve the sibling `integrations/shared/` directory, which contains the harness-independent scoped adapter. The MCP transport and Claude launch configuration remain in this bundle.
