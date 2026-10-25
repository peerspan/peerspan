# Live delivery contract

Roadmap milestone 9. The design and its settled decisions are in the [live delivery proposal](live-delivery-proposal.md). It extends the [agent adapter](agent-adapter-contract.md), [outbound](adapter-outbound-contract.md), [recovery](adapter-recovery-contract.md), [task](task-contract.md), [harness integration](harness-integration-contract.md), and [launch](launch-contract.md) contracts; where they differ, this contract applies. The behavior is the same in Go and Rust hosts and in the shared Node adapter.

## Slice 1: readiness and diagnostics

### Handshake

- **Hello event.** After MCP initialization, the adapter connects as before. It then emits one channel event with `meta.kind` `hello` and `meta.nonce`, a fresh 128-bit hex value, before claiming any work. The event's content asks the model to call `peerspan_ready` with that nonce now, and says that no messages arrive until it does.
- **`peerspan_ready`.** The tool takes `{nonce}`. A matching nonce makes the adapter post `POST /adapter/v1/ready` with `{nonce}`, start claiming work, and return `{ready: true}`. A wrong nonce returns a tool error and changes nothing. A repeated call after readiness returns `{ready: true}`.
- **Daemon.** The daemon stores `channel_verified_at` on the adapter's authorization, keeping the first time. The adapter connection object (`GET /v1/adapters/{id}/connection`) gains `channel`, `channel_verified_at`, and `protocol_version`, and session objects from the session routes (`/v1/sessions`, `/v1/sessions/{id}`, attach, detach, setup, and `/adapter/v1/session`) gain `channel`. The session views inside `GET /v1/status` are unchanged; item 13 covers them. The route requires the adapter's credential and lease, as `/adapter/v1/next` does, and is idempotent.
- **Work routes.** Until the authorization is verified, `/adapter/v1/next`, `/adapter/v1/tasks/next`, `/adapter/v1/tasks/cancels/next`, `/adapter/v1/task-updates/next`, and `/adapter/v1/replies/next` answer 409 with `{code: "conflict", error: "channel not verified"}` and claim nothing. Outbound tools work before verification.
- **Re-sending hello.** If the model has not called `peerspan_ready` within 60 seconds, the adapter emits the hello event once more with the same nonce, and then never again. It keeps its lease and keeps waiting.
- **Recovery.** Verification belongs to the authorization, so an adapter recovering its session after a daemon restart (recovery contract) stays verified. A new authorization, from `attach` or `session start`, starts unverified.

### Connected and status

- **Directory.** A directory entry's `connected` is true only when the agent has an attached session whose adapter holds a valid lease and whose authorization is verified. Entries gain `channel`: `verified`, `unverified` (a lease but no verification), or null (no lease).
- **Status item 13.** `GET /v1/status` and `status` add `channel_unverified`. It is added by the daemon for each authorization that holds a lease, is unverified, and first connected more than 120 seconds ago (counted from the authorization's first connection, not its latest reconnection). Its subject is `AGENT_NAME`, and its command is `peerspan session doctor`. Its message names the likely causes: the organization has not enabled channels (`channelsEnabled`), the provider does not support channels, the Claude Code version is older than the minimum, or the session was started without the channel flag.
- **Session lists.** `session doctor` and `session list` report `channel` the same way.

### Doctor

`session doctor` (and the harness `doctor`) gains these checks:
- **`claude_version`:** the executable's `--version` output, run with no other arguments, must parse as `X.Y.Z` and be at least **2.1.187**. Otherwise it fails, naming the minimum.
- **`claude_account`:** from `claude auth status` (JSON), a warning when `apiProvider` is present and not `firstParty` ("channels are not available on this provider"), or when `subscriptionType` is `team` or `enterprise` ("an organization Owner must enable channels"). A warning is a passing check whose detail starts with `Warning: `, since helper checks are `ok` or `error`.
- **`channel`:** `verified`, `unverified`, or `not running`. `unverified` fails with the item 13 message; `not running` passes, so `session start` can run the same checks before launching. Integration checks appear with the CLI's usual `harness/` prefix.
- **`mcp_protocol`:** the adapter reports, as `protocol_version` in `POST /adapter/v1/connect`, the revision of the protocol through which the harness reaches Peerspan's tools, and the daemon stores the latest value reported. A connect without `protocol_version` leaves the stored value unchanged. The value depends on the integration (settled with the owner on 2026-10-25; see the [proposal's decisions](live-delivery-proposal.md#decisions)):
  - **Claude Code:** the MCP revision `channel.mjs` negotiated with Claude Code in `initialize`; the first connect carries it.
  - **Codex:** the MCP revision the Peerspan MCP server (`mcp.mjs`) negotiated with Codex in `initialize` (`2025-06-18` with Codex 0.160.0). `mcp.mjs` sends it as `protocol_version` in each `POST /tool` on the tool socket; the sidecar accepts it only from a call whose `_meta.threadId` is the selected thread, so it is known from the first tool call, normally `peerspan_ready`.
  - **OpenCode:** OpenCode reaches the tools through its native plugin API, not MCP. The value is `opencode-plugin-VERSION`, where VERSION is the server version from `GET /global/health` that the sidecar checks before connecting; the first connect carries it.

  Whenever the value differs from the one it last reported, the adapter connects again before its next daemon request, so the daemon stores it before `POST /adapter/v1/ready` records verification. Doctor's detail names the stored value, or says none has been reported yet; a missing value is not a failure. Doctor fails only when the harness is Claude Code (`claude-code`) and the value is a date of `2026-07-28` or later; for other harnesses it reports the value and passes. The adapter's MCP SDK stays on major version 1.

`adapter_ready` now also requires `channel` `verified`.

### Launch

- **Environment.** The Claude integration launches Claude Code with `MCP_PROTOCOL_NEGOTIATION=legacy` in its environment (through `env` in the launch command), in addition to the existing arguments.
- **Instructions.** The MCP server instructions are at most 2,048 characters. Guidance that does not fit moves into the descriptions of the tools it concerns (`delegate_task`, `artifact_save`, the `task_*` tools), with no change in meaning.

### Fatal stops

When the adapter stops polling for good (a 409 or 400 from the daemon that the recovery contract treats as final, or a replaced instance), it:
1. emits one channel event with `meta.kind` `disconnected` and content saying Peerspan is disconnected and how to reattach (`peerspan attach HARNESS` in the project);
2. writes the reason to stderr;
3. exits with status 1 after the event is written, so Claude Code shows the server as failed.

### Deadlines

Adapter sends by address, and sends through routes, default to a 1-hour deadline (previously 5 minutes), bounded by the credential's expiry and, for routes, the route's expiry, whichever is earliest. Explicit deadlines are unchanged.

### Shared state

The shared schema moves to version 14. It adds `channel_verified_at` and `protocol_version` to adapter authorizations. Existing authorizations migrate as unverified.

### Verification

`conformance/live_delivery.py` is written from this contract by an author independent of all implementations. It runs every Go/Rust CLI and daemon pairing with `--probe`, the Go coordinator, `--node`, and OpenSSH, using a deterministic MCP consumer that can choose whether to call `peerspan_ready`. It covers:
- **Handshake:**
  - the hello event first, with its nonce;
  - work routes answering 409 before verification;
  - a wrong nonce;
  - the single re-sent hello after 60 seconds;
  - work flowing after `peerspan_ready`;
  - verification surviving a daemon restart, and a new attachment starting unverified.
- **Connected:** `connected` and `channel` in `GET /v1/directory` on another host, before and after verification, and item 13 after 120 seconds unverified.
- **Doctor:** a fixture `claude` executable reporting versions below and at the minimum, and `auth status` accounts that trigger each warning.
- **Protocol:** `protocol_version` recorded; doctor failing a fixture adapter of a `claude-code` session that reports `2026-07-28`, and passing a fixture adapter of another harness that reports it; a fixture adapter that connects without `protocol_version` and later learns one having it stored before `POST /adapter/v1/ready`, and keeping it across a later connect without the field.
- **Launch:** the launch environment includes `MCP_PROTOCOL_NEGOTIATION=legacy`, and the instructions are at most 2,048 characters.
- **Fatal stop:** a `disconnected` event and exit 1 on a replaced instance.
- **Deadlines:** the default deadline of agent sends by address and through routes.
- **Migration:** schema version 14 from 13.

Existing suites that assume work flows without `peerspan_ready` are updated to call it.

`conformance/live_launch_agents.py` repeats its live run with real Claude Code sessions. It also records that each session called `peerspan_ready` and that no item 13 appeared.

## Slice 2: seen, redelivery, adoption, and pending work

### Seen

Every delivered item has a `seen_at`, set by the daemon when the session that holds it reports it seen:
- **Inbound delivery:** `reply` with its `delivery_id` (a refused reply does not count), or `mark_seen`.
- **Reply to the session's own send:** `mark_seen` with its `request_id`, or `send_status` naming it.
- **Task:** `task_accept` or `task_reject`.
- **Task update or cancellation request:** `mark_seen` with its `task_id`, or any `task_*` call on that task after the update was forwarded.

New tool `mark_seen` takes `{ids}`, 1 to 100 delivery, request, or task IDs that this session holds. It returns `{seen: [ids]}` and ignores IDs already seen. If any ID is not held by this session, the route answers 404 and marks none. The instructions ask the model to call it for events it will not otherwise answer. Adapter route: `POST /adapter/v1/seen` with `{ids}`.

### Redelivery

When an authorization ends, whether replaced by a new attachment of the same agent, expired, or revoked, every item it was forwarded but never saw returns to the agent's queue, if its deadline has not passed. The next verified session of the same agent receives it again with `meta.redelivered` `true`.
- A sender's view of a returned message is unchanged: it stays accepted.
- An item is redelivered at most 3 times, so at most four sessions hold it in all. When the fourth ends without seeing it, it is `blocked` for messages, and `failed` with `session never saw the task` for tasks.
- Items that were seen are never redelivered.
- Revocation of the sender's access still blocks queued delivery, as before.

These rules settle the details:
- **When items return.** Returns happen when a verified session of the agent next claims work or lists `pending_work`: every unseen item held by the agent's ended authorizations (replaced, detached, revoked, or expired) returns then. Ending an authorization may also return them at once; the result is the same.
- **Forwarded means claimed.** An item counts as forwarded once its session claimed it, including a delivery whose forwarding the adapter never confirmed, and a task or cancellation, which have no confirmation.
- **Deadlines while returned.** A returned message or task whose deadline passes is handled as a queued one is today: it is not redelivered, and the sender's view follows the existing deadline rules.
- **Replies and task updates** have no deadline of their own. Past the limit of 3 they are no longer offered and stay unseen; the sender's view is unchanged.
- **Late arrivals.** A reply or task event that arrives after the authorization it belongs to has ended goes to the agent's next verified session, with `redelivered` `false`, since it was never forwarded. An adopted task's later updates and its children's updates go to the adopting session.
- **Adoption happens at the claim** through `/adapter/v1/tasks/next`, which only a verified session reaches.
- **A task past the limit** is still `queued`, since it was never accepted; it moves from `queued` to `failed` with error `session never saw the task`, emitting the usual `failed` event to its sender. This is a new receiver-side transition.
- **Upgrades.** Migration to version 15 marks every existing handed-off item seen, so nothing from before the upgrade is redelivered.
- **Owner output** (`GET /v1/deliveries` and similar records) is unchanged.
- **`message origin`** keeps the original authorization and session of the send, also after a later session claims its reply. Its `reply_delivery` names the session that holds the reply now.

### Adoption

When an authorization of an agent is verified, it adopts the tasks claimed by the agent's ended authorizations that are `running` or `cancel_requested`. For each adopted task, the session receives a `kind=task` event with `meta.adopted` `true`, its current state, and its latest progress (see Events). From then on, only the adopting session may change the task. A delegation chain whose link was adopted continues unchanged. Adoption never moves a task between agents.

### Pending work

New tool `pending_work` returns `{deliveries, replies, tasks}` for this agent. Field names match the channel event `meta` the model already saw, and each list is ordered oldest first, by when the item first reached this host (so returned and adopted items keep their place):
- `deliveries`: unanswered inbound deliveries held by this session, each `{delivery_id, request_id, sender_host_id, origin_agent_id, preview, seen, deadline, redelivered}`;
- `replies`: unseen replies to this agent's sends held by this session, each `{notification_id, request_id, peer_host_id, preview}`;
- `tasks`: tasks in `queued` (offered to this session), `running`, or `cancel_requested` held by this session, each `{task_id, delivery_id, sender_host_id, state, preview, deadline, adopted}`. Here and in event `meta`, `state` is `cancel_requested` for a running task whose cancellation was requested.

`preview` is the first 200 characters of the content (a task's `input`). `deadline` is null when the item has none. An answered delivery is one the session has replied to.

Adapter route: `GET /adapter/v1/pending`.

The Claude integration's launch adds `--settings PATH`, where PATH is `claude-settings.json` in the session profile directory, written at launch with mode 0600:

```json
{"hooks": {"SessionStart": [{"matcher": "clear|compact|resume",
  "hooks": [{"type": "command", "command": "'/ABSOLUTE/PATH/peerspan' session pending --hook"}]}]}}
```

The command names the absolute path of the `peerspan` executable that launched the session, single-quoted for the shell (a `'` in it becomes `'\''`). The CLI passes that path to the integration helper as `peerspan_executable` in the `launch` request context: the running executable's absolute path (Go `os.Executable`, Rust `std::env::current_exe`), which in a bundle is `peerspan-host`, behaving the same as `peerspan`. The helper writes the file itself during `launch`. Claude Code reads a `SessionStart` hook's JSON standard output as hook output, not as context, so `--hook` wraps the list in its documented form. It changes no global or project Claude Code settings, and `--settings` among the user's extra arguments is refused, as `--mcp-config` is.

`peerspan session pending [--json | --hook]` prints the same object as `pending_work` for the current directory's attachment (an `attach` profile whose workspace is the current directory, under whichever state directory it was made, since the hook passes no `--state`; with `--state`, only that state's), read through the local administration API (`GET /v1/sessions/{id}/pending`, with the same object). Without `--json` it prints one line per item. With `--hook` it prints `{"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": TEXT}}`, where TEXT is `Peerspan work this session still owes, listed after /clear, compaction, or resume. Finish each task with the task_* tools and answer each delivery with reply; call pending_work for the current list. ` followed by the object as compact JSON; when all three lists are empty, it prints nothing. With no attachment for the directory, it prints nothing and exits 0, so the hook never fails a session start.

### Events

The daemon's handoff objects from `/adapter/v1/next`, `/adapter/v1/replies/next`, and `/adapter/v1/tasks/next` gain a top-level `redelivered` boolean, and task handoffs also gain `adopted` (boolean) and `progress` (the latest progress message, or null). The adapter copies them into `meta`. A redelivered `message`, `reply`, or `task` event carries `meta.redelivered` `true`; others carry `false`. An adopted task's `task` event carries `meta.adopted` `true`, `meta.state` (`running` or `cancel_requested`), and `meta.progress` (the latest progress message, omitted when there is none, since Claude Code channel meta values are strings); other `task` events carry `adopted` `false`. The adapter derives `meta.state` from the handoff's `status`.

### Shared state

The shared schema moves to version 15. It adds `seen_at` and `redeliveries` to handed-off items, and records the adopting authorization on tasks.

The additions are columns, not record fields. Handoff objects, owner records, and the task delivery and notification records keep their current fields, and `received_tasks` records are unchanged, since they are also the peer status record. All columns are added with `ALTER TABLE ... ADD COLUMN`:
- `deliveries`, `task_update_notifications`: `seen_at TEXT`, `redeliveries INTEGER NOT NULL DEFAULT 0`, `returned_at TEXT`.
- `task_deliveries`: the same three, plus `cancel_seen_at TEXT` and `adopted_at TEXT`.
- `adapter_outbound`, for the reply notification in `reply_delivery`: `reply_seen_at TEXT`, `reply_redeliveries INTEGER NOT NULL DEFAULT 0`, `reply_returned_at TEXT`.

Times are RFC3339 text, as in records, and null means not yet:
- `seen_at` (`reply_seen_at`): when the holding session reported the item seen, as listed under Seen. For a task delivery it is the task itself; `cancel_seen_at` is its cancellation request.
- `returned_at` (`reply_returned_at`): when the item went back to the agent's queue because its holding authorization ended while it was unseen. While set, no session holds the item, and only a verified session of the same agent may claim it. A claimed task still `running` returns in the same way, for adoption. A claim clears it.
- `redeliveries` (`reply_redeliveries`): how many times the item was claimed again after a return. Each such claim adds 1, except an adoption. An item whose count is already 3 is not returned. `redelivered` is `redeliveries > 0`.
- `adopted_at`: when the current holder adopted the task, by claiming it after a return while `running`; null when the holder claimed it while `queued`. `adopted` is `adopted_at` not null.

A claim of a returned item keeps its row and ID (`delivery_id`, `notification_id`) and rebinds it in place: `adapter_id`, `session_id`, and `updated_at` in the record where present, the `session_id` column, and `state` back to `unknown` where the record has one. `cancel_claimed_at` and `cancel_seen_at` are kept, so the adopting session still claims a cancellation request nobody claimed. An ended authorization therefore resolves none of its returned items.

Migration from 14 reads each table's columns through `pragma_table_info` and adds only those missing, as version 14 did, then sets `PRAGMA user_version = 15`. Existing rows take 0 redeliveries and null `returned_at` and `adopted_at`, and the migration sets each seen column (`seen_at`, `cancel_seen_at`, `reply_seen_at`) to the migration time, so nothing from before the upgrade is redelivered. No index is added.

### Verification

`conformance/live_delivery.py` gains these cases, across the same pairings:
- **Seen:** set by `reply`, `mark_seen`, `send_status`, and the `task_*` tools.
- **Redelivery after replacement:** a message, a reply, and a task forwarded but unseen are redelivered to the next attachment with `redelivered`, and never to the sender twice. Seen items are not redelivered.
- **Limits:** the redelivery limit of 3, deadlines passing while queued, and revocation blocking a returned message.
- **Adoption:** a running and a cancel-requested task adopted by the new attachment, the old authorization unable to change them, and a two-link delegation chain completing after the middle agent's session is replaced.
- **Pending work:** `pending_work` contents, `peerspan session pending --json`, and `--hook` output, including nothing when no work is pending.
- **Launch settings:** the `--settings` file's hook matchers.
- **Migration:** schema version 15 from 14.

`conformance/live_launch_agents.py` adds a case that runs `/clear` in one real session mid-task and checks the model still completes the task.
