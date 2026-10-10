# Live delivery contract

Roadmap milestone 9. The design and its settled decisions are in the [live delivery proposal](live-delivery-proposal.md). It extends the [agent adapter](agent-adapter-contract.md), [outbound](adapter-outbound-contract.md), [recovery](adapter-recovery-contract.md), [task](task-contract.md), [harness integration](harness-integration-contract.md), and [launch](launch-contract.md) contracts; where they differ, this contract applies. The behavior is the same in Go and Rust hosts and in the shared Node adapter.

## Slice 1: readiness and diagnostics

### Handshake

- **Hello event.** After MCP initialization, the adapter connects as before. It then emits one channel event with `meta.kind` `hello` and `meta.nonce`, a fresh 128-bit hex value, before claiming any work. The event's content asks the model to call `capsule_ready` with that nonce now, and says that no messages arrive until it does.
- **`capsule_ready`.** The tool takes `{nonce}`. A matching nonce makes the adapter post `POST /adapter/v1/ready` with `{nonce}`, start claiming work, and return `{ready: true}`. A wrong nonce returns a tool error and changes nothing. A repeated call after readiness returns `{ready: true}`.
- **Daemon.** The daemon stores `channel_verified_at` on the adapter's authorization. The route requires the adapter's credential and lease, as `/adapter/v1/next` does, and is idempotent.
- **Work routes.** Until the authorization is verified, `/adapter/v1/next`, `/adapter/v1/tasks/next`, `/adapter/v1/tasks/cancels/next`, and `/adapter/v1/replies/next` answer 409 with `{error: "channel not verified"}` and claim nothing. Outbound tools work before verification.
- **Re-sending hello.** If the model has not called `capsule_ready` within 60 seconds, the adapter emits the hello event once more with the same nonce, and then never again. It keeps its lease and keeps waiting.
- **Recovery.** Verification belongs to the authorization, so an adapter recovering its session after a daemon restart (recovery contract) stays verified. A new authorization, from `attach` or `session start`, starts unverified.

### Connected and status

- **Directory.** A directory entry's `connected` is true only when the agent has an attached session whose adapter holds a valid lease and whose authorization is verified. Entries gain `channel`: `verified`, `unverified` (a lease but no verification), or null (no lease).
- **Status item 13.** `GET /v1/status` and `status` add `channel_unverified`. It is added by the daemon for each authorization whose adapter has held a lease for more than 120 seconds without verification. Its subject is `AGENT_NAME`, and its command is `capsule session doctor`. Its message names the likely causes: the organization has not enabled channels (`channelsEnabled`), the provider does not support channels, the Claude Code version is older than the minimum, or the session was started without the channel flag.
- **Session lists.** `session doctor` and `session list` report `channel` the same way.

### Doctor

`session doctor` (and the harness `doctor`) gains these checks:
- **`claude_version`:** the executable's `--version` output, run with no other arguments, must parse as `X.Y.Z` and be at least **2.1.187**. Otherwise it fails, naming the minimum.
- **`claude_account`:** from `claude auth status` (JSON), a warning (not a failure) when `apiProvider` is not `firstParty` ("channels are not available on this provider") or `subscriptionType` is `team` or `enterprise` ("an organization Owner must enable channels").
- **`channel`:** `verified`, `unverified`, or `not running`. `unverified` fails with the item 13 message.
- **`mcp_protocol`:** the adapter reports the protocol revision it negotiated in `POST /adapter/v1/connect` as `protocol_version`, and the daemon stores it. Doctor fails when it is `2026-07-28` or later. The adapter's MCP SDK stays on major version 1.

`adapter_ready` now also requires `channel` `verified`.

### Launch

- **Environment.** The Claude integration launches Claude Code with `MCP_PROTOCOL_NEGOTIATION=legacy` in its environment, in addition to the existing arguments.
- **Instructions.** The MCP server instructions are at most 2,048 characters. Guidance that does not fit moves into the descriptions of the tools it concerns (`delegate_task`, `artifact_save`, the `task_*` tools), with no change in meaning.

### Fatal stops

When the adapter stops polling for good (a 409 or 400 from the daemon that the recovery contract treats as final, or a replaced instance), it:
1. emits one channel event with `meta.kind` `disconnected` and content saying Capsule is disconnected and how to reattach (`capsule attach NAME`);
2. writes the reason to stderr;
3. exits with status 1 after the event is written, so Claude Code shows the server as failed.

### Deadlines

Adapter sends by address, and sends through routes, default to a 1-hour deadline (previously 5 minutes), bounded by the credential's expiry. Explicit deadlines are unchanged.

### Shared state

The shared schema moves to version 14. It adds `channel_verified_at` and `protocol_version` to adapter authorizations. Existing authorizations migrate as unverified.

### Verification

`conformance/live_delivery.py` is written from this contract by an author independent of all implementations. It runs every Go/Rust CLI and daemon pairing with `--probe`, the Go coordinator, `--node`, and OpenSSH, using a deterministic MCP consumer that can choose whether to call `capsule_ready`. It covers:
- **Handshake:**
  - the hello event first, with its nonce;
  - work routes answering 409 before verification;
  - a wrong nonce;
  - the single re-sent hello after 60 seconds;
  - work flowing after `capsule_ready`;
  - verification surviving a daemon restart, and a new attachment starting unverified.
- **Connected:** `connected` and `channel` in `GET /v1/directory` on another host, before and after verification, and item 13 after 120 seconds unverified.
- **Doctor:** a fixture `claude` executable reporting versions below and at the minimum, and `auth status` accounts that trigger each warning.
- **Protocol:** `protocol_version` recorded, and doctor failing a fixture adapter that reports `2026-07-28`.
- **Launch:** the launch environment includes `MCP_PROTOCOL_NEGOTIATION=legacy`, and the instructions are at most 2,048 characters.
- **Fatal stop:** a `disconnected` event and exit 1 on a replaced instance.
- **Deadlines:** the default deadline of agent sends by address and through routes.
- **Migration:** schema version 14 from 13.

Existing suites that assume work flows without `capsule_ready` are updated to call it.

`conformance/live_launch_agents.py` repeats its live run with real Claude Code sessions. It also records that each session called `capsule_ready` and that no item 13 appeared.

## Slice 2: seen, redelivery, adoption, and pending work

### Seen

Every delivered item has a `seen_at`, set by the daemon when the session that holds it reports it seen:
- **Inbound delivery:** `reply` with its `delivery_id`, or `mark_seen`.
- **Reply to the session's own send:** `mark_seen` with its `request_id`, or `send_status` naming it.
- **Task:** `task_accept` or `task_reject`.
- **Task update or cancellation request:** `mark_seen` with its `task_id`, or any `task_*` call on that task after the update was forwarded.

New tool `mark_seen` takes `{ids}`, 1 to 100 delivery, request, or task IDs that this session holds. It returns `{seen: [ids]}` and ignores IDs already seen. The instructions ask the model to call it for events it will not otherwise answer. Adapter route: `POST /adapter/v1/seen` with `{ids}`.

### Redelivery

When an authorization ends, whether replaced by a new attachment of the same agent, expired, or revoked, every item it was forwarded but never saw returns to the agent's queue, if its deadline has not passed. The next verified session of the same agent receives it again with `meta.redelivered` `true`.
- A sender's view of a returned message is unchanged: it stays accepted.
- An item is redelivered at most 3 times. After that it is `blocked` for messages, and `failed` with `session never saw the task` for tasks.
- Items that were seen are never redelivered.
- Revocation of the sender's access still blocks queued delivery, as before.

### Adoption

When an authorization of an agent is verified, it adopts the tasks claimed by the agent's ended authorizations that are `running` or `cancel_requested`. For each adopted task, the session receives a `kind=task` event with `meta.adopted` `true`, its current state, and its latest progress. From then on, only the adopting session may change the task. A delegation chain whose link was adopted continues unchanged. Adoption never moves a task between agents.

### Pending work

New tool `pending_work` returns `{deliveries, replies, tasks}` for this agent:
- `deliveries`: unanswered inbound deliveries held by this session, with `delivery_id`, sender address, a preview of the content (first 200 characters), `seen`, and `deadline`;
- `replies`: unseen replies to this agent's sends;
- `tasks`: tasks in `queued` (offered to this session), `running`, or `cancel_requested` held by this session, with `task_id`, state, summary, and `deadline`.

Adapter route: `GET /adapter/v1/pending`.

The Claude integration's launch adds `--settings` with a JSON file in the session profile directory. The file holds a `SessionStart` hook for the matchers `clear`, `compact`, and `resume`. The hook gives the model the `pending_work` result as additional context, either through an `mcp_tool` hook calling `pending_work` or through a command hook running `capsule session pending --json` for this profile. It changes no global or project Claude Code settings. `capsule session pending [--json]` prints the same object for the current directory's attachment.

### Shared state

The shared schema moves to version 15. It adds `seen_at` and `redeliveries` to handed-off items, and records the adopting authorization on tasks.

### Verification

`conformance/live_delivery.py` gains these cases, across the same pairings:
- **Seen:** set by `reply`, `mark_seen`, `send_status`, and the `task_*` tools.
- **Redelivery after replacement:** a message, a reply, and a task forwarded but unseen are redelivered to the next attachment with `redelivered`, and never to the sender twice. Seen items are not redelivered.
- **Limits:** the redelivery limit of 3, deadlines passing while queued, and revocation blocking a returned message.
- **Adoption:** a running and a cancel-requested task adopted by the new attachment, the old authorization unable to change them, and a two-link delegation chain completing after the middle agent's session is replaced.
- **Pending work:** `pending_work` contents, and `capsule session pending --json`.
- **Launch settings:** the `--settings` file's hook matchers.
- **Migration:** schema version 15 from 14.

`conformance/live_launch_agents.py` adds a case that runs `/clear` in one real session mid-task and checks the model still completes the task.
