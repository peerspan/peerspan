# Task delegation contract

Roadmap milestone 6, slice 2: single-hop tasks. The design and its settled decisions are in the [delegation proposal](delegation-proposal.md). This contract builds on the [messaging contract](peer-messaging-contract.md), including agent origin, retry, and the QUIC transport, and on owner access policy in the [coordination contract](coordination-contract.md). Artifacts (slice 3) and delegation chains (slice 4) extend it later. Until then, task requests carry neither.

## Model

A task is work that one host's agent, the **submitter**, asks an agent on another host, the **receiver**, to perform.

| State | Meaning |
| --- | --- |
| `queued` | The receiver host has durably accepted responsibility, and no agent has taken the task yet. |
| `running` | The target agent accepted the task through its adapter. |
| `rejected` | The target agent declined it, giving a reason. Final. |
| `expired` | No agent accepted it before its `deadline`. Final. |
| `succeeded` / `failed` | The agent finished it, with an output. Final. |
| `cancelled` | The agent confirmed it stopped after a cancellation request. Final. |

`cancel_requested` is a separate flag. Requesting cancellation never changes the state by itself: the agent either confirms `cancelled` or finishes anyway. Connection state and task state are independent, so a disconnect never fails a task. A host receipt (`queued`) means durable responsibility, not that work has started.

IDs are `task_` followed by 16 random bytes in lowercase hex. `input`, progress `message`, rejection `reason`, and final `output` are non-empty UTF-8 text of at most 65,536 bytes (a rejection reason may be empty). `deadline` is RFC3339, in the future at the receiver, and bounded by the authorizing grant or policy, as for messages.

## Peer routes

| Route | Body | Behavior |
| --- | --- | --- |
| `POST /peer/v1/tasks` | exactly `task_id`, `target_agent_id`, `deadline`, `input`, optional `origin`, and exactly one of `grant_id` or `policy` | Authorizes the action `task.submit` (below). Persists the task as `queued`, together with a `task.received` activity event, and returns 200 with the status record. It is idempotent by `(sender, task_id)`: identical fields return the existing record, and changed fields return 409. Validation and error codes are as for messages, including 503 for a recoverable connected state or a policy version behind the cited one. |
| `GET /peer/v1/tasks/{task_id}` | none | The status record, for the authenticated submitter only; anyone else gets 404. |
| `GET /peer/v1/tasks/{task_id}/events?after=N&limit=N` | none | A JSON array of events after cursor `N` (default 0), in sequence order, up to `limit` (default 100, 1 to 1,000). Submitter only. |
| `POST /peer/v1/tasks/{task_id}/cancel` | `{}` | Sets `cancel_requested` and records a `cancel_requested` event with the `task.cancel_requested` activity. A repeat, or a cancel of a task already final, returns the record unchanged with no event. Returns the status record. Submitter only. |

The **status record** is `{task_id, sender_host_id, receiver_host_id, target_agent_id, state, cancel_requested, created_at, updated_at, last_event}`. `last_event` is the highest event sequence, `created_at` is the time of the `queued` event, and `updated_at` is the time of the latest event. An **event** is `{sequence, kind, state, message, output, created_at}`, where `kind` is one of `queued`, `accepted`, `rejected`, `progress`, `cancel_requested`, `succeeded`, `failed`, `cancelled`, or `expired`. `state` is the task state after the event; a `cancel_requested` event carries the unchanged state. `message` carries progress text or a rejection reason, and `output` carries the final output. Fields that do not apply are null. Sequences are per task and start at 1 for `queued`.

Status, events, and cancel authorize no new work, so they remain available to the submitter after the grant or policy is revoked, as receipt lookup does.

## Authorization

Grants gain `action`, either `message.append` (the default and current behavior) or `task.submit`, set with `grant create --action`. Policy rules accept `task.submit` in `actions`. Submission and the adapter handoff check the same predicates as messages, including bounds, deadline, the connected state, the block list, and requester-agent constraints. A rule's `max_message_bytes` bounds task `input`. `access allow --action` sets a rule's actions; it is repeatable and defaults to `message.append`. Handoff and acceptance recheck authorization. A recoverable failure (503 for messages) leaves the task queued. A final denial records `rejected` with the reason `authorization lapsed before acceptance` and the `task.rejected` activity; at acceptance, the rejection is committed and the call returns 403. Once the agent has accepted, the work belongs to that agent: later revocation does not change the task's state, and only cancellation does.

## Receiver: adapter

The receiving host delivers queued tasks to an attached session of the target agent through the adapter socket, with the same credential, lease, and instance rules as message handoff.

| Adapter API | Behavior |
| --- | --- |
| `POST /adapter/v1/tasks/next` with `{}` | Claims the oldest queued task for this session's agent after rechecking authorization, or returns `null`. Claiming persists a delivery bound to this session, so the task is never offered to another session. Returns `{delivery, task, status, sender_person_id, sender_person}`, where `task` is the request as received (`grant_id` only when a grant was cited, `origin` only when present) and `status` the status record. |
| `POST /adapter/v1/tasks/{task_id}/accept` with `{}` | `queued` to `running`. |
| `POST /adapter/v1/tasks/{task_id}/reject` with `{reason}` | `queued` to `rejected`. |
| `POST /adapter/v1/tasks/{task_id}/progress` with `{message}` | Appends a progress event while `running`. Repeating the latest progress message appends nothing. |
| `POST /adapter/v1/tasks/{task_id}/complete` with `{status, output}` | `status` is `succeeded` or `failed`; `running` to that state. |
| `POST /adapter/v1/tasks/{task_id}/cancelled` with `{}` | `running` to `cancelled`; allowed only after a cancellation request. |
| `POST /adapter/v1/tasks/cancels/next` with `{}` | Claims one unseen cancellation request for this session's running tasks, oldest delivery first, and returns `{delivery, status}`, or `null`. |

The **task delivery** record is `{id, sender_host_id, task_id, target_agent_id, session_id, adapter_id, cancel_claimed_at, created_at}`, with an ID of `delivery_` and 32 hex digits. Transitions resolve `task_id` to this credential's own delivery, the oldest if two senders reused an ID. Only the session that claimed a task may change it: a task ID known on this host but claimed by another session or credential returns 403, and an unknown one 404. Every transition returns the status record. Invalid transitions return 409. Each change persists the state, its event, and its activity (`task.accepted`, `task.rejected`, `task.progress`, `task.completed`, or `task.cancelled`) in one transaction, and an identical repeat returns 200 with no change; a repeat with different content, such as another rejection reason or output, returns 409. Claims of tasks and cancellations record no activity.

A task still `queued` at its deadline, claimed or not, becomes `expired`, with an event and the `task.expired` activity. Hosts apply expiry within each task transaction and in a sweep at least every second, so accepting an expired task returns 409. The MCP adapter adds:
- an incoming event of `kind: "task"`, with the task ID, input, and the origin and sender person fields that message events carry;
- an event of `kind: "task_cancel_requested"`;
- tools `task_accept`, `task_reject`, `task_progress`, `task_complete`, and `task_cancelled`.

## Submitter: daemon, CLI, and adapter

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `task submit --peer HOST --agent ID --input TEXT [--deadline TIME] [--grant ID] [--from-agent ID [--from-session ID]] [--task ID]` | `POST /v1/tasks` | Persists the outbound task with a `task.submitted` event, then submits it. Without `--grant`, it cites the target's policy, as for messages. The deadline defaults to 1 hour. An uncertain submission is retried automatically with the same `task_id` (milestone 5 rules). Returns the local record. |
| `task list [--after N] [--limit N]` | `GET /v1/tasks` | Outbound tasks in insertion order as `[{sequence, task}]`, paged like messages. |
| `task inspect --peer HOST ID` | `GET /v1/tasks/{peer}/{id}` | The local record (below). |
| `task events --peer HOST ID [--after N]` | `GET /v1/tasks/{peer}/{id}/events` | Locally stored events. |
| `task cancel --peer HOST ID` | `POST /v1/tasks/{peer}/{id}/cancel` | Sends the cancellation request now if the submission was accepted, and returns the record. An uncertain cancel is resent by the polling worker, also after a restart. Cancelling a rejected or final task returns the record unchanged. |

`POST /v1/tasks` takes `peer_host_id`, `target_agent_id`, `input`, and optional `task_id`, `deadline`, `grant_id`, and `origin`; the daemon generates a missing ID and sets the default deadline. Reusing an ID with a different request returns 409. A deadline may not outlive the authorizing grant or policy, so the default of 1 hour needs `--deadline` under one that expires sooner.

The **local record** is `{peer_host_id, request, submit_state, status, events_after, cancel_state, adapter_id, route_id, attempts, next_attempt_at, error, status_queries}`:
- `request` is the peer request, with `grant_id` null when policy is cited;
- `submit_state` is `unknown`, `accepted`, or `rejected`, as for outbound messages: a 200 accepts, 400, 403, 404, and 409 reject, and anything else stays unknown;
- `status` is the newest remote status record seen, from any response, or null; it may run ahead of the stored events until polling catches up;
- `events_after` is the highest locally stored event sequence;
- `cancel_state` is null, `unknown`, or `sent`;
- `adapter_id` and `route_id` are set for agent-initiated tasks;
- `attempts`, `next_attempt_at`, `error`, and `status_queries` follow the retry schedule for messages. After the deadline, retries become status queries (`GET /peer/v1/tasks/{id}`), and a 200 accepts.

For every accepted task whose status is not final, the daemon polls events from the receiver. It uses at most 4 concurrent polls per daemon, with backoff from 1 second to 60 seconds, and resumes from the last stored sequence after a restart. Polls, retries, and cancel resends share those 4 slots. Events must arrive with contiguous sequences. The daemon stores them, updates `status`, and records one `task.updated` activity per stored event and per change of `submit_state`. Polling stops once a final state and all its events are stored.

Agent-initiated tasks use adapter routes. Routes now carry an `action`, `message.append` (the default) or `task.submit`, set with `adapter route add --action` or in session setup, and shown in route records and destinations. Sending a message through a `task.submit` route, or delegating through a `message.append` route, returns 403. A route's `max_messages` budget counts both.

| Adapter API | Behavior |
| --- | --- |
| `POST /adapter/v1/delegations` with `{destination, task_id, input}` | Submits through the named route, with the session's agent and session as `origin`, the route's grant or policy citation, and a deadline of 1 hour or the route's expiry, whichever is sooner. Ownership and repeats follow adapter sends. Returns the local record. MCP `delegate_task`. |
| `GET /adapter/v1/delegations/{task_id}` | The local record of a task this credential submitted, or 404. MCP `task_status`. |
| `POST /adapter/v1/task-updates/next` with `{}` | Claims the oldest stored event, `queued` included, of a task this credential submitted from this session, and returns `{delivery, event}`, or `null`. |
| `POST /adapter/v1/task-updates/{id}/forwarded` with `{}` | Marks the notification forwarded. Idempotent; 404 for another credential. |

The **task-update notification** is `{id, peer_host_id, task_id, sequence, adapter_id, session_id, state, created_at, updated_at}`, with an ID of `notification_` and 32 hex digits, and `state` `unknown` or `forwarded`, following the reply-notification rules. The originating session receives each as a `kind: "task_update"` event, with the task ID, event kind, state, and message or output.

## Persistence

Database version 9 adds:

```sql
CREATE TABLE received_tasks (sender TEXT NOT NULL, task_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, task_id));
CREATE TABLE task_events (sender TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, task_id, sequence));
CREATE TABLE outbound_tasks (peer TEXT NOT NULL, task_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, task_id));
CREATE TABLE outbound_task_events (peer TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, task_id, sequence));
CREATE TABLE task_deliveries (id TEXT PRIMARY KEY, sender TEXT NOT NULL, task_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, task_id));
CREATE TABLE task_update_notifications (id TEXT PRIMARY KEY, peer TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, UNIQUE(peer, task_id, sequence));
PRAGMA user_version = 9;
```

Records are JSON, as elsewhere. Older binaries reject version 9, and version 9 binaries reject version 10. Grant records already carried `action`, always `message.append` until now. Route records gain `action`, and an older route without one reads as `message.append`. New activity kinds:
- `task.submitted` and `task.updated` (sender side);
- `task.received`, `task.accepted`, `task.rejected`, `task.progress`, `task.completed`, `task.cancel_requested`, `task.cancelled`, and `task.expired` (receiver side).

Each subject is the other host ID and the task ID.

## Verification

`conformance/tasks.py` runs every Go/Rust pairing, with deterministic adapter consumers and no model calls. It covers:
- authorization: by grant with `--action task.submit`, by policy with `task.submit`, and refusal under a `message.append`-only grant;
- duplicate and conflicting submission;
- a lost submit response recovered by automatic retry;
- the full lifecycle: queued, accepted, progress, succeeded;
- rejection, expiry, and failure;
- cancellation: requested and confirmed, and requested but completed anyway;
- event cursors resumed after a submitter restart, and a receiver restart preserving state;
- refusal of transitions by another session or credential;
- revocation before acceptance recording `rejected`, while an accepted task keeps running;
- status and events from a non-submitter returning 404;
- an agent-initiated `delegate_task` through a route, with `task_update` events back to the originating session;
- migration from version 8 to version 9.
