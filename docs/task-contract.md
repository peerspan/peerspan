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
| `GET /peer/v1/tasks/{task_id}/events?after=N&limit=N` | none | Events after cursor `N`, in sequence order, up to `limit` (default 100, maximum 1,000). Submitter only. |
| `POST /peer/v1/tasks/{task_id}/cancel` | `{}` | Sets `cancel_requested` and records an event. Idempotent. Returns the status record. Submitter only. |

The **status record** is `{task_id, sender_host_id, receiver_host_id, target_agent_id, state, cancel_requested, created_at, updated_at, last_event}`. `last_event` is the highest event sequence. An **event** is `{sequence, kind, state, message, output, created_at}`, where `kind` is one of `queued`, `accepted`, `rejected`, `progress`, `cancel_requested`, `succeeded`, `failed`, `cancelled`, or `expired`. `message` carries progress text or a rejection reason, and `output` carries the final output. Fields that do not apply are null. Sequences are per task and start at 1 for `queued`.

Status, events, and cancel authorize no new work, so they remain available to the submitter after the grant or policy is revoked, as receipt lookup does.

## Authorization

Grants gain `action`, either `message.append` (the default and current behavior) or `task.submit`, set with `grant create --action`. Policy rules accept `task.submit` in `actions`. Submission and the adapter handoff check the same predicates as messages, including bounds, deadline, the connected state, the block list, and requester-agent constraints. A rule's `max_message_bytes` bounds task `input`. Handoff rechecks authorization, and an authorization that lapses before an agent accepts the task records `rejected`, with a reason naming the lapse. Once the agent has accepted, the work belongs to that agent: later revocation does not change the task's state, and only cancellation does.

## Receiver: adapter

The receiving host delivers queued tasks to an attached session of the target agent through the adapter socket, with the same credential, lease, and instance rules as message handoff.

| Adapter API | Behavior |
| --- | --- |
| `POST /adapter/v1/tasks/next` | Claims the oldest queued task for this session's agent after rechecking authorization, or returns `null`. Claiming persists a delivery bound to this session, so the task is never offered to another session. Returns `{delivery, task, sender_person_id, sender_person}`. |
| `POST /adapter/v1/tasks/{task_id}/accept` | `queued` to `running`. |
| `POST /adapter/v1/tasks/{task_id}/reject` with `{reason}` | `queued` to `rejected`. |
| `POST /adapter/v1/tasks/{task_id}/progress` with `{message}` | Appends a progress event while `running`. |
| `POST /adapter/v1/tasks/{task_id}/complete` with `{status, output}` | `status` is `succeeded` or `failed`; `running` to that state. |
| `POST /adapter/v1/tasks/{task_id}/cancelled` | `running` to `cancelled`; allowed only after a cancellation request. |
| `POST /adapter/v1/tasks/cancels/next` | Claims one unseen cancellation request for this session's running tasks, or returns `null`. |

Only the session that claimed a task may change it. Invalid transitions return 409. Each change persists the state and its event in one transaction, and an identical repeat is idempotent. A task still `queued` at its deadline becomes `expired`, with an event. The MCP adapter adds:
- an incoming event of `kind: "task"`, with the task ID, input, and the origin and sender person fields that message events carry;
- an event of `kind: "task_cancel_requested"`;
- tools `task_accept`, `task_reject`, `task_progress`, `task_complete`, and `task_cancelled`.

## Submitter: daemon, CLI, and adapter

| CLI after `--state DIR` | Local API | Behavior |
| --- | --- | --- |
| `task submit --peer HOST --agent ID --input TEXT [--deadline TIME] [--grant ID] [--from-agent ID [--from-session ID]] [--task ID]` | `POST /v1/tasks` | Persists the outbound task with a `task.submitted` event, then submits it. Without `--grant`, it cites the target's policy, as for messages. The deadline defaults to 1 hour. An uncertain submission is retried automatically with the same `task_id` (milestone 5 rules). Returns the local record. |
| `task list [--after N] [--limit N]` | `GET /v1/tasks` | Outbound tasks in insertion order, paged like messages. |
| `task inspect --peer HOST ID` | `GET /v1/tasks/{peer}/{id}` | The local record: `{peer_host_id, request, submit_state, status, events_after}`. `submit_state` is `unknown`, `accepted`, or `rejected`, as for outbound messages, and `status` is the latest remote status record, or null. |
| `task events --peer HOST ID [--after N]` | `GET /v1/tasks/{peer}/{id}/events` | Locally stored events. |
| `task cancel --peer HOST ID` | `POST /v1/tasks/{peer}/{id}/cancel` | Sends the cancellation request now, retrying with backoff if uncertain, and returns the record. |

For every submitted task whose status is not final, the daemon polls events from the receiver. It uses at most 4 concurrent polls per daemon, with backoff from 1 second to 60 seconds, and resumes from the last stored sequence after a restart. It stores the events and updates `status`. Polling stops once a final state is stored.

Agent-initiated tasks use adapter routes. Routes now carry an `action` (`message.append` or `task.submit`), and the MCP tool `delegate_task` submits through a route whose action is `task.submit`. The originating session receives updates as `kind: "task_update"` events, with the task ID, state, and message or output, through `POST /adapter/v1/task-updates/next`, which follows the reply-notification rules. `task_status` returns the local record for a task this credential submitted.

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

Records are JSON, as elsewhere. Older binaries reject version 9. New activity kinds:
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
