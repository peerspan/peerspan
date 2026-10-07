# Task delegation, agent origin, and delegation chains

Status: proposal for review (roadmap milestone 6). Nothing here is implemented. It builds on owner access policy (milestone 2b) and the [access model](access-model.md). The decisions to settle are listed under [Decisions to settle](#decisions-to-settle).

## Problem

Hosts exchange only messages today, and every request is authenticated and authorized as a **host**. That leaves three gaps against the system design's goals:

- **No task delegation.** The design's first collaboration capability is to assign work to a remote agent, receive progress and results, and request cancellation. Nothing implements it.
- **No agent-level origin.** A receiver knows that Bob's host sent a request, but not which of Bob's agents did. Policy can grant to people and groups, not to agents.
- **No provenance across hops.** Suppose Alice's agent delegates to Bob's agent, which hands part of the work to Carol's agent. Carol's host sees only Bob's host. It cannot tell that the work originated with Alice, nor check that Bob only passed on authority Alice had. The design requires that "delegation preserves or narrows the applicable authority; it cannot increase it".

## Goals and non-goals

**Goals:**
- A task operation between hosts, with these properties:
  - durable and idempotent submission;
  - accept or reject;
  - progress events with resumable cursors;
  - a final result;
  - cancellation;
  - status queries.
- Delivery of tasks to an attached agent session, through the existing adapter.
- An agent origin on every request: which local agent, and optionally which session, originated it.
- Delegation chains that let a delegate pass on narrowed authority to another host. The final receiver verifies that the whole chain only narrows.

**Non-goals for milestone 6:**
- **Remote tools and resources** (capability calls) and **conversations.** They reuse the envelope designed here, but are later operations.
- **Agent identity independent of the host.** Agents under one OS account cannot be told apart cryptographically. Agent origin is asserted by the authenticated host. Isolated runtimes are where agent-level keys become meaningful.
- **Delegation across networks.**
- **Host-launched sessions.** Tasks go to attached sessions, as messages do today.

## Agent origin

Every peer request gains `origin: {agent_id, session_id}`, where `session_id` is nullable. The sending host fills it in, and the peer TLS connection authenticates that host. The receiver records the origin and exposes it to its agent. Policy rules gain an optional principal `agent:<host_id>/<agent_id>`, which matches only requests whose authenticated host is `host_id` and whose asserted origin is `agent_id`.

This is exactly as strong as the sending host. A compromised host can assert any of its own agents, but never another host's. The design should state that plainly, rather than imply per-agent cryptography.

## Tasks

| Operation | Peer route | Notes |
| --- | --- | --- |
| Submit | `POST /peer/v1/tasks` | Idempotent by `(sender, task_id)`. The body carries `task_id`, `target_agent_id`, the authorization (grant or policy), `origin`, the optional `delegation` chain, a `deadline`, and `input`, bounded at first to 64 KiB of text. |
| Status | `GET /peer/v1/tasks/{task_id}` | Visible only to the authenticated submitter. |
| Events | `GET /peer/v1/tasks/{task_id}/events?after=N` | Progress and result events with a durable sequence, so a disconnected submitter resumes from its last cursor. |
| Cancel | `POST /peer/v1/tasks/{task_id}/cancel` | Records a cancellation request. Whether the agent actually stopped is reported as an outcome, never assumed. |

**Task states:** `submitted` → `accepted` | `rejected` → `running` → `succeeded` | `failed` | `cancelled`, plus `unknown` on the submitting side. Acceptance means the receiving host has persisted responsibility for the task; execution may still be queued, as the design defines. Connection state and task state are separate. A disconnect does not fail a task.

The receiving host hands tasks to an attached session through the adapter. New MCP tools let the agent accept, report progress, and finish with a result, or reject. The sending side's adapter receives progress and results the way it receives replies today. Retries reuse the submission's `task_id` (milestone 5). A re-submitted task never creates duplicate work.

**Authorization** uses the existing machinery with new actions:
- `task.submit` on grants and policy rules;
- `task.delegate`, which lets a recipient pass the task on (see below).

Handoff, progress, and result delivery recheck authorization, as for messages.

## Delegation chains

A **chain** is an ordered list of links, carried with a task. Each link is signed by a host and passes the task's authority, possibly narrowed, to the next hop.

- **Link 0** is created by the originator's host A. It names the originator (A's host and agent, and A's person if bound) and the scope:
  - actions;
  - permitted next-hop principals;
  - an expiry;
  - a remaining depth;
  - whether further delegation is allowed.
- **Link k**, for k ≥ 1, is created by the host that received the task at hop k (B, C, …). It names the next hop and a scope that is a subset of link k−1's in every dimension:
  - fewer or equal actions;
  - fewer or equal principals;
  - an expiry no later;
  - a depth one less;
  - further delegation only if the previous link allowed it.

  It is signed by that host's key and covers the hash of the previous link, so links cannot be reordered or spliced.
- **The final receiver Z verifies four things:**
  1. every signature and every narrowing;
  2. that the last link names the authenticated sender as its holder;
  3. that every hop was allowed to delegate;
  4. that no participant is blocked locally.

  It then authorizes against its own grants and policy (see decision 1).
- **Revocation:**
  - every link expires;
  - cancelling at any hop propagates downstream as a cancellation request;
  - Z's owner can block any participant;
  - revoking membership of any host in the chain invalidates the chain.

The format would be our own minimal line-encoded links, with Ed25519 host signatures, in the same style as every other signed statement here. That is simpler to keep identical across Go and Rust than adopting a capability-token library with its own policy language. Biscuit is the closest such design.

## Security analysis

| Compromised | Can | Cannot |
| --- | --- | --- |
| A host in the middle of a chain | Refuse or delay the task; narrow it further; assert any of its own agents as origin | Widen scope, extend expiry, forge earlier links, or claim another host's agents |
| The originator's host | Start tasks within what receivers' policies allow it | Exceed any receiver's policy (decision 1) |
| Coordinator | Withhold membership or policy, as before | Forge links or task state; task traffic never passes through coordination |
| An agent on a host | Act with its host's asserted origin, as any local process can today | Escape the receiver's policy, or the chain's scope |

## Delivery

1. **Agent origin:** `origin` on messages and replies, and `agent:` principals in grants and policies.
2. **Tasks, single hop:**
   - the peer routes, storage, and events with cursors;
   - cancellation;
   - adapter delivery and MCP tools;
   - automatic retry of uncertain submissions.
3. **Delegation chains:** multi-hop, with attenuation, verification, and cancellation that propagates.
4. **Live acceptance:** two or three real Claude sessions delegating across hosts. This extends the existing live experiments.

Each slice ships in both host implementations with shared conformance, including adversarial cases: a widened scope, a spliced or reordered link, an expired link, a blocked middle hop, and replay of a task under a different chain.

## Decisions to settle

| # | Decision | Recommendation | Alternatives |
| --- | --- | --- | --- |
| 1 | Whose authority the final receiver checks | **Originator and sender.** The receiver's grants or policy must allow the originator for the action, and the chain must reach the sender through valid narrowing. Authority can then never be laundered through an intermediary. | Originator only, with the sender as a conduit. Sender only, with the chain merely informational. |
| 2 | Agent identity strength | Host-asserted origin now; agent keys with isolated runtimes later | Per-agent keys now, which adds little under one OS account |
| 3 | Who may delegate | Only where the receiver's grant or policy rule includes `task.delegate`, and the incoming link allows it | Any authorized recipient may delegate within the chain |
| 4 | Maximum chain depth | 3 hops past the originator | Configurable per rule; unlimited, bounded by expiry |
| 5 | Chain format | Own minimal line-encoded links | Biscuit tokens (a Datalog policy language, plus a library dependency in each language) |
| 6 | Cancellation | Best-effort downstream propagation, with the outcome reported, never assumed | Cancellation only at the immediate receiver |
| 7 | Task results | Bounded text results (64 KiB) first; artifacts and streaming later | Large results and artifacts in milestone 6 |
| 8 | Scope of milestone 6 | Tasks and chains; tools and conversations later on the same envelope | Include remote tools now |
