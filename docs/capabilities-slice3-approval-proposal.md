# Per-call approval (capabilities slice 3, item B)

Status: **Accepted on 2026-10-25.** The owner accepted every recommendation under [Owner decisions needed](#owner-decisions-needed), recorded as [decision 16](capabilities-contract.md#owner-decisions) in the capabilities contract. The recommended design below is the design for item B. The normative text is the [Per-call approval](capabilities-contract.md#per-call-approval-slice-3) section of the capabilities contract, which uses database version 20 because machine linking reserves 19.

Roadmap milestone 10, slice 3, item B. The system design (`docs-internal`, `docs/design.md`) asks that owners can "require approval for individual requests or selected actions" instead of only standing permission. The [capabilities contract](capabilities-contract.md) lists "approval of each call" as later work, and [credentials for shared tools](tool-credentials.md) names it option 4: safe for anything outside a known scope, but it does not scale and fails while the owner is away. This proposal builds on the capabilities contract (call states, decision 15 call timing, call updates), the [live delivery contract](live-delivery-contract.md), and status in the [launch contract](launch-contract.md).

The other slice 3 items, (A) remote MCP servers and OAuth, (C) sharing with one agent, and (D) resource bounds and non-MCP sources, are designed separately. [Interactions](#interactions-with-items-a-c-and-d) notes where they touch this one.

## Summary

- **Where it is set.** On the capability record, on the serving host: `approval: {operations, agent_self}`. Not in the signed policy. It is a host-local narrowing, like the capability's operation list itself.
- **What it covers.** Per operation: none, every operation that can change things, every operation, or a named list. It applies to every recipient of the capability.
- **Who approves.** The person, at a terminal on the serving host: `peerspan approvals`, `peerspan approve`, `peerspan deny`. Agents never approve: no adapter route exists, and `approve` needs a terminal.
- **How the person learns of it.** A status attention item, an activity record, and a notice event into the attached session of the capability's source agent, which tells the agent to ask the person and says it cannot approve.
- **What the caller sees.** On the wire the call stays `queued`, with a new `approval` object on the status record, so older callers keep working. Caller-side views (the agent's call view, `call`, `pending_work`) show a derived state, `awaiting_approval`.
- **Expiry.** An approval waits at most until the call's deadline (at most 15 minutes). Then the call becomes `expired` with the error `approval_timeout`.
- **Denial.** The call becomes `rejected` with the error `approval_denied` and an optional reason.

## Model

| Term | Meaning |
| --- | --- |
| **Approval requirement** | The `approval` field of a capability record: which operations need approval, and whether self-access agent calls do. |
| **Approval** | The record of one call's approval: `pending`, then `approved`, `denied`, `expired`, or `cancelled`. One per received call that needs it, keyed like the call by `(sender, call_id)`. |
| **Approver** | The person, acting through the owner CLI on the serving host. |

An approval covers exactly one call: one sender, one `call_id`, one input. It never covers later calls, even with the same input (decision 8).

## Configuration

### The capability record

The record gains:

```json
"approval": {"operations": "changing", "agent_self": true}
```

- **`operations`** is one of:
  - `"none"`: no call needs approval. This is how existing records read.
  - `"changing"`: an operation needs approval when it can change things, that is, a tool whose entry in the snapshot the call runs against has `read_only` false. `read` never needs approval under `"changing"`. The check uses the current snapshot when the call is accepted, so a tool that loses its `readOnlyHint` in a later snapshot starts needing approval.
  - `"all"`: every operation, `read` included.
  - a list of operation names, each one of the capability's `operations`, or `read` when the capability has resources. A name that later leaves the capability is dropped from the list when the capability is next written.
- **`agent_self`** (boolean, default `true`): whether calls authorized by self access that carry an `origin`, meaning the person's own agents on their other trusted machines, need approval too. Self-access calls without an `origin`, the person at the CLI of a trusted machine, never need approval. Calls authorized by policy always follow `operations`, whatever their origin. See decision 4.
- **Sources** (`AGENT/SERVER` implicit capabilities) never need approval. They are reachable only from the person's own CLI, with no origin, which approval exempts anyway.

A record without `approval` reads as `{"operations": "none", "agent_self": true}`, so migration rewrites none.

**Why not "can change things" alone.** `read_only` comes from the server's `readOnlyHint`, a claim Peerspan cannot verify ([tool credentials](tool-credentials.md)). A server that wrongly marks a write tool read-only escapes `"changing"`. The review says so, and `"all"` or a list is the safe choice for an untrusted server.

### Why the record, not the policy

The capability rule in `peerspan-policy-v2` could carry an approval flag. The record is recommended instead (decision 1), because:
- **Operations are host-local.** The policy names a capability, never its operations, so it cannot say "approve only `create_issue`" without carrying operation names to coordination.
- **One rule per capability per policy.** A policy holds at most one rule per capability name, with all its principals. A rule flag would be per capability, never per recipient, so it gains nothing over the record.
- **No signing, no format break.** A rule flag changes the signed lines, the JSON, the test vector, and the merge, and older software rejects the result. Coordinators would be upgraded first again.
- **It only narrows.** Requiring approval never widens access, so it needs no owner signature beyond control of the serving host, which already holds the record and enforces every call.
- **At once, offline.** A local change applies on the next call, even with coordination down; a policy change waits for signing and storage.

The cost: other hosts of the person do not see the setting, and coordination never does. A caller learns it only from the capability listing (below), peer to peer.

### Commands

| CLI | Local API | Behavior |
| --- | --- | --- |
| `capability create NAME --from SOURCE … [--approval none\|changing\|all\|OP[,OP...]] [--no-agent-self-approval]` | `POST /v1/capabilities` gains optional `approval` | Stores the requirement with the record. Absent means `none`. A name in the list that is not an operation of the record is 400. `approval` is part of the record for the repeat rule: an identical repeat returns 200, a different one 409. |
| `capability approval NAME (none\|changing\|all\|OP[,OP...]) [--agent-self\|--no-agent-self]` | `PUT /v1/capabilities/{name}/approval` with `{operations, agent_self}` | Replaces the requirement. Signs nothing. Returns the record. Applies to calls accepted afterwards; calls already accepted keep the requirement they were accepted under (below). Records `capability.approval_changed` (subject: the name). |
| `share NAME --with …`, guided `share --with …` | as before | The review gains one line (below). The guided share, at a terminal, asks after the operations when any selected tool can change things: `Require your approval for each call to tools that can change things? [Y/n] `. Without a terminal, `--approval` decides, absent meaning `none`. `share NAME` on an existing capability never changes its requirement. |
| `capability show`, `capability list`, `shares` | as before | Show `approval`. |

**The review line.** After the operations, `share` prints one of:
- `Calls to OP, OP wait for your approval at this machine (peerspan approvals).`;
- `Every call waits for your approval at this machine (peerspan approvals).`;
- or, when some selected tool can change things and none needs approval: `No call waits for your approval. To require it: peerspan capability approval NAME changing`.

Under `"changing"` it adds: `Tools are marked by the server itself; a tool it wrongly marks read-only runs without approval.`

## Receiving a call

### Acceptance

`POST /peer/v1/calls` authorizes exactly as today (blocks, capability, bounds, budget). Then:
1. **Does it need approval?** Yes when the operation is covered by the capability's `operations` requirement and the call is not exempt: a self-access call without `origin` is exempt, and a self-access call with `origin` is exempt when `agent_self` is false.
2. **Pending limit.** At most 20 approvals may be `pending` per rule identity and caller, the pair that counts the hourly budget (for self access, per caller). A call over it is refused with 429 `{code: "limit", error: "too many calls are waiting for approval", limit: "max_pending_approvals"}` and persists nothing. Older callers already treat 429 as final `rejected`.
3. **Persist.** In the one acceptance transaction: the call as `queued`, its approval as `pending` with `expires_at` equal to the call's deadline, the notice for the source agent (below), and the activities `call.received` and `call.approval_requested`.
4. **Answer.** 200 with the status record, whose `approval` is the pending object.

The call counts against `max_calls_per_hour` at acceptance, as any call, approved or not.

The requirement is evaluated once, at acceptance, and stored on the approval record. Changing the capability's requirement later does not add or remove approvals of calls already accepted. A call accepted without approval and still queued when the owner turns approval on runs without it. Turning approval off does not approve pending calls; the owner approves or denies them, or they expire.

### The approval record

`{sender_host_id, call_id, state, capability, operation, changes_things, caller, origin, input_sha256, requested_at, expires_at, decided_at, reason}`
- `state`: `pending`, `approved`, `denied`, `expired`, or `cancelled`.
- `changes_things`: the snapshot's `read_only` negated at acceptance; false for `read`.
- `caller`: `{person_id, person_label, host_id, via}`, where `via` is `policy` or `self` and the label is the sender's binding label as message events show it, or null.
- `origin`: the call's `origin`, or null.
- `reason`: the denial reason, at most 1,024 bytes of UTF-8, or null.

The record never holds the input itself; the input stays in the received call's request, and is deleted with it after 7 days.

### Transitions

| From | Event | Approval | Call |
| --- | --- | --- | --- |
| `pending` | `approve` | `approved` | stays `queued`; the dispatcher may start it |
| `pending` | `deny` | `denied` | `rejected`, error `approval_denied` |
| `pending` | the call's deadline passes | `expired` | `expired`, error `approval_timeout` |
| `pending` | the caller cancels | `cancelled` | `cancelled`, as for any queued call |
| `approved` | start | unchanged | `running`, after the recheck |

- **Dispatch.** The dispatcher never starts a call whose approval is `pending`, and never starts a server instance for one. Today's dispatcher starts an instance for any `queued` call; that loop must filter first.
- **Recheck.** An approved call is rechecked before it starts, as today. An `unshare` between approval and start rejects it with `authorization lapsed before start`. Approval never overrides authorization.
- **Restart.** Approvals persist. After a daemon restart, pending calls stay pending and approved calls stay queued and start normally.
- **Each one once.** Every transition happens in one transaction with its call change and activity. Approving or denying a call that is no longer `pending` changes nothing and returns 409 `{code: "conflict", error: "the call is no longer waiting for approval", approval}`.
- **Repeated `call_id`.** A repeat of an accepted call, identical by the existing rule, returns the existing record with its approval and creates nothing. A changed repeat is 409 as before. A new `call_id` with the same input is a new call and a new approval (decision 8).

### The status record

The peer status record gains `approval`, null when the call needed none:

```json
"approval": {"state": "pending", "requested_at": "RFC3339", "expires_at": "RFC3339", "decided_at": null, "reason": null}
```

The wire `state` stays one of today's eight values: `queued` while pending or approved and not yet started. A new state value was rejected on purpose: v18 callers check `state` against the known states (Go `validCallStatus`, Rust `valid_status`), and an unknown state makes every submit and poll response invalid, so the call would never resolve. Both implementations ignore unknown fields of the status record, so `approval` is safe for them (decision 5).

`error` gains the values `approval_denied` (with `rejected`) and `approval_timeout` (with `expired`). Older callers show them as text.

### Held status requests

`GET /peer/v1/calls/{id}?wait=N&state=S` gains an optional `approval=A`, the approval state the caller last stored, or `none`. The receiver also answers as soon as the approval's state differs from `A`. A host that predates this ignores the parameter (both parse queries leniently), and answers on state changes only, which is enough: approval leads to `running` or a final state within seconds.

## Telling the person

### Status

- **`GET /v1/status`** `capabilities` gains `approvals_pending`, the count of pending approvals.
- **Attention item `call_approval_pending`.** One item while any approval is pending. Subject: the count as a decimal string. Detail: the oldest pending call's capability, operation, caller, and expiry. Command: `peerspan approvals`. Its number follows the last item in use when slice 3 merges (17 today; items A, C, and D may add some), and the number is fixed then.

### The notice to the person's agent

The person is usually working in an agent session, not watching `status`. So the daemon also tells the capability's **source agent** (`source.agent` of the record, an agent of this host), in its attached, verified session, with a notice event. Decision 6 covers whether to send it.

- **Notice record.** Created with the approval: `{id, sender_host_id, call_id, agent_id, session_id, state, created_at}`, with an ID of `notice_` and 32 hex digits, and `state` `unknown`, `forwarded`, or `void`. `session_id` is null until claimed.
- **Claim.** `POST /adapter/v1/approval-notices/next` with `{}` claims the oldest unclaimed notice for this session's agent whose approval is still pending, and returns `{notice, approval}`, or `null`. It needs a verified channel (409 before, as the other work routes), but not `calls` on the credential. A notice whose approval is decided before it is claimed becomes `void` and is never offered.
- **Forwarded.** `POST /adapter/v1/approval-notices/{id}/forwarded` with `{}`. Idempotent; 404 for another credential.
- **No redelivery.** A notice is claimed once, by one session. It has no `seen` and is not listed in `pending_work`: it is a heads-up, and `status` and `peerspan approvals` are the record.
- **The event.** `meta.kind` `approval_request`, `meta` `{notice_id, call_id, sender_host_id, caller, origin_agent_id, capability, operation, changes_things, expires_at}`. The content is exactly:

  `A call to your capability CAPABILITY (OPERATION) from CALLER is waiting for the person's approval, until EXPIRES. You cannot approve or deny it. Tell the person, and ask them to run peerspan approvals in a terminal on this machine.`

  where `CALLER` is the person label, or the host ID when there is none. The input is never included: it is text written by the caller, and putting it in the owner's agent context would let a caller address the owner's agent directly (decision 7).

### What agents cannot do

- **No adapter route** lists, approves, or denies approvals. The four call tools and the new event are the whole agent surface.
- **`approve` needs a terminal.** It refuses with exit 1 and `peerspan approve needs a terminal: approval must come from the person.` when stdin is not a terminal. It has no `--yes`. `deny` and `approvals` work anywhere, because denying only narrows.
- **The remaining limit.** An agent running shell commands as the same OS user can still reach the local administration socket directly. That is the existing owner-local trust boundary ([agent adapter contract](agent-adapter-contract.md)): adapter credentials do not isolate a process with full access to the account. Approval stops the person's agent from approving by mistake or on a caller's request through Peerspan; it does not stop a deliberately misbehaving local process. A signed approval (decision 3, option c) would close this only for processes without the person key.

## Approving

| CLI | Local API | Behavior |
| --- | --- | --- |
| `approvals [--all] [--json]` | `GET /v1/approvals?state=pending\|all` | Pending approvals, oldest first; with `--all`, also decided ones from the last 7 days. Each line: caller, capability, operation with `(can change things)` where it applies, origin agent, age, time left, and the input preview (first 512 bytes of its JSON, control characters escaped). JSON: `{approvals: [RECORD + {input_preview, input_bytes}]}`. |
| `approvals show ID` | `GET /v1/approvals/{sender}/{call_id}` | One approval with the whole input, pretty-printed and with control characters escaped, and the capability's review lines (source, credential context). |
| `approve ID` | `POST /v1/approvals/{sender}/{call_id}/approve` with `{}` | Shows what `approvals show` shows, asks `Approve this call? It runs once, with the credentials it runs with on this machine. [y/N] `, and on `y` approves. Needs a terminal (above). Prints the record. |
| `deny ID [--reason TEXT]` | `POST /v1/approvals/{sender}/{call_id}/deny` with `{reason}` | Denies at once, without a prompt. Prints the record. |

- **`ID`** is the call ID (`call_` and 32 hex digits), or `SENDER_HOST_ID/CALL_ID`. A bare call ID that two senders used is 409 `{code: "ambiguous", candidates}`; the full form is then needed.
- **Refusals.** An unknown ID is 404. An approval no longer pending is 409, as above, so approving twice is harmless.
- **Showing untrusted text.** Input, labels, and origin names come from the caller. The CLI escapes control characters and terminal escape sequences in everything it prints from them.
- **Where.** Only on the serving host (decision 2). The person may log in to it, or work in an agent session there and run `peerspan approve` in their own terminal.

## What the caller sees

### Capability listing

In `GET /peer/v1/capabilities`, each operation gains `approval`: `true` when a call from this sender, under that entry's `via`, would need approval now, and `false` otherwise. `discover`, `GET /v1/discover`, and `list_capabilities` carry it through, and `discover` prints `(needs approval)` after such an operation. It is advisory: the receiver decides at acceptance. A host that predates this omits it, which reads as `false`.

### The outbound record and owner CLI

- The outbound record stores the receiver's `approval` object with the status, as returned. Records without it read as null.
- **`call`** prints, on stderr, while the stored approval is pending: `Waiting for OWNER to approve this call (until EXPIRES).` Its exit code stays 3 while not final. `--wait` keeps its 15-minute maximum, which now matters: a call that needs approval usually needs more than the default 60 seconds, so the message adds `Check it later with peerspan calls inspect --peer HOST ID.`
- **`calls list` and `calls inspect`** show the approval.
- **Results without polling.** While the stored approval is `pending`, the daemon keeps holding status requests (`wait=10`, with `approval=pending`) past the usual 60 seconds, until the approval is decided or the call is final. So an approval reaches the caller within a second, not after a 60-second backoff. This keeps one open request per waiting call, at most 15 minutes each.

### The agent's call view

- **State.** The call view's `state` gains a derived value, `awaiting_approval`: the stored status is `queued` and its approval is `pending`. The view also gains `approval`, the stored object or null.
- **Note.** For `awaiting_approval`, exactly: `The capability's owner must approve this call before it runs; it has not run. Its result arrives as a kind=call_update event; call_status reports it at any time. Do not call it again: a new call needs a new approval.`
- **Timing.** `call_capability` still returns within the 15-second wait limit, with `awaiting_approval` when the owner has not decided. Nothing about the wait limit changes.
- **Updates.** The call-update notification is created when the call becomes final, as today. A denial gives `rejected` with `approval_denied`, and a timeout `expired` with `approval_timeout`; both carry the existing never-ran note, and a denial's reason, when given, is in `approval.reason`. No event is sent when an approval is granted: the final result follows.
- **`pending_work`** lists such calls with `state` `awaiting_approval`, and the `--hook` text is unchanged.
- **Tool descriptions.** `call_capability`'s description gains one sentence: some operations wait for their owner's approval, shown by `approval` in `list_capabilities`, and such calls return `awaiting_approval`.

### Older peers

| Caller | Receiver | Result |
| --- | --- | --- |
| new | old | No approval exists; nothing changes. |
| old | new | Approval is enforced. The caller sees `queued` until the call runs, is `rejected` (`approval_denied`), or `expired` (`approval_timeout`). Its CLI and agent see a queued call with the existing pending note. Its held requests end after 60 seconds, then it polls with backoff up to 60 seconds, so an approved call's result can arrive up to a minute late. |

## Persistence

Database version 19 (the number is taken by whichever slice 3 item merges first; the others renumber) adds:

```sql
CREATE TABLE call_approvals (sender TEXT NOT NULL, call_id TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id), FOREIGN KEY(sender, call_id) REFERENCES received_calls(sender, call_id));
CREATE INDEX call_approvals_state ON call_approvals(state, expires_at);
CREATE TABLE approval_notices (id TEXT PRIMARY KEY, sender TEXT NOT NULL, call_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id), session_id TEXT REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, call_id));
PRAGMA user_version = 19;
```

- **`call_approvals`** is kept as long as its received call's status record, which today is kept indefinitely; the input it refers to is deleted after 7 days with the call's.
- **Capability records** gain `approval`; **received call status records** and **outbound records** gain `approval`. Records without it read as none or null.
- **Migration** from 18 creates the tables and index and sets the version in one transaction. Older binaries reject 19.

**Activity** (subject `SENDER_HOST_ID/CALL_ID` unless noted):
- `call.approval_requested`, `call.approved`, `call.denied`, `call.approval_expired`;
- `capability.approval_changed` (subject: the capability name).

These are the audit trail: who called, what, when it was asked, and when and how it was decided. Activity never holds inputs or denial reasons; the reason is in the approval record. Every decision is made at the local administration socket, which is the owner by definition, so the record names no approver beyond `decided_at`.

## Verification

`conformance/capabilities.py` gains, written from the eventual contract text by an author independent of both implementations and the adapter, across all four Go/Rust pairings with `--node` and the fixture MCP server:
- **Configuration:** `--approval` at create, each mode, the list refusal, repeat and conflict including `approval`; `capability approval` changing modes without signing a policy; the review lines and the guided prompt; `shares` and `show`.
- **Acceptance:** `changing` holding a non-read-only tool and passing a read-only one and `read`; `all`; a list; self access without origin exempt, with origin held, and exempt with `--no-agent-self`; the pending limit of 20 giving 429 `max_pending_approvals`; the budget counted at acceptance.
- **Decisions:** approve then run, with exactly one execution; deny with reason, giving `rejected` `approval_denied`; timeout at the deadline, giving `expired` `approval_timeout`; cancel while pending; approve after `unshare`, rejected at the recheck; double approve 409; a repeated `call_id` returning the same approval; no server instance started for a pending call; pending and approved calls surviving a receiver restart.
- **CLI:** `approvals`, `--all`, `show`, `approve` refused without a terminal, accepted at a pseudo-terminal, `deny` without one; ambiguous bare IDs; escaped control characters in the input preview.
- **Caller:** `approval` on the wire status; `awaiting_approval` and its note from `call_capability` within the wait limit; one `call_update` on approval-then-success, on denial, and on timeout, none on approval itself; `pending_work`; `call`'s stderr line and exit 3; held requests continuing past 60 seconds while pending and the result arriving within 2 seconds of `approve`; `approval` in listings and `(needs approval)` in `discover`.
- **Older peers:** a version 18 caller against a new receiver seeing `queued`, then the result after approval, and `rejected` after denial; a new caller against a version 18 receiver unchanged.
- **Notices:** one `approval_request` event to the source agent's verified session, its exact content without input; no event once decided; 409 before verification.
- **Status:** `approvals_pending` and the attention item.
- **Migration:** from 18 to 19.

`conformance/live_capability_agents.py` adds one live run per harness: Bob sets `capability approval github-issues all`; Alice's agent calls `list_issues`, gets `awaiting_approval`, and tells Alice it is waiting; Bob's Claude Code session receives the notice and tells Bob without approving; Bob runs `peerspan approve` at a terminal; Alice's agent receives the `call_update` and answers with the issues.

## Interactions with items A, C, and D

Noted only; each item designs its own side.
- **A, remote MCP servers and OAuth.** Approval is per operation and source-agnostic, so it applies to remote servers unchanged. Their `readOnlyHint` is equally unverified. An OAuth token that expires while a call awaits approval surfaces as the usual failure after approval; A decides whether re-consent can happen then. A's one-time browser consent at share time is a different approval and must not be confused with this one in wording.
- **C, sharing with one agent (`PERSON/AGENT`, `call --from-agent`).** The approval listing shows `origin` so the owner sees which of the caller's agents asks. `call --from-agent` gives an owner CLI call an origin; under self access it would then need approval when `agent_self` is true, which is correct for testing what the agent will experience. A per-recipient exception list (decision 9) would naturally use C's principal forms.
- **D, resource bounds and non-MCP sources.** Bounds are checked at acceptance before an approval is created, so the owner is never asked about a call the bounds refuse. A `gh` adapter defines its own operations, and must mark each one `read_only` (Peerspan-defined, so trustworthy unlike `readOnlyHint`) for `"changing"` to work. The `bounds` and `approval` fields sit side by side on the record and both show in the review.

## Implementation size

Rough, including tests in each language:
- **Go:** about 1,000 to 1,300 lines: record field and validation, acceptance and pending limit, approval table and transitions, dispatcher filter, expiry sweep, held-request `approval` parameter, local routes and CLI with terminal check and escaping, notices, status, migration.
- **Rust:** about the same, 1,000 to 1,300 lines.
- **Shared Node adapter:** about 150 to 250 lines: the derived `awaiting_approval` in the call view and its note, the notice claim loop and `approval_request` event for all three harnesses, description changes.
- **Conformance:** about 700 to 1,000 lines in `capabilities.py`, a pseudo-terminal helper for `approve`, a version 18 binary for the older-peer cases, and one live scenario.
- **Contract text:** a new "Per-call approval" section in the capabilities contract.

## Owner decisions needed

1. **Where the requirement lives.**
   - (a) On the capability record, host-local, unsigned, not visible to coordination.
   - (b) As a fourth bound in the policy's capability rule (`none`, `changing`, or `all`), signed and visible to coordination; no per-operation list, since the policy never names operations.
   - (c) Both: the policy flag as a floor the person sets everywhere, the record for operation lists.
   - **Recommend (a).** It only narrows, needs no signing or format break, applies offline at once, and can name operations; a policy flag can only be per capability anyway.

2. **Where the person approves.**
   - (a) Only on the serving host, through its local CLI.
   - (b) Also from any of the person's trusted machines, through a new peer route authorized by self access.
   - (c) Also from a future dashboard.
   - **Recommend (a) for this slice, (b) as a follow-up.** (b) makes approval authority follow `trusted_hosts`, which any holder of the person key can grant itself; that deserves its own review.

3. **How strong the approval act is.**
   - (a) A terminal prompt; `approve` refuses without a terminal and has no `--yes`.
   - (b) Like `share`: a prompt, or `--yes` without a terminal.
   - (c) A person-key signature over `(sender, call_id, input_sha256)`, through ssh-agent.
   - **Recommend (a).** It keeps the person's agent from approving through its shell by accident, without key prompts for every call. (c) stops only processes that cannot reach the ssh-agent, and the agent usually can.

4. **Which calls are covered.**
   - (a) Policy calls per the requirement; self calls with an agent origin too unless `agent_self` is false; self calls without origin never.
   - (b) Policy calls only; everything under self access is exempt.
   - (c) Every call, including the person's own CLI from trusted machines.
   - **Recommend (a), with `agent_self` true by default.** The person's own agent on another machine using write tools is a main reason to want approval; the person typing at their own CLI is not.

5. **How the caller sees it on the wire.**
   - (a) `state` stays `queued`, with a new `approval` object; callers derive `awaiting_approval` locally.
   - (b) A new wire state `awaiting_approval`, with an upgrade gate: the receiver uses it only for callers that announce support, for example with a request field.
   - (c) A new wire state for everyone.
   - **Recommend (a).** (c) breaks every v18 caller, whose validation rejects unknown states, so their calls never resolve. (b) works but adds a negotiation for no gain over (a).

6. **Whether to notify the person's agent session.**
   - (a) A notice event to the capability's source agent, as specified.
   - (b) To every attached agent session on the serving host.
   - (c) No agent notice in this slice; status and activity only.
   - **Recommend (a).** The person is most often in an agent session; the source agent is the natural one and avoids spamming every session.

7. **What the notice and listing show of the input.**
   - (a) The notice carries no input; the CLI shows it.
   - (b) The notice carries an escaped preview.
   - **Recommend (a).** Input is caller-written text; in the owner's agent context it becomes a channel for a caller to instruct the owner's agent.

8. **Remembering approvals.**
   - (a) Each approval covers one call only.
   - (b) `approve --for 30m` also approves later calls from the same caller to the same operation for a window.
   - (c) `approve --same-input` approves later calls with an identical input hash.
   - **Recommend (a) now; consider (b) after real use.** (b) and (c) turn approval back into short standing permission, which needs its own review of scope and revocation.

9. **Per recipient.**
   - (a) The requirement applies to every recipient of the capability.
   - (b) The record also holds `approval_exempt: [principals]`, recipients who never need approval.
   - **Recommend (a).** Two capabilities on the same source, one with approval, already serve "trusted Bob, approved Carol" without new syntax; (b) can follow C's principal forms later.

10. **How long a call may wait.**
    - (a) Until the call's deadline, at most 15 minutes, as for every call.
    - (b) Raise the deadline limit for calls to operations that need approval, for example to 24 hours.
    - **Recommend (a) for this slice.** (b) changes the receiver's deadline check, which older receivers enforce with 400, and the caller's daemon does not know before submitting whether approval is needed except from the advisory listing. The design notes approval "fails while the owner is away"; (a) accepts that, and the caller sees `approval_timeout` clearly.

11. **Default for new capabilities.**
    - (a) `none` unless chosen; the guided share asks when write tools are selected, defaulting to yes at the prompt.
    - (b) `changing` by default everywhere.
    - (c) `none`, with no prompt.
    - **Recommend (a).** It keeps existing scripts and records unchanged while steering the interactive path, where write tools are chosen, toward approval.

12. **Pending limit per caller.**
    - (a) 20 pending approvals per rule identity and caller, fixed.
    - (b) A per-rule or per-capability setting.
    - **Recommend (a).** It stops one caller from flooding the owner's list; `max_calls_per_hour` already bounds volume.
