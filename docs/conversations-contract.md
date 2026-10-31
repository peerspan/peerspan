# Conversations contract

Launch-plan track 3. The design and its settled decisions are in the [conversations proposal](conversations-proposal.md) and the owner decisions [CONV-1 to CONV-27](decision-log.md#conv-conversations-2026-10-25). Feature slice 1 is built as PRs C1 to C6 ([Slices](conversations-proposal.md#slices)); each PR adds its section here. Where this contract and the proposal differ, this contract applies; anything the proposal gives to a later PR is not part of an earlier section.

It builds on the [messaging contract](peer-messaging-contract.md) (authorization citations, retry), [sending by address](launch-contract.md#sending-by-address) and [directory sessions](launch-contract.md#directory-sessions), the [adapter](agent-adapter-contract.md) and [live delivery](live-delivery-contract.md) contracts, and the [coordinator-free spec](decentralized-spec.md) for membership, owner policies and sync. Rust is the only host.

**Words.** A *conversation message* (here just "message") is what a participant sends into a conversation. A *one-to-one message* is a message of the messaging contract (`send`, `POST /peer/v1/messages`).

## C1: two hosts, one message each way

C1 lets a person on the home host start a conversation with one remote agent, and lets both send. Everything not listed here (more participants, persons other than the creator, roster changes, close, catch-up, seen and redelivery, rate limits, `addressed_to` from local surfaces, the read cursor, the event log, status) comes in C2 to C6. CONV-24: the conversation commands are not listed in the root help, the README or the quick start until C6; they exist and have their own `--help`.

### Common shapes

**IDs.**
- Conversation: `conv_` and 16 random bytes in lowercase hex (`^conv_[0-9a-f]{32}$`).
- Message: `cmsg_` and 16 random bytes in lowercase hex (`^cmsg_[0-9a-f]{32}$`).
- Notification: `cnot_` and 16 random bytes in lowercase hex.
- Participant: `agent:HOST_ID/AGENT_ID` for an agent, `person:HOST_ID/PERSON_ID` for a person taking part from one host.

**Roster** (the home host's record of the conversation, as in the proposal's [Identity and fields](conversations-proposal.md#identity-and-fields)):

```json
{
  "conversation_id": "conv_…",
  "home_host_id": "host_…",
  "version": 2,
  "title": "Flaky checkout test",
  "state": "open",
  "created_by": "person:host_a…/person_…",
  "created_at": "RFC3339",
  "participants": [
    {"id": "person:host_a…/person_…", "kind": "person", "host_id": "host_a…", "person_id": "person_…",
     "agent_id": null, "name": null, "state": "joined", "added_by": null, "added_at": "RFC3339"},
    {"id": "agent:host_b…/agent_…", "kind": "agent", "host_id": "host_b…", "person_id": "person_…",
     "agent_id": "agent_…", "name": "bert", "state": "joined", "added_by": "person:host_a…/person_…",
     "added_at": "RFC3339"}
  ],
  "departed": []
}
```

`title` is omitted when there is none (0 to 200 bytes of UTF-8 without control characters otherwise). In C1, `state` is always `open`, participant states are `inviting` and `joined`, and `departed` is always empty. A participant's `person_id` is the person bound to its host as the home host knows it, or null.

**Message** (as stored and sent between hosts):

```json
{
  "message_id": "cmsg_…",
  "conversation_id": "conv_…",
  "author": "agent:host_b…/agent_…",
  "seq": 1,
  "clock": 2,
  "roster_version": 2,
  "sent_at": "RFC3339",
  "content": "text",
  "origin": {"agent_id": "agent_…", "session_id": "session_…"}
}
```

- `seq` counts the author's messages in the conversation from 1, with no gaps, assigned by the author's host when it stores the message.
- `clock` is one more than the highest `clock` of any message the author's host holds for the conversation (1 for the first). Storing a received message therefore raises the next clock past it.
- `roster_version` is the roster version the author's host held when it stored the message.
- `origin` is present for agent authors (the sending agent and session) and absent for person authors.
- `addressed_to`, an optional array of 1 to 16 participant IDs, is accepted and stored by the peer route (below) and shown in views; no C1 local surface sets it (C6).
- `content` is 1 to 65,536 bytes of UTF-8.

**Display order** of messages is `(clock, author, seq)`, comparing `author` as bytes, on every surface.

**Labels.** Each host derives labels itself, never from the home host's or a message's text: for a person participant, the member label of the person bound to the participant's host in this host's verified records; for an agent, that label, `/`, and the agent's `name` in the roster. Without a known person, the host ID stands in for the label (`HOST_ID`, `HOST_ID/NAME`).

**Errors** are `{code, error}` with the HTTP statuses of the host service contract. CLI successes print JSON (except the readable views below) and exit 0. CLI failures exit 1 and write `error: CODE: TEXT` to stderr, with the daemon's `code` and `error`. The texts C1 fixes are `not_participant: This participant is not in that conversation.`, `conflict: This message_id was already used with different content.`, and `not_bound: This host is not bound to a person; conversations need one (peerspan join).`

### Who may see what

A host stores each message once. Every C1 surface shows a participant P only the messages P authored and those with an accepted inbound target record for P (proposal, [What each local participant may see](conversations-proposal.md#what-each-local-participant-may-see)). Being in the roster alone shows nothing else.

### Local API and CLI

All routes are on the owner API (`admin.sock`). A host with no bound person cannot take part as a person: `POST /v1/conversations` and `POST /v1/conversations/{id}/messages` without an agent author return 409 `{code: "not_bound", error: "This host is not bound to a person; conversations need one (peerspan join)."}`, and reads without `participant` return the same.

The person participant of this host is `person:HOST_ID/PERSON_ID`, with this host's bound person. Every read takes an optional `participant` query parameter naming a local participant (a `person:` or `agent:` ID on this host), defaulting to the person participant. A `participant` that is not a local participant ID is 400 `invalid`; one never in the conversation's roster is 403 `not_participant`. Routes take the full conversation ID; an unknown one is 404 `not_found`.

#### Views

**Participant view:** the roster participant plus `label` (derived as above) and `local` (true when the participant is on this host).

**Conversation view:** `{conversation_id, title, state, home_host_id, roster_version, created_by, created_at, participants: [PARTICIPANT VIEW], last_message_at}`. `title` is null when there is none. `last_message_at` is the newest `sent_at` among the messages the viewing participant may see, or null.

**Message view:** `{message_id, conversation_id, author, author_label, author_kind, seq, clock, roster_version, sent_at, received_at, content, addressed_to, mine, targets}`. `author_kind` is `agent` or `person`. `addressed_to` is `[]` when absent. `received_at` is when this host stored it (the authoring time for its own messages). `mine` is true when the viewing participant is the author. `targets` is a list of target views when `mine`, and null otherwise.

**Target view:** `{participant, label, state, code, error, attempts}`.
- `state` is `sending` (not yet confirmed), `delivered` (the target's host returned a receipt; host acceptance, not that a model read it), `refused` (a final refusal), or `unsupported` (the target's host has no conversation routes).
- `code` is null unless `refused` or `unsupported`: `not_authorized`, `not_participant`, `invalid`, or `conflict` for `refused`, and `unsupported` for `unsupported`. `error` is a short text or null.
- `attempts` counts network attempts so far.

#### Routes

| Route | Body / query | Answer |
| --- | --- | --- |
| `GET /v1/conversations?state=open\|all` | `state` defaults to `open` | 200 `{conversations: [SUMMARY]}`: every conversation in which a local participant is `joined`, newest activity first (`last_message_at`, else `created_at`). `all` adds closed ones (none exist in C1). |
| `POST /v1/conversations` | `{participants, title?, content?, message_id?, network?}` | 201 `{conversation: VIEW, invites: [INVITE OUTCOME], message: MESSAGE VIEW or null}` |
| `GET /v1/conversations/{id}?participant=P` | | 200 conversation view |
| `GET /v1/conversations/{id}/messages?participant=P&before=MESSAGE_ID&limit=N` | `limit` 1 to 100, default 20 | 200 `{messages, next_before_message_id}`: the newest `limit` visible messages before `before` (or overall), returned in display order; `next_before_message_id` is the oldest returned message's ID when older visible ones exist, else null. An unknown `before` is 400. |
| `POST /v1/conversations/{id}/messages` | `{content, message_id?}` | 200 `{message: MESSAGE VIEW, targets: [TARGET VIEW]}`, sent as the person participant |

**Summary:** `{conversation_id, title, state, home_host_id, participants: [{id, label, kind, state, local}], created_at, last_message_at}`.

**Starting** (`POST /v1/conversations`), in order:
1. **Shape.** `participants` is exactly one string of at most 256 characters in C1; more than one is 400 `invalid` (C2 adds more). It must be an agent address, `PERSON/AGENT` or `HOST_ID/AGENT`. A person form (`person:…`, or a value with no `/`) is 400 `invalid` with `person participants are not supported yet` (C3). `title` is 0 to 200 bytes of UTF-8 without control characters; `content` as for messages; `message_id` as above. Unknown fields and nulls are 400. `note` and `as` are unknown fields in C1.
2. **Bound person.** As above, 409 `not_bound`.
3. **Resolution** through the agent directory exactly as `send TARGET` resolves, with optional `network`: 404 `unknown`, 409 `ambiguous` with `matches`, 400 `local` for an agent on this host (local participants come in C2), each `{code, error, matches}`.
4. **Authorization.** The home host chooses an authorization for the person to reach the target agent with `message.append`, as sending by address chooses (self, then the target owner's policy, then a grant). When none allows it, it refreshes that host's directory entry once and tries again, then refuses with 403 `{code: "not_authorized"}`. Nothing is persisted before this step passes.
5. **Persist.** The conversation with roster version 1: the person participant `joined` (`added_by` null) and the target `inviting`, with the `name` from the directory entry.
6. **Invite** (below), retried until a final answer. The route waits for the answer at most 15 seconds. On `joined`, home stores roster version 2 with the target `joined` and the `name` from the answer. On a final refusal, home stores roster version 2 without the target. An invite still unanswered at 15 seconds leaves the target `inviting` in the answer; retries continue (the 10-minute limit is C2).
7. **First message.** With `content`, home then sends it as the person participant, exactly as `POST /v1/conversations/{id}/messages` does. Its targets are the participants `joined` at that moment, so a target still `inviting` gets no target record for it.

**Invite outcome:** `{target, participant, label, state, code, error}`. `target` is the string as given, `participant` the resolved participant ID, `state` `joined`, `inviting`, `refused` or `unsupported`, and `code` as for target views (`not_authorized` for a 403, `invalid` for a 400, `unsupported` for a 404), null otherwise.

**Sending** (`POST /v1/conversations/{id}/messages`, and the adapter route below):
- `content` 1 to 65,536 bytes; `message_id` optional (generated when absent). Unknown fields and nulls are 400.
- The author must be `joined` in the roster this host holds; otherwise 403 `{code: "not_participant", error: "This participant is not in that conversation."}`.
- **Repeats.** A `message_id` this host already holds for the same author and conversation with identical `content` returns 200 with the stored message and the current targets, without a second message or target. The same `message_id` with other content, another author, or in another conversation is 409 `{code: "conflict", error: "This message_id was already used with different content."}`.
- In one transaction the host assigns `seq` and `clock`, stores the message, and creates one outbound target record (`sending`) per other `joined` participant in its roster. It answers once that commits, without waiting for delivery, so targets are usually `sending` in the answer.

#### CLI

| CLI | Route | Output |
| --- | --- | --- |
| `conversations [--all] [--json]` | `GET /v1/conversations` | Readable: one line per conversation with the ID's first 13 characters (`conv_` and 8 hex digits), the title in quotes if any, the participant labels, and the last activity time. `--json`: the route's answer. |
| `conversation start TARGET [--title T] [--message TEXT] [--message-id ID] [--network ID]` | `POST /v1/conversations` | The route's answer. |
| `conversation say ID TEXT [--message-id ID]` | `POST /v1/conversations/{id}/messages` | The route's answer. |
| `conversation show ID [--limit N] [--before MESSAGE_ID] [--as AGENT] [--json]` | `GET /v1/conversations/{id}` and `.../messages` | Readable view below. `--json`: `{conversation: VIEW, messages: [MESSAGE VIEW], next_before_message_id}`. |

- **`ID`** is the full ID, or `conv_` and at least 6 hex digits matching exactly one conversation this host holds; no match exits 1 with `not_found`, and several exit 1 with `ambiguous`, listing the matching IDs.
- **`--as AGENT`** (an agent name or ID on this host) reads as that agent's participant, `agent:HOST_ID/AGENT_ID`.
- **Readable `show`:** a header line with the ID, the title in quotes, the state and the participant count; a line with the participant labels, the viewer marked `(you)`; then one line per message in display order with the `sent_at` time (`HH:MM`, UTC), the author label and the content; under each of the viewer's own messages, one indented line per target not `delivered`: `not yet received by LABEL (STATE)`, or `not received by LABEL (refused: CODE)`. Other wording and spacing are not part of the contract; terminal escaping of content is C6.

### Peer routes

Both routes are on the peer router beside `/peer/v1/messages`, with its per-request host authentication, the 1 MiB body limit, and strict JSON: unknown fields, nulls, and a missing required field are 400 `invalid`. Neither is served on the first-contact listener, the completion listener, or a helper. Hosts reach each other as for one-to-one messages: direct QUIC to a host-signed contact, or a relay it lists.

The sender of every request must be a current member of a coordinator-free network the receiving host belongs to (spec section 5); otherwise 403 `{code: "forbidden"}`, except that a manual grant with `allow_disconnected` works on its own terms.

**Authorization citation.** A request for an agent target carries exactly one of `policy` `{person_id, version}`, `grant_id`, or `self` `{person_id}`, as in the messaging contract; none or more than one is 400. A request for a person target carries none (any is 400). The citation does not limit the check: the receiver accepts when self access, its owner's current policy, or a current grant allows `message.append` from the author (from the adder, for invites). An agent author matches through `origin.agent_id` (the `agent:` principal) as well as through its host's person; a person author has no `origin` and matches as an owner CLI send does. The block list applies to the author's host and person. The only thing the cited `policy` version decides is that a receiver holding a lower version, or no current policy of that person, answers 503 `{code: "unavailable"}`, and its network sync usually fetches the newer one within 60 seconds. Authorization failures are 403 `{code: "forbidden"}`.

#### `POST /peer/v1/conversations/invites`

Body: `{conversation_id, roster, target, adder, note?, origin?, policy | grant_id | self}`.
- `target` is `{kind: "agent", agent_id}`. A person target (`{kind: "person", person_id}`) is 400 in C1 (C3).
- `roster` is the roster home will commit if the invite is answered `joined`: its `conversation_id` equals the body's, its `home_host_id` is the authenticated sender, and it lists the target as `agent:RECEIVER/AGENT_ID`, `joined`. Every participant has a unique `id` whose kind and host match its `kind` and `host_id`, with `agent_id` (and a `name`) matching an agent ID, or `person_id` matching a person ID; states are `inviting` or `joined`. Otherwise 400. Labels are always derived from the host in the participant ID. A receiving host never takes a peer's word that a participant on itself is joined: a roster listing any `person:RECEIVER/…` participant, in any state, is 400 `invalid` (a local person joins only on its own host, by creating the conversation there in C1, or with `conversation join` in C3), and so is a roster listing any other `agent:RECEIVER/…` participant that the receiver does not already hold as `joined`; an invite joins its own target and nothing else.
- `adder` is a participant ID that is `joined` in `roster` and on the sender host; otherwise 403 `forbidden`. `origin` is present exactly when `adder` is an agent, and then names it; otherwise 400.
- `note` is optional text up to 4,096 bytes (no C1 sender sends it).

The receiver checks membership and authorization of `adder` to reach the target agent, as above; an unknown target agent is 403 `forbidden`. On success it stores the roster (if it holds none for the conversation, or a lower version) and answers 200 `{state: "joined", name}` with the agent's name. A repeat for the same `(home host, conversation_id, target)` is idempotent: it is checked again and answers the same while the agent remains joined. C1 creates no notification for being added (C2 adds the `conversation_roster` event).

Home records 200 `joined` as `joined`; 400 as `refused` (`invalid`); 403 as `refused` (`not_authorized`); 404 as `unsupported`; and retries anything else (503, other statuses, transport failures, lost answers).

#### `POST /peer/v1/conversations/{id}/messages`

Body: `{message, target, prev_seq?, policy | grant_id | self}`. `target` is a participant ID on the receiving host. `prev_seq` is the `seq` of the author's previous message sent to this target, omitted for the first one since the target joined; C1 sends and stores it and does not act on gaps (C4).

**Acceptance**, in order:
1. **Shape.** IDs, sizes and the citation rule above; `message.conversation_id` equals the path's; `seq`, `clock` and `roster_version` from 1 to 2^53 − 1; otherwise 400 `invalid`. (Content larger than the `max_message_bytes` of every rule or grant that would allow it is not allowed: 403 at step 5.) A `deadline` field is 400, as any unknown field.
2. **Author's host.** The host in `message.author` is the authenticated sender; otherwise 403 `forbidden`.
3. **Repeat.** A request whose `(sender host, message_id, target)` this host already accepted returns the saved receipt when `message`, `target` and `prev_seq` are identical (whatever it cites), and 409 `{code: "conflict"}` when any differs, before any later step.
4. **Roster.** A conversation this host holds no roster for, or a `roster_version` above the version it holds, is 503 `{code: "unavailable"}` (C2 adds fetching the roster). Then a `clock` more than 1,048,576 above the highest `clock` this host holds for the conversation is 400 `invalid` (honest clocks advance by one per message; this keeps a peer from exhausting the counter). The target not `joined` here, or the author not `joined` in the held roster, is 403 `{code: "not_participant"}`. A person target counts as joined only when this host joined it itself: in C1, only the creator of a conversation homed on this host; a person shown as `joined` in a roster from elsewhere is `not_participant`.
5. **Authorization.** For an agent target, as above, with 403 `forbidden` and 503 `unavailable`. For a person target (the person participant on this host), the person is `joined` here, and the author's host and person are not blocked; otherwise 403 `forbidden`.
6. **Persist.** In one transaction: the message, stored once per host by `message_id` (a second target of the same message adds only its target record); the inbound target record; the clock raise; and, for an agent target, one conversation notification for that agent. Answer 200 with the receipt `{message_id, target, receiver_host_id, accepted_at}`.

A host never stores a message whose `message_id` it already holds with different `message` fields: such a request is 409 `conflict`.

**Fan-out and retry.** After committing a message, the author's host sends one request per outbound target, citing the authorization it holds at that moment for the author to reach that target (self, then the target owner's newest policy, then a grant, as sending by address chooses). When none of these allows it, it cites the target owner's newest policy it holds, so the receiver decides; when it holds no policy of that owner and no grant or self access applies, the target becomes `refused` with `not_authorized` without a request. The retry schedule is milestone 5's: the first attempt at once; a new target record is due 10 seconds after it was stored, so one whose first attempt never finished is still retried; after any attempt that leaves it `sending`, the next is 1 second later, doubling to 60 seconds with ±20% jitter, persisted in the record. At most 4 automatic conversation attempts (invites and messages together) run at once per daemon, separate from other retries. Overdue records after a restart are spread as in the messaging contract. The answer decides the target's state:

| Answer | Target |
| --- | --- |
| 200 with a receipt for this `message_id` and target | `delivered` |
| 400 | `refused`, `invalid` |
| 403 `not_participant` | `refused`, `not_participant` |
| any other 403 | `refused`, `not_authorized` |
| 409 | `refused`, `conflict` |
| 404 | `unsupported`, error `HOST_ID is running a Peerspan without conversations` |
| anything else, or no answer | stays `sending`, retried |

`delivered`, `refused` and `unsupported` are final. In C1 retries of a `sending` target do not stop (C4 adds the 24-hour limit and `stopped`).

### Adapter routes

They use the adapter's credential and lease, as `/adapter/v1/next` does, and are scoped to the credential's agent; any session of the agent may use them.

| Route | Body | Answer |
| --- | --- | --- |
| `POST /adapter/v1/conversations/{id}/messages` | `{content, message_id?}` | As the local sending route, with the agent's participant as author and `origin` `{agent_id, session_id}` from the credential. Works before the channel is verified. |
| `POST /adapter/v1/conversation-notifications/next` | `{}` | 200 with a claim, or 200 `null`. |
| `POST /adapter/v1/conversation-notifications/{id}/forwarded` | `{}` | 200 `{notification}`. Idempotent: a repeat returns the same notification, with the first call's `forwarded_at`. 404 `not_found` for an unknown notification or another agent's. |

- **Directory access.** A credential without directory access gets 403 `{code: "no_directory"}` from the sending route, and `null` from the claim route.
- **Sending errors.** 404 `not_found` for a conversation this host does not hold; 403 `not_participant` when the agent is not `joined`; 409 `conflict` and 400 `invalid` as for the local route.
- **Claiming.** Before the authorization's channel is verified, the claim route answers 409 `{code: "conflict", error: "channel not verified"}` and claims nothing. Otherwise it claims the oldest unclaimed conversation notification of the agent, binding it to the claiming session; a claimed notification is not offered again in C1 (C5 adds returning and redelivery).

**Notification:** `{id, kind, conversation_id, message_id, session_id, created_at, claimed_at, forwarded_at}`. In C1 `kind` is always `message`.

**Claim:** `{notification, conversation, messages, window, window_total, redelivered}`:
- `conversation` is the agent's summary `{conversation_id, title, state, home_host_id, participants: [{id, label, kind, state, you}], unseen, last_message_at, creator}`, where `you` marks this agent and `creator` is whether this agent created the conversation. `unseen` counts this agent's message notifications in the conversation not yet forwarded, this one included (C5 replaces forwarding with seen).
- `messages` is a list of adapter message views, in C1 exactly the notification's message: `{message_id, author, author_label, author_kind, origin_agent_id, sender_person_id, sender_person, seq, clock, sent_at, received_at, content, addressed_to, addressed, mine}`. `origin_agent_id` is null for person authors. `sender_person_id` and `sender_person` are the person bound to the author's host and its member label, as for one-to-one handoffs, null when unbound. `addressed` is true when `addressed_to` is empty or includes this agent.
- `window` is non-empty only on the first notification of this conversation that this session claims: the messages this agent may see that sort before the new one in display order, at most the newest 10 and 16,384 bytes of (cut) content, newest kept, in display order. Each window entry is an adapter message view whose `content` is cut to its first 2,048 bytes at a UTF-8 boundary, with `truncated: true` and `content_bytes` (the full length) when cut, and `truncated: false` otherwise. Otherwise `window` is `[]`.
- `window_total` is the number of messages this agent may see before the new one when `window` is filled (the session's first claim in the conversation), and 0 whenever `window` is `[]`.
- `redelivered` is always false in C1.

### Node adapter

#### The `conversation` event

For each claim, the shared adapter emits one channel event with `meta.kind` `conversation`, then calls `forwarded`. It claims conversation notifications in the same loop and under the same readiness rule as other work.

`meta` is `{kind, conversation_id, notification_id, message_id, author, author_label, author_kind, origin_agent_id, sender_person_id, sender_person, seq, clock, addressed, catch_up, unseen, session_id, redelivered}`, from the claim's new message and summary. `catch_up` is false in C1. As for other events, Claude Code receives strings (numbers and booleans as JSON text, nulls omitted), and other integrations receive JSON types. The presentation title is `Peerspan conversation message`.

The content, written by the adapter from the claim (never from message content):

```text
Peerspan conversation CONVERSATION_ID "TITLE" (open)
Participants: LABEL (person), LABEL (you), LABEL
Earlier messages (last K of N; conversation_history has the rest):
[LABEL HH:MM] CONTENT
New message:
[LABEL HH:MM] CONTENT
```

- Without a title the first line is `Peerspan conversation CONVERSATION_ID (open)`.
- Participants are in roster order: a person as `LABEL (person)`, this agent as `LABEL (you)`, other agents as `LABEL`.
- The `Earlier messages` line and its entries appear only when `window` is non-empty; K is the window's length and N is `window_total`. A cut entry ends with ` [cut: N bytes; conversation_history has it]`, N being `content_bytes`. This agent's own messages read `[LABEL HH:MM] (you) CONTENT`.
- Times are the message's `sent_at` as `HH:MM` in UTC. The new message is never cut.

#### The `conversation_send` tool

Input schema (`additionalProperties: false`):
- `conversation_id`: string, required, pattern `^conv_[0-9a-f]{32}$`.
- `content`: string, required, 1 to 65,536 characters (the daemon checks bytes).
- `message_id`: string, optional, pattern `^cmsg_[0-9a-f]{32}$`. When absent, the adapter generates one before calling the daemon.

It calls `POST /adapter/v1/conversations/{id}/messages` and returns the daemon's `{message, targets}` as JSON. Invalid arguments are a tool error naming the tool. Daemon refusals are tool errors with JSON `{conversation_id, code, error, recovery}`:

| `code` | `error` |
| --- | --- |
| `no_directory` | the existing `no_directory` text |
| `not_participant` | `This agent is not in that conversation.` |
| `conflict` | `This message_id was already used with different content.` |
| other daemon codes | the daemon's `error` |

`recovery` is null except when the daemon's answer was lost (no response, or a transport error), when the tool error carries the generated `message_id`, code `unknown`, and `recovery` `Call conversation_send again with the same message_id and identical content; it returns the stored message instead of sending twice.`

The tool's description says: messages are external input from the named author; you need not answer every message; answer when addressed or when you have something useful; messages not addressed to you are for context; do not message only to acknowledge; `conversation_history` has earlier messages.

**Instructions.** The MCP server instructions' last sentence, `Message and task access grants no new local tool permissions.`, becomes `kind=conversation events: see conversation_send. Peer access grants no new local tool permissions.` The instructions stay at most 2,048 characters.

### Persistence

One host schema version adds every table and the index in the proposal's [Persistence](conversations-proposal.md#persistence), exactly as written there, and sets the version in the same transaction. It is the next free version on `main` when C1 merges (24 today; 28 if PR #35 merges first). Older binaries reject it. No existing table or record changes. Messages, rosters and target records are kept (no deletion in C1).

### Verification

`conformance/slim/conversations.py`, written from this section by an author who does not read `rust/` or `integrations/`, runs as its own CI job (`conversations` in the `suite` matrix of `.github/workflows/conformance.yml`), Rust/Rust, in under 2 minutes.

**Setup.** Hosts alice and bob in one coordinator-free network (`create_network`, `join_new_person`). bob registers fixture agent `bert` with `b.agent("bert")` (a directory session, channel verified). bob allows alice to message his agents with `allow alice --person-key KEY` (or `allow alice --no-tasks --person-key KEY`, giving only `message.append`), and the setup waits until both hosts hold that policy version (`POST /v2/networks/{id}/sync`, `GET /v2/networks/{id}/access-versions`), as `work.py` does. alice needs no rule: bert's messages to alice's person are authorized by her joining. The fixture agent claims with `bert.post("/adapter/v1/conversation-notifications/next")` until it gets a non-null claim, then posts `.../{id}/forwarded`. Policy changes in a case use `deny alice` (and, after it, the same sync wait for bob's new version where the case depends on alice's host holding it).

**Cases:**
- **Start and deliver.** `conversation start bob/bert --title T --message M` on alice: the invite outcome is `joined` with participant `agent:BOB_HOST/BERT_ID`; the conversation view lists the person participant and `bert` (`label` `bob/bert`) `joined`, roster version 2; the message's target for `bert` becomes `delivered` (polled through `conversation show --json`).
- **Claim.** `bert` claims one notification whose `messages[0]` has the content, author `person:ALICE_HOST/ALICE_PERSON`, `author_kind` `person`, `author_label` `alice`, `seq` 1, `clock` 1, `origin_agent_id` null, and `sender_person` `alice`; `conversation.unseen` 1; `window` `[]`; `redelivered` false; a second claim is `null`; `forwarded` is idempotent.
- **Reply.** `bert` sends with its own `message_id` through the adapter route; its target for alice's person becomes `delivered`; alice's `conversation show --json` lists both messages in `(clock, author, seq)` order, bert's with `clock` 2, `seq` 1, `author_label` `bob/bert`, `mine` false and `targets` null, alice's own with `mine` true and `targets`.
- **Repeats.** The same `message_id` with the same content returns the stored message (same `seq`, no new message in `show`); with other content, 409 `conflict`. The same for `conversation say --message-id` on alice.
- **Refused after deny.** After bob runs `deny alice`, alice's next `conversation say` gets a target for `bert` that becomes `refused` with `code` `not_authorized`, and `bert` gets no notification for it.
- **Edges.** The claim route answers 409 before the channel is verified (a session attached with `ready=False`); a session without directory access gets `null` from the claim route and 403 `no_directory` from the sending route; `conversation say` by bob's person (not a participant) exits 1 with `not_participant`; `conversations --json` on both hosts lists the conversation; an ID prefix of `conv_` and 6 hex digits works with `show`.

**Node adapter.** The slim suite cannot reach the Node adapter, so `integrations/shared` tests (run with `node --test`, as its existing tests are) cover: the `conversation` event's `meta` and content from a claim, with and without a title and a window, including a cut window entry; `forwarded` after the event; `conversation_send` input validation, a generated `message_id` when absent, the daemon call, and the `not_participant`, `conflict` and lost-response tool errors; and the instructions' new last sentence, within 2,048 characters.

## C2: membership

C2 adds more than two participants, agents as creators, local participants (decision 18), adding, removing, leaving and closing, roster pushes and fetches, and the agent tools for them. Everything in C1 stays as written unless this section changes it. Not in C2: person participants other than the home host's own person, person invites, `join` and `decline` (C3); the 10-minute conversation sync, `heads`, `acks`, gap fetches and the 24-hour push window (C4); seen, redelivery, `pending_work`, `conversation_history` and `conversation_undelivered` (C5); rate limits, `addressed_to` from local surfaces, the read cursor, the event log, `forget`, status, and `home_unavailable` (C6). CONV-24 still holds: none of the commands below are listed in the root help, the README or the quick start.

### Roster changes

**Shape.** The roster is C1's, with these values now possible:
- `state` `open` or `closed`.
- `created_by` a person participant or an agent participant on the home host.
- `participants[].state` `inviting` or `joined` (`invited` is C3).
- `departed` lists `{id, kind, reason, at}` for participants no longer in the conversation, with `reason` `left`, `removed` or `unanswered`, and `at` when home recorded it. An ID appears at most once in `participants` and `departed` together. Re-adding a departed participant removes its `departed` entry. A target whose invite was refused is dropped without a `departed` entry (it never joined).

**Authority.** Only the home host changes the roster. Each change is one new roster with a higher `version`, committed in one transaction with whatever caused it: one higher than home's current version, or higher still when an invite already offered that version (below). After close (`state` `closed`), home commits no further version: no add, remove, leave, or `unanswered` drop changes a closed roster.

**Admission.** A host decides itself which of its own participants are joined, and never takes a peer's word for it (C1, peer rules). It **admits** a local participant when:
- it is the home host and creates the conversation with that participant as creator, or commits a local agent as `joined` (at start or by `add`); or
- it accepts an invite for that agent (`POST /peer/v1/conversations/invites`, answered `joined`).

A local participant is **joined here** while this host has admitted it, it has not left on this host, and no roster this host stored after the admission lists it in `departed` or omits it. A stored roster listing an admitted local participant as `inviting` (an older view of home's) does not end the admission. Every local check and view that C1 bases on "joined" (sending, message acceptance step 4, the claim, the list) uses "joined here" for local participants and the held roster for remote ones. Views on this host show a local participant that is not joined here, but that the held roster still lists, in `departed` with this host's own reason (`left` after a local leave).

**Pushes.** After committing a version, home pushes its newest roster with `POST /peer/v1/conversations/{id}/roster` to every other host that has a participant in it (any state) or that has a participant this version moved to `departed`. Pushes to one host coalesce: only the newest roster is sent, and a push is done when that host answers 200 with a `version` at or above it. Home retries with the C1 retry schedule and concurrency (pushes share the 4 conversation attempts with invites and messages), without a time limit in C2. A 400, 403 or 404 answer ends the push of that roster to that host; a later version is pushed again.

**Invites with several targets.** Home may have several invites outstanding. Each invite attempt carries home's current roster with the target `joined` and `version` one higher; home remembers the highest version each invite offered. When the answer is `joined` and home's version is still the one below the version that invite offered, home commits exactly the invite's roster at that version. Every other change, including a join after home's roster moved on, is committed at one more than the higher of home's current version and every version an invite of the conversation offered. So a host holding an invite's roster that home did not commit always receives a higher version, and its push corrects it. When a `joined` answer arrives for an invite home already stopped (the target was removed, dropped as `unanswered`, or the conversation closed), home pushes its current roster to that host again.

### Starting, now with several participants and agent creators

`POST /v1/conversations` body: `{participants, title?, content?, message_id?, note?, as?, network?}`. C1's steps apply with these changes:
1. **Shape.** `participants` is 1 to 15 distinct strings of at most 256 characters, each an agent address (`PERSON/AGENT` or `HOST_ID/AGENT`). A person form is still 400 `invalid` with `person participants are not supported yet` (C3). `note` is 0 to 4,096 bytes of UTF-8. `as` names a local agent (its ID or name); the creator is then `agent:HOST_ID/AGENT_ID` instead of the person participant. An unknown `as` is 404 `not_found`.
2. **Bound person.** Only without `as`: 409 `not_bound`. A start with `as` needs no bound person.
3. **Resolution** as in C1, except that an address naming an agent on this host resolves to that local agent instead of 400 `local`. Local agents are matched beside the directory: `HOST_ID/AGENT` with this host's ID, or `PERSON/AGENT` where PERSON is this host's bound person's label and AGENT is registered here. An address matching a local agent and a remote one is 409 `ambiguous`. Two targets resolving to the same participant, or a target resolving to the creator, are 400 `invalid`.
4. **Authorization** for each remote target as in C1, for the creator (an agent creator is the origin agent when choosing the citation). Any target failing is 403 `not_authorized` and nothing is persisted. Local agents need none (self access).
5. **Limits.** The creator already joined here in 200 open conversations is 429 `{code: "limit", error: "A participant can be in at most 200 open conversations."}`, before anything is persisted.
6. **Persist** roster version 1: the creator `joined`; each local agent target `joined` unless it is joined here in 200 open conversations, in which case it is left out with outcome `refused`, code `limit`; each remote target `inviting`.
7. **Invites** to the remote targets, all at once, as in C1 and [Invites with several targets](#roster-changes); `note` is sent with each. The route waits at most 15 seconds for all of them together.
8. **First message** with `content`, as in C1, to the participants `joined` at that moment.

Each local agent admitted here, other than the creator, gets an `added` notification (below).

Answer: 201 `{conversation: VIEW, invites: [INVITE OUTCOME], message: MESSAGE VIEW or null}`, with one invite outcome per target in the order given.

**Invite outcome** gains `reachable_from` and `reaches`, and `refused` gains code `limit`: `{target, participant, label, state, code, error, reachable_from, reaches}`.
- `state` is `joined`, `inviting`, `refused` or `unsupported`. `code` is `not_authorized` (403), `invalid` (400), `limit` (429), `not_participant` (403 `not_participant`) or `unsupported` (404), null otherwise.
- `reachable_from` lists the IDs of the other participants (`joined` or `inviting`) that may send messages to this participant, and `reaches` those this participant may send to, as far as the home host knows, in roster order. Both are `[]` unless `state` is `joined` or `inviting`. Home decides each ordered pair X to Y this way: Y a person participant is reachable from every participant whose host and person this host has not blocked; Y an agent is reachable from X when X and Y are on one host, when both hosts are bound to the same person by current binding grants this host holds, or when Y's owner's current `policy` statement that this host holds, in a network shared by both hosts, allows `message.append` from X (X's `agent:` principal, X's host's person, `network`, `everyone`, or a group of them, for Y's agent name or `*`). Manual grants count only when this host is one of the two hosts. These lists are information; they authorize nothing, and each recipient still decides each message.

### Managing

`POST /v1/conversations/{id}/manage` body `{action, participant?, as?, network?}`; `action` is `add`, `remove` or `close`. `as` names the local agent acting (ID or name), otherwise the person participant acts (409 `not_bound` without a bound person). `network` is only for `add`. `participant` is required for `add` and `remove` and refused (400) for `close`. Checks, in order:
1. Shape, then 404 `not_found` for an unknown conversation.
2. The actor is the conversation's `created_by` and this host is home; otherwise 403 `{code: "not_creator", error: "Only the conversation's creator can add, remove, or close."}`. An actor that is the creator but no longer joined here is 403 `not_participant`.
3. A closed conversation is 409 `{code: "closed", error: "This conversation is closed."}`, except `close`, which answers 200 with the view again.

**`add`**: `participant` is an agent address, resolved and authorized as at start (resolution and authorization errors as there). A target already `joined` or `inviting` answers 200 with its current outcome and changes nothing. With 16 participants already `joined` or `inviting`, 409 `{code: "full", error: "A conversation has at most 16 participants."}`. A local agent is committed `joined` at once (or `refused` `limit`); a remote one is committed `inviting` and invited, the route waiting at most 15 seconds for the answer (it answers as soon as every invite it waits for has a final answer). Answer: 200 `{conversation: VIEW, invite: INVITE OUTCOME}`.

**`remove`**: `participant` is a participant ID, or a label that matches exactly one participant in `participants` as this host shows it. No match is 404 `{code: "not_found", error: "No such participant in that conversation."}`; several are 409 `ambiguous` with the matching IDs in `matches`; the creator itself is 400 `invalid` (the creator leaves instead). The participant, `joined` or `inviting`, moves to `departed` with `reason` `removed`; an outstanding invite to it stops. Answer: 200 `{conversation: VIEW}`.

**`close`**: home sets `state` `closed` in a new version and stops every outstanding invite (those participants stay `inviting` in the closed roster). Answer: 200 `{conversation: VIEW}`.

**Unanswered invites.** A participant still `inviting` 10 minutes after its `added_at` (on home's clock) is moved by home to `departed` with `reason` `unanswered`, in a new version, within 15 seconds after the 10 minutes pass; its invite stops, and a later `joined` answer to it is ignored. This applies only while the conversation is open.

### Leaving

`POST /v1/conversations/{id}/leave` body `{agent?}`. Without `agent`, the person participant leaves (409 `not_bound` without a bound person); with `agent` (a local agent's ID or name, 404 `not_found` if unknown), the owner takes that agent out. The participant must be joined here, otherwise 403 `not_participant`; a conversation held as closed is 409 `closed`. Answer: 200 `{conversation: VIEW}`.

Leaving takes effect on the leaving host at once, in one transaction: the participant is no longer joined here, so this host refuses messages to it (403 `not_participant`), sends none as it, and creates no further notification for it; an agent's unclaimed `message` notifications in the conversation are withdrawn and never offered. If this host is home, it then commits the participant to `departed` (`left`) as a new version and pushes it. Otherwise it sends `POST /peer/v1/conversations/{id}/leave` to home with the C1 retry schedule until home answers 200 (stored if its roster is newer) or 400, 403 or 404. The creator may leave; afterwards nobody can add, remove or close.

A local agent that is removed, or whose departure arrives in a pushed roster, is treated the same way here: it stops being joined here and its unclaimed `message` notifications are withdrawn; it gets a `removed` notification when the reason is `removed`.

### Closed conversations

- **Authoring.** A host that holds a conversation as closed refuses new messages from local surfaces with 409 `{code: "closed", error: "This conversation is closed."}` (owner, CLI and adapter routes), and refuses `leave` the same way. Messages already stored keep their targets and retries.
- **Acceptance step 5 (new).** Between C1's steps 4 (roster) and 5 (authorization): a conversation this host holds as closed is 409 `{code: "closed"}`, except a message whose `roster_version` is lower than the version of the closed roster this host holds. Such a message was authored before its author's host knew of the close, and is accepted if every other step passes.
- **Views.** The conversation stays readable. `state` is `closed` everywhere, and `GET /v1/conversations?state=all` lists it.

### Local participants

A message whose target is on the author's host is delivered in the same transaction that stores it, with no peer request: its target record is created `delivered` with `attempts` 0, together with the inbound target record and, for an agent target, its notification. Self access authorizes it; it is still subject to "joined here" for both author and target. A remote author's message to several participants on one host is one peer request per target (C1), stored once.

### Local API and CLI changes

**Views.**
- The conversation view gains `departed: [{id, kind, label, reason, at}]`, from the held roster and this host's own local departures.
- `GET /v1/conversations` lists, by default, open conversations with a local participant joined here; `state=all` adds closed conversations and those whose local participants have all departed.
- Target views gain codes `closed` (from a 409 `closed`) and `limit` (from a 429) for `refused`.

C1's answer table becomes:

| Answer | Target |
| --- | --- |
| 200 with a receipt for this `message_id` and target | `delivered` |
| 400 | `refused`, `invalid` |
| 403 `not_participant` | `refused`, `not_participant` |
| any other 403 | `refused`, `not_authorized` |
| 409 `closed` | `refused`, `closed` |
| any other 409 | `refused`, `conflict` |
| 429 | `refused`, `limit` |
| 404 | `unsupported`, error `HOST_ID is running a Peerspan without conversations` |
| anything else, or no answer | stays `sending`, retried |

**CLI.** Each prints the route's JSON answer and exits 0, or exits 1 with `error: CODE: TEXT` (C1).

| CLI | Route |
| --- | --- |
| `conversation start TARGET... [--title T] [--message TEXT] [--message-id ID] [--note TEXT] [--as AGENT] [--network ID]` | `POST /v1/conversations` |
| `conversation add ID TARGET [--as AGENT] [--network ID]` | `POST /v1/conversations/{id}/manage` `add` |
| `conversation remove ID PARTICIPANT [--as AGENT]` | `.../manage` `remove` |
| `conversation close ID [--as AGENT]` | `.../manage` `close` |
| `conversation leave ID [--agent NAME]` | `POST /v1/conversations/{id}/leave` |
| `conversations [--all] [--json]` | `GET /v1/conversations`, `--all` as `state=all` |

`ID` accepts a prefix as in C1. `--as AGENT` and `--agent NAME` take an agent name or ID on this host.

### Peer routes

All are on the peer router with C1's rules: per-request host authentication, the 1 MiB body limit, strict JSON (400 `invalid`), a sender that is not a current member of a shared coordinator-free network is 403 `forbidden`, and none is served on the first-contact listener, the completion listener or a helper. A route naming a conversation the receiver holds no roster for is 404 `{code: "not_found"}`.

#### `POST /peer/v1/conversations/{id}/roster`

Body `{roster}`, from home to a participant host. In order:
1. **Shape.** As for an invite's roster in C1, with the C2 values above (`closed`, `departed`); `roster.conversation_id` equals the path's; otherwise 400 `invalid`.
2. **Held.** No roster held for the conversation is 404 `not_found`.
3. **Sender.** The authenticated sender is the held roster's `home_host_id`, and `roster.home_host_id` equals it; otherwise 403 `forbidden`.
4. **Version.** A `version` at or below the held one changes nothing: 200 `{version}` with the held version.
5. **Local participants.** A roster that lists a participant on this host as `joined` when that participant is not joined here is 400 `invalid` and nothing is stored, with one exception: a local agent that left here and whose leave home has not yet confirmed is accepted as listed, and stays not joined here. Listing a local participant as `inviting`, in `departed`, or not at all is accepted.
6. **Store** the roster. Local participants it lists in `departed`, or omits after their admission, stop being joined here (as in [Leaving](#leaving)); each such agent with `reason` `removed` gets a `removed` notification, and each local agent still joined here when the roster first shows `state` `closed` gets a `closed` notification. Answer 200 `{version}` with the new version.

Home creates the same `removed` and `closed` notifications for its own local agents when it commits the change, except for the agent that made it.

#### `GET /peer/v1/conversations/{id}/roster`

From a participant host to home. Home answers 200 `{roster}` with its current roster when the sender host holds a participant in it in any state or in `departed`; otherwise 404 `not_found`, which is also the answer of a host that is not home. The requester stores the answer as it stores a push (steps 3 to 6).

A host fetches the roster from home when message acceptance step 4 meets a `roster_version` above the version it holds (it still answers 503 `unavailable`, so the author retries), at most one fetch per conversation at a time. A host that holds no roster for the conversation still answers 503 without a fetch (it does not know home).

#### `POST /peer/v1/conversations/{id}/leave`

Body `{participant}`, from a participant's host to home. `participant` is an `agent:` participant ID whose host is the authenticated sender, otherwise 403 `forbidden` (a `person:PERSON_ID` decline is C3 and is 400 here). Home moves it from `participants` to `departed` with `reason` `left` as a new version and pushes it; a participant already departed or not listed changes nothing; a closed conversation changes nothing. Answer: 200 `{roster}` with home's current roster.

#### Changes to the C1 routes

**`POST /peer/v1/conversations/invites`:**
- The roster may list other agents on the receiver as `inviting`; it may list another agent on the receiver as `joined` only when that agent is joined here; any `person:RECEIVER/…` participant is still 400. Its `state` must be `open`, and it may carry `departed`.
- The target agent joined here in 200 open conversations is 429 `{code: "limit", error: "A participant can be in at most 200 open conversations."}`.
- The first acceptance admits the agent and creates an `added` notification for it, with the invite's `note`. A repeat for the same `(home, conversation_id, target)` whose roster gives the target the same `added_at` answers `{state: "joined", name}` again with no new notification while the agent is joined here, and 403 `not_participant` after it left or was removed. A repeat with a later `added_at` (a re-add) is a new invite. An invite superseded by a roster this host already holds is 403 `not_participant` and admits nothing: the held roster differs from the invite's roster, has a version at or above it, and either does not list the target or lists it with another `added_at`. Home ignores an answer to an invite it has since replaced by re-adding the target; a `joined` answer for it only makes home push its current roster to that host again.
- The receiver stores the invite's roster when it holds none or a lower version.

**`POST /peer/v1/conversations/{id}/messages`:** step 4 fetches the roster as above, and the new closed step comes before authorization. "Joined" for the target means joined here. As in C1's persist step, a message whose author and `seq` this host already holds under another `message_id` is 409 `conflict`: an author's host never numbers two messages alike.

### Notifications and adapter routes

**Notification** gains `kind` `roster` beside `message`, and `change`: null for `message`, otherwise `{change, by, by_label, note, roster_version}`. `change` is `added` (this agent was admitted, by invite or at home), `removed` (home removed it), or `closed`. `by` is the participant that made the change (the adder, or the creator for `removed` and `closed`) and `by_label` its label here. `note` is the invite's note for `added`, null otherwise. The creator gets no `added` notification. Leaving creates no notification.

The claim route claims the oldest unclaimed notification of either kind. A `roster` claim is `{notification, conversation, messages: [], window: [], window_total: 0, redelivered: false}`, with `conversation` the agent's summary after the change. A `roster` claim does not count as the session's first claim in the conversation for C1's window rule.

**Agent summary** is C1's: `{conversation_id, title, state, home_host_id, participants: [{id, label, kind, state, you}], unseen, last_message_at, creator}`, `participants` excluding `departed`.

| Route | Body / query | Answer |
| --- | --- | --- |
| `GET /adapter/v1/conversations` | | 200 `{conversations: [AGENT SUMMARY]}`: the open conversations this agent is joined in, and closed ones it was joined in at the close with `unseen` above 0, newest activity first. |
| `POST /adapter/v1/conversations` | `{participants, title?, content?, note?, message_id?}` | As `POST /v1/conversations` with this agent as creator (`as`) and the first message's `origin` `{agent_id, session_id}`: 201 `{conversation: AGENT SUMMARY, invites: [INVITE OUTCOME], message: MESSAGE VIEW or null}`, the message view (with its `targets`) as the adapter sending route returns it. |
| `POST /adapter/v1/conversations/{id}/manage` | `{action, participant?}` | `action` `add`, `remove`, `leave` or `close`. `add`, `remove`, `close` as the owner's manage route with this agent as actor; `leave` as the owner's leave route for this agent. 200 `{conversation: AGENT SUMMARY, invite}` with `invite` the outcome for `add` and null otherwise. |

All three require directory access (403 `no_directory`) and work before the channel is verified. Their errors are the owner routes' (`not_found`, `not_participant`, `not_creator`, `closed`, `full`, `limit`, `ambiguous`, `unknown`, `not_authorized`, `invalid`). `participant` for `add` and `remove` follows the owner routes; for `leave` and `close` it is 400.

### Node adapter

**The `conversation_roster` event.** For a claim whose notification `kind` is `roster`, the adapter emits one channel event with `meta.kind` `conversation_roster`, then calls `forwarded`. `meta` is `{kind, conversation_id, notification_id, change, by, by_label, roster_version, session_id, redelivered}`, with C1's value encoding. The presentation title is `Peerspan conversation change`. The content, written by the adapter from the claim:

```text
Peerspan conversation CONVERSATION_ID "TITLE" (STATE)
Participants: LABEL (person), LABEL (you), LABEL
SENTENCE
```

The first two lines are as for the `conversation` event (`STATE` is the summary's state). `SENTENCE` is:
- `added`: `BY_LABEL added you to this conversation. Send with conversation_send; you see messages sent from now on.`, followed, when there is a note, by a line `Note from BY_LABEL: NOTE`.
- `removed`: `BY_LABEL removed you from this conversation; you can no longer send to it.`
- `closed`: `BY_LABEL closed this conversation; it can still be read, but no one can send to it.`

**Tools.** Each has `additionalProperties: false`; invalid arguments are a tool error naming the tool. Daemon refusals are tool errors `{conversation_id, code, error, recovery}` with `recovery` null and `conversation_id` null where there is none, using these texts, and the daemon's `error` for other codes:

| `code` | `error` |
| --- | --- |
| `no_directory` | the existing `no_directory` text |
| `not_participant` | `This agent is not in that conversation.` |
| `not_creator` | `Only the conversation's creator can add, remove, or close.` |
| `closed` | `The conversation is closed; it can still be read with conversation_history.` |
| `full` | `A conversation has at most 16 participants.` |

`conversation_send` uses the `closed` text too.

| Tool | Input | Call |
| --- | --- | --- |
| `list_conversations` | `{}` | `GET /adapter/v1/conversations`; returns its JSON. |
| `conversation_start` | `participants` (required, 1 to 15 strings of at most 256 characters), `title` (at most 200 characters), `content` (1 to 65,536 characters), `note` (at most 4,096 characters) | `POST /adapter/v1/conversations`, with a `message_id` the adapter generates when `content` is given; returns its JSON. A lost response with `content` is a tool error with code `unknown`, the generated `message_id`, and `recovery` `Check list_conversations before starting again; the conversation may exist.` |
| `conversation_manage` | `conversation_id` (required, `^conv_[0-9a-f]{32}$`), `action` (required: `add`, `remove`, `leave`, `close`), `participant` (string of at most 256 characters, required for `add` and `remove`, not allowed for `leave` and `close`) | `POST /adapter/v1/conversations/{id}/manage`; returns its JSON. |

The `conversation_start` description says that participants are agent addresses as `list_agents` shows them, that each participant's owner still decides who may message it, and that the result reports who can reach whom. The MCP server instructions do not change.

### Persistence

No new schema version: C1's tables hold everything (admission and local departures live in the conversation's `record`, roster pushes and leaves in `conversation_roster_outbound` with `kind` `roster` or `leave`, and `roster` notifications in `conversation_notifications`).

### Verification

The C1 suite gains C2 cases, written from this section by the same spec-only author, still under 2 minutes in total.

**Setup.** A third host carol joins alice's network (`join_new_person`). carol registers fixture agent `cara` (`c.agent("cara")`). alice registers local agents with `a.agent(...)` for the local cases (or `POST /v1/agents` alone when no session is needed). Policies: bob runs `allow alice --no-tasks --person-key KEY` and carol runs the same, so alice's person and alice's agents reach `bert` and `cara`; neither bob nor carol allows the other, so `bert` and `cara` cannot reach each other. Wait for the policy versions on every host as in C1. Agents reach alice's person by her joining. Before a case that stops carol, `agents --refresh --json` on alice must list `carol/cara`, so resolution needs no answer from carol. The 10-minute case uses the debug test clock (`suite.use_clock()` before the hosts start, then `suite.set_offset(...)`). Raw peer requests use `peerspan-peer-probe` with the sending host's state directory, as C1's invite cases do; a probe sent with alice's state is a request from home. Fixture agents claim `roster` notifications with the same claim route as messages.

**Cases** (the proposal's C2 column, made concrete):
- **Add and push.** alice starts with `bob/bert`, then `conversation add ID carol/cara`: outcome `joined`, `reachable_from` and `reaches` both exactly `[alice's person participant]`. Within 20 seconds bob's and carol's `conversation show --json` report alice's roster version and three `joined` participants. `cara` claims a `roster` notification with `change.change` `added` and `by` alice's person.
- **Unreachable pair.** `bert` sends through the adapter route: the target for alice's person becomes `delivered`, the one for `cara` `refused` with `not_authorized`; `cara` gets no `message` notification for it.
- **Remove.** `conversation remove ID carol/cara` (by label) on alice: every host reaches the new version with `cara` in `departed`, reason `removed`; `cara` claims a `removed` notification; a probe message from alice to target `cara` on carol is 403 `not_participant`; alice's next message has no target for `cara`. `remove` by bob's person on bob is 403 `not_creator`.
- **Leave.** `bert` leaves with `POST /adapter/v1/conversations/{id}/manage` `{action: "leave"}`: a probe message from alice to `bert` on bob is 403 `not_participant` at once; alice's roster then lists `bert` in `departed` with reason `left`. The owner form: bob's `conversation leave ID --agent bert` on a fresh conversation does the same.
- **Close.** `conversation close ID` on alice: every participant host shows `state` `closed` at the new version; `bert` claims a `closed` notification; `conversation say` on alice exits 1 with `error: closed: This conversation is closed.`; `bert`'s adapter send is 409 `closed`; a probe message from alice with `roster_version` equal to the closed version is 409 `closed`, and one with a lower `roster_version` (a new `message_id`) is accepted with 200; `conversations --all --json` lists it as `closed`; `add` after close is 409 `closed`.
- **Unanswered.** With carol stopped, `conversation add ID carol/cara` answers with outcome `inviting`; after the test clock moves 601 seconds, within 15 seconds alice's view lists `cara` in `departed` with reason `unanswered`. (Run it last: moving the clock 10 minutes outdates the hosts' signed contacts.)
- **Local participants.** alice starts with two local agents (`alice/ada alice/abe`); `ada` sends through the adapter route; the target for `abe` is `delivered` with `attempts` 0 in the answer, and `abe` claims the message. Both local agents got an `added` notification.
- **Agent creator.** `conversation start bob/bert --as ada` on alice gives `created_by` `agent:ALICE_HOST/ADA_ID`; `bert` sees `creator` false and `ada` `creator` true in `GET /adapter/v1/conversations`; `bert`'s `manage` `close` is 403 `not_creator`; `ada`'s `POST /adapter/v1/conversations` with `content` starts another conversation whose first message reaches `bert`.
- **Full.** A conversation of alice's person and 15 local agents: adding a 16th local agent is 409 `full`.
- **Roster route edges** (probe): a push from bob (not home) is 403 `forbidden`; a push from alice with a version at or below bob's held one answers 200 with the held version; a push from alice with a higher version that lists a bob agent never admitted (any agent registered on bob) as `joined` is 400 `invalid` and bob's version does not change; `GET .../roster` from carol after `cara` was removed answers 200 with the roster; a leave from bob naming carol's agent is 403 `forbidden`.

**Node adapter** (`node --test` in `integrations/shared`, as in C1): the `conversation_roster` event's `meta` and content for `added` (with and without a note), `removed` and `closed`; `forwarded` after it; input validation of `conversation_start`, `conversation_manage` (`participant` required and not allowed) and `list_conversations`; the generated `message_id` of `conversation_start`; and the `not_creator`, `closed` and `full` tool errors.

## C3: people

C3 lets a person be invited to a conversation, join it on one host bound to them, decline it, and take part from that host. Everything in C1 and C2 stays as written unless this section changes it. Not in C3: the 10-minute conversation sync, `heads`, `acks`, gap fetches and the 24-hour push window (C4); seen, redelivery, `pending_work`, `conversation_history` and `conversation_undelivered` (C5); rate limits, `addressed_to` from local surfaces, the read cursor and unread counts, the event log, `forget`, and `home_unavailable` (C6). CONV-24 still holds: none of the commands below are listed in the root help, the README or the quick start.

**Words.** A host is *bound* to a person when it holds a current binding grant for that person in a coordinator-free network (spec section 5; `GET /v2/networks/{id}/members`, field `person_id`). A person ID is `person_` and 64 lowercase hex digits. The *person participant* of a host is C1's `person:HOST_ID/PERSON_ID`. An invited person who has not joined has no participant ID; surfaces that need to name one use `person:PERSON_ID` (no `/`, as the policy principal).

### Roster changes

**Shape.** The roster is C2's, with these additions:
- `participants[].state` may be `invited`. A person entry is either joined, with `id` `person:HOST_ID/PERSON_ID`, `host_id` and `person_id` set; or not yet joined, with `id` null, `host_id` null, `person_id` set, `agent_id` and `name` null, and `state` `inviting` (no bound host has answered `invited` yet) or `invited` (at least one has).
- At most one person entry per `person_id`, joined or not. A person who joins keeps the entry's `added_by` and `added_at`.
- A person who never joined is dropped from `participants` without a `departed` entry, as C2 drops a refused invite: when every bound host refused the invite, when no bound host answered within 10 minutes, when the person declines, when the creator removes them, and when the invite expires. A person who joined and then leaves or is removed gets a `departed` entry as an agent does.
- C1's invite rule that a roster listing any `person:RECEIVER/…` participant is 400 becomes: an invite's roster (agent or person target) may list the receiver's person participant as `joined` only when it is joined here, and may list any person not yet joined. A roster push follows the admission rule below.

**Admission (C2's rule, extended).** A host admits its own person participant when:
- it is home and creates the conversation with that person as creator (C1); or
- the person runs `conversation join` here and home confirms it: a 200 answer to `POST /peer/v1/conversations/{id}/join` from this host, or, on home, the local join committing.

While this host has an *outstanding join* for the conversation (it sent a join that got no final answer), a roster from home that lists this host's person participant as `joined`, with the pending invite's `added_at` and a version at or above the pending invite's roster, is also home's confirmation and admits the person, while the pending invite is current. Nothing else admits a local person: an invite never does, and a roster listing a person on this host as `joined` without an admission or an outstanding join is 400 `invalid`, as C2's roster step 5 says for agents.

**Expiry.** A person entry still `inviting` or `invited` 7 days after its `added_at` (on home's clock) is dropped by home in a new version, within 15 seconds after the 7 days pass. C2's 10-minute `unanswered` rule applies to a person entry still `inviting`, dropping it without a `departed` entry. Both apply only while the conversation is open.

**Pushes.** C2's push set gains every host that answered `invited` to a person invite of the conversation, until a roster pushed to that host no longer lists that person as `inviting` or `invited` (the person joined, declined, was removed, or the invite expired) or has `state` `closed`. A host in the push set for a pending invite gets every newer roster, so its pending copy shows the current title and participants.

**Versions of person invites.** Person invites follow C2's [Invites with several targets](#roster-changes) with `invited` in place of `joined`: each attempt carries home's current roster with the person `invited` and the version one higher. On the first `invited` answer for a person still `inviting`, home commits the person as `invited` (exactly the offered roster when home's version is still the one below it, otherwise at one more than the higher of its current version and every offered version). Later `invited` answers from the person's other hosts change nothing.

### Pending invites

A host keeps one *pending invite* per `(conversation_id, person_id)` for its own bound person, with the invite's roster, `adder`, `note`, home, and `expires_at` = the person entry's `added_at` plus 7 days. A pending invite is current while it has not expired on this host's clock, not been joined or declined here, and not been dropped by a newer roster. A newer roster from home (pushed or fetched) replaces the pending invite's roster, and drops the pending invite when it no longer lists the person as `inviting` or `invited` with the same `added_at`, or when its `state` is `closed`.

A conversation known to this host only through a pending invite is not a conversation this host holds: reads (`GET /v1/conversations/{id}`, `.../messages`), sending, and every peer message route treat it as unknown (404 `not_found` locally, as C1; 503 `unavailable` at message acceptance step 4, as C1 for a conversation with no roster). Only `conversations --invites`, `join`, `decline`, the roster push and the roster fetch use it.

On home, an invite for a person that home itself is bound to is a pending invite held on home, created when the entry is committed, with no peer request; it counts as an `invited` answer from home.

### Starting and adding people

`POST /v1/conversations` (`participants`), `POST /v1/conversations/{id}/manage` `add` (`participant`), and their adapter and CLI forms accept person targets beside agent addresses: `person:PERSON_ID`, `person:LABEL`, or a bare label with no `/`. C1's 400 `person participants are not supported yet` is gone.

**Resolution of a person target**, with optional `network` limiting it to one network:
- `person:PERSON_ID` names a person admitted in a current person grant of one of home's coordinator-free networks (`GET /v2/networks/{id}/persons`, `person_id` of `person_public_key` as above); otherwise 404 `{code: "unknown", error: "No person with that ID in this host's networks."}`.
- `person:LABEL` or a bare label is matched exactly against the `member` label of those persons. No match is 404 `{code: "unknown", error: "No person with that label in this host's networks."}`; labels of more than one distinct person are 409 `{code: "ambiguous", error: "That label matches more than one person.", matches: [PERSON_ID, …]}`. A person admitted in several networks under one label is one match.
- The person's **bound hosts** are every host that is a current member, with a current binding grant for that person, of a coordinator-free network home belongs to (with `network`, of that network), home included. No bound host is 404 `{code: "unknown", error: "No current host is bound to that person."}`.
- The creator's own person (the creator is that person participant) is 400 `invalid`, as C2 refuses a target resolving to the creator. Two targets resolving to the same person are 400 `invalid`.

**No authorization step** for person targets: any member host that the person's host has not blocked may invite a person (decision 7). Each bound host decides for itself when the invite arrives.

**Persist and invite.** The person entry is committed `inviting` (or `invited` at once when home is a bound host, with home's pending invite). Home sends the invite to every other bound host, all at once, with C1's retry schedule and C2's concurrency, sharing the start's or the add's 15-second wait. A person entry counts toward the 16-participant limit while `inviting` or `invited`.

**Already present.** At `add`, a person who is already joined (from any host), `inviting` or `invited` answers 200 with the current outcome and changes nothing.

**Invite outcome** for a person: `{target, participant, label, state, code, error, reachable_from, reaches, hosts}`.
- `participant` is `person:PERSON_ID` while not joined, and the participant ID once joined. `label` is the person's member label as this host derives it.
- `hosts` lists, in host ID order, each bound host and its answer: `{host_id, state, code}` with `state` `invited`, `inviting` (no final answer yet), `refused` or `unsupported`, and `code` as for target views (null unless `refused` or `unsupported`). Agent outcomes carry `hosts` `[]`.
- `state` is `joined` when the person joined, else `invited` when any host answered `invited` (or home is bound), else `inviting` while any host has no final answer, else `unsupported` when every host answered 404, else `refused` with the `code` of the first refusing host in `hosts`. A person whose outcome is `refused` or `unsupported` is dropped from the roster.
- `reachable_from` and `reaches` are C2's, and also filled for `invited`. For a person not yet joined, the pair rules use the person in place of the participant's host and person: Y is reachable from that person when Y's host is bound to the same person, or Y's owner's current policy allows `message.append` from `person:PERSON_ID`, `network`, `everyone`, or a group containing that person; the person is reachable from every participant whose host and person home has not blocked.

**Answer to a person invite at home**, per host, extends C2's table: 200 `{state: "invited"}` is `invited`; 400 `refused` `invalid`; 403 `not_participant` `refused` `not_participant`; any other 403 `refused` `not_authorized`; 429 `refused` `limit`; 404 `unsupported`; anything else is retried.

**Removing** (`manage` `remove`) accepts a person not yet joined by `person:PERSON_ID` or by its label (C2's label matching now includes their labels). It drops the entry (no `departed` entry) and stops the person's outstanding invites. A joined person is removed as C2 removes an agent: `departed` with `reason` `removed`, and the person's host stops treating it as joined here when it stores that roster.

### Local API and CLI

**Views.**
- The participant view of a person not yet joined has `id` null, `host_id` null, `person_id`, `label` (its member label, or the person ID when this host knows no label), `state` `inviting` or `invited`, and `local` false.
- The readable `conversation show` header marks a participant that is not joined with ` (invited)` or ` (inviting)` after its label, for example `dave (invited)`.
- The agent summary's `participants` include persons not yet joined, as `{id: null, label, kind: "person", state, you: false}`.

**Routes.**

| Route | Body / query | Answer |
| --- | --- | --- |
| `GET /v1/conversations/invites` | | 200 `{invites: [INVITE VIEW]}`: the current pending invites on this host, newest `added_at` first; `{invites: []}` when there are none, and on a host with no bound person (for example, one whose binding lapsed), never `not_bound`. |
| `POST /v1/conversations/{id}/join` | `{}` | 200 `{conversation: VIEW}` once home confirmed. |
| `POST /v1/conversations/{id}/decline` | `{}` | 200 `{conversation_id, state: "declined"}`. |

`{id}` in the join and decline routes is a full conversation ID. Unknown fields and nulls are 400.

**Invite view:** `{conversation_id, title, home_host_id, person_id, added_by, added_by_label, note, added_at, expires_at, participants: [{id, label, kind, state}]}`, from the pending invite's roster; `title` and `note` are null when absent; labels are derived here.

**Joining**, in order:
1. No current pending invite here in that conversation (for this host's bound person, or for any person when this host has none): 404 `{code: "not_found", error: "No pending invite to that conversation on this host."}`.
2. 409 `not_bound` without a bound person.
3. This host's person participant already joined here in 200 open conversations: 429 `limit` with C2's text.
4. On home: the local join commits as home's peer join route below would for this host. Elsewhere: this host records an outstanding join and sends `POST /peer/v1/conversations/{id}/join` to home, waiting at most 15 seconds:
   - 200 `{roster}`: in one transaction this host admits its person participant, stores the roster, drops the pending invite and the outstanding join. Answer 200 `{conversation: VIEW}`.
   - 404: the pending invite and the outstanding join are dropped; answer 404 `not_found` with step 1's text.
   - 409 `closed`: dropped; answer 409 `closed` with C2's text. 409 `conflict`: dropped; answer 409 `{code: "conflict", error: "That person already takes part from another host."}`.
   - 403: dropped; answer 403 `{code: "forbidden", error: "The home host refused the join."}`.
   - Anything else, or no answer within 15 seconds: the pending invite and the outstanding join stay, and the answer is 503 `{code: "unavailable", error: "The home host did not answer; run conversation join again."}`. The host does not retry by itself; running `join` again sends again, and home answers a repeat as a success.

The outstanding join ends with a final answer, when the pending invite stops being current, or when a roster from home admits the person.

**Declining**, in order: 404 `not_found` as for joining; 409 `not_bound`; then, in one transaction, this host drops the pending invite (it is no longer current here) and records a decline for home. On home the decline commits at once (as home's leave route below). Elsewhere this host sends `POST /peer/v1/conversations/{id}/leave` `{participant: "person:PERSON_ID", added_at}` (the declined invite's `added_at`) to home with C1's retry schedule until home answers 200, 400, 403 or 404, as C2 sends a leave. Answer 200 `{conversation_id, state: "declined"}` without waiting for home. A later push of a roster that still lists the person as `invited` does not bring the pending invite back.

**Leaving** (C2's `POST /v1/conversations/{id}/leave` without `agent`) now works for a person participant joined here on any host: off home it sends `POST /peer/v1/conversations/{id}/leave` `{participant: "person:HOST_ID/PERSON_ID"}` as C2 does for agents.

**CLI.** Each prints the route's JSON answer and exits 0, or exits 1 with `error: CODE: TEXT` (C1).

| CLI | Route |
| --- | --- |
| `conversations --invites [--json]` | `GET /v1/conversations/invites`. Readable: one line per invite with the ID's first 13 characters, the title in quotes if any, `from ADDED_BY_LABEL`, and `expires EXPIRES_AT`; `No pending conversation invites.` when there are none. `--json`: the route's answer. `--invites` with `--all` is a usage error (exit 2). |
| `conversation join ID` | `POST /v1/conversations/{id}/join` |
| `conversation decline ID` | `POST /v1/conversations/{id}/decline` |
| `conversation start TARGET...`, `conversation add ID TARGET` | as in C2, with person targets |
| `conversation remove ID PARTICIPANT` | as in C2, also for persons not yet joined |

For `join` and `decline`, `ID` is the full ID or `conv_` and at least 6 hex digits matching exactly one current pending invite on this host (C1's prefix rule, over pending invites): none exits 1 with `not_found` and step 1's text, several with `ambiguous`.

**Status.** `GET /v1/status` (and `GET /v2/status`, the same object) gains `conversations: {open, invites}`: `open` is the number of open conversations in which this host's person participant is joined here, `invites` the number of current pending invites here (both 0 without a bound person). While `invites` is above 0, `attention` has one item `{kind: "conversation_invites", subject: "N", detail: "pending conversation invites: N", command: "peerspan conversations --invites"}`, N being `invites` in decimal; its kind sorts after every existing kind. `peerspan status` therefore exits 1 while an invite is pending, as for any attention item. Unread counts come with the read cursor in C6.

### Peer routes

C1's and C2's rules hold: per-request host authentication, the 1 MiB body limit, strict JSON (400 `invalid`), 403 `forbidden` for a sender that is not a current member of a shared coordinator-free network, and none is served on the first-contact listener, the completion listener or a helper.

#### `POST /peer/v1/conversations/invites` with a person target

Body: C1's, with `target` `{kind: "person", person_id}` and no citation (any citation is 400). In order:
1. **Shape.** C1's and C2's roster rules, with the person entry for `person_id` present, `id` null, `state` `invited`, and the roster's other entries as above. The roster may list this host's person participant as `joined` only when it is joined here. Otherwise 400 `invalid`.
2. **Sender and adder.** C1's: the roster's `home_host_id` is the sender and `adder` is `joined` on the sender host, else 403 `forbidden`.
3. **Bound.** This host is bound to `person_id`; otherwise 403 `forbidden`.
4. **Block list.** The sender host, or the adder's person (an agent adder's host's person, or the person adder), blocked here: 403 `forbidden`.
5. **Repeat.** A pending invite for `(home, conversation_id, person_id)` with the same `added_at` answers 200 `{state: "invited"}` while current, and 403 `{code: "not_participant"}` once it was joined, declined, expired or dropped here. A later `added_at` is a new invite. An invite superseded by a roster this host already holds for that conversation (pending or held, at or above the invite's version, not listing the person as `invited` with this `added_at`) is 403 `not_participant`.
6. **Limit.** 20 current pending invites from this sender host held here already (repeats of one of them not counted): 429 `{code: "limit", error: "This host holds 20 pending conversation invites from that host."}`.
7. **Store** the pending invite. Answer 200 `{state: "invited"}`. The host creates no notification; the person sees it with `conversations --invites` and in status.

#### `POST /peer/v1/conversations/{id}/join`

From a person's host to home. Body `{person_id}`. In order:
1. Shape; 400 `invalid`.
2. Home holds the conversation (it is its `home_host_id`); otherwise 404 `not_found`.
3. The sender is bound to `person_id` by a current binding grant in a network both hosts share, and neither the sender host nor the person is blocked on home; otherwise 403 `forbidden`.
4. A closed conversation is 409 `closed`.
5. The person is already joined from the sender host: 200 `{roster}` with home's current roster (an idempotent repeat). Joined from another host: 409 `{code: "conflict", error: "That person already takes part from another host."}`.
6. No `inviting` or `invited` entry for the person: 404 `not_found`.
7. Home commits the entry as joined, `id` `person:SENDER/PERSON_ID`, `host_id` the sender, in a new version (C2's version rule), stops the person's outstanding invites, pushes the roster, and answers 200 `{roster}`.

#### `POST /peer/v1/conversations/{id}/leave`, for people

`participant` may also be:
- `person:SENDER/PERSON_ID`, a person participant on the sender host: leave, as C2 for agents.
- `person:PERSON_ID` with `added_at`, a decline: the sender must be bound to that person by a current binding grant in a network both hosts share, otherwise 403 `forbidden`. Home drops the person's `inviting` or `invited` entry whose `added_at` equals the body's in a new version and pushes it; anything else changes nothing (a joined person is not removed by a decline, and a repeated decline never drops a newer invite). Answer 200 `{roster}`. `added_at` comes with this form only: missing here, or present with any other `participant`, is 400 `invalid`.

#### Roster push and fetch

- `POST /peer/v1/conversations/{id}/roster`: a host whose only state for the conversation is a pending invite holds that invite's roster, so step 2 (404) does not apply; steps 3 and 4 use the pending invite's home and version; step 6 stores the roster in the pending invite, dropping it as in [Pending invites](#pending-invites). Step 5 accepts this host's person participant listed as `joined` when it is joined here or this host has an outstanding join, which the roster then admits.
- `GET /peer/v1/conversations/{id}/roster`: home also answers a host in the push set for a pending invite.

#### Messages to people

C1's acceptance applies to a person target with "joined" meaning joined here under the admission rule above. Step 5 for a person target: the author's host and the author's person (for an agent author, its host's person) are not blocked here; otherwise 403 `forbidden`. There is no policy check and no citation. Messages sent before the person joined are never sent to it (decision 8): fan-out targets only participants `joined` in the author's host's roster when the message is stored.

### Node adapter

- **The `conversation` and `conversation_roster` events.** In the `Participants:` line, a person not yet joined reads `LABEL (person, invited)` or `LABEL (person, inviting)`. Nothing else changes.
- **`conversation_send`** is unchanged: same input schema, call, and errors.
- **`conversation_start`** and **`conversation_manage`** take person targets in `participants` and `participant` (same string limits). The `conversation_start` description says that participants are agent addresses as `list_agents` shows them, or people as `person:LABEL`; that each participant's owner still decides who may message it; that people receive messages only after they join on one of their hosts; and that the result reports who can reach whom.

### Persistence

No new schema version: pending invites live in `conversation_invites` (`expires_at` as above, the roster, adder, note, home, outstanding join and decline in `record`), declines to send in `conversation_roster_outbound`, and person entries in the conversation's `record`.

### Verification

The suite gains C3 cases, written from this section by the same spec-only author, still under 2 minutes in total.

**Setup.** C1's alice and bob, and a fourth host `bob2` linked to bob's person with `link_machine(bob, bob2, NETWORK, BOB_PERSON_KEY, key=...)`, so bob's person is bound to bob and bob2. Inviting a person and messaging a joined person need no policy rule; `bert` cases keep C1's `allow alice --no-tasks --person-key KEY` and its sync wait. Fixture agents claim notifications as in C1 and C2. Raw peer requests use `peerspan-peer-probe` with the sending host's state directory. The expiry case uses the debug test clock and runs last (moving it 7 days outdates every grant).

**Cases** (the proposal's C3 column, made concrete):
- **Invite to every bound host.** `conversation start person:bob --title T` on alice (also with the bare label `bob`): the outcome for bob is `invited`, `participant` `person:BOB_PERSON_ID`, `hosts` listing bob and bob2 each `invited`. Within 20 seconds `conversations --invites --json` on bob and on bob2 lists it with `added_by` alice's person participant and `added_by_label` `alice`. alice's view lists the person with `id` null and `state` `invited`.
- **Attention.** On bob, `GET /v1/status` has `conversations.invites` 1 and the `conversation_invites` attention item with subject `1` and command `peerspan conversations --invites`; `peerspan status` exits 1. After the join, `invites` is 0 and the item is gone.
- **Join on one host.** `conversation join ID` (by prefix) on bob: the answer's view lists `person:BOB_HOST/BOB_PERSON_ID` `joined`. alice's view reaches the new version with that participant. Within 20 seconds bob2's `conversations --invites --json` no longer lists it, and `conversation join ID` on bob2 exits 1 with `not_found`. A second `join` on bob exits 1 with `not_found` (no pending invite remains).
- **Messages to and from the person.** alice's `conversation say` gets a target for bob's person that becomes `delivered`; bob's `conversation show --json` lists it. bob's `conversation say` reaches alice (`delivered`, and alice's `show` lists it with `author_label` `bob`). A message alice sent before the join has no target for bob and is not in bob's `show`.
- **Block.** After bob runs `block alice`, alice's next message's target for bob's person becomes `refused` with `not_authorized`; after `unblock alice` the next one is `delivered`.
- **Decline.** A new conversation inviting `person:bob`; `conversation decline ID` on bob2: within 20 seconds alice's view no longer lists bob's person (no `departed` entry), and bob's pending copy is gone too.
- **Remove an invited person.** `conversation remove ID bob` on alice drops the entry; bob's and bob2's pending copies disappear within 20 seconds.
- **Peer edges** (probe):
  - a person invite with a citation: 400 `invalid`;
  - a person invite to bob for a person bob is not bound to (alice's person): 403 `forbidden`;
  - `POST .../join` from bob2's state for a conversation in which bob's person joined from bob: 409 `conflict`;
  - `POST .../join` from bob2's state for a conversation that does not list bob's person: 404 `not_found`;
  - a roster push from alice listing `person:BOB2_HOST/BOB_PERSON_ID` as `joined`, sent to bob2 while bob2 holds a pending invite for that conversation and has sent no join: 400 `invalid`, and the pending invite stays.
- **Limit.** alice starts conversations inviting `person:bob` until bob and bob2 each hold 20 current pending invites from alice (`conversations --invites --json`); the next start's outcome for bob is `refused` with code `limit`, both entries of `hosts` `refused` with `limit`, and alice's view of that conversation does not list bob's person. A probe person invite from alice to bob for another new conversation is 429 `limit`.
- **Expiry** (last). With an invite pending on bob, the test clock moves 7 days and 1 second: bob's `conversations --invites --json` is empty, `conversation join ID` exits 1 with `not_found`, and within 15 seconds alice's view no longer lists the person.

**Node adapter** (`node --test` in `integrations/shared`, as in C1 and C2): the `Participants:` line with a person `invited` and `inviting`, in a `conversation` and a `conversation_roster` event; `conversation_start` and `conversation_manage` accept `person:LABEL` and bare labels.

## C4: catch-up

C4 lets a participant whose host was offline, or missed a message, catch up from the author's host: gap detection through `prev_seq`, the peer routes `GET .../heads`, `GET .../messages` and `POST .../acks`, the conversation sync (roster first) at startup, every 10 minutes and after a roster change, the 24-hour push window and the `stopped` target state, and sync after close until every host has answered or 30 days pass (`unsynced`). Everything in C1 to C3 stays as written unless this section changes it. Not in C4: seen, redelivery, catch-up events, `pending_work`, `conversation_history` and `conversation_undelivered` (C5); rate limits, `addressed_to` from local surfaces, the read cursor, the event log, `forget`, and `home_unavailable` (C6). CONV-24 still holds: `conversation sync` below is not listed in the root help, the README or the quick start.

**Words.** For a message M authored on host H and a participant T on another host, H's *outbound record* for (M, T) is the target record C1 creates at fan-out. "Messages sent to T" are exactly the messages with an outbound record for T, whatever its state; a message stored before T was `joined` in H's roster has none (decision 8). A *final* answer or outcome is one that C1 and C2 record as `delivered`, `refused` or `unsupported`.

### The 24-hour push window and `stopped`

- **Messages.** An outbound record still `sending` 24 hours after its message's `sent_at` (on the author host's clock) becomes `stopped`, within 15 seconds after the 24 hours pass, whether or not an attempt is due. No attempt starts after that moment, and an attempt in flight when it passes may still make the record final with its answer. A conversation message has no `deadline`, and nothing else shortens the 24 hours: not the cited policy's `not_after`, nor a grant's `expires_at` (CONV-22).
- **Target view.** `state` gains `stopped`, with `code` null and `error` `retries stopped 24 hours after sending; the recipient's host fetches it when it syncs`. `stopped` is not final: an `acks` answer (below) makes it `delivered` or `refused`. Readable `conversation show` lists a `stopped` target under the viewer's own message as `not yet received by LABEL (stopped)`.
- **Roster pushes.** C2's roster pushes to one host stop 24 hours after home committed the version being pushed; the host gets that roster or a newer one at its next sync (roster first). A newer version starts a new push with its own 24 hours. Invites (C2's 10 minutes), joins (no automatic retry), and leaves and declines (retried until home answers) are unchanged.

### Gap detection

Each host keeps, per conversation, remote author A and local participant T joined here, a *chain head*: the highest `seq` of A's messages it has *resolved* for T with no gap before it. A message is resolved for T when this host accepted it for T (pushed or fetched), when it refused it for T at a fetch with a final code (below), or when the author's host reports it as already `refused` for T. A final refusal stays final (C1): a message refused at a push is never delivered later, even when the sender is allowed again.

- The chain head starts at 0 when T is first admitted here. A participant admitted again keeps its chain, and `prev_seq` continues across its departure.
- A message for T whose `prev_seq` is absent (the first message to T since T joined), or equals the chain head, moves the chain head to its `seq`, and then on through any resolved messages whose `prev_seq` continues the chain.
- A message for T accepted (step 6) with a `prev_seq` above the chain head reveals a **gap**. The host stores the message as usual, answers the push with its receipt, and at once (without waiting for its answer) fetches A's messages to T after the chain head from A's host (`GET .../messages`, below), page by page, applying [fetched-message acceptance](#fetched-messages) to each, then sends `acks` to A's host. At most one gap fetch per (conversation, author host, T) runs at a time; a gap the fetch could not close (no answer, or a non-final outcome) waits for the next sync.
- A `prev_seq` at or below the chain head that is not resolved, or that names a `seq` this host never saw, changes nothing beyond the push's own acceptance.

### Peer routes

C1's to C3's rules hold for every route below: per-request host authentication, the 1 MiB body limit, strict JSON and query parameters (unknown fields or parameters, nulls, missing required ones, and malformed values are 400 `invalid`), 403 `forbidden` for a sender that is not a current member of a coordinator-free network the receiver belongs to, and none is served on the first-contact listener, the completion listener or a helper. A conversation the receiver holds no roster for (a pending invite alone does not count, C3) is 404 `not_found`.

A host H **serves** a participant T to the requesting host R when T's host is R (otherwise 403 `forbidden`) and T is `joined` in the roster H holds, open or closed (otherwise 404 `not_found`). A departed participant is never served: what it missed before its departure is not caught up. `GET .../messages` has one more limit after a close: for a conversation H holds as closed, H returns messages for T only while at least one of H's outbound records for T is neither `delivered` nor `refused` and fewer than 30 days have passed since H stored the closed roster; otherwise 404 `not_found`. `heads` stays served, so the requester can confirm it is complete, and in that case answers `authors` `[]`, since nothing is left to fetch.

#### `GET /peer/v1/conversations/{id}/heads?target=T`

From T's host to a participant host H. H serves T as above. Answer 200 `{roster_version, authors: [{author, last_seq}]}`: `roster_version` is the version H holds; `authors` has one entry per participant on H that authored at least one message sent to T, with the highest `seq` among those messages, ordered by `author` as bytes. A host none of whose participants sent anything to T answers `authors` `[]`.

#### `GET /peer/v1/conversations/{id}/messages?author=A&target=T&after=N&limit=M`

From T's host to A's host. `author` is a participant ID on the serving host (another host's participant is 400 `invalid`); `after` an integer from 0 to 2^53 − 1; `limit` 1 to 100, default 50. H serves T as above. Answer 200 `{messages: [ENTRY], more}`: one entry per message of A's sent to T with `seq` above N, in `seq` order, at most M of them and at most 900,000 bytes of encoded entries (always at least one when any exists). An entry is `{message, prev_seq}`, with `message` as C1 sends it, or, for an outbound record that is `refused`, `{message_id, seq, prev_seq, refused: CODE}` without the content. `prev_seq` is the value H's outbound record holds (omitted where C1 omits it). `more` is true when further messages after the last one returned exist. Fetching acknowledges nothing and changes no outbound record.

#### `POST /peer/v1/conversations/{id}/acks`

From T's host to an author host H. Body `{target, acks: [{author, through_seq, refused: [{seq, code}]}]}`. `target` is T; `acks` has 1 to 16 entries with distinct `author`s, each a participant ID on H; `through_seq` from 1 to 2^53 − 1; `refused` (required, possibly empty, at most 100 entries) lists seqs at or below `through_seq` with `code` one of `not_authorized`, `not_participant`, `closed`, `invalid`, `conflict`. H checks that the sender is T's host (otherwise 403 `forbidden`) and holds a roster for the conversation (otherwise 404 `not_found`); T need not still be joined. For each entry, H sets every outbound record for T of A's messages with `seq` at most `through_seq`: those listed in `refused` that are not `delivered` become `refused` with that `code`; every other one that is `sending` or `stopped` becomes `delivered`. `refused` (not listed), `delivered` and `unsupported` records are unchanged. Answer 200 `{acked}`, the number of records changed. Idempotent: a repeat changes nothing and answers `{acked: 0}`.

A recipient acks `through_seq` = its chain head for (A, T), and lists in `refused` the seqs it refused at a fetch since its last answered ack for that chain. With more than 100 refusals to report for one chain, it sends several acks, each with `through_seq` below the first refusal it cannot list yet. It sends `acks` after each gap fetch and in each sync for every (author host, local T) whose chain head moved since the last answered ack; a failed ack is sent again at the next sync.

#### Fetched messages

The recipient applies to each fetched entry exactly the acceptance steps of a pushed message, with the host it fetched from as the authenticated sender and no citation:
1. **Shape**, as C1. An entry not for the requested author, a `seq` not above the requested `after`, or `seq`s out of order end the processing of that page, and every entry of the page not yet resolved is left for the next sync. An entry this host already resolved for T (accepted, or refused at a fetch) is skipped.
2. **Author's host**: `message.author`'s host is the host fetched from; otherwise the page is processed no further.
3. **Repeat**: a `(author host, message_id, T)` this host already resolved is skipped and never overwritten. Another `message_id` with a `seq` this host holds from that author is refused `conflict`.
4. **Roster**: a `roster_version` above the version held, after the sync's roster fetch, stops processing of this author's entries until the next sync (not final). T not joined here, or the author not `joined` in the held roster, is refused `not_participant`.
5. **Closed** (C2 step 5): refused `closed`, except a message whose `roster_version` is below the version of the closed roster held.
6. **Authorization**, as for a push (C1, C3), evaluated against this host's records at the time of the fetch: self access, the recipient owner's current policy, or a current grant allows `message.append` from the author for an agent T; for a person T, the author's host and person are not blocked here. A failure is refused `not_authorized`. When this host holds no current policy statement of T's owner in any network both hosts share, and neither self access nor a grant allows it, the entry is not final: processing of this author's entries stops until the next sync (as C1's 503 `unavailable`).
7. **Persist**, as C1 step 6: the message (stored once per host), the inbound target record, the clock raise, and, for an agent T, one `message` notification for that agent, exactly as for a pushed message (the claim, its `window` rule, and the `conversation` event are unchanged).

A `refused` entry from the author's host resolves its `seq` for T, and nothing is stored but that. An entry refused here with a final code is resolved for T: its content is not stored (only its author, `seq`, `prev_seq` and code), never shown to T, never fetched again, and reported in the next `acks`. A later push of it gets the same refusal (403 `forbidden` for `not_authorized`). Nothing a sync fetches is accepted on any weaker terms than a push: no step is skipped, and a message is fetched only from its author's host.

A recipient answers a push of a message it has already accepted by fetch with the saved receipt (C1 step 3), so the author's record becomes `delivered` either way.

### Conversation sync

A host H **syncs** a conversation it holds (not one known only from a pending invite):
1. **Roster first.** Unless H is home, `GET /peer/v1/conversations/{id}/roster` from home, stored as C2 stores a push. No answer, or 404, leaves the held roster.
2. **Heads.** For every other host P holding a participant `joined` in the held roster, and every local participant T joined here, `GET .../heads?target=T` on P. For each `{author, last_seq}` above H's chain head for (author, T), H fetches the missing messages (`GET .../messages`, after the chain head, page by page until `more` is false) and accepts them as above.
3. **Acks** to P as above.

**When.** At daemon startup (within 15 seconds after it), every 10 minutes per conversation (10 minutes of this host's clock after that conversation's last sync started; due syncs start within 15 seconds), after this host stores a newer roster for it, and on the owner's request (`POST /v1/conversations/{id}/sync`). It covers each open conversation with a local participant joined here, and each closed one still syncing (below). At most 4 conversation syncs run at once per daemon, separate from the 4 push attempts; each peer request in a sync has a 5-second limit. Conversation sync exchanges no grants, policies or contacts; it is separate from the network's record sync (spec section 10).

**After close.** For a conversation H holds as closed, at the version V that closed it, H keeps syncing with each host P that held a participant `joined` in that closed roster (other than H) until P is **complete**: in one sync, P answered `heads` for every local T with a `roster_version` at or above V, every message P reported that H lacked was fetched and resolved, and every ack H sent P was answered 200. A complete host is not asked again. A host not complete 30 days after H stored the closed roster (on H's clock) becomes **unsynced** and is not asked again. Once every such host is complete or unsynced, H stops syncing the conversation.

**Conversation view** gains `unsynced: [HOST_ID]`, the unsynced hosts in host ID order (`[]` for open conversations and while none is unsynced).

### Local API and CLI

| Route | Body | Answer |
| --- | --- | --- |
| `POST /v1/conversations/{id}/sync` | `{}` | Runs one sync of the conversation now (at most one per conversation at a time; a request while one runs waits for it and then runs its own) and answers when it ends: 200 `{conversation_id, roster_version, hosts: [{host_id, state, fetched, error}]}`. |

- `roster_version` is the version held after the roster step. `hosts` lists, in host ID order, every other host holding a participant `joined` in the held roster, with `state`: `synced` (it answered `heads` for every local T, every message it reported missing was resolved, and its acks were answered), `failed` (any of those did not happen; `error` a short reason), `complete` (closed conversation; complete earlier, not asked), or `unsynced` (closed conversation; past 30 days, not asked). `fetched` counts the messages accepted from that host in this sync. `error` is null unless `failed`.
- A full conversation ID; an unknown conversation (or one known only from a pending invite) is 404 `not_found`. Unknown fields and nulls are 400.
- **CLI:** `conversation sync ID`, with C1's prefix rule for `ID`, prints the route's JSON answer and exits 0, or exits 1 with `error: CODE: TEXT`. Not listed in the root help (CONV-24).

The owner and adapter routes, the claim, the `conversation` and `conversation_roster` events, and the `conversation_send`, `conversation_start`, `conversation_manage` and `list_conversations` tools are unchanged; their target views may now show `stopped`. A fetched message reaches a local agent through the same `message` notification and claim as a pushed one.

### Persistence

No new schema version. Chain heads, unacked fetch refusals and per-host sync state (last sync, complete, unsynced) live in the conversation's `record`; a fetch refusal is also an inbound row in `conversation_targets` with `state` `refused`; `stopped` is an outbound `state` there.

### Verification

Spec-only cases, written from this section by the separate author, in `conformance/slim/conversations_sync.py`, with its own `suite` matrix entry, as C3 did (the 24-hour and 30-day clock moves need hosts of their own).

**Setup.** `suite.use_clock()` before any host starts. Hosts alice and bob in one coordinator-free network (`create_network`, `join_new_person`), and carol joined to it the same way. Participants in the clock cases are **people**, not agents: a person target needs no policy (C3), whereas bob's `allow` policy statement lasts at most 24 hours and the harness gives the daemon no `ssh-agent` to renew it, so after a 24-hour move bob would hold no current policy and every fetched message for an agent would wait (step 6). Each conversation is started on alice with `conversation start person:bob` (or `person:carol`) and joined with `conversation join ID` on the invited host, as in C3. Cases that need an agent recipient before any clock move use C1's setup: fixture agent `bert` on bob (`b.agent("bert")`), bob's `allow alice --no-tasks --person-key KEY` (only `message.append`), and the policy-version wait of C1; `bert` claims with `bert.post("/adapter/v1/conversation-notifications/next")` until non-null, then `.../{id}/forwarded`. Raw peer requests use `peerspan-peer-probe` with the requesting host's state directory (`peer(sender, receiver, ...)`). Syncs are triggered with `conversation sync ID` (or `POST /v1/conversations/{id}/sync`) instead of waiting 10 minutes; a host restart also syncs within 15 seconds. After a clock move, the suite restarts every running host before expecting peer traffic (so each holds fresh signed contacts), and polls with a 20-second bound. Order: gap and route cases first, then the 24-hour world, then the 30-day case last.

**Cases** (the proposal's C4 column, made concrete):
- **Refused stays refused.** conv G between alice's and bob's persons. `block alice` on bob; alice's `conversation say G m1`: its target for bob becomes `refused` (`not_authorized`). `unblock alice`; alice says m2: it becomes `delivered`; after `conversation sync G` on bob, bob's `conversation show G --json` lists m2 and not m1, and m1's target is still `refused`.
- **Route edges** (probe):
  - `GET .../heads?target=BOB_PERSON_PARTICIPANT` from bob on alice: 200, `roster_version` alice's, `authors` `[{author: ALICE_PERSON_PARTICIPANT, last_seq: 2}]` for conv G; from carol's state (not T's host): 403 `forbidden`; from carol's state with `target` carol's own person participant, which is not in conv G: 404 `not_found`.
  - `GET .../messages?author=ALICE_PERSON_PARTICIPANT&target=BOB_PERSON_PARTICIPANT&after=0` from bob on alice: m1 as `{message_id, seq: 1, refused: "not_authorized"}` without content and m2 as `{message, prev_seq: 1}`, `more` false; `limit=1` returns m1's entry with `more` true; `limit=101` and an unknown parameter are 400; from carol's state: 403.
  - `POST .../acks` from carol's state for bob's person: 403 `forbidden`; from bob's state repeating an earlier ack: 200 `{acked: 0}`.
- **24 hours** (the 24-hour world). bob's person joins four conversations: W and X started on alice, Y and V started on carol (each `conversation start person:bob`, then `conversation join` on bob). bob stops. alice says three messages in W and one in X, then `conversation close X`; carol says one message in Y and one (v1) in V. The test clock moves 24 hours and 1 second: within 20 seconds every one of those targets, on alice and on carol, is `stopped` (`conversation show --json`), and alice's view of X has `unsynced` `[]`. Then, in this order: carol stops; alice restarts; bob starts (its startup sync catches up W and X from alice; its sync of Y fails, carol being down); `block carol` on bob; carol stays down until bob's startup sync has finished (15 seconds for it to start plus 5 seconds for its request), then starts.
  - **Catch-up.** Within 20 seconds (`conversation sync W` on bob makes it immediate), bob's `conversation show W --json` lists the three messages in display order, and alice's three targets for bob become `delivered`.
  - **Close while down.** bob's view of X is `closed` at alice's closing version and lists the message alice sent before the close; alice's target for it becomes `delivered`. `conversation sync X` on alice then reports bob's host `synced` or `complete`, and a second one `complete`; a probe `GET .../messages?author=ALICE_PERSON_PARTICIPANT&target=BOB_PERSON_PARTICIPANT&after=0` for X from bob's state on alice is 404 `not_found`, while `GET .../heads` for X still answers 200.
  - **No back door.** `conversation sync Y` on bob: carol's host is `synced` with `fetched` 0; bob's `show Y` does not list carol's message; carol's target for bob becomes `refused` with `not_authorized` (through `acks`). After `unblock carol`, another `conversation sync Y` on bob fetches nothing and the target stays `refused`.
  - **Gap fetch.** bob has not synced V since it started (its startup sync failed, carol being down), and v1's target is `stopped`, so carol no longer pushes it. carol says v2 in V: its push reveals the gap at `prev_seq` 1, and within 20 seconds, with no `conversation sync`, bob's `conversation show V --json` lists v1 and v2 in display order, and carol's targets for both are `delivered` (v1 through `acks`).
- **30 days** (last). Conversation Z between alice's and carol's persons; carol stops; alice closes Z; the test clock moves 30 days and 1 second; `conversation sync Z` on alice reports carol's host `unsynced`, and alice's `GET /v1/conversations/{Z}?participant=ALICE_PERSON_PARTICIPANT` has `unsynced` `[CAROL_HOST]`. The `participant` parameter is needed because alice's binding grant has lapsed by then, so she has no default person participant.

**Node adapter.** No change in C4; no new adapter tests.

## C5: session context

C5 gives an agent's session what it needs to follow a conversation across sessions: the handoff authorization recheck, seen tracking, returning and redelivering notifications, coalesced catch-up, `pending_work.conversations`, `conversation_history`, and the `conversation_undelivered` event. Everything in C1 to C4 stays as written unless this section changes it. Not in C5: rate limits, `addressed_to` from local surfaces, the read cursor, the event log, `forget`, and `home_unavailable` (C6). CONV-24 still holds: nothing below is listed in the root help, the README or the quick start.

**Words.** P is a local agent participant. A *session* is one adapter authorization of P; it *ends* when replaced by a new attachment of the agent, when it expires, or when it is revoked or detached (live delivery slice 2). `POST /v1/adapters/setup` still answers 409 while the old adapter's lease is live, so a replacement can only happen once that lease has lapsed (15 seconds without a renewal) or after a detach. A notification is *held* by the session that claimed it. *Message notification* means `kind` `message`.

### The handoff recheck

A message notification is the only way a remote author's message becomes visible to P. C1's acceptance is not enough: **the recheck** evaluates, against this host's records at that moment, exactly the authorization of C4's [fetched-message](#fetched-messages) step 6 for an agent T, for the message's author and P. It has three outcomes:

| Outcome | When | Effect |
| --- | --- | --- |
| **pass** | Self access, the recipient owner's current policy, or a current grant allows `message.append` from the author, and the block list does not apply. A message from an author on this host always passes (self access, decision 18). | The message may be shown. |
| **fail** | Step 6's final refusal (`not_authorized`). | Not shown. At a claim, the notification becomes `blocked`. |
| **wait** | Step 6's non-final case: this host holds no current policy statement of P's owner in any network both hosts share, and neither self access nor a grant allows it. | Not shown, not counted and not claimed now. It is evaluated again at each later claim and read. |

**Blocked is final.** Only a claim records it. A notification whose recheck fails at a claim becomes `blocked`, in the claim's transaction, and is skipped: the claim goes on to the next notification. A blocked notification is never offered, listed or counted, and its message is never shown to P on any surface, even after the owner allows the author again (a final refusal stays final, DEC.impl76). Reads record nothing: a message hidden by a failing recheck at a read, whose author is allowed again before any claim, is claimed normally.

The author's target stays `delivered`; blocking creates no `conversation_undelivered` event and tells the author's host nothing, as for a blocked one-to-one message. There is no peer request, new code or changed acceptance step in C5.

**What an agent may see.** This replaces C1's [Who may see what](#who-may-see-what) for agent participants. A message is visible to P only when:
1. P authored it; or
2. P has a message notification for it that is not blocked, and at least one of these holds: it is seen; a session of P whose authorization has not ended holds it; or the recheck passes now.

A message with an accepted inbound target but no such notification (for example, one withdrawn when P left, C2) is not visible, including after P is added again. Being in the roster shows nothing else. Messages already handed to a session that has not ended, and seen ones, are not withdrawn when the author loses access.

This rule applies to every agent surface: `conversation_history`, the event `window` on first events and catch-up, `pending_work` and `GET /v1/sessions/{id}/pending`, `unseen`, `last_message_at`, and the owner's reads with an `agent:` `participant` (`GET /v1/conversations/{id}`, `.../messages`, `conversation show --as AGENT`). Person participants are unchanged: their authorization is checked at acceptance only.

### Notification life

| State | Meaning | Offered by the claim route | Counted in `unseen` |
| --- | --- | --- | --- |
| unclaimed | No session has held it. | Yes, after the recheck for messages. | When the recheck passes. |
| held | Claimed by a session, not seen. | No. | Yes. |
| returned | Its holder ended while it was unseen. | Yes, after the recheck for messages. | When the recheck passes. |
| exhausted | Its holder ended, and it was already redelivered 3 times. | No. Stays unseen. | No. |
| seen | Reported seen by its holder. | No. | No. |
| blocked | The recheck failed at a claim. | No. | No. |

**Unseen.** `unseen`, in the agent summary and the claim's `conversation`, is the number of P's message notifications in the conversation that are held by a session that has not ended, or are unclaimed, returned, or held by an ended session and under the limit with a passing recheck. This replaces C1's "not yet forwarded": `forwarded` no longer changes `unseen`. `GET /adapter/v1/conversations` keeps a closed conversation while its `unseen` is above 0.

**Seen.** A notification is seen when the session holding it:
- gets a 200 from `POST /adapter/v1/conversations/{id}/messages` (a repeat counts), `GET /adapter/v1/conversations/{id}/messages` or `POST /adapter/v1/conversations/{id}/manage`: all notifications of any kind that this session holds in that conversation at that moment become seen. A refused call marks nothing. `POST /adapter/v1/conversations`, `GET /adapter/v1/conversations`, and owner routes (including `--as`) mark nothing;
- names it in `POST /adapter/v1/seen` (below).

**Returning.** When a verified session of P claims work on any work route or calls `GET /adapter/v1/pending`, each unseen notification held by an ended session of P changes, in that transaction:
- a message notification for a conversation in which P is no longer joined here is withdrawn, as C2 withdraws an unclaimed one;
- otherwise, with fewer than 3 redeliveries, it becomes returned;
- otherwise it becomes exhausted.

Roster and `undelivered` notifications return and exhaust the same way, also after P left. A notification that arrives while P has no verified session stays unclaimed, and is not redelivered when claimed.

### Claiming

`POST /adapter/v1/conversation-notifications/next` with `{}`. C1's verified-channel and directory rules hold. In one transaction:
1. Return notifications as above.
2. Take the oldest (by creation) notification of P that is unclaimed or returned. For a message notification, run the recheck: on fail, block it and repeat this step; on wait, leave it and repeat this step with the next.
3. **Unclaimed:** claim it for this session as C1 and C2 do, with `redelivered` false and `catch_up` false.
4. **Returned, not a message notification:** claim it for this session, adding 1 to its redeliveries, with `redelivered` true, `catch_up` false, and C2's empty lists.
5. **Returned message notification (catch-up):** gather every returned message notification of P in the same conversation; block any that fails the recheck and leave any that waits. Claim the rest together for this session, adding 1 to the redeliveries of each. The newest of them in display order is the new message.

No notification is claimable: 200 `null`.

**Claim:** C1's and C2's, gaining `catch_up` and `coalesced`: `{notification, conversation, messages, window, window_total, catch_up, coalesced, redelivered}`.
- `notification` is the claimed one, for catch-up the new message's. It gains `seen_at` (null until seen) and `redeliveries`. `kind` may also be `undelivered`.
- `messages` is exactly the new message (never cut), `[]` for roster and `undelivered` claims.
- `catch_up` is true only for step 5. `coalesced` lists the IDs of the other notifications claimed with it, in display order of their messages, and is otherwise `[]`.
- `window` and `window_total` follow C1's rule (at most the newest 10 messages and 16,384 bytes of cut content, each cut at 2,048 bytes), counted over the messages visible to P that sort before the new one. They are filled on the session's first message claim in the conversation **and on every catch-up**, and `[]` and 0 otherwise. So a catch-up window holds the other coalesced messages, and earlier visible ones as context, newest kept. A coalesced message that does not fit stays held, is counted in `unseen`, and is reachable with `conversation_history`.
- `redelivered` is true for steps 4 and 5.

**`forwarded`** works as in C1; called with a catch-up's notification ID, it also marks those in its `coalesced`. It answers for the notification named. Forwarding does not mean seen, and an item counts as handed to its session from the claim, even if its forwarding is never confirmed.

Messages that became unclaimed while P had no session are separate events. For example, with m1 returned and m2 and m3 unclaimed, a new session's claims are a catch-up with m1 (`unseen` 3), then m2, then m3, each of the last two with `redelivered` false and no window.

### `conversation_undelivered`

When an outbound target of a message authored by a local agent P becomes `refused`, `unsupported` or `stopped`, in the same transaction, this host creates one notification with `kind` `undelivered`, `message_id` that message and the field below. There is at most one per (message, target): `stopped` followed by `refused` makes no second one, and `stopped` followed by `delivered` makes no correction. No notification is created when P is no longer joined here, for a person author, for a target that becomes `delivered`, or for a refused invite. Target states and answer tables are unchanged.

`notification.undelivered` is `{participant, label, state, code, error, preview}`, with the target view's first five fields at that moment, and `preview` the first 200 characters of the message. It is null for other kinds. It counts toward no `unseen` and is not in `pending_work`.

### `pending_work`

`GET /adapter/v1/pending`, and `GET /v1/sessions/{id}/pending` with the same object, gain `conversations`, beside `deliveries`, `replies`, `tasks` and `calls`:

```json
{"conversation_id": "conv_…", "title": "Flaky checkout test", "unseen": 2, "addressed": true,
 "latest": {"message_id": "cmsg_…", "author_label": "alice", "preview": "first 200 characters"}}
```

- There is one entry per conversation in which P is joined here and has at least one message notification this session holds or could claim: held by this session, or unclaimed, returned, or held by an ended session and under the limit, with the recheck passing for all but those held by this session. Those held by another session that has not ended are not listed. Roster and `undelivered` notifications are not listed.
- `unseen` counts exactly those notifications, and `addressed` is true when any of their messages has `addressed` true. `latest` is the newest of their messages in display order. `title` is null when there is none. The list is ordered oldest first, by when the earliest of those messages reached this host.
- A credential without directory access gets `conversations` `[]`.
- Both routes record nothing about a recheck. The adapter route returns notifications first when its session is verified, as today; the owner route does not, and gives the same list.

### Adapter routes

`POST /adapter/v1/conversation-notifications/next`, `.../{id}/forwarded`, `GET /adapter/v1/pending` and `POST /adapter/v1/seen` change as above and below. New:

| Route | Query | Answer |
| --- | --- | --- |
| `GET /adapter/v1/conversations/{id}/messages` | `before=MESSAGE_ID`, `limit=N` (both optional; `limit` 1 to 50, default 20) | 200 `{messages, next_before_message_id, participants}` |

It works before the channel is verified. Checks, in order:
1. No directory access: 403 `no_directory`.
2. Malformed `id`, `before` or `limit`, or an unknown query parameter: 400 `invalid`.
3. A conversation this host does not hold (a pending invite alone does not count): 404 `not_found`.
4. P not joined here: 403 `{code: "not_participant", error: "This participant is not in that conversation."}`. A closed conversation P was joined in at the close stays readable.
5. A `before` that is not visible to P, whether unknown or hidden, is 400 `invalid`, with the same text.

**Page.** Starting with the newest message visible to P that sorts before `before` (or the newest overall), the route takes messages going back in display order until it has `limit`, or until the next would take the total `content` bytes above 262,144. The first message taken is never left out: if it alone is above the budget, its content is cut to the budget at a UTF-8 boundary. `messages` are returned in display order. Each is the adapter message view (C1) with `targets` (the target views when `mine`, otherwise null), `truncated` (a boolean) and, when cut, `content_bytes`. `next_before_message_id` is the oldest returned message's ID when older visible messages exist, otherwise null. `participants` are the agent summary's.

**`POST /adapter/v1/seen`** (`{ids}`, 1 to 100) also takes:
- a `cmsg_` ID: every notification this session holds with that `message_id`, and, for a catch-up's new message, those in its `coalesced`. It is held when this session holds at least one.
- a `conv_` ID: every notification of any kind that this session holds in that conversation. It is held when this session holds at least one.

As today, the answer is 200 `{seen: [ids]}` naming the IDs that changed something, an already seen ID is ignored, and any ID not held is 404 with nothing marked. A notification P's other session holds, or an unclaimed one, is not held. A value with no accepted prefix, including a `cnot_` notification ID, is 400 `invalid` with exactly `invalid request: ids must be 1 to 100 delivery, request, task, call, conversation, or conversation message IDs`; a notification can be named only through its `cmsg_` or `conv_` ID.

### Local API and CLI

No new conversation command or `/v1` route. Reads with an `agent:` `participant` follow [What an agent may see](#the-handoff-recheck), with the same errors as C1 and without changing any state; the person participant's are unchanged.

`peerspan session pending [--json | --hook]` (exit 0, and nothing printed with no attachment here, as today):
- `--json`: the object above, with `conversations`.
- Readable: one more line per conversation, starting `conversation CONVERSATION_ID`, with the unseen count, the latest author label and preview. Other wording is not part of the contract.
- `--hook`: the lead sentence becomes `Peerspan work this session still owes, listed after /clear, compaction, or resume. Finish each task with the task_* tools, answer each delivery with reply, check each call with call_status, and follow each conversation with conversation_history; call pending_work for the current list. ` It prints nothing only when `conversations` is empty too.

Peer routes, target states and answers, acceptance steps, and the owner's write routes are unchanged.

### Node adapter

The claim loop emits one event per claim, then calls `forwarded`, as before.

**The `conversation` event** keeps C1's `meta` keys, and its content. `meta.catch_up` and `meta.redelivered` now come from the claim, and `meta.unseen` from `conversation.unseen`. A catch-up's content has the same form, with `Earlier messages (last K of N; conversation_history has the rest):` when `window` is non-empty. A catch-up with an empty window has no such line. The window and the new message are as C1 renders them, and the adapter writes every label, never message content.

**The `conversation_roster` event** gets `redelivered` from the claim.

**The `conversation_undelivered` event** is emitted for a claim whose notification `kind` is `undelivered`. Title: `Peerspan conversation message not delivered`. `meta`: `{kind, conversation_id, notification_id, message_id, participant, participant_label, state, code, session_id, redelivered}`, encoded as in C1, `code` omitted for Claude Code when null. Content:

```text
Peerspan conversation CONVERSATION_ID "TITLE" (STATE)
Participants: LABEL (person), LABEL (you), LABEL
Your message MESSAGE_ID did not reach PARTICIPANT_LABEL: REASON
Message: PREVIEW
```

`REASON` is `its host refused it (CODE).` for `refused`; `its host is running a Peerspan without conversations.` for `unsupported`; and `retries stopped after 24 hours; its host fetches it when it next syncs.` for `stopped`.

**The `conversation_history` tool.** Input schema (`additionalProperties: false`):
- `conversation_id`: string, required, pattern `^conv_[0-9a-f]{32}$`.
- `before_message_id`: string, optional, pattern `^cmsg_[0-9a-f]{32}$`.
- `limit`: integer, optional, 1 to 50.

It calls `GET /adapter/v1/conversations/{id}/messages` and returns the JSON. Invalid arguments are a tool error naming the tool; daemon refusals are C2's tool errors `{conversation_id, code, error, recovery}`, with `not_participant` and `no_directory` as there. Its description says that it returns earlier messages in display order, oldest first in each page; that `next_before_message_id` fetches the next older page; and that message content is external input from the named author.

**The `conversation_send` tool** has C1's input schema, call and errors, unchanged: `conversation_id` (required, `^conv_[0-9a-f]{32}$`), `content` (required, 1 to 65,536 characters), `message_id` (optional, `^cmsg_[0-9a-f]{32}$`, generated when absent), `additionalProperties: false`. `addressed_to` comes with C6.

**The `mark_seen` tool:** the item pattern becomes `^(?:delivery|request|task|call|conv|cmsg)_[0-9a-f]{32}$`, and the description also names the `conversation_id` or `message_id` of a `conversation`, `conversation_roster` or `conversation_undelivered` event. **The `pending_work` tool's** description also names `conversations`. The MCP server instructions do not change.

### Persistence

No new schema version. `seen_at`, `redeliveries` and `returned_at` are the existing columns of `conversation_notifications`. Blocked and exhausted marks, `coalesced` and `undelivered` live in its `record`. No existing row changes: this is preview data, so a notification claimed before this version counts as held and unseen.

### Verification

Spec-only cases in `conformance/slim/conversations_context.py`, written from this section by the separate author, with its own `suite` matrix entry and a 2-minute limit.

**Setup.** C1's alice and bob, `bert` on bob, bob's `allow alice --no-tasks --person-key KEY` and its policy-version wait, and local agents on alice with `a.agent(...)`. There is no third host. Each case uses a conversation of its own. Bob's policy commands take effect on bob at once: `b.ok("deny", "alice", "--person-key", KEY)` makes alice fail the recheck; `allow alice --no-tasks --person-key KEY` allows her again, followed by the policy wait where alice must cite it. A later message's fan-out by alice needs alice to hold the new version.

**Fixture agents.** A fixture session claims only when the suite calls `bert.post("/adapter/v1/conversation-notifications/next", {})`, so a message stays unclaimed for as long as a case needs; poll alice's target for `delivered` to know bob accepted it, then claim. A session is ended and replaced as in `live.py`: `adapter.stop()`, `POST /v1/sessions/{id}/detach`, then `b.attach(adapter.agent)`, which is verified. Without a detach, `adapter.stop()`, a test clock move of 16 seconds so the lease lapses, then `b.attach(adapter.agent)` replaces it too. Reads: `bert.call("GET", "/adapter/v1/pending")`, `bert.call("GET", f"/adapter/v1/conversations/{ID}/messages?limit=N")`, and `bert.post("/adapter/v1/seen", {"ids": [...]})`. Existing helpers that take the next claim may now also meet `kind` `undelivered`, for example after C2's unreachable pair.

**Cases** (the proposal's C5 column, made concrete):
- **Catch-up.** alice sends m1, m2, m3; `bert` claims all three and sees none. After replacing the session, the first claim has `catch_up` true, `redelivered` true, `messages` exactly m3, `window` m1 and m2 in display order, `window_total` 2, `coalesced` two IDs, and `conversation.unseen` 3. The next claim is `null`.
- **Pending until seen.** Before that claim, `GET /adapter/v1/pending` lists the conversation with `unseen` 3, `latest` m3's ID, `author_label` `alice` and preview; `GET /v1/sessions/ID/pending` is the same object. After that claim, and then a send by `bert` through the adapter route: `unseen` 0 and `conversations` `[]`, on the owner route too, and replacing the session again gives `null` from the claim.
- **Other seen paths.** `GET .../messages` marks held notifications seen, as does `manage`, and a refused send does not. `POST /adapter/v1/seen` with the catch-up's new message ID marks every coalesced notification; with the `conv_` ID marks the rest; with an ID this session does not hold is 404 and marks none (including a batch with one valid ID); with a malformed ID is 400. An ID held only by an ended session is 404.
- **Redelivery limit.** One message claimed and unseen by four sessions in turn: claims 2, 3 and 4 have `redelivered` true and `notification.redeliveries` 1, 2, 3. A fifth session's claim is `null`, `pending_work` does not list it, and `unseen` is 0. `conversation_history` still lists it. Once seen by the first session, a message is not redelivered.
- **Late arrival.** With `bert`'s session stopped and detached and no new one, alice sends m. The next session's claim has m with `redelivered` false and `catch_up` false, and its window as a first claim.
- **Never offered.** alice sends s1, delivered, unclaimed. After `deny alice` on bob: the claim is `null`; `pending_work` has no entry for it; `GET .../messages` and `conversation show --as bert --json` on bob do not list s1; `GET /adapter/v1/conversations` has `unseen` 0 and `last_message_at` not from s1; `GET .../messages?before=S1` is 400; alice's target stays `delivered`. After `allow alice` and the policy wait, the claim is still `null` and s1 still appears nowhere; alice's new s2 is claimed with a `window` and `window_total` that do not include s1.
- **Hidden, then allowed, before any claim.** alice sends r1, delivered. After `deny alice`, `pending_work` and history hide it; after `allow alice` with no claim between, they show it and the claim returns it.
- **Blocked on return.** `bert` claims t1, unseen; after `deny alice`, `conversation show --as bert --json` on bob still lists t1, since a live session holds it (not `conversation_history`, which would mark it seen). After replacing the session with the deny still in place, the claim is `null`, and `conversation_history` no longer lists t1.
- **Undelivered.** alice runs `block bob`; `bert` sends u1 in a conversation with alice's person: the target becomes `refused`, and `bert`'s claim has `notification.kind` `undelivered`, `message_id` u1, `undelivered` with the participant, `state` `refused`, `code` `not_authorized` and the preview; the next claim is `null`, so there is exactly one; `unseen` is unchanged; `unblock bob` afterwards. A second target that was `delivered` produces no notification. Replacing the session before seeing it redelivers it with `redelivered` true.
- **History pages.** `ada` and a person on alice exchange 5 messages of 65,536 bytes and a short one. `GET .../messages` without `limit`: the newest messages within the budget (the short one and 3 large, or 4 large when the short one is older), in display order, total content at most 262,144 bytes, `next_before_message_id` the oldest returned. Following it pages through all of them with no repeats. `limit=2`, `limit=0` and `limit=51`, an unknown parameter, and an unknown `before` behave as above. `participants` lists the participants. After leaving, the route is 403 `not_participant`; on an unknown conversation, 404; without directory access, 403 `no_directory`. A closed conversation stays readable.
- **`stopped`** (last; bob's host is stopped). `ada`, a local agent in a conversation with `bert` started before bob stopped, sends a message; its target stays `sending`. The test clock moves 24 hours and 1 second; within 20 seconds the target is `stopped`, and a new session from `a.attach(ada.agent)` (the old one's 2-hour authorization has expired) claims one `undelivered` notification with `state` `stopped`.

**Rust.** `cargo test` unit tests cover what the slim suite cannot reach: the `--hook` lead sentence, and output when only `conversations` is non-empty (no `attach` profile in the harness); the recheck's `wait` outcome (no host there lacks a current policy of the owner while still holding the message); and `stopped` followed by `delivered` or `refused` making no second notification, and none when P has already left.

**Node adapter** (`node --test` in `integrations/shared`, as in C1 and C2): a catch-up claim's `meta` (`catch_up`, `redelivered`, `unseen`) and content with and without a window; `forwarded` after it; the `conversation_undelivered` event's `meta` and content for `refused`, `unsupported` and `stopped`; `conversation_history` input validation, its daemon call with `before` and `limit`, and the `not_participant` tool error; `mark_seen` accepting `conv_` and `cmsg_` IDs.

## C6: rate, addressing, and the person's tools

C6 finishes feature slice 1 (DEC.impl90 to DEC.impl99): the 60-messages-per-hour limit on both sides, `addressed_to` from local surfaces and `meta.addressed`, the `about` task link, the read cursor and unread counts, the event log and `conversation watch`, `conversation forget`, `home_unavailable`, terminal escaping, the activity kinds, and listing the commands (CONV-24). Everything in C1 to C5 stays as written unless this section changes it. No acceptance rule of an earlier section is relaxed. The manual live run (CONV-25) is recorded separately and is not part of this section's verification.

**Words.** P is a local participant. *Visible to P* is the rule of C1's [Who may see what](#who-may-see-what) for a person and of C5's [What an agent may see](#the-handoff-recheck) for an agent, including the recheck. Every read path below uses it; none records anything about a recheck, as C5 says.

### The rate limit

An author may have at most 60 messages per conversation in any trailing hour. The limit is checked by the author's host and again by each recipient host. Both checks count stored rows, so a restart changes nothing. No counter lives in memory.

**A message's time.** A message's *time* is the lesser of its `sent_at` and when this host stored it. The count for a message at time T covers the messages this host holds with the same author and conversation, and with a time above T minus 3,600 seconds and at most T.

Counting by `sent_at` rather than by arrival means an honest author never trips a recipient's limit. A burst of retries or a catch-up after an outage carries the times the author's host already limited. Claiming a future `sent_at` gains nothing, since the time is then the storing time.

**At the author's host.** The owner and adapter sending routes (`POST /v1/conversations/{id}/messages`, `POST /adapter/v1/conversations/{id}/messages`) check, in this order, after C1's shape check:
1. the repeat rule (below), so a repeat is never limited and consumes nothing;
2. closed, then joined, as today;
3. `addressed_to` resolution (below);
4. **rate:** 60 or more of this author's messages in the hour ending now is 429 `{code: "limit", error: "This participant reached its limit of 60 messages per hour in this conversation."}`. Nothing is stored and no `seq` is used.

The CLI prints `error: limit: This participant reached its limit of 60 messages per hour in this conversation.` and exits 1. Each author is counted alone: a person and an agent on one host have separate allowances. Local deliveries (decision 18) are covered by this check and have no second one.

**At a recipient host.** `POST /peer/v1/conversations/{id}/messages` gains a step between authorization and persist, after the repeat, roster, closed and authorization steps:
- **Rate.** A message whose `message_id` this host does not yet hold, with 60 or more messages of this author in the hour ending at its time, is 429 `{code: "limit", error: "This author reached its limit of 60 messages per hour in this conversation."}`. Nothing is stored.
- A further target of a message this host already holds passes this step and is not counted again.
- An identical repeat returns the saved receipt at C1's step 3 and never reaches this step. Only accepted messages count: a refused attempt counts for nothing, and repeating it gets 429 again while the hour is full.

The author's host records the 429 as `refused` with code `limit`, as C2's answer table says. It is final for that target, even after the hour passes. As for every `refused` target of an agent author, C5's `conversation_undelivered` event follows.

**Fetched messages.** [Fetched-message acceptance](#fetched-messages) gains the same step between its authorization and persist steps. A failure is refused `limit`, resolved for T like any other final code, and its content is not stored. The `refused` codes of `POST .../acks` gain `limit`. An author host's fetch entry for an outbound record refused with `limit` is C4's `{message_id, seq, prev_seq, refused: "limit"}`.

### `addressed_to`

Every joined participant still receives an addressed message. The field only tells the others it is not mainly for them.

**Local sending.** `POST /v1/conversations/{id}/messages` and `POST /adapter/v1/conversations/{id}/messages` gain optional `addressed_to`: an array of at most 16 strings of at most 256 characters each. Each names a participant in any of these forms, the forms `conversation start` takes for a target plus the full ID, resolved against the entries of `participants` in the held roster that have an `id` and are `joined` or `inviting`:
- a participant ID;
- a label as this host shows it (`alice`, `alice/claude`);
- for a person participant, `person:LABEL`, `person:PERSON_ID`, or `PERSON_ID`;
- for an agent participant, `HOST_ID/NAME` or `HOST_ID/AGENT_ID`, HOST_ID being the host in its participant ID.

The result of resolving:
- no match is 404 `{code: "not_found", error: "No such participant in that conversation."}`, so a departed participant or a person not yet joined cannot be named;
- several matches are 409 `ambiguous` with the matching IDs in `matches`, as C2's `remove`;
- entries resolving to one participant count once; the author may be named.

The stored `message.addressed_to` holds the resolved participant IDs in roster order. An empty array is the same as none: the field is left out of the stored and sent message, so the peer route's existing 1-to-16 rule still holds. The first message of `POST /v1/conversations` and `POST /adapter/v1/conversations` has no `addressed_to`.

**Repeats.** C1's repeat rule compares `addressed_to` as well as `content`. A repeat matches when, against the stored IDs and their current labels, the given entries, in any of the forms above, name exactly the stored set; absent or empty matches only a message with none. This is decided before resolution, so a repeat still succeeds after a named participant departed. Every form above still matches a departed participant, including `HOST_ID/NAME` for a departed agent, whose name this host remembers; a host that no longer knows the name matches only the other forms. A difference is 409 `conflict` with C1's text.

**Views.**
- The owner message view and the adapter message view gain `addressed_to_labels`, the label of each `addressed_to` entry in the same order, derived as `author_label` is.
- The owner message view gains `addressed`, as the adapter view has: true when `addressed_to` is empty or includes the viewing participant.
- Readable `show` and `watch` print `to LABEL, LABEL` after the author label when `addressed_to` is not empty.

### The `about` task link

A conversation may name a task it is about. The link is informational: it is shown in views and events only, and grants nothing. No host checks that the task exists.

- `POST /v1/conversations` and `POST /adapter/v1/conversations` gain optional `about: {peer_host_id, task_id}`, where `peer_host_id` is a host ID (`^host_[0-9a-f]{64}$`), `task_id` is `^task_[0-9a-f]{32}$`, and no other key is allowed; otherwise 400 `invalid`.
- The roster gains optional `about` with the same shape, omitted when there is none. Home never changes it after start. A peer's roster with a malformed `about` fails C1's shape check (400 `invalid`).
- The conversation view, the invite view, and both summaries gain `about`, null when none.
- CLI: `conversation start ... --about HOST_ID/TASK_ID`.

### The read cursor and unread counts

There is one read cursor per person participant, in `conversation_reads`, holding a `local_seq` that only moves forward. Agents use seen (C5), not a cursor.

**Unread.** A person's *unread* count in a conversation is the number of messages visible to that person, not authored by that person, with a `local_seq` above the cursor. A message that arrives late is unread even if it sorts before messages already read.

- `GET /v1/conversations` summaries gain `unread`, the count for this host's person participant, and 0 when that person is not in the conversation or the host has no bound person.
- `GET /v1/status` and `GET /v2/status`: `conversations` becomes `{open, unread, invites}`. `unread` sums the count over the conversations counted in `open`, and is 0 without a bound person. Unread messages add no attention item.
- Readable `conversations` shows `N unread` when N is above 0.

| Route | Body | Answer |
| --- | --- | --- |
| `POST /v1/conversations/{id}/read` | `{message_ids?}` | 200 `{conversation_id, participant, unread}` |

- `message_ids` is 1 to 100 message IDs, each visible to the person; anything else is 400 `invalid`. The cursor moves to the highest `local_seq` among them. Without `message_ids`, it moves to the highest `local_seq` of the messages visible to the person now.
- A cursor already at or past that point does not move, and the route still answers 200.
- 404 `not_found` for an unknown conversation; 409 `not_bound` without a bound person; 403 `not_participant` when the person was never in the roster. Unknown fields and nulls are 400.

**What advances it.** Only this route does; every `GET` leaves the cursor alone.
- `conversation read ID` posts without `message_ids`.
- `conversation show` (readable or `--json`) posts the IDs of the messages it listed, so the cursor reaches the most recently stored of them. It does not post with `--as AGENT` or when it listed none. A page reached with `--before` cannot move the cursor back.
- `conversation watch` posts the IDs of the messages it printed, except with `--as AGENT`.

### The event log

`conversation_events` holds a local log. An entry is `{sequence, kind, conversation_id, message_id, participant, at}`, committed in the transaction of the change it reports, and it never holds content. `sequence` is never reused.

| `kind` | Written when | `message_id` | `participant` |
| --- | --- | --- | --- |
| `message_sent` | a local participant's message is stored | that message | the author |
| `message_received` | a message is accepted for a local participant, pushed, fetched or by local delivery; one entry per target | that message | the target |
| `target_changed` | an outbound target of a local author's message changes state (`delivered`, `refused`, `unsupported`, `stopped`) | that message | the author |
| `roster_changed` | this host commits or stores a newer roster for a conversation it holds | null | null |
| `invited` | a pending invite is first stored here (not on a repeat) | null | `person:PERSON_ID` |
| `read_changed` | a read cursor moves | null | the person participant |

Entries older than 30 days on this host's clock, and those beyond the newest 10,000, are deleted.

| Route | Query | Answer |
| --- | --- | --- |
| `GET /v1/conversations/events` | `after` (default 0), `limit` (1 to 1,000, default 100), `wait` (seconds, 0 to 25, default 0), `participant`, `conversation` (a full ID) | 200 `{events, next_after, latest}` |

- `participant` follows C1's read rule: a local participant ID, defaulting to the person participant (409 `not_bound` without one, 400 `invalid` for one that is not local). `conversation` naming a conversation this host does not hold is 404 `not_found`. An unknown or malformed query parameter is 400 `invalid`.
- **What P gets.** Entries in `sequence` order above `after`, keeping only those for P:
  - `message_sent`, `message_received` and `target_changed` whose `participant` is P and whose message is visible to P at the time of this read;
  - `read_changed` whose `participant` is P;
  - `roster_changed` for a conversation whose roster or departures list P;
  - `invited` whose person is P's person.
- **Hidden entries are passed over for good by a reader that follows `next_after`.** An entry whose message fails or waits on the recheck is skipped, and `next_after` moves past it, so that reader does not get it later even if the author is allowed again. Each read decides afresh from the `after` it is given: a new read from an earlier `after` returns the entry if its message is visible at that time. `conversation show` and the claim still follow C5.
- `next_after` is the sequence of the last entry examined: the last returned entry's when `limit` was reached, otherwise `latest`, and never below `after`. `latest` is the highest sequence in the log (0 when it has never held one).
- `wait` holds the request until an entry for P exists or the wait ends, then answers, possibly with `events` `[]`.

| Route | Query | Answer |
| --- | --- | --- |
| `GET /v1/conversations/{id}/messages/{message_id}` | `participant` | 200 `{message: MESSAGE VIEW, earlier_missing}` |

It follows C1's read rule for `participant`. A message that does not exist, or is not visible to P, is 404 `not_found` with the same text either way.

`earlier_missing` is true while this message lies past a gap for P: its author is on another host and P's chain head for that author (C4) is below this message's `seq`. It is false otherwise, including for P's own messages and for authors on this host. It turns false once the gap closes, so it can change between reads. A gap the fetch cannot close keeps it true until a sync closes it.

### `home_unavailable`

The conversation view and both summaries gain `home_unavailable`: true while the home host is not a current member of any coordinator-free network this host shares with it (CONV-23), and always false on the home host. Sending continues among participants whose hosts are members, a local leave still works at once (C2), and readable `show` adds `home unavailable` to its header line.

### `conversation forget`

| CLI | Route | Answer |
| --- | --- | --- |
| `conversation forget ID [--yes]` | `DELETE /v1/conversations/{id}` | 200 `{conversation_id, state: "forgotten", roster_kept}` |

**CLI.** `ID` follows C1's prefix rule. At a terminal without `--yes`, it asks before sending; any answer other than `y` or `yes` prints `Not forgotten.`, changes nothing, and exits 0. Not at a terminal, without `--yes`, it exits 1 with `error: confirm: conversation forget needs --yes when not at a terminal.` and sends nothing.

**Checks,** in order:
1. 404 `not_found` for a conversation this host does not hold, including one already forgotten here or known only from a pending invite.
2. If the conversation is open and a local participant is joined here, or a current pending invite for it is held here, 409 `{code: "in_use", error: "Someone on this host is still in that conversation; leave it first."}`. A closed conversation can be forgotten with its participants still listed.

**What is deleted,** in one transaction: this host's messages, inbound and outbound target records, notifications, read cursors, and event log entries of the conversation. Outbound targets still `sending` stop. Activity entries stay; they hold no content.

**Not on home** (`roster_kept` false): the roster goes too, and the host then answers as one that never held the conversation. An unconfirmed leave or decline in `conversation_roster_outbound` is kept and still sent. So is, with no content, the highest `seq` each local author used, so that author's next message after a later invite never reuses a `seq` other hosts hold. A later invite is a new start: its chain heads begin at 0, so a gap fetch may bring back messages the authors sent to that participant, each passing acceptance again.

**On home** (`roster_kept` true): the conversation row, the roster, and the outbound pushes stay, and the conversation is marked forgotten.
- Local routes treat it as unknown (404 `not_found`), and it leaves the list.
- Peer routes keep serving it: `GET .../roster`, `POST .../join`, `POST .../leave` and roster pushes work as before, home's expiry and `unanswered` timers keep running, and every new roster is still pushed.
- `heads` answers `authors` `[]`, `GET .../messages` is 404 `not_found`, and `acks` answers `{acked: 0}`.

### Terminal escaping

**The rule.** Text printed for a person never carries a terminal control character. Every piece of peer-supplied text in readable output is **escaped**: each character below U+0020 (including newline and tab), U+007F, and U+0080 to U+009F is written as `\u` and four lowercase hex digits, as capability approval views already show caller text. So a message cannot start a new line that looks like another message.

**Readable output** covers content, titles, participant and author labels, names, `addressed_to` labels, invite notes, `added_by` labels, target labels and reasons, previews, and error texts, in:
- `conversations`, `conversations --invites`, `conversation show`, `conversation watch`;
- `session pending` and `session pending --hook`, for conversation entries;
- `error: CODE: TEXT` from any conversation command, on stderr.

**JSON output.** Every JSON the `conversations` and `conversation` commands print, with or without `--json`, writes U+007F and U+0080 to U+009F as `\u00XX` in strings, beside the escapes JSON already requires. Parsing returns the original text. The daemon's routes are unchanged: they answer the original text, encoded as JSON.

**Names.** A peer-asserted agent `name` is not refused for its characters; it is escaped wherever printed. Titles keep C1's rule, where a control character is any of U+0000 to U+001F and U+007F to U+009F, so such a title is 400 `invalid` from the owner route and in a peer's roster.

**Agent events.** In the channel events' content and meta, the adapter writes labels and the title with control characters escaped by the same rule, so a peer-chosen name cannot forge a line. Message content stays as received and is presented as peer content (C1).

### Activity

These kinds are recorded in `GET /v1/activity`, each in the transaction of its change, as `{sequence, kind, subject_id, created_at}`. Activity never holds content, a title, or a label.

| Kind | When | `subject_id` |
| --- | --- | --- |
| `conversation.created` | this host creates a conversation as home | `CONVERSATION_ID` |
| `conversation.roster_changed` | this host commits or stores a newer roster, other than the creating one and the closing one | `CONVERSATION_ID` |
| `conversation.closed` | this host commits or first stores a closed roster | `CONVERSATION_ID` |
| `conversation.message_sent` | a local participant's message is stored | `CONVERSATION_ID/MESSAGE_ID` |
| `conversation.message_received` | a remote author's message is first stored here, once per message while this host holds it (after `forget` and a later invite, a fetch may store it and record it again) | `CONVERSATION_ID/MESSAGE_ID` |
| `conversation.message_refused` | an outbound target becomes `refused` | `CONVERSATION_ID/MESSAGE_ID` |

A local delivery is one `conversation.message_sent` only. A repeat records nothing. Each host records only what happens on it: only home records `conversation.created`, and only the author's host records `conversation.message_refused`.

### Commands

**CONV-24.** `conversations` and `conversation` are listed in the root help (`MAIN_COMMANDS`), the advanced help, the README and the quick start. `conversation sync` stays out of the README and the quick start. The unit test on the root help's list changes with `MAIN_COMMANDS`.

| CLI | Route | Output |
| --- | --- | --- |
| `conversation say ID TEXT [--to PARTICIPANT ...] [--message-id ID]` | `POST .../messages` | As C1; `--to` fills `addressed_to`. |
| `conversation start ... [--about HOST_ID/TASK_ID]` | `POST /v1/conversations` | As C2. |
| `conversation read ID` | `POST .../read` | The route's JSON. |
| `conversation forget ID [--yes]` | `DELETE /v1/conversations/{id}` | The route's JSON. |
| `conversation watch [ID] [--as AGENT]` | `GET /v1/conversations/events`, `GET .../messages/{message_id}`, `POST .../read` | Below. |

**A host where only agents take part.** A host's person may be outside a conversation that an agent on the host has joined: `conversations` lists it, and the person's reads are refused by C1's rule. The routes do not change. The CLI adds what to do:

- `conversation show ID` without `--as` (readable or `--json`), when the read is refused with `not_participant` or `not_bound` and at least one agent on this host is `joined` in the conversation, exits 1 with C1's line followed by the agents' names, sorted by name and separated by `, `, for example:

  ```
  error: not_participant: This participant is not in that conversation. Agents on this host that are: claude-8e17, helper. Use --as NAME.
  ```

  It does not choose an agent by itself, even when there is only one: the reader stays explicit, and `--as` leaves the person's read cursor alone. With no such agent, the line is C1's, unchanged.
- `conversation watch ID` makes the same read first and exits 1 before the `Watching` line when it is refused. Without `--as` the error is the one above. With `--as` the agent is outside the conversation, and the error is C1's line, unchanged.
- `conversation watch` with no `ID` and no `--as` keeps running, and writes one line to stderr for each open conversation where an agent on this host is `joined` and this host's person participant is not:

  ```
  Not showing conv_0123abcd: this host's person is not in it. Agents on this host that are: claude-8e17, helper. Use conversation watch --as NAME.
  ```

  For conversations already there when it starts, the line comes right after the `Watching` line. For one that comes to qualify later, the line comes within 30 seconds. Each conversation gets the line once per run. Nothing about these conversations goes to stdout.

**`conversation watch`.**
- It first reads `latest` with `wait=0&limit=1`, then writes `Watching; press Ctrl-C to stop.` to stderr, so it prints only what happens after that line. It then long-polls with `wait=25`, or shorter while it holds a message (below). `ID` follows C1's prefix rule and limits it to that conversation.
- For each `message_sent` and `message_received` it fetches the message, and prints one line to stdout: the conversation ID's first 13 characters, the `sent_at` time (`HH:MM`, UTC), the author label, `to LABEL, LABEL` when addressed, and the content, all escaped. A message the fetch no longer shows is skipped. Each `target_changed` to `refused`, `unsupported` or `stopped` prints the line `show` uses for that target. Each `roster_changed` and `invited` prints one line starting with the conversation ID's first 13 characters, followed by the change. Other wording and spacing are not part of the contract.
- **Order.** Messages print in display order as far as the host can know it:
  - A message with `earlier_missing` true is held and not printed, and each held message is read again at least once a second. It prints when `earlier_missing` turns false, or at the latest 5 seconds after watch first read it, whichever comes first. A message that comes in later than that prints when it arrives, out of order; its `HH:MM` time shows this.
  - A later message of an author with an earlier one held waits behind it. While any of an author's messages in a conversation is held, a further one of that author takes the same limit, which runs from the first of them; so no arrival extends the 5 seconds.
  - Messages that become printable together print in display order, per conversation. So one author's messages print in `seq` order whenever the earlier ones arrive within the hold.
  - Messages of different authors that arrive in separate polls print as they arrive: nothing tells this host that an earlier one is on its way.
- stdout is flushed after each line.
- It posts the cursor after printing each batch (see above). A held message has not been printed, so the cursor does not count it, and it stays unread if watch ends first. The cursor is a single high-water mark, so while a conversation holds a message, watch posts nothing for that conversation: messages it printed meanwhile are posted once the hold ends, and stay unread if watch ends first.
- SIGINT or SIGTERM ends it with exit 0. A daemon that cannot be reached exits 1 as for any command; a failure after it started is retried once a second until the daemon answers again.

**Daemon stop.** A held `GET /v1/conversations/events` answers at once when the daemon gets SIGINT or SIGTERM, with what it has, possibly `events` `[]`, so a running `watch` does not delay the stop. The routes that wait up to 15 seconds for another host do not delay it either: `POST /v1/conversations` and C2's `add` answer at once as they do at 15 seconds, with the target `inviting`, and `POST /v1/conversations/{id}/join` answers at once with its 503 `unavailable`. See the [host service contract](host-service-contract.md) for the limits.

### Node adapter

**`conversation_send`** gains `addressed_to`: an array of at most 16 strings of at most 256 characters each, optional, sent to the daemon as given. The input schema is now (`additionalProperties: false`):
- `conversation_id`: string, required, `^conv_[0-9a-f]{32}$`.
- `content`: string, required, 1 to 65,536 characters.
- `addressed_to`: as above.
- `message_id`: string, optional, `^cmsg_[0-9a-f]{32}$`, generated when absent.

Its refusals gain:

| Daemon `code` | Tool `code` | `error` |
| --- | --- | --- |
| `limit` | `rate_limited` | `This agent reached its limit of 60 messages per hour in this conversation. Wait, or ask the person.` |
| `not_found`, from `addressed_to` | `not_found` | the daemon's |
| `ambiguous` | `ambiguous` | the daemon's |

**`conversation_start`** gains `about`: an object with required `peer_host_id` and `task_id` of the patterns above, `additionalProperties: false`.

**The `conversation` event.**
- `meta` gains `about_peer_host_id` and `about_task_id` beside the C1 keys, only when the conversation has an `about`. `meta.addressed` is from the claim's new message, as C1 defines it.
- The content gains a line `About task TASK_ID on HOST_ID` after `Participants:` when `about` is set, on `conversation`, `conversation_roster` and `conversation_undelivered` events.
- A new message or window entry with `addressed_to` reads `[LABEL HH:MM, to LABEL, LABEL] CONTENT`, the labels from `addressed_to_labels`. For this agent's own: `[LABEL HH:MM, to LABEL] (you) CONTENT`.

The MCP server instructions do not change. `list_conversations` and `conversation_history` return the new view fields.

### Persistence

No new schema version: schema 24 already has `conversation_reads` and `conversation_events`. `about` lives in the roster inside `record`; the forgotten mark on home lives in the conversation's `record`.

### Verification

Spec-only cases in `conformance/slim/conversations_tools.py`, written from this section by the separate author, with its own `suite` matrix entry and a 2-minute limit.

**Setup.** C1's alice and bob in one coordinator-free network, with `suite.use_clock()` before any host starts.
- **Fixture agent.** `bert` on bob comes from `b.agent("bert")`, a directory session with a verified channel. It claims with `bert.post("/adapter/v1/conversation-notifications/next")` until non-null, then posts `.../{id}/forwarded`. A fixture claims only when the suite calls this, so a message stays unclaimed for as long as a case needs. Sends use `bert.post("/adapter/v1/conversations/ID/messages", {...})`.
- **Policy.** bob's `allow alice --no-tasks --person-key KEY` gives alice `message.append` to bob's agents; `deny alice --person-key KEY` takes it away, at once on bob. Each change is followed by C1's policy-version wait where alice must cite it. People need no policy: `conversation start person:bob` and `conversation join ID` on bob, as in C3.
- **Raw requests.** Use `peer(sender, receiver, method, path, body)`. A probe message omits `prev_seq` (so it reveals no gap), uses `seq` values alice's host has not used, and carries the roster version bob holds. A person target takes no citation.
- **Speed.** The 60 sends go through `POST /v1/conversations/{id}/messages`, not the CLI, except where a case names the CLI.
- **Watch.** Run `peerspan conversation watch` with `suite.spawn`, wait for `Watching` on stderr before sending, and terminate it in the case.
- **Clock.** A case moving the test clock runs after every other case, and restarts hosts before expecting peer traffic.

**Cases** (the proposal's C6 column, made concrete):
- **Limit at the author's host.** In a conversation with `bert`, alice sends 60 messages through the owner route, each 200. All 60 targets for `bert` reach `delivered`, so the recipient's limit does not trip. The 61st `conversation say` exits 1 with `error: limit: This participant reached its limit of 60 messages per hour in this conversation.`, and `show --json` lists no 61st message. A repeat of the 60th `message_id` with its content is 200. After restarting alice, a new message is still refused. `bert` can still send (each author is counted alone).
- **Limit at a recipient.** In a conversation between alice's and bob's persons, 60 probe messages from alice with `sent_at` now are each 200. The 61st is 429 `limit`, and again when repeated. A repeat of the 60th returns its saved receipt. After restarting bob, a new one is still 429. A probe with `sent_at` two hours earlier is 200 (it counts in its own hour).
- **Final refusal.** With the allowance on bob filled by those probes, alice's own next `conversation say` in that conversation is 200 on alice (her host stored none of the probes), and its target for bob's person becomes `refused` with `limit`.
- **The window** (clock). After the clock moves 3,601 seconds and the hosts restart, alice's next `conversation say` in the first conversation is 200.
- **`addressed_to`.** With alice, `bert` and a second fixture agent `bea` on bob in one conversation, `conversation say ID TEXT --to bob/bert`:
  - `bert`'s claim has `addressed` true, `addressed_to` `[BERT]` and `addressed_to_labels` `["bob/bert"]`;
  - `bea`'s claim has the message with `addressed` false;
  - a message with no `--to` is `addressed` true for both;
  - `--to` by participant ID works; `--to nobody` exits 1 with `not_found`, and no message is stored;
  - a repeat of the `message_id` with another `--to` is 409 `conflict`; `pending_work` shows `addressed` accordingly;
  - alice's `show --json` gives `addressed` true for her own unaddressed message, and false for one addressed only to `bert`.
- **`about`.** `conversation start bob/bert --about HOST/TASK`: alice's and bob's views show the same `about`, and `GET /adapter/v1/conversations` on `bert` shows it; a malformed value is 400 `invalid`. It gives no access: with `deny alice` in place, a start with `about` does not admit the agent. Which answer depends on alice's directory entry, not on the policy version she holds: a policy sync does not update that entry, so after `deny alice` and the policy wait it is still the earlier one, and the answer is 201 with the invite outcome `refused`, code `not_authorized`, from bob's host. After `agents --refresh` the directory no longer lists the agent, and the answer is 404 `unknown`. 403 `not_authorized` is for an entry that still lists the agent without `message.append`. In every form the agent is not `joined`.
- **Read cursor.** In a conversation of alice's person, bob's person and `bert`:
  - alice sends 2 messages: bob's summary `unread` is 2, and `GET /v1/status` `conversations.unread` rises by 2;
  - `GET /v1/conversations/{id}/messages` changes nothing;
  - `conversation show ID --as bert` changes nothing;
  - `conversation show ID` makes it 0;
  - a third message makes it 1, and `conversation read ID` makes it 0;
  - bob's own message does not count;
  - `POST .../read` with a message ID not visible to bob is 400.
- **Watch.** Before watch, bob has one unread message. It is not printed, and it stays unread until a later cursor moves past it. With watch running, alice's new message prints a line with its content and the unread count reaches 0 within 20 seconds. A message in another conversation prints only without an `ID`. After the watch is terminated (exit 0), a new message stays unread.
- **Event log.** `GET /v1/conversations/events` on bob lists `message_received` and `read_changed` for the person, with exactly the keys `sequence, kind, conversation_id, message_id, participant, at` and ascending sequence. `after=N&wait=2`, N being the number in an earlier answer's `latest` field, answers `events` `[]` after about 2 seconds, and a message arriving during `wait=20` ends it early. `wait=26`, `limit=0` and an unknown parameter are 400.
- **Nothing hidden leaks.** alice sends s1 to `bert`, `delivered`, unclaimed. After `deny alice` on bob:
  - `GET /v1/conversations/events?participant=BERT&after=0` has no entry with s1's ID;
  - `GET /v1/conversations/{id}/messages/S1?participant=BERT` is 404;
  - a `conversation watch --as bert` started now, with alice then sending s2 (refused at bob), prints neither message.

  After `allow alice` again and no claim, the claim returns s1 (C5), and the event entry stays passed over for a reader already past it.
- **Forget.**
  - bob's person, joined in a conversation homed on alice, gets 409 `in_use` from `forget` on bob.
  - After `conversation leave`, `forget --yes` on bob answers `roster_kept` false, and `show` exits 1 with `not_found`. Without `--yes` and not at a terminal, it exits 1 with `confirm` and changes nothing.
  - On home: alice starts with `person:bob` and `bob/bert`, bob joins, alice leaves, `forget --yes` answers `roster_kept` true; `show` on alice is `not_found` and the list omits it; `GET .../roster` by probe from bob still answers 200; bob's `conversation leave ID` reaches home and a later `GET .../roster` lists bob's person in `departed`; `bert` still leaves through `manage`, and the roster shows that too. Alice's `GET /v1/activity` keeps the earlier entries.
- **`home_unavailable`** (use a fresh host dave, since it is revoked).
  - dave joins alice's network and starts `conversation start person:alice`, and alice joins. alice's view has `home_unavailable` false.
  - After `network revoke --network ID --host DAVE`, alice's view has it true, and `conversation leave ID` on alice answers 200 at once.
- **Escaping.** alice says a message whose content is `ESC [31m red BEL U+009B 2J newline fake`.
  - bob's `conversation show` stdout holds `\u001b[31m`, `\u0007`, `\u009b`, `\u000a` as text, and no raw ESC, BEL, or the bytes of U+009B.
  - `watch` prints the same.
  - `conversation show --json` holds no raw U+009B, and parsing it returns the content exactly.
  - A probe roster push from alice with a higher version, in a conversation of its own, listing an alice agent with `name` holding ESC, prints escaped in bob's `show`, `conversations`, and the `show --json` bytes for U+009B.
  - A title with a control character is 400 from the owner route.
- **Activity.** `activity --limit 1000` on alice holds `conversation.created`, `.roster_changed`, `.message_sent`, `.message_received`, `.message_refused` and `.closed`, and on bob at least `.roster_changed`, `.closed`, `.message_sent` and `.message_received`, with the subject shapes above, and no case's message content or title anywhere in either output.
- **Help.** `peerspan --help` lists `conversations` and `conversation`.

**Multi-machine run fixes.** Spec-only cases in a new suite `conformance/slim/conversations_run_fixes.py`, with its own matrix entry and a 2-minute limit. Same setup as above.
- **`addressed_to` forms.** In a conversation of alice's person, bob's person and `bert`, each of these resolves to the same participant through `conversation say --to`, through the owner route, and through `bert`'s adapter route: `person:alice`, `alice`, `person:PERSON_ID`, `PERSON_ID` and the participant ID, for alice's person; `bob/bert`, `HOST_ID/bert` and `HOST_ID/AGENT_ID`, for `bert`. `person:nobody` is 404 `not_found` with `No such participant in that conversation.`. `person:bob/bert` is the same 404. A person still `invited` named as `person:LABEL` is the same 404. A repeat of a `message_id` first sent with `--to alice` and repeated with `--to person:alice` is 200 with the stored message; repeated with `--to bob/bert` it is 409 `conflict`.
- **Agents only: `show`.** alice runs `conversation start bob/bert`, so bob's person is not in it, and bob's `conversations` lists it. bob's `conversation show ID` exits 1 with exactly `error: not_participant: This participant is not in that conversation. Agents on this host that are: bert. Use --as NAME.`, with `--json` too. `conversation show ID --as bert` exits 0. After `bea` on bob is added, the sentence reads `bea, bert`. After every agent of bob's has been removed from the conversation, the error is C1's line alone.
- **Agents only: `watch`.** In that conversation, bob's `conversation watch ID` exits 1 with the same text, and writes no `Watching` line. bob's `conversation watch` with no `ID` writes `Watching`, then the `Not showing` line with this conversation's first 13 characters and `bea, bert`; after alice sends a message, its stdout stays empty for 3 seconds. `conversation watch --as bert` prints that message. A conversation started for `bert` while the no-`ID` watch runs gets its line within 30 seconds, and each conversation's line appears once. A conversation with bob's person joined gets no such line, and its messages print.
- **Order, gap closed.** In a conversation of alice's person and bob's person, with alice's real message s1 `delivered` and with `conversation watch` running on bob: a probe message with `seq` 3, `prev_seq` 2 and `clock` above s1's by 2, then within 1 second a probe message with `seq` 2, `prev_seq` 1 and `clock` above s1's by 1. stdout prints seq 2's line, then seq 3's. `GET /v1/conversations/{id}/messages/{seq 3's ID}` answers `earlier_missing` false after this.
- **Order, gap not closed.** A probe message with `seq` 6 and `prev_seq` 5 alone: the route answers `earlier_missing` true; the line has not printed 2 seconds after the push, and has printed within 8 seconds of it. bob's unread count includes it until it has printed. A probe `seq` 5 with `prev_seq` 4 that follows later still prints.
- **`earlier_missing` otherwise.** It is false on a message's own author's read, and false for a message of an agent on this host.
- **Stop with a watch.** With `conversation watch` running on bob for 2 seconds, SIGINT to bob's daemon ends it within the 2-second limit of the host service contract, and again with SIGTERM; the suite's margin allows 5 seconds. The same watch keeps running across the restart and prints a later message.
- **Stop with a route waiting.** With bob's daemon stopped, alice's `conversation start person:bob` running for 1 second, SIGINT to alice's daemon ends it within the same limit and margin. The command exits 0 with the target `inviting`, and the conversation is there after the restart. `conversation add ID person:bob` behaves the same. With alice's daemon, the home host, stopped, and bob's `conversation join ID` waiting for it, SIGINT to bob's daemon ends it within the same limit and margin, and the command exits 1 with `unavailable`.

The next live run also checks the order the way a person meets it: stop a host, send two messages to it, restart it with a watch running there.

**Claim order.** The claim route takes notifications in the order they were created, which is the order messages reached this host (C5). A host's fan-out sends each message's request on its own, so two messages sent in quick succession can arrive, and be claimed, in either order; a case that needs one order waits for the first to be `delivered` before sending the second.

**Rust.** `cargo test` unit tests cover what the slim suite cannot reach:
- the event log's retention at 30 days and 10,000 entries;
- the `--hook` and `session pending` escaping (no `attach` profile in the harness);
- a saved fetch refusal with code `limit` answering a later push with 429 `limit`;
- a future-dated `sent_at` counting at its storing time.

**Node adapter** (`node --test` in `integrations/shared`, as before):
- `conversation_send` passes `addressed_to` and validates it, and maps `limit` to `rate_limited` with its text;
- `conversation_start` validates `about`;
- the `conversation` event's `to` labels and `About task` line, and `meta.addressed` and the `about_*` keys;
- labels holding control characters are escaped in event content.
