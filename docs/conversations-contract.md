# Conversations contract

Launch-plan track 3. The design and its settled decisions are in the [conversations proposal](conversations-proposal.md) and the owner decisions [CONV-1 to CONV-26](decision-log.md#conv-conversations-2026-10-25). Feature slice 1 is built as PRs C1 to C6 ([Slices](conversations-proposal.md#slices)); each PR adds its section here. Where this contract and the proposal differ, this contract applies; anything the proposal gives to a later PR is not part of an earlier section.

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

While this host has an *outstanding join* for the conversation (it sent a join that got no final answer), a roster from home that lists this host's person participant as `joined` is also home's confirmation and admits the person. Nothing else admits a local person: an invite never does, and a roster listing a person on this host as `joined` without an admission or an outstanding join is 400 `invalid`, as C2's roster step 5 says for agents.

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
| `GET /v1/conversations/invites` | | 200 `{invites: [INVITE VIEW]}`: the current pending invites on this host, newest `added_at` first. 409 `not_bound` without a bound person. |
| `POST /v1/conversations/{id}/join` | `{}` | 200 `{conversation: VIEW}` once home confirmed. |
| `POST /v1/conversations/{id}/decline` | `{}` | 200 `{conversation_id, state: "declined"}`. |

`{id}` in the join and decline routes is a full conversation ID. Unknown fields and nulls are 400.

**Invite view:** `{conversation_id, title, home_host_id, person_id, added_by, added_by_label, note, added_at, expires_at, participants: [{id, label, kind, state}]}`, from the pending invite's roster; `title` and `note` are null when absent; labels are derived here.

**Joining**, in order:
1. 409 `not_bound` without a bound person.
2. No current pending invite here for this host's person in that conversation: 404 `{code: "not_found", error: "No pending invite to that conversation on this host."}`.
3. This host's person participant already joined here in 200 open conversations: 429 `limit` with C2's text.
4. On home: the local join commits as home's peer join route below would for this host. Elsewhere: this host records an outstanding join and sends `POST /peer/v1/conversations/{id}/join` to home, waiting at most 15 seconds:
   - 200 `{roster}`: in one transaction this host admits its person participant, stores the roster, drops the pending invite and the outstanding join. Answer 200 `{conversation: VIEW}`.
   - 404: the pending invite and the outstanding join are dropped; answer 404 `not_found` with step 2's text.
   - 409 `closed`: dropped; answer 409 `closed` with C2's text. 409 `conflict`: dropped; answer 409 `{code: "conflict", error: "That person already takes part from another host."}`.
   - 403: dropped; answer 403 `{code: "forbidden", error: "The home host refused the join."}`.
   - Anything else, or no answer within 15 seconds: the pending invite and the outstanding join stay, and the answer is 503 `{code: "unavailable", error: "The home host did not answer; run conversation join again."}`. The host does not retry by itself; running `join` again sends again, and home answers a repeat as a success.

The outstanding join ends with a final answer, when the pending invite stops being current, or when a roster from home admits the person.

**Declining**, in order: 409 `not_bound`; 404 `not_found` as for joining; then, in one transaction, this host drops the pending invite (it is no longer current here) and records a decline for home. On home the decline commits at once (as home's leave route below). Elsewhere this host sends `POST /peer/v1/conversations/{id}/leave` `{participant: "person:PERSON_ID"}` to home with C1's retry schedule until home answers 200, 400, 403 or 404, as C2 sends a leave. Answer 200 `{conversation_id, state: "declined"}` without waiting for home. A later push of a roster that still lists the person as `invited` does not bring the pending invite back.

**Leaving** (C2's `POST /v1/conversations/{id}/leave` without `agent`) now works for a person participant joined here on any host: off home it sends `POST /peer/v1/conversations/{id}/leave` `{participant: "person:HOST_ID/PERSON_ID"}` as C2 does for agents.

**CLI.** Each prints the route's JSON answer and exits 0, or exits 1 with `error: CODE: TEXT` (C1).

| CLI | Route |
| --- | --- |
| `conversations --invites [--json]` | `GET /v1/conversations/invites`. Readable: one line per invite with the ID's first 13 characters, the title in quotes if any, `from ADDED_BY_LABEL`, and `expires EXPIRES_AT`; `No pending conversation invites.` when there are none. `--json`: the route's answer. `--invites` with `--all` is a usage error (exit 2). |
| `conversation join ID` | `POST /v1/conversations/{id}/join` |
| `conversation decline ID` | `POST /v1/conversations/{id}/decline` |
| `conversation start TARGET...`, `conversation add ID TARGET` | as in C2, with person targets |
| `conversation remove ID PARTICIPANT` | as in C2, also for persons not yet joined |

For `join` and `decline`, `ID` is the full ID or `conv_` and at least 6 hex digits matching exactly one current pending invite on this host (C1's prefix rule, over pending invites): none exits 1 with `not_found` and step 2's text, several with `ambiguous`.

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
- `person:PERSON_ID`, a decline: the sender must be bound to that person by a current binding grant in a network both hosts share, otherwise 403 `forbidden`. Home drops the person's `inviting` or `invited` entry in a new version and pushes it; a person not listed that way changes nothing (a joined person is not removed by a decline). Answer 200 `{roster}`.

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
