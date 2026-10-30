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

**Errors** are `{code, error}` with the HTTP statuses of the host service contract. CLI successes print JSON (except the readable views below) and exit 0. CLI failures exit 1 and write the daemon's `error` text to stderr.

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
- The author must be `joined` in the roster this host holds; otherwise 403 `{code: "not_participant"}`.
- **Repeats.** A `message_id` this host already holds for the same author and conversation with identical `content` returns 200 with the stored message and the current targets, without a second message or target. The same `message_id` with other content, another author, or in another conversation is 409 `{code: "conflict"}`.
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
- `roster` is the roster home will commit if the invite is answered `joined`: its `conversation_id` equals the body's, its `home_host_id` is the authenticated sender, and it lists the target as `agent:RECEIVER/AGENT_ID`, `joined`. Otherwise 400.
- `adder` is a participant ID that is `joined` in `roster` and on the sender host; otherwise 403 `forbidden`. `origin` is present exactly when `adder` is an agent, and then names it; otherwise 400.
- `note` is optional text up to 4,096 bytes (no C1 sender sends it).

The receiver checks membership and authorization of `adder` to reach the target agent, as above; an unknown target agent is 403 `forbidden`. On success it stores the roster (if it holds none for the conversation, or a lower version) and answers 200 `{state: "joined", name}` with the agent's name. A repeat for the same `(home host, conversation_id, target)` is idempotent: it is checked again and answers the same while the agent remains joined. C1 creates no notification for being added (C2 adds the `conversation_roster` event).

Home records 200 `joined` as `joined`; 400 as `refused` (`invalid`); 403 as `refused` (`not_authorized`); 404 as `unsupported`; and retries anything else (503, other statuses, transport failures, lost answers).

#### `POST /peer/v1/conversations/{id}/messages`

Body: `{message, target, prev_seq?, policy | grant_id | self}`. `target` is a participant ID on the receiving host. `prev_seq` is the `seq` of the author's previous message sent to this target, omitted for the first one since the target joined; C1 sends and stores it and does not act on gaps (C4).

**Acceptance**, in order:
1. **Shape.** IDs, sizes and the citation rule above; `message.conversation_id` equals the path's; `seq`, `clock` and `roster_version` at least 1; content within the recipient's `max_message_bytes` from the allowing rule or grant, when it has one. Otherwise 400 `invalid`. A `deadline` field is 400, as any unknown field.
2. **Author's host.** The host in `message.author` is the authenticated sender; otherwise 403 `forbidden`.
3. **Repeat.** A request whose `(sender host, message_id, target)` this host already accepted returns the saved receipt when `message`, `target` and `prev_seq` are identical (whatever it cites), and 409 `{code: "conflict"}` when any differs, before any later step.
4. **Roster.** A conversation this host holds no roster for, or a `roster_version` above the version it holds, is 503 `{code: "unavailable"}` (C2 adds fetching the roster). The target not `joined` here, or the author not `joined` in the held roster, is 403 `{code: "not_participant"}`.
5. **Authorization.** For an agent target, as above, with 403 `forbidden` and 503 `unavailable`. For a person target (the person participant on this host), the person is `joined` here, and the author's host and person are not blocked; otherwise 403 `forbidden`.
6. **Persist.** In one transaction: the message, stored once per host by `message_id` (a second target of the same message adds only its target record); the inbound target record; the clock raise; and, for an agent target, one conversation notification for that agent. Answer 200 with the receipt `{message_id, target, receiver_host_id, accepted_at}`.

A host never stores a message whose `message_id` it already holds with different `message` fields: such a request is 409 `conflict`.

**Fan-out and retry.** After committing a message, the author's host sends one request per outbound target, citing the authorization it holds at that moment for the author to reach that target (self, then the target owner's newest policy, then a grant, as sending by address chooses). When none of these allows it, it cites the target owner's newest policy it holds, so the receiver decides; when it holds no policy of that owner and no grant or self access applies, the target becomes `refused` with `not_authorized` without a request. The retry schedule is milestone 5's: the first attempt at once, then the first retry 10 seconds after the message was stored, then 1 second doubling to 60 seconds with ±20% jitter, persisted. At most 4 automatic conversation attempts (invites and messages together) run at once per daemon, separate from other retries. Overdue records after a restart are spread as in the messaging contract. The answer decides the target's state:

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
| `POST /adapter/v1/conversation-notifications/{id}/forwarded` | `{}` | 200 `{notification}`. Idempotent. 404 `not_found` for an unknown notification or another agent's. |

- **Directory access.** A credential without directory access gets 403 `{code: "no_directory"}` from the sending route, and `null` from the claim route.
- **Sending errors.** 404 `not_found` for a conversation this host does not hold; 403 `not_participant` when the agent is not `joined`; 409 `conflict` and 400 `invalid` as for the local route.
- **Claiming.** Before the authorization's channel is verified, the claim route answers 409 `{code: "conflict", error: "channel not verified"}` and claims nothing. Otherwise it claims the oldest unclaimed conversation notification of the agent, binding it to the claiming session; a claimed notification is not offered again in C1 (C5 adds returning and redelivery).

**Notification:** `{id, kind, conversation_id, message_id, session_id, created_at, claimed_at, forwarded_at}`. In C1 `kind` is always `message`.

**Claim:** `{notification, conversation, messages, window, window_total, redelivered}`:
- `conversation` is the agent's summary `{conversation_id, title, state, home_host_id, participants: [{id, label, kind, state, you}], unseen, last_message_at, creator}`, where `you` marks this agent and `creator` is whether this agent created the conversation. `unseen` counts this agent's message notifications in the conversation not yet forwarded, this one included (C5 replaces forwarding with seen).
- `messages` is a list of adapter message views, in C1 exactly the notification's message: `{message_id, author, author_label, author_kind, origin_agent_id, sender_person_id, sender_person, seq, clock, sent_at, received_at, content, addressed_to, addressed, mine}`. `origin_agent_id` is null for person authors. `sender_person_id` and `sender_person` are the person bound to the author's host and its member label, as for one-to-one handoffs, null when unbound. `addressed` is true when `addressed_to` is empty or includes this agent.
- `window` is non-empty only on the first notification of this conversation that this session claims: the messages this agent may see that sort before the new one in display order, at most the newest 10 and 16,384 bytes of (cut) content, newest kept, in display order. Each window entry is an adapter message view whose `content` is cut to its first 2,048 bytes at a UTF-8 boundary, with `truncated: true` and `content_bytes` (the full length) when cut, and `truncated: false` otherwise. Otherwise `window` is `[]`.
- `window_total` is the number of messages this agent may see before the new one (0 when `window` is empty because there are none).
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
