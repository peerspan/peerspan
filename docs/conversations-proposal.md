# Conversations

Status: **Proposed — owner decisions pending.** Nothing here is decided or implemented. The choices the owner has to make are listed under [Owner decisions needed](#owner-decisions-needed). Where this text says "is" or "does", it describes the recommended design, not a settled one.

This is launch-plan track 3, "Conversations" (`docs-internal`, `docs/launch-plan.md`). The owner tabled it on 2026-10-16 to follow the interface track. On 2026-10-25 the owner chose to start it now, designed for the surfaces that exist today: the `peerspan` CLI and the agents' Peerspan tools in Claude Code, Codex, and OpenCode. A later UI (local web UI, tray, or TUI, undecided) must be addable without changing the protocol, so [What a later UI needs](#what-a-later-ui-needs) lists what it would use.

It builds on the [messaging contract](peer-messaging-contract.md) (agent origin, retry, receipts), [owner access policy](coordination-contract.md#owner-access-policy), the [adapter](agent-adapter-contract.md), [outbound](adapter-outbound-contract.md), and [recovery](adapter-recovery-contract.md) contracts, [live delivery](live-delivery-contract.md) (seen, redelivery, `pending_work`), the [directory and addressing](launch-contract.md#slice-4-directory-and-addressing), and the agent-tools style of the [capabilities contract](capabilities-contract.md#agent-tools-slice-2).

## What exists today

- **Messages.** A host's agent or owner CLI sends one message to one remote agent (`POST /peer/v1/messages`). The receiving agent may answer once with `reply`. A reply event cannot itself be answered: that rule exists to prevent reply loops. Further exchange needs a new `send`, unrelated to the first.
- **No conversation object.** Nothing groups messages. A receiving session gets each message alone, with no history, and after `/clear` it has nothing but `pending_work` previews.
- **Two parties only.** Every exchange is one sender and one receiver.
- **Agents only receive.** Messages target agents. A person can send from the CLI (no `origin`), but nothing is ever delivered to a person.
- **The system design** asks for "exchanges between identifiable agents with sufficient context to continue across messages", with the operations "open, exchange messages, subscribe to replies, and close", explicit participants, hosts persisting their own sent and received messages, and no globally replicated transcript (`docs-internal`, `docs/design.md`).

## Goals and limits

**Goals:**
- A conversation object with an ID, explicit participants, and an open or closed state.
- Two or more participants, agents and people, on any number of hosts, with no central transcript: each host keeps the posts it sent and received.
- Each recipient's own owner policy decides, on the recipient's host, whether each sender may reach it. Being in a conversation never widens access.
- A receiving agent session gets enough context each turn to take part, bounded in size, and can fetch more.
- People take part from the CLI.
- Delivery to sessions uses live delivery's seen tracking, redelivery, and `pending_work`.
- A local API and event stream that a later UI can use unchanged.

**Not in the first slice** (see [Slices](#slices)):
- History for late joiners (they see posts from when they joined).
- Task discussion threads with their own authorization.
- Signed posts, or fetching one author's posts from another participant's host.
- Moving a conversation's home to another host.
- Files in conversations (task artifacts stay with tasks).
- A person taking part from more than one of their hosts at once.

## The object

### Identity and fields

A conversation ID is `conv_` followed by 16 random bytes in lowercase hex. The host that creates it is its **home host**, and stays so for the conversation's life in this proposal (decision 3).

The **roster** is the home host's record of who is in the conversation. Every participant host keeps a copy, replaced only by a higher `version` from the home host:

```json
{
  "conversation_id": "conv_…",
  "home_host_id": "host_…",
  "version": 3,
  "title": "Flaky checkout test",
  "state": "open",
  "created_by": "person:host_a…/person_…",
  "created_at": "RFC3339",
  "participants": [
    {"id": "person:host_a…/person_…", "kind": "person", "host_id": "host_a…", "person_id": "person_…",
     "agent_id": null, "name": null, "state": "joined", "added_by": null, "added_at": "RFC3339"},
    {"id": "agent:host_b…/agent_…", "kind": "agent", "host_id": "host_b…", "person_id": "person_…",
     "agent_id": "agent_…", "name": "claude-laptop", "state": "joined", "added_by": "person:host_a…/person_…", "added_at": "RFC3339"},
    {"id": null, "kind": "person", "host_id": null, "person_id": "person_…",
     "agent_id": null, "name": null, "state": "invited", "added_by": "person:host_a…/person_…", "added_at": "RFC3339"}
  ],
  "departed": [
    {"id": "agent:host_c…/agent_…", "kind": "agent", "reason": "left", "at": "RFC3339"}
  ]
}
```

- **Participant IDs.** An agent is `agent:HOST_ID/AGENT_ID`, the same text as the policy principal. A person is `person:HOST_ID/PERSON_ID`: the person, taking part from one host. Policy's `person:PERSON_ID` has no `/`, so the two never collide. An invited person has no ID until they join on one of their hosts.
- **State** of a participant is `inviting` (the home host has not yet had an answer from the target's host), `invited` (a person who has not joined), or `joined`. Departed participants move to `departed` with `reason` `left` or `removed`.
- **Names and labels.** `name` is the agent's name as its own host gave it in the invite answer. Each host displays labels it derives itself: the person label from its own network map for the participant's host, then `/NAME` for agents, for example `bob/claude-laptop`. A host never displays a person label the home host asserted.
- **Title** is optional, 0 to 200 bytes of UTF-8 without control characters. Without one, views show the participant labels.
- **State** of the conversation is `open` or `closed`. A closed conversation accepts no posts or roster changes, and stays readable.

### Who may do what

| Act | Who | How |
| --- | --- | --- |
| Create | Any local agent with directory access, through `conversation_start`; the person, through `peerspan conversation start` | The creating host becomes home. |
| Add a participant | The creator only, in slice 1 (decision 4) | Home host invites the target's host. |
| Remove a participant | The creator only | Home host bumps the roster. |
| Leave | Any participant, for itself. The owner of a host, for any of its local agents (`conversation leave ID --agent NAME`) | The participant's host tells home, and stops at once locally. |
| Join | An invited person, on one of their hosts | `peerspan conversation join ID`. Agents join on an authorized invite without a step (decision 5). |
| Close | The creator | Home host sets `state: closed` and pushes the roster. |
| Post | Any joined participant | Fan-out from the author's host (below). |

"The creator" is the creator participant: for an agent, any session of that agent on the home host; for a person, the person's CLI on the home host.

### Limits

| Limit | Value |
| --- | --- |
| Participants, `inviting`, `invited`, and `joined` together | 16, the creator included |
| Post content | 1 to 65,536 bytes of UTF-8, and within each recipient's `max_message_bytes` |
| Posts per author per conversation | 60 in any trailing hour, checked by the author's host and again by each recipient host |
| Open conversations a local agent or person is in | 200 |
| Pending person invites from one sender host, held on one host | 20 |
| Person invite lifetime | 7 days |
| Push retries per post and recipient | until 24 hours after the post, then the recipient's host fetches it (below) |
| `addressed_to` entries | up to 16 |

## Posts, fan-out, and order

### A post

A post is authored by exactly one participant, on that participant's host, so one host numbers all of an author's posts.

```json
{
  "post_id": "post_…",
  "conversation_id": "conv_…",
  "author": "agent:host_b…/agent_…",
  "seq": 7,
  "clock": 31,
  "roster_version": 3,
  "sent_at": "RFC3339",
  "content": "I can take the fix if someone reviews.",
  "addressed_to": ["person:host_a…/person_…"],
  "origin": {"agent_id": "agent_…", "session_id": "session_…"}
}
```

- **`post_id`** is `post_` followed by 16 random bytes in lowercase hex. The adapter or CLI generates it before calling the daemon, so a lost response can be retried with the same ID, as `send` does with `request_id`.
- **`seq`** counts the author's posts in this conversation from 1, assigned by the author's host when it persists the post.
- **`clock`** is a Lamport clock: one more than the highest `clock` of any post the author's host holds for the conversation. A host that stores a received post raises its own value to at least that post's `clock`.
- **`addressed_to`** is optional. Every joined participant still receives the post; the field tells the others it is not mainly for them (`meta.addressed` false). Empty or absent means everyone.
- **`origin`** is present for agent authors, as for adapter sends, and absent for person authors, as for owner CLI sends.

### Fan-out from the author's host

When a participant posts, its host, in one transaction:
1. assigns `seq` and `clock`, and stores the post;
2. creates one **outbound target** record per other joined participant in its current roster, each with its own retry schedule;
3. records `conversation.post_sent` activity.

It then sends one request per target: `POST /peer/v1/conversations/{id}/posts` (below). A target on the author's own host is delivered locally in the same transaction, with no peer request (decision 18). The milestone 5 retry schedule applies to each target: first retry 10 seconds after preparation, then 1 second doubling to 60 seconds with jitter, at most 4 automatic attempts at once per daemon, shared with nothing else. Retries stop at a final answer or at the request's `deadline` (decision 17). The `deadline` is 24 hours after `sent_at`, capped by the cited policy's `valid_until` or grant's `expires_at`, as for messages.

Each target's state, shown to the author and in views:

| State | Meaning |
| --- | --- |
| `sending` | Not yet confirmed. |
| `delivered` | The target's host accepted the post. This is host acceptance, not that a model read it. |
| `refused` | The target's host refused it for a final reason (`not_authorized`, `not_participant`, `closed`, `limit`, `invalid`). Not retried. |
| `unsupported` | The target's host predates conversations (404 on the route). |
| `stopped` | Retries stopped at the deadline. The target's host fetches the post when it next syncs, if the target is still a participant. |

There is no central copy. The author's host keeps its own posts; each recipient host keeps what it accepted. Two participants on one host share one stored copy, with one delivery each.

### Order

- **Display order** is by `(clock, author, seq)`, comparing `author` as bytes. Every host that holds the same posts shows them in the same order, and a reply always sorts after the post it answers, because its author's host had raised its clock past it.
- **Arrival order** can differ. A post that arrives late and sorts earlier is inserted in its place in views; the event for it is still emitted when it arrives.
- **Per-author order** is exact: `seq` has no gaps on the author's host.

### Gaps, duplicates, and offline participants

- **Per-target chain.** Each post request carries `prev_seq`: the `seq` of the author's previous post sent to this same target, or null for the first since the target joined. A recipient host keeps, per author and local target, the highest `seq` it holds with no gap before it. A post whose `prev_seq` it does not hold reveals a gap: the host stores the post and fetches the missing ones from the author's host at once.
- **Fetching.** `GET /peer/v1/conversations/{id}/posts?author=A&target=T&after=N&limit=M` on the author's host returns, in `seq` order, the author's posts that were sent to target T, for the host that holds T only. The recipient applies the acceptance checks of a pushed post, except the deadline: a fetched post carries no `deadline`, and step 1's deadline check and the deadline bounds of policy and grants do not apply to it. Every other check applies, with authorization evaluated against the recipient owner's current policy, grants, and block list at the time of the fetch, so a fetch never lets a post in that a push made now would be refused for any reason but its age.
- **Sync.** At startup, every 10 minutes for each conversation with a local joined participant, and after a roster change, a host first fetches the roster from home (`GET /peer/v1/conversations/{id}/roster`) and stores it if its `version` is higher, so a close or removal whose push expired while the host was offline still takes effect. It then asks each other participant host `GET /peer/v1/conversations/{id}/heads?target=T` for each local target T, and fetches whatever it lacks, then sends `acks` for what it stored. For a closed conversation it keeps doing so, per host, until that host has answered with a `roster_version` at or above the closing version (so it can author nothing more), everything it reported missing has been fetched, and its `acks` have been answered; a host that does not answer is asked again at every sync. It stops once every host that held a participant at the close has answered that way, or 30 days after it stored the closed roster, whichever comes first; a host still unanswered then is shown in the conversation view as `unsynced`. This is how a participant that was offline past the 24-hour retry window catches up. At most 4 syncs run at once per daemon, 5 seconds each.
- **Duplicates.** A recipient deduplicates by `(sender host, post_id, target)`: an identical repeat returns the original receipt; changed fields return 409 and never overwrite. The author's host refuses a second post with an existing `post_id` and different content with 409, and returns the existing post for an identical one.
- **Authenticity.** Posts are fetched only from their author's host, which the transport authenticates. A host never forwards another author's posts in slice 1.

### What each local participant may see

A host stores a post once, but two local participants may have different rights to it: a remote author may be authorized to reach one local agent and not another, and a participant who joined later was not a target of earlier posts. So every surface that shows posts to a local participant P shows only:
- posts P authored; and
- posts with an accepted inbound target record for P (or, for a local author, a local delivery to P).

This applies to `conversation_history`, the event window and catch-up, `pending_work` previews, summary counts (`unseen`, unread), `conversation show`, `watch`, and the local API. A post accepted for P but not yet handed to P's session is shown to P's session only after the handoff authorization recheck passes, as for messages; one that fails it is `blocked` for P and never shown to P. Conversation membership alone never exposes the host's stored copy.

The local API therefore takes a `participant` parameter on every read (`GET /v1/conversations/{id}`, `.../posts`, `.../events`), defaulting to this host's person participant; the CLI's `--as AGENT` selects an agent's view. Adapter routes always use the credential's agent.

## Membership changes

### Roster authority

The home host orders all roster changes and numbers them with `version`. It pushes each new roster to every participant host, joined, invited, or just departed, with `POST /peer/v1/conversations/{id}/roster`, retried like posts. A host accepts a roster only from the conversation's `home_host_id`, and only with a higher `version` than it holds. A host behind (a post carries a higher `roster_version` than it holds) fetches `GET /peer/v1/conversations/{id}/roster` from home and answers the post with 503 `unavailable` until it has it, so the author retries.

Messages never pass through the home host; only roster changes do. If the home host is offline, participants keep posting to each other with the roster they hold, and no one can join, be added, be removed, or close the conversation until it returns (decision 3).

### Adding

1. The creator names targets by address: `PERSON/AGENT` or `HOST_ID/AGENT` for an agent, resolved through the directory as `send --to` is; `person:LABEL`, `person:PERSON_ID`, or a bare label with no `/` for a person, resolved through the network map. Resolution errors are those of addresses: `unknown`, `ambiguous` with candidates.
2. **Agent target.** Home chooses an authorization for the creator to reach that agent with `message.append`, as sending by address does (self, then policy, then grant), and sends `POST /peer/v1/conversations/invites` to the target's host. The target's host checks exactly what it checks for a message from the creator (see [Access](#access)). On success it stores the conversation, makes the agent `joined`, queues a `conversation_roster` event (`added`) for the agent, and answers with the agent's `name`. Refusals return the message codes: 403 `forbidden`, 503 `unavailable`.
3. **Person target.** Home sends the same invite to **every** host bound to that person in the shared network. Each holds it as a pending invite (decision 7). The person runs `peerspan conversation join ID` on the host they want to take part from, which sends `POST /peer/v1/conversations/{id}/join` to home. Home checks that the invite is pending, that the requesting host is bound to that person in the network map, and adds `person:HOST_ID/PERSON_ID` as `joined`. The roster push tells the person's other hosts, which drop their pending copies. `peerspan conversation decline ID` removes the invite at home.
4. An invite whose answer is lost is retried by home with the same `(conversation_id, target)`; the target host deduplicates. Until an answer arrives the participant is `inviting`, and posts are not fanned out to it. After 10 minutes without an answer, home drops it from the roster and reports `unanswered`.
5. Home commits each change as a new roster version and pushes it.

A late joiner receives posts sent after the roster that made it `joined` reached the author's host (decision 8). Its first event carries the creator's optional invite `note`, up to 4,096 bytes.

### Leaving, removal, and closing

- **Leave.** The participant's host marks it departed locally at once, refuses further posts to it with 403 `not_participant`, stops its deliveries, and sends `POST /peer/v1/conversations/{id}/leave` to home, retried until home answers. Home removes it and pushes the roster.
- **Remove.** Home removes the participant and pushes the roster, including to the removed participant's host, which then refuses posts to it as above.
- **Close.** Home sets `state: closed` and pushes the roster. Hosts refuse new posts with 409 `closed` once they hold it. A host that missed the push learns of it at its next sync, which always fetches the roster first, and still fetches the posts sent to its participants before the close (step 5 of post acceptance).
- **Races.** A post sent while its author was being removed is accepted by hosts that had not yet received the new roster, and refused by those that had. Views show what each host holds; nothing is retracted.

## Access

Each recipient's host decides, for each post and each local recipient, using its own owner's policy, exactly as for a message. Conversation membership only narrows: a host accepts a post only when the author is a joined participant in the roster it holds, the target is a joined local participant, and the conversation is open, **and** ordinary authorization passes.

| Recipient | What authorizes a post from author X | Recheck |
| --- | --- | --- |
| A local agent | `message.append` from X, under the recipient owner's policy, a grant, or self access, cited by X's host as for messages (decision 1). An agent author's `origin` is matched against `agent:` principals. A person author has no `origin` and matches as an owner CLI send does. Size, deadline, the connected state (503 when it can recover), and the block list apply. | At acceptance, and again at handoff to a session, as for messages. |
| A local person | The person joined this conversation on this host. The block list applies to X's host and X's person. | At acceptance. |

- **No transitive access** (decision 2). If Alice's agent may reach Bob's and Carol's agents, that does not let Bob's agent reach Carol's. A post from Bob's agent to Carol's agent needs Carol's owner to allow Bob (or Bob's agent). Without it, that target is `refused` with `not_authorized`, Bob sees which participant did not receive it, and everyone else still does. `conversation_start` and `conversation add` report, per new participant, which existing participants can reach it and which it can reach, as far as the home host's directory knows, so the gap is visible before anyone posts.
- **Policy v2 and actions.** No new policy action in slice 1: conversations use `message.append`, so no policy format or coordinator change is needed (decision 1).
- **Revocation mid-conversation.** A recipient owner who denies or blocks X makes the recipient's host refuse X's later posts (`refused`, `not_authorized`), and hold X's undelivered posts as `blocked` at handoff, as for messages. Posts already handed to a session are not withdrawn. X stays in the roster; the owner can also remove their own agent with `conversation leave ID --agent NAME`.
- **The home host.** Adding someone is authorized as the creator messaging them. The home host can remove participants or close the conversation, which is the creator's authority, but it cannot make any host accept a post its owner did not authorize, or attribute a post to another author.
- **Approvals.** Per-call approval (capabilities slice 3) does not apply to posts. A post asking the person to approve something is text; agents still cannot approve.

## Peer routes

All use the existing QUIC peer transport, the per-request re-authentication, the 1 MiB body limit, and strict JSON (unknown fields and nulls are 400). Any host not holding the state a route names gets 404.

| Route | From → to | Body / query | Behavior |
| --- | --- | --- | --- |
| `POST /peer/v1/conversations/invites` | home → target host | `{conversation_id, roster, target, adder, origin, note, policy \| grant_id \| self}`, where `target` is `{kind: "agent", agent_id}` or `{kind: "person", person_id}` and `adder` the adding participant's ID | Agent: authorize, store, join; 200 `{state: "joined", name}`. Person: hold pending; 200 `{state: "invited"}`. Idempotent by `(home, conversation_id, target)`. 429 `limit` past 20 pending person invites from this sender. |
| `POST /peer/v1/conversations/{id}/roster` | home → participant hosts | `{roster}` | Store if higher; 200 `{version}` with the version held. 403 from anyone but home. |
| `GET /peer/v1/conversations/{id}/roster` | participant host → home | none | The current roster, for hosts holding a current, invited, or departed participant. |
| `POST /peer/v1/conversations/{id}/join` | person's host → home | `{person_id}` | Join as above; 200 `{roster}`. 404 when no invite is pending. |
| `POST /peer/v1/conversations/{id}/leave` | participant host → home | `{participant}` | Leave, or decline a pending invite with `person:PERSON_ID`; 200 `{roster}`. Idempotent. |
| `POST /peer/v1/conversations/{id}/posts` | author host → target host | `{post, target, prev_seq, deadline, policy \| grant_id \| self}` | Acceptance checks below; 200 receipt `{post_id, target, receiver_host_id, accepted_at}`. |
| `GET /peer/v1/conversations/{id}/heads?target=T` | target host → author hosts | none | `{roster_version, authors: [{author, last_seq}]}`: the roster version this host holds, and for each author on this host the last `seq` sent to T. Only to the host holding T. |
| `GET /peer/v1/conversations/{id}/posts?author=A&target=T&after=N&limit=M` | target host → author host | none | Posts by A sent to T after `seq` N, in order, up to M (1 to 100, default 50) or 900,000 encoded bytes. Only to the host holding T. Acknowledges nothing; see `acks`. |
| `POST /peer/v1/conversations/{id}/acks` | target host → author host | `{target, acks: [{author, through_seq}]}` | Sent after the target host has stored fetched posts, retried until answered. The author's host marks every target record of those authors' posts to T up to `through_seq` `delivered`. 200 `{acked}`. Idempotent; only from the host holding T. |

**Post acceptance**, in order:
1. **Shape:** IDs, sizes, `deadline` in the future and at most 24 hours plus 1 minute of skew ahead; otherwise 400 `invalid`. Fetched posts have no `deadline` and skip that part (see Gaps).
2. **Author's host:** `post.author`'s host is the authenticated sender; otherwise 403 `forbidden`.
3. **Repeat:** a request whose `(sender host, post_id, target)` this host already accepted returns the saved receipt when its fields are identical, and 409 `{code: "conflict"}` when they differ, before any later step. An identical retry therefore never meets the roster, closed, or rate checks, and consumes no rate allowance: the post was accepted once, and the retry adds nothing.
4. **Roster:** unknown conversation, or a `roster_version` above the one held, fetches the roster from home and answers 503 `unavailable` meanwhile. The target not joined here, or the author not joined in the held roster, is 403 `{code: "not_participant"}`.
5. **Open:** a closed conversation is 409 `{code: "closed"}`, except for a post whose `roster_version` is lower than the version that closed it: its author's host sent it before it knew of the close, so it is accepted, pushed or fetched, and every other check still applies. An author's host never authors a post in a conversation it holds as closed.
6. **Authorization:** as in [Access](#access), with the message error codes, including 503 for a recoverable connected state or a policy behind the cited version.
7. **Rate:** more than 60 accepted posts from this author in this conversation in the trailing hour is 429 `{code: "limit"}`. Only first acceptances count.
8. **Persist:** the post (stored once per host by `post_id`), the inbound target record that later repeats are checked against, any delivery to a local agent, and `conversation.post_received` activity commit together.

The sender records 400, 403, 404, 409, and 429 as final (`refused`, or `unsupported` for a 404 from a host without the route), and retries anything else.

## Agent tools

The shared Node adapter adds five MCP tools, so Claude Code, Codex, and OpenCode get the same ones. They require the credential's `directory` access, as addressing does today; without it each refuses with 403 `no_directory` and the existing text (decision 15).

| Tool | Input | Behavior |
| --- | --- | --- |
| `list_conversations` | `{}` | `GET /adapter/v1/conversations`. The agent's open conversations, and closed ones with unseen posts: `{conversations: [SUMMARY]}`. |
| `conversation_start` | `{participants, title, content, note}` | `POST /adapter/v1/conversations`. Creates a conversation with this agent as creator, invites each participant, and posts `content` if given. Returns the view, with each invite's outcome. |
| `conversation_post` | `{conversation_id, content, addressed_to, post_id}` | `POST /adapter/v1/conversations/{id}/posts`. Returns `{post, targets}` as soon as the post is stored; does not wait for delivery. |
| `conversation_history` | `{conversation_id, before_post_id, limit}` | `GET /adapter/v1/conversations/{id}/posts`. Older posts in display order, with the participant list. |
| `conversation_manage` | `{conversation_id, action, participant}` | `POST /adapter/v1/conversations/{id}/manage`. `action` is `add`, `remove`, `leave`, or `close`; `participant` is required for `add` and `remove`. |

**Input schemas.** Each has `additionalProperties: false`; invalid arguments return a tool error naming the tool.
- `participants`: array of 1 to 15 strings, each at most 256 characters: `PERSON/AGENT`, `HOST_ID/AGENT`, `person:LABEL`, `person:PERSON_ID`, or a bare person label.
- `conversation_id`: pattern `^conv_[0-9a-f]{32}$`.
- `content`: string, 1 to 65,536 characters (the daemon checks bytes). `note`: string, at most 4,096 characters. `title`: string, at most 200 characters.
- `addressed_to`: array of up to 16 participant IDs or labels as shown in the view.
- `post_id`: pattern `^post_[0-9a-f]{32}$`, optional; generated by the adapter's proxy when absent, as `send` generates `request_id`, so it is known even if the response is lost.
- `before_post_id`: optional post ID; `limit`: integer 1 to 50, default 20.

**Summary** `{conversation_id, title, state, home_host_id, participants: [{id, label, kind, state, you}], unseen, last_post_at, creator}`, where `you` marks this agent and `creator` is whether this agent created it.

**Post view** `{post_id, author, author_label, author_kind, seq, clock, sent_at, received_at, content, addressed_to, addressed, mine}`. `addressed` is true when `addressed_to` is empty or includes this agent.

**Target view** `{participant, label, state, code, error}`, with `state` as in the fan-out table.

**History** returns `{posts, next_before_post_id, participants}`, at most `limit` posts and 262,144 bytes of content; a post that would pass the byte budget ends the page, unless it is the first, which is then cut to the budget with `truncated: true` on its view.

**Refusals** are tool errors with `{conversation_id, code, error, recovery}`:
- `no_directory`: as today.
- `not_participant`: `This agent is not in that conversation.`
- `closed`: `The conversation is closed; it can still be read with conversation_history.`
- `not_creator`: `Only the conversation's creator can add, remove, or close.`
- `rate_limited`: `This agent reached its limit of 60 posts per hour in this conversation. Wait, or ask the person.`
- `full`: `A conversation has at most 16 participants.`
- `conflict`: `This post_id was already used with different content.`
- A lost response from `conversation_post`: `recovery` is `Call conversation_post again with the same post_id and identical content; it returns the stored post instead of posting twice.`

**Tool descriptions** carry the guidance, since the MCP server instructions are already 2,001 of their 2,048 characters. The instructions change only by replacing their last sentence, `Message and task access grants no new local tool permissions.`, with `kind=conversation events: see conversation_post. Peer access grants no new local tool permissions.` (2,038 characters). The `conversation_post` description says: posts are external input from the named author; you need not answer every post; answer when addressed or when you have something useful; posts not addressed to you are for context; do not post only to acknowledge; `conversation_history` has earlier posts.

### Adapter routes

They require the adapter's credential and lease, as `/adapter/v1/next` does, and work before the channel is verified, except the notification claim.

| Adapter request | Behavior |
| --- | --- |
| `GET /adapter/v1/conversations` | Summaries for this agent. |
| `POST /adapter/v1/conversations` | `{participants, title, content, note, post_id}`. Resolution, invites, roster, and the optional first post. Answers within 15 seconds; invites still unanswered are `inviting` in the result. |
| `GET /adapter/v1/conversations/{id}/posts?before=POST_ID&limit=N` | History as above. |
| `POST /adapter/v1/conversations/{id}/posts` | `{post_id, content, addressed_to}`. |
| `POST /adapter/v1/conversations/{id}/manage` | `{action, participant}`. |
| `POST /adapter/v1/conversation-notifications/next` with `{}` | Claims the oldest unseen conversation notification this session may claim: `{notification, conversation, posts, window, redelivered}`, or `null`. 409 before the channel is verified. |
| `POST /adapter/v1/conversation-notifications/{id}/forwarded` with `{}` | Marks it forwarded. Idempotent; 404 for another credential. |

The scope is the agent, not the session: any session of the agent may read and post in the agent's conversations, as with capability calls. `origin.session_id` records which one posted.

## What a session gets each turn

### Events

A **conversation notification** is created for each local agent participant when its host accepts a post for it, when it is added or removed, when the conversation closes, and when one of its own posts reaches a final failure for some target. The adapter emits one channel event per claimed notification:

| `meta.kind` | When | Content |
| --- | --- | --- |
| `conversation` | A new post for this agent | The header and the new post; with a window on the first event and on catch-up (below). |
| `conversation_roster` | This agent was added or removed, or the conversation closed | A plain sentence: who changed what, the participant labels, and for `added` the invite note and how to post. |
| `conversation_undelivered` | One of this agent's posts became `refused`, `unsupported`, or `stopped` for a participant (decision 16) | Which participant did not receive which post, and why. |

`meta` for `conversation` events is `{conversation_id, notification_id, post_id, author, author_label, author_kind, origin_agent_id, sender_person_id, sender_person, seq, clock, addressed, catch_up, unseen, session_id, redelivered}`. Claude Code channel meta values are strings, so booleans and numbers are sent as their JSON text and nulls are omitted, as for other events.

### Content and window

Recommended (decision 10): the new post only, with a short header, because a live session already has the earlier events in its context. A window of earlier posts comes only when the session lacks them: on the **first** event of a conversation for this session, and on **catch-up** after redelivery.

```text
Peerspan conversation conv_3f9a… "Flaky checkout test" (open)
Participants: alice (person), bob/claude-laptop (you), carol/codex-box
Earlier posts (last 4 of 11; conversation_history has the rest):
[alice 10:02] Our checkout test fails one run in twenty.
[carol/codex-box 10:02] The retry loop in checkout_test.go hides the race; see line 88.
[bob/claude-laptop 10:03] (you) I can take the fix if someone reviews.
[alice 10:04] Go ahead.
New post:
[carol/codex-box 10:05, to bob/claude-laptop] I'll review. Push a branch when ready.
```

- **Window size:** up to 10 earlier posts and 16,384 bytes of their content, newest kept; each earlier post is cut at 2,048 bytes with `[cut: N bytes; conversation_history has it]`. The new post is never cut.
- **Labels** in brackets are written by the adapter from the daemon's view, never taken from post content, and the presentation marks the content as peer-authored, as for other events.
- **More history:** `conversation_history` with `before_post_id`.
- **Catch-up:** when a new session claims returned notifications, the daemon coalesces each conversation's returned post notifications into one `conversation` event with `meta.catch_up` true, the newest returned post as the new post, the others in the window, and `unseen` counting all of them.

### Seen, redelivery, and pending work

These follow [live delivery slice 2](live-delivery-contract.md#slice-2-seen-redelivery-adoption-and-pending-work), with one difference: a post asks for no answer, so nothing is "owed".
- **Seen.** A conversation notification is seen when the session that holds it calls `conversation_post`, `conversation_history`, or `conversation_manage` in that conversation (all its held notifications for the conversation up to that moment), or `mark_seen` with the notification's post ID or the conversation ID. `mark_seen` accepts `post_` and `conv_` IDs beside the existing kinds.
- **Redelivery.** Unseen notifications of an ended authorization return to the agent's queue and go to its next verified session, coalesced as catch-up, at most 3 times, as for deliveries. Past the limit they stay unseen and are not offered again.
- **Late arrivals.** A post that arrives while the agent has no verified session waits, unclaimed, for the next one, with `redelivered` false.
- **Revocation.** A post whose author lost authorization before handoff is `blocked`, as for messages, and is never offered.
- **`pending_work`** gains `conversations`: `[{conversation_id, title, unseen, addressed, latest: {post_id, author_label, preview}}]`, oldest first by the earliest unseen post, for conversations with unseen notifications this session holds or could claim. `peerspan session pending --hook` adds `follow each conversation with conversation_history` to its text.

## People from the CLI

A person takes part from one host bound to them. Their posts carry no `origin`. Their unread state is a read cursor, since no session is involved.

| CLI | Local API | Behavior |
| --- | --- | --- |
| `conversations [--all] [--invites] [--json]` | `GET /v1/conversations?state=open\|all` | Open conversations (with `--all`, closed ones too) of the person and of this host's agents, newest activity first: ID prefix, title, participants, unread count for the person, last activity. `--invites` lists pending person invites. |
| `conversation start TARGET... [--title T] [--message TEXT] [--note TEXT] [--as AGENT] [--network ID]` | `POST /v1/conversations` | Creates a conversation with the person as creator, or with a local agent as creator under `--as` (so an owner can try what the agent will see). Prints the view with each invite's outcome. |
| `conversation show ID [--limit N] [--before POST] [--json]` | `GET /v1/conversations/{id}`, `GET /v1/conversations/{id}/posts` | Header, participants with state, and the last N posts (default 20), with targets not `delivered` listed under the person's own posts. Advances the person's read cursor to the newest post shown. |
| `conversation say ID TEXT [--to PARTICIPANT ...] [--post POST_ID]` | `POST /v1/conversations/{id}/posts` | Posts as the person. `--to` fills `addressed_to`. Prints the post and its targets. |
| `conversation watch [ID]` | `GET /v1/conversations/events?after=N&wait=25` | Prints new posts and changes as they arrive, for one conversation or all, until interrupted. Advances the read cursor for posts printed. |
| `conversation add ID TARGET` / `remove ID PARTICIPANT` / `close ID` | `POST /v1/conversations/{id}/manage` | Creator only (the person, or with `--as AGENT`, that agent). |
| `conversation join ID` / `decline ID` | `POST /v1/conversations/{id}/join`, `/decline` | Accept or decline a pending person invite on this host. |
| `conversation leave ID [--agent NAME]` | `POST /v1/conversations/{id}/leave` | The person leaves; with `--agent`, the owner takes that local agent out of the conversation. |
| `conversation read ID` | `POST /v1/conversations/{id}/read` | Marks everything read for the person. |
| `conversation forget ID [--yes]` | `DELETE /v1/conversations/{id}` | Deletes this host's copy of a conversation no local participant is in any longer (left, removed, or closed). Asks for confirmation at a terminal. On the home host it deletes posts, receipts, and notifications but keeps the roster and its outbound pushes, so the home host still serves `GET .../roster`, joins, leaves, and roster reconciliation to the remaining participants; the roster is small and is never deleted while the home host exists. |

`ID` is the full ID, or `conv_` plus at least 6 hex digits that match exactly one local conversation; otherwise 404, or 409 `ambiguous` with the candidates. A person on a host without a bound person cannot take part: `start`, `say`, and `join` refuse with `This host is not bound to a person; conversations need one (peerspan join).`

Readable output of `conversation show`:

```text
conv_3f9a1c… "Flaky checkout test"   open   4 participants
  alice (you)   bob/claude-laptop   carol/codex-box   dave (invited)

10:02  alice              Our checkout test fails one run in twenty.
10:02  carol/codex-box    The retry loop in checkout_test.go hides the race; see line 88.
10:03  bob/claude-laptop  I can take the fix if someone reviews.
10:04  alice              Go ahead.
         not yet received by carol/codex-box (sending)
```

Content from other participants is printed with control characters and terminal escape sequences escaped, as the approval proposal requires for caller text.

**Status.** `GET /v1/status` gains `conversations: {open, unread, invites}` for the person, and one attention item, `conversation_invites`, while a person invite is pending: subject the count, command `peerspan conversations --invites`. Its number follows whatever capabilities slice 3 adds when this merges.

## Relation to messages and tasks

| Today | With conversations |
| --- | --- |
| `send` + `reply`: one request, one bounded answer, no follow-up | Unchanged. Still the way to ask one agent one thing (decision 12). |
| A reply event cannot be answered, to prevent loops | Conversations are where back-and-forth goes. Loops are bounded by the per-author rate limit, `addressed_to`, and tool guidance instead. |
| Message and reply records | Not migrated or converted. No table changes. |
| Tasks with progress and results | Unchanged. A conversation may name a task it is about (`about: {peer_host_id, task_id}`), shown in views and events only; it grants nothing (decision 13). |

A task's own discussion thread, where the submitter and the receiving agent talk about one task under the task's authorization, is proposed for a later slice (decision 13). Turning a message into a conversation ("continue this as a conversation") is also later; the agent can start a conversation with the sender today, if it may reach the sender.

## What a later UI needs

The local API above is the whole surface; a UI served by the daemon on loopback, a tray app, or a TUI uses it as the CLI does, with no new peer protocol.

| Need | Provided by |
| --- | --- |
| Conversation list with unread counts | `GET /v1/conversations` |
| Participant list with state and reachability | `GET /v1/conversations/{id}`: roster, per-participant labels, and for each pair the home host's directory view of who can reach whom |
| History with paging | `GET /v1/conversations/{id}/posts?before=POST&after=POST&limit=N`, in display order |
| Per-post delivery | The target views on the person's own posts |
| Unread state | Read cursor per local participant; `POST /v1/conversations/{id}/read` |
| Live updates | `GET /v1/conversations/events?after=N&limit=M&wait=S`: a local event log `{sequence, kind, conversation_id, post_id, participant, at}`, with `kind` `post_received`, `post_sent`, `target_changed`, `roster_changed`, `invited`, `read_changed`. `wait` holds the request up to 25 seconds until something arrives. Kept for 30 days or 10,000 events. |
| Posting, invites, membership | The same routes as the CLI |

A UI would also want approvals in the same place; those come from the capabilities slice 3 approval routes, not from here.

## Persistence

The next shared schema version (19 when written; whichever proposal merges first takes it, and the others renumber, as the capabilities slice 3 proposals say) adds:

```sql
CREATE TABLE conversations (id TEXT PRIMARY KEY, home_host TEXT NOT NULL, roster_version INTEGER NOT NULL, state TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE conversation_posts (conversation_id TEXT NOT NULL REFERENCES conversations(id), post_id TEXT NOT NULL, author TEXT NOT NULL, seq INTEGER NOT NULL, clock INTEGER NOT NULL, local_seq INTEGER NOT NULL UNIQUE, record TEXT NOT NULL, PRIMARY KEY(conversation_id, post_id), UNIQUE(conversation_id, author, seq));
CREATE INDEX conversation_posts_order ON conversation_posts(conversation_id, clock, author, seq);
CREATE TABLE conversation_targets (conversation_id TEXT NOT NULL, post_id TEXT NOT NULL, target TEXT NOT NULL, direction TEXT NOT NULL, peer TEXT NOT NULL, prev_seq INTEGER, state TEXT NOT NULL, next_attempt_at TEXT, record TEXT NOT NULL, PRIMARY KEY(conversation_id, post_id, target, direction));
CREATE TABLE conversation_invites (conversation_id TEXT NOT NULL, person_id TEXT NOT NULL, home_host TEXT NOT NULL, expires_at TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(conversation_id, person_id));
CREATE TABLE conversation_roster_outbound (conversation_id TEXT NOT NULL, peer TEXT NOT NULL, kind TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(conversation_id, peer, kind));
CREATE TABLE conversation_notifications (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, kind TEXT NOT NULL, post_id TEXT, agent_id TEXT NOT NULL REFERENCES agents(id), session_id TEXT REFERENCES sessions(id), record TEXT NOT NULL, seen_at TEXT, redeliveries INTEGER NOT NULL DEFAULT 0, returned_at TEXT);
CREATE TABLE conversation_reads (conversation_id TEXT NOT NULL, participant TEXT NOT NULL, read_through INTEGER NOT NULL, PRIMARY KEY(conversation_id, participant));
CREATE TABLE conversation_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, record TEXT NOT NULL);
```

- **`conversation_targets`** holds, for authored posts (`direction` `out`), each target's delivery state and retry schedule, and for received posts (`in`), the receipt used for deduplication. Its `peer` is the other host.
- **`conversation_notifications`** columns `seen_at`, `redeliveries`, and `returned_at` behave as for `task_update_notifications`.
- **`conversation_reads.read_through`** is a `local_seq`.
- **Retention.** Posts and rosters are kept until the owner runs `conversation forget` (decision 14). A home host keeps the roster row even then, as the authority the other participants still rely on. Inbound receipts are kept as message receipts are.
- **Activity** kinds: `conversation.created`, `conversation.roster_changed`, `conversation.post_sent`, `conversation.post_received`, `conversation.post_refused`, `conversation.closed`. The subject is `CONVERSATION_ID` or `CONVERSATION_ID/POST_ID`. Activity never holds content.
- **Migration** creates the tables and index and sets the version in one transaction. Older binaries reject the new version. No existing record changes.

## Compatibility with older hosts

- **Wire.** All peer routes are new. An older host answers 404, so an invite to it fails with `unsupported` (`HOST is running a Peerspan without conversations`) and nothing is added; a post to a participant whose host was downgraded becomes `unsupported` for that target.
- **No policy change** in slice 1 (decision 1), so coordinators and the policy test vectors are unchanged.
- **Messages and tasks** keep their routes, records, and tools.
- **Adapters** ship with the daemon, so a host's adapter and daemon always match; mixed versions occur only between hosts, which the 404 rule covers.
- **Directory.** Unchanged. A host learns that a peer lacks conversations only from the 404.

## Security

- **Content is untrusted.** Posts are peer-authored text in the agent's context, now several authors at once. The adapter writes every author label and the header; the content is presented as peer content, as other events are. A post cannot claim to be from another participant: its author must be the authenticated sending host's participant, and posts are fetched only from the author's host.
- **Equivocation.** Posts are not signed, so an author's host could send different text to different recipients. Each host shows what it received. Signed posts (later) would let participants compare.
- **The home host** is trusted for membership only. It can remove people or close the conversation, but cannot widen anyone's access or forge posts.
- **Spam and loops.** Receiving hosts cap posts per author per conversation, cap pending person invites per sender host, and apply the block list. Agents are told they need not answer every post.
- **Owner control.** An owner can always take their agent out (`conversation leave --agent`), and deny or block a sender, enforced locally at once.
- **The local trust boundary** is unchanged: adapter credentials do not isolate a process running as the same OS user.

## Interactions with capabilities slice 3

Noted only; each slice 3 item designs its own side.
- **Per-call approval (item B).** Its `approval_request` notice is a separate event kind delivered to the capability's source agent; conversation events never carry approvals, and a post asking for approval is just text. Both add an adapter work route that answers 409 before the channel is verified, and both add an attention item, whose numbers are fixed at merge. A later UI shows approvals and conversations side by side from their own routes.
- **Sharing with one agent (item C).** Its `PERSON/AGENT` parsing for `--with` (one `/` means an agent) matches how conversation participants are named, and bare labels mean persons in both. Its new lookup route resolves agents the caller cannot reach; conversations do not need it, because every participant must be reachable with `message.append` anyway. `agent:` principals authorize agent-authored posts as they do messages, and `call --from-agent` parallels `conversation start --as AGENT`.
- **Remote MCP and OAuth (item A), resource bounds and `gh` (item D).** No direct interaction. A conversation is not a capability and has no operations to bound.
- **Schema and status numbers.** Every one of these proposals adds a schema version and possibly an attention item; numbers are assigned in merge order.

## Slices

1. **Conversations (first slice).** Everything above: the object and home-host roster, creator-only membership changes, leave and close, fan-out with per-target retry, per-author `seq` and Lamport `clock`, gap fetch and sync, `message.append` authorization per recipient, person participants on one host with explicit join, local participants on the same host, the five agent tools and three event kinds with windowed context, live delivery integration, the CLI, the local API and event log, status, and no history for late joiners. Conformance in `conformance/conversations.py` across all four Go/Rust pairings with `--node`, and a live run with Claude Code, Codex, and OpenCode agents and one person in one conversation across two machines.
2. **History and threads.** History for late joiners under whichever rule decision 8 picks; task discussion threads; continuing a message as a conversation; any participant adding (if decision 4 allows).
3. **Later.** Signed posts and fetching history from any participant; moving the home host; a person on several hosts; files in conversations; a UI using the local API.

### Implementation size of slice 1

Rough, including tests in each language:
- **Go:** about 2,800 to 3,500 lines: tables and migration, roster and home-host logic, invites and joins, fan-out and retry, acceptance checks, gap fetch and sync workers, notifications with live delivery rules, local routes, CLI with readable output and escaping, the event log, status.
- **Rust:** about the same, 2,800 to 3,500 lines.
- **Shared Node adapter:** about 500 to 700 lines: five tools and schemas, `post_id` generation in the proxy, the notification claim loop and three event kinds with the header and window, presentation titles, `mark_seen` and `pending_work` changes, the instructions edit.
- **Conformance:** about 1,500 to 2,000 lines in a new `conformance/conversations.py` (three-host topologies, partial authorization, lost responses, offline recipient past 24 hours, gap fetch, roster races, migration), plus a live script `conformance/live_conversations.py`.
- **Contract text:** a new `docs/conversations-contract.md`.

## Owner decisions needed

1. **Which permission authorizes a post.**
   - (a) `message.append`, unchanged: whoever may message an agent may talk to it in a conversation.
   - (b) A new policy action `conversation.post`, separate from messages.
   - (c) A new action that `message.append` implies, so owners can later grant conversations without messages.
   - **Recommendation: (a).** A post is a message with context; (b) and (c) change the policy format, test vectors, and coordinators for a distinction no one has asked for yet.
2. **Whether being in a conversation lets participants reach each other.**
   - (a) No: each recipient's policy governs every author; unreachable pairs are shown and their posts refused for that target.
   - (b) Yes: an authorized invite implies permission from every participant.
   - (c) Opt-in: an owner rule letting "participants of conversations my agent is in" post to it.
   - **Recommendation: (a).** (b) lets one person introduce strangers to someone else's agent, against the owner-decides model; (c) can come later.
3. **Who orders membership changes.**
   - (a) The creator's host, as home, for the conversation's life.
   - (b) Any participant's host, with a merged roster (add and remove sets) and no single authority.
   - (c) (a), with handing home to another participant later.
   - **Recommendation: (a) now, (c) later.** One authority makes adds and removes simple and auditable; posting does not depend on it.
4. **Who may add and remove participants.**
   - (a) The creator only.
   - (b) Any participant may add; only the creator removes.
   - (c) Any participant may add or remove.
   - **Recommendation: (a) in slice 1.** It keeps "who brought this person in" obvious; (b) can follow once rosters are seen in use.
5. **Whether an agent must accept being added.**
   - (a) No: an invite that passes the agent owner's `message.append` check joins it, and it can leave.
   - (b) The agent accepts with a tool before posts arrive.
   - (c) The agent's owner accepts.
   - **Recommendation: (a).** The owner already allowed this sender to message the agent; an extra model turn adds cost, not control.
6. **How people take part.**
   - (a) A person takes part from one bound host, after an explicit `join`, and receives posts from any joined participant not blocked.
   - (b) As (a), but posts to a person also need a policy rule naming the author.
   - (c) People can read and post, but cannot be invited; only agents are participants in slice 1.
   - **Recommendation: (a).** Joining is the person's own consent, and they can leave or block; policy rules today name agents, not people.
7. **Who may invite a person.**
   - (a) Any member host of a shared network that is not blocked, held as pending, at most 20 per sender, expiring after 7 days.
   - (b) Only principals the person lists in a new local allow list.
   - **Recommendation: (a).** An invite carries only a title and note, and nothing reaches the person until they join.
8. **What a late joiner sees.**
   - (a) Posts from when they joined, plus the inviter's note.
   - (b) Earlier posts, each served by its author's host only if that author's owner allows history for late joiners (a setting per conversation or per host).
   - (c) All earlier posts, by default.
   - **Recommendation: (a) in slice 1, (b) in slice 2.** Earlier posts were written for the earlier participants; (c) would share them without their authors' consent.
9. **How posts are ordered.**
   - (a) Lamport clock plus per-author `seq`, display order `(clock, author, seq)`.
   - (b) Vector clocks, showing concurrency explicitly.
   - (c) Each host's arrival order.
   - **Recommendation: (a).** Same order on every host once complete, replies after what they answer, and a fixed-size field; (b) grows with participants for little visible gain.
10. **What a receiving session gets each turn.**
    - (a) The new post with a header, and a window (10 posts, 16 KiB) only on the first event and on catch-up.
    - (b) A window with every event.
    - (c) The new post only, always.
    - **Recommendation: (a).** The session already holds earlier events in its context; repeating them each turn costs tokens, while (c) leaves a new session lost.
11. **How to bound back-and-forth between agents.**
    - (a) 60 posts per author per conversation per hour, `addressed_to`, and "you need not answer every post" guidance; not counted against `max_sends_per_hour`.
    - (b) As (a), and also counted against `max_sends_per_hour`.
    - (c) Turn-taking: one post per author until someone else posts.
    - **Recommendation: (a).** It stops runaway loops without throttling a busy legitimate conversation; (c) breaks multi-step work.
12. **Messages and replies.**
    - (a) Keep both unchanged beside conversations; no migration.
    - (b) Reimplement messages as two-participant conversations and migrate records.
    - **Recommendation: (a).** One-shot ask-and-answer stays useful and tested; migration risks working behavior for no user gain.
13. **Tasks.**
    - (a) Slice 1: an optional, informational `about` task link. Slice 2: a task thread between submitter and receiver, authorized by the task itself.
    - (b) Task threads in slice 1.
    - (c) No link between conversations and tasks.
    - **Recommendation: (a).** Threads need their own authorization rule (like replies to accepted work), which deserves its own review.
14. **How long posts are kept.**
    - (a) Until the owner runs `conversation forget`.
    - (b) Pruned automatically, for example 90 days after the last post.
    - **Recommendation: (a)** for now, matching messages, which have no deletion; revisit with the UI.
15. **Which agents get the conversation tools.**
    - (a) Sessions with directory access (every `attach` session), refusing otherwise with `no_directory`.
    - (b) A new `attach --conversations` opt-in, like `--calls`.
    - **Recommendation: (a).** Conversations use the same addressing and authorization as `send --to`; a second prompt adds friction without new reach.
16. **Telling an author about undelivered posts.**
    - (a) One `conversation_undelivered` event per final failure.
    - (b) Nothing; failures show only in views and `conversation_history`.
    - **Recommendation: (a).** An agent should know a participant missed its post; successes stay silent.
17. **How long the author's host keeps pushing.**
    - (a) 24 hours, then the recipient fetches on sync.
    - (b) 1 hour, as agent sends.
    - **Recommendation: (a).** Conversations last longer than one request, and sync covers anything later.
18. **Participants on the same host.**
    - (a) Allowed: a post to a local participant is delivered locally, under self access.
    - (b) Refused with `local`, as sends by address are.
    - **Recommendation: (a).** A person with Claude Code and Codex on one laptop is the simplest useful conversation, and nothing crosses a trust boundary.
19. **Closing.**
    - (a) The creator can close; a closed conversation is read-only.
    - (b) No close; only leaving.
    - **Recommendation: (a).** It gives the design's "close" operation and a clear end for agents.
20. **Command names.**
    - (a) `peerspan conversations` and `peerspan conversation start|show|say|watch|add|remove|join|decline|leave|close|read|forget`, in the root help beside `send` and `task`.
    - (b) Shorter top-level verbs, such as `peerspan talk` and `peerspan say`.
    - **Recommendation: (a).** It matches `capability` and `calls`, and stays clear as subcommands grow.
21. **First slice scope.**
    - (a) Agents and people together, as in [Slices](#slices).
    - (b) Agents only first; people from the CLI in the next slice.
    - **Recommendation: (a).** The CLI is the only human surface today, and people in the conversation are the multiplayer case worth proving first.
