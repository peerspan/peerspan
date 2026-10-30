# Conversations

Status: **Accepted on 2026-10-25; refreshed on 2026-10-30 for coordinator-free networks.** The owner accepted every recommendation under [Owner decisions needed](#owner-decisions-needed), recorded as [CONV-1 to CONV-21](decision-log.md#conv-conversations-2026-10-25) in the owner decision log. The work was then held until the coordinator-free networks landed. On 2026-10-30 the owner made conversations the next feature ([DEC-OWN11](decision-log.md#dec-own11-next-feature-after-the-coordinator-free-work-2026-10-30)). This revision changes every reference and mechanism to match `main` today ([What changed since acceptance](#what-changed-since-acceptance)) and keeps every accepted decision. Where an accepted decision no longer fits as written, it is not changed here: it is listed under [Open questions after the coordinator-free work](#open-questions-after-the-coordinator-free-work) (CQ-1 to CQ-4) for the owner. The design is not yet implemented; `docs/conversations-contract.md` is written by the implementing PRs.

This is launch-plan track 3, "Conversations" (`docs-internal`, `docs/launch-plan.md`). The owner tabled it on 2026-10-16 to follow the interface track. On 2026-10-25 the owner chose to start it now, designed for the surfaces that exist today: the `peerspan` CLI and the agents' Peerspan tools in Claude Code, Codex, and OpenCode. A later UI (local web UI, tray, or TUI, undecided) must be addable without changing the protocol, so [What a later UI needs](#what-a-later-ui-needs) lists what it would use.

It builds on:
- the [coordinator-free spec](decentralized-spec.md) and its [wire appendix](decentralized-wire-formats.md): membership from host, person and binding grants (section 5), owner policies as 24-hour signed statements (section 5, appendix section 5), policy edits (section 12), peer transport and helpers (section 9), and sync (section 10);
- the [messaging contract](peer-messaging-contract.md) for agent origin, retry and receipts, and its request authorization (`grant_id`, `policy` `{person_id, version}`, or `self`), which on coordinator-free networks is checked against the verified records above;
- the [adapter](agent-adapter-contract.md), [outbound](adapter-outbound-contract.md), and [recovery](adapter-recovery-contract.md) contracts, and [live delivery](live-delivery-contract.md) (seen, redelivery, `pending_work`);
- the agent [directory and addressing](launch-contract.md#slice-4-directory-and-addressing), whose host list is now the verified member list of each coordinator-free network;
- the agent-tools style of the [capabilities contract](capabilities-contract.md#agent-tools-slice-2).

Rust is the only host (DEC-OWN5). There is no coordinator (DEC-OWN2), no in-place migration (DEC-OWN3), and no Go implementation or Go/Rust pairing (DEC-OWN5, DEC-OWN8). Conformance is one slim suite (DEC-OWN6, DEC-OWN9).

## What changed since acceptance

| Accepted text assumed | On `main` today | Where this proposal uses it |
| --- | --- | --- |
| Membership from the coordinator's signed network map | Each host checks host, person, binding and device grants itself (spec section 5). Host and person grants last at most 7 days and renew automatically. A host is a member only while its host grant and the grant's chain are current and not banned. | [Access](#access), [Adding](#adding) |
| "Hosts bound to a person in the network map" | Hosts with a current binding grant for that person (`GET /v2/networks/{id}/members`, field `person_id`) | Person invites and `join` |
| Person labels from the network map | The member label of the person's person grant (`GET /v2/networks/{id}/persons`), the same label their hosts' grants carry | Display labels, `person:LABEL` targets |
| Owner access policy in the [coordination contract](coordination-contract.md#owner-access-policy), valid 1 to 90 days, served by coordinators | The person's current `policy` statement: a `peerspan-policy-v2` body, signed by the person's original key or a scope-1 device, valid at most 24 hours, renewed when less than 8 hours remain (DEC-Q24). Its `version` is the statement's sequence. Edits use a version check (DEC-S16). | [Access](#access), CQ-1 |
| The agent directory queried the coordinator's member list | The same directory (`/peer/v1/networks/{id}/agents`, `GET /v1/directory`) queries every verified member of each coordinator-free network. Addresses (`PERSON/AGENT`, `HOST_ID/AGENT`) are unchanged. | Adding, agent tools |
| QUIC peer transport, with the coordinator's relay as fallback | Direct QUIC to addresses in host-signed contacts (valid at most 300 seconds, exchanged only between members), or QUIC through a helper's `peerspan-relay/4` relay. Helper mailboxes carry only join-request frames. | [Peer routes](#peer-routes) |
| Go and Rust hosts, four pairings, a shared schema | Rust only. Host schema 23 on `main` | [Persistence](#persistence), [Slices](#slices) |
| `conformance/conversations.py` across pairings, plus a live script | One slim suite `conformance/slim/conversations.py`, at most 2 minutes, its own CI matrix job, written from the contract by a spec-only author | [Slices](#slices) |

Conversations work only in coordinator-free networks. Legacy coordinator networks are read-only history (spec section 14) and give no membership, so they authorize no post.

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
- **Names and labels.** `name` is the agent's name as its own host gave it in the invite answer. Each host displays labels it derives itself: the member label of the person bound to the participant's host, from its own verified records, then `/NAME` for agents, for example `bob/claude-laptop`. A host never displays a person label the home host asserted.
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

It then sends one request per target: `POST /peer/v1/conversations/{id}/posts` (below). A target on the author's own host is delivered locally in the same transaction, with no peer request (decision 18). The milestone 5 retry schedule applies to each target: first retry 10 seconds after preparation, then 1 second doubling to 60 seconds with jitter, at most 4 automatic attempts at once per daemon, shared with nothing else. Retries stop at a final answer or at the request's `deadline` (decision 17). The `deadline` is 24 hours after `sent_at`, capped by the cited policy's `valid_until` or grant's `expires_at`, as for messages. On coordinator-free networks a policy is valid for at most 24 hours and is renewed when less than 8 hours remain, so this cap usually ends pushes between 8 and 24 hours after the post, not at 24 hours. [CQ-1](#open-questions-after-the-coordinator-free-work) asks whether to keep that.
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
- **Sync.** At startup, every 10 minutes for each conversation with a local joined participant, and after a roster change, a host first fetches the roster from home (`GET /peer/v1/conversations/{id}/roster`) and stores it if its `version` is higher, so a close or removal whose push expired while the host was offline still takes effect. It then asks each other participant host `GET /peer/v1/conversations/{id}/heads?target=T` for each local target T, and fetches whatever it lacks, then sends `acks` for what it stored. For a closed conversation it keeps doing so, per host, until that host has answered with a `roster_version` at or above the closing version (so it can author nothing more), everything it reported missing has been fetched, and its `acks` have been answered; a host that does not answer is asked again at every sync. It stops once every host that held a participant at the close has answered that way, or 30 days after it stored the closed roster, whichever comes first; a host still unanswered then is shown in the conversation view as `unsynced`. This is how a participant that was offline past the 24-hour retry window catches up. At most 4 syncs run at once per daemon, 5 seconds each. Conversation sync is separate from the network's record sync (spec section 10, every 60 seconds): it runs over the same peer connections but exchanges no grants or catalogs.
- **No store-and-forward.** A post reaches an offline participant only from its author's host, by retry or by the recipient's sync, so both must be online at some common time. Helpers do not hold posts: their mailboxes carry join-request frames only (spec section 9.2), and their relay forwards live QUIC packets.
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

Messages never pass through the home host; only roster changes do. If the home host is offline, participants keep posting to each other with the roster they hold, and no one can join, be added, be removed, or close the conversation until it returns (decision 3). The same holds while the home host is not a current member of any network it shares with a participant host (its grants lapsed, or it was revoked): other hosts refuse its peer requests. [CQ-2](#open-questions-after-the-coordinator-free-work) asks what happens when that lasts.

### Adding

1. The creator names targets by address: `PERSON/AGENT` or `HOST_ID/AGENT` for an agent, resolved through the agent directory as `send --to` is; `person:LABEL`, `person:PERSON_ID`, or a bare label with no `/` for a person, resolved against the current person grants of the home host's coordinator-free networks (`GET /v2/networks/{id}/persons`). Resolution errors are those of addresses: `unknown`, `ambiguous` with candidates.
2. **Agent target.** Home chooses an authorization for the creator to reach that agent with `message.append`, as sending by address does (self, then policy, then grant), and sends `POST /peer/v1/conversations/invites` to the target's host. The target's host checks exactly what it checks for a message from the creator (see [Access](#access)). On success it stores the conversation, makes the agent `joined`, queues a `conversation_roster` event (`added`) for the agent, and answers with the agent's `name`. Refusals return the message codes: 403 `forbidden`, 503 `unavailable`.
3. **Person target.** Home sends the same invite to **every** host that has a current binding grant for that person in a network home shares with it. Each holds it as a pending invite (decision 7). The person runs `peerspan conversation join ID` on the host they want to take part from, which sends `POST /peer/v1/conversations/{id}/join` to home. Home checks that the invite is pending, that the requesting host is a current member with a current binding grant for that person, and adds `person:HOST_ID/PERSON_ID` as `joined`. The roster push tells the person's other hosts, which drop their pending copies. `peerspan conversation decline ID` removes the invite at home.
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
| A local agent | `message.append` from X, under the recipient owner's policy, a grant, or self access, cited by X's host as for messages (decision 1). An agent author's `origin` is matched against `agent:` principals. A person author has no `origin` and matches as an owner CLI send does. Size, deadline, and the block list apply. | At acceptance, and again at handoff to a session, as for messages. |
| A local person | The person joined this conversation on this host, and X's host is a current member of a network this host belongs to. The block list applies to X's host and X's person. | At acceptance. |

How the receiving host evaluates each citation today, on coordinator-free networks:
- **Membership first.** X's host must be a current member of a coordinator-free network the receiving host belongs to: a current host grant whose chain is current and not banned (spec section 5). A host whose grants lapsed or that was revoked gets 403 `forbidden` under `policy` and `self`. A manual grant with `allow_disconnected: true` still works on its own terms (spec section 5, "Manual grants are separate").
- **`policy` `{person_id, version}`.** The receiver loads the current `policy` statement of the recipient agent's owner in each network both hosts share. The statement must be in its window (at most 24 hours), and the post's `deadline` must not be later than its `not_after`. If the receiver holds a lower version than cited, or no current one, it answers 503 `unavailable`, and its network sync (spec section 10) usually fetches the newer one within 60 seconds. Rules match as today: named-agent rules before `*` rules, `person:`, `group:` and `agent:` principals, with groups from current `group` statements.
- **`self` `{person_id}`.** X's host and the receiving host are both bound, by current binding grants, to that person in a shared network.
- **`grant_id`.** A manual grant, unchanged.

- **No transitive access** (decision 2). If Alice's agent may reach Bob's and Carol's agents, that does not let Bob's agent reach Carol's. A post from Bob's agent to Carol's agent needs Carol's owner to allow Bob (or Bob's agent). Without it, that target is `refused` with `not_authorized`, Bob sees which participant did not receive it, and everyone else still does. `conversation_start` and `conversation add` report, per new participant, which existing participants can reach it and which it can reach, as far as the home host's directory knows, so the gap is visible before anyone posts.
- **Policy v2 and actions.** No new policy action: conversations use `message.append`, so the `peerspan-policy-v2` body, the `policy` statement and policy edits are unchanged (decision 1).
- **Revocation mid-conversation.** A recipient owner who denies or blocks X makes the recipient's host refuse X's later posts (`refused`, `not_authorized`), and hold X's undelivered posts as `blocked` at handoff, as for messages. Posts already handed to a session are not withdrawn. X stays in the roster; the owner can also remove their own agent with `conversation leave ID --agent NAME`.
- **The home host.** Adding someone is authorized as the creator messaging them. The home host can remove participants or close the conversation, which is the creator's authority, but it cannot make any host accept a post its owner did not authorize, or attribute a post to another author.
- **Approvals.** Per-call approval (capabilities slice 3) does not apply to posts. A post asking the person to approve something is text; agents still cannot approve.

## Peer routes

All use the existing peer QUIC listener and router (`/peer/v1/...`, beside `/peer/v1/messages`), the per-request re-authentication, the 1 MiB body limit, and strict JSON (unknown fields and nulls are 400). Any host not holding the state a route names gets 404. A host reaches a participant host the way it reaches any member today: directly at a QUIC address from that host's latest signed contact, or through a relay that contact lists (`peerspan-relay/4` on a `peerspan-helper`). No route is served on the first-contact listener, the completion listener, or a helper.

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
6. **Authorization:** as in [Access](#access), with the message error codes, including 503 when this host's policy is behind the cited version.
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

**Status.** `GET /v1/status` gains `conversations: {open, unread, invites}` for the person, and one attention item, `conversation_invites`, while a person invite is pending: subject the count, command `peerspan conversations --invites`. It comes after the existing items, including the network items of spec section 16.

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

A UI would also want approvals in the same place; those come from the per-call approval routes (schema 20), not from here.

## Persistence

One host schema version adds every table below, in the first slice PR, so later slices add no migration. It is the next free version on `main` when that PR merges: `main` is at 23 today, and open PR #35 (guided onboarding) uses 24 to 27, so it is 28 if #35 merges first. Whichever merges second renumbers.

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
- **Migration** creates the tables and index and sets the version in one transaction, in `rust/src/store.rs`'s ordered migration list. Older binaries reject the new version. No existing record changes, and no `dec_*` table changes. This is a schema upgrade of the host database, not a network migration.

## Compatibility with older hosts

- **Wire.** All peer routes are new. An older Rust host answers 404, so an invite to it fails with `unsupported` (`HOST is running a Peerspan without conversations`) and nothing is added; a post to a participant whose host was downgraded becomes `unsupported` for that target.
- **No policy change** (decision 1), so the policy body, policy statements, and their test vectors are unchanged.
- **Messages and tasks** keep their routes, records, and tools.
- **Adapters** ship with the daemon, so a host's adapter and daemon always match; mixed versions occur only between hosts, which the 404 rule covers.
- **Directory.** Unchanged. A host learns that a peer lacks conversations only from the 404.
- **Legacy networks.** Not used: they give no membership (spec section 14.1).

## Security

- **Content is untrusted.** Posts are peer-authored text in the agent's context, now several authors at once. The adapter writes every author label and the header; the content is presented as peer content, as other events are. A post cannot claim to be from another participant: its author must be the authenticated sending host's participant, and posts are fetched only from the author's host.
- **Equivocation.** Posts are not signed, so an author's host could send different text to different recipients. Each host shows what it received. Signed posts (later) would let participants compare.
- **The home host** is trusted for membership only. It can remove people or close the conversation, but cannot widen anyone's access or forge posts.
- **Spam and loops.** Receiving hosts cap posts per author per conversation, cap pending person invites per sender host, and apply the block list. Agents are told they need not answer every post.
- **Owner control.** An owner can always take their agent out (`conversation leave --agent`), and deny or block a sender, enforced locally at once.
- **The local trust boundary** is unchanged: adapter credentials do not isolate a process running as the same OS user.

## Interactions with other features

- **Per-call approval (schema 20).** Its `approval_request` notice is a separate event kind delivered to the capability's source agent; conversation events never carry approvals, and a post asking for approval is just text. Both have an adapter work route that answers 409 before the channel is verified. A later UI shows approvals and conversations side by side from their own routes.
- **Sharing with one agent.** Its `PERSON/AGENT` parsing for `--with` (one `/` means an agent) matches how conversation participants are named, and bare labels mean persons in both. Its lookup route resolves agents the caller cannot reach; conversations do not need it, because every participant must be reachable with `message.append` anyway. `call --from-agent` parallels `conversation start --as AGENT`.
- **Remote MCP and OAuth (schema 22), resource bounds and `gh` (schema 21).** No interaction. A conversation is not a capability and has no operations to bound.
- **Guided onboarding (open PR #35).** No interaction beyond the schema number (see [Persistence](#persistence)).

## Slices

Feature slice 1 (decision 21: agents and people together) is built as six small PRs, C1 to C6, each mergeable on its own. Slices 2 and 3 below are unchanged.

**Every PR** has two parts, in the same PR:
- **Implementation** in `rust/src` and, where named, the shared Node adapter (`integrations/shared`), with the matching section of `docs/conversations-contract.md`. The implementer adds no tests the contract or owner did not ask for (AGENTS.md).
- **Spec-only test cases** appended to `conformance/slim/conversations.py`, written from that contract section by a separate author who does not read `rust/` or `integrations/`. The suite drives real Rust hosts through the CLI, the owner API and the adapter socket, using `conformance/slim/harness.py` (`Suite`, `create_network`, `join_new_person`, the fixture `Adapter`, and the debug test `Clock` for the 10-minute, 24-hour and 30-day timers). The whole suite stays under 2 minutes. C1 adds `conversations` to the `suite` matrix in `.github/workflows/conformance.yml`, so it runs as its own CI job from the first PR.

The PRs, in order:

| PR | Implementation | Spec-only cases added |
| --- | --- | --- |
| **C1. Two hosts, one post each way** | The schema version with every table of [Persistence](#persistence). A person on the home host creates a conversation with one remote agent and posts: `peerspan conversation start TARGET [--title T] [--message TEXT]`, `conversation say ID TEXT`, `conversation show ID`, `conversations`, and their `/v1/conversations` routes. Peer routes `POST /peer/v1/conversations/invites` (agent targets only) and `POST /peer/v1/conversations/{id}/posts`, with acceptance steps 1 to 4 (without the roster fetch, which comes in C2: an unknown conversation or a higher `roster_version` is 503 `unavailable`), 6 and 8, per-target retry, and target states `sending`, `delivered`, `refused`, `unsupported`. Conversation notifications and the adapter routes `POST /adapter/v1/conversation-notifications/next`, `.../{id}/forwarded` and `POST /adapter/v1/conversations/{id}/posts`. In the Node adapter: the `conversation` event kind with its header (and the window on a session's first event), the `conversation_post` tool, and the instructions edit. | Hosts alice and bob in one network; bob's fixture agent `bert` has directory access, and bob's policy allows alice `message.append` to `bert`. alice starts with `bob/bert` and a first message; the invite answers `joined` and the target becomes `delivered`. `bert`'s adapter claims one notification with the post and the `meta` fields. `bert` posts back with its own `post_id`; alice's `conversation show` lists both posts in `(clock, author, seq)` order. The same `post_id` with the same content returns the stored post; with other content, 409. After bob's policy stops allowing alice, alice's next post is `refused` with `not_authorized` for `bert`. |
| **C2. Membership** | Creator-only `add`, `remove`, `close`; any participant's `leave`, and the owner's `leave --agent`. Roster push and fetch (`POST`/`GET /peer/v1/conversations/{id}/roster`, `POST .../leave`), `inviting` and `unanswered` after 10 minutes, the 16-participant and 200-open limits, step 5 (closed), and local participants on the same host (decision 18). An agent as creator: `POST /adapter/v1/conversations`, `GET /adapter/v1/conversations`, `POST .../manage`, `conversation start --as AGENT`. In the Node adapter: `conversation_start`, `conversation_manage`, `list_conversations`, and the `conversation_roster` event. | A third host carol. Add, remove and close push new roster versions to every participant host; a removed or departed participant's host refuses posts with `not_participant`; a closed conversation refuses posts with `closed`. An unreachable invitee becomes `unanswered` after 10 minutes on the test clock. A pair that cannot reach each other is reported at add time, and a post between them is `refused` for that one target only. Two agents on one host take part with local delivery. |
| **C3. People** | Person invites to every bound host, pending invites (20 per sender host, 7 days), `POST /peer/v1/conversations/{id}/join`, decline through `.../leave`, person recipients and their block-list check, `conversations --invites`, `conversation join` and `decline`, the `conversations` status object and the `conversation_invites` attention item. | bob is invited as a person on a host bound to him; the attention item appears; `join` makes him `joined` on that host, and his other bound host drops its pending copy. A declined invite disappears at home. A 21st pending invite from one sender host is 429 `limit`; an invite expires after 7 days on the test clock. |
| **C4. Catch-up** | `prev_seq` gap detection and `GET /peer/v1/conversations/{id}/posts`, `GET .../heads`, `POST .../acks`, the 10-minute sync (roster first), the deadline and the `stopped` state, and sync after close until every host has answered or 30 days pass (`unsynced`). | bob's host is stopped while alice posts three times; after the push deadline passes on the test clock, alice's targets are `stopped`; bob's host restarts, syncs, holds all three posts in order, and its acks turn alice's targets `delivered`. A close pushed while bob's host was down takes effect at its next sync. |
| **C5. Session context** | The window on a first event and on catch-up, coalescing returned notifications, seen through the conversation tools and `mark_seen` with `conv_` and `post_` IDs, redelivery at most 3 times, `blocked` at handoff, `pending_work.conversations` and the `--hook` text, `GET /adapter/v1/conversations/{id}/posts` and the `conversation_history` tool, and the `conversation_undelivered` event. | A new session for `bert` after posts it did not see gets one `catch_up` event with the window and `unseen` count; posting marks them seen; `pending_work` lists the conversation until then. A post whose author lost access before handoff is never offered. A `refused` target produces one `conversation_undelivered` event for its author. History pages by `before_post_id` within the byte budget. |
| **C6. Rate, addressing, and the person's tools** | The 60-posts-per-hour limit on both sides, `addressed_to` and `meta.addressed`, the `about` task link, `conversation watch` and the `/v1/conversations/events` log, the read cursor and `conversation read`, `conversation forget`, terminal escaping in readable output, and the activity kinds. The CLI root help lists the conversation commands (see CQ-3). The decision log's CONV group gains "Implemented in: PRs C1 to C6". | The 61st post in an hour is 429 `limit` at the author's host and, sent directly with the peer probe, at a recipient host. `addressed_to` sets `addressed` per recipient. `watch` prints new posts and advances the read cursor. `forget` on the home host keeps the roster so others can still leave. Escape sequences in content are printed escaped. |

Feature slices after the first:
2. **History and threads.** History for late joiners under whichever rule decision 8 picks; task discussion threads; continuing a message as a conversation; any participant adding (if decision 4 allows).
3. **Later.** Signed posts and fetching history from any participant; moving the home host; a person on several hosts; files in conversations; a UI using the local API.

### Implementation size of feature slice 1

Rough, across C1 to C6:
- **Rust:** about 3,000 to 3,800 lines: tables and migration, roster and home-host logic, invites and joins, fan-out and retry, acceptance checks, gap fetch and sync workers, notifications with live delivery rules, local routes, CLI with readable output and escaping, the event log, status. C1 is about a third of it.
- **Shared Node adapter:** about 500 to 700 lines: five tools and schemas, `post_id` generation in the proxy, the notification claim loop and three event kinds with the header and window, presentation titles, `mark_seen` and `pending_work` changes, the instructions edit.
- **Conformance:** about 700 to 1,000 lines in `conformance/slim/conversations.py`, under 2 minutes in total.
- **Contract text:** `docs/conversations-contract.md`, one section per PR.

## Open questions after the coordinator-free work

These come from accepted decisions that no longer fit as written. Each is for the owner; nothing here changes the accepted design until the owner answers. The rest of the proposal follows the recommendation only where it says so.

**CQ-1. How long the author's host pushes, now that policies last at most 24 hours (CONV-17).** CONV-17 chose 24 hours of pushing, then the recipient fetches on sync. A pushed post carries a `deadline` capped by the cited policy's `valid_until`, as messages do. Policies used to last days; now they last at most 24 hours and are renewed when less than 8 hours remain, so most pushes stop 8 to 24 hours after the post, and earlier when the recipient owner's hosts were offline and could not renew.
- (a) Keep the message rule. Pushes stop at the capped deadline; sync covers the rest. No design change.
- (b) Re-cite on each retry: the author's host cites its newest copy of the recipient owner's policy on every attempt, with a new deadline capped by it, up to 24 hours after `sent_at`. The repeat check (acceptance step 3) ignores `deadline` and the citation fields.
- (c) Posts carry no `deadline`. The author's host pushes until 24 hours after `sent_at`, and the receiver checks a pushed post as it checks a fetched one: under its own current policy, grants and block list, with no deadline bounds. The cited `policy` version is still sent, so a receiver behind it answers 503.
- **Recommendation: (c).** It gives CONV-17's 24 hours as written, and makes a pushed and a fetched post pass the same checks, which removes a field and a rule instead of adding one. The host's message authorization already has a check without the deadline, used today when an agent replies to a delivered message.

**CQ-2. A home host that stops being a member (CONV-3).** CONV-3 made the creator's host the only roster authority, and expected it to be offline only for a while. Now a host's grants last at most 7 days: a home host that is switched off for more than about a week, whose owner's other hosts cannot renew it, or that is revoked, is not a member, and other hosts refuse its requests. Its conversations can then have no adds, removals, joins, or close until it is a member again, possibly never.
- (a) As accepted: posting continues among participants whose hosts are members; membership changes wait for home. Each host shows `home_unavailable` in the conversation view while home is not a current member of any network they share, and any participant can still leave locally (it stops deliveries at once; its `leave` to home is retried).
- (b) Bring CONV-3(c) forward: the creator may hand home to another participant host while home is still a member.
- (c) Automatic handover to a host of the same person, when home has been a non-member for 7 days.
- **Recommendation: (a)** now, (b) in feature slice 3 as already planned. Lapsed grants are renewed when the host returns, revocation is rare, and handover needs its own design for roster authority.

**CQ-3. What "first slice" means when it is built as six PRs (CONV-21).** CONV-21 chose agents and people together in the first slice. The slice is now C1 to C6 on `main`, one at a time, and the repository is public; after C1 a user could find an agents-only, person-creator-only conversation.
- (a) C1 to C6 together are CONV-21's first slice. Each PR is complete for what it covers. The root help, README, and quick start mention conversations only from C6; until then the commands exist but are not listed in the root help.
- (b) Agents first: list the commands from C2, and add people in C3 as a second user-visible step (CONV-21(b)).
- (c) Keep everything behind a build or runtime flag until C6.
- **Recommendation: (a).** It keeps CONV-21's scope as the first thing users see, needs no flag, and each PR still runs in CI.

**CQ-4. The live run with real agents (CONV-21's slice text).** The accepted slice 1 ended with "a live run with Claude Code, Codex, and OpenCode agents and one person in one conversation across two machines". DEC-OWN6 and DEC-OWN9 replaced the old suites with slim, fixture-driven suites in CI, and say nothing about live runs for new features.
- (a) Keep it as a one-time manual run before C6 merges, recorded in `docs/results/` and linked from C6's PR. It does not gate CI.
- (b) Drop it; the slim suite with fixture adapters and the shared adapter's own tests (`integrations/shared/*.test.mjs`) are enough.
- (c) Make it a scripted CI job with real agents.
- **Recommendation: (a).** The window, labels, and "you need not answer every post" guidance only show their value with real models, and a single recorded run is cheap. Real agents in CI need accounts and keys the project does not have.

## Owner decisions needed

The list the owner accepted on 2026-10-25 (CONV-1 to CONV-21), kept as written. "Slice 1" here means feature slice 1, now built as PRs C1 to C6. Questions raised by the coordinator-free work are CQ-1 to CQ-4 above.

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
