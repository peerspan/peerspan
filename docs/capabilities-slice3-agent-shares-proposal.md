# Capabilities slice 3: sharing with one agent

Status: **Accepted on 2026-10-25.** The owner accepted every recommendation under [Owner decisions needed](#owner-decisions-needed), recorded as [decision 16](capabilities-contract.md#owner-decisions) in the capabilities contract. The recommended design below is the design for item C; it is not yet implemented, and its contract section is added when it is.

Slice 3 has four items, proposed separately: (A) remote MCP servers and OAuth, (B) per-call approval, (C) sharing with one agent (this document), and (D) optional resource bounds and non-MCP sources such as a `gh` adapter. [Interactions](#interactions-with-a-b-and-d) notes where C touches the others.

## What exists today

Slice 2 of the [capabilities contract](capabilities-contract.md#agent-origin-and-agent-principals) already lets an owner share a capability with one agent, but only by its IDs:

```text
Bob$ peerspan share github-issues --with agent:host_3f…/agent_9c…
```

- **The principal.** A capability rule may name `agent:HOST_ID/AGENT_ID`. The serving host matches it only for calls that arrive over an authenticated connection from `HOST_ID` and carry `origin.agent_id` equal to `AGENT_ID` ([coordination contract](coordination-contract.md#policy-statement), milestone 6 [agent origin](peer-messaging-contract.md#agent-origin)).
- **Origin.** Every adapter call carries `origin: {agent_id, session_id}`. Owner CLI calls carry none.
- **Listing.** `GET /peer/v1/capabilities` marks a rule that matches only through `agent:` principals with `from_agent`. The owner's `discover` and `call` drop such entries, so an owner cannot see or use an agent-only share. `list_capabilities` keeps the ones for its own agent.
- **Deferred.** Decision 14 put two things off: naming the agent as `PERSON/AGENT`, converted to the `agent:` form, and `call --from-agent`.

Two facts from the launch contract shape this proposal:
- **Agent IDs are the identity; names are labels.** "Nothing authorizes by name" ([launch contract, slice 4](launch-contract.md#slice-4-directory-and-addressing)). A person's agent names are unique across their hosts as far as `attach` can check, so `alice/claude-laptop` names one agent.
- **The directory is filtered.** A host lists only the agents the caller may already reach (`GET /peer/v1/networks/{id}/agents`). So Bob's host usually **cannot see** `alice/claude-laptop` in its directory, because Alice has not let Bob message that agent. Turning `alice/claude-laptop` into an ID needs another way to ask Alice's host. This is the main new piece.

## Goals and limits

**Goals:**
- `share NAME --with alice/claude-laptop` writes `agent:HOST_ID/AGENT_ID` into the policy, after a review that names the agent in words.
- `shares`, `unshare`, and the owner's `discover` show agent recipients by name, and say when the agent is gone.
- `call --from-agent AGENT` lets an owner make a call as one of their own agents, so they can use and test an agent-only share without starting the agent.

**Not in this item:**
- No change to the policy statement or its test vector. The stored principal stays `agent:HOST_ID/AGENT_ID` (unless the owner picks otherwise in decision 2).
- No agent keys. Agent origin stays host-asserted, as milestone 6 decided.
- No change to the adapter or the four MCP tools.

## Naming one agent

### Accepted forms

`share`, the guided `share --with`, and `unshare` accept, for `--with`:

| Form | Example | Meaning |
| --- | --- | --- |
| `PERSON/AGENT` | `alice/claude-laptop` | The agent named `claude-laptop` on one of the hosts bound to the person labelled `alice` in the selected network. |
| `HOST_ID/AGENT` | `host_3f…/claude-laptop` | The agent with that name on that host. For hosts without a bound person, persons whose label contains `/`, and duplicate names. |
| `agent:HOST_ID/AGENT_ID` | as today | Used as given; no lookup. |

Parsing:
- A value with no `kind:` prefix and **exactly one** `/` is an agent address. Today such a value is read as a person label; that changes (decision 4). A person whose label contains `/` is still named as `person:LABEL` or by person ID.
- A value with two or more `/` and no prefix is refused: `invalid recipient "a/b/c": use PERSON/AGENT, HOST_ID/AGENT, or person:LABEL for a label that contains /`.
- `AGENT` must be an addressable name (1–64 of `a-z 0-9 . _ -`, starting with a letter or digit), since only those are addressable. Otherwise: `invalid agent name "X"`.
- The split is at the one `/`, as for capability addresses, so it agrees with [addresses](capabilities-contract.md#model).

### Resolving the agent

The CLI resolves the address before it shows the review, in the network the share is written to (`--network`, or the host's only network). Steps:
1. **Hosts to ask.** For `HOST_ID/AGENT`: that host, which must be a current member of the network, else `unknown host HOST_ID in network NET`. For `PERSON/AGENT`: the person is resolved as other person arguments are (unknown, or ambiguous with candidates), and the hosts are those bound to that person in the network map.
2. **This host.** If one of those hosts is this host and it has an agent with that name, the share is refused with 400 `local` (decision 5): `alice/claude-laptop is on this host, and a host never calls itself. Share with an agent on another machine.`
3. **Ask each other host** with the new peer route below, at most 8 at once, 5 seconds each, over the usual peer transport, relay included. A host that answers 404 to the route predates it (`unsupported`); for that host only, a matching entry in this host's directory cache counts as its answer.
4. **Result.**
   - Exactly one match: the principal is `agent:HOST_ID/AGENT_ID`.
   - More than one: 409 `ambiguous`, `{code, error, matches: [{address: "HOST_ID/AGENT", network_id}]}`, as address resolution does.
   - None: 404 `unknown`, `{code, error, unanswered: [{host_id, error}]}`: `alice has no agent named claude-laptop on the hosts that answered.` When hosts did not answer, the text adds `Not answered: host_… (timeout). Try again when it is online, or use agent:HOST_ID/AGENT_ID.`
   - One match while other hosts did not answer: the share goes ahead and the review lists the unanswered hosts (decision 7). Names are unique per person, so a second match is unlikely; the review makes it visible.

Resolution runs in the CLI through a new local route, `GET /v1/agent-lookup?address=A&network=N`, so the CLI does no peer traffic itself. It returns `{principal, host_id, agent_id, person_id, address, unanswered}` or the errors above.

### The lookup route (new)

`GET /peer/v1/networks/{network_id}/agent-lookup?name=NAME` or `?agent_id=ID`, exactly one of the two.
- **Who may ask.** Any current, unrevoked member of that network, as for the agents route. Others get 403; a network the host is not in is 404 `not_found` with a `code`.
- **Answer.** Always 200 when allowed: `{agent: {agent_id, name} | null}`. `name` matches addressable names exactly; `agent_id` matches any registered agent, and returns its name, or null for the name if it is not addressable. Answering 200 with `agent: null` keeps 404 meaning "route not supported" for older hosts.
- **What it reveals.** That an agent with this exact name or ID exists on the host, nothing else: no connection state, no authorizations. It never lists. Agent IDs are already visible to members in any policy that names them. Decision 1 is whether to accept this disclosure.
- **Bounds.** Query string at most 256 bytes; response at most 4 KiB. `peerspan-peer-probe` gains the route.

### What goes into the policy

The `agent:HOST_ID/AGENT_ID` principal, unchanged. The signed statement, its JSON, the test vector, coordinator handling, and propagation do not change. The rule's other principals, bounds, and the 64-principal limit apply as today; each agent share uses one principal slot.

## The review and outputs

### `share`

The review (stderr) keeps every line it has today. The recipient line and reach text change for an agent:

```text
Share bob/github-issues
  source:      claude-laptop/github (claude-code:project)
  operations:  list_issues, get_issue
  credentials: the source's own environment
  recipient:   alice/claude-laptop
               agent agent_9c… on host host_3f…, bound to alice
  not checked: host_77… (timeout)

alice/claude-laptop can use these operations with the credentials they run
with on this host. Anything those credentials can reach through them,
alice/claude-laptop can too.
Only calls that host_3f… says come from this agent are allowed. That host
makes the claim itself: alice, and any program that can run peerspan as her
on that machine, can call as this agent. Alice's other machines and other
agents, and other people, cannot.
The share stays with this agent on this machine. If the agent is set up
again on another machine, share it again.
Share? [y/N]
```

- `not checked` appears only when hosts did not answer.
- For the owner's own agent on a host that is trusted in this network, it adds: `This machine is trusted, so this agent already reaches all your capabilities through self access. This share matters only if you untrust it.` (decision 5).

`share` prints `{policy, capability, principal, recipient, created}`. `recipient` is new: `{address, host_id, agent_id, person_id}`, where `address` is the form the owner typed resolved to `PERSON/AGENT` when the host has a bound person whose label contains no `/`, else `HOST_ID/AGENT`; it is null for the `agent:` form. Sharing again with an agent already in the rule signs nothing, as today.

### `shares` and `capability list`

Recipients are labelled by a live lookup (decision 6): for each `agent:` principal, the CLI asks that host with `?agent_id=`, using the same limits as above, and takes the person from the network map.

Each agent recipient in `shares --json` is `{network_id, principal, label, agent_state, unshare}`:
- `label` is `alice/claude-laptop` (or `HOST_ID/NAME`), or null when the name is not known.
- `agent_state` is one of:
  - `found`: the host answered with this agent;
  - `not_found`: the host answered `agent: null`, so the agent no longer exists there;
  - `host_gone`: the host is no longer a member of that network;
  - `unanswered`: the host did not answer;
  - `unbound`: the host answered, but is no longer bound to any person in that network.

  The label always uses the host's **current** person from the network map. Nothing about the person is stored, so if the host is later bound to someone else, the label shows the new person's name (`carol/claude-laptop`), which is how the owner notices (decision 3).
- `unshare` is the command to remove it: `peerspan unshare NAME --with alice/claude-laptop` when `found`, otherwise `peerspan unshare NAME --with agent:HOST_ID/AGENT_ID`.

Non-agent recipients are unchanged. The readable layout shows, for example, `with: alice, alice/claude-laptop (agent), carol/codex-desk (agent, gone)`. `GET /v1/capabilities` gains `label` and `agent_state` on the same entries; it is not shared output, so it uses the daemon's cache of the last lookup and does no peer traffic.

### `unshare`

`unshare NAME --with alice/claude-laptop` resolves the address as `share` does and removes that principal. When resolution fails (the host is offline, or the agent is gone), the error lists the rule's `agent:` principals on that person's hosts, each with its `unshare --with agent:…` command, so a gone agent can always be removed.

The output gains `recipient`, as for `share`. Two notes are added:
- With `removed: 0` for an agent address, the note says `Access through person:alice, a group, or everyone is unaffected.`
- When `unshare --with alice` removes `person:alice` and the rule still names agents on Alice's hosts, the output adds `note`: `alice/claude-laptop still has its own share. Run peerspan unshare NAME --with alice/claude-laptop to remove it.`

### The recipient's `discover`

Today Alice's `discover` hides a share made only to her agent. Proposed (decision 11):
- **Default `discover`** lists such capabilities with `for_agents: [{agent_id, name}]`, naming the local agents that may use them, and the readable line `bob/github-issues   only for your agent claude-laptop`. `via` entries keep `from_agent`.
- **`call` without `--from-agent`** on such a capability is refused before persisting, with 403 `{code: "agent_only", error, for_agents}`: `bob/github-issues is shared only with your agent claude-laptop. Add --from-agent claude-laptop to call as that agent.`
- **`discover --from-agent AGENT`** shows exactly what that agent's `list_capabilities` would show (capabilities only, no sources), so the owner can check an agent's view.

## When the agent changes

The principal names a host ID and an agent ID, so it follows those IDs and nothing else.

| What happens | Effect on the share | What the owner sees |
| --- | --- | --- |
| Alice re-attaches the same project | `attach` reuses the agent ID; the share keeps working. A new credential or session changes nothing. | Nothing. |
| Alice re-attaches with another `--name`, or attaches another project | That is a new agent with a new ID; the share does not cover it. There is no rename today: an agent's name is fixed for its life. | The old agent stays `found` while it exists. |
| The agent's record disappears (no delete command exists today; a wiped state directory gives a new host ID, below) | Matches nothing. | `not_found`. |
| Alice moves to a new machine, or reinstalls with a new state directory | New host ID and agent ID; the share does not follow. Bob shares again. | `host_gone` or `unanswered`. Alice's agent stops seeing the capability in `list_capabilities`. |
| The host is revoked from the network | Its calls fail authentication in that network. | `host_gone`. |
| The host is unbound from Alice, or later bound to someone else | The `agent:` principal still matches: milestone 6 matching does not look at the person. | `unbound`, or the label with the new person's name (decision 3). |
| Alice's person label changes | Nothing; labels are not stored. | The new label. |

Dead principals are never removed automatically (decision 15). They cost a principal slot, which `shares` makes visible.

## `call --from-agent`

```text
Alice$ peerspan call bob/github-issues list_issues --repo acme/api --from-agent claude-laptop
```

**Syntax.** `call ADDRESS OPERATION … [--from-agent AGENT [--from-session SESSION_ID]]`. `discover` gains `--from-agent AGENT`.
- `AGENT` is a local agent ID, or the name of an agent registered on this host (decision 13). An unknown one is 404 before persisting: `no agent claude-laptop on this host`.
- `--from-session` names one of that agent's sessions, as `message send --from-session` does; without `--from-agent` it is refused, `--from-session needs --from-agent` (decision 12).
- Both are `call`'s own flags, so a tool property named `from-agent` or `from-session` must go in `--input`, as for the existing flags.

**Who the owner may act as.** Any agent registered on this host (decision 8). This matches `message send --from-agent` and `send`/`task --from-agent`: whoever controls the daemon's owner socket already speaks for every agent on the host, and the receiving host cannot tell the difference anyway. The agent need not have `attach --calls`; that opt-in limits what the agent does on its own, not what its owner does.

**What happens.**
1. **Resolution** uses the agent's view: `via` entries of kind `self`, or `policy` with `from_agent` null or this agent, as `list_capabilities` does. Sources are refused with 400 `{code: "source"}`: `Agents cannot call sources; call them without --from-agent.` (decision 10).
2. **Citation** is the first entry of the resolved capability that applies to this agent, self first, then policy entries in listed order, or the first from `--network`. This is step 5 of adapter submission.
3. **The request** carries `origin: {agent_id, session_id}` (session omitted when not given). The local API `POST /v1/calls` gains optional `origin`, checked as for `message send`: an unknown agent or session is 404, and a session of another agent is 400.
4. **Records.** The outbound record stores `origin` in `request` and has `adapter_id: null`. That pair, origin with no adapter, is how a reader tells an owner call made as an agent from one the agent made. The receiver stores and shows `origin` as for any call; it cannot tell the two apart, by design.
5. **Limits.** No `adapter_calls` row is written, so the call does not count against the agent's `max_calls_per_hour`. The receiver's rule budget counts it as usual: per rule identity and caller, where the caller is Alice's person (or her host ID), the same as her other calls under that rule.
6. **The agent does not see it** (decision 9). There is no call-update notification, it is not in `pending_work`, and the agent's `call_status` answers `not_recorded`. The owner follows it with `calls inspect`, `calls list`, and `calls cancel`.
7. **Output and exit codes** are as for `call`.

## Security

- **An agent share is as strong as the recipient's host.** Origin is asserted by the authenticated sending host. Alice, or anything able to run `peerspan` as her on that machine (including another agent with shell access under the same OS account), can call as that agent. It does stop Alice's other machines, Alice's other agents' adapter sessions, and other people. The review says this in plain words instead of implying an agent boundary.
- **It never widens access.** An `agent:` principal can match only calls from its one host; the rule's bounds, the block list, rechecks before start, and revocation apply unchanged.
- **The lookup route** discloses whether an exact agent name or ID exists on a host, to members of that network (decision 1). It grants nothing.
- **`call --from-agent`** adds no authority: the owner could already assert any local agent with `message send --from-agent`.

## Interactions with A, B, and D

- **A, remote MCP and OAuth.** No special case. An agent share of an OAuth-backed capability runs on the owner's token like any other share; the review's reach text applies. If A gives the review extra lines about the token's scope, they apply to agent recipients unchanged.
- **B, per-call approval.**
  - The approval prompt should name the caller with the same labels as `shares` (`alice/claude-laptop (agent, asserted by host_3f…)`), and say when origin is absent. The label lookup here is reusable.
  - If B lets an owner set approval per principal, `agent:` principals must be valid keys there.
  - A call waiting for approval is `queued`, so an `unshare` of the agent meanwhile rejects it at the recheck before start.
  - `call --from-agent` gives B a way to test approval of agent-only shares from the CLI.
- **D, bounds and `gh`.** Bounds live in the capability record (`bounds`), so they apply to agent recipients as to anyone. If D adds bounds per share (per principal), the `agent:` principal must be a valid key. A `gh`-backed capability is shared with an agent like any other.
- **Schema numbers.** This item needs no database migration (with decision 6 as recommended). If A, B, or D bump the version, C has nothing to merge.

## Contract changes

- **Capabilities contract:** a slice 3 section with the forms, resolution, the local and peer lookup routes, the review lines, `share`/`unshare`/`shares` outputs, `discover` `for_agents` and `--from-agent`, `call --from-agent`, and `POST /v1/calls` `origin`. The slice 2 sentence "There is no `call --from-agent`" is replaced.
- **Launch contract:** if decision 14 is accepted, `allow` and `deny` take `PERSON/AGENT` and `HOST_ID/AGENT` with the same resolver.
- **Policy, coordination, and the adapter:** unchanged.
- **Persistence:** none, beyond the daemon's in-memory label cache.

## Verification

Cases for `conformance/capability_agents.py`, written from the contract by an independent author, across all Go/Rust CLI and daemon pairings with `--probe`, the Go coordinator, OpenSSH, and `--node` where an adapter is used:
- **Forms:** `PERSON/AGENT` and `HOST_ID/AGENT` producing the same `agent:` principal; `agent:` unchanged; two `/` refused; a non-addressable name refused; a person whose label contains `/` reached through `person:`.
- **Resolution:** an agent not in the caller's directory found through the lookup route; `unknown` with `unanswered` for a stopped host; one match with an unanswered host going ahead and listing it; `ambiguous` with two hosts carrying the same name; `local` for an agent on this host; a host predating the route resolved from the directory, and `unknown` when the directory lacks it.
- **Lookup route:** 200 with `agent: null`; 403 for a non-member; 404 for another network; by `agent_id` for a non-addressable name.
- **Review and output:** the recipient and reach lines; the trusted-own-agent note; `recipient` in JSON; a repeat signing nothing.
- **Authorization:** the agent's adapter calls accepted; another agent on the same host refused; the same agent name on Alice's other host refused.
- **`shares`:** each `agent_state`, including `not_found` after the agent's record is removed by the fixture, `host_gone` after revocation, and `unbound` after unbinding; the `unshare` command for each.
- **`unshare`:** by `PERSON/AGENT`; the fallback listing when the host is stopped; the agent-share note after `unshare --with PERSON`.
- **Recipient views:** `for_agents` in default `discover`; `agent_only` from `call` without the flag; `discover --from-agent` equal to the agent's `list_capabilities`.
- **`call --from-agent`:** by ID and by name; with `--from-session`; unknown agent or session refused before persisting; a source refused; `origin` stored on both hosts with `adapter_id` null; not counted against the agent's limit; counted in the receiver's budget; invisible to the agent's `call_status` and `pending_work`; no `call_update` event.
- **Unchanged:** the policy v2 test vector.

## Implementation size

Rough estimates, from the current code (`resolveTopPrincipal`, `listingView`, the directory and peer routers):
- **Go:** about 600–800 lines. The resolver and local lookup route (~250), the peer lookup route (~80), `shares` labels and states (~150), `unshare` fallback and notes (~80), `call`/`discover --from-agent` and `for_agents` (~150). `listingView` already supports an agent view.
- **Rust:** about the same, 650–850 lines, in `addressing.rs`, `directory.rs`, `calls.rs`, `call_outbound.rs`, and the CLI.
- **Adapter:** none.
- **Probe:** the new route, ~30 lines.
- **Conformance:** about 35 cases, ~600–800 lines of Python, plus `launch_onboarding.py` cases if decision 14 is accepted.
- **Contract text:** about 150 lines.

## Owner decisions needed

1. **How Bob's host finds Alice's agent ID.**
   - (a) A new peer route that answers one exact name or ID to any member of the network, with the directory as fallback for older hosts.
   - (b) The directory only. It works only when Alice already lets Bob's host reach that agent, which is usually not the case.
   - (c) No lookup. Alice reads `agent:HOST_ID/AGENT_ID` from `peerspan agents` and sends it to Bob.
   - **Recommendation: (a).** It is the only option where `--with alice/claude-laptop` works in the common case, and it discloses only that an exact name exists.
2. **What the stored principal names.**
   - (a) Host ID and agent ID, the existing `agent:` form; the share does not follow the agent to another machine.
   - (b) A new form naming the person and the agent name (for example `agent-name:PERSON_ID/NAME`), which follows moves. The sending host would have to assert the agent's name in `origin`, the format and test vector change, and names would start to authorize.
   - **Recommendation: (a).** It keeps "nothing authorizes by name" and needs no format change. Moves are rare, and re-sharing is one command.
3. **A host unbound from the person it was shared as.**
   - (a) Keep milestone 6 matching (host and agent only). `shares` shows `unbound`, or labels the agent with the host's new person.
   - (b) Add the person to the principal (for example `agent:HOST_ID/AGENT_ID@PERSON_ID`), so the share stops when the host's person changes. This is a format change.
   - (c) Keep the format, store the person at `share` time on the sharing host, and add a status attention item when the host's person differs.
   - **Recommendation: (a).** Unbinding is rare, signed, and deliberate, and `shares` makes it visible. (b) is the safe choice if the owner sees this as a real risk.
4. **A bare `--with` value containing one `/`.**
   - (a) It is always an agent address. A person label with `/` is given as `person:LABEL`.
   - (b) Try a person label first, then an agent address.
   - **Recommendation: (a).** One reading, matching capability addresses. (b) makes the meaning depend on who exists.
5. **Sharing with the owner's own agents.**
   - (a) Allowed for agents on the owner's other hosts, with a note when that host is trusted; refused with `local` for agents on this host.
   - (b) Refused for all of the owner's own agents, since self access covers trusted machines.
   - **Recommendation: (a).** It is how one agent on an untrusted machine gets one capability.
6. **How `shares` labels agent recipients.**
   - (a) A live lookup by agent ID when `shares` runs (up to 5 seconds), showing gone agents.
   - (b) Store the name at `share` time in a new table (a schema bump); fast and offline, but stale and present only on the host that shared.
   - (c) Show IDs, with only the person taken from the network map.
   - **Recommendation: (a).** No schema change, and it shows when an agent is gone. Names never change, so a lookup is accurate.
7. **One match while some of the person's hosts did not answer.**
   - (a) Go ahead, and list the unanswered hosts in the review.
   - (b) Refuse until every host answers.
   - **Recommendation: (a).** Names are unique per person, `attach` already works this way, and an offline laptop should not block sharing.
8. **Which agents `call --from-agent` may act as.**
   - (a) Any agent registered on this host.
   - (b) Only agents with an `attach` profile.
   - (c) Only agents whose credential has `calls`.
   - **Recommendation: (a).** It matches `message send --from-agent`; the owner already controls every local agent, and the receiver cannot tell the difference.
9. **Whether the agent sees calls made as it.**
   - (a) No: owner's records only.
   - (b) Yes: visible to `call_status` and `pending_work`, with a `call_update` event.
   - **Recommendation: (a).** The owner made the call and follows it; injecting it into a live session would confuse the agent.
10. **`--from-agent` with a source address.**
    - (a) Refused, since agents cannot call sources.
    - (b) Allowed, carrying the origin.
    - **Recommendation: (a).** `--from-agent` should show exactly what the agent can do.
11. **The recipient's default `discover`.**
    - (a) List agent-only shares with `for_agents`, and refuse `call` without the flag with an `agent_only` error that names the flag.
    - (b) Keep them hidden; only `discover --from-agent` shows them.
    - **Recommendation: (a).** Alice can see what her agents were given, and the error tells her how to use it.
12. **`--from-session`.**
    - (a) Accept it, as `message send` does.
    - (b) Omit it.
    - **Recommendation: (a).** It is cheap, keeps parity, and lets an owner reproduce an adapter call exactly.
13. **How `--from-agent` names the agent.**
    - (a) An agent ID or a local agent name.
    - (b) An ID only, as `send --from-agent` takes today.
    - **Recommendation: (a)**, and accept names in `send`/`task --from-agent` too, later or in this slice.
14. **`allow` and `deny` (message and task access).**
    - (a) Accept `PERSON/AGENT` and `HOST_ID/AGENT` with the same resolver, in this slice.
    - (b) Leave them at `agent:HOST/AGENT` for now.
    - **Recommendation: (a).** The resolver is shared, and one recipient syntax everywhere is easier to explain. It adds `launch_onboarding.py` cases.
15. **Principals for agents that are gone.**
    - (a) Show them in `shares` with their state, and never remove them automatically.
    - (b) Remove them at the next policy edit.
    - (c) Add a status attention item.
    - **Recommendation: (a).** An unanswered host may come back, and silent removal by a signing tool is surprising. `shares` already shows the state and the `unshare` command.
