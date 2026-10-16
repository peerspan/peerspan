# Remote tools and resources

Status: accepted as an MCP-specific technical proposal on 2026-10-16, then reopened for a product experience review the same day. The owner chose **shareable capability** as the public unit for tools and resources, scoped to one coherent use case with defined operations or resources and stated credential reach, whether backed by an MCP server or a bounded CLI operation. A resource restriction such as a repository is optional. The earlier whole-server sharing default and the CLI, agent-tool, discovery, and addressing shapes below are pending revision under that model. Nothing is implemented. The earlier decisions are listed under [Decisions](#decisions); the slice 1 technical contract is in [tools-contract.md](tools-contract.md). This would be roadmap milestone 10. It builds on owner access policy (milestone 2b), tasks (milestone 6), and the [access model](access-model.md). Credentials and how far they reach are covered separately, in [Credentials for shared tools](tool-credentials.md).

## Problem

The system design requires three collaboration capabilities. Task delegation ships, and peer conversation ships as messages and replies. The third, "discover and use explicitly permitted tools or resources on another host", does not exist:

- **Nothing can be shared except agents.** The `agents.capabilities` column is local metadata. It is never served to peers, and by the host contract it grants nothing.
- **Policy cannot name a tool.** The only actions are `message.append`, `task.submit`, and `task.delegate`, and the only scope in a rule is the agent name.
- **To use something on Bob's machine, you have to ask Bob's agent.** Alice's agent delegates a task and hopes Bob's model calls the right tool with the right arguments. The result is model output, not the tool's result. Bob cannot grant "read issues in this repository" without also granting "talk to my agent".
- **Everything is asynchronous and text-only.** Tasks carry at most 64 KiB of text each way. Peer requests are bounded at 1 MiB and 8 seconds, with no streaming.

## Goals and non-goals

**Goals:**

- **Nothing new to set up.** An owner shares a tool their agent already uses, without registering or configuring it again. The only explicit step is the decision to share, through the `allow` command that owners already run.
- **Owner-signed policy grants access to specific tools and resources.** Grants go to persons, groups, or the network, and the receiving host enforces them exactly as it does for messages and tasks.
- **Callers get the tool's own result.** An authorized caller, whether an agent through MCP or an owner through the CLI, can list what it may use, call a tool, and read a resource.
- **Bounded credential reach.** Without a narrower credential, a share covers read-only tools only, and the owner is told how far the credential reaches ([tool credentials](tool-credentials.md)).
- **Every call is recorded on both hosts.** An uncertain outcome is reported as uncertain and never repeated automatically.
- **No running session needed.** The receiving host does not need an agent session running.

**Non-goals for the first slices:**

- tools that a running session provides itself, such as Claude Code's built-in tools, because no integration can expose them;
- isolation of the server process, which runs as the owner's user until isolated runtimes exist;
- streaming results and MCP prompts;
- calls inside delegation chains;
- argument rules and profiles for popular servers ([tool credentials](tool-credentials.md#narrowing-what-a-credential-can-reach)).

## What is shared: discovered servers

**Decided:** shared servers are discovered from the configuration of the harness an agent already uses. They are not registered separately.

| Harness | Where its MCP servers are configured |
| --- | --- |
| Claude Code | `.mcp.json` in the project, and the project and user scopes in `~/.claude.json` |
| Codex | `[mcp_servers.*]` in `~/.codex/config.toml` |
| OpenCode | `mcp` in `opencode.json` |

`peerspan attach` reads the configuration for the agent and project it attaches, and reports what it found:

```text
$ peerspan attach claude
alice/claude-laptop is ready.
MCP servers found: github, linear, postgres. None are shared.
```

- **Snapshot.** The daemon starts each server once, briefly, to list its tools and resources. It records their names, descriptions, input schemas, and `readOnlyHint` annotations in host state, as a snapshot per agent. Peers see only this snapshot. A server cannot change what callers see until the owner runs `attach` again or `peerspan tools refresh`.
- **Following configuration changes.** When the harness configuration changes, `attach` and `tools refresh` follow it. A newly added server or tool is never shared automatically. A server removed from the configuration stops serving calls.
- **Running a server.** The daemon runs a shared server itself, over stdio, in the project directory, on its first call. It stops the server after 10 minutes without calls. Credentials come as described in [tool credentials](tool-credentials.md#where-shared-servers-get-their-credentials):
  - literal values are read from the configuration;
  - `${VAR}` references are captured at `attach`, or read from the per-user environment file;
  - remote OAuth servers use Peerspan's own OAuth client (slice 3).
- **Addressing.** A server is addressed by its agent and server name, such as `alice/claude-laptop/github`.
- **Inspecting what is shared.** `peerspan tools` lists, for each agent:
  - the discovered servers;
  - each server's tools, marked read-only or write;
  - which tools are shared, with whom, and under which share profile.

**Share profiles.** A profile is a narrower credential for one server. It runs a separate instance of the server with its own environment or arguments:

```sh
peerspan tools profile add github acme-api --env-file ~/.config/peerspan/github-acme-api.env
```

The profile lives only on the host, and policy refers to it by name (`github@acme-api`). The secret never enters signed policy, which is distributed through coordination.

## Authorization

### Sharing

```sh
peerspan allow bob --tools github                         # read-only tools of github
peerspan allow bob --tools github@acme-api:create_issue   # a write tool, through a narrower profile
peerspan allow group:eng --resources 'docs:file:///srv/docs/*'
peerspan deny bob --tools github
```

- **Scope of `--tools SERVER`.** It covers that server's read-only tools only. Write tools must be named, and only through a profile, until approval of each call exists (slice 4). `allow` refuses a write tool on a server without a profile, explaining both routes.
- **Stating the reach.** `allow` prints the credential's reach before it signs, for example: "bob can read every repository your GitHub token can."
- **Agents covered.** `--agent NAME` limits the rule to one agent. Without it, the rule applies to every agent with a server of that name, matching how `allow` treats agents today.
- **Existing `allow` is unchanged.** `allow` without `--tools` or `--resources` keeps its current meaning, and never covers tools.
- **Grants.** Grants gain the same targets: `grant create --action tool.call --agent NAME --tools github`.

### Rule shape

There are two new actions, `tool.call` and `resource.read`, and a new kind of rule:

```text
tool_rule
claude-laptop
github@acme-api
group:eng person:5c12…
tool.call
create_issue list_issues
max_input_bytes allow_disconnected max_calls_per_hour
```

The lines are, in order:

1. the rule kind;
2. the agent (`*` for any);
3. the server, with an optional profile;
4. the principals;
5. the actions;
6. the scope: tool names, `readonly`, or resource URI patterns;
7. the bounds.

The receiving host evaluates the intersection of three things:

- the rule's scope;
- the tools that exist in the agent's snapshot;
- the read-only rule for servers without a profile.

### Compatibility

Older verifiers reject unknown actions and rule kinds. That covers the coordinator's `VerifyPolicy`, map application, sibling sync, and directory parsing in both implementations. So a policy with a `tool_rule` would be refused by coordinators and hosts that have not been upgraded.

**Proposed:** a clean break, as with the rename, because there are no public users yet:

- the policy header becomes `peerspan-policy-v2`;
- coordinators are upgraded first, and then hosts;
- a v2 policy without tool rules means the same as v1.

The alternative is a separately signed tool policy statement, carried beside the v1 policy. It keeps old hosts working, but needs a second policy pipeline.

### Self access

Self access currently allows every action with no policy. For tools, that would let any of an owner's machines call any discovered tool on the others.

**Proposed:** self access does not cover `tool.call` or `resource.read` until the owner runs `peerspan allow self --tools SERVER`. This would be a deliberate exception to decision 3 of the launch proposal.

### Enforcement

At acceptance, the receiving host checks:

1. the cited authorization (`grant_id`, `policy`, or `self`), as for tasks;
2. the block list;
3. that the agent's snapshot has the server and tool, or a resource that matches;
4. that a rule scope covers it, including the read-only rule;
5. the input size;
6. the hourly call budget.

The budget is counted per server for each requesting person. A host that is not bound to a person in any network this host shares with it, such as a manually configured grant peer, is counted by its host ID instead.

Authorization is checked again immediately before the server runs the call. A call queued while access was withdrawn is refused, not run.

## Calls

Tool calls can be slow and can have side effects. The system design requires that uncertain side effects are never silently repeated. So a call is a persisted record, like a task.

| Route | Purpose |
| --- | --- |
| `GET /peer/v1/tools` | The tools and resources the caller may use on this host, from the snapshots, with descriptions and input schemas. An optional `?network=ID` limits the listing to policy from that network. The route is not scoped to a network, so a manually configured peer that holds only a grant can still list tools. |
| `POST /peer/v1/calls` | Submit `{call_id, agent, server, kind: tool\|resource, name, arguments \| uri, deadline, origin?}` with one authorization citation. The response is `accepted` or a refusal. |
| `GET /peer/v1/calls/{id}` | The state and, once final, the result. Submitter only; anyone else gets 404. It stays available after revocation, as task status does. |
| `POST /peer/v1/calls/{id}/cancel` | Request cancellation. The server receives MCP `notifications/cancelled`. Submitter only. |

- **States:** `queued`, `running`, `succeeded`, `failed` (the tool returned an error), `rejected`, `expired`, `cancelled`, and `uncertain`.
- **Results.** The MCP `CallToolResult` or `ReadResourceResult`, up to 1 MiB. A larger result is `failed` with `result_too_large`.
- **Deduplication** by `(sender, call_id)`, as for tasks. Retrying a submission never starts a second run.
- **Uncertain outcomes.** If the daemon restarts or the server dies while a call is `running`, the call becomes `uncertain`. It is never run again by either side, and trying again needs a new `call_id`.
- **Bounds.** A deadline of at most 15 minutes, within the authorization's validity. `allow_disconnected` applies as for tasks.

### Records

The receiving host stores, for each call:

- the caller and the origin agent;
- the agent, server, and profile;
- the tool or URI;
- the SHA-256 of the arguments;
- timestamps, the final state, and the result size.

It keeps the arguments and the result for 7 days. The calling host stores its own outbound calls. `peerspan calls list` shows them on either host.

## Agent and owner surface

The shared adapter gains four generic MCP tools:

- `list_tools`: every reachable tool, by address, such as `bob/claude-laptop/github`;
- `call_tool {target, tool, arguments}`: waits up to 60 seconds for a final state, and otherwise returns the `call_id`;
- `read_resource {target, uri}`;
- `call_status`: the state of an earlier call.

Results that arrive later come as a `call_update` event.

Owners get `peerspan tools --remote`, `peerspan call bob/claude-laptop/github list_issues --arguments JSON`, and `peerspan read`.

Mirroring each remote tool as a native MCP tool can come after the generic tools.

## Security analysis

- **A shared tool acts with the owner's credential.** The default limits sharing to read-only tools, and `allow` states the reach. Write tools need a narrower profile, or later approval of each call ([tool credentials](tool-credentials.md)). Even read-only tools reach everything the credential can read.
- **The read-only flag is unverified.** It is a claim made by software the owner installed.
- **Message or task access never implies tool access.** The actions and rule kinds are separate, and `allow` without `--tools` never covers tools.
- **Secrets stay on the host.** Captured values, environment files, profile credentials, and OAuth tokens are never sent to peers or placed in policy, listings, logs, or activity records.
- **The coordinator learns more names.** Listings, arguments, and results travel only on the peer path. Server, profile, and tool names in signed rules become visible to the coordinator; see the open decisions.
- **Results reach only their submitter.** Call status and cancellation are for the submitter only, so a peer that learns a call ID cannot read the result or cancel the call.
- **No isolation.** A malicious or buggy server can do anything the owner's user can. `attach` and the documentation must say so until isolated runtimes exist.

## Slices

1. **Discovery and owner calls.**
   - discovery and snapshots at `attach`;
   - `tools` and `tools profile`;
   - the policy v2 `tool_rule`, the read-only default, and `allow --tools`;
   - the peer listing and call routes, and call records;
   - `peerspan call` and `peerspan read` for stdio servers.

   Then contract additions, and a `conformance/tools.py` suite written by a separate author across all Go/Rust pairings. The suite uses a fixture MCP server that records each execution and marks some tools read-only.
2. **Agent surface.** The four MCP tools and `call_update` events in all three integrations. Live acceptance: Alice's session lists issues through Bob's shared `github`, then Bob runs `deny` and the next call is refused.
3. **Remote OAuth servers.** Peerspan as its own OAuth client, with a one-time browser approval when a server is first shared.
4. **Approval of each call.** This allows write tools on servers without a profile.
5. **Later.**
   - argument rules and profiles for popular servers;
   - larger results as artifacts;
   - streaming;
   - tools in delegation chains;
   - tools that sessions provide;
   - servers in isolated runtimes.

## Decisions

Settled with the owner on 2026-10-16 for the MCP-specific proposal. The later shareable-capability decision supersedes item 10 as the public share model. A capability is scoped to one coherent use case; its exact naming, backing, and enforcement still need design.

1. **Discovery, not registration.** Servers come from the harness configuration. The only explicit step is sharing, through `allow`.
2. **Read-only by default.** Without a narrower credential, a share covers read-only tools, with the reach stated. The owner flagged that this may still be too permissive, so the question stays open below.
3. **`${VAR}` secrets are captured at `attach`.** A per-user environment file is the alternative ([tool credentials](tool-credentials.md#decisions)).
4. **The owner confirms the reach.** The first time a server is shared, `allow` shows the credential's reach and the owner confirms it once.
5. **Compatibility.** Policy v2 is a clean break, with coordinators upgraded first.
6. **Trust is per machine.** Self access covers tools only from hosts the person marks trusted, because an owner's machines differ in access, scope, and role. The trusted hosts are listed in the signed policy. `join` and `network create` ask, defaulting to no, and `trust` and `untrust` change it later. This replaces the opt-in with `allow self --tools` proposed above.
7. **Calls.** Calls are persisted and asynchronous only.
8. **Rule visibility.** Server, profile, and tool names in policy being visible to coordination is accepted for now.
9. **Default budget.** 100 calls per hour per caller and rule, adjustable in review of the contract.
10. **One thing to share: the server** (agreed after the contract's first review). `--tools SERVER` shares its read-only tools and all of its resources, there is no `--resources` flag, and `deny` removes everything for the server. Resource URI patterns and tool grants are left out of slice 1. The `peerspan allow group:eng --resources …` and `grant create --action tool.call …` forms above are superseded.
11. **The environment file is scoped to each server.** A server receives only the variables its own definition names.
