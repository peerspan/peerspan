# Remote tools and resources

Status: proposal drafted on 2026-10-16 for owner review. Nothing here is decided or implemented. Choices marked **proposed** are recommendations; the [open decisions](#open-decisions) list what the owner settles before a contract is written. This would be roadmap milestone 10. It builds on owner access policy (milestone 2b), tasks (milestone 6), and the [access model](access-model.md).

## Problem

The system design requires three collaboration capabilities. Task delegation ships, and peer conversation ships as messages and replies. The third, "discover and use explicitly permitted tools or resources on another host", does not exist:

- **Nothing can be shared except agents.** A host registers agents. The `agents.capabilities` column is local metadata that is never served to peers and, by the host contract, grants nothing.
- **Policy cannot name a tool.** The only actions are `message.append`, `task.submit`, and `task.delegate`, and the only scope in a rule is the agent name.
- **The only way to use something on Bob's machine is to ask Bob's agent.** Alice's agent must delegate a task and hope Bob's model calls the right tool with the right arguments. The result is model output, not the tool's result. Bob cannot grant "create issues in this repository" without also granting "talk to my agent".
- **Everything is asynchronous and text-only.** Tasks carry at most 64 KiB of text in and out. Peer requests are bounded at 1 MiB and 8 seconds, without streaming.

## Goals and non-goals

**Goals:**

- An owner shares a specific MCP server on their host, and chooses which of its tools and resources are shared.
- Owner-signed policy grants calls to persons, groups, or the network for each shared capability and each tool. The receiving host enforces it, exactly as it does for messages and tasks.
- An authorized caller, whether an agent through MCP or an owner through the CLI, lists what it may use, calls a tool, and reads a resource. It receives the tool's own structured result.
- Every call is recorded on both hosts. A call whose outcome is uncertain is reported as uncertain and never repeated automatically.
- No agent session needs to be running on the receiving host.

**Non-goals for the first slices:**

- Tools exposed by a running agent session, such as Claude Code's own tools. No integration can expose them today.
- Isolation of the tool process. Shared tools run as the owner's user, with the owner's local permissions, until isolated runtimes exist.
- Streaming results and MCP prompts.
- Calls inside delegation chains.
- Approval of individual calls. This is designed below, but as a later slice.

## What is shared: host capabilities

**Proposed:** a *capability* is an MCP server that the owner registers on their host, with a name unique on that host.

```sh
peerspan capability add github --tools create_issue,list_issues \
  -- npx -y @modelcontextprotocol/server-github
peerspan capability add docs --resources 'file:///srv/docs/*' -- mcp-docs-server
peerspan capability list
peerspan capability remove github
```

- The daemon starts the server as a child process over stdio on first use, and stops it after 10 minutes idle. A `--url` form for a local streamable-HTTP MCP server is a possible later addition. Environment comes from `--env-file`, which is never sent to peers.
- **The shared set is explicit.** `--tools` and `--resources` list exactly which tools, and which resource URI patterns, any peer can ever reach. A tool the server adds later is not shared until the owner adds it. `--tools '*'` is accepted only with `--all-tools`, and `status` warns while it is set.
- Each capability record stores the owner person, the command, the shared tool and resource lists, and a snapshot of their MCP descriptions and input schemas, taken at `add` and on `capability refresh`. The snapshot is what peers see, so a server cannot change what callers are shown without the owner refreshing it.
- Capabilities belong to the host, not to an agent. This matches the design's separate "shared capability" entity. An agent registered on the same host gains nothing from it.

Alternative: share an agent session's own tools. That needs each harness to expose its tool list and execute calls on request, and no integration can do either today ([integration investigation](agent-integration-investigation.md)). It is deferred.

## Authorization

### Actions and scope

**Proposed:** two new actions, `tool.call` and `resource.read`, and a second kind of rule that names a capability instead of an agent:

```text
capability_rule
github
group:eng person:5c12…
tool.call
create_issue list_issues
max_input_bytes allow_disconnected max_calls_per_hour
```

- The fourth line, the scope, lists the shared tool names, or resource URI patterns for `resource.read`. `*` means everything the capability shares.
- A scope never widens what `capability add` shares. The host evaluates the intersection of the two.
- CLI: `peerspan allow group:eng --capability github --tools create_issue` and `peerspan deny group:eng --capability github`. `allow` without `--capability` keeps its current meaning and never covers capabilities.
- Grants gain the same pair: `grant create --action tool.call --capability github --tools create_issue`.

### Compatibility

Older verifiers reject unknown actions and rule kinds. That covers the coordinator's `VerifyPolicy`, map application, sibling sync, and directory parsing in both implementations. A policy carrying a `capability_rule` would therefore be refused by un-upgraded coordinators and hosts.

**Proposed:** a clean break, as with the rename, because there are no public users yet:

- the policy header becomes `peerspan-policy-v2`;
- coordinators are upgraded before hosts, and hosts are re-released together;
- a v2 policy without capability rules is identical in meaning to v1.

The alternative is a separately signed capability policy statement, distributed and synced beside the v1 policy. It keeps old hosts working, at the cost of a second policy pipeline in coordination, sync, and both implementations.

### Self access

Self access currently allows every action with no policy. Applied to capabilities, every machine an owner binds would be able to run every shared tool on every other machine they own.

**Proposed:** self access does not cover `tool.call` or `resource.read`. An owner who wants their own machines to use a capability runs `peerspan allow self --capability NAME`. This is a deliberate exception to decision 3 of the launch proposal.

### Enforcement

The receiving host checks the following in order, at acceptance:

1. the cited authorization (`grant_id`, `policy`, or `self`), exactly as for tasks;
2. the block list;
3. that the capability exists and shares the tool or resource;
4. that a rule scope covers it;
5. input size;
6. the per-caller hourly call budget, counted per requesting person and capability.

The host checks again immediately before executing. A call queued while access is withdrawn is refused, not run.

## Calls

Tool calls can be slow and can have side effects. Peer requests are bounded at 8 seconds, and the system design requires that uncertain side effects are never silently repeated. **Proposed:** a call is a persisted record, like a task, and not a synchronous request.

### Peer routes

| Route | Purpose |
| --- | --- |
| `GET /peer/v1/networks/{id}/capabilities` | List the capabilities, tools, and resources the caller may use, with descriptions and input schemas from the owner's snapshot. Only entries the caller is authorized for are returned. |
| `POST /peer/v1/calls` | Submit `{call_id, capability, kind: tool\|resource, name, arguments \| uri, deadline, origin?}` plus one authorization citation. The response is `accepted` or a refusal. |
| `GET /peer/v1/calls/{id}` | Read the state and, when finished, the result. |
| `POST /peer/v1/calls/{id}/cancel` | Request cancellation; MCP `notifications/cancelled` is sent to the server. |

- **Separate listing route.** Discovery uses its own route rather than extending the peer agents route, so directory entries keep their current exact shape for existing callers.
- **States:** `queued`, `running`, `succeeded`, `failed` (the tool returned an error result), `rejected`, `expired`, `cancelled`, and `uncertain`.
- **Results.** The result is the MCP `CallToolResult` or `ReadResourceResult`, up to 1 MiB inline. Larger results are refused as `failed` with `result_too_large` in the first slice. Carrying them as artifacts is a later option.
- **Deduplication** uses `(sender, call_id)`, as for tasks. Submission is therefore retried automatically and safely: a repeat returns the existing record and never starts a second execution.
- **Uncertain outcomes.** If the daemon restarts or the server dies while a call is `running`, the call becomes `uncertain`. It is never re-executed by either side. The caller sees `uncertain`, and repeating the call needs a new `call_id`. MCP `readOnlyHint` and `idempotentHint` annotations are hints from the server and are not trusted for this.
- **Bounds.** Each call carries a deadline of at most 15 minutes, bounded by the authorization's validity. `allow_disconnected` applies as it does for tasks.

### Records

- **Receiving host:** stores each call with its caller, origin agent, capability, tool or URI, the SHA-256 of the arguments, timestamps, final state, and result size. It keeps the arguments and result for 7 days, the same retention as artifacts.
- **Calling host:** stores its outbound calls and their states.
- **Inspection:** `peerspan calls list` on either host.

## Agent and owner surface

**Proposed, generic tools first.** The shared adapter gains three MCP tools:

- `list_capabilities`: the peer listing for every reachable host, with addresses such as `bob/github`;
- `call_tool {target, tool, arguments}`: submits the call and waits up to 60 seconds for a final state, otherwise returns the `call_id`;
- `read_resource {target, uri}`.

`call_status` follows a pending call. Results that finish later arrive as a `call_update` event, as task updates do today.

Owners get `peerspan capabilities`, `peerspan call bob/github create_issue --arguments JSON`, and `peerspan read bob/docs URI`.

Alternative: mirror each remote tool as a native MCP tool, such as `bob__github__create_issue`, with `tools/list_changed` when the listing changes. It looks better to models, but tool lists can grow without bound and every change needs a client refresh. This can come after the generic tools.

## Security analysis

- **A shared tool acts with the owner's local authority.** Sharing `github` shares the owner's GitHub token for those tools. That is why the shared set is explicit, the default is nothing, and listings show only the owner's snapshot. `status` lists every shared tool and who may call it.
- **Message or task access never implies tool access.** The actions and rule kinds are separate, and `allow` without `--capability` never covers capabilities.
- **The coordinator learns nothing new.** Listings, arguments, and results travel only on the peer path. The coordinator distributes the signed policy, which already names principals. Capability names and tool names in rules become visible to it, which is a change from today; see the open decisions.
- **Callers cannot widen scope.** A call names one capability and one tool, and the host intersects the rule scope with what the owner shares.
- **Uncertain side effects stay visible** to both owners, and are never retried.
- **No isolation.** A malicious or buggy MCP server can do anything the owner's user can. The docs and the `capability add` output must say so plainly until isolated runtimes exist.

## Slices

1. **Capabilities and owner calls.** The capability registry and CLI, the policy v2 `capability_rule`, the two actions, the peer listing and call routes, call records, and `peerspan call` and `read`. Contract additions, then a `conformance/capabilities.py` suite written by a separate author, across all Go/Rust pairings, with a fixture MCP server that records each execution.
2. **Agent surface.** `list_capabilities`, `call_tool`, `read_resource`, `call_status`, and `call_update` events in the shared adapter and all three integrations. Live acceptance: Alice's Claude Code session creates an issue through Bob's shared `github` capability, then Bob denies it and the next call is refused.
3. **Approval-required calls.** A rule flag `approve`. Calls wait in `awaiting_approval` until the owner runs `peerspan calls approve ID`, or the owner's attached session approves through a new MCP tool.
4. **Later.** Larger results as artifacts, streamed progress, tools in delegation chains, session-exposed tools, and capabilities in isolated runtimes.

Slice 1 alone would give the launch demonstration "an explicitly shared capability, a request, and a result" that does not depend on model behavior.

## Open decisions

1. **What a capability is.** Host-registered MCP servers (proposed), or also session tools from the start.
2. **Compatibility.** Policy v2 as a clean break (proposed), or a separate capability policy statement.
3. **Self access.** Excluded from capabilities unless allowed (proposed), or covered like everything else.
4. **Call model.** Persisted asynchronous calls with a 60-second wait in the MCP tool (proposed), or a synchronous route for short calls as well.
5. **Explicit tool lists.** Required, with `--all-tools` as the escape (proposed), or `*` by default.
6. **Rule visibility.** Capability and tool names in policy are visible to the coordinator. Accept this, or hash the names in signed rules.
7. **Default budget.** For example, 100 calls per hour per caller and capability, like the session send cap.
8. **Launch scope.** Whether slice 1, or slices 1 and 2, gate the public launch (option B in the [launch plan](../../mesh-new/docs/launch-plan.md)).
