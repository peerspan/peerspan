# Remote tools contract

Roadmap milestone 10, slice 1: discovery and owner calls. The design and its decisions are in the [remote tools proposal](remote-tools-proposal.md) and [credentials for shared tools](tool-credentials.md). This contract builds on the [task contract](task-contract.md) for call records, retry, and polling; on owner access policy in the [coordination contract](coordination-contract.md); and on `attach`, `allow`, and self access in the [launch contract](launch-contract.md).

Status: unimplemented. The owner subsequently chose shareable capabilities scoped to one coherent use case, with defined operations or resources and stated credential reach, as the public abstraction for remote tools and resources. A resource restriction such as a repository is optional. MCP and bounded CLI operations are possible backends. This contract still describes the earlier MCP-server-specific slice. Its whole-server sharing default, public commands, agent tools, discovery, addresses, and share shape need revision before implementation; the call lifecycle and authorization details must be reconciled with that revision.

Slice 1 covers only stdio servers and owner calls from the CLI. The agent-facing MCP tools (slice 2), remote OAuth servers (slice 3), and approval of each call (slice 4) extend it later.

Decided with the owner on 2026-10-16 for the earlier MCP-specific contract:
- shared servers are discovered from harness configuration, never registered;
- a share without a profile covers read-only tools, and `allow` asks the owner to confirm the credential's reach once per server;
- `${VAR}` values are captured at `attach`, and a per-user environment file overrides them;
- the policy format makes a clean break to `peerspan-policy-v2`;
- calls are persisted and asynchronous only;
- server and tool names in policy are visible to coordination;
- self access covers tools only from hosts the person has marked trusted;
- a server receives only the environment-file variables its own definition names;
- in this earlier MCP-specific slice, people share a server, not tools and resources separately: one `--tools` flag covers both, and `deny` removes everything for that server; the public share model is under revision as noted above;
- resource URI patterns and tool grants are left out of slice 1, to keep it small.

## Model

| Term | Meaning |
| --- | --- |
| **Server** | An MCP server in the configuration of an attached agent's harness, named as the harness names it. Its identity is `(agent, name)`. |
| **Profile** | A host-local variant of a server, `SERVER@PROFILE`. It runs a separate instance with its own environment file, and optionally its own arguments. |
| **Snapshot** | The tools and resources a server reported when the host last listed them. Peers see only the snapshot. |
| **Share** | A `tool_rule` in the owner's signed policy that lets principals call tools or read resources of one server or profile. |
| **Call** | One `tools/call` or `resources/read` request from a peer, persisted on both hosts. |

**Names.** Server and profile names match `[a-z0-9][a-z0-9_-]{0,62}`. A harness server whose name does not match is listed with `shareable: false` and the reason `name`.

**IDs.** Call IDs are `call_` followed by 16 random bytes in lowercase hex.

## Discovery

`attach` discovers servers after its session setup succeeds. `peerspan tools refresh [--agent NAME]` repeats discovery for each `attach` profile on this host, or for one agent. Both run in the CLI, which has the user's environment and the project directory. The CLI sends the result to the daemon.

### Configuration read

| Integration | Sources, lowest precedence first |
| --- | --- |
| `claude-code` | top-level `mcpServers` in `~/.claude.json` (user scope); `mcpServers` in `WORKSPACE/.mcp.json` (project scope); `projects[WORKSPACE].mcpServers` in `~/.claude.json` (local scope) |
| `codex` | `[mcp_servers.NAME]` tables in `$CODEX_HOME/config.toml`, default `~/.codex/config.toml` |
| `opencode` | `mcp` in `$XDG_CONFIG_HOME/opencode/opencode.json`, then `WORKSPACE/opencode.json` |

- **Precedence.** A name defined in several sources takes the highest-precedence definition whole; fields are not merged.
- **Workspace.** `WORKSPACE` is the profile's recorded workspace.
- **Unreadable sources.** A source that is missing contributes nothing. A source that does not parse is reported in the output's `errors` and contributes nothing; discovery continues with the rest.
- **Peerspan's own server.** The integration's own Peerspan MCP server entry, which `attach` writes into its private profile, is never discovered.

### Server definitions

Each discovered server is normalized to:

```json
{
  "name": "github",
  "transport": "stdio",
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-github"],
  "env": {"GITHUB_TOKEN": {"source": "literal"}},
  "url": null,
  "source": "claude-code:project"
}
```

- **`transport`.** `stdio`, or `remote` for any URL-based server (Claude Code `http` or `sse`, Codex `url`, OpenCode `type: "remote"`). A `remote` server is listed with `shareable: false` and the reason `remote` until slice 3.
- **`command` and `args`** come from the harness's own shape:
  - Claude Code: `command` and `args`;
  - Codex: `command` and `args`;
  - OpenCode: the first element of `command`, and the rest as `args`.
- **`env`** maps each variable name to how its value is obtained:
  - `literal`: the value is written in the configuration;
  - `captured`: the value is a reference resolved at discovery;
  - `missing`: the value is a reference that could not be resolved.

  Values are sent to the daemon only in the `values` payload (below), and never appear in definitions, listings, output, logs, or activity.
- **`source`** is `INTEGRATION:SCOPE`. The scope is `user`, `project`, or `local` for Claude Code, `user` for Codex, and `global` or `project` for OpenCode.
- **Unsupported fields.** A definition using a field this contract does not list, such as Codex `startup_timeout_ms` or OpenCode `enabled: false`, is still discovered. Fields that change only timing or visibility are ignored. A definition disabled in its harness (OpenCode `enabled: false`, Codex `enabled = false`) is discovered with `shareable: false` and the reason `disabled`.

### References

- **Where they are resolved.** In `command`, `args`, and `env` values, `${NAME}` and `${NAME:-DEFAULT}` are resolved from the CLI's environment at discovery. This applies to Claude Code definitions, and to the same syntax in the other harnesses.
- **What is stored.** A value that contains a reference is resolved and sent in `values`, and its `env` entry is `captured`. Literal `env` values are sent in `values` too, as `literal`. The daemon stores both in `tool_values`, which is the only place it reads them from.
- **Unresolved references.** A reference with no value and no default makes the entry `missing`. The server is then listed with `shareable: false` and the reason `missing_env`, naming the variables.
- **The environment file.** `$XDG_CONFIG_HOME/peerspan/env` (default `~/.config/peerspan/env`) holds `NAME=VALUE` lines, with `#` comments. When it exists, the daemon reads it each time it starts a server. Only variables whose names appear in the server definition's `env` are taken from it; others in the file are ignored for that server. Those values override captured values and literals of the same name. If it is not mode 0600 or stricter, servers start without it and status item 14 reports it.

### Daemon side

| CLI | Local API | Behavior |
| --- | --- | --- |
| (from `attach` and `tools refresh`) | `PUT /v1/agents/{agent_id}/tool-servers` with `{workspace, servers, values}` | Replaces the agent's server definitions and stored values in one transaction, then snapshots each shareable server. `values` maps `SERVER` to `{FIELD: VALUE}`, where `FIELD` is `env.NAME`, `command`, or `args.N`. It holds every `env` value, whether `literal` or `captured`, and every `command` or `args` element that contained a reference, fully resolved. It returns the stored servers with their snapshots. |
| `tools [--agent NAME] [--json]` | `GET /v1/tools` | For each agent: its servers, each with `shareable` and `reason`, its snapshot's tools (marked `read_only`) and resources, its profiles, and the shares in this person's stored policy that name it. |
| `tools refresh [--agent NAME]` | the same `PUT`, for each profile | As `attach` discovery. |
| `tools profile add SERVER PROFILE --env-file PATH [--arg A ...] [--agent NAME]` | `POST /v1/agents/{agent_id}/tool-servers/{server}/profiles` | Records the profile and snapshots it. `PATH` is absolute and read each time the profile's instance starts. `--arg`, repeatable, replaces the server's `args`. `--agent` is needed when more than one agent has the server. |
| `tools profile remove SERVER@PROFILE [--agent NAME]` | `DELETE …/profiles/{profile}` | Removes it. Shares naming it stop matching. |

**Snapshots.**
- **Starting.** The daemon starts the server (or profile instance) as described in [Running servers](#running-servers) and sends MCP `initialize`. It then calls `tools/list` and `resources/list`, following `nextCursor` up to 1,000 entries each, and stops the instance.
- **Bounds.** The whole snapshot must finish within 30 seconds. A failure records `snapshot_error` and keeps the previous snapshot, if any.
- **Stored tool entries.** Each tool is `{name, description, input_schema, read_only}`, where `read_only` is true only when `annotations.readOnlyHint` is `true`.
- **Stored resource entries.** Each resource is `{uri, name, description, mime_type}`.
- **Size.** A snapshot larger than 1 MiB of JSON is a `snapshot_error`.

**Following configuration.** A `PUT` that drops a server deletes its definition, profiles, stored values, and snapshot. Calls already `running` on it finish; new calls to it are refused as unknown. A server or tool that appears in a new definition or snapshot is not shared until a share names it, or names `readonly` and the tool is read-only.

**Output.** `attach` adds `tools: {servers, errors}` to its output. `servers` is `[{name, transport, shareable, reason, tools, read_only_tools}]`, with counts for the last two. Its readable output adds one line, for example `MCP servers found: github, linear (remote, not shareable yet). None are shared.`

## Sharing

### Policy statement, version 2

The policy statement's header line becomes `peerspan-policy-v2`. A v2 statement's lines are:
1. the v1 header fields (`network_id`, `person_public_key`, `version`, `issued_at`, `valid_until`);
2. the v1 rules, unchanged, including the optional third value of the fifth line for `max_artifact_bytes`;
3. for each tool rule, eight lines:
   1. `tool_rule`;
   2. the agent name, or `*`;
   3. the server, `NAME` or `NAME@PROFILE`;
   4. the principals, space-separated;
   5. the actions, space-separated: `tool.call`, optionally followed by `resource.read`;
   6. the scope, space-separated: `readonly`, `*`, or tool names;
   7. `max_input_bytes`, `allow_disconnected`, and `max_calls_per_hour`, space-separated;
   8. `end`;
4. a final line, `trusted` followed by host IDs, space-separated, sorted, possibly none.

The JSON gains `format: 2`, `tool_rules`, and `trusted_hosts`. Each tool rule is `{agent, server, principals, actions, scope, max_input_bytes, allow_disconnected, max_calls_per_hour}`.

**Bounds and validation.**
- **`max_input_bytes`:** 1 to 262,144; it bounds the JSON encoding of `arguments`, or the URI.
- **`max_calls_per_hour`:** 1 to 10,000.
- **Count limits:** at most 64 tool rules, 64 principals per tool rule, 256 scope entries per tool rule, and 64 trusted hosts.
- **Principals:** as for rules.
- **Scope:**
  - `readonly` and `*` stand alone;
  - `*` is valid only with a profile;
  - `resource.read` is allowed only with the scope `readonly` or `*`, and then covers every resource in the snapshot.
- **Trusted hosts:** each must be a host ID.

**Compatibility.**
- **Coordinators and hosts** that implement this contract accept v1 and v2. A v1 policy reads as v2 with no tool rules and no trusted hosts.
- **Signing.** The CLI and daemon renewal always sign v2.
- **Older software** rejects v2, which is the clean break: coordinators are upgraded before hosts, and an owner's hosts upgrade together.
- **Ordering.** Versions, the tie-break hash, renewal, propagation, and storage are unchanged. The tie-break hashes the v2 lines.
- **Directory.** The peer agents route and `GET /v1/directory` are unchanged and never show tool rules.

**Test vector.** Both implementations produced this independently. The owner is the earlier person, in the network of the v1 vector. The policy is version 1, issued `2026-10-10T00:00:00Z`, valid until `2026-10-17T00:00:00Z`. Its contents are:
- the two v1 vector rules;
- tool rule `reviewer`, `github`, `person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2`, actions `tool.call resource.read`, scope `readonly`, `65536 false 100`;
- tool rule `*`, `github@acme-api`, `group:backend`, action `tool.call`, scope `create_issue list_issues`, `4096 true 10`;
- trusted hosts `host_` followed by 64 `b`s and `host_` followed by 64 `a`s, given in that order.

The statement lines are:

```text
peerspan-policy-v2
net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e
bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=
1
2026-10-10T00:00:00Z
2026-10-17T00:00:00Z
rule
reviewer
person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2 group:backend
message.append
65536 false
rule
triage
network
message.append
4096 true
tool_rule
reviewer
github
person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2
tool.call resource.read
readonly
65536 false 100
end
tool_rule
*
github@acme-api
group:backend
tool.call
create_issue list_issues
4096 true 10
end
trusted host_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa host_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

Its `signature` is `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQN3R+JpYFSWwJYDv5TPcPhxvjwoOUVpErPzSlzkRC3DfkaZYNtdsjUSgm0C3KvvXJtNSlozD1UJ894T6bomQvgE=`, and the statement hashes to `84e7e3312f15fa07d06aee1a9bb8953f01d47602ba3439b25bc656a9d4d01729`.

**Encoding details:**
- `allow_disconnected` is `true` or `false`.
- An empty trusted list is the bare line `trusted`, with no trailing space.
- Trusted hosts are sorted in the statement, and duplicates are refused.
- The JSON keys are, in order, `format`, `network_id`, `person_public_key`, `version`, `issued_at`, `valid_until`, `rules`, `tool_rules`, `trusted_hosts`, `signature`. A stored v2 policy keeps `trusted_hosts` sorted.
- A v1 policy is stored in its v1 JSON shape, with no `format`, `tool_rules`, or `trusted_hosts`.
- The actions of a tool rule are `tool.call` or `tool.call resource.read`, each at most once, in that order. A server or profile name not matching the name pattern, or a malformed line, is refused with 400.

### Commands

`allow` and `deny` gain a tool form. The forms without `--tools` are unchanged and never touch tool rules. People share a server; the two actions stay in the policy, and the CLI chooses them.

| Command | Behavior |
| --- | --- |
| `allow PRINCIPAL --tools SPEC [--agent NAME] [--yes] [--calls-per-hour N] [--network ID]` | Sets PRINCIPAL's tool access, described below. |
| `deny PRINCIPAL --tools SERVER[@PROFILE] [--agent NAME] [--network ID]` | Removes PRINCIPAL from tool rules within the agent scope, whatever their actions or scope, and drops empty rules. A bare `SERVER` removes the rules for that server and for every `SERVER@PROFILE`; `SERVER@PROFILE` removes only that profile's rules. It reports `removed` and `note`, as `deny` does. |
| `trust [HOST] [--network ID]` / `untrust HOST [--network ID]` | Adds the host to, or removes it from, `trusted_hosts` in this person's policy for the selected network, then signs and submits that policy's next version. Network selection follows the usual defaulting: `--network` is optional when this host belongs to exactly one network. `HOST` defaults to this host, and for `trust` it must be bound to this person in the selected network. |

**`SPEC`.** It is one of:
- `SERVER` or `SERVER@PROFILE`: scope `readonly`, actions `tool.call resource.read`. This shares the server's read-only tools and all of its resources.
- `SERVER[@PROFILE]:TOOL[,TOOL...]`: those tools, action `tool.call` only.
- `SERVER@PROFILE:*`: scope `*`, actions `tool.call resource.read`. This shares every tool and resource of the profile.

`--tools` may be repeated, and each occurrence makes its own rule.

**What `allow --tools` checks, before signing:**
1. **The server exists here.** Tool shares never default to `*`. Without `--agent`, `allow` makes one rule for each agent on this host whose snapshot has the server as `shareable`, named explicitly, and refuses if there is none. With `--agent NAME`, that agent must be on this host and have the server as `shareable`; a remote, disabled, misnamed, or `missing_env` server is refused with its reason. The server's credentials are therefore always ones whose reach is confirmed on this host. To share another machine's server, run `allow` on that machine.

   `--agent '*'` is accepted explicitly. It makes one `*` rule, and requires `--yes` even after earlier confirmations. It warns that the rule covers servers of that name on every machine of this person, including servers whose credentials were not confirmed on this host.
2. **No write tools without a profile.** Named tools on a server without a profile must be `read_only` in the snapshot. Otherwise `allow` refuses. The error names the tools, and says to add a profile with `tools profile add` or to wait for approval of each call.
3. **The reach is confirmed.** The first time a share names a given `(agent, server, profile)`, `allow` prints the reach and requires confirmation. The prompt reads: `PRINCIPAL can call these tools of SERVER on AGENT, and read its resources, with the credentials it runs with there: TOOLS. Anything those credentials can reach through them, PRINCIPAL can too.` The resources clause appears only when the actions include `resource.read`. Confirmation is `y` at a terminal, or `--yes`. Without a terminal and without `--yes`, `allow` refuses with exit 1. Confirmations are stored per `(agent, server, profile)` on this host, and are not asked again.

**Applying the rule.**
- **Settings:** `max_input_bytes` 65,536, `allow_disconnected` false, and `max_calls_per_hour` 100 or `--calls-per-hour`.
- **Set semantics** follow `allow`, applied once per invocation. For each `(agent, server[@profile])` named by any `--tools` in the invocation, PRINCIPAL is first removed from every tool rule for it. Then each `--tools` occurrence adds PRINCIPAL to the first remaining rule with identical settings, actions, and scope, or appends a new rule. Finally, empty rules are dropped. So `--tools github:foo --tools github:bar` leaves both, while a later `allow` naming github replaces them.
- **Output:** `allow` prints `{policy, principal, rules: [{agent, server, actions, scope}]}`, one entry for each rule it set.

`deny --tools` without `--agent` removes the principal from tool rules for that server under every agent name, `*` included.

**`join` and `network create`** gain `--trusted` and `--untrusted`. When bound to a person and given neither, they ask at a terminal: `Let this machine use tools shared from your other machines? [y/N]`. Without a terminal, the answer is no. A yes adds this host to `trusted_hosts` in the policy of the network being created or joined, in its next signed version. Their output gains `trusted`.

### Authorization

A receiving host bound to person P authorizes a call to its agent N's server S (or profile S@R) when the call cites one of the following:
- **Policy.** P's newest verified policy has a tool rule that matches:
  - the rule's agent is N, or `*` with no tool rule naming N for S;
  - its server is `S` (or `S@R`);
  - its action is the call's;
  - a principal matches the sender, as for rules;
  - the scope covers the tool, or the actions include `resource.read` for a resource.
- **Self.** In some network N, the sender and receiver are both bound to P, and the sender's host ID is in `trusted_hosts` of P's newest verified policy for N. Trust is per network: trusting a host in one network does not cover calls that rely on another. Self covers every shareable server and profile of every agent, and every tool, including tools that are not read-only. Its bounds are `max_input_bytes` 262,144, `allow_disconnected` true, and no hourly budget.

Then, in this order:
1. **Blocks.** The block list applies, except to self.
2. **The snapshot.** The agent's snapshot has the tool, or a resource with that URI. Otherwise 404.
3. **The read-only rule.** Under policy, a tool that is not `read_only` on a server without a profile is refused with 403, whatever the scope says.
4. **Bounds.** Input size within `max_input_bytes`, otherwise 413. The deadline within the policy's `valid_until`. The connected state unless `allow_disconnected`, with 503 when it can recover, as for messages.
5. **Budget.** At most `max_calls_per_hour` accepted calls in the trailing hour, counted per `(rule, caller)`. The caller is the sender's bound person in that network, or else the sender's host ID. A call over the limit is refused with 429 and the limit's name.

Several matching rules combine as for messages: the call is authorized if any applicable rule allows it, under that rule's bounds and budget.

**Rechecks.** Authorization is checked at submission, and again immediately before the call starts. A failure at the start makes the call `rejected`, with the reason `authorization lapsed before start`. Once a call has started, revocation does not stop it; cancellation can.

**Grants.** Grants do not authorize calls in slice 1, and `grant create` does not accept `tool.call` or `resource.read`. A manually configured peer outside any network gets an empty tool listing.

**Citation form.** Exactly one of `policy` (`{person_id, version}`) or `self` (`{person_id}`); a `grant_id` is refused with 400. The CLI cites what the listing reported:
- with `--network ID`, the first `via` entry from that network, after querying the listing with `?network=ID`;
- otherwise, the first `via` entry.

An entry without a usable `via` is refused locally before anything is persisted. The citation, and its network, are stored in the outbound record, and retries reuse them.

## Calls

### Peer routes

| Route | Body | Behavior |
| --- | --- | --- |
| `GET /peer/v1/tools?network=ID` | none | Lists what the authenticated sender may call or read on this host: `[{agent, agent_id, server, profile, tools: [{name, description, input_schema, read_only, via}], resources: [{uri, name, description, mime_type, via}]}]`, from snapshots, filtered by authorization without budgets. `via` lists what authorizes each entry, as `{kind: "self", network_id}`, `{kind: "policy", network_id, person_id, version}`, self before policy, then by network ID. With `network`, only authorizations from that network are evaluated. Without it, every network is evaluated. Sorted by agent, server, and profile. |
| `POST /peer/v1/calls` | exactly `call_id`, `target_agent_id`, `server`, `profile` (string or null), `kind` (`tool` or `resource`), `name` (for `tool`) or `uri` (for `resource`), `arguments` (an object, for `tool`), `deadline`, optional `origin`, and one citation | Authorizes as above, then persists the call as `queued` with a `call.received` activity, and returns 200 with the status record. Idempotent by `(sender, call_id)`: an identical repeat returns the existing record, and a changed one returns 409. |
| `GET /peer/v1/calls/{call_id}` | none | The status record with its `result` once final. Submitter only; anyone else gets 404. It remains available after revocation. |
| `POST /peer/v1/calls/{call_id}/cancel` | `{}` | Sets `cancel_requested`. A `queued` call becomes `cancelled` at once. A `running` call is sent MCP `notifications/cancelled` and becomes `uncertain` with the error `cancel_requested`, unless its result was already received. Submitter only. A repeat, or a cancel of a final call, returns the record unchanged. |

**The status record** is `{call_id, sender_host_id, receiver_host_id, target_agent_id, server, profile, kind, name, uri, state, cancel_requested, error, result_bytes, created_at, started_at, finished_at}`, plus `result` on `GET` once the call is final.

**States.**

| State | Meaning |
| --- | --- |
| `queued` | Persisted; not yet started. |
| `running` | Sent to the server. |
| `succeeded` | The server returned a result: a `CallToolResult` without `isError`, or a `ReadResourceResult`. |
| `failed` | The server returned `isError: true` or a JSON-RPC error, or the call could not run. `error` is `server_start_failed`, `server_exited`, `result_too_large`, `jsonrpc_error`, or `tool_error`. |
| `rejected` | Authorization lapsed before start. |
| `expired` | The deadline passed before the call started. |
| `cancelled` | Cancelled while `queued`, before it was sent to the server. |
| `uncertain` | The call was `running` and ended without a result: the daemon or the server stopped, or the call was cancelled or reached its deadline after it was sent. Whether it took effect is unknown. `error` is `daemon_restarted`, `server_exited`, `cancel_requested`, or `deadline`. Final. |

**Further rules:**
- **Results.** `result` is the server's JSON-RPC `result` object, or `{code, message}` for a JSON-RPC error, at most 1,048,576 bytes encoded. A larger result makes the call `failed` with `result_too_large`, and the result is not stored.
- **Deadlines.** A deadline is at most 15 minutes after submission. A call still `queued` at its deadline becomes `expired`. A call `running` at its deadline is sent `notifications/cancelled` and becomes `uncertain` with the error `deadline`.
- **One rule for running calls without a result.** A running call ends exactly once: with the result, if the server's response is received first, or otherwise `uncertain`, whichever of cancellation, deadline, daemon restart, or server exit happens first. A response that arrives after the call is final is discarded, and noted in the server's log.
- **No re-execution.** A call is never sent to a server twice. At daemon start, every call still `running` becomes `uncertain` with the error `daemon_restarted`.

### Running servers

- **Starting.** The daemon starts a server or profile instance on demand, as a child process with:
  - the definition's `command` and `args` (a profile's `--arg` values replacing `args`), after substituting stored values;
  - an environment built in this order, later entries overriding earlier ones:
    1. the daemon's own `PATH` and `HOME`;
    2. the definition's `env`, with its stored values;
    3. from the environment file, only the variables named in the definition's `env`, as described in [References](#references), never any other entry;
    4. for a profile, every entry of its own `--env-file`, unfiltered, because the owner wrote that file for that instance.
  - the agent's workspace as the working directory.
- **Lifetime.** One instance per `(agent, server, profile)` is shared by all calls. It runs at most 4 calls concurrently, and later calls wait as `queued`. An instance with no calls for 10 minutes is stopped.
- **Start failures.** An instance that does not complete `initialize` within 30 seconds is stopped, and its waiting calls fail with `server_start_failed`.
- **Exits.** If an instance exits, its running calls become `uncertain` with the error `server_exited`, its queued calls start a new instance, and a server that fails to start 3 times in 10 minutes fails its queued calls.
- **Protocol.** The MCP client speaks protocol version `2025-06-18`, and accepts the server's negotiated version if it is one this implementation supports. It sends `tools/call` with `{name, arguments}`, or `resources/read` with `{uri}`.
- **stderr.** A server's standard error is appended to `STATE/tool-logs/AGENT_ID/SERVER[@PROFILE].log`, mode 0600, truncated to its last 1 MiB at each start.

### Records

The receiver stores the request, the status record, and the result. The request's `arguments` and the result are deleted 7 days after the call becomes final, and the status record and `arguments_sha256` remain.

### Owner CLI

| CLI | Local API | Behavior |
| --- | --- | --- |
| `tools remote [PERSON[/AGENT]] [--network ID] [--json]` | `GET /v1/remote-tools?target=…` | Fetches `GET /peer/v1/tools` from each matching host in the directory, at most 8 at once with a 5-second timeout each, and prints what this host may call. |
| `call TARGET TOOL [--arguments JSON] [--deadline T] [--wait D] [--network ID]` | `POST /v1/calls` | `TARGET` is `PERSON/AGENT/SERVER[@PROFILE]` or `HOST_ID/AGENT/SERVER[@PROFILE]`, resolved as below. Persists the outbound call and submits it, with retries as for tasks. It then waits up to `--wait` (default 60 seconds, at most 15 minutes) for a final state, and prints the local record. The exit code is 0 for `succeeded`, 1 for other final states, and 3 if still pending. |
| `read TARGET URI [same options]` | `POST /v1/calls` | The same, for `resource.read`. |
| `calls list [--after N] [--limit N]` | `GET /v1/calls` | Outbound calls in insertion order, paged as tasks are. |
| `calls received [--after N] [--limit N]` | `GET /v1/calls/received` | Calls received by this host. |
| `calls inspect --peer HOST ID` | `GET /v1/calls/{peer}/{id}` | The local outbound record. |
| `calls cancel --peer HOST ID` | `POST /v1/calls/{peer}/{id}/cancel` | Sends cancellation, resent while uncertain, as for tasks. |

**Resolving a target.** The directory lists only agents with message or task access, so `call` and `read` do not use it:
- **`HOST_ID/…`** names a known host directly: a member of any network this host shares with it. It is the form for picking one host when a person's agent name is ambiguous.
- **`PERSON/…`** resolves PERSON (a label or person ID) through each network's map to the hosts bound to that person, limited to `--network` when given. It fetches `GET /peer/v1/tools` from each of those hosts, with `?network=ID` when `--network` is given, at most 8 at once with a 5-second timeout each, and keeps the hosts whose listing has AGENT with that server and profile.
- **Outcomes.** Exactly one match is the target. None is an error that lists the hosts that did not answer. More than one is an error listing the `HOST_ID/AGENT/SERVER` form of each. The resolved host ID and agent ID are stored in the outbound record, so retries and polling never resolve again.

`tools remote` uses the same resolution, and lists every match instead of choosing one.

**The outbound record** is `{peer_host_id, request, submit_state, status, result, cancel_state, attempts, next_attempt_at, error, status_queries}`, with the meanings of the task record. The daemon polls `GET /peer/v1/calls/{id}` for each accepted call that is not final, with backoff from 1 to 60 seconds, sharing the task polling slots, and stores the final status and result.

### Status

Two additions to `GET /v1/status`:
- `tools: {servers, shared_servers, calls_running}`.
- Attention item **14**, `tool_server_failing`, after item 13. It covers:
  - a server whose latest snapshot failed;
  - an instance that failed to start in the last 24 hours;
  - an environment file with permissions that are too open;
  - a server that answered with a JSON-RPC error whose message suggests authentication (case-insensitive `auth`, `401`, `403`, or `token`) in the last 24 hours.

  The subject is `AGENT_NAME/SERVER[@PROFILE]`, or `env` for the environment file. The command is `peerspan tools refresh --agent AGENT_NAME`, or `chmod 600 PATH`.

## Persistence

Database version 16 adds:

```sql
CREATE TABLE tool_servers (agent_id TEXT NOT NULL REFERENCES agents(id), name TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, name));
CREATE TABLE tool_values (agent_id TEXT NOT NULL, server TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(agent_id, server, field));
CREATE TABLE tool_profiles (agent_id TEXT NOT NULL, server TEXT NOT NULL, name TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, server, name));
CREATE TABLE tool_confirmations (agent_id TEXT NOT NULL, server TEXT NOT NULL, profile TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, server, profile));
CREATE TABLE received_calls (sender TEXT NOT NULL, call_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id));
CREATE TABLE outbound_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, call_id));
PRAGMA user_version = 16;
```

- **Records** are JSON. `tool_servers.record` holds the definition and snapshot. `tool_confirmations.profile` is empty for none.
- **Version checks.** Older binaries reject version 16, and version 16 binaries reject version 17.

**New activity kinds:**
- `tools.discovered` (subject: agent ID);
- `tools.snapshot_failed` (subject: `AGENT_ID/SERVER`);
- `tools.profile_added` and `tools.profile_removed`;
- `call.received`, `call.started`, `call.finished`, and `call.cancel_requested` (subject: the sender host ID and the call ID);
- `call.submitted` and `call.updated` (subject: the peer host ID and the call ID).

Activity never includes arguments, results, or secret values.

## Local API and clarifications

Settled on 2026-10-16, after both implementations and the suite's author compared readings. Where this section and an earlier one differ, this section applies. The local API is shared between CLI and daemon, so mixed Go/Rust pairings depend on these shapes exactly.

### Discovery

- **`PUT /v1/agents/{agent_id}/tool-servers` request.**
  - The body is `{workspace, servers, values}`. `values` may be absent.
  - Each element of `servers` has exactly the definition fields `name`, `transport`, `command`, `args`, `env`, `url`, and `source`, plus an optional boolean `disabled`. Unknown fields are refused with 400.
  - The daemon computes `shareable` and `reason`. Reasons, in precedence order, are `name`, `remote`, `disabled`, and `missing_env`.
  - A stdio entry without a command is reported by the CLI in `errors`, and is not sent.
  - In `values`, `env.NAME` is accepted only for entries whose source is `literal` or `captured`.
- **`PUT` response.** It is the agent object below, returned once snapshots finish, so `tools refresh` returns only after them.
- **`GET /v1/tools` response.** It is `{agents: [AGENT]}`, sorted by agent name, where `AGENT` is `{agent: {id, name}, workspace, servers: [SERVER]}`.
- **`SERVER`** is `{name, transport, command, args, env, url, source, disabled, shareable, reason, missing_env, tools, resources, snapshot_at, snapshot_error, start_failed_at, auth_error_at, confirmed, profiles, shares}`, where:
  - `missing_env` is the list of referenced variable names that could not be resolved, such as `FX_MISSING_VAR`, never the `env` keys;
  - `tools` and `resources` are `[]` before the first snapshot;
  - `confirmed` is a boolean for the base server;
  - `shares` lists the tool rules naming the server, each as the tool rule plus `network_id`.
- **`PROFILE`** is `{name, env_file, args, created_at, tools, resources, snapshot_at, snapshot_error, start_failed_at, auth_error_at, confirmed}`.
- **Missing references.** A `missing` reference keeps the server `missing_env` even when the environment file has that name, because discovery resolves from the CLI's environment.
- **Peerspan's own entries.** Discovery skips server names `peerspan` and `peerspan_` followed by 32 hex digits.
- **OpenCode.** It reads `environment`, falling back to `env`. Its files are parsed as strict JSON.
- **Defaults.** `${VAR:-D}` uses `D` when `VAR` is unset or empty.
- **Entry cap.** Following `nextCursor` beyond 1,000 entries is a `snapshot_error` (`too_many_entries`).
- **Listing calls.** `tools/list` and `resources/list` are each called when the server's `initialize` result has that capability key, whatever its value.
- **Dropped servers.** A dropped server loses its reach confirmations, so a returning server asks again.
- **`attach` output.** It is `tools: {servers: [{name, transport, shareable, reason, missing_env, tools, read_only_tools, snapshot_error}], errors: [{source, path, server, error}]}`, where `tools` and `read_only_tools` are counts, and `path` and `server` may be null. The readable line goes to stderr, and its wording is not shared.

### Profiles and confirmations

- **Adding a profile.** `POST /v1/agents/{agent_id}/tool-servers/{server}/profiles` takes `{name, env_file, args}`, where `args` is optional and, when given, an array. `null` is refused.
  - The server must be `shareable`, and `env_file` must exist.
  - It returns 201 with `PROFILE` plus `agent_id` and `server`. An identical repeat returns 200 with the existing profile, and a different one returns 409.
- **Recording a confirmation.** `POST /v1/agents/{agent_id}/tool-servers/{server}/confirmations` takes `{profile}`, which is null for the base server. It returns 200 with `{agent_id, server, profile, confirmed_at}`.
- **Reading confirmations.** They appear as `confirmed` in `GET /v1/tools`. There is no other confirmation route.

### Sharing output and prompts

- **Prompt text.** Each statement is the contract's sentence. When the actions include `resource.read`, it is followed by ` PRINCIPAL can also read every resource it offers.` An empty tool list reads `(none yet)`.
- **Asking.** `allow` prints every statement to stderr, then asks once: `Share? [y/N] `. It reads one line from stdin, and `y` or `yes` agrees. "At a terminal" means stdin is a terminal. Declining, or no terminal without `--yes`, exits 1 with nothing signed.
- **`--agent '*'`.** It prints its warning instead of a statement, and always needs `--yes`.
- **`trust` and `untrust` output.** It is `{policy, host, trusted, changed}`. When nothing changes, `changed` is false and no version is signed.
- **`join` and `network create`.** They always output `trusted` as a boolean, and sign the trust change at once. If that signing fails, the command still succeeds, with `trusted: false` and `trusted_error`.
- **Notes.** The wording of `deny`'s `note`, and of all refusals, is not shared.

### Calls

- **`POST /v1/calls` request.** It takes `{target, kind, name, uri, arguments, deadline, network, call_id}`. A null field is treated as absent.
  - `deadline` is RFC3339. The CLI's `--deadline` also accepts a duration, which it converts.
  - The daemon refuses a deadline that is in the past or more than 15 minutes ahead with 400 before persisting.
  - It returns 200 with the outbound record.
- **Targets.** `target` is `PERSON|HOST_ID/AGENT/SERVER[@PROFILE]`.
  - Resolution failures are 404 `{code: "not_found", error, unanswered: [{host_id, error}]}` or 409 `{code: "ambiguous", error, candidates: [ADDRESS]}`.
  - `unanswered` and the other failures refuse the call with nothing persisted.
- **`GET /v1/calls`** returns `[{sequence, call}]`.
- **`GET /v1/calls/received`** returns `[{sequence, request, status}]`.
- **The outbound record.** Its keys are `peer_host_id, target, network_id, request, submit_state, status, result, cancel_state, attempts, next_attempt_at, error, status_queries`. The request never carries `grant_id`.
- **`GET /v1/remote-tools?target=…&network=…`** returns `{entries: [{host_id, address, agent, agent_id, server, profile, tools, resources}], unanswered: [{host_id, error}]}`.
  - `target` accepts `PERSON|HOST_ID[/AGENT[/SERVER[@PROFILE]]]`.
  - Without a target, it covers the members of the selected networks only.
- **`--wait`** takes `N`, `Ns`, or `Nm`, from 0 to 15 minutes, default 60 seconds.
- **Submission outcomes.** 400, 403, 404, 409, 413, and 429 are final `rejected`. Anything else stays `unknown` and is retried.
- **Deadline at the receiver.** It must be in the future, and at most 15 minutes plus 1 minute of clock skew after receipt. Otherwise the call is refused with 400 `invalid`.
- **Recheck before start.** A recoverable failure (503-type) leaves the call `queued`, rechecked at least every 5 seconds until its deadline, when it becomes `expired`. Any other failure rejects it with `authorization lapsed before start`.
- **Budget key.** The budget is counted per rule identity and caller. The rule identity covers the network, owner, agent, server, actions, scope, and bounds, but not the principals, so adding or removing principals does not reset anyone's budget.
- **`*` rules.** A rule naming the agent hides `*` rules only for the same server string; `S` and `S@R` are distinct.
- **Self.** It needs the person's policy for that network to be within its validity window.
- **Resource calls.** A resource call must name a URI present in the snapshot.
- **Wire body.**
  - A resource call has no `name` or `arguments` keys, and a tool call has no `uri` key.
  - `profile` is always present.
  - `grant_id` is never sent.
  - The POST response's state is `queued`.
- **Error bodies.**
  - 413 is `{code: "too_large", error}`.
  - 429 is `{code: "limit", error, limit: "max_calls_per_hour"}`.
- **Repeated start failures.** After 3 start failures in 10 minutes, queued calls fail with `server_start_failed`.
- **Activity subjects** for `call.*` are `HOST_ID/CALL_ID`, using the sender for received calls and the peer for outbound calls.
- **Size limits.**
  - Peer response bodies of `GET /peer/v1/tools` and `GET /peer/v1/calls/{id}` may be up to 4 MiB. Other peer routes keep their limits.
  - Local API responses may be up to 16 MiB.

## Verification

`conformance/tools.py` is written from this contract by an author independent of both implementations. It runs across all Go/Rust CLI and daemon pairings, with `--probe`, the Go coordinator, and OpenSSH. It uses a fixture MCP stdio server, provided with the suite, that:
- marks some tools read-only;
- records every execution to a file;
- can sleep, fail, return `isError`, return oversized results, exit mid-call, and report the environment variables it was given, by name only.

It covers:
- **Discovery:**
  - each harness's sources and precedence, from fixture configuration files under a temporary `HOME`;
  - remote, disabled, and invalidly named servers marked not shareable;
  - `${VAR}` and `${VAR:-DEFAULT}` captured, and missing ones reported;
  - the environment file overriding captured values only for variables the definition names, other variables not reaching the server, and the file ignored when too open (item 14);
  - values never present in output, listings, activity, or the peer route;
  - a server dropped from configuration refusing new calls;
  - a new tool not shared until named, except under `readonly` when it is read-only.
- **Snapshots:** the 30-second bound, `snapshot_error` keeping the previous snapshot, and pagination.
- **Policy v2:**
  - signing and verifying across implementations, and the generated test vector;
  - a v1 policy accepted and read with no tool rules;
  - coordinator acceptance;
  - sibling propagation of v2;
  - an equal-version tie-break over v2 lines.
- **`allow --tools`:**
  - each `SPEC` form;
  - one rule per local agent with the server when `--agent` is omitted, refusal when no local agent has it, and `--agent '*'` requiring `--yes` with its warning;
  - refusal of write tools without a profile, and of a named agent's server that is not `shareable`;
  - reach confirmation at a terminal, with `--yes`, refused without either, and not asked twice;
  - set semantics;
  - `deny --tools` removing rules for the server whatever their actions or scope, a bare server also removing its profiles' rules, and a profile removing only its own;
  - repeated `--tools` for one server in one invocation keeping every requested scope;
  - `SERVER` sharing read-only tools and all resources, named tools sharing no resources, and the reach prompt's resources clause.
- **`trust`/`untrust`**, with network selection and per-network trust, and the `join` prompt and flags.
- **Authorization:**
  - by policy, and by self from a trusted host; a grant citation refused with 400;
  - self refused from an untrusted host of the same person;
  - another person's host never covered by self;
  - the read-only rule under policy, but not under self;
  - blocks, except under self;
  - the budget, counted per person and per host for unbound senders;
  - 413 for oversized input;
  - lapsed authorization before start recorded as `rejected`.
- **Calls:**
  - the full lifecycle for tools and resources;
  - `isError` and JSON-RPC errors;
  - `result_too_large`;
  - duplicate and conflicting submission;
  - a lost submit response recovered by retry with exactly one execution recorded by the fixture;
  - expiry before start;
  - cancellation queued (`cancelled`) and running (`uncertain`), and a running call at its deadline (`uncertain`);
  - a daemon restart during a running call producing `uncertain` and no re-execution;
  - a server exit producing `uncertain` for running calls;
  - concurrency capped at 4 per instance;
  - idle stop.
- **Routes:** `GET /peer/v1/tools` filtered by authorization, and empty for a manually configured peer outside any network; status and cancel from a non-submitter returning 404.
- **Owner CLI:**
  - `tools`, `tools remote`, `call` and `read` exit codes, and `calls` listings;
  - target resolution for an agent with only tool access, by person and by host ID, and the ambiguous and not-found errors;
  - `--network` scoping: a tool authorized only in another network of the same person and host is neither listed nor cited, and `via` ordering decides the citation otherwise.
- **Literal values:** a server configured with a literal token starts with it, and the token appears nowhere else.
- **Profiles:** a profile instance receiving its own environment file and arguments, and a share of a profile not matching the bare server.
- **Status:** item 14 for each cause.
- **Migration:** from version 15 to version 16.

## Owner review points

- **Self covers write tools.** Self from a trusted host covers write tools without a profile, on the reasoning that trusting a machine means trusting it with your credentials. Agreed on 2026-10-16.
- **The person key can mark any host trusted.** Any host holding the person key can sign a policy that marks itself trusted. Untrusted marking protects only against hosts that do not hold the key, for example hosts bound through ssh-agent forwarding. `join` on an untrusted machine prints this. Agreed on 2026-10-16.
- **Reach confirmations are recorded only locally.** Because tool shares name agents on the host where `allow` runs, the confirmation is always made on the machine whose credentials are shared. Agreed on 2026-10-16.
