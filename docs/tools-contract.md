# Remote tools contract

Roadmap milestone 10, slice 1: discovery and owner calls. The design and its decisions are in the [remote tools proposal](remote-tools-proposal.md) and [credentials for shared tools](tool-credentials.md). This contract builds on the [task contract](task-contract.md) for call records, retry, and polling; on owner access policy in the [coordination contract](coordination-contract.md); and on `attach`, `allow`, and self access in the [launch contract](launch-contract.md).

Slice 1 covers only stdio servers and owner calls from the CLI. The agent-facing MCP tools (slice 2), remote OAuth servers (slice 3), and approval of each call (slice 4) extend it later.

Decided with the owner on 2026-10-16:
- shared servers are discovered from harness configuration, never registered;
- a share without a profile covers read-only tools, and `allow` asks the owner to confirm the credential's reach once per server;
- `${VAR}` values are captured at `attach`, and a per-user environment file overrides them;
- the policy format makes a clean break to `peerspan-policy-v2`;
- calls are persisted and asynchronous only;
- server and tool names in policy are visible to coordination;
- self access covers tools only from hosts the person has marked trusted.

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

  Values never appear in definitions, listings, output, logs, or activity.
- **`source`** is `INTEGRATION:SCOPE`. The scope is `user`, `project`, or `local` for Claude Code, `user` for Codex, and `global` or `project` for OpenCode.
- **Unsupported fields.** A definition using a field this contract does not list, such as Codex `startup_timeout_ms` or OpenCode `enabled: false`, is still discovered. Fields that change only timing or visibility are ignored. A definition disabled in its harness (OpenCode `enabled: false`, Codex `enabled = false`) is discovered with `shareable: false` and the reason `disabled`.

### References

- **Where they are resolved.** In `command`, `args`, and `env` values, `${NAME}` and `${NAME:-DEFAULT}` are resolved from the CLI's environment at discovery. This applies to Claude Code definitions, and to the same syntax in the other harnesses.
- **What is stored.** A value that contains a reference is stored, fully resolved, as a **captured value** for `(agent, server, field)`, and its `env` entry is `captured`.
- **Unresolved references.** A reference with no value and no default makes the entry `missing`. The server is then listed with `shareable: false` and the reason `missing_env`, naming the variables.
- **The environment file.** `$XDG_CONFIG_HOME/peerspan/env` (default `~/.config/peerspan/env`) holds `NAME=VALUE` lines, with `#` comments. When it exists, the daemon reads it each time it starts a server. Its values override captured values and literals of the same name in `env`. If it is not mode 0600 or stricter, servers start without it and status item 14 reports it.

### Daemon side

| CLI | Local API | Behavior |
| --- | --- | --- |
| (from `attach` and `tools refresh`) | `PUT /v1/agents/{agent_id}/tool-servers` with `{workspace, servers, captured}` | Replaces the agent's server definitions and captured values in one transaction, then snapshots each shareable server. `captured` maps `SERVER` to `{FIELD: VALUE}`, where `FIELD` is `env.NAME`, `command`, or `args.N`. It returns the stored servers with their snapshots. |
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

**Following configuration.** A `PUT` that drops a server deletes its definition, profiles, captured values, and snapshot. Calls already `running` on it finish; new calls to it are refused as unknown. A server or tool that appears in a new definition or snapshot is not shared until a share names it, or names `readonly` and the tool is read-only.

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
   5. the action, `tool.call` or `resource.read`;
   6. the scope, space-separated: `readonly`, `*`, tool names (for `tool.call`), or URI patterns (for `resource.read`);
   7. `max_input_bytes`, `allow_disconnected`, and `max_calls_per_hour`, space-separated;
   8. `end`;
4. a final line, `trusted` followed by host IDs, space-separated, sorted, possibly none.

The JSON gains `format: 2`, `tool_rules`, and `trusted_hosts`. Each tool rule is `{agent, server, principals, action, scope, max_input_bytes, allow_disconnected, max_calls_per_hour}`.

**Bounds and validation.**
- **`max_input_bytes`:** 1 to 262,144; it bounds the JSON encoding of `arguments`, or the URI.
- **`max_calls_per_hour`:** 1 to 10,000.
- **Count limits:** at most 64 tool rules, 64 principals per tool rule, 256 scope entries per tool rule, and 64 trusted hosts.
- **Principals:** as for rules.
- **Scope:**
  - `readonly` and `*` stand alone;
  - `*` is valid only with a profile, or for `resource.read`;
  - URI patterns are literal URIs, or a prefix ending in `*`.
- **Trusted hosts:** each must be a host ID.

**Compatibility.**
- **Coordinators and hosts** that implement this contract accept v1 and v2. A v1 policy reads as v2 with no tool rules and no trusted hosts.
- **Signing.** The CLI and daemon renewal always sign v2.
- **Older software** rejects v2, which is the clean break: coordinators are upgraded before hosts, and an owner's hosts upgrade together.
- **Ordering.** Versions, the tie-break hash, renewal, propagation, and storage are unchanged. The tie-break hashes the v2 lines.
- **Directory.** The peer agents route and `GET /v1/directory` are unchanged and never show tool rules.

**Test vectors** for a v2 policy, with the earlier person as owner, are added when this contract is accepted. Each implementation generates the vector, and the vector is adopted only if both produce the same statement.

### Commands

`allow` and `deny` gain tool forms. The forms without `--tools` or `--resources` are unchanged and never touch tool rules.

| Command | Behavior |
| --- | --- |
| `allow PRINCIPAL --tools SPEC [--agent NAME] [--yes] [--calls-per-hour N] [--network ID]` | Sets PRINCIPAL's tool access, described below. |
| `allow PRINCIPAL --resources SERVER[@PROFILE]:PATTERN [...] [--agent NAME] [--network ID]` | The same for `resource.read`. |
| `deny PRINCIPAL --tools SERVER[@PROFILE] [--agent NAME] [--network ID]` | Removes PRINCIPAL from every tool rule naming that server or profile, within the agent scope, and drops empty rules. It reports `removed` and `note`, as `deny` does. |
| `trust [HOST]` / `untrust HOST` | Adds the host to, or removes it from, `trusted_hosts`, then signs and submits the next version. `HOST` defaults to this host and must be bound to this person in a shared network. |

**`SPEC`.** It is one of:
- `SERVER` or `SERVER@PROFILE`, meaning `readonly`;
- `SERVER[@PROFILE]:TOOL[,TOOL...]`;
- `SERVER@PROFILE:*`.

`--tools` and `--resources` may be repeated, and each occurrence makes its own rule.

**What `allow --tools` checks, before signing:**
1. **The server exists.** With `--agent`, that agent has the server and it is `shareable`. Without `--agent`, the scope is `*`, and at least one agent on this host has it.
2. **No write tools without a profile.** Named tools on a server without a profile must be `read_only` in the snapshot. Otherwise `allow` refuses. The error names the tools, and says to add a profile with `tools profile add` or to wait for approval of each call.
3. **The reach is confirmed.** The first time a share names a given `(agent, server, profile)`, `allow` prints the reach and requires confirmation. The prompt reads: `PRINCIPAL can call these tools of SERVER on AGENT with the credentials it runs with there: TOOLS. Anything those credentials can reach through these tools, PRINCIPAL can too.` Confirmation is `y` at a terminal, or `--yes`. Without a terminal and without `--yes`, `allow` refuses with exit 1. Confirmations are stored per `(agent, server, profile)` on this host, and are not asked again.

**Applying the rule.**
- **Settings:** `max_input_bytes` 65,536, `allow_disconnected` false, and `max_calls_per_hour` 100 or `--calls-per-hour`.
- **Set semantics** follow `allow`. Within the same agent scope and server, PRINCIPAL is removed from every tool rule with the same action. It is then added to the first remaining rule with identical settings and scope, or a new rule is appended, and empty rules are dropped.
- **Output:** `allow` prints `{policy, principal, agent, server, action, scope}`.

**`join` and `network create`** gain `--trusted` and `--untrusted`. When bound to a person and given neither, they ask at a terminal: `Let this machine use tools shared from your other machines? [y/N]`. Without a terminal, the answer is no. A yes adds this host to `trusted_hosts` in the next signed version. Their output gains `trusted`.

### Authorization

A receiving host bound to person P authorizes a call to its agent N's server S (or profile S@R) when the call cites one of the following:
- **Policy.** P's newest verified policy has a tool rule that matches:
  - the rule's agent is N, or `*` with no tool rule naming N for S;
  - its server is `S` (or `S@R`);
  - its action is the call's;
  - a principal matches the sender, as for rules;
  - the scope covers the tool or URI.
- **Grant.** A grant with `action` `tool.call` or `resource.read`. Grants gain `server` and `scope`, set with `grant create --server SERVER[@PROFILE] --scope ENTRY ...`.
- **Self.** The sender and receiver are both bound to P in a shared network, and the sender's host ID is in `trusted_hosts` of P's newest verified policy. Self covers every shareable server and profile of every agent, and every tool, including tools that are not read-only. Its bounds are `max_input_bytes` 262,144, `allow_disconnected` true, and no hourly budget.

Then, in this order:
1. **Blocks.** The block list applies, except to self.
2. **The snapshot.** The agent's snapshot has the tool, or a resource whose URI matches. Otherwise 404.
3. **The read-only rule.** Under policy or a grant, a tool that is not `read_only` on a server without a profile is refused with 403, whatever the scope says.
4. **Bounds.** Input size within `max_input_bytes`, otherwise 413. The deadline within the policy's `valid_until` or the grant's expiry. The connected state unless `allow_disconnected`, with 503 when it can recover, as for messages.
5. **Budget.** At most `max_calls_per_hour` accepted calls in the trailing hour, counted per `(rule or grant, caller)`. The caller is the sender's bound person in that network, or else the sender's host ID. A call over the limit is refused with 429 and the limit's name.

Several matching rules combine as for messages: the call is authorized if any applicable rule allows it, under that rule's bounds and budget.

**Rechecks.** Authorization is checked at submission, and again immediately before the call starts. A failure at the start makes the call `rejected`, with the reason `authorization lapsed before start`. Once a call has started, revocation does not stop it; cancellation can.

**Citation form.** As for tasks: exactly one of `grant_id`, `policy` (`{person_id, version}`), or `self` (`{person_id}`). What senders cite follows tasks, except that `self` is cited only when this host is in the trusted list. Otherwise the sender cites the policy.

## Calls

### Peer routes

| Route | Body | Behavior |
| --- | --- | --- |
| `GET /peer/v1/tools?network=ID` | none | Lists what the authenticated sender may call or read on this host: `[{agent, agent_id, server, profile, tools: [{name, description, input_schema, read_only}], resources: [...]}]`, from snapshots, filtered by authorization without budgets. `network` is optional. Without it, all policies and grants are evaluated. Sorted by agent, server, and profile. |
| `POST /peer/v1/calls` | exactly `call_id`, `target_agent_id`, `server`, `profile` (string or null), `kind` (`tool` or `resource`), `name` (for `tool`) or `uri` (for `resource`), `arguments` (an object, for `tool`), `deadline`, optional `origin`, and one citation | Authorizes as above, then persists the call as `queued` with a `call.received` activity, and returns 200 with the status record. Idempotent by `(sender, call_id)`: an identical repeat returns the existing record, and a changed one returns 409. |
| `GET /peer/v1/calls/{call_id}` | none | The status record with its `result` once final. Submitter only; anyone else gets 404. It remains available after revocation. |
| `POST /peer/v1/calls/{call_id}/cancel` | `{}` | Sets `cancel_requested`. A `queued` call becomes `cancelled` at once. For a `running` call, the server receives MCP `notifications/cancelled`, and the call ends as the server answers. Submitter only. A repeat, or a cancel of a final call, returns the record unchanged. |

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
| `cancelled` | Cancelled before start, or the server reported cancellation. |
| `uncertain` | The call was `running` when the daemon or the server stopped, so whether it took effect is unknown. Final. |

**Further rules:**
- **Results.** `result` is the server's JSON-RPC `result` object, or `{code, message}` for a JSON-RPC error, at most 1,048,576 bytes encoded. A larger result makes the call `failed` with `result_too_large`, and the result is not stored.
- **Deadlines.** A deadline is at most 15 minutes after submission. A call that is `running` at its deadline is sent `notifications/cancelled`, and becomes `cancelled` if the server stops, or keeps its eventual outcome otherwise.
- **No re-execution.** A call is never sent to a server twice. At daemon start, every call still `running` becomes `uncertain`.

### Running servers

- **Starting.** The daemon starts a server or profile instance on demand, as a child process with:
  - the definition's `command` and `args` (a profile's `--arg` values replacing `args`), after substituting captured values;
  - an environment of the daemon's own `PATH` and `HOME`, the definition's `env` with captured values, then the environment file, then, for a profile, its `--env-file`;
  - the agent's workspace as the working directory.
- **Lifetime.** One instance per `(agent, server, profile)` is shared by all calls. It runs at most 4 calls concurrently, and later calls wait as `queued`. An instance with no calls for 10 minutes is stopped.
- **Start failures.** An instance that does not complete `initialize` within 30 seconds is stopped, and its waiting calls fail with `server_start_failed`.
- **Exits.** If an instance exits, its running calls become `uncertain`, its queued calls start a new instance, and a server that fails to start 3 times in 10 minutes fails its queued calls.
- **Protocol.** The MCP client speaks protocol version `2025-06-18`, and accepts the server's negotiated version if it is one this implementation supports. It sends `tools/call` with `{name, arguments}`, or `resources/read` with `{uri}`.
- **stderr.** A server's standard error is appended to `STATE/tool-logs/AGENT_ID/SERVER[@PROFILE].log`, mode 0600, truncated to its last 1 MiB at each start.

### Records

The receiver stores the request, the status record, and the result. The request's `arguments` and the result are deleted 7 days after the call becomes final, and the status record and `arguments_sha256` remain.

### Owner CLI

| CLI | Local API | Behavior |
| --- | --- | --- |
| `tools remote [PERSON[/AGENT]] [--network ID] [--json]` | `GET /v1/remote-tools?target=…` | Fetches `GET /peer/v1/tools` from each matching host in the directory, at most 8 at once with a 5-second timeout each, and prints what this host may call. |
| `call TARGET TOOL [--arguments JSON] [--deadline T] [--wait D] [--grant ID] [--network ID]` | `POST /v1/calls` | `TARGET` is `PERSON/AGENT/SERVER[@PROFILE]`. Persists the outbound call and submits it, with retries as for tasks. It then waits up to `--wait` (default 60 seconds, at most 15 minutes) for a final state, and prints the local record. The exit code is 0 for `succeeded`, 1 for other final states, and 3 if still pending. |
| `read TARGET URI [same options]` | `POST /v1/calls` | The same, for `resource.read`. |
| `calls list [--after N] [--limit N]` | `GET /v1/calls` | Outbound calls in insertion order, paged as tasks are. |
| `calls received [--after N] [--limit N]` | `GET /v1/calls/received` | Calls received by this host. |
| `calls inspect --peer HOST ID` | `GET /v1/calls/{peer}/{id}` | The local outbound record. |
| `calls cancel --peer HOST ID` | `POST /v1/calls/{peer}/{id}/cancel` | Sends cancellation, resent while uncertain, as for tasks. |

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
CREATE TABLE tool_captured (agent_id TEXT NOT NULL, server TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(agent_id, server, field));
CREATE TABLE tool_profiles (agent_id TEXT NOT NULL, server TEXT NOT NULL, name TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, server, name));
CREATE TABLE tool_confirmations (agent_id TEXT NOT NULL, server TEXT NOT NULL, profile TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, server, profile));
CREATE TABLE received_calls (sender TEXT NOT NULL, call_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id));
CREATE TABLE outbound_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, call_id));
PRAGMA user_version = 16;
```

- **Records** are JSON. `tool_servers.record` holds the definition and snapshot. `tool_confirmations.profile` is empty for none.
- **Grants** gain `server` and `scope`, and grant records without them read as before.
- **Version checks.** Older binaries reject version 16, and version 16 binaries reject version 17.

**New activity kinds:**
- `tools.discovered` (subject: agent ID);
- `tools.snapshot_failed` (subject: `AGENT_ID/SERVER`);
- `tools.profile_added` and `tools.profile_removed`;
- `call.received`, `call.started`, `call.finished`, and `call.cancel_requested` (subject: the sender host ID and the call ID);
- `call.submitted` and `call.updated` (subject: the peer host ID and the call ID).

Activity never includes arguments, results, or secret values.

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
  - the environment file overriding captured values, and ignored when too open (item 14);
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
  - refusal of write tools without a profile;
  - reach confirmation at a terminal, with `--yes`, refused without either, and not asked twice;
  - set semantics;
  - `deny --tools`.
- **`trust`/`untrust`**, and the `join` prompt and flags.
- **Authorization:**
  - by policy, by grant, and by self from a trusted host;
  - self refused from an untrusted host of the same person;
  - another person's host never covered by self;
  - the read-only rule under policy and grants, but not under self;
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
  - cancellation queued and running;
  - a daemon restart during a running call producing `uncertain` and no re-execution;
  - a server exit producing `uncertain` for running calls;
  - concurrency capped at 4 per instance;
  - idle stop.
- **Routes:** `GET /peer/v1/tools` filtered by authorization, and reachable by a grant-only peer outside any network; status and cancel from a non-submitter returning 404.
- **Owner CLI:** `tools`, `tools remote`, `call` and `read` exit codes, and `calls` listings.
- **Profiles:** a profile instance receiving its own environment file and arguments, and a share of a profile not matching the bare server.
- **Status:** item 14 for each cause.
- **Migration:** from version 15 to version 16.

## Points for owner review

- **Self covers write tools.** Self from a trusted host covers write tools without a profile, on the reasoning that trusting a machine means trusting it with your credentials.
- **The person key can mark any host trusted.** Any host holding the person key can sign a policy that marks itself trusted. Untrusted marking protects only against hosts that do not hold the key, for example hosts bound through ssh-agent forwarding. `join` on an untrusted machine prints this.
- **The reach confirmation is recorded only locally,** on the host where `allow` runs, so a second machine of the same person asks again.
