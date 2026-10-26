# Capabilities contract

Roadmap milestone 10, slice 1: sources, capabilities, sharing, and owner calls; slice 2: [agent tools](#agent-tools-slice-2); and slice 3: [sharing with one agent](#sharing-with-one-agent-slice-3), [per-call approval](#per-call-approval-slice-3), [resource bounds and the `gh` source](#resource-bounds-and-the-gh-source-slice-3), and [remote MCP servers and OAuth](#remote-mcp-servers-and-oauth-slice-3).
- **Public surface.** It follows the CLI experience agreed on 2026-10-16 in the system design (`docs-internal`, `docs/cli-spec.md`).
- **Background.** The [remote tools proposal](remote-tools-proposal.md) and [credentials for shared tools](tool-credentials.md) give the background. Their MCP-server sharing model is superseded.
- **What it builds on.** The [task contract](task-contract.md) for call records, retry, and polling; owner access policy in the [coordination contract](coordination-contract.md); and `attach`, self access, and status in the [launch contract](launch-contract.md).

Slice 1 covers MCP sources and owner calls from the CLI. [Slice 2](#agent-tools-slice-2) adds the agent-facing MCP tools. Slice 3 was settled with the owner on 2026-10-25 ([decision 16](#owner-decisions)). Its designs are in four proposals, and each item's section is added here when it is implemented; all four are now specified: [remote MCP servers and OAuth](#remote-mcp-servers-and-oauth-slice-3), [sharing with one agent](#sharing-with-one-agent-slice-3), [per-call approval](#per-call-approval-slice-3), and [resource bounds and the `gh` source](#resource-bounds-and-the-gh-source-slice-3):
- remote MCP servers and OAuth ([proposal](capabilities-slice3-remote-proposal.md));
- approval of each call ([proposal](capabilities-slice3-approval-proposal.md));
- sharing with one agent, and `call --from-agent` ([proposal](capabilities-slice3-agent-shares-proposal.md));
- optional resource bounds, and the `gh` source ([proposal](capabilities-slice3-bounds-sources-proposal.md)).

**Decided with the owner on 2026-10-16:**
- **Discovery.** Sources are discovered from harness configuration, never registered.
- **What gets shared.** The unit people share is a named **capability**, one use case with selected operations, created by its owner. Capabilities are created explicitly or through the guided share.
- **Credentials.** `${VAR}` values are captured at `attach`. A per-user environment file overrides them, filtered to the names each definition uses.
- **Policy format.** The policy makes a clean break to `peerspan-policy-v2`. Capability names in policy are visible to coordination.
- **Calls** are persisted and asynchronous only.
- **Self access** covers capabilities only from hosts the person has marked trusted, per network.

**Decided with the owner on 2026-10-17:** the [owner decisions](#owner-decisions) below, including raw sources for the person's own machines behind a two-sided gate.

**Decided with the owner on 2026-10-18:** a capability's name is claimed in the person's policy when the capability is created, so `PERSON/CAPABILITY` names one capability everywhere for a claimed name. A name no policy binds that the person has on several hosts is 409 `ambiguous` (decision 12). A policy edit lost to a concurrent one is re-applied, as specified under [Concurrent edits](coordination-contract.md#concurrent-edits).

## Model

| Term | Meaning |
| --- | --- |
| **Source** | Something this host can operate. In slice 1, an MCP server from an attached agent's configuration, identified as `AGENT/SERVER`. From slice 3, also a [built-in source](#built-in-sources) such as `builtin/gh`, and a [remote MCP server](#remote-mcp-servers-and-oauth-slice-3). |
| **Snapshot** | The tools and resources a source reported when the host last listed them. |
| **Capability** | The owner's named, host-local definition of one use case. It binds a source, selected operations, and the credential context that serves calls. |
| **Operation** | One thing a capability lets a caller do. It is either a selected MCP tool, named as the tool, or `read`, which reads one of the capability's selected resources. |
| **Claim** | A `capability_rule` with no principals. It reserves the capability's name for the host that serves it, and authorizes nothing. |
| **Share** | A principal in the capability's rule. It lets that principal call the capability's operations on the host the rule names. |
| **Call** | One invocation of an operation by a peer, persisted on both hosts. |

**Names.**
- Server names and capability names match `[a-z0-9][a-z0-9_-]{0,62}`.
- A harness server whose name does not match is listed with `shareable: false` and the reason `name`.
- A capability may not be named `read`.
- `read` is reserved as an operation name. `capability create` refuses a source tool named `read` as an operation with 400, so such a tool cannot be shared in slice 1.

**IDs.** Call IDs are `call_` followed by 16 random bytes in lowercase hex.

**Addresses.** A capability's address is `PERSON/CAPABILITY`, for example `bob/github-issues`. `HOST_ID/CAPABILITY` names a capability on one host. A source's address, usable only by the person's own machines, is `PERSON/AGENT/SERVER` or `HOST_ID/AGENT/SERVER` (see [Sources for the person's own machines](#sources-for-the-persons-own-machines)). Capability names never contain `/`, so the forms cannot collide. A person label may contain `/`, so a person whose label contains `/` is never used as `PERSON` in an address: their capabilities and sources are addressed by host ID, and an address is split at every `/`.

## Sources

A **source** is an MCP server found in the configuration of an attached agent's harness, which this host can run. It is identified on this host as `AGENT/SERVER`, for example `claude-laptop/github`. Slice 3 adds [built-in sources](#built-in-sources), starting with the `gh` adapter Peerspan ships.

`attach` discovers sources after its session setup succeeds. `peerspan sources refresh [--agent NAME]` repeats discovery for each `attach` profile on this host, or for one agent. Both run in the CLI, which has the user's environment and the project directory. The CLI sends the result to the daemon.

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

- **`transport`.** `stdio`, or `remote` for any URL-based server (Claude Code `http` or `sse`, Codex `url`, OpenCode `type: "remote"`). From slice 3, a `remote` server is a source as specified under [Remote MCP servers and OAuth](#remote-mcp-servers-and-oauth-slice-3); the reason `remote` is retired.
- **`command` and `args`** come from the harness's own shape:
  - Claude Code: `command` and `args`;
  - Codex: `command` and `args`;
  - OpenCode: the first element of `command`, and the rest as `args`.
- **`env`** maps each variable name to how its value is obtained:
  - `literal`: the value is written in the configuration;
  - `captured`: the value is a reference resolved at discovery;
  - `missing`: the value is a reference that could not be resolved. Such an entry is `{"source": "missing", "variables": [NAME, ...]}`, naming the referenced variables that could not be resolved.

  Values are sent to the daemon only in the `values` payload (below), and never appear in definitions, listings, output, logs, or activity.
- **`source`** is `INTEGRATION:SCOPE`. The scope is `user`, `project`, or `local` for Claude Code, `user` for Codex, and `global` or `project` for OpenCode.
- **Unsupported fields.** A definition using a field this contract does not list, such as Codex `startup_timeout_ms` or OpenCode `enabled: false`, is still discovered. Fields that change only timing or visibility are ignored. A definition disabled in its harness (OpenCode `enabled: false`, Codex `enabled = false`) is discovered with `shareable: false` and the reason `disabled`.

### References

- **Where they are resolved.** In `command`, `args`, and `env` values, `${NAME}` and `${NAME:-DEFAULT}` are resolved from the CLI's environment at discovery. This applies to Claude Code definitions, and to the same syntax in the other harnesses.
- **What is stored.** A value that contains a reference is resolved and sent in `values`, and its `env` entry is `captured`. Literal `env` values are sent in `values` too, as `literal`. The daemon stores both in `tool_values`, which is the only place it reads them from.
- **Unresolved references.** A reference with no value and no default makes the entry `missing`. The server is then listed with `shareable: false` and the reason `missing_env`, naming the variables.
- **Entries without a stored value.** A `literal` or `captured` entry that has no value in `tool_values` is left unset when the server starts. It does not make the server `missing_env`.
- **The environment file.** `$XDG_CONFIG_HOME/peerspan/env` (default `~/.config/peerspan/env`) holds `NAME=VALUE` lines, with `#` comments. When it exists, the daemon reads it each time it starts a server. Only variables whose names appear in the server definition's `env` are taken from it; others in the file are ignored for that server. Those values override captured values and literals of the same name. If it is not mode 0600 or stricter, servers start without it and status item 14 reports it.

### Local commands

| CLI | Local API | Behavior |
| --- | --- | --- |
| (from `attach` and `sources refresh`) | `PUT /v1/agents/{agent_id}/tool-servers` with `{workspace, servers, values}` | Replaces the agent's server definitions and stored values in one transaction, then snapshots each shareable server. It returns once the snapshots finish. `values` maps `SERVER` to `{FIELD: VALUE}`, where `FIELD` is `env.NAME`, `command`, or `args.N`. It holds every `env` value, whether `literal` or `captured`, and every `command` or `args` element that contained a reference, fully resolved. |
| `sources [--agent NAME] [--json]` | `GET /v1/sources` | Each source, with where it came from, whether it is shareable and why not, its tools (marked `read_only`) and resources, and the capabilities built on it. Secret values are never shown. |
| `sources refresh [--agent NAME]` | the same `PUT` | As `attach` discovery. |

**Snapshots.**
- **Starting.** The daemon starts the server as described in [Running servers](#running-servers) and sends MCP `initialize`. It then calls `tools/list` and `resources/list`, following `nextCursor` up to 1,000 entries each, and stops the instance.
- **Bounds.** The whole snapshot must finish within 30 seconds. A failure records `snapshot_error` and keeps the previous snapshot, if any.
- **Stored tool entries.** Each tool is `{name, description, input_schema, read_only}`, where `read_only` is true only when `annotations.readOnlyHint` is `true`.
- **Stored resource entries.** Each resource is `{uri, name, description, mime_type}`.
- **Size.** A snapshot larger than 1 MiB of JSON is a `snapshot_error`.

**Following configuration.**
- **Dropped servers.** A `PUT` that drops a server deletes its definition, stored values, and snapshot. Capabilities built on it remain, but become `unavailable`.
- **Calls in flight.** Calls already `running` finish. New calls are refused for an operation in the capability's `unavailable` list, or for any operation when the list contains `source`; its other operations still run (see [Authorization](#authorization)).
- **New tools.** A tool that appears later is never added to an existing capability.
- **Own credentials.** A `PUT` for an agent snapshots again, with their own credential, the capabilities built on that agent's sources that have their own credential context. A failure keeps the previous snapshot.
- **Missing operations.** A selected tool missing from the latest snapshot makes that operation `unavailable`. A selected resource missing from it is excluded from `read` until it returns.

## Capabilities and sharing

### Capabilities

A capability record is:

```json
{
  "name": "github-issues",
  "source": {"agent": "claude-laptop", "server": "github"},
  "operations": ["list_issues", "get_issue"],
  "resources": null,
  "credential": {"env_file": null, "args": null},
  "bounds": {},
  "state": "available",
  "unavailable": [],
  "created_at": "RFC3339"
}
```

- **`operations`** lists tool names from the source's snapshot, at least one unless `resources` is set. It never contains `read`, which is reserved for resources. Tools may be read-only or not; the review marks the ones that can change things.
- **`resources`** is null, meaning no `read` operation. It may instead be `"all"`, meaning every resource in the snapshot, or a list of URIs from the snapshot. When set, the capability has a `read` operation whose input is `{uri}`.
- **`credential`** is the credential context:
  - With both fields null, calls run on the source's own instance, with the source's environment.
  - With `env_file` or `args`, the capability has its own instance. The whole `env_file` is applied, and `args` replaces the source's arguments (the narrower-credential use case).
  - `env_file` is absolute, must exist when the capability is created, and is read each time the instance starts.
- **`bounds`** is `{}`, or an optional [resource bound](#resource-bounds) from slice 3.
- **`state`** is `available` or `unavailable`. `unavailable` lists the operations that cannot run now, or `source` when the source itself is gone.

| CLI | Local API | Behavior |
| --- | --- | --- |
| `capability create NAME --from SOURCE [--operations OP[,OP...]] [--resources all\|URI[,URI...]] [--env-file PATH] [--arg A ...] [--person-key PATH]` | `POST /v1/capabilities` with `{name, source, operations, resources, env_file, args, policies}` | Creates the record and claims its name (see [Claims](#claims)), without sharing it. `SOURCE` is `AGENT/SERVER` as `sources` shows it, or `SERVER` when exactly one agent on this host has it. The source must be `shareable`, and each operation and URI must be in its snapshot. A capability with its own credential is snapshotted with that credential, and its operations are checked against that snapshot. Returns 201 with the record; an identical repeat signs nothing and returns 200; a different record under the same name returns 409. |
| `capability list [--json]` / `capability show NAME` | `GET /v1/capabilities`, `GET /v1/capabilities/{name}` | The records, each with its recipients from this person's stored policies. |
| `capability remove NAME [--yes] [--person-key PATH]` | `DELETE /v1/capabilities/{name}` | Removes the record. If it is shared, it first shows the recipients and asks for confirmation (`y` at a terminal, or `--yes`). It then removes this host's rule for the capability, claim included, from every stored policy that holds it, whoever owns that policy and whether or not this host is still bound in that network, signing and storing new versions. In a network where this host is bound to the signing person, each withdrawal is an edit and starts from the edit route. Where it is not bound to that person, the edit route returns 404, so the withdrawal starts from that person's newest stored policy (`GET /v1/networks/{id}/policy?person=PERSON_ID`), is signed as its version + 1 with its `edits` entries copied except retired ones and none added for this host, and is submitted through the existing route; it is not an edit and is not re-applied. It deletes the record only after every one of them is stored. A policy owned by a person other than the signing key's cannot be withdrawn: the command first withdraws the rule from the signing person's policies, then fails before deleting, names each other person and network, and says to run it again with that person's key. If any signing fails, the command fails and the record is kept. Policies already signed stay signed, and repeating the command finishes the removal. The daemon also refuses `DELETE` with 409 while any stored policy still holds this host's rule for the name. |

**Uniqueness.** A capability name is unique on its host, and claimed across the person's hosts.

### Claims

A claim is a capability rule with no principals. It binds the name to the host that serves the capability, so a person's capability names are unique across their hosts, and `PERSON/CAPABILITY` names one capability for every caller, including the person's own trusted machines.
- **At creation.** `capability create`, and the guided share when it creates, claim the name in this person's policy for every network in which this host is bound to that person. The CLI gets each policy from the edit route ([Concurrent edits](coordination-contract.md#concurrent-edits)), adds a rule for this host with no principals, `max_input_bytes` 65,536, `allow_disconnected` false, and `max_calls_per_hour` 100, and signs each as an edit. It sends the signed policies in `policies` with the record. The daemon checks the record, then stores the policies and the record in one transaction, and submits the policies as any policy. A refusal stores nothing.
- **Refusal.** A name that a capability rule in any of this person's stored policies binds to another host is refused with 409, before anything is signed. The check is local, so it also covers hosts that are offline.
- **The guided share** signs one policy per network: in the selected network, the rule with its principal; in the others, the claim.
- **A host without a person** creates the record without claims, and `policies` is empty. Nothing can use such a capability until the host is bound.
- **A network bound later.** A network in which the name is not yet claimed gains the claim at the next `share` in it, which refuses the name if another host holds it there.
- **`unshare`** that removes the last principal keeps the rule as a claim.
- **`capability remove`** removes the rule, claim included.
- **Concurrent claims.** Two hosts that claim one name while out of contact sign policies that cannot both stand, because a policy binds a name to one host. One wins; the other host's re-applied edit drops its claim, as a withdrawal wins over a concurrent addition. Status item 15 then reports the capability.

### Policy statement, version 2

The policy statement's header line is `peerspan-policy-v2`. Its lines are:
1. the v1 header fields (`network_id`, `person_public_key`, `version`, `issued_at`, `valid_until`);
2. the v1 rules, unchanged, including the optional third value of the fifth line for `max_artifact_bytes`;
3. for each capability rule, in the order of `capability_rules`, six lines:
   1. `capability_rule`;
   2. the host ID of the host that serves the capability;
   3. the capability name;
   4. the principals, space-separated, which is an empty line for a claim;
   5. `max_input_bytes`, `allow_disconnected`, and `max_calls_per_hour`, space-separated;
   6. `end`;
4. a line `trusted` followed by host IDs, space-separated and sorted in byte order. With none, it is the bare word `trusted`;
5. a final line `edits` followed by `HOST_ID:SEQ` entries, space-separated and sorted in byte order, as defined under [Concurrent edits](coordination-contract.md#concurrent-edits). With none, it is the bare word `edits`.

Lines are joined with `\n`, with no trailing newline, as in v1.

**JSON.** It adds `format: 2`, `capability_rules`, `trusted_hosts`, and `edits`. Each capability rule is `{host, capability, principals, max_input_bytes, allow_disconnected, max_calls_per_hour}`, where `principals` is `[]` for a claim. `edits` is `[{host, seq}]`, sorted by host. The keys are, in order, `format`, `network_id`, `person_public_key`, `version`, `issued_at`, `valid_until`, `rules`, `capability_rules`, `trusted_hosts`, `edits`, `signature`. A v1 policy is stored in its v1 JSON shape.

**Bounds and validation.**
- `max_input_bytes` is 1 to 262,144, and bounds the JSON encoding of the call's `input`.
- `max_calls_per_hour` is 1 to 10,000.
- At most 256 capability rules, claims included, at most one rule per capability name, and 0 to 64 principals per rule. A name is bound to one host per policy, so two rules for the same name on different hosts are refused with 400.
- At most 256 `edits` entries, each a host ID without duplicates, with `seq` from 1 to 2^53 − 1.
- The host is a host ID; it need not be in the network map when the policy is signed.
- At most 64 trusted hosts, each a host ID, without duplicates.
- Principals are as for rules.
- `allow_disconnected` is `true` or `false`.
- A capability name that does not match the name pattern, or a malformed line, is refused with 400.

**Compatibility.**
- Coordinators and hosts that implement this contract accept v1 and v2. A v1 policy reads as v2 with no capability rules, no trusted hosts, and no edits.
- Claims and the `edits` line amend v2 before any release. Software built to the earlier v2 text rejects them; nothing outside test runs signed that form.
- The CLI and daemon renewal always sign v2.
- Older software rejects v2, which is the clean break: coordinators are upgraded first.
- Versions, the tie-break hash over the v2 lines, propagation, and storage are unchanged. A renewal copies `edits`, dropping retired entries. Concurrent edits are re-applied as specified in the coordination contract.
- The directory never shows capability rules.

**Test vector.** Both implementations generate it independently from the inputs below. It is adopted only when both produce the same statement. The amended inputs replace the vector adopted on 2026-10-17.
- **Owner and network:** the earlier person as owner, in the network of the v1 vector.
- **Validity:** version 1, issued `2026-10-10T00:00:00Z`, valid until `2026-10-17T00:00:00Z`.
- **Rules:** the two v1 vector rules.
- **Capability rule `github-issues`:** host `host_` followed by 64 `a`s, principal `person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2`, bounds `65536 false 100`.
- **Capability rule `docs`:** host `host_` followed by 64 `b`s, principal `group:backend`, bounds `4096 true 10`.
- **Claim `notes`:** host `host_` followed by 64 `a`s, no principals, bounds `65536 false 100`.
- **Trusted hosts:** `host_` followed by 64 `b`s and `host_` followed by 64 `a`s, given in that order.
- **Edits:** `host_` followed by 64 `b`s at 1, and `host_` followed by 64 `a`s at 3, given in that order.

### Sharing

| CLI | Behavior |
| --- | --- |
| `share NAME --with PRINCIPAL [--calls-per-hour N] [--yes] [--network ID]` | Grants PRINCIPAL access to the existing capability NAME on this host. It shows the review below and asks for confirmation. It then adds PRINCIPAL to the capability's rule for this host, which is usually its claim, creating the rule when the network has none with `max_input_bytes` 65,536, `allow_disconnected` false, and `max_calls_per_hour` 100 or `--calls-per-hour`. When the rule exists, `--calls-per-hour` replaces its limit for every recipient, and the review lists the old and new limits and the recipients affected; without the flag the existing limit is kept. Finally it signs and submits the next version. Sharing again with a principal already in the rule and no limit change signs nothing. |
| `share --with PRINCIPAL [--from SOURCE --operations … --resources … --name NAME --env-file … --arg …] [--yes] [--network ID]` | The guided first share. At a terminal it asks, in order, for: the source (from `sources`), the operations, whether to include resources, and the capability name, suggesting the server name. Then it shows the review and asks for confirmation. On confirmation it creates the capability and shares it. Without a terminal, every selection must be given as a flag, plus `--yes`. Otherwise it refuses with nothing created. |
| `shares [--json] [--network ID]` | Every capability on this host and every capability rule in this person's stored policies. Each shows its source, operations, credential context, recipients (labels where they resolve), and state, and the `unshare` command for each recipient. |
| `unshare NAME --with PRINCIPAL [--network ID]` | Removes PRINCIPAL from the capability's rule for this host, keeping the rule as a claim when it empties, and signs the next version. Its output says that PRINCIPAL's future calls are denied, that calls already running finish, and that queued calls are refused when they would start. When PRINCIPAL was not in the rule, it reports `removed: 0` with a note explaining that access through a group or `everyone` is unaffected, and signs nothing. |
| `trust [HOST] [--network ID]` / `untrust HOST [--network ID]` | Adds the host to, or removes it from, `trusted_hosts` in this person's policy for the selected network, then signs and submits that policy's next version. `--network` is optional when this host belongs to exactly one network. `HOST` defaults to this host, and for `trust` it must be bound to this person in the selected network. Without a change, it signs nothing. |

**The review.** Before every confirmation, `share` prints to stderr:
- the capability's address;
- its source and where the source came from;
- each operation, with the tools that can change things marked `(can change things)`;
- the resources, if any;
- the credential context, either the source's own environment or the capability's environment file;
- the recipient;
- with `--calls-per-hour` on an existing rule, the old and new limits and every recipient whose limit changes, each by label where the principal resolves to one and otherwise as the principal.

It then states the reach: `PRINCIPAL can use these operations with the credentials they run with on this host. Anything those credentials can reach through them, PRINCIPAL can too.` It asks `Share? [y/N] `, reading one line from stdin, and `y` or `yes` agrees. "At a terminal" means stdin is a terminal. Declining, or no terminal without `--yes`, exits 1 with nothing signed.

**Several networks.** A share is written to the selected network's policy. `--network` is optional when the host belongs to exactly one network.

**`join` and `network create`** gain `--trusted` and `--untrusted`.
- **Prompt.** When bound to a person and given neither, they ask at a terminal: `Let this machine use your capabilities on your other machines, and the tools of those that allow it? [y/N]`. Without a terminal, the answer is no.
- **Signing.** A yes adds this host to `trusted_hosts`, and the policy is signed at once.
- **Output.** They always output `trusted`. If the trust signing fails, the command still succeeds, with `trusted: false` and `trusted_error`.
- **The person key.** On an untrusted machine they print that any host holding the person key can mark itself trusted.

**Outputs.**
- `share` prints `{policy, capability, principal, recipient, created}`, where `created` says whether the guided share created the capability. `recipient` (slice 3, [Sharing with an agent](#sharing-with-an-agent)) is null unless `--with` was an agent address.
- `unshare` prints `{policy, capability, principal, recipient, removed}`, with `recipient` as for `share`, plus `note` when `removed` is 0 (or, from slice 3, when agent shares remain after removing a person; [Unsharing an agent](#unsharing-an-agent)).
- `trust` and `untrust` print `{policy, host, trusted, changed}`.

### Authorization

A receiving host bound to person P authorizes a call to its capability C, operation O, when the call cites one of the following.

**Policy.** P's newest verified policy for the cited network has a capability rule for C whose host is this host and whose principals match the sender, as for rules. A rule naming another host never authorizes a call here, and a claim authorizes no one. While an edit made on this host is unsettled, its withdrawals apply here at once ([Concurrent edits](coordination-contract.md#concurrent-edits)).

**Self.** In the network N that the call cites:
- the sender and the receiver are both bound to P;
- the sender's host ID is in `trusted_hosts` of P's newest verified policy for N;
- that policy is within its validity window.

Self covers every capability of P on the receiving host, and the sources the receiving host has opened to the sender (see [Sources for the person's own machines](#sources-for-the-persons-own-machines)). Its bounds are `max_input_bytes` 262,144 and `allow_disconnected` true, and it has no hourly budget.

Then, in this order:
1. **Blocks.** The block list applies, except to self.
2. **The capability.** C exists on this host, and O is one of its operations; otherwise 404. If O is in the capability's `unavailable` list, or the list contains `source`, the call is refused with 409 `{code: "unavailable", error}`. Other operations of a capability whose `state` is `unavailable` still run. For `read`, the input's `uri` must be one of the capability's resources currently in the snapshot; otherwise 404.
3. **Bounds.**
   - Input size within `max_input_bytes`, otherwise 413 `{code: "too_large", error}`.
   - A deadline in the future and at most 15 minutes plus 1 minute of clock skew after receipt, otherwise 400 `invalid`.
   - The connected state unless `allow_disconnected`, with 503 when it can recover, as for messages.
4. **Budget.** At most `max_calls_per_hour` accepted calls in the trailing hour, counted per rule identity and caller. Otherwise 429 `{code: "limit", error, limit: "max_calls_per_hour"}`.
   - The rule identity is the network, owner, host, capability, and bounds, but not the principals.
   - The caller is the sender's bound person in that network, or else the sender's host ID.

**Rechecks.** Authorization is checked at submission and again immediately before the call starts.
- **Recoverable failures** (503-type) leave the call `queued`. It is rechecked at least every 5 seconds until its deadline, and then becomes `expired`.
- **Any other failure** rejects the call with `authorization lapsed before start`.
- **After the start**, revocation does not stop the call, but cancellation can.

**Grants** do not authorize calls in slice 1, and `grant create` does not accept capability actions.

**Citation form.** A call carries exactly one of:
- `policy`, which is `{person_id, network_id, version}`;
- `self`, which is `{person_id, network_id}`.

A `grant_id` is refused with 400. The CLI cites the first `via` entry of the listing, or the first one from `--network` when given. The citation is stored in the outbound record, and retries reuse it.

### Sources for the person's own machines

A person's trusted machines can call a source's tools directly, without a capability, when the machine serving the source allows it. Both sides must agree:
1. **The caller is trusted.** The sender passes self access in the network N that the call cites: both hosts are bound to P in N, and the sender is in `trusted_hosts` of P's newest verified policy for N, within its validity window. Trust in another network does not count.
2. **The server is open to the caller.** The receiving host's local open list contains the sender's host ID, or `*`.

A source call that fails either check is refused with 403. The open list is stored only on the serving host, never in policy. A machine holding the person key can therefore mark itself trusted, and so reach P's capabilities, but it cannot open another machine's sources.

**The implicit capability.** A source `AGENT/SERVER` that is `shareable` and has a snapshot is called as if it were a capability named `AGENT/SERVER`, where:
- its operations are every tool in the current snapshot except one named `read`, plus `read` over every resource in the snapshot when there are any;
- a tool that appears later is included as soon as a snapshot has it;
- calls run on the source's own instance, with the source's own environment;
- it is never shareable: `capability create`, `share`, and capability rules refuse names containing `/`;
- it has self bounds, and no hourly budget;
- otherwise, calls behave as for capabilities: records, states, rechecks, cancellation, and `unavailable` when the source is gone.

**The open list.**

| CLI | Local API | Behavior |
| --- | --- | --- |
| `sources open-to HOST\|--all` | `POST /v1/sources/open-to` with `{host_id}`, where `*` means all | Adds the host, or `*`. A host must be bound to this host's person in at least one network map, and cannot be this host. `*` means every host that passes self access, including hosts trusted later. A repeat is unchanged and returns 200; an addition returns 201. An invalid host ID, a host not bound to this person, or this host is refused with 400. |
| `sources close-to HOST\|--all` | `DELETE /v1/sources/open-to/{host_id}` | Removes the host, or `*`. Removing `*` does not remove hosts listed individually. Removing an absent entry returns 200 with `removed: 0`. |
| (in `sources`) | `GET /v1/sources` | The response adds `open_to: [host_id or "*"]`, sorted, with `*` first. |

The list starts empty. Calls already running when a host is closed finish, and queued ones are rejected at the recheck before start.

## Calls

### Peer routes

| Route | Body | Behavior |
| --- | --- | --- |
| `GET /peer/v1/capabilities?network=ID` | none | The capabilities on this host that the authenticated sender may use. Each entry is `{kind, capability, operations: [{name, description, input_schema, read_only}], resources, state, unavailable, via}`, sorted by `capability`. `kind` is `capability`, or `source` for a source opened to the sender, whose `capability` is `AGENT/SERVER` and whose `via` lists only self entries. Unauthorized capabilities and unopened sources never appear. For a tool operation, `description` and `input_schema` come from the snapshot. For `read`, the input schema is `{"type": "object", "properties": {"uri": {"type": "string", "enum": [URIS]}}, "required": ["uri"]}`, and `resources` lists `{uri, name, description, mime_type}`; for a capability without resources it is `[]`. `via` lists what authorizes the capability, as `{kind: "self", network_id}` or `{kind: "policy", network_id, person_id, version}`, self before policy, then by network ID. With `network`, only that network is evaluated. |
| `POST /peer/v1/calls` | exactly `call_id`, `capability` (a capability name, or `AGENT/SERVER` for a source), `operation`, `input` (an object), `deadline`, optional `origin`, and one citation | Authorizes as above, then persists the call as `queued` with a `call.received` activity, and returns 200 with the status record. It is idempotent by `(sender, call_id)`: an identical repeat returns the existing record, and a changed one returns 409. |
| `GET /peer/v1/calls/{call_id}?wait=N&state=S` | none | The status record, with its `result` once final. Submitter only; anyone else gets 404. It remains available after revocation. With `wait`, an integer from 0 to 10, and `state`, the state the caller last stored, the receiver holds the request until the call's `state` differs from `S` (so `queued` to `running`, or to a final state), or `N` seconds have passed, and then answers. A call already final, a `state` that already differs, or a `wait` of 0 or absent answers at once; `wait` without `state` is held as if `state` were the call's state on arrival. A `wait` outside 0 to 10, or a `state` that is not a call state, is 400. A host that predates `wait` ignores it and answers at once. |
| `POST /peer/v1/calls/{call_id}/cancel` | `{}` | Sets `cancel_requested`. A `queued` call becomes `cancelled` at once. A `running` call is sent MCP `notifications/cancelled`, and becomes `uncertain` with the error `cancel_requested` unless its result was already received. Submitter only. A repeat, or a cancel of a final call, returns the record unchanged. |

**The status record** is `{call_id, sender_host_id, receiver_host_id, capability, operation, state, cancel_requested, error, result_bytes, created_at, started_at, finished_at}`, plus `result` on `GET` once the call is final. `result_bytes` is null until there is a result.

**Mapping to MCP.**
- A tool operation sends `tools/call` with `{name: OPERATION, arguments: input}`.
- `read` sends `resources/read` with `{uri}`.

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
| `uncertain` | The call was `running` and ended without a result, so whether it took effect is unknown. `error` is `daemon_restarted`, `server_exited`, `cancel_requested`, or `deadline`. Final. |

**Further rules:**
- **Results.** `result` is the server's JSON-RPC `result` object, or `{code, message}` for a JSON-RPC error, at most 1,048,576 bytes encoded. A larger result makes the call `failed` with `result_too_large`, and the result is not stored.
- **Deadlines.** A call still `queued` at its deadline becomes `expired`. A call `running` at its deadline is sent `notifications/cancelled`, and becomes `uncertain` with the error `deadline`.
- **Running calls end once.** A running call ends exactly once. If the server's response arrives first, the call ends with its result. Otherwise it becomes `uncertain` at the first of cancellation, deadline, daemon restart, or server exit. A response that arrives after the call is final is discarded, and noted in the server's log.
- **No re-execution.** A call is never sent to a server twice. At daemon start, every call still `running` becomes `uncertain` with the error `daemon_restarted`.
- **After `unshare`.** Calls already running finish. Queued calls are rechecked when they would start, and are rejected then.

### Running servers

- **Instances.** There is one instance per source, shared by its capabilities that use the source's own credential. A capability with its own credential context has its own instance.
- **Starting.** An instance starts on demand as a child process, with:
  - the definition's `command` and `args`, after substituting stored values. A capability's `args` replace the source's arguments.
  - an environment built in this order, later entries overriding earlier ones:
    1. the daemon's own `PATH` and `HOME`;
    2. the definition's `env`, with its stored values;
    3. from the environment file `$XDG_CONFIG_HOME/peerspan/env`, only the variables named in the definition's `env`;
    4. for a capability with its own credential, every entry of its `env_file`.
  - the agent's workspace as the working directory.
- **Concurrency.** An instance runs at most 4 calls at once, and later calls wait as `queued`.
- **Idle stop.** An instance with no calls for 10 minutes is stopped.
- **Start failures.**
  - An instance that does not complete `initialize` within 30 seconds is stopped, and its waiting calls fail with `server_start_failed`.
  - After 3 start failures in 10 minutes, queued calls fail with `server_start_failed`.
- **Exits.** If an instance exits, its running calls become `uncertain` with `server_exited`, and its queued calls start a new instance.
- **Protocol.** The MCP client speaks protocol version `2025-06-18`. It accepts the server's negotiated version if it is one this implementation supports.
- **stderr.** A server's standard error is appended to `STATE/tool-logs/AGENT_ID/SERVER.log`, or `…/SERVER@CAPABILITY.log` for a capability's own instance. The file is mode 0600, truncated to its last 1 MiB at each start.

### Records

The receiver stores the request, the status record, and the result. Seven days after the call becomes final, the request's `input` and the result are deleted. The status record and `input_sha256` remain. The daemon deletes them within 60 seconds of starting, and at least every 10 minutes after that.

### Discovery and calls from the CLI

| CLI | Local API | Behavior |
| --- | --- | --- |
| `discover [PERSON] [--network ID] [--json]` | `GET /v1/discover?person=…&network=…` | Reachable agents and usable capabilities together. Agents come from the directory, as `agents` shows them. Capabilities come from `GET /peer/v1/capabilities` on each host bound to a person in the selected networks' maps, at most 8 at once with a 5-second timeout each. The JSON is `{agents: [...], capabilities: [{address, host_id, kind, capability, operations, resources, state, unavailable, via}], unanswered: [{host_id, error}]}`, including sources opened to this host. `agents` uses the `reachable` entries of `agents --json`. An entry belongs to the person its host is bound to in one of the entry's `via` networks, the first such network deciding; with `PERSON`, entries that belong to someone else are left out, and "the person has it on only one host" counts only entries that belong to that person. `address` is `PERSON/CAPABILITY` when the person's label contains no `/` and the person's policy for the entry's network binds the name to that host, or when none of the person's policies binds the name and the person has it on only one host; otherwise it is `HOST_ID/CAPABILITY`. A copy that lost a concurrent claim is therefore listed only by host ID. For a source it is `PERSON/AGENT/SERVER`, or `HOST_ID/AGENT/SERVER` when the person's label contains `/` or the person has that agent and server on more than one host. |
| `call ADDRESS OPERATION [--input JSON] [--KEY VALUE ...] [--deadline T] [--wait D] [--network ID]` | `POST /v1/calls` with `{target, operation, input, deadline, network, call_id}` | Resolves ADDRESS as `discover` does, persists the outbound call, and submits it, with retries as for tasks. It waits up to `--wait` (`N`, `Ns`, or `Nm`, 0 to 15 minutes, default 60 seconds) for a final state, and prints the local record. The exit code is 0 for `succeeded`, 1 for other final states, and 3 if still pending. |
| `calls list [--after N] [--limit N]` | `GET /v1/calls` | Outbound calls in insertion order, as `[{sequence, call}]`. |
| `calls received [--after N] [--limit N]` | `GET /v1/calls/received` | `[{sequence, request, status}]`. |
| `calls inspect --peer HOST ID` | `GET /v1/calls/{peer}/{id}` | The local outbound record. |
| `calls cancel --peer HOST ID` | `POST /v1/calls/{peer}/{id}/cancel` | Sends cancellation, resent while uncertain, as for tasks. |

**Input.**
- **The input object.** `--input` is a JSON object.
- **`--KEY VALUE` options.** Each fills the top-level property KEY of the operation's input schema, which must have type `string`, `integer`, `number`, or `boolean`. VALUE is parsed by that type, and `true` or `false` are accepted for booleans.
- **Errors.** A KEY the schema does not declare as such a property is an error, as is a KEY also present in `--input`.
- **`call`'s own flags win.** `--input`, `--deadline`, `--wait`, and `--network` are always `call`'s own. A property with one of those names must be given in `--input`.
- **Schema lookup.** The CLI reads the schema from the capability listing during resolution.
- **Example.** `peerspan call bob/github-issues list_issues --repo acme/api`.

**Resolving an address.**
- **`HOST_ID/CAPABILITY`** names a member host directly. `HOST_ID/AGENT/SERVER` likewise names a source, and `PERSON/AGENT/SERVER` resolves as below.
- **`PERSON/CAPABILITY`** queries the person's hosts, as `discover` does, and matches the entries whose `discover` address is `PERSON/CAPABILITY`.
  - Exactly one match is the target, and more than one is 409 `{code: "ambiguous", error, candidates: ["HOST_ID/CAPABILITY", ...]}`.
  - With no match, the name may still be unsettled: none of the person's policies binds it, and the person has it on more than one host, each bound to the person in the entry's network. That is also 409 `ambiguous`, with those entries as `candidates`, so the caller learns which `HOST_ID/CAPABILITY` addresses to use. Copies of a name that a policy binds to another host are never candidates.
  - Otherwise it is 404 `{code: "not_found", error, unanswered}`.
  - `candidates` are sorted. A source named `PERSON/AGENT/SERVER` follows the same rule: one host is the target, and several are 409 `ambiguous`.
- **Before persisting.** All of these refusals happen before anything is persisted. The resolved host and the citation are stored in the outbound record.

**Deadlines.** `--deadline` is RFC3339, or a duration in the `--wait` form, where a bare `N` is seconds. It defaults to 15 minutes, capped by the cited policy's `valid_until`. The daemon refuses a past deadline, or one more than 15 minutes ahead, with 400 before persisting.

**The outbound record** is `{peer_host_id, target, network_id, request, submit_state, status, result, cancel_state, attempts, next_attempt_at, error, status_queries}`.
- **Submission outcomes.** 400, 403, 404, 409, 413, and 429 are final `rejected`. Anything else stays `unknown` and is retried.
- **Polling.** The daemon polls `GET /peer/v1/calls/{id}` for each accepted call that is not final. It backs off from 1 to 60 seconds, shares the task polling slots, and stores the final status and result. For a call's first 60 seconds after acceptance it holds a status request open instead, as under [Results without polling](#adapter-routes).
- **Final only with the result.** The outbound record's status becomes final only from a `GET /peer/v1/calls/{id}` response, stored together with its `result`. When a submit or cancel response is already final, the daemon fetches the call with GET at once. Until a GET succeeds, the record stays non-final and is polled as usual.

### Status

`GET /v1/status` gains:
- **`capabilities: {sources, capabilities, shared, calls_running}`.** These count:
  - discovered sources on this host;
  - capabilities on this host;
  - capabilities on this host named by a rule for this host with at least one principal in this person's stored policies;
  - received calls in `running`.

  The object also contains `open_to`, the number of entries in this host's open list.
- **Attention item 14, `capability_failing`**, after item 13. It covers:
  - a source whose latest snapshot failed;
  - an instance that failed to start in the last 24 hours;
  - an environment file with permissions that are too open, in which case servers start without it;
  - an authentication-looking JSON-RPC error in the last 24 hours (case-insensitive `auth`, `401`, `403`, or `token`);
  - a capability that is `unavailable`.

  The subject is `AGENT/SERVER`, `CAPABILITY`, or `env`. The command is `peerspan sources refresh --agent AGENT`, `peerspan capability show NAME`, or `chmod 600 PATH`.
- **Attention item 15, `capability_name_conflict`.** A capability name on this host is bound to another host by a capability rule in one of this person's stored policies, which happens only when a concurrent claim was lost ([Claims](#claims)). The capability still works through self access, addressed as `HOST_ID/CAPABILITY` only, but cannot be shared under its name. The subject is the name. The command is `peerspan capability create NEW_NAME --from AGENT/SERVER`, with the capability's operations and credential options, followed by `peerspan capability remove NAME`.

## Persistence

Database version 16 adds:

```sql
CREATE TABLE tool_servers (agent_id TEXT NOT NULL REFERENCES agents(id), name TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, name));
CREATE TABLE tool_values (agent_id TEXT NOT NULL, server TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(agent_id, server, field));
CREATE TABLE capabilities (name TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE source_access (host_id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE received_calls (sender TEXT NOT NULL, call_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id));
CREATE TABLE outbound_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, call_id));
PRAGMA user_version = 16;
```

- **Records** are JSON. `tool_servers.record` holds the definition and the snapshot. A capability's own snapshot is kept in its record.
- **Version checks.** Older binaries reject version 16, and version 16 binaries reject version 17.
- **The existing `agent register --capability`** metadata is unrelated and unchanged. It confers nothing, and its CLI flag is renamed `--label`, with `--capability` kept as an alias; the [host service contract](host-service-contract.md#api-and-commands) records the rename. The API field stays `capabilities`.

**New activity kinds:**
- `sources.discovered` (subject: the agent ID);
- `sources.snapshot_failed` (subject: `AGENT_ID/SERVER`);
- `capability.created` and `capability.removed` (subject: the name);
- `sources.opened` and `sources.closed` (subject: the host ID, or `*`);
- `call.received`, `call.started`, `call.finished`, and `call.cancel_requested` (subject: `SENDER_HOST_ID/CALL_ID`);
- `call.submitted` and `call.updated` (subject: `PEER_HOST_ID/CALL_ID`).

Activity never includes inputs, results, or secret values.

## Local API details

### Sources

- **`PUT /v1/agents/{agent_id}/tool-servers` request.**
  - The body is `{workspace, servers, values}`. `values` may be absent.
  - Each element of `servers` has exactly the definition fields `name`, `transport`, `command`, `args`, `env`, `url`, and `source`, plus an optional boolean `disabled`. Unknown fields are refused with 400.
  - The daemon computes `shareable` and `reason`. Reasons, in precedence order, are `name`, `remote`, `disabled`, and `missing_env`. Slice 3 retires `remote` and adds the remote reasons under [Shareable and reasons](#shareable-and-reasons).
  - Slice 3 adds the optional `remote` and `headers` fields under [Remote definitions](#remote-definitions).
  - A stdio entry without a command is reported by the CLI in `errors`, and is not sent.
  - Each `env` entry is exactly `{source}` for `literal` and `captured`, or `{source: "missing", variables}` with a non-empty `variables`. Any other shape is refused with 400.
  - In `values`, `env.NAME` is accepted only for entries whose source is `literal` or `captured`.
- **`PUT` response.** It is the agent object below, returned once snapshots finish, so `sources refresh` returns only after them.
- **`GET /v1/sources` response.** It is `{agents: [AGENT]}`, sorted by agent name, where `AGENT` is `{agent: {id, name}, workspace, servers: [SERVER]}`.
- **`SERVER`** is `{name, transport, command, args, env, url, source, disabled, shareable, reason, missing_env, tools, resources, snapshot_at, snapshot_error, start_failed_at, auth_error_at, capabilities}`, where:
  - `missing_env` is the list of referenced variable names that could not be resolved, such as `FX_MISSING_VAR`, never the `env` keys. For `env` entries, the daemon takes them from each `missing` entry's `variables`. For `command` and `args`, it parses the references in the definition;
  - `tools` and `resources` are `[]` before the first snapshot;
  - `capabilities` lists the names of this host's capabilities built on the server.
- **Missing references.** A `missing` reference keeps the server `missing_env` even when the environment file has that name, because discovery resolves from the CLI's environment.
- **Peerspan's own entries.** Discovery skips server names `peerspan` and `peerspan_` followed by 32 hex digits.
- **OpenCode.** It reads `environment`, falling back to `env`. Its files are parsed as strict JSON.
- **Defaults.** `${VAR:-D}` uses `D` when `VAR` is unset or empty.
- **Entry cap.** Following `nextCursor` beyond 1,000 entries is a `snapshot_error` (`too_many_entries`).
- **Listing calls.** `tools/list` and `resources/list` are each called when the server's `initialize` result has that capability key, whatever its value.
- **`attach` output.** It is `sources: {servers: [{name, transport, shareable, reason, missing_env, tools, read_only_tools, snapshot_error}], errors: [{source, path, server, error}]}`, where `tools` and `read_only_tools` are counts, and `path` and `server` may be null. The readable line goes to stderr, and its wording is not shared.


### Size limits and the probe

- **Peer responses.** Bodies of `GET /peer/v1/capabilities` and `GET /peer/v1/calls/{id}` may be up to 4 MiB. Other peer routes keep their limits, and `peerspan-peer-probe` accepts the same limits.
- **Local API responses** may be up to 16 MiB.

### Capabilities

- **`POST /v1/capabilities` body.** It is `{name, source: {agent, server}, operations, resources, env_file, args, policies}`.
  - A null `operations` means none, and a null `resources` means no `read`.
  - `args` is absent or an array.
  - `policies` holds one signed policy for each network in which this host is bound to its person, each the stored policy's successor with this host's claim for `name`. It is `[]` for a host without a person.
- **Refusals.**
  - An unknown agent or source is 404.
  - An invalid body or name, a non-shareable source, an operation or URI not in the snapshot, an operation named `read`, or a missing `env_file` is 400.
  - A missing policy for a network in which this host is bound, a policy without this host's claim for `name`, or a policy that fails verification is 400.
  - A name in use on this host, or bound to another host by a stored capability rule, is 409.
- **`GET /v1/capabilities`** returns `{capabilities: [RECORD + {recipients: [{network_id, principal, label}]}]}`, sorted by name.
- **`GET /v1/discover`** follows the `discover` JSON above.

## Verification

`conformance/capabilities.py` is written from this contract by an author independent of both implementations. It runs across all Go/Rust CLI and daemon pairings, with `--probe`, the Go coordinator, and OpenSSH.

It uses a fixture MCP stdio server that:
- marks some tools read-only;
- records every execution;
- can sleep, fail, return `isError`, return oversized results, and exit mid-call;
- reports the names of the environment variables it received;
- serves resources.

It covers:
- **Sources:** each harness's discovery as specified above, including not-shareable reasons, references, `missing_env`, the environment file, `sources` and `sources refresh`, values appearing nowhere outside `tool_values`, and following configuration changes.
- **Capabilities:**
  - `capability create` with operations, resources, and both;
  - its own credential context: a separate instance, the whole `env_file`, and `args`;
  - refusals: a non-shareable source, an unknown operation or URI, a tool named `read`, a name containing `/`, a missing `env_file`, a name in use on this host, and a name a stored rule binds to another host;
  - claims: one per network at creation, in the guided share, at the first `share` in a network bound later, kept after the last `unshare`, removed with the capability, never authorizing, and none for a host without a person;
  - repeat and conflict;
  - `list`, `show`, and `remove`, with and without shares;
  - `unavailable` when a source or tool disappears, and recovery when it returns;
  - item 15, after two hosts each claim one name while the other and the coordinator are stopped.
- **Policy v2:**
  - capability rule lines and JSON, claims, the `edits` line, validation including a name bound to two hosts, and v1 acceptance;
  - coordinator acceptance, sibling propagation, and the tie-break;
  - the adopted test vector.
- **Sharing:**
  - `share NAME --with`, with the review content, `--calls-per-hour` on an existing rule, the `(can change things)` marks, confirmation at a terminal, `--yes`, and refusal without either;
  - the guided `share --with` at a terminal and with flags, including refusal without a terminal or flags;
  - `shares`;
  - `unshare`, with its output and the zero-removal note;
  - several networks;
  - `trust` and `untrust`, and the `join` and `create` prompt and flags;
  - `sources open-to` and `close-to`, with `--all`, and their refusals.
- **Authorization:**
  - by policy, and by self from a trusted host;
  - sources: called from a trusted host the server is open to, refused from a trusted host it is not open to, refused from an untrusted host it is open to, refused with 403 when the call cites a network in which the sender is not trusted although it is trusted in another, and `*` covering a host trusted later;
  - a source never listed or callable by another person, even through `everyone`;
  - a rule for the same name bound to another host authorizing nothing here;
  - self refused from an untrusted host and from another person's host;
  - blocks, except under self;
  - an operation outside the capability, and a URI outside its resources;
  - 413, 429, and a deadline outside the window;
  - the budget counted per person, per host for unbound callers, and not reset by changing principals;
  - the recheck before start, both rejecting and leaving queued;
  - grant citations refused.
- **Calls:**
  - the full lifecycle for tool operations and `read`, on capabilities and on sources;
  - a tool added to a source becoming callable through it, but not through capabilities built on it;
  - `isError`, JSON-RPC errors, and `result_too_large`;
  - duplicate and conflicting submission;
  - a lost submit response recovered with exactly one execution;
  - expiry;
  - cancellation while queued and while running, and the deadline while running;
  - daemon restart and server exit giving `uncertain` with no re-execution;
  - concurrency and idle stop;
  - running calls finishing after `unshare`.
- **Routes:** `GET /peer/v1/capabilities` filtered, sorted, with `via` and `?network`, and never listing unauthorized capabilities; status and cancel from a non-submitter returning 404.
- **CLI:**
  - `discover`, by person, with `--network`, with ambiguous names, and with unanswered hosts;
  - `call` with `--input`, the `--KEY VALUE` options and their errors, a property named like one of `call`'s flags, `--deadline`, `--wait`, and exit codes;
  - address resolution errors, including 409 `ambiguous` with `candidates` for a name unsettled on two of the person's hosts, and 404 when the only other copy lost its claim;
  - a person whose label contains `/`, whose capabilities and sources `discover` addresses by host ID and which are callable by those addresses;
  - `calls` listings.
- **Status:** the `capabilities` counts, and items 14 and 15.
- **Migration:** from version 15 to version 16.
- **Removal:** `capability remove` keeping the record when a signing fails, and finishing on repeat; withdrawing the rule from a network where the host is no longer bound; refusing, with the record kept, while a policy of another person holds the rule, and finishing with that person's key; and the daemon's 409 for a `DELETE` while a rule remains.

## Agent tools (slice 2)

Roadmap milestone 10, slice 2. Attached agents call capabilities through the shared adapter, as settled in [owner decision 13](#owner-decisions). It extends the [agent adapter](agent-adapter-contract.md), [outbound](adapter-outbound-contract.md), [recovery](adapter-recovery-contract.md), and [live delivery](live-delivery-contract.md) contracts and `attach` in the [launch contract](launch-contract.md); where they differ, this section applies. The behavior is the same in Go and Rust hosts and in the shared Node adapter, so Claude Code, Codex, and OpenCode get the same tools.

Out of scope: approving each call, remote OAuth servers, capabilities inside delegation chains, tools provided by sessions, and streaming results. Raw sources stay CLI-only: no agent route lists or calls them.

### Opt-in at attach

The setting belongs to the adapter credential, as `directory` does.
- **`POST /v1/adapters/setup`** gains optional `calls` (boolean, default false) and `max_calls_per_hour` (1 to 10,000, default 100; it requires `calls`, and otherwise is refused with 400). The adapter record (`GET /v1/adapters`, `GET /v1/adapters/{id}`, and the setup response) gains `calls` and `max_calls_per_hour`, which is null when `calls` is false. A credential created any other way, including `session setup` and `adapter create`, has `calls` false.
- **`attach`** gains `--calls`, `--no-calls`, and `--max-calls-per-hour N`:
  - Given neither `--calls` nor `--no-calls`, it asks on stderr at a terminal, before setup: `Let this agent call capabilities shared with you, and yours on your other trusted machines? [y/N] `, reading one line from stdin, where `y` or `yes` agrees. "At a terminal" means stdin is a terminal. Without a terminal, the answer is no.
  - `--calls` and `--no-calls` together, `--max-calls-per-hour` with `--no-calls`, or a value outside 1 to 10,000, are refused with exit 1 before anything changes. When the prompt is declined, `--max-calls-per-hour` is not used.
  - Setup sends `calls` and, when enabled, `max_calls_per_hour` (default 100).
  - Its output gains `calls` and `max_calls_per_hour`, as on the adapter record.
  - **Re-attaching.** When `attach` reuses a never-connected credential (`reused: true`), the stored setting stands. A `--calls`, `--no-calls`, or `--max-calls-per-hour` that differs from it is refused with exit 1 before anything changes, naming the stored `calls` and `max_calls_per_hour`; a matching flag is accepted. When `attach` replaces the credential with a new setup, the old setting is not carried over: the flags or the prompt decide again, as for a first attach. Re-attaching with none of the three flags asks nothing and keeps the stored setting. These re-attach rules hold with or without a terminal. On a first attach or a replacement, without a terminal and without `--calls` or `--no-calls`, the answer is no and `--max-calls-per-hour` is not used, as when the prompt is declined.

### Agent origin and agent principals

- **Origin.** Every call an adapter makes carries `origin: {agent_id, session_id}`, the session's agent and session, as adapter sends do. Owner CLI calls carry none. The outbound record stores it in `request`, and the receiver stores it with the request, shown by `calls received`.
- **Agent principals.** A capability rule may name `agent:HOST_ID/AGENT_ID`, as policy rules may (`share NAME --with agent:HOST_ID/AGENT_ID`, and `unshare` likewise). It matches only calls from that authenticated host whose `origin.agent_id` is that agent. Other principals match as before, whatever the origin.
- **Listing.** In `GET /peer/v1/capabilities`, each `via` entry of kind `policy` gains `from_agent`. A rule whose only matching principals are `agent:` principals for the caller host appears once per such agent, with `from_agent` set to that agent ID; a rule with any other matching principal appears once, with `from_agent` null. Self entries have no `from_agent`. Within one network, the entry with `from_agent` null comes first, then by agent ID. A capability is listed when at least one entry applies. An entry from a host that predates this slice has no `from_agent` and reads as null.
- **Owner views are unchanged.** `GET /v1/discover` and `call` ignore `via` entries whose `from_agent` is not null (the remaining policy entries keep `from_agent: null` in `discover` JSON), and omit capabilities left with none, so the owner CLI never cites a rule it cannot use without an origin. Slice 3 lists agent-only capabilities in `discover` with `for_agents`, refuses `call` on them with `agent_only`, and adds `call --from-agent` ([The recipient's `discover`](#the-recipients-discover), [Calling as an agent](#calling-as-an-agent)).
- **Naming the agent.** `share` and `unshare` took an agent only as `agent:HOST_ID/AGENT_ID` in this slice; slice 3 adds `PERSON/AGENT` and `HOST_ID/AGENT` ([Agent addresses](#agent-addresses)).
- **Budget.** Agent calls count against `max_calls_per_hour` of the receiver's rule exactly as owner calls do: per rule identity and caller, where the caller is the sender's bound person, or else its host ID.

### Adapter routes

All of them require the adapter's credential and lease, as `/adapter/v1/next` does. Without `calls` on the credential, each answers 403 `{code: "no_calls", error}`. They work before the channel is verified, except `call-updates/next`.

| Adapter request | Behavior |
| --- | --- |
| `GET /adapter/v1/capabilities` | `{capabilities: [ENTRY], unanswered: [{host_id, error}]}`. It queries hosts as `GET /v1/discover` does, in every network of this host, and keeps the entries of kind `capability` that have a `via` entry of kind `self`, or of kind `policy` with `from_agent` null or this session's agent. `ENTRY` is `{address, host_id, capability, operations, resources, state, unavailable}`, with `address` and the other fields as in `discover`. Sorted by address, then host ID. Sources never appear. |
| `POST /adapter/v1/calls` | `{call_id, address, operation, input}` and optional `wait`, an integer of at least 0; `null` or any other value is 400. Persists and submits one call, then holds the response until the call is final or the wait ends (below), and returns 200 with the call view. |
| `GET /adapter/v1/calls/{call_id}?offset=N` | The call view from byte `offset` of the result (default 0). Answers for calls made through any credential of this session's agent on this host; any other call ID is 404. An `offset` greater than `result_bytes`, or inside a UTF-8 character of the result text, is 400; before there is a result, any `offset` other than 0 is 400. |
| `POST /adapter/v1/calls/{call_id}/cancel` with `{}` | As `calls cancel`: sends cancellation, resent while uncertain. Returns the call view. Same scope and 404 as the `GET`. |
| `POST /adapter/v1/call-updates/next` with `{}` | Claims the oldest unseen call-update notification this session may claim, and returns `{delivery, call, redelivered}`, where `delivery` is the notification record and `call` the call view at offset 0; or `null`. Before the channel is verified, it answers 409 `{code: "conflict", error: "channel not verified"}`, as the other work routes do. |
| `POST /adapter/v1/call-updates/{id}/forwarded` with `{}` | Marks the notification `forwarded`. Idempotent; 404 for another credential. |

**Submitting.** `POST /adapter/v1/calls` takes these steps, in order:
1. **Shape.** `call_id` is `call_` and 32 lowercase hex digits, `address` a string of at most 256 bytes, `operation` a string of 1 to 128 bytes, and `input` a JSON object; otherwise 400.
2. **Repeat.** A `call_id` this agent already used returns the existing call view when `address`, `operation`, and `input` are identical, and 409 `{code: "conflict"}` when they differ. Neither counts against the rate limit.
3. **Rate limit.** A call that would make more than `max_calls_per_hour` calls persisted through this credential in the preceding 60 minutes returns 429 `{code: "rate_limited", error, retry_after}`, where `retry_after` is a whole number of seconds, at least 1, until the oldest counted call leaves the window. It persists nothing.
4. **Address.** An address with two `/` names a source, and returns 400 `{code: "source", error}`. Otherwise it resolves as `call` does, over the entries `GET /adapter/v1/capabilities` would list: 409 `{code: "ambiguous", error, candidates}` and 404 `{code: "not_found", error, unanswered}` as for `call`. The operation is not checked against the entry's `operations`: the receiver refuses one it does not serve, and the call becomes `rejected`.
5. **Citation.** The first `via` entry of the resolved entry that applies to this agent: self, then policy entries in listed order.
6. **Deadline.** 15 minutes, capped by the cited policy's `valid_until` and the credential's `expires_at`.
7. **Persist.** In one transaction: the outbound record, with `origin` and `adapter_id`; the `adapter_calls` row, which is what the rate limit counts; and the `call.submitted` activity. If steps 4 to 7 cannot finish within the [wait limit](#the-wait-limit) of receipt, the route returns 503 `{code: "timeout", error}` and persists nothing.
8. **Submit.** It submits as `call` does, with retries as for tasks. Attempts after the first continue in the background.
9. **Hold.** The response is held until the call is final, or until `wait` seconds after receipt, where `wait` is the request's value capped at the wait limit, or the wait limit when absent; it is sent no earlier than step 7 completes. It answers within 100 milliseconds of the call becoming final: the daemon signals the held request when it stores the final status, and does not wait for a timer. A held request answers for the call that made it only: a repeat (step 2) holds as well.

**Results without polling.** For the first 60 seconds after any call, owner or agent, is accepted by its receiver, the daemon asks for its status with `GET /peer/v1/calls/{id}?wait=10&state=S`, where `S` is the state it has stored, one request at a time, each sent as soon as the previous answers, storing each answer's state. A stored final status is never replaced: an answer that arrives after the call became final, for example through a cancel, is discarded, and an answer whose state is earlier than the stored one (`running` stored, `queued` answered) is not stored. Held requests do not use the task polling slots. So a result reaches the daemon as soon as the receiver has it. An answer that comes back in under 1 second with the same non-final state that was sent, as from a host that predates `wait`, is followed by the next request no sooner than 1 second after the previous request was sent; an answer with a new state is followed at once. After the 60 seconds it polls without `wait`, backing off from 1 to 60 seconds as for owner calls. The window is kept in memory: after a daemon restart, a call still in it is polled with the usual backoff.

<a id="the-wait-limit"></a>**The wait limit** is 15 seconds. It is one constant in each daemon, and the adapter never states it: the adapter passes `wait` through and the daemon caps it. It must stay at or below 45 seconds, so that a held `POST /adapter/v1/calls` fits the adapter's 50-second request timeout and the tool answers within Codex's default 60-second tool timeout.

**The outbound record** gains `adapter_id`, the credential that made the call, or null for owner calls. `calls list` and `calls inspect` show agent calls with the owner's.

**The call view** is `{call_id, address, peer_host_id, operation, submit_state, state, error, created_at, deadline, result, result_part, truncated, result_bytes, offset, next_offset, note}`:
- `address` is the address as given, and `peer_host_id` the resolved host. `created_at` is when the call was persisted (step 7 of Submitting).
- `submit_state` is from the outbound record. `state` is `submitting` while it is `unknown`, `rejected` when the submission was refused, and otherwise the status record's `state`.
- `error` is the status record's `error`, or the refusal's error text for a refused submission, or null.
- **The result text** is the outbound record's stored `result` encoded the same way by every implementation: no whitespace outside strings; object keys sorted by their UTF-8 bytes; numbers exactly as the receiver sent them; strings as raw UTF-8, escaping only `"` and `\` as `\"` and `\\`, U+0008, U+0009, U+000A, U+000C, and U+000D as `\b`, `\t`, `\n`, `\f`, and `\r`, and the other characters below U+0020 as `\u00` and two lowercase hex digits. So the same result has the same `result_bytes` and part boundaries in Go and Rust. `result_bytes` is its length in bytes, or null before there is a result.
- **Inline or in parts.** When the result text is at most 65,536 bytes and `offset` is 0, `result` is the result object, `result_part` is null, and `truncated` is false. Otherwise `result` is null, `truncated` is true, and `result_part` is the longest piece of the result text that starts at `offset`, is at most 65,536 bytes, and ends on a UTF-8 character boundary. `next_offset` is the offset after it, or null when the piece reaches the end. Concatenating the parts from 0 gives the result text. Before there is a result, `result` and `result_part` are null, `truncated` is false, and `next_offset` is null.
- **`note`** is one of these exact texts:
  - while `state` is `submitting`, `queued`, or `running`: `The call has not finished. Its result arrives as a kind=call_update event; call_status reports it at any time.`
  - for `uncertain`: `The call was running when it ended without a result, so it may or may not have taken effect. Do not call it again on your own: check whether it took effect, or ask the person.`
  - for `rejected`, `expired`, and `cancelled`: `The call never ran, so it had no effect. Calling again makes a new call.`
  - for `succeeded` and `failed` with `truncated` true: `The result is in parts; call call_status with offset set to next_offset for the next part.`
  - otherwise null.

Nothing is executed twice: the daemon's retries reuse the `call_id`, and the receiver deduplicates as for any call.

### MCP tools

The shared adapter adds four tools. Calls through them are refused unless the credential has `calls`; the tools are listed either way, as `list_agents` is.

| Tool | Input | Behavior |
| --- | --- | --- |
| `list_capabilities` | `{}` | `GET /adapter/v1/capabilities`. Returns its object. Remote descriptions and input schemas appear only here, inside the result. |
| `call_capability` | `{address, operation, input, wait, call_id}` | Uses the given `call_id`, or generates one when it is absent, and posts `POST /adapter/v1/calls` with `wait` when the agent gave one. The daemon holds the response until the call is final or the wait ends, so the tool returns within the wait limit of being called. Returns the call view. |
| `call_status` | `{call_id, offset}` | `GET /adapter/v1/calls/{call_id}?offset=offset`. Returns the call view. |
| `call_cancel` | `{call_id}` | `POST /adapter/v1/calls/{call_id}/cancel`. Returns the call view. |

**Input schemas.**
- `address`: string, pattern `^[^/]+/[^/]+(/[^/]+)?$`, at most 256 characters: `PERSON/CAPABILITY` or `HOST_ID/CAPABILITY` from `list_capabilities`. A source address, with a second `/`, passes the schema so that the daemon's `source` refusal and its text reach the agent.
- `operation`: string, 1 to 128 characters.
- `input`: object, default `{}`.
- `wait`: integer, at least 0, optional. Seconds to wait for a final state. Peerspan caps it at its wait limit, 15 seconds, which is also the default; the description says so.
- `call_id`: string, pattern `^call_[0-9a-f]{32}$`; optional for `call_capability`, required for `call_status` and `call_cancel`. An agent that lost a `call_capability` response calls it again with the same `call_id`, which returns the existing call (step 2 of Submitting) instead of making a second one.
- `offset`: integer, at least 0, default 0.
- Each schema has `additionalProperties: false`. Invalid arguments return a tool error naming the tool, and call nothing.

**Results.** Each tool returns its object as JSON text. A call view is never a tool error, whatever its state. A tool error (`isError: true`) is returned for invalid arguments and for refusals:
- **Refusals that persisted nothing** (`no_calls`, `rate_limited`, `source`, `ambiguous`, `not_found`, `timeout`, `conflict`, and any other 4xx from `POST /adapter/v1/calls`) return `{call_id, address, code, error, recovery}`, plus `retry_after`, `candidates`, or `unanswered` when the daemon gave them. `recovery` is `Nothing was called or recorded.` `error` is the daemon's text, except for these codes, which use exactly: `code` is null when the daemon's refusal has none. `list_capabilities`, `call_status`, and `call_cancel` refused with 403 `no_calls` return the same shape, without `address` for any of them and without `call_id` for `list_capabilities`.
  - `no_calls`: `This session may not call capabilities. The person enables it with peerspan attach --calls.`
  - `rate_limited`: `This session reached its hourly limit of capability calls.`
  - `source`: `Sources can be called only from the peerspan CLI.`
  - `ambiguous`: `The address names a capability on more than one host; use one of candidates.`
  - `not_found`: `No capability at this address is available to this session now. It may have been unshared, or its host may not have answered (see unanswered). Check list_capabilities.`
- **A lost response** from `POST /adapter/v1/calls` returns `{call_id, address, error, recovery}`, with `recovery` `Check call_status with this call_id. If it reports not_recorded, the call was never recorded and calling again makes a new call.`
- **`call_status` and `call_cancel` on a 404** return, without an error, `{call_id, state: "not_recorded", note: "The host has no record of this call for this agent; it never ran."}`.

**Adapter details.**
- **Timeouts.** The adapter's request timeout is 30 seconds for `GET /adapter/v1/capabilities`, as for sends by address, 50 seconds for `POST /adapter/v1/calls`, and 5 seconds for the other call routes. The response limit is 16 MiB for `GET /adapter/v1/capabilities`, and 1 MiB as before for the others.
- **Instructions.** The MCP server instructions are unchanged, and stay within 2,048 characters. The guidance in this section lives in the four tools' descriptions and in `call_update` event content. The descriptions say what the tool does, that remote descriptions and schemas come from `list_capabilities`, that `call_capability` returns a `call_id` when the call has not finished and a `kind=call_update` event follows, how `truncated` and `next_offset` work, and the `uncertain` rule as in its `note`.

### Call updates

When a call made through an adapter becomes final (its outbound status becomes final with its result, or its submission is refused), the daemon creates, in the same transaction, a **call-update notification** `{id, peer_host_id, call_id, adapter_id, session_id, state, created_at, updated_at}`, with an ID of `notification_` and 32 hex digits, and `state` `unknown` or `forwarded`, following the task-update notification rules. It is bound to the session that made the call.

- **Seen.** A notification is seen, under the [Seen](live-delivery-contract.md#seen) rules of live delivery, when the session that holds it gets a call view in a final state for that call through `POST /adapter/v1/calls` (including a repeat) or `GET /adapter/v1/calls/{call_id}` (so `call_capability` and `call_status` both count), or calls `mark_seen` with the call ID. `mark_seen` accepts call IDs, `call_` and 32 hex digits, beside delivery, request, and task IDs. A notification already seen is never claimed. Only the session that holds the notification marks it seen this way. A late notification that no session holds yet is bound to a verified session of its agent that gets a final call view for its call, and is seen at once, so it is never claimed afterwards.
- **No event for a call already answered.** While a `POST /adapter/v1/calls` for a call is held, `call-updates/next` never claims that call's notification. When the call becomes final, the held request answers with the final view, which marks the notification seen, so no event follows. If the adapter loses that response, the notification is unseen and is claimed as usual.
- **The event.** Otherwise the adapter emits a channel event with `meta.kind` `call_update`, and `meta` `{call_id, notification_id, address, operation, state, error, result_bytes, truncated, session_id, redelivered}`, then acknowledges it through `forwarded`. Its content is the call view at offset 0, as JSON text, so the result or its first part and the `note` come with it. `meta.session_id` is the session that holds the notification, which may differ from the session that made the call. A channel that cannot carry null meta values, as the Claude Code channel cannot, omits those keys, and a missing key reads as null.
- **Redelivery and late arrivals** follow live delivery slice 2, as for task updates: a notification forwarded but unseen when its authorization ends returns to the agent's queue and is claimed again by the agent's next verified session with `redelivered` true, at most 3 times. One created after its session's authorization ended goes to the agent's next verified session with `redelivered` false.

### Pending work

`pending_work`, `GET /adapter/v1/pending`, and `GET /v1/sessions/{id}/pending` gain `calls`, ordered oldest first by `created_at`:
- calls made by this session, or by an ended session of the same agent on this host, that are not final. A session has ended when its authorization has: detached, revoked, replaced, or expired;
- calls whose call-update notification this session holds and has not seen.

Each is `{call_id, address, operation, state, error, result_bytes, created_at, deadline, session_id, redelivered}`, with `state` as in the call view, `session_id` the session that made the call, and `redelivered` from the notification, false when there is none. As with task adoption, a new session of the agent so sees the unfinished calls its earlier sessions started, and can follow them with `call_status` and `call_cancel`.

`peerspan session pending` includes `calls`. With `--hook` it prints nothing only when all four lists are empty, and its TEXT becomes `Peerspan work this session still owes, listed after /clear, compaction, or resume. Finish each task with the task_* tools, answer each delivery with reply, and check each call with call_status; call pending_work for the current list. ` followed by the object as compact JSON.

### Status

`GET /v1/status` is unchanged, and no attention item is added. Agent calls appear in the existing activity kinds `call.submitted` and `call.updated`, with the receiver's `call.*` kinds as before. Claims of call-update notifications record no activity.

### Persistence

Database version 18 adds:

```sql
CREATE TABLE adapter_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id), adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), session_id TEXT NOT NULL REFERENCES sessions(id), called_at_ms INTEGER NOT NULL, PRIMARY KEY(peer, call_id), UNIQUE(agent_id, call_id), FOREIGN KEY(peer, call_id) REFERENCES outbound_calls(peer, call_id));
CREATE INDEX adapter_calls_rate ON adapter_calls(adapter_id, called_at_ms);
CREATE TABLE call_update_notifications (id TEXT PRIMARY KEY, peer TEXT NOT NULL, call_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, seen_at TEXT, redeliveries INTEGER NOT NULL DEFAULT 0, returned_at TEXT, UNIQUE(peer, call_id));
PRAGMA user_version = 18;
```

- **`adapter_calls`** binds an agent's call to its credential and session, and counts it for `max_calls_per_hour` at `called_at_ms`. A row is written only with the outbound record, and never on a repeat or retry.
- **`call_update_notifications`** columns follow the live delivery columns of the same names: `seen_at`, `redeliveries`, and `returned_at` behave as for `task_update_notifications`, and a claim after a return rebinds `session_id` and the record in place.
- **Credential records** gain `calls` and `max_calls_per_hour` in their JSON. A record without them reads as `calls` false and `max_calls_per_hour` null, so migration rewrites none.
- **Outbound call records** gain `adapter_id`; a record without it reads as null.
- **Version checks.** Older binaries reject version 18, and version 18 binaries reject version 19. Migration from 17 creates the two tables and the index, and sets the version, in one transaction.

### Verification

`conformance/capabilities.py` gains these cases, written from this section by an author independent of both implementations and of the adapter. They run across all four Go/Rust CLI and daemon pairings, with `--probe`, the Go coordinator, OpenSSH, `--node` for the real shared adapter, and a deterministic MCP consumer, using the fixture MCP server.
- **Opt-in:**
  - `attach --calls`, `--no-calls`, and `--max-calls-per-hour`, and their refusals;
  - the prompt at a terminal answered `y` and declined, and no prompt answering no without a terminal;
  - `calls` and `max_calls_per_hour` on the adapter record and in `attach` output;
  - `POST /v1/adapters/setup` refusing `max_calls_per_hour` without `calls`;
  - re-attaching onto a never-connected credential: a differing `--calls`, `--no-calls`, or `--max-calls-per-hour` refused, naming the stored setting, and a matching one accepted; after replacement, the prompt asked again;
  - each adapter call route answering 403 `no_calls` without opt-in, and the tools returning the `no_calls` text.
- **Listing:**
  - `list_capabilities` through policy and through self from a trusted host;
  - nothing from an untrusted host of the same person;
  - sources opened to the host never listed;
  - an `agent:` rule listed for that agent and not for another agent of the same host;
  - `from_agent` in `GET /peer/v1/capabilities`;
  - `discover` unchanged by `agent:` rules;
  - `unanswered` with a stopped host.
- **Calls:**
  - a call finishing within `wait`, with `origin` stored on both hosts and the citation chosen as specified;
  - a call taking 10 seconds returned final by `call_capability` with the default `wait`;
  - a call outlasting `wait`, returning `queued` or `running` with the pending note, then one `call_update` event, and `call_status` returning the result;
  - no `call_update` event for a call `call_capability` already returned final;
  - `wait` 0 answering once the call is persisted, and a `wait` above the limit answering no later than the wait limit;
  - a call whose tool takes 2 seconds returned final by `call_capability` within 3 seconds of the tool call, between Go and Rust hosts in every pairing;
  - the daemon's held `GET /peer/v1/calls/{id}?wait=10`, observed at the receiver: at most one open at a time per call, and answered within 1 second of the call starting to run and within 1 second of it finishing;
  - a receiver that predates `wait` (a version 17 host) asked again no sooner than 1 second after each previous request was sent, and the call still returned final;
  - `wait` 11 on the peer route refused with 400;
  - a source address refused with `source`;
  - the same source address through `call_capability` returning the `source` text;
  - an operation the capability does not list submitted and `rejected` by the receiver;
  - `ambiguous` with candidates, and `not_found`;
  - a call refused at its first attempt (the receiver's 429 `limit`) returned final by `call_capability` with no `call_update` event;
  - a call whose update is claimed while `call_capability` waits returning the final view, with no `call_update` event and the notification seen;
  - an `agent:` rule authorizing only its agent, refused for another agent of the same host;
  - a repeated `call_id` returning the same call, and a changed one 409, through the route and through `call_capability` with `call_id` given;
  - `call_cancel` while queued (`cancelled`, never-ran note) and while running (`uncertain`, the uncertain note);
  - `uncertain` after the receiver restarts mid-call, with exactly one execution recorded by the fixture;
  - `rejected` at submission, `expired`, and `rejected` at the recheck before start, each with the never-ran note;
  - the receiver's 429 `limit` making the call `rejected`.
- **Rate limit:**
  - with `--max-calls-per-hour 2`, the third call refused with `rate_limited` and `retry_after`, persisting nothing;
  - repeats and daemon retries not counted;
  - sends by address and calls counted separately.
- **Results:**
  - a result of exactly 65,536 bytes inline, and one byte more in parts;
  - paging with `offset` until `next_offset` is null, the parts concatenating to the result text, a multi-byte character at a part boundary, and a bad `offset` refused;
  - `result_too_large` as `failed`.
  - a result with unsorted keys, escapes, control characters, non-ASCII text, and number spellings a JSON encoder would normally rewrite (`-0`, `1.50`, `1e+00`, `1E2`, `100000000000000000000000`) giving the same `result_bytes` and parts from Go and Rust daemons, with each number spelled as the receiver sent it;
  - a non-zero `offset` before there is a result refused with 400.
- **Call updates and pending work:**
  - `mark_seen` and `call_status` marking a notification seen;
  - `call-updates/next` answering 409 before verification;
  - redelivery to the next attachment after replacement, with `redelivered`, and at most 3 times;
  - a call finishing after its session ended reaching the next verified session;
  - `call_status` from that session answering for the earlier session's call;
  - a late notification no session holds marked seen by the next session's `call_status`, and never claimed afterwards;
  - `calls` in `pending_work`, `session pending --json`, and the `--hook` text, including an unfinished call made by the agent's ended session, with its `session_id`.
- **Revocation:** after `unshare`, `call_capability` refused with the `not_found` text; a running call finishing.
- **Migration:** from version 17 to version 18, with existing credentials reading `calls` false.

`conformance/live_capability_agents.py` runs live acceptance with real harnesses, separately from deterministic conformance, and records its results in `docs/results/capabilities-live.json`. Bob's host has a `github-issues` capability built on a GitHub MCP server in his Claude Code configuration, with `list_issues` selected, shared with Alice by `share github-issues --with person:ALICE`. Alice attaches with `--calls`. For each of Claude Code, Codex, and OpenCode in turn, Alice's session is asked in plain words to list the open issues of a test repository through Bob's capability, and the run checks that:
- the model called `list_capabilities` and `call_capability` with `bob/github-issues` and `list_issues`, and its answer names issues from the repository;
- both hosts recorded the call, with Alice's agent as `origin`;
- after Bob runs `unshare github-issues --with person:ALICE`, the next call is refused with the `not_found` text, nothing is executed on Bob's host, and the model's answer says it can no longer reach the capability.

Before each harness's run Bob shares again. The report records each harness's version, the adapter connection's `protocol_version` on Alice's host (the negotiated MCP revision for Claude Code and Codex, `opencode-plugin-VERSION` for OpenCode; [live delivery contract](live-delivery-contract.md#doctor)), which must be non-null for every harness, and the model's tool calls and answers, without claiming model behavior from notification acknowledgements alone.

## Sharing with one agent (slice 3)

Slice 3, item C, as designed in its [proposal](capabilities-slice3-agent-shares-proposal.md) and accepted in [decision 16](#owner-decisions). An owner names one agent of another person as `PERSON/AGENT`, the CLI turns it into the existing `agent:HOST_ID/AGENT_ID` principal, and `shares` labels such principals by asking their hosts. An owner can also call, and list capabilities, as one of their own agents. Where this section differs from the slices above, it applies.

Unchanged: the policy statement, its JSON, and its test vector; coordinator handling and propagation; `agent:` matching under [Agent origin and agent principals](#agent-origin-and-agent-principals) (host and agent ID only, never the person or the name); the adapter and its four MCP tools; the database schema. The only new state is an in-memory label cache in the daemon.

### Agent addresses

`share`, the guided `share --with`, and `unshare` accept these forms for `--with`, beside the principal forms they already take:

| Form | Example | Meaning |
| --- | --- | --- |
| `PERSON/AGENT` | `alice/claude-laptop` | The agent named `AGENT` on one of the hosts bound to the person `PERSON` in the selected network. `PERSON` is a person label or person ID, resolved as other person arguments are. |
| `HOST_ID/AGENT` | `host_3f…/claude-laptop` | The agent named `AGENT` on that host. It also reaches hosts without a bound person, and persons whose label contains `/`. |
| `agent:HOST_ID/AGENT_ID` | as before | Used as given, with no lookup. |

**Parsing.** For a value with no `KIND:` prefix (`person:`, `group:`, `agent:`) that is not `everyone` or `network`:
- **No `/`.** A person label or ID, as before.
- **Exactly one `/`.** An agent address, always; it is never read as a person label. The left part is a host ID when it is `host_` followed by 64 lowercase hex digits, and a person otherwise. A person whose label contains `/` is named `person:LABEL` or by person ID.
- **Two or more `/`.** Refused with exit 1 before anything is signed: `invalid recipient "a/b/c": use PERSON/AGENT, HOST_ID/AGENT, or person:LABEL for a label that contains /`.
- **The name.** `AGENT` must be an [addressable name](launch-contract.md#names-and-addresses) (1 to 64 of `a-z 0-9 . _ -`, starting with a letter or digit). Otherwise exit 1: `invalid agent name "X"`.

`allow` and `deny` take the same forms, with the same resolver ([launch contract](launch-contract.md#principals-and-sizes)).

### Resolving an agent address

The CLI resolves an agent address before it shows the review, through the local route `GET /v1/agent-lookup?address=A&network=N`; the CLI sends no peer traffic itself. `N` is the network the share is written to: `--network`, or the host's only network. The daemon takes these steps:
1. **Hosts to ask.**
   - For `HOST_ID/AGENT`: that host, which must be a current, unrevoked member of `N`; otherwise 404 `{code: "unknown_host", error}` with the text `unknown host HOST_ID in network N`.
   - For `PERSON/AGENT`: the person is resolved in `N`'s map as other person arguments are. A person that matches no current person is 404 `{code: "unknown_person", error}`; a label matching several persons is 400 `{code: "invalid", error}`, naming the candidates. The hosts are the current, unrevoked members of `N` bound to that person.
2. **This host.** When one of those hosts is this host and this host has an agent whose name is exactly `AGENT`, the lookup is refused with 400 `{code: "local", error}`: `ADDRESS is on this host, and a host never calls itself. Share with an agent on another machine.` When this host is among them without such an agent, it is skipped and not asked.
3. **Asking.** Each other host is asked with the [lookup route](#the-lookup-route) by `name`, at most 8 at once, each within 5 seconds, over the usual peer transport, relay included.
   - A host that answers 404 without a JSON `code` predates the route. For that host only, an agent with that name in this host's cached directory entries for `N` counts as its answer; without one, the host is listed in `unanswered` with the error `unsupported`.
   - A host that does not answer, or answers anything else, is listed in `unanswered` with a short error, such as `timeout`.
4. **Result.**
   - **One match**, whatever the others answered: 200 with `{principal, host_id, agent_id, person_id, address, unanswered}`. `principal` is `agent:HOST_ID/AGENT_ID`; `person_id` is the host's bound person in `N`, or null; `address` is `PERSON_LABEL/AGENT` when the host is bound to a person whose label contains no `/`, otherwise `HOST_ID/AGENT`. `unanswered` lists the hosts that did not answer, possibly `[]`.
   - **Several matches:** 409 `{code: "ambiguous", error, matches: [{address, network_id}]}`, where each `address` is `HOST_ID/AGENT`, sorted.
   - **None:** 404 `{code: "unknown", error, unanswered}`. The text is `PERSON has no agent named AGENT on the hosts that answered.` (for `HOST_ID/AGENT`, `HOST_ID has no agent named AGENT.`), followed, when `unanswered` is not empty, by ` Not answered: HOST_ID (ERROR), …. Try again when it is online, or use agent:HOST_ID/AGENT_ID.`
   - `unanswered` entries are `{host_id, error}`, sorted by host ID.
5. **Syncing.** On `unknown_person` or `unknown_host`, the CLI syncs the network once (`POST /v1/networks/{id}/sync`) and asks again before failing, as `allow` does for person labels.

Other refusals of the route: a missing `address`, or one that is not an agent address under [Parsing](#agent-addresses), is 400 `{code: "invalid", error}`; a network this host does not belong to is 404. The CLI prints the daemon's `error` text and exits 1, with nothing signed.

### The lookup route

`GET /peer/v1/networks/{network_id}/agent-lookup?name=NAME`, or `?agent_id=AGENT_ID`, with exactly one of the two.
- **Who may ask.** Callers that are current, unrevoked members of that network, as for the [agents route](launch-contract.md#peer-route). Any other caller gets 403. A network this host does not belong to is 404 `{code: "not_found", error}`.
- **Answer.** When allowed, always 200 with `{agent: {agent_id, name}}` or `{agent: null}`.
  - `name` matches a registered agent of this host whose name is exactly `NAME` and is addressable. A non-addressable `NAME` matches nothing.
  - `agent_id` matches any registered agent of this host, and returns its name, or null for `name` when the name is not addressable.
  - Answering 200 with `agent: null` keeps 404 without `code` meaning "route not supported".
- **Disclosure.** It says only whether an agent with that exact name or ID exists on this host: no connection state, no authorizations, never a list.
- **Bounds.** Neither or both parameters, an empty value, any other parameter, or a query string longer than 256 bytes is 400 `{code: "invalid", error}`. The response is at most 4 KiB, and callers, `peerspan-peer-probe` included, accept at most 4 KiB from this route.

### Sharing with an agent

**The review.** For an agent principal, the review keeps every line it has today, with these changes. Lines are compared after trimming leading and trailing whitespace; `PERSON` below is the host's bound person's label in the selected network.
- **Recipient.** The recipient is the resolved `address` for an agent address, or the principal as given for the `agent:` form. For an agent address, the next line is `agent AGENT_ID on host HOST_ID, bound to PERSON`, or `agent AGENT_ID on host HOST_ID, not bound to a person` for a host without a bound person.
- **Not checked.** When `unanswered` is not empty, a line `Not checked: HOST_ID (ERROR), HOST_ID (ERROR)` follows, in `unanswered` order. Without unanswered hosts there is no such line.
- **Reach.** The reach sentence uses the same recipient text in place of `PRINCIPAL`.
- **The agent paragraph.** After the reach sentence, for every `agent:` principal, including the `agent:` form, three lines:
  1. `Only calls that HOST_ID says come from this agent are allowed.`
  2. For a host bound to a person: `That host makes the claim itself: PERSON, and any program that can run peerspan as PERSON on that machine, can call as this agent. PERSON's other machines and other agents, and other people, cannot.` For a host without one: `That host makes the claim itself: anyone, and any program, that can run peerspan as that host's owner can call as this agent. Other machines, other agents, and other people cannot.`
  3. `The share stays with this agent on this machine. If the agent is set up again on another machine, share it again.`
- **Trusted own agent.** When the host is bound to the signing person in the selected network and is in `trusted_hosts` of that person's current policy for it, one more line: `This machine is trusted, so this agent already reaches all your capabilities through self access. This share matters only if you untrust it.`

Then `Share? [y/N] ` as before. Sharing with an agent on another host of the signing person is allowed; only an agent on this host is refused (`local`).

**Output.** `share` prints `{policy, capability, principal, recipient, created}`. `recipient` is `{address, host_id, agent_id, person_id}` from the lookup for an agent address, and null for every other form, the `agent:` form included. Sharing again with an agent already in the rule signs nothing, as for any principal, and still prints `recipient`.

### Agent recipients in listings

**Labels and states.** Each `agent:HOST_ID/AGENT_ID` recipient has a `label` and an `agent_state`. The state is, in this precedence:
1. `host_gone`: `HOST_ID` is not a current, unrevoked member of the recipient's network;
2. `unanswered`: the host did not answer the lookup by `agent_id` (any non-200 answer, including a host that predates the route, unless its cached directory entries list that agent ID, which then count as `found`);
3. `not_found`: the host answered `agent: null`;
4. `unbound`: the host answered with the agent, but is not bound to any person in that network;
5. `found`: the host answered with the agent, and is bound to a person.

`label` is `PERSON/NAME` when the host is currently bound to a person whose label contains no `/`, otherwise `HOST_ID/NAME`, where `NAME` is the agent's addressable name from the latest answer that found it during the daemon's life. It is null when no such name is known. The person is always the host's **current** person from the network map; no person is stored with a share, so if the host is later bound to someone else, the label names the new person.

**`GET /v1/capabilities` and `GET /v1/capabilities/{name}`.** Each recipient whose principal is `agent:` gains `agent_state`; its `label` follows the rule above. Other recipients are unchanged, `{network_id, principal, label}`. Without a query, the daemon sends no peer traffic: it uses its cache of the last lookup of each agent, recomputes `host_gone`, `unbound`, and the person part of `label` from the current map, and reports `unanswered` for an agent it has not looked up since it started. With `?lookup=true`, it first looks up every agent recipient by `agent_id` on its host, at most 8 hosts at once, each within 5 seconds, skipping hosts that are `host_gone`, and updates the cache.

**`shares`, `capability list`, and `capability show`** use `?lookup=true`.
- The overall layout of `shares --json` is not shared, but each recipient object of a capability on this host whose principal is `agent:` is exactly `{network_id, principal, label, agent_state, unshare}`, where `unshare` is the command that removes it: `peerspan unshare NAME --with HOST_ID/AGENT_NAME --network NETWORK_ID` when `agent_state` is `found` and `label` is not null, where `AGENT_NAME` is the part of `label` after its last `/`, and `peerspan unshare NAME --with agent:HOST_ID/AGENT_ID --network NETWORK_ID` otherwise. The command uses the host's address rather than `label`: `HOST_ID/AGENT_NAME` names exactly that agent even when the person has an agent of the same name on another host, and it is always safe to paste into a shell.
- The readable layout marks agent recipients, for example `alice/claude-laptop (agent)` and, for any state other than `found`, `carol/codex-desk (agent, gone)`. Its wording is not shared.

Principals of agents that are gone are never removed automatically. Each still uses one of the rule's 64 principal slots.

### Unsharing an agent

`unshare NAME --with ADDRESS` resolves an agent address as `share` does and removes the resulting principal. Its output is `{policy, capability, principal, recipient, removed}`, plus `note` as below; `recipient` is as for `share`, so it is null for every form other than an agent address, in `unshare` as in `share`.
- **When resolution fails** with `unknown` or `unknown_host`, the command exits 1 with nothing signed. Its stderr gives the resolver's error and then, for each `agent:` principal of the capability's rule for this host in the selected network whose host is one of the address's hosts (that host for `HOST_ID/AGENT`; for `PERSON/AGENT`, the hosts bound to the person and every host that is no longer a member of the network, whose binding left with it), a line containing `peerspan unshare NAME --with agent:HOST_ID/AGENT_ID --network NETWORK_ID`. So a gone agent can always be removed.
- **Nothing removed.** With `removed: 0` for an agent address, `note` is `the rule for NAME on this host does not name PRINCIPAL. Access through person:PERSON, a group, or everyone is unaffected.`, where `PERSON` is the host's bound person's label; for a host without one, the middle reads `Access through a group or everyone is unaffected.`
- **Agents left after a person.** When `unshare --with PERSON` (or `person:PERSON`) removes the person and the rule still names `agent:` principals whose hosts are bound to that person in the selected network, the output adds `note`, with one sentence per such principal, in rule order, joined by a space: `LABEL still has its own share. Run peerspan unshare NAME --with ADDRESS --network NETWORK_ID to remove it.` `LABEL` is the agent's `label` from a lookup by `agent_id` and `ADDRESS` its `HOST_ID/AGENT_NAME`, as for the `unshare` command in `shares`; when the agent is not `found` or has no label, both are the principal.

### The recipient's `discover`

**Agent-only capabilities.** In `GET /v1/discover` and `discover`, a capability whose every `via` entry has a non-null `from_agent` is now listed instead of omitted. Such an entry keeps all its `via` entries, and gains `for_agents: [{agent_id, name}]`, one per distinct `from_agent` in `via` order, where `name` is that local agent's name, or null when this host has no such agent. Capabilities with at least one `via` entry whose `from_agent` is null are listed as before: only those `via` entries, and no `for_agents` key. The readable line for an agent-only capability says `only for your agent NAME` (or `agents NAME, NAME`).

**`call` without `--from-agent`.** Address resolution in `call` and `POST /v1/calls` without `origin` matches over the same entries as `discover`, agent-only ones included. When the resolved entry is agent-only, the call is refused before anything is persisted with 403 `{code: "agent_only", error, for_agents}`, with the text `ADDRESS is shared only with your agent NAME. Add --from-agent NAME to call as that agent.` With several agents, it reads `your agents NAME, NAME` and names the first in `--from-agent`. An agent whose name is null is named by its ID.

**`discover --from-agent AGENT`** shows the capabilities that agent's `list_capabilities` would show. `GET /v1/discover?from_agent=AGENT_ID` returns exactly the object of [`GET /adapter/v1/capabilities`](#adapter-routes) for that agent, `{capabilities: [ENTRY], unanswered}`, without `agents` and without sources. With `person` or `network`, the hosts asked and the entries kept are narrowed as in `discover`; with neither, the object equals what the agent's `list_capabilities` returns at the same moment. It does not need `calls` on any credential. An unknown agent ID is 404.

### Calling as an agent

**Syntax.** `call ADDRESS OPERATION [...] [--from-agent AGENT [--from-session SESSION_ID]]`, and `discover [PERSON] [--network ID] [--json] [--from-agent AGENT]`.
- **`AGENT`** is the ID of an agent registered on this host, or else the exact name of one. The CLI resolves it with `GET /v1/agents` before anything else: an ID that matches is used; otherwise a name matching exactly one agent is used; a name matching several, which unique names make unreachable today, is refused, `several agents on this host are named AGENT; give the agent ID`; none is refused, `no agent AGENT on this host`. Each refusal exits 1 with nothing persisted.
- **`--from-session`** names one of that agent's sessions. Without `--from-agent` it is refused with exit 1: `--from-session needs --from-agent`. `discover` does not take it.
- **Own flags.** `--from-agent` and `--from-session` are `call`'s own flags, like `--input`, `--deadline`, `--wait`, and `--network`: a tool property with one of those names must be given in `--input`.
- **Who.** The owner may act as any agent registered on this host, whether or not it has an `attach` profile or `calls` on a credential.

**`POST /v1/calls`** accepts optional `origin: {agent_id, session_id}`, where `session_id` may be absent. It is checked before anything else, as for `message send`: an unknown agent ID, or a session that is not one of that agent's sessions, is 404 before anything is persisted. With `origin`, the call is made as that agent:
1. **Sources.** An address with two `/` names a source, and is refused with 400 `{code: "source", error}`: `Agents cannot call sources; call them without --from-agent.`
2. **Resolution** uses the agent's view: the entries of kind `capability` that have a `via` entry of kind `self`, or of kind `policy` with `from_agent` null or this agent, as `GET /adapter/v1/capabilities` keeps them; errors are as for `call`.
3. **Citation.** The first of the resolved entry's `via` entries that apply to this agent, self first, then policy entries in listed order; with `network`, the first such entry from that network.
4. **The request** to the receiver carries `origin: {agent_id, session_id}`, with `session_id` omitted when not given.
5. **Records.** The outbound record stores `origin` in `request`, and has `adapter_id: null`. That pair, an origin with no adapter, marks an owner call made as an agent. The receiver stores and shows `origin` as for any call.
6. **Limits.** No `adapter_calls` row is written, so the call does not count against the agent's `max_calls_per_hour`. The receiver counts it in the rule's budget as usual, per rule identity and caller.
7. **The agent does not see it.** No call-update notification is created; it is not in `pending_work` or `session pending`; and the agent's `call_status` and `call_cancel` answer `not_recorded`. The owner follows it with `calls inspect`, `calls list`, and `calls cancel`.
8. **Output and exit codes** are as for `call`.

### Verification

`conformance/capability_agents.py` gains these cases, written from this section by an author independent of both implementations, across all four Go/Rust CLI and daemon pairings, with `--probe`, the Go coordinator, OpenSSH, and `--node` where an adapter is used:
- **Forms:**
  - `share --with PERSON/AGENT` and `--with HOST_ID/AGENT` storing the same `agent:HOST_ID/AGENT_ID` principal;
  - `agent:HOST_ID/AGENT_ID` stored as given, with `recipient` null;
  - a value with two `/` refused with the `invalid recipient` text, and a non-addressable agent name refused with `invalid agent name`, each signing nothing;
  - a person whose label contains `/` shared with through `person:LABEL`, and that person's agent through `HOST_ID/AGENT`.
- **Resolution:**
  - an agent the caller's directory does not list (no rule lets the caller reach it) found through the lookup route;
  - `unknown` with `unanswered` naming a stopped host, and the not-answered text;
  - one match while another host of the person is stopped: the share goes ahead, the review has the `Not checked:` line, and the lookup's `unanswered` lists the host;
  - `ambiguous` with `matches` when two hosts of the person each have an agent with the name;
  - `local` for an agent on this host, through `PERSON/AGENT` and `HOST_ID/AGENT`;
  - `unknown_host` for a host ID that is not a member;
  - a host that predates the route (simulated with a probe-served 404, or an older build) resolved from the directory cache, and `unknown` listing it as `unsupported` when the cache lacks the agent;
  - the local route's JSON shapes for each outcome.
- **Lookup route:** by `name` and by `agent_id`; 200 with `agent: null` for an unknown name or ID, and for a non-addressable name; by `agent_id` for an agent with a non-addressable name returning `name: null`; 403 for a caller that is not a member; 404 with `code` for a network the host is not in; 400 for neither or both parameters and for a query over 256 bytes.
- **Review and output:** the recipient line and the `agent … on host …` line, bound and unbound; the reach sentence with the address; the three agent-paragraph lines; the trusted-own-agent line for an agent on a trusted host of the signer, and its absence for an untrusted one; `recipient` in `share` JSON; a repeat signing nothing.
- **Authorization:** the shared agent's adapter calls accepted; another agent on the same host refused; an agent with the same name on another host of the same person refused.
- **`shares`:**
  - `found` with `PERSON/NAME`, `unanswered` for a stopped host, `not_found` after the fixture deletes the agent's record on its host while that daemon is stopped, `host_gone` after the host is revoked, and `unbound` after the host is unbound; the label using the host's current person;
  - the `unshare` command for each state, by `HOST_ID/AGENT_NAME` for `found` (also when the person has an agent of that name on another host) and by principal otherwise; the note after `unshare --with PERSON` naming `--network`;
  - `GET /v1/capabilities` without `lookup` sending no lookup (observed with a stopped host: it answers at once) and reporting cached states.
- **`unshare`:** by `PERSON/AGENT`, with `recipient`; the fallback listing with each `agent:` command when the agent's host is stopped, and when it was revoked; the `removed: 0` note for an agent address; the note after `unshare --with PERSON` naming the agent shares that remain.
- **Recipient views:**
  - `for_agents` in default `discover` for an agent-only capability, with the agent's name, and none on capabilities the owner can call;
  - `call` without `--from-agent` refused with 403 `agent_only` and its text, persisting nothing;
  - `discover --from-agent` by ID and by name equal to the agent's `list_capabilities`, including an agent-only capability and excluding sources.
- **`call --from-agent`:**
  - by agent ID and by agent name, with and without `--from-session`;
  - an unknown agent, an unknown session, and another agent's session, each refused before persisting; `--from-session` without `--from-agent` refused. (A name shared by two agents cannot be created, since names are unique within a host; its refusal stays as defensive behavior and is not a case.)
  - a source address refused with `source`;
  - `origin` stored on both hosts, and `adapter_id` null in the outbound record;
  - not counted against the agent's `max_calls_per_hour` (with `--max-calls-per-hour 1`, owner calls as the agent do not block the agent's own call), and counted in the receiver's rule budget (429 `limit` after `max_calls_per_hour` calls);
  - invisible to the agent: `call_status` answers `not_recorded`, `pending_work` does not list it, and no `call_update` event arrives.
- **Replaced slice 2 case.** "`discover` unchanged by `agent:` rules" now reads: capabilities the owner can call keep only their `from_agent: null` entries, and agent-only ones are listed with `for_agents`.
- **Unchanged:** the policy v2 test vector.

`conformance/launch_onboarding.py` gains the `allow` and `deny` cases listed in the [launch contract](launch-contract.md#verification-2).

## Per-call approval (slice 3)

Roadmap milestone 10, slice 3, item B, as accepted in [decision 16](#owner-decisions) from its [proposal](capabilities-slice3-approval-proposal.md). The owner can require that calls to selected operations of a capability wait until the person approves each one at a terminal on the serving host. It extends the calls, agent tools, and status sections above; where they differ, this section applies. The behavior is the same in Go and Rust hosts and in the shared Node adapter.

Out of scope: approving from another machine or a dashboard, signed approvals, approvals that cover more than one call, per-recipient exemptions, and deadlines longer than 15 minutes.

### Terms

| Term | Meaning |
| --- | --- |
| **Approval requirement** | The `approval` field of a capability record: which operations need approval, and whether self-access calls from agents do. |
| **Approval** | The record of one received call's approval, keyed like the call by `(sender, call_id)`: `pending`, then `approved`, `denied`, `expired`, or `cancelled`. |
| **Approver** | The person, acting through the owner CLI on the serving host. Agents never approve. |

An approval covers exactly one call: one sender, one `call_id`, one input. It never covers another call, even one with the same input.

### The requirement

The capability record gains `approval`:

```json
"approval": {"operations": "changing", "agent_self": true}
```

- **`operations`** is one of:
  - `"none"`: no call needs approval;
  - `"changing"`: a call to a tool operation needs approval when that tool's entry in the snapshot the call runs against (the capability's own snapshot for a capability with its own credential, otherwise the source's), read when the call is accepted, has `read_only` false. `read` never needs approval under `"changing"`;
  - `"all"`: every operation, `read` included;
  - a list of operation names: each is one of the record's `operations`, or `read` when the record has `resources`. The list is non-empty, and is stored without duplicates, sorted by byte order.
- **`agent_self`** is a boolean, default `true` (see [Which calls need approval](#which-calls-need-approval)).
- **Reading.** A record without `approval`, including every record written before this slice, reads as `{"operations": "none", "agent_self": true}`, and every response that shows a capability record shows `approval` in that form.
- **Sources.** A source called as an implicit capability (`AGENT/SERVER`) never needs approval.
- **Not in policy.** The requirement lives only in the record on the serving host. It is never signed, never sent to coordination, and changing it signs nothing.

### Commands

| CLI | Local API | Behavior |
| --- | --- | --- |
| `capability create NAME --from SOURCE … [--approval none\|changing\|all\|OP[,OP...]] [--no-agent-self-approval]` | `POST /v1/capabilities` gains optional `approval: {operations, agent_self}` | Stores the requirement with the record. An absent `approval` means `{"operations": "none", "agent_self": true}`; within it, an absent `agent_self` means `true`. `--no-agent-self-approval` sends `agent_self: false`; without `--approval` it sends `operations: "none"`. A list name that is not an operation of the record (or `read` without `resources`), an empty list, or any other value is 400. `approval` is part of the record for the repeat rule, compared after reading defaults: an identical repeat returns 200, a different one 409. |
| `capability approval NAME (none\|changing\|all\|OP[,OP...]) [--agent-self\|--no-agent-self]` | `PUT /v1/capabilities/{name}/approval` with `{operations, agent_self}` | Replaces the requirement and returns the record as `capability show` does, with status 200. `operations` is required, with the values and refusals of `create`. `agent_self` is optional: absent keeps the record's current value; the CLI sends it only when `--agent-self` or `--no-agent-self` is given (both together are refused with exit 1 before any request). Signs nothing and needs no person key. Records `capability.approval_changed` (subject: the name), also when nothing changed. An unknown name is 404. It applies to calls accepted afterwards (see [Acceptance](#acceptance-with-approval)). |
| `capability show NAME`, `capability list [--json]`, `shares [--json]` | `GET /v1/capabilities`, `GET /v1/capabilities/{name}` | Show `approval` in every record. The readable `capability list` line adds `approval: MODE`, where `MODE` is `none`, `changing`, `all`, or the list joined with `,`, and `+agent_self` or `-agent_self`. |
| `share NAME --with …` | as before | The review gains the approval lines (below). `share` of an existing capability never changes its requirement; `--approval` or `--no-agent-self-approval` given with `share NAME` is refused with exit 1 before anything is signed. |
| guided `share --with … [--approval …] [--no-agent-self-approval]` | as before | Creates the capability with the requirement. At a terminal, when `--approval` is not given and any selected operation is a tool whose snapshot entry has `read_only` false, it asks right after the operations are chosen: `Require your approval for each call to tools that can change things? [Y/n] `, reading one line from stdin. An empty line, `y`, or `yes` (any case) means `changing`; anything else means `none`. Without a terminal, or with `--approval`, nothing is asked and `--approval` decides, absent meaning `none`. `--no-agent-self-approval` sets `agent_self` false either way. |

**The review lines.** `share` prints, on stderr, right after the operation and resource lines of the review and before the credential line, at most one of these lines, where the covered operations are those the requirement covers (every tool with `read_only` false under `"changing"`; the list's names under a list; every operation under `"all"`), in the order of the record's `operations` followed by `read`:
- under `"all"`: `Every call waits for your approval at this machine (peerspan approvals).`
- otherwise, when at least one operation is covered: `Calls to OP, OP wait for your approval at this machine (peerspan approvals).`, with the covered operations joined by `, `;
- otherwise, when some selected tool has `read_only` false: `No call waits for your approval. To require it: peerspan capability approval NAME changing`, with `NAME` the capability name;
- otherwise nothing.

Under `"changing"`, it then prints one more line: `Tools are marked by the server itself; a tool it wrongly marks read-only runs without approval.`

### Which calls need approval

At acceptance, a call needs approval when both hold:
1. **The operation is covered:** the capability's requirement covers the call's operation, as defined above.
2. **The call is not exempt.** Exempt are:
   - every call to a source;
   - a call citing `self` without `origin` (the person at the CLI of a trusted machine);
   - a call citing `self` with `origin`, when `agent_self` is false.

A call citing `policy` follows the requirement, whatever its origin.

<a id="acceptance-with-approval"></a>
### Acceptance

`POST /peer/v1/calls` authorizes exactly as before: citation, blocks, capability, bounds, and budget, in that order, with the same refusals. A repeat of an accepted `call_id` is answered as before, before any of the following, and creates nothing. Then, for a new call:
1. **Need.** It decides whether the call needs approval, as above. The decision is made once and stored: changing the capability's requirement later never adds or removes the approval of a call already accepted. A call accepted without approval runs without it even if approval is turned on while it is queued; turning approval off neither approves nor removes pending approvals.
2. **Pending limit.** At most 20 approvals may be `pending` per pending key. The pending key of a call citing `policy` is its budget key (rule identity and caller, as for `max_calls_per_hour`); of a call citing `self`, it is the caller alone: the sender's bound person in the cited network, or else the sender's host ID. A call that would be the 21st is refused with 429 `{code: "limit", error: "too many calls are waiting for approval", limit: "max_pending_approvals"}` and persists nothing. The check follows the budget check, so a call over both limits gets the `max_calls_per_hour` refusal.
3. **Persist.** In one transaction: the received call as `queued`; its approval as `pending`, with `expires_at` equal to the call's `deadline`; the [notice](#the-notice) for the capability's source agent; and the activities `call.received` and `call.approval_requested`.
4. **Answer.** 200 with the status record, whose `approval` is the pending object.

The call counts against `max_calls_per_hour` at acceptance, as any accepted call, whether it is later approved, denied, expired, or cancelled.

### The approval record

`{sender_host_id, call_id, state, capability, operation, changes_things, caller, origin, input_sha256, requested_at, expires_at, decided_at, reason}`:
- `state`: `pending`, `approved`, `denied`, `expired`, or `cancelled`.
- `changes_things`: for a tool operation, the negation of its snapshot entry's `read_only` at acceptance; `false` for `read`.
- `caller`: `{person_id, person_label, host_id, via}`. `host_id` is the sender. `person_id` is the sender's bound person in the cited network, or null. `person_label` is that person's binding label in the cited network's map, as message events show it, or null. `via` is `policy` or `self`, as cited.
- `origin`: the call's `origin` (`{agent_id, session_id}`), or null.
- `input_sha256`: as stored with the received call.
- `requested_at`: the acceptance time. `expires_at`: the call's deadline. `decided_at`: when the state left `pending`, or null. All RFC3339.
- `reason`: the denial reason, or null.

The record never holds the input itself; the input stays in the received call's request and is deleted with it, 7 days after the call becomes final.

### Transitions

| From | Event | Approval | Call | Activity |
| --- | --- | --- | --- | --- |
| `pending` | `approve` | `approved` | stays `queued`; the dispatcher may start it | `call.approved` |
| `pending` | `deny` | `denied`, with `reason` | `rejected`, `error` `approval_denied` | `call.denied`, `call.finished` |
| `pending` | the call's deadline passes | `expired` | `expired`, `error` `approval_timeout` | `call.approval_expired`, `call.finished` |
| `pending` | the caller cancels | `cancelled` | `cancelled`, as for any queued call | `call.cancel_requested`, `call.finished` |
| `approved` | the dispatcher starts the call | unchanged | `running`, after the recheck | `call.started` |

- **Each one once.** Every transition happens in one transaction with its call change and activities, and sets `decided_at` when it leaves `pending`. Approving or denying an approval that is no longer `pending` changes nothing and returns 409 `{code: "conflict", error: "the call is no longer waiting for approval", approval: RECORD}`.
- **Dispatch.** The dispatcher never starts a call whose approval is `pending`, and never starts or keeps alive a server instance for one. A pending call takes no concurrency slot.
- **Recheck.** An approved call is rechecked immediately before it starts, as any call. A failure rejects it with `authorization lapsed before start` (for example after `unshare` or `capability remove`); a recoverable failure leaves it queued as before. Approval never overrides authorization.
- **Deadline.** A call approved but not yet started at its deadline becomes `expired` as any queued call, with `error` null; its approval stays `approved`. A pending approval expires at the deadline even while no request reaches the daemon: the daemon checks at least every 5 seconds.
- **Restart.** Approvals persist. After a daemon restart, pending calls stay pending, approved calls stay queued and start normally, and approvals past their deadline expire as above.

### The status record

The peer status record (`POST /peer/v1/calls`, `GET /peer/v1/calls/{id}`, `POST /peer/v1/calls/{id}/cancel`, and `calls received`) gains `approval`, null when the call needed none, and otherwise:

```json
"approval": {"state": "pending", "requested_at": "RFC3339", "expires_at": "RFC3339", "decided_at": null, "reason": null}
```

- **States on the wire.** `state` stays one of the eight call states. A call is `queued` while its approval is pending, and while it is approved and not yet started.
- **Errors.** `error` gains `approval_denied` (with `rejected`) and `approval_timeout` (with `expired`).
- **Older callers** ignore the unknown field, so they keep working: they see `queued`, then the final state.

### Held status requests

`GET /peer/v1/calls/{id}?wait=N&state=S` gains an optional `approval=A`, the approval state the caller last stored: one of the five approval states, or `none` when it stored no approval. The receiver also answers as soon as the call's approval state (`none` when the call has no approval) differs from `A`, so a held request answers within 1 second of an approval or denial. With `approval` but without `wait`, it answers at once. An `approval` value outside these six is 400. A host that predates this ignores the parameter.

### Telling the person

**Status.**
- `GET /v1/status` `capabilities` gains `approvals_pending`, the number of approvals in `pending`.
- **Attention item 18, `call_approval_pending`**, after item 17. One item while at least one approval is pending. Subject: the number of pending approvals as a decimal string. Detail (free text): the oldest pending call's capability, operation, caller, and `expires_at`. Command: `peerspan approvals`.

<a id="the-notice"></a>**The notice.** With each approval, the daemon creates a notice for the capability's source agent (`source.agent` of the record), so that the person, who is often working in that agent's session, learns of it there.
- **Record.** `{id, sender_host_id, call_id, agent_id, session_id, state, created_at}`, with an ID of `notice_` and 32 lowercase hex digits. `session_id` is null until claimed. `state` is `unknown`, `forwarded`, or `void`.
- **Claim.** `POST /adapter/v1/approval-notices/next` with `{}` requires the adapter's credential and lease, as `/adapter/v1/next` does, and a verified channel: before verification it answers 409 `{code: "conflict", error: "channel not verified"}`, as the other work routes do. It does not need `calls` on the credential. It claims the oldest notice (by `created_at`, then ID) whose `agent_id` is this session's agent, whose `session_id` is null, and whose approval is still `pending`, binds it to this session, and returns `{notice, approval}`, where `approval` is the approval record; or `null` when there is none.
- **Void.** A notice whose approval leaves `pending` before the notice is claimed becomes `void` and is never offered.
- **Forwarded.** `POST /adapter/v1/approval-notices/{id}/forwarded` with `{}` sets `state` `forwarded` and returns the notice. Idempotent; a notice claimed by another credential, or an unknown ID, is 404.
- **Once.** A notice is claimed once, by one session, and never redelivered. It has no `seen`, `mark_seen` does not accept its ID, and it is not listed in `pending_work`. Claims and forwards record no activity.
- **The event.** For each claimed notice, the shared adapter emits a channel event with `meta.kind` `approval_request` and `meta` `{notice_id, call_id, sender_host_id, caller, origin_agent_id, capability, operation, changes_things, expires_at}`, then acknowledges it through `forwarded`. `caller` is the approval's `caller.person_label`, or `caller.host_id` when the label is null; `origin_agent_id` is `origin.agent_id` or null. A channel that cannot carry null meta values omits those keys. The content is exactly:

  `A call to your capability CAPABILITY (OPERATION) from CALLER is waiting for the person's approval, until EXPIRES. You cannot approve or deny it. Tell the person, and ask them to run peerspan approvals in a terminal on this machine.`

  with `CAPABILITY`, `OPERATION`, and `CALLER` as in `meta`, and `EXPIRES` the approval's `expires_at`. Neither the content nor `meta` ever includes the call's input.
- **What agents cannot do.** No adapter route or MCP tool lists, approves, or denies approvals.

### Approving

| CLI | Local API | Behavior |
| --- | --- | --- |
| `approvals [--all] [--json]` | `GET /v1/approvals?state=pending\|all` | `state` defaults to `pending`; any other value is 400. `pending` lists pending approvals; `all` lists them and every other approval whose `decided_at` is within the last 7 days. Sorted oldest first by `requested_at`, then `sender_host_id`, then `call_id`. The JSON is `{approvals: [ITEM]}`, where `ITEM` is the approval record plus `input_preview` and `input_bytes`. `--json` prints it; otherwise one readable line per approval, which contains its `SENDER_HOST_ID/CALL_ID`, and `No calls are waiting for your approval.` when there is none. |
| `approvals show ID [--json]` | `GET /v1/approvals/{sender}/{call_id}` | One approval, in any state: the approval record plus `input_preview`, `input_bytes`, and `input`, the input object, or null once it has been deleted. `--json` prints it; otherwise readable text with the whole input pretty-printed and escaped (below), and the capability's source and credential context when the capability still exists. |
| `approve ID` | `POST /v1/approvals/{sender}/{call_id}/approve` with `{}` | Needs a terminal (below). Prints what `approvals show` prints to stderr, asks `Approve this call? It runs once, with the credentials it runs with on this machine. [y/N] `, reading one line from stdin, and on `y` or `yes` (any case) approves and prints the returned record on stdout as JSON. Any other answer exits 1 with nothing changed. When the shown approval is not `pending`, it asks nothing and sends the request, whose 409 makes it exit 1. The route returns 200 with the approval record. |
| `deny ID [--reason TEXT]` | `POST /v1/approvals/{sender}/{call_id}/deny` with `{reason}` | Denies at once, with no prompt and with or without a terminal, and prints the returned record on stdout as JSON. `reason` is optional, a string or null; an empty string reads as null; more than 1,024 bytes of UTF-8 is 400. The route returns 200 with the approval record. |
| (ID resolution) | `GET /v1/approvals/{call_id}` | Resolves a bare call ID: 200 with what `GET /v1/approvals/{sender}/{call_id}` returns when exactly one approval has that `call_id`, 409 `{code: "ambiguous", error, candidates: ["SENDER_HOST_ID/CALL_ID", ...]}` (sorted) when several senders used it, and 404 when none. |

- **`deny` and access `deny`.** `deny PRINCIPAL` ([launch contract](launch-contract.md)) keeps its meaning. `deny` treats its argument as an approval `ID` exactly when it has one of the two `ID` forms below; anything else is the access `deny`. `--reason` with an argument that is not an `ID` is refused with exit 1 before any request, as is `--agent` or `--network` with an `ID`.
- **`ID`** is a call ID (`call_` and 32 lowercase hex digits), or `SENDER_HOST_ID/CALL_ID`. The CLI resolves a bare ID through `GET /v1/approvals/{call_id}`, then uses the full form. Anything else is refused with exit 1 before any request.
- **Refusals.** An unknown approval is 404, an approval no longer pending is 409 as above, and the CLI exits 1 for each, printing the daemon's error on stderr.
- **`approve` needs a terminal.** When stdin is not a terminal, `approve` exits 1 before any request, printing on stderr a line that contains `peerspan approve needs a terminal: approval must come from the person.` It has no `--yes`. `deny` and `approvals` work without a terminal, because denying only narrows.
- **Where.** Only on the serving host, at its local administration socket. No peer route approves.
- **The remaining limit.** A process running as the same OS user can reach the local administration socket directly; this is the existing owner-local trust boundary. The terminal check stops the person's agent from approving through Peerspan's own surfaces, not a deliberately misbehaving local process.

**The input preview.** The input text is the input object encoded as the call view encodes a result ([The call view](#adapter-routes): no whitespace, keys sorted by UTF-8 bytes, numbers as sent, minimal string escapes), so it is the same in Go and Rust. `input_bytes` is its length in bytes. `input_preview` is its longest prefix of at most 512 bytes that ends on a UTF-8 character boundary, with U+007F and U+0080 to U+009F then written as `\u` and four lowercase hex digits (the encoding already escapes characters below U+0020). Both are null once the input has been deleted.

**Showing untrusted text.** The input, person labels, and origin IDs come from the caller. In its readable output, the CLI writes every character below U+0020 (other than the line breaks of its own layout), U+007F, and U+0080 to U+009F in anything it prints from them as `\u` and four lowercase hex digits, so no terminal escape sequence reaches the terminal. The pretty-printed input in `approvals show` and `approve` uses the same escapes.

### What the caller sees

**The capability listing.** In `GET /peer/v1/capabilities`, each operation of a `capability` entry gains `approval`, a boolean: `true` when the operation is covered by the requirement and either the entry has a `via` entry of kind `policy` or `agent_self` is true; otherwise `false`. It is advisory, assumes the call carries an `origin`, and the receiver decides at acceptance; a self-access call without `origin` never needs approval. Operations of `source` entries have `approval: false`. `GET /v1/discover`, `GET /adapter/v1/capabilities`, and `list_capabilities` carry it through unchanged; an entry from a host that predates this has none, which reads as `false` and is shown as `false` by this host. Readable `discover` prints ` (needs approval)` right after such an operation's name.

**The outbound record.** The stored `status` includes the receiver's `approval` as returned, null for a receiver that predates this.

**Results without polling.** While the stored status is `queued` and its `approval` is `pending`, the caller's daemon keeps sending held status requests (`wait=10&state=S&approval=pending`, one at a time as before) past the first 60 seconds after acceptance, until the stored approval is no longer pending or the call is final. When it stores an approval that is no longer pending for a call that is not final, a new 60-second window of held requests begins, as at acceptance, so the result of an approved call also arrives at once; after it, the call is polled with backoff as usual. So an approval or denial reaches the caller within 2 seconds of the decision. After a daemon restart, a call whose stored approval is pending is followed this way again.

**`call`.** When `call` exits 3 and the record's stored approval is `pending`, it prints on stderr one line: `Waiting for OWNER to approve this call (until EXPIRES). Check it later with peerspan calls inspect --peer HOST ID.`, where `OWNER` is the `PERSON` of a `PERSON/CAPABILITY` address and otherwise the host ID, `EXPIRES` the approval's `expires_at`, `HOST` the peer host ID, and `ID` the call ID. Its exit code stays 3, and `--wait` keeps its 15-minute maximum. `calls list` and `calls inspect` show `approval` inside `status`.

**The agent's call view** gains `approval`, the stored status's `approval`, or null.
- **State.** `state` is `awaiting_approval` when the stored status is `queued` and its `approval.state` is `pending`; otherwise as before.
- **Note.** For `awaiting_approval`, exactly: `The capability's owner must approve this call before it runs; it has not run. Its result arrives as a kind=call_update event; call_status reports it at any time. Do not call it again: a new call needs a new approval.`
- **Timing.** `call_capability` still returns within the wait limit, with `awaiting_approval` when the owner has not decided.
- **Updates.** The call-update notification is created when the call becomes final, as before. A denial gives `rejected` with `approval_denied`, and a timeout `expired` with `approval_timeout`, each with the never-ran note; a denial's reason, when given, is in `approval.reason`. No notification is created when an approval is granted.
- **`pending_work`** lists such calls with `state` `awaiting_approval`, and the `--hook` text is unchanged.
- **Tool description.** `call_capability`'s description gains: `Some operations wait for their owner's approval, shown by approval in list_capabilities; such a call returns awaiting_approval, and its result follows as a kind=call_update event.`

**Older peers.**

| Caller | Receiver | Result |
| --- | --- | --- |
| this slice | version 18 | No approval exists; everything is as before, and listings read `approval: false`. |
| version 18 | this slice | Approval is enforced. The caller sees `queued` until the call runs, or until it becomes `rejected` (`approval_denied`) or `expired` (`approval_timeout`). Its held requests end after 60 seconds, then it polls with backoff, so a result can arrive up to a minute after the decision. |

### Persistence

Database version 20 adds the following. Version 19 is machine linking. Version 20 binaries migrate every version from 0 to 19 up to 20, and refuse anything above 20. [Resource bounds](#persistence-3) add version 21, which binaries from then on migrate to.

```sql
CREATE TABLE call_approvals (sender TEXT NOT NULL, call_id TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id), FOREIGN KEY(sender, call_id) REFERENCES received_calls(sender, call_id));
CREATE INDEX call_approvals_state ON call_approvals(state, expires_at);
CREATE TABLE approval_notices (id TEXT PRIMARY KEY, sender TEXT NOT NULL, call_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id), session_id TEXT REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, call_id));
PRAGMA user_version = 20;
```

- **`call_approvals`** rows are kept as long as their received call's status record. `record` holds the approval record, and the pending key under `pending_key`, which is not shown.
- **Records.** Capability records gain `approval`; received call status records and outbound records gain `approval` in the status. Records without them read as none and null, so migration rewrites no record.
- **Migration** to 20 creates the two tables and the index and sets the version, in the same transaction as any earlier version's migration (a database below 19 gets the version 19 tables first). Older binaries reject version 20.

**Activity** (subject `SENDER_HOST_ID/CALL_ID` unless noted): `call.approval_requested`, `call.approved`, `call.denied`, `call.approval_expired`, and `capability.approval_changed` (subject: the capability name). Activity never holds inputs or denial reasons.

### Verification

`conformance/capabilities.py` gains these cases, written from this section by an author independent of both implementations and the adapter. They run across all four Go/Rust CLI and daemon pairings, with `--probe`, the Go coordinator, OpenSSH, `--node`, and the fixture MCP server; the older-peer and migration cases also take `--baseline18`, a `peerspan-host` built from main before this section (schema 18, for example `ef86f06`).
- **Configuration:**
  - `capability create --approval` with `none`, `changing`, `all`, and a list, the stored list sorted and deduplicated, and `--no-agent-self-approval`;
  - refusals: a list name that is not an operation, `read` without resources, an empty list, and an invalid value;
  - repeat and conflict including `approval`;
  - `capability approval` changing modes, keeping `agent_self` when neither flag is given, signing no policy (the stored policy versions unchanged), recording `capability.approval_changed`, and 404 for an unknown name;
  - records without `approval` reading as `none` with `agent_self` true;
  - the review lines for each case and the `changing` warning; the guided prompt at a pseudo-terminal answered with an empty line and with `n`, not asked without write tools, and `--approval` deciding without a terminal; `share NAME --approval` refused;
  - `approval` in `capability show`, `capability list --json`, and `shares --json`.
- **Acceptance:**
  - under `changing`, a tool with `read_only` false held, and a read-only tool and `read` running at once;
  - `all` holding `read`; a list holding only its names;
  - self access without `origin` exempt; with `origin` held; with `origin` exempt under `agent_self` false; a policy call with an origin held whatever `agent_self`;
  - sources never held;
  - the pending limit: 20 pending calls from one caller under one rule accepted, the 21st refused with 429 `max_pending_approvals` and nothing persisted, and another caller still accepted;
  - the budget counted at acceptance, with `max_calls_per_hour` refused before the pending limit;
  - a requirement changed after acceptance not changing the accepted call's approval.
- **Decisions:**
  - approve, then the call runs with exactly one execution recorded by the fixture;
  - deny with a reason, giving `rejected` with `approval_denied` and the reason in the approval, never executed; a reason over 1,024 bytes refused;
  - a pending approval reaching its deadline: `expired` with `approval_timeout`, and the approval `expired`, with no request reaching the receiver;
  - cancel while pending: call `cancelled`, approval `cancelled`;
  - approve after `unshare`, rejected at the recheck with `authorization lapsed before start`;
  - approve or deny twice: 409 `conflict` with the record;
  - a repeated `call_id` returning the same record with its approval, and creating no second approval or notice; a new `call_id` with the same input needing its own approval;
  - no server instance started while every queued call is pending (the fixture records no start);
  - pending and approved calls surviving a receiver restart, then approved and run, or started;
  - the activities for each transition.
- **CLI:**
  - `approvals` and `--json`, `--all` including decided ones, the order, and the empty message;
  - `approvals show` with the input, and `input` null after the input is deleted;
  - `approve` refused without a terminal with its text and nothing changed; accepted at a pseudo-terminal with `y`; declined with `n`;
  - `deny` without a terminal;
  - a bare ID resolved, two senders using one call ID giving `ambiguous` with `candidates`, and the full form then working; unknown IDs 404 and exit 1;
  - `input_preview` truncated at 512 bytes on a character boundary, with `input_bytes`, and U+007F and C1 characters escaped; readable output with an escape sequence in the input and in a person label showing no raw escape character.
- **Caller:**
  - `approval` in the peer status record, and in `calls received`, `calls list`, and `calls inspect`;
  - `call_capability` returning `awaiting_approval` with its note and `approval` within the wait limit;
  - exactly one `call_update` event after approval and success, after denial, and after timeout, with the never-ran note for the last two, and none on approval itself;
  - `pending_work` and `session pending --json` listing `awaiting_approval`;
  - `call`'s stderr line and exit 3;
  - held requests with `approval=pending` continuing past 60 seconds while pending, observed by their effect: a call pending for more than 75 seconds stored final by the caller within 2 seconds of `approve`, which polling with backoff could not do; the peer route answering a held request within 1 second of a decision, and refusing an invalid `approval` value with 400;
  - `approval` per operation in `GET /peer/v1/capabilities`, `discover --json`, and `list_capabilities`, and `(needs approval)` in readable `discover`.
- **Older peers:** a version 18 caller against this slice's receiver seeing `queued`, then the result after approval, and `rejected` with `approval_denied` after denial; this slice's caller against a version 18 receiver unchanged, with listings reading `approval: false`.
- **Notices:**
  - one `approval_request` event in the source agent's verified session, with its exact content and meta and without the input;
  - no event for a notice whose approval was decided before it was claimed;
  - the claim route answering 409 before verification, `null` when there is nothing, and working without `calls` on the credential; `forwarded` idempotent and 404 for another credential;
  - no event in a session of another agent.
- **Status:** `approvals_pending`, and item 18 present while an approval is pending and gone once it is decided.
- **Migration:** a version 18 database from `--baseline18` migrating to 20 with its capabilities reading `approval` `none`; a database at version 19 migrating to 20 (to the current version, 21, once resource bounds landed); a database above the current version refused.

`conformance/live_capability_agents.py` adds one live run per harness, separately from deterministic conformance: Bob sets `capability approval github-issues all`; Alice's agent calls `list_issues`, gets `awaiting_approval`, and tells Alice it is waiting; Bob's Claude Code session receives the notice and tells Bob without approving; Bob runs `peerspan approve` at a terminal; Alice's agent receives the `call_update` and answers with the issues.

## Resource bounds and the `gh` source (slice 3)

Item D of slice 3, settled in [owner decision 16](#owner-decisions) by accepting the [proposal](capabilities-slice3-bounds-sources-proposal.md) in full. It adds optional resource bounds on capabilities, built-in sources, and the first built-in source, `gh`, which runs the GitHub CLI. Where this section differs from the sections above, this section applies. Behavior is the same in Go and Rust hosts, in every CLI and daemon pairing. Policy v2, its test vector, and coordinators are unchanged.

### Built-in sources

A **built-in source** is an adapter Peerspan ships and detects on the host, not tied to any agent. Each binary has an internal registry of built-in adapters; this slice registers only `gh`. There is no plugin interface.

- **Address.** A built-in source is `builtin/NAME`, for example `builtin/gh`. Its capability records keep `source: {agent, server}`, with `agent` `builtin` and `server` the source name, so every path keyed by agent and server works unchanged.
- **The reserved agent name.** `attach --name builtin` exits 1 before anything changes, with an error saying the name `builtin` is reserved. An agent named `builtin` that already exists on a host keeps working, but a built-in source whose name equals one of that agent's tool servers is listed with `shareable: false` and the reason `name`.
- **Raw sources.** For the person's own machines, a built-in source is addressed `PERSON/builtin/NAME` or `HOST_ID/builtin/NAME`, and is listed and called as any source under [Sources for the person's own machines](#sources-for-the-persons-own-machines): kind `source`, `capability` `builtin/NAME`, behind the same two-sided gate.
- **`SOURCE` in `capability create --from` and `share --from`.** `builtin/NAME` names a built-in source. A bare `NAME` resolves when exactly one source with that name exists among the agents' sources and the built-in sources; with several, the CLI exits 1 and lists the qualified names.
- **Own credentials.** `--env-file` works as for any source. `--arg` is refused for a built-in source with 400, because the adapter has no arguments to replace.
- **Per-call approval.** A capability on a built-in source may require approval as any capability. A built-in source has no source agent, so no approval notice is created: the call waits for the owner's decision through `peerspan approvals` only.

### Discovering `gh`

Built-in discovery runs in the CLI, where the user's `PATH` and `gh` login are:
- at every `attach`, after its MCP source discovery;
- at `sources refresh` without `--agent`, after the agents' discovery;
- at `sources refresh --builtin`, which runs only built-in discovery. `--builtin` with `--agent` exits 1.

**Steps:**
1. **Find it.** Search the CLI's `PATH` entries in order for a regular file named `gh` with execute permission, skipping empty and relative entries. The first match, as an absolute path, is the definition's `command`. If there is none, discovery sends no `gh` definitions, which removes earlier ones.
2. **Version.** Run `gh --version`. The version is `X.Y.Z` from the first line of standard output when it starts with `gh version X.Y.Z` (three decimal numbers). A non-zero exit, a timeout, or no match leaves the version null.
3. **Too old or unknown.** With a null version or one below 2.81.0 (compared numerically), discovery sends one definition `gh` with `account` null and `authenticated` false, and runs nothing else.
4. **Accounts.** Run `gh auth status --json hosts`. Its standard output is `{"hosts": {HOST: [{state, active, host, login, tokenSource, gitProtocol}, ...]}}`. Only the entries under `github.com` are used, and entries whose `tokenSource` is `GH_TOKEN` or `GITHUB_TOKEN` are ignored. A non-zero exit, a timeout, output that does not parse, or no remaining entry yields one definition `gh` with `account` null and `authenticated` false.
5. **One source per account.** The remaining entry with `active: true` is source `gh`; when none is active, the first remaining entry is. Each other entry is `gh-LOGIN`: `gh-` followed by the login lowercased, with every character outside `[a-z0-9_-]` replaced by `-`, cut to 63 characters. A later entry whose name repeats an earlier one is dropped. `authenticated` is true when the entry's `state` is `success`.
6. **Capture the token.** For each authenticated account, run `gh auth token --hostname github.com --user LOGIN`. Standard output with surrounding whitespace removed, when the exit is 0 and it is not empty, is the token: the definition's `env` is `{"GH_TOKEN": {"source": "captured"}}` and `values` maps the source name to `{"env.GH_TOKEN": TOKEN}`. Otherwise, and for every account that is not authenticated, `env` is `{"GH_TOKEN": {"source": "missing", "variables": ["GH_TOKEN"]}}`.

Each command runs with the CLI's environment, minus `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, and `GITHUB_ENTERPRISE_TOKEN`, plus `GH_PROMPT_DISABLED=1` and `GH_NO_UPDATE_NOTIFIER=1`, with a 10-second timeout after which the process is killed. Its output is never printed or logged. A token appears only in `values`, which the daemon stores in `tool_values` with `agent_id` `builtin`; it never appears in definitions, listings, output, logs, or activity.

**The definition:**

```json
{
  "name": "gh",
  "adapter": "gh",
  "command": "/usr/bin/gh",
  "version": "2.102.0",
  "host": "github.com",
  "account": "bob",
  "authenticated": true,
  "env": {"GH_TOKEN": {"source": "captured"}},
  "disabled": false
}
```

**The local route.**

| CLI | Local API | Behavior |
| --- | --- | --- |
| (from `attach` and `sources refresh`) | `PUT /v1/builtin-sources` with `{sources, values}` | Replaces every built-in source definition and the stored values with `agent_id` `builtin` in one transaction, records `sources.discovered` with subject `builtin`, then snapshots each shareable source and each capability with its own credential built on a built-in source. It returns `{builtin: [SERVER]}`, as in `GET /v1/sources`, once the snapshots finish. |

- **Request shape.** `values` may be absent. Each element of `sources` has exactly `name`, `adapter`, `command`, `version`, `host`, `account`, `authenticated`, `env`, and `disabled`; an unknown or missing field is 400. `adapter` is `gh`. `command` is an absolute path. `version` and `account` are strings or null. `host` is `github.com`. `name` follows the server label rules of `PUT /v1/agents/{agent_id}/tool-servers`, and names are distinct. `env` entries have the shapes defined for tool servers. In `values`, only `env.NAME` fields for `literal` or `captured` entries are accepted. At most 100 sources. Any other shape is 400.
- **Shareable.** The daemon computes `shareable` and `reason`. Reasons, in precedence order: `name` (the name does not match the server name pattern, or an agent named `builtin` has a tool server with this name), `version` (null or below 2.81.0), `not_authenticated` (`authenticated` false), and `missing_env` (an `env` entry is `missing`).
- **Following discovery.** As for agents' sources: a dropped built-in source's capabilities remain and become `unavailable`, instances started from a changed definition or changed values take no new calls, and the previous snapshot stays until a new one succeeds.

**Listing.** `GET /v1/sources` gains `builtin: [SERVER]` beside `agents`, sorted by name; with `?agent=`, `builtin` is `[]`. A built-in `SERVER` has the fields of an agent's `SERVER`, with `transport` `stdio`, `command` the `gh` path, `args` `[]`, `url` null, and `source` `builtin`, plus `adapter`, `version`, `host`, `account`, `authenticated`, and `reach` (below; null before the first snapshot).

**`sources` text output** lists the built-in sources after the agents, under a line `builtin`, each as `  builtin/NAME  gh VERSION  account LOGIN  usable` or `not usable: REASON`, where `VERSION` and `LOGIN` are the definition's `version` and `account` (the discovered account, not the reach's), each `unknown` when null, followed by its tools as for other sources and a line `    reach: SENTENCE` with the [reach sentence](#the-reach-sentence). When the CLI's `PATH` has no `gh`, the text output ends with the line `GitHub CLI (gh) not found on PATH; install gh 2.81.0 or later and run peerspan sources refresh to use it as a source.` `--json` is unchanged apart from `builtin`.

**`attach` and `sources refresh` output.** `attach`'s `sources` object gains `builtin: [ENTRY]`, where `ENTRY` has the shape of an element of its `servers`. `sources refresh` adds to its JSON list one element `{agent_id: null, agent: "builtin", workspace: null, sources: {servers: [ENTRY], errors: []}}` for built-in discovery; with `--builtin` the list holds only that element. A failure to store built-in sources is reported in `errors`, and does not fail `attach`.

### Running a built-in source

**The instance.** The daemon starts a built-in source as any stdio source, through [Running servers](#running-servers): instances, concurrency, idle stop, start failures, call records, cancellation, and uncertainty are unchanged. Its command is the daemon's own executable with the hidden subcommand `peerspan builtin-source gh`, which is given the definition's `command` and the state directory. Its working directory is `STATE/builtin/gh/work`. Its environment is built as for any source: the daemon's `PATH` and `HOME`, the stored `GH_TOKEN`, then `GH_TOKEN` from the environment file, then a capability's whole `env_file`. Its standard error goes to `STATE/tool-logs/builtin/NAME.log`, or `NAME@CAPABILITY.log` for a capability's own instance.

**The server.** It answers `initialize` with `serverInfo.name` `peerspan-gh` and `capabilities` `{"tools": {}}`, so `resources/list` is never called and built-in sources have no resources. `tools/list` returns the [ten operations](#gh-operations) in the table's order, in one page. `ping` answers `{}`. An unknown method is JSON-RPC error `-32601`, and `tools/call` for an unknown tool is `-32602` with the message `Unknown tool: NAME`. It handles several `tools/call` requests at once. Its log has one line per call, naming the operation, the exit code or `timeout` or `cancelled`, and the duration, and never arguments, standard input, output, or the token.

**Snapshot and reach.** A snapshot is taken as for an MCP source. After `tools/list` succeeds, the daemon checks the credential's reach: it runs `COMMAND api --include --hostname github.com user` with the [gh environment](#the-gh-process) built from the instance's environment, in `STATE/builtin/gh/work`, with a 10-second timeout. It stores `reach: {account, host, token_type, scopes, checked_at, error}` with the snapshot, never the token:
- **`token_type`** comes from the prefix of `GH_TOKEN` in that environment: `gho_` is `oauth`, `ghp_` is `classic`, `github_pat_` is `fine_grained`, `ghu_` or `ghs_` is `app`, and anything else, or no token, is `unknown`.
- **On success** (exit 0, then an HTTP status line, header lines, an empty line, and a JSON object body with a string `login`; lines end in `\n` or `\r\n`): `account` is that `login`, `scopes` is the value of the `X-OAuth-Scopes` header (name matched case-insensitively) split on `,` with each scope trimmed and empty ones dropped, or null when the header is absent, and `error` is null.
- **On failure:** `account` is the definition's account, `scopes` is null, and `error` is one of `gh exited with status N`, `gh did not finish within 10 seconds`, `gh could not be started`, or `gh returned output Peerspan could not read`.
- `host` is `github.com` and `checked_at` is the check's time. A failed reach check does not fail the snapshot. A failed snapshot keeps the previous `reach`.
- A capability with its own credential gets its own `reach` from its own snapshot.

<a id="the-reach-sentence"></a>**The reach sentence**, used by `sources`, the review, and `shares`, takes the first row that applies. `LOGIN` is the reach's `account`, else the definition's, else `unknown`; `HOST` is `github.com`; `SCOPES` is the scopes joined with `, `.

| Reach | Sentence |
| --- | --- |
| null (never checked) | `Peerspan could not check the reach of the gh account LOGIN on HOST (not checked yet). Assume everything the account can reach.` |
| `error` set | `Peerspan could not check the reach of the gh account LOGIN on HOST (ERROR). Assume everything the account can reach.` |
| `scopes` contains `repo` | `The gh account LOGIN on HOST (token scopes: SCOPES) can read and change every repository LOGIN can, public and private.` |
| `scopes` contains `public_repo` | `The gh account LOGIN on HOST (token scopes: SCOPES) can read public repositories and change public repositories LOGIN can.` |
| `token_type` `oauth` or `classic`, `scopes` not null | `The gh account LOGIN on HOST (token scopes: SCOPES) can read public repositories only.`, with `none` for `SCOPES` when the list is empty |
| otherwise | `The gh account LOGIN on HOST uses a token that states no scopes, so Peerspan cannot tell which repositories it reaches. Assume every repository it was granted.` |

<a id="gh-operations"></a>
### `gh` operations

| Operation | Read-only | `gh` arguments, in order | Result text |
| --- | --- | --- | --- |
| `issue_list` | yes | `issue list --repo=R --state=S --limit=N`, `--label=L` per label, `--assignee=A`, `--author=A`, `--milestone=M`, `--json=F` | `{"issues":OUT}` |
| `issue_view` | yes | `issue view N --repo=R`, `--comments` when `comments`, `--json=F` | `{"issue":OUT}` |
| `pr_list` | yes | `pr list --repo=R --state=S --limit=N`, `--base=B`, `--head=H`, `--label=L` per label, `--author=A`, `--draft` when `draft`, `--json=F` | `{"pull_requests":OUT}` |
| `pr_view` | yes | `pr view N --repo=R`, `--comments` when `comments`, `--json=F` | `{"pull_request":OUT}` |
| `pr_diff` | yes | `pr diff N --repo=R --color=never`, `--name-only` when `name_only` | `{"diff":TEXT}` or `{"files":[PATH,...]}` |
| `pr_checks` | yes | `pr checks N --repo=R --json=F` | `{"checks":OUT}` |
| `repo_view` | yes | `repo view R --json=F` | `{"repository":OUT}` |
| `issue_create` | no | `issue create --repo=R --title=T --body-file=-`, `--label=L` per label, `--assignee=A` per assignee | `{"number":N,"url":URL}` |
| `issue_comment` | no | `issue comment N --repo=R --body-file=-` | `{"url":URL}` |
| `pr_comment` | no | `pr comment N --repo=R --body-file=-` | `{"url":URL}` |

- **Arguments.** Optional flags appear only when their input property is given (a boolean only when true), in the order listed. `S` and `N` in lists are always passed, with their defaults when not given. Every value is passed in one element as `--flag=value`, so a value starting with `-` never becomes a flag. Positional values are only the decimal `number` and, for `repo_view`, the validated `repo`. `--jq` and `--template` are never passed.
- **`F`**, fixed per operation:
  - `issue_list`: `number,title,state,author,labels,assignees,milestone,createdAt,updatedAt,url`
  - `issue_view`: `number,title,state,stateReason,body,author,labels,assignees,milestone,createdAt,updatedAt,closedAt,url`, with `,comments` appended when `comments` is true
  - `pr_list`: `number,title,state,isDraft,author,baseRefName,headRefName,labels,createdAt,updatedAt,url`
  - `pr_view`: `number,title,state,isDraft,body,author,baseRefName,headRefName,mergeable,reviewDecision,additions,deletions,changedFiles,files,labels,createdAt,updatedAt,mergedAt,url`, with `,comments,reviews` appended when `comments` is true
  - `pr_checks`: `name,state,bucket,workflow,link,startedAt,completedAt`
  - `repo_view`: `nameWithOwner,description,url,visibility,isArchived,defaultBranchRef,homepageUrl,primaryLanguage,stargazerCount,forkCount,pushedAt,updatedAt`
- **Annotations.** Read-only operations have `readOnlyHint: true`. The others have `readOnlyHint: false`, `destructiveHint: false`, and `idempotentHint: false`.

**Input schemas.** Each is `{"type": "object", "properties": {...}, "required": [...], "additionalProperties": false}`, with these properties, required ones marked `*`:

| Operation | Properties |
| --- | --- |
| `issue_list` | `repo`*, `state` (`open`, `closed`, `all`), `limit`, `label`, `assignee`, `author`, `milestone` |
| `issue_view` | `repo`*, `number`*, `comments` |
| `pr_list` | `repo`*, `state` (`open`, `closed`, `merged`, `all`), `limit`, `base`, `head`, `label`, `author`, `draft` |
| `pr_view` | `repo`*, `number`*, `comments` |
| `pr_diff` | `repo`*, `number`*, `name_only` |
| `pr_checks` | `repo`*, `number`* |
| `repo_view` | `repo`* |
| `issue_create` | `repo`*, `title`*, `body`, `label` (array), `assignee` (array) |
| `issue_comment` | `repo`*, `number`*, `body`* |
| `pr_comment` | `repo`*, `number`*, `body`* |

| Property | Schema | Rule enforced by the server |
| --- | --- | --- |
| `repo` | `{"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$"}` | matches the pattern, and does not end in `/.` or `/..` |
| `number` | `{"type": "integer", "minimum": 1, "maximum": 2147483647}` | a JSON number with a whole value in range |
| `state` | `{"type": "string", "enum": [...], "default": "open"}` | one of the enum |
| `limit` | `{"type": "integer", "minimum": 1, "maximum": 100, "default": 30}` | as `number`, 1 to 100 |
| `label`, and `assignee` for `issue_create` | `{"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 256}, "maxItems": 10}` | 0 to 10 strings |
| `assignee` (lists), `author`, `milestone`, `base`, `head` | `{"type": "string", "minLength": 1, "maxLength": 256}` | a string |
| `draft`, `comments`, `name_only` | `{"type": "boolean"}`, with `"default": false` for `comments` and `name_only` | a boolean |
| `title` | `{"type": "string", "minLength": 1, "maxLength": 256}` | a string |
| `body` | `{"type": "string", "maxLength": 65536}` | 0 to 65,536 bytes, without U+0000 |

Every string other than `body`, including array items, is 1 to 256 bytes with no character below U+0020 and no U+007F. `repo` has no `HOST/` prefix, and `number` is only an integer, because `gh` also accepts a URL or a branch in that position.

Descriptions are identical in both implementations. Tools: `issue_list` "List issues in a GitHub repository."; `issue_view` "Show one issue of a GitHub repository, with its comments when comments is true."; `pr_list` "List pull requests in a GitHub repository."; `pr_view` "Show one pull request of a GitHub repository, with its comments and reviews when comments is true."; `pr_diff` "Show the diff of a pull request, or with name_only the names of the changed files."; `pr_checks` "Show the status checks of a pull request."; `repo_view` "Show a GitHub repository."; `issue_create` "Create an issue in a GitHub repository."; `issue_comment` "Add a comment to an issue."; `pr_comment` "Add a comment to a pull request." Properties: `repo` "The repository, as OWNER/REPO."; `number` "The issue or pull request number."; `state` "Which items to list."; `limit` "At most this many items."; `label` "Only items with all of these labels." in lists and "Labels to add." in `issue_create`; `assignee` "Only items assigned to this login." in lists and "Logins to assign." in `issue_create`; `author` "Only items opened by this login."; `milestone` "Only issues in this milestone."; `base` "Only pull requests into this base branch."; `head` "Only pull requests from this head branch."; `draft` "Only draft pull requests."; `comments` "Include comments." for `issue_view` and "Include comments and reviews." for `pr_view`; `name_only` "Return only the names of the changed files."; `title` "The issue title."; `body` "The text, in Markdown."

### Executing a `gh` call

For each `tools/call`, the server:
1. **Validates** the arguments (absent means `{}`) against the operation's schema and the rules above: unknown properties, missing required ones, types, ranges, enums, lengths, and patterns. A failure returns a tool result with `isError: true` and the text `Invalid arguments for OPERATION: DETAIL`, where the wording of `DETAIL` is not shared, and runs nothing.
2. **Builds the arguments** from the table.
3. **Runs `gh`** directly, never through a shell, as below.
4. **Returns** a `CallToolResult` `{"content": [{"type": "text", "text": TEXT}]}`, or with `"isError": true` for the errors below.

<a id="the-gh-process"></a>**The `gh` process.**
- **Executable:** the definition's `command`, an absolute path, never looked up on a `PATH`.
- **Working directory:** `STATE/builtin/gh/work`, created empty with mode 0700 when missing, so `gh` never infers a repository from a checkout.
- **Environment, exactly:** `PATH` and `HOME` from the instance's environment when set; `GH_TOKEN` from the instance's environment when set and not empty; `GH_HOST=github.com`; `GH_CONFIG_DIR=STATE/builtin/gh/config` (created with mode 0700 when missing), so the user's aliases, extensions, and stored accounts are not used; `GH_PROMPT_DISABLED=1`; `GH_NO_UPDATE_NOTIFIER=1`; `GH_NO_EXTENSION_UPDATE_NOTIFIER=1`; `GH_SPINNER_DISABLED=1`; `NO_COLOR=1`; `GH_PAGER=cat`; and `GH_TELEMETRY=0`. Nothing else, not even variables of a capability's `env_file` other than `GH_TOKEN`.
- **Standard input:** for the three writes, `body` (empty when absent for `issue_create`), then closed; for the others, closed at once.
- **Limits:** standard output is read up to 1,000,000 bytes; one more byte kills the process. The last 65,536 bytes of standard error are kept.
- **Timeout:** 120 seconds. Killing means `SIGTERM` to the process and its process group, then `SIGKILL` 2 seconds later if it is still running. A call's deadline is enforced by the daemon, which sends `notifications/cancelled` as for any source.
- **Cancellation:** on `notifications/cancelled` for a request, the server kills that request's `gh` process the same way, and sends no response for it. The daemon already makes such a call `uncertain`, so a write that may have reached GitHub is never repeated.

**Outcomes**, in this order:
- **Not started** (the executable cannot be run): `isError` with the text `gh could not be started.`
- **Output over the limit:** a JSON-RPC error, not a tool result, with code `-32002` and the message `gh output exceeded 1000000 bytes.`
- **Timeout:** `isError` with the text `gh did not finish within 120 seconds.`
- **Exit 4**, which `gh` uses when authentication is required: a JSON-RPC error with code `-32001` and the message `gh is not authenticated for github.com. The owner runs gh auth login, then peerspan sources refresh.` The call is `failed` with `jsonrpc_error`, and since the message matches the authentication pattern, `auth_error_at` is set and status item 14 reports it.
- **`pr_checks` with exit 0, 1, or 8** (`gh` uses 1 when checks failed and 8 when they are pending) and standard output that is a JSON array: success.
- **Any other non-zero exit:** `isError` with the text `gh failed: STDERR`, where `STDERR` is the last 2,048 bytes of standard error, started at a UTF-8 character boundary, with trailing whitespace removed. With nothing left, the text is `gh failed with exit status N.`
- **Exit 0:** the result text below. Output it cannot be built from is `isError` with the text `gh returned output Peerspan could not read.`

**Result text.** `OUT` is standard output with surrounding ASCII whitespace removed, copied byte for byte, and must be a JSON array for `issue_list`, `pr_list`, and `pr_checks`, and a JSON object for `issue_view`, `pr_view`, and `repo_view`. `pr_diff` returns standard output as `TEXT`, or with `name_only` the lines of standard output, each without a trailing `\r`, empty lines dropped. For the writes, `URL` is the last line of standard output, trimmed, that starts with `https://`, and `issue_create`'s `number` is the decimal last path segment of `URL` after removing any `#` fragment. Strings and objects that are not copied byte for byte are encoded as [the call view's result text](#adapter-routes): no whitespace, keys sorted, and strings escaped only as specified there. A byte of standard output or error that is not part of valid UTF-8 becomes U+FFFD, one per byte.

**The daemon's one rule.** For a source whose `agent` is `builtin`, a JSON-RPC error with code `-32002` makes the call `failed` with `result_too_large`, and no result is stored (`result` and `result_bytes` are null). Every other answer maps to call states as for any source. Diffs over the limit therefore fail; `name_only` is the fallback.

**Left out:** free-form search (`--search` on lists, `gh search`), closing, editing, merging, reviewing, labels on existing items, workflow runs, releases, and `gh api`.

### Resource bounds

A capability's `bounds` is `{}`, meaning no bound, or `{"arguments": [COMBINATION, ...]}`, a list of 1 to 16 **combinations**. Each combination is an object mapping 1 to 4 argument names to one string value each. A record without `bounds` reads as `{}`.
- **Names** match `[A-Za-z_][A-Za-z0-9_]{0,63}`. **Values** are 1 to 256 bytes of UTF-8 with no character below U+0020 and no U+007F.
- **Order.** Within a combination, entries are ordered by name, in byte order, wherever they are listed or written into text.
- **Resources are not bounded.** A bound applies to tool operations only; `read` stays limited by the capability's resources.

**Setting a bound.**

| CLI | Local API |
| --- | --- |
| `capability create NAME --from SOURCE … [--bound KEY=VALUE[,KEY=VALUE…]]…` | `POST /v1/capabilities` gains optional `bounds`: absent, `{}`, or `{"arguments": [...]}`. |
| guided `share --with PRINCIPAL [… --bound …]` | the same body when it creates the capability |

- **`--bound`** may repeat; each one is a combination, in the order given. Its value is split on `,`, and each part at its first `=`. A part without `=`, an empty name, or a name given twice in one flag exits 1 before anything is sent. A value cannot contain `,`.
- **The guided share** asks at a terminal, after the operations and resources and only when `--bound` is not given: for a `gh` source, `Limit which repositories? Enter OWNER/REPO, several separated by spaces, or leave empty for no limit: `, where each word becomes the combination `{repo: WORD}`; for another source, `Limit by argument values? Enter KEY=VALUE[,KEY=VALUE] combinations separated by spaces, or leave empty for no limit: `, where each word is read as a `--bound` value. An empty answer is no bound. Without a terminal, only `--bound` sets one.
- **Checks at create**, after the existing ones, each refusing with 400 and storing nothing:
  - a malformed `bounds` (wrong shape, counts, names, or values) is `invalid`;
  - for a `gh` source, a `repo` value that is neither a valid `repo` argument nor `OWNER/*`, with `OWNER` matching `^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`, is `invalid` with the error `A gh repository bound is OWNER/REPO or OWNER/*.`;
  - a bound on a capability without tool operations is `invalid` with the error `A bound applies to tool operations, and the capability has none.`;
  - for each operation in `operations` order and each name in order of first appearance (the first combination's names, then each later combination's new names), the operation's tool in the snapshot that create checks against must have an `input_schema` whose `properties` has the name with `type` exactly `"string"`. The first that does not is refused with `{"code": "bound_unenforceable", "error": TEXT}`, where `TEXT` is exactly `Operation OPERATION has no string argument KEY, so Peerspan cannot check this bound for it. Leave the operation out, or narrow the credential instead (--env-file).` A property need not be required.
- **Records stay immutable.** An identical repeat, including equal `bounds` (combinations in the same order, each with the same entries), returns 200; a different record, including different `bounds`, returns 409. A bound is changed by `capability remove` and `capability create` again. Bounds are per capability, so different scopes for different recipients take different capabilities.
- **Warnings for `gh`.** After creating (201) a capability on a `gh` source with a bound, the daemon runs `repo_view`'s `gh` arguments, with the [gh environment](#the-gh-process) of the capability's credential and a 10-second timeout each, for each distinct exact `repo` value in order of first appearance, skipping `OWNER/*`. A non-zero exit, a timeout, or a failure to start adds `REPO is not visible to this credential` to the response's `warnings`. The checks run one after another and share a 40-second budget, each check's timeout cut to what is left, so the response comes within the CLI's request timeout; a repository the budget leaves no time for is not checked and gets no warning. The create is not refused. The `POST /v1/capabilities` response is the capability view plus `warnings`, always present: on 201 the check's warnings, `[]` when there are none, and on a 200 repeat always `[]`, since a repeat runs no check. The CLI prints each as `warning: TEXT` to stderr.

**Matching.** A call passes a bound when, for at least one combination, every name in it is present at the top level of the call's `input` with a string value that matches:
- by exact byte equality, by default;
- for the `repo` argument of a `gh` source, by ASCII case-insensitive equality, and a bound value `OWNER/*` matches any value with a non-empty part after its first `/` whose part before it equals `OWNER`, ignoring ASCII case.

A call that omits a bound argument does not match. Peerspan never fills in or changes a value.

**Enforcement.** [Authorization](#authorization) step 2 gains a final check, at submission and at the recheck before start: when the capability has a bound and the operation is not `read`, the input must pass it. Otherwise the receiver answers 403 `{"code": "out_of_bounds", "error": TEXT, "bounds": BOUNDS}`, with the capability's `bounds`, and runs nothing:
- `TEXT` is exactly `This capability is limited to calls where ALLOWED. The call has GOT. Nothing was run.`
- `ALLOWED` is the combinations joined by ` or `, each as its entries `KEY is VALUE` joined by ` and `: `repo is acme/api or repo is acme/web`.
- `GOT` is every name in order of first appearance, joined by ` and `, each as `KEY "VALUE"` with the value encoded as a JSON string under the result text rules, `no KEY` when absent, or `a non-string KEY`: `repo "acme/infra"`.
- At submission it is a final `rejected` for `call`, and for agent tools a `rejected` call view whose `error` is `TEXT` and whose `note` is the never-ran note, as for any refused submission under slice 2's Submitting. At the recheck, a call queued under a removed and recreated capability with a narrower bound is `rejected` with `authorization lapsed before start`. A recheck that falls between the `capability remove` and the `capability create` finds no capability, so it rejects every call queued for it, inside the new bound or not. Refused calls are not counted against `max_calls_per_hour`.
- Raw sources, including the implicit capability `AGENT/SERVER` and `builtin/NAME`, have no bounds.

**Listings.** Each entry of `GET /peer/v1/capabilities`, `discover --json` (`GET /v1/discover`), and `GET /adapter/v1/capabilities` gains `bounds`: the capability's `bounds`, or `{}` for a source and for an entry from a host that predates this slice. For a bounded capability's tool operations, `GET /peer/v1/capabilities` narrows each `input_schema` (the stored snapshot is unchanged):
- when every combination has exactly one entry, all with the same name, and no value is a `gh` `OWNER/*`, that property becomes exactly `{"type": "string", "enum": [VALUES]}`, the distinct values in combination order;
- otherwise, each property named in a combination has `Limited by the owner: ALLOWED.` appended to its `description` after one space, or as its whole `description` when it has none;
- a property the schema no longer declares is left alone.

**The capability view.** `GET /v1/capabilities`, `capability show`, and the `POST /v1/capabilities` response show `bounds` from the record, and gain `credential_reach`: for a capability on a `gh` source, the `reach` of its own snapshot when it has its own credential, else of the source, or null when there is none; for any other source, null. `capability list` text adds `  bounds: ALLOWED` to a bounded capability's line.

### The review and `shares`

**The review**, which `share` prints to stderr before confirmation, changes in two places.

After the operations and resources lines, a bounded capability gets a bounds block:
- `Bounds: ALLOWED`;
- then one line: for a `gh` source whose every combination names `repo`, `  Every gh operation names its repository in repo, so Peerspan checks every call.`; otherwise `  Not checked by Peerspan: OP: NAME, NAME; OP: NAME.`, listing for each operation in the capability's order its top-level `input_schema` properties other than the bound names, sorted in byte order, leaving out operations with none, or `  Peerspan checks every argument of these operations.` when no operation has any. The schemas are those in the source's snapshot as `sources` lists it;
- when the capability has resources, a further line `  The bound does not apply to read, which is limited to the capability's resources.`

The reach statement becomes one of these lines, where `SENTENCE` is the [reach sentence](#the-reach-sentence) of the capability's `credential_reach`. For a guided share that will create a capability with its own credential, `SENTENCE` uses a null reach, since the credential has not been checked yet.

| Source | Bound | Reach statement |
| --- | --- | --- |
| `gh` | yes | `PRINCIPAL can use these operations only where ALLOWED; Peerspan refuses other calls. The credential reaches more than the bound. SENTENCE` |
| other | yes | `PRINCIPAL can use these operations only where ALLOWED; Peerspan refuses other calls. Arguments Peerspan does not check can still reach anything the credentials they run with on this host can reach.` |
| `gh` | no | `PRINCIPAL can use these operations with the credentials they run with on this host. SENTENCE No resource bound.` |
| other | no | `PRINCIPAL can use these operations with the credentials they run with on this host. Anything those credentials can reach through them, PRINCIPAL can too. No resource bound.` |

The `(can change things)` marks for a `gh` source follow its annotations, which are Peerspan's own and accurate.

**`shares`.** Each capability in `--json` gains `reach`, the reach statement above with `Recipients` as `PRINCIPAL`; `bounds` comes from the record. The text output adds two lines under each capability: `  bounds: ALLOWED` or `  bounds: none`, and `  reach: STATEMENT`.

**`discover`** text adds `    limited to ALLOWED` under a bounded capability's line.

### Status

- **Counts.** `capabilities.sources` counts built-in sources too.
- **Item 14** covers built-in sources as it covers other sources, with the subject `builtin/NAME` and the command `peerspan sources refresh --builtin`.
- The **activity kinds** are the existing ones: `sources.discovered` with subject `builtin`, and `sources.snapshot_failed` with subject `builtin/NAME`.

### Shared adapter

`list_capabilities` returns each entry's `bounds` as the daemon gives it. Its description gains the sentence: `Each entry's bounds lists the argument values its owner allows, as combinations; an empty object means no bound, and a call outside them is refused and never runs.`

### Persistence

Database version 21 adds the following. Version 19 is machine linking and version 20 is [per-call approval](#per-call-approval-slice-3). Version 21 binaries migrate every version from 0 to 20 up to 21, and refuse anything above 21. [Remote MCP servers](#remote-mcp-servers-and-oauth-slice-3) add version 22, which binaries from then on migrate to.

```sql
CREATE TABLE builtin_sources (name TEXT PRIMARY KEY, record TEXT NOT NULL);
PRAGMA user_version = 21;
```

- **Migration** to 21 creates the table and sets the version, in the same transaction as any earlier version's migration. Older binaries reject version 21.
- **Records.** `builtin_sources.record` holds the definition, `shareable`, `reason`, `missing_env`, the snapshot with its health fields, and `reach`. Values are rows of `tool_values` with `agent_id` `builtin`; that table has no foreign key to `agents`. Capability records gain only the populated `bounds`, and a capability's own snapshot may hold `reach`.
- **Peers.** A caller older than this slice ignores `bounds` and sees `out_of_bounds` as an ordinary 403. A receiver older than this slice has no bounds and no built-in sources, so nothing it serves changes.

### Verification

`conformance/capabilities.py` gains these cases, written from this section by an author independent of both implementations. They run across all four Go/Rust CLI and daemon pairings with `--probe`, the Go coordinator, and OpenSSH; the `list_capabilities` cases also need `--node`. They use a fake `gh`, and the fixture MCP server for bounds on MCP sources (extended as needed with tools that take string, non-string, and free-form arguments).

**The fake `gh`** is an executable script named `gh` in a directory placed on the CLI's `PATH` and absent from the daemon's. The daemon runs it with only the variables listed for the gh process, so the script finds its control file and log by a path written into it, not through the environment. It:
- answers `--version`, `auth status --json hosts`, `auth token --hostname github.com --user LOGIN`, `api --include --hostname github.com user`, and each operation's arguments with canned output chosen per test, including several accounts, an unauthenticated one, `GH_TOKEN` entries, tokens of each prefix, and responses with and without `X-OAuth-Scopes`;
- records each invocation: its arguments, the names of its environment variables and the values of those other than `GH_TOKEN`, a digest of `GH_TOKEN`, its working directory, and its standard input;
- can exit 1, 4, or 8, sleep, ignore `SIGTERM`, write more than 1,000,000 bytes, and write invalid UTF-8.

It covers:
- **Discovery:** `gh` absent (no built-in sources, earlier ones removed, and the `sources` hint line); each `shareable: false` reason, in precedence order, including `name` for an agent named `builtin` with a tool server `gh`; a version below 2.81.0 and an unparseable one; `gh` and `gh-LOGIN` naming, lowercasing and replacement, the first account when none is active, and `GH_TOKEN` entries ignored; the discovery commands' environment, with the four token variables removed and the two `GH_` variables set; the absolute `command` used by the daemon although its `PATH` lacks the script; `sources refresh` with and without `--builtin`, `--builtin` with `--agent` refused, and `attach`'s `builtin` output; `attach --name builtin` refused.
- **Token capture:** the token in `tool_values` with `agent_id` `builtin` and nowhere in definitions, `sources --json`, `capability show`, the review, logs, or activity; a failed `auth token` giving `missing_env`; the environment file and a capability's `env_file` overriding the stored `GH_TOKEN`.
- **Reach:** `reach` for each token type, the scopes header present, absent, and empty, a failing check with each error text, and the matching sentence in `sources`, the review, and `shares`; a capability with its own `GH_TOKEN` getting its own reach in `credential_reach`.
- **Operations:** `tools/list` names, order, read-only marks, annotations, and schemas, as seen in `sources --json`; for each operation, the exact arguments with and without each optional property and the defaults, the result text, standard input for writes and none otherwise, the working directory, and the exact environment; invalid arguments for each rule, running nothing; injection attempts: values starting with `-`, a URL or branch in `number`, `HOST/` in `repo`, `/..` endings, control characters, and unknown properties.
- **Execution:** exit 1 with the `gh failed` text and the 2,048-byte tail, and with empty standard error; exit 4 as `jsonrpc_error` with the message and item 14; `pr_checks` exits 1 and 8 as success; output over 1,000,000 bytes as `failed` with `result_too_large` and no stored result; a `pr_diff` with invalid UTF-8; unreadable output; the 120-second timeout with a process that ignores `SIGTERM` killed 2 seconds later; cancellation of a running write killing the process, the call `uncertain`, and no second invocation; the server's log holding no arguments, bodies, results, or token.
- **Bounds on `gh` and on an MCP source:** `--bound` parsing and its refusals; combinations versus independent values (`owner=acme,repo=api` and `owner=beta,repo=web` refusing `acme/web`); `bound_unenforceable` with its text for a missing and a non-string argument; the `gh` matcher's case-insensitivity and `OWNER/*`, other wildcards refused; a bound without tool operations refused; repeat and conflict with bounds; `out_of_bounds` with its exact text and `bounds` for a different value, an absent argument, and a non-string one, with nothing executed and nothing counted against the budget; `read` unaffected; rejection at the recheck after remove and recreate with a narrower bound; raw sources unbounded; the `warnings` for a repository the credential cannot see, and none for `OWNER/*`.
- **Display:** `bounds` in `capability list` and `show`, `discover`, `GET /peer/v1/capabilities`, and `list_capabilities`; narrowed schemas by `enum` and by description; the review's bounds block and each reach statement; `shares` text and `--json`; the guided share's prompts for `gh` and for MCP sources at a terminal.
- **Calls through capabilities on `gh`:** a full call by policy and by self, from the CLI and through `call_capability`, and a raw `builtin/gh` source call from a trusted host it is open to.
- **Status:** built-in sources in the counts, and item 14 with its subject and command.
- **Migration:** a database at version 20 migrating to 21; with `--baseline18`, a version 18 database migrating to 21; a database at version 22 refused.
- **Compatibility:** when a version 18 build is given (`--baseline18`), a receiver at version 18 serving capabilities without `bounds`, listed with `bounds` `{}` by `discover`.

`conformance/live_capability_agents.py` gains one run against a real test repository with a real `gh`, through all three harnesses: a bounded `gh` capability lists issues in the bound repository, and a call for another repository is refused with the `out_of_bounds` text.

## Remote MCP servers and OAuth (slice 3)

Slice 3, item A, as accepted in [decision 16](#owner-decisions) from its [proposal](capabilities-slice3-remote-proposal.md), with the owner's addition on the share review of a server with no sign-in. A source can be a remote MCP server reached over Streamable HTTP. It gets its credential in one of three ways: **none** (a server that asks for no sign-in), **headers** (fixed headers from the harness configuration), or **oauth** (Peerspan signs in as its own OAuth client and keeps its own tokens on the serving host). Capabilities, sharing, policy, the peer routes, call states, and the agent tools are unchanged above the transport. Where this section differs from the sections above, this section applies. Behavior is the same in Go and Rust hosts, in every CLI and daemon pairing.

Out of scope: the deprecated HTTP+SSE transport, Client ID Metadata Documents, the OAuth device flow, completing a sign-in from another machine, using a harness's stored tokens, `headersHelper`, proxies, server-to-client requests other than `ping`, and the session-less 2026-07-28 protocol form.

### Remote definitions

A remote server's definition, in `PUT /v1/agents/{agent_id}/tool-servers`, adds two optional fields, `remote` and `headers`:

```json
{
  "name": "linear",
  "transport": "remote",
  "command": null,
  "args": [],
  "env": {},
  "url": "https://mcp.linear.app/mcp",
  "remote": {"protocol": "http", "oauth": {"client_id": null, "scopes": null, "callback_port": null}, "headers_helper": false},
  "headers": {"Authorization": {"source": "captured", "variables": ["LINEAR_TOKEN"]}},
  "source": "claude-code:user"
}
```

- **Shape.** A JSON `null` for `remote` or `headers` reads as absent. For `transport` `stdio`, `remote` is absent and `headers` is absent or `{}`. For `remote`, `command` is null, `args` is `[]`, and `env` is `{}`; `remote` absent reads as `{"protocol": "http", "oauth": {"client_id": null, "scopes": null, "callback_port": null}, "headers_helper": false}`, and `headers` absent reads as `{}`. Any other shape is 400.
- **`remote`** is exactly `{protocol, oauth, headers_helper}`:
  - `protocol` is `http` (Streamable HTTP) or `sse` (the deprecated HTTP+SSE transport, which is not supported);
  - `oauth` is null when the harness turned OAuth off (OpenCode `oauth: false`), and otherwise exactly `{client_id, scopes, callback_port}`: the harness's public hints, each null when absent. `client_id` and `scopes` are strings (`scopes` space-separated), and `callback_port` an integer from 1 to 65535;
  - `headers_helper` is true when the harness runs a command to produce headers (Claude Code `headersHelper`).
- **`headers`** maps each header name (an HTTP token, at most 64 entries) to how its value is obtained:
  - `{"source": "literal"}`: the value is written in the configuration;
  - `{"source": "captured", "variables": [NAME, ...]}`: the value contained references, all resolved at discovery; `variables` lists every variable it referenced, in order of first appearance, without duplicates;
  - `{"source": "missing", "variables": [NAME, ...]}`: a reference could not be resolved; `variables` lists those that could not.
- **Values.** The `values` payload carries, per server:
  - `headers.NAME`: the full value of each `literal` or `captured` header;
  - `header_templates.NAME`: for each `captured` header, the configured text with its references, written as `${NAME}` or `${NAME:-DEFAULT}`;
  - `url`: the resolved URL, when the configured `url` contained a reference.

  Any other field for a remote server, or one of these for a header whose entry does not allow it, is 400. As for `env`, values appear only in `tool_values`, never in definitions, listings, output, logs, or activity. Header templates are stored as values because they may hold text written in the configuration.
- **References** in `url` are resolved like those in `command`: a URL with an unresolved reference makes the server `missing_env`, naming the variables, and is not judged for `insecure_url`.

**Per harness** (the CLI reads only these fields; client secrets are never read):

| Harness | Remote when | `protocol` | Headers | `oauth` hints |
| --- | --- | --- | --- | --- |
| Claude Code | `type` is `http`, `streamable-http`, or `sse`, or `url` is set and `type` is not `stdio` | `sse` for `type: "sse"`, else `http` | `headers`, with `${VAR}` and `${VAR:-D}` resolved from the CLI's environment as for `env` | `oauth.clientId`, `oauth.scopes` (a string, or an array joined with spaces), `oauth.callbackPort`; `headersHelper` present sets `headers_helper` |
| Codex | `url` is set | `http` | `http_headers` (literal); each `env_http_headers` entry `HEADER = "VAR"` as the template `${VAR}`; `bearer_token_env_var = "VAR"` as `Authorization` with the template `Bearer ${VAR}`. Later entries in that order replace earlier ones of the same name, compared case-insensitively. A variable that is set, even empty, is `captured`; an unset one makes the header `missing` | `scopes` (an array joined with spaces, or a string); `oauth.callback_port`, else the top-level `mcp_oauth_callback_port` |
| OpenCode | `type` is `remote`, or `url` is set and `type` is not `local` | `http` | `headers`, with `{env:VAR}` resolved as `${VAR}` without a default; the template is written with `${VAR}` | `oauth: false` makes `oauth` null; otherwise `oauth.clientId` and `oauth.scope` |

Codex `http_headers` values are literal even when they contain `${`. A header value that is not a string is written as its JSON text, as for `env`.

**The environment file and `--env-file`.** When the environment file defines every variable that a `captured` header references, the daemon resolves that header's template again with those values, instead of using the captured value; otherwise the captured value stands. For a capability with its own `env_file`, the lookup takes the capability's file first, then the environment file, under the same every-variable rule. Literal headers and the URL are never overridden.

### Shareable and reasons

`shareable` and `reason` are computed for every source. The reason `remote` is retired. Reasons, in precedence order: `name`, `disabled`, `insecure_url`, `sse`, `headers_helper`, `missing_env`, `login`.
- **`insecure_url`**: the URL (`values.url` when present, else `url`) is not an absolute `http` or `https` URL with a host, or it is `http` and its host, compared case-insensitively, is not `localhost`, `127.0.0.1`, or `[::1]`.
- **`sse`**: `remote.protocol` is `sse`.
- **`headers_helper`**: `remote.headers_helper` is true.
- **`login`**: the source's auth mode is `oauth` and this host has no usable credential for it ([Auth mode](#auth-mode)). It is the only reason a sign-in clears.

A source record stored before this slice keeps the reason `remote` until the next `PUT` for its agent, which recomputes it. A `PUT` from a CLI that predates this slice (no `remote` or `headers`) is accepted with the defaults above.

<a id="auth-mode"></a>
### Auth mode

Each remote source has an **auth mode**, learned when the daemon first reaches it: null (not reached yet), `none`, `headers`, or `oauth`. It is stored with the source, with the latest **challenge** `{resource_metadata, scope}` (each a string or null) when the mode is `oauth`.

**The probe.** A snapshot of a remote source whose definition reasons do not apply (every reason above but `login`) starts with `initialize`:
- with a usable OAuth credential for the source, the request carries its token, refreshed first as under [Use and refresh](#use-and-refresh);
- otherwise it carries only the definition's headers.

Its answer decides:
- **2xx:** the mode stays `oauth` if the request carried a token; otherwise it becomes `headers` when the definition has headers, else `none`. The snapshot proceeds as for stdio.
- **401 with a `WWW-Authenticate` header whose scheme is `Bearer`, when the request carried no token, the definition has no `Authorization` header (compared case-insensitively), and `remote.oauth` is not null:** the mode becomes `oauth` and the challenge is stored from the header's `resource_metadata` and `scope` parameters. The source has no usable credential, so it gets the reason `login`; the snapshot stops without a `snapshot_error`, and the previous snapshot is kept.
- **401 when the request carried a token:** the daemon refreshes once and repeats `initialize`. A second 401, or a refresh that is refused, makes the credential `login_required` and the source `login`, without a `snapshot_error`.
- **Any other 401**, including one for a source with a configured `Authorization` header or with `remote.oauth` null: `snapshot_error` is exactly `unauthorized`. The daemon never starts OAuth over a configured header.
- **Any other failure:** a `snapshot_error` as today. For an HTTP answer it contains the decimal status, for example `the server answered HTTP 503`.

**Usable.** A credential is usable when it exists for the source (or capability), its `state` is `ok` or `refresh_failed`, and its `resource` equals the source's canonical URL ([Signing in](#signing-in)).

### Listing

`GET /v1/sources` `SERVER` gains `remote` (null for stdio and built-in sources), `headers` (`{}` for them), and `auth`: null for stdio and built-in sources, and for remote sources `{mode, state, issuer, scope, account, registration, obtained_at, expires_at}`:
- `mode` is the auth mode;
- `state` is null unless `mode` is `oauth`; then it is the credential's `state`, or `login_required` when there is no credential;
- the other fields come from the source's own credential (capability sign-ins are not shown here), each null without one. No token, client secret, or header value ever appears.

**`sources` text.** For a remote source, the line `  AGENT/SERVER  remote  from SOURCE  STATE` is unchanged, with `STATE` `not usable: login` for a source that needs a sign-in. It is followed by `    url: URL` (the configured `url`, references unresolved) and one auth line:
- mode null: `    auth: not reached yet`;
- `none`: `    auth: none (the server asks for no sign-in)`;
- `headers`: `    auth: headers NAME, NAME` (the header names, sorted by byte order);
- `oauth` with a usable credential: `    auth: signed in to ISSUER_HOST, scopes SCOPE, account LABEL, STATE` with `SCOPE` `none` when null, `LABEL` `not labelled` when null, and `STATE` the credential's state;
- `oauth` otherwise: `    auth: needs a sign-in: peerspan sources login AGENT/SERVER`.

`ISSUER_HOST` and `URL_HOST` are the host of the issuer or URL, lowercased, without port; an IPv6 host keeps its brackets.

**`attach` output.** The `sources.servers` entries keep their shape. The readable line's wording is not shared.

### Signing in

| CLI | Local API | Behavior |
| --- | --- | --- |
| `sources login SOURCE [--scopes "A B"] [--client-id ID] [--client-secret-file PATH] [--port N] [--no-browser] [--account LABEL]` | `POST /v1/sources/{agent}/{server}/login`, then `POST /v1/oauth/logins/{login_id}/complete` | Signs Peerspan in to the source's server, as below. `SOURCE` is `AGENT/SERVER`, or `SERVER` when exactly one agent on this host has a server of that name; when several do, the CLI exits 1 before any request, listing the qualified names. |
| `capability login NAME [same flags]` | the same routes, with `capability: NAME` | Gives the capability its own sign-in ([Per-capability sign-in](#per-capability-sign-in)). |
| `sources logout SOURCE [--yes]` | `POST /v1/sources/{agent}/{server}/logout` | Revokes and deletes this host's credential for the source ([Revocation](#revocation-and-removal)). |
| `capability logout NAME` | the same route, with `capability: NAME` | Revokes and deletes the capability's own credential. |

`{agent}` is an agent name or ID. The CLI resolves `capability login` and `logout` to the capability's source first, through `GET /v1/capabilities/{name}`.

**Starting.** `POST /v1/sources/{agent}/{server}/login` takes `{capability, scopes, client_id, client_secret, redirect_port, account}`, each optional and nullable; any other field is 400. `scopes` is a space-separated string; `redirect_port` an integer from 1 to 65535; `account` at most 256 bytes without characters below U+0020 or U+007F; `client_secret` only with `client_id`. The daemon:
1. **Checks**, in this order, refusing as in [Refusals](#login-refusals): the source exists; with `capability`, that capability exists and is built on this source; the source is remote; `remote.oauth` is not null; no definition reason applies.
2. **Probes.** It sends `initialize` with the definition's headers and no token. The answer must be a 401 with a `Bearer` challenge, and the definition must have no `Authorization` header; the challenge is stored as under the probe. Anything else is `no_challenge`; a failure to connect is `unreachable`.
3. **Finds the authorization server.** It fetches the protected resource metadata ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)) from the challenge's `resource_metadata` when given, else from `ORIGIN/.well-known/oauth-protected-resource/PATH` when the MCP URL has a path other than `/` (`PATH` without its leading `/`), then from `ORIGIN/.well-known/oauth-protected-resource`, using the first 200 answer that is a JSON object with a non-empty string array `authorization_servers`. The issuer `I` is its first entry. It then fetches the authorization server metadata from, in order: for an `I` with a path `P` other than `/`, `ORIGIN/.well-known/oauth-authorization-server/P`, `ORIGIN/.well-known/openid-configuration/P`, and `I/.well-known/openid-configuration`; for an `I` without a path, `ORIGIN/.well-known/oauth-authorization-server` and `ORIGIN/.well-known/openid-configuration`. The first 200 JSON object is used. Its `issuer` must equal `I` exactly, and it must have string `authorization_endpoint` and `token_endpoint`. Every metadata URL and every endpoint must be `https`, or `http` on a loopback host (`localhost`, `127.0.0.1`, `[::1]`). Any failure is `oauth_metadata`.
4. **Requires PKCE.** `code_challenge_methods_supported` must be an array containing `S256`; otherwise `no_pkce`.
5. **Picks the redirect URI** `http://127.0.0.1:PORT/callback`, where `PORT` is `redirect_port`, else the hint `remote.oauth.callback_port`, else the port of the most recently created stored client registration for `I`, else a free port the daemon finds by binding `127.0.0.1:0`.
6. **Gets a client**, the first that applies:
   - `client_id` given: stored as the registration for `(I, redirect URI)` with `registration` `manual`, replacing any stored one, with `client_secret` when given;
   - a stored registration for `(I, redirect URI)`;
   - the hint `remote.oauth.client_id`: stored with `registration` `harness` and no secret;
   - the metadata has a string `registration_endpoint`: dynamic client registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)), below, stored with `registration` `dcr`; a refused or unreadable registration is `registration_failed`;
   - otherwise `no_registration`.
7. **Chooses scopes:** `scopes` given, else the hint `remote.oauth.scopes`, else the challenge's `scope`, else the protected resource metadata's `scopes_supported` joined with spaces, else none.
8. **Builds the authorization URL**: the `authorization_endpoint` with these query parameters added (after its own query, if any): `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `resource`, and `scope` when scopes were chosen. `state` is 32 random bytes in lowercase hex. The PKCE verifier is 32 random bytes in base64url without padding, and `code_challenge` is the base64url encoding, without padding, of its SHA-256 digest. `resource` is the source's **canonical URL**: the URL with scheme and host lowercased, no fragment, and trailing `/` characters removed from the path.
9. **Keeps the login in memory only**, for 10 minutes: `{login_id, state, verifier, client, issuer, redirect_uri, scopes, account, source, capability, endpoints}`. `login_id` is `login_` and 16 random bytes in lowercase hex. A daemon restart forgets it.
10. **Answers** 200 `{login_id, authorization_url, redirect_uri, expires_at}`.

**Dynamic client registration.** A `POST` to `registration_endpoint` with `Content-Type: application/json` and exactly `{"client_name": "Peerspan (HOST_LABEL)", "redirect_uris": [REDIRECT_URI], "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "token_endpoint_auth_method": "none", "application_type": "native"}`. `HOST_LABEL` is this machine's host name up to its first `.`, at most 64 bytes; with none, the name is `Peerspan`. A 200 or 201 JSON answer with a string `client_id` is kept with its `client_secret` and `registration_access_token` when present. With a `client_secret`, the client authenticates as the answer's `token_endpoint_auth_method` says, `client_secret_post` or `client_secret_basic`, and `client_secret_basic` when it says neither; without one, it is a public client (`none`). A `manual` client with a secret uses `client_secret_post`, unless the metadata's `token_endpoint_auth_methods_supported` lists `client_secret_basic` and not `client_secret_post`.

**One registration per issuer and redirect URI per host**, reused by every source and capability using that issuer. A source whose issuer changes gets a new registration; a registration is never sent to another issuer.

**Approving.** The CLI then:
1. Refuses before any request when stdin is not a terminal and `--no-browser` is not given (see [Refusals](#login-refusals)). `--client-secret-file` without `--client-id` exits 1 with `--client-secret-file needs --client-id.`; a secret file whose mode grants any group or other permission exits 1 with `PATH must have mode 0600 or stricter.` It reads the file once, removes trailing whitespace, and sends it as `client_secret`.
2. Starts the login, then listens on `127.0.0.1:PORT`, the port of `redirect_uri`. If the port is busy, it prints `Port PORT on 127.0.0.1 is in use, so Peerspan cannot receive the redirect; paste the address instead.` and only reads pasted lines.
3. Prints, to stderr, in **print mode** (with `--no-browser`, when `SSH_CONNECTION` is set, or on Linux when neither `DISPLAY` nor `WAYLAND_DISPLAY` is set, or when the browser command cannot be started):
   ```text
   Open this link in a browser on any machine and approve Peerspan:
     AUTHORIZATION_URL
   If the browser then shows a page that cannot be reached, copy the full address
   from its address bar and paste it here:
   ```
   Otherwise it starts `xdg-open AUTHORIZATION_URL` (Linux) or `open AUTHORIZATION_URL` (macOS) and prints the same block with the first line `Opening your browser to approve Peerspan. If it does not open, use this link:`.
4. Waits for whichever comes first: a `GET` to the listener with the path `/callback` (other requests get 404 and are ignored), or a non-empty line on stdin, trimmed. At end of stdin it keeps waiting for the listener if it has one, and otherwise exits 1 with `The sign-in was not completed.` When the login's `expires_at` passes first, it exits 1 with the `login_expired` text.
5. Posts `{callback_url}` to `POST /v1/oauth/logins/{login_id}/complete`: for the listener, `http://127.0.0.1:PORT` followed by the request's path and query; for a pasted line, the line. The listener answers the browser after the daemon has answered: 200 with `Content-Type: text/html; charset=utf-8` and a page containing `Peerspan sign-in complete. You can close this tab.`, or 400 with a page containing `Peerspan sign-in failed.` and the daemon's error text.
6. On success prints the daemon's answer as JSON on stdout and `Signed in to ISSUER_HOST for SOURCE (scopes: SCOPE).` on stderr, with `SCOPE` `none` when null, and exits 0. On a refusal it prints the error and exits 1.

The PKCE verifier and the tokens never pass through the CLI; only the redirect URL does.

**Finishing.** `POST /v1/oauth/logins/{login_id}/complete` with exactly `{callback_url}`. The login is removed from memory at the first attempt, whatever its outcome. The daemon:
1. reads the query of `callback_url`. An unknown or expired `login_id`, a missing `state`, or a `state` that differs is `login_expired`;
2. an `error` parameter is `provider_refused`; a missing `code` is `no_code`;
3. posts the token request to `token_endpoint` (`application/x-www-form-urlencoded`, `Accept: application/json`) with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`, and `resource`, plus the client's authentication: `client_secret` in the form for `client_secret_post`, or HTTP Basic with the URL-encoded client ID and secret for `client_secret_basic`;
4. needs a 200 JSON object with a string `access_token`, and `token_type` absent or `Bearer` in any case; anything else is `token_refused`, with `ERROR` the answer's `error` string when it has one, else `HTTP STATUS`;
5. checks, as it stores, that the source still exists with the same canonical URL (and, for a capability, that the capability still exists on it); otherwise the sign-in is `login_expired` and the issued tokens are revoked in the background. It then stores the credential (below), replacing any stored one for the key; a replaced credential's tokens are revoked in the background, best effort. It records `sources.login` and, for a capability, sets its [own sign-in](#per-capability-sign-in);
6. snapshots the source, or for a capability its own instance, with the token. A failed snapshot does not fail the sign-in; it is recorded as `snapshot_error`;
7. answers 200 `{source, capability, issuer, scopes, account, expires_at, registration}`: `source` is `AGENT/SERVER` (agent name), `capability` the name or null, `scopes` the stored `scope` (a string or null), and the rest from the credential.

<a id="login-refusals"></a>**Refusals.** Each is `{code, error}` with exactly this `error` text, which the CLI prints on stderr before exiting 1. `SOURCE` is `AGENT/SERVER`, `ISSUER` the issuer, and `PORT` the redirect URI's port.

| Case | Status and code | Text |
| --- | --- | --- |
| No such source (also the CLI's `SERVER` matching none) | 404 `not_found` | `No source SOURCE on this host. Run peerspan sources.` |
| `capability` names no capability on this host | 404 `not_found` | `No capability NAME on this host. Run peerspan capability list.` |
| The capability is built on another source | 400 `invalid` | `NAME is not built on SOURCE.` |
| `remote.oauth` is null | 409 `oauth_disabled` | `SOURCE has OAuth turned off in its harness configuration.` |
| A definition reason applies | 409 `not_usable` | `SOURCE is not usable (REASON), so Peerspan cannot sign in to it.` |
| Not remote, or the probe found no challenge | 409 `no_challenge` | `SOURCE did not ask for a sign-in, so there is nothing to sign in to.` |
| The probe could not connect | 502 `unreachable` | `Peerspan could not reach SOURCE: DETAIL` |
| Metadata missing, unreadable, insecure, or with a wrong `issuer` | 502 `oauth_metadata` | `Peerspan could not read the authorization server metadata for SOURCE: DETAIL` |
| No `S256` | 409 `no_pkce` | `The authorization server for SOURCE (ISSUER) does not advertise PKCE, so Peerspan will not sign in to it.` |
| No way to register | 409 `no_registration` | `The authorization server for SOURCE (ISSUER) does not let Peerspan register itself. Register an OAuth app with the provider, with redirect URI http://127.0.0.1:PORT/callback, then run: peerspan sources login SOURCE --client-id ID [--client-secret-file PATH]` |
| Registration refused | 502 `registration_failed` | `The authorization server for SOURCE (ISSUER) refused to register Peerspan: DETAIL` |
| Unknown or expired login, or `state` missing or different | 400 `login_expired` | `This sign-in link is no longer valid. Run peerspan sources login SOURCE again.` (for an unknown `login_id`, `SOURCE` is the literal word `SOURCE`) |
| `error` in the redirect | 400 `provider_refused` | `The provider refused the sign-in: ERROR (DESCRIPTION).`, or `The provider refused the sign-in: ERROR.` without `error_description` |
| No `code` in the redirect | 400 `no_code` | `The redirect carried no authorization code. Run peerspan sources login SOURCE again.` |
| Token request refused | 502 `token_refused` | `The provider refused to issue a token: ERROR (DESCRIPTION).`, or without the parenthesis when there is no `error_description` |
| CLI: no terminal and no `--no-browser` | exit 1, no request | `sources login needs a terminal, or --no-browser to print the link and read the pasted address from stdin.` (`capability login` says `capability login` instead) |

`DETAIL` wording is not shared. Other invalid bodies are 400 `invalid`.

### Tokens

**The credential.** Each sign-in is one OAuth credential, keyed by `(agent_id, server, capability)`, where `capability` is `""` for the source's own sign-in. Its record:

```json
{
  "issuer": "https://auth.example",
  "resource": "https://mcp.example/mcp",
  "registration": "dcr",
  "client": {"issuer": "https://auth.example", "redirect_uri": "http://127.0.0.1:53682/callback"},
  "token_endpoint": "https://auth.example/token",
  "revocation_endpoint": "https://auth.example/revoke",
  "access_token": "…",
  "refresh_token": "… or null",
  "token_type": "Bearer",
  "expires_at": "RFC3339 or null",
  "scope": "read write",
  "account": "work or null",
  "obtained_at": "RFC3339",
  "refreshed_at": "RFC3339 or null",
  "state": "ok",
  "refresh_failed_at": "RFC3339 or null"
}
```

- `registration` is `dcr`, `manual`, or `harness`. `revocation_endpoint` is the metadata's, or null.
- `expires_at` is `obtained_at` (or the refresh time) plus `expires_in` when the token answer has a numeric `expires_in`, else null. `scope` is the answer's `scope`, else the scopes requested, else null. `account` is `--account`, else null.
- `state` is `ok`; `refresh_failed` (the latest refresh failed in a way that may recover, such as a network error, a 5xx, or an error other than `invalid_grant` and `invalid_client`; `refresh_failed_at` is when the first such failure since the last success happened); or `login_required` (a refresh was refused with `invalid_grant` or `invalid_client`, the token was refused after a refresh, or it could not be refreshed because there is no refresh token).
- **Client registrations** are stored separately, keyed by issuer and redirect URI: `{issuer, redirect_uri, client_id, client_secret, registration_access_token, method, registration, created_at}`, where `method` is `none`, `client_secret_post`, or `client_secret_basic`.
- **At rest.** Credentials and registrations are stored in the host database, in the 0700 state directory, as `tool_values` are. Tokens, client secrets, and registration access tokens never appear in any response, output, log, or activity, and are never sent to peers or the coordinator.

<a id="use-and-refresh"></a>**Use and refresh.**
- **Every request** to the MCP endpoint of an OAuth source carries `Authorization: Bearer ACCESS_TOKEN`. Tokens are sent only to the MCP URL and to the credential's token and revocation endpoints. HTTP redirects from the MCP endpoint or any OAuth endpoint are never followed: a 3xx answer is an error.
- **Refresh before use.** Before `initialize`, before each call, and before each snapshot request, when `expires_at` is within 60 seconds, or when the credential was marked by a 401 to a call, the daemon refreshes: a `POST` to `token_endpoint` with `grant_type=refresh_token`, `refresh_token`, `client_id`, and `resource`, with the client's authentication. A 200 JSON answer with an `access_token` replaces the access token, the refresh token when the answer has one, `expires_at`, and `scope` when given, sets `refreshed_at`, `state` `ok`, and `refresh_failed_at` null.
- **One refresh at a time.** Refreshes of one credential are serialized, and the new tokens are stored, in one transaction, before they are used. A request waiting on a refresh uses its result.
- **A refused refresh** (`invalid_grant` or `invalid_client` in a 400 or 401 JSON answer, or no refresh token when one is needed) makes the credential `login_required`. Any other failure makes it `refresh_failed`, and the request goes ahead with the current access token. Each failed refresh records `sources.token_refresh_failed`.
- **401 during a session.** For `initialize`, `tools/list`, and `resources/list`, the daemon refreshes once and repeats the request; a second 401 makes the credential `login_required`. For `tools/call` and `resources/read`, a 401 makes the call `failed` with `auth_required`, the call is not sent again, and the credential is marked so that the next request refreshes first.
- **403 `insufficient_scope`** (a `WWW-Authenticate` `Bearer` challenge with `error="insufficient_scope"`) makes the call `failed` with `insufficient_scope`, and records the time and the challenge's `scope` on the source, or on the capability's own instance, for [status](#remote-status). There is no automatic step-up.

<a id="revocation-and-removal"></a>**Revocation and removal.**
- **`sources logout SOURCE [--yes]`.** When capabilities built on the source use its sign-in (those without their own), the CLI first prints them, one per line, and asks `Sign out? Calls to these capabilities will fail until the next sign-in. [y/N] `; `--yes` skips the question, and without a terminal and `--yes` it exits 1 with `confirm this sign-out at a terminal, or pass --yes`. The route takes `{capability}` (optional, nullable). When the credential has a `revocation_endpoint`, the daemon posts the refresh token (when there is one) and then the access token to it ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)), as `token` with `token_type_hint` `refresh_token` or `access_token`, `client_id`, and the client's authentication. It then deletes the credential, whatever the revocation did, and records `sources.logout`. It answers 200 `{source, capability, revoked, deleted}`: `revoked` is true when every token posted got a 200; `deleted` is false only when there was no credential (then nothing is posted). Shares are kept.
- **The CLI** prints the answer as JSON on stdout. When `deleted` is true and `revoked` false, it prints on stderr `ISSUER has no revocation endpoint Peerspan could use. To revoke access there, remove "Peerspan (HOST_LABEL)" from the connected apps of your account.`; when `deleted` is false, `SOURCE has no sign-in on this host.` (`capability logout`: `NAME has no sign-in of its own on this host.`).
- **A source dropped by a `PUT`** loses its credentials, the source's and its capabilities' own, with the definition, values, and snapshot. **A URL change** (a canonical URL that no longer equals a credential's `resource`) deletes the source's credentials likewise, and resets the stored auth mode and challenge, so the next probe learns them again. In both cases the credentials are deleted in the `PUT`'s transaction, and their tokens are revoked in the background, best effort.
- **`capability remove`** deletes the capability's own credential with the record, revoking it in the background, best effort.
- **At the provider.** When the owner revokes Peerspan there, the next refresh or request gets `invalid_grant` or 401, and the credential becomes `login_required`.
- **`unshare`** does not touch credentials.

<a id="per-capability-sign-in"></a>
### Per-capability sign-in

A capability built on an OAuth source may have its own sign-in (`capability login NAME`), for example with another account or fewer scopes.
- **Effect.** A successful `capability login` stores the credential under the capability's key and marks the capability record with `own_sign_in: true`. The capability then has its own instance (`…/SERVER@CAPABILITY.log`) and its own snapshot, taken with its own token, as a capability with its own `env_file` does; its operations are judged against that snapshot. It is judged only by its own credential: it keeps working while the source's sign-in has lapsed or been signed out.
- **Sign-out.** `capability logout NAME` deletes the capability's credential but keeps `own_sign_in`, so the capability is `unavailable` with `auth` until the next `capability login`; it never falls back to the source's sign-in, which may reach more.
- **The record.** `own_sign_in` is stored only when true, and is not part of the comparison for an identical `capability create` repeat.
- **Snapshots.** A `PUT` for the agent, and `sources refresh`, snapshot such a capability with its own token when its credential is usable, and skip it, without a `snapshot_error`, when it is not.

### Running remote servers

The rules of [Running servers](#running-servers) apply, with these meanings:

| Rule | For a remote server |
| --- | --- |
| Instance | One MCP session: an HTTP client, the negotiated protocol version, and `MCP-Session-Id` when the server set one. One per source, and one per capability with its own `env_file` or own sign-in. |
| Starting | `POST initialize`, then `notifications/initialized`, within 30 seconds. A failure fails the instance's waiting calls with `server_start_failed` and counts toward the 3 failures in 10 minutes, except a 401 after the refresh and retry, which fails them with `auth_required`. |
| Concurrency | At most 4 calls at once per instance. |
| Idle stop | After 10 minutes without calls, a `DELETE` to the MCP URL with `MCP-Session-Id`, when one was set; any answer is accepted. |
| Log | `STATE/tool-logs/AGENT_ID/SERVER.log` (or `…@CAPABILITY.log`), mode 0600, records HTTP statuses, session changes, refreshes, and errors, never header values or tokens. |

- **Requests.** Each JSON-RPC message is a `POST` to the URL with `Content-Type: application/json`, `Accept: application/json, text/event-stream`, the definition's headers (with their values and overrides), `Authorization` for OAuth, `MCP-Protocol-Version` with the negotiated version after `initialize`, and `MCP-Session-Id` once set. Definition headers named `Content-Type`, `Accept`, `Content-Length`, `Host`, `MCP-Protocol-Version`, or `MCP-Session-Id` (case-insensitively) are not sent. Notifications expect 202 or 200, and their answers are not read.
- **Answers.** A `Content-Type` of `application/json` is read whole as one JSON-RPC response. `text/event-stream` is read event by event until the event whose `data` (its `data:` lines joined with `\n`) is the response to this request. Other messages on the stream are dropped and logged; a request from the server on it is answered with a `POST` of the JSON-RPC response `{"jsonrpc": "2.0", "id": ID, "result": {}}` for `ping`, and of a JSON-RPC error response with code `-32601` otherwise. Any other content type is an error.
- **Protocol version.** The client offers `2025-06-18` and accepts `2025-03-26`, `2025-06-18`, or `2025-11-25` from the server.
- **Size.** A body, or the part of an event stream read for one response, is read up to 2 MiB; beyond that the read stops. For a call this is `failed` with `result_too_large` and `result_bytes` null; a result over 1,048,576 bytes is `failed` with `result_too_large` as today.
- **Timeouts.** Connecting, TLS included, has 10 seconds. A call has no read timeout of its own beyond its deadline.
- **TLS and proxies.** `https` uses the system's trust store in both hosts. Neither host uses `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY`.

**Call outcomes** for an answer to `tools/call` or `resources/read`, beyond the JSON-RPC and result outcomes of today:

| Answer | State | `error` |
| --- | --- | --- |
| The connection could not be made (DNS, connect, or TLS), so nothing was sent | `failed` | `server_exited` |
| 401 | `failed` | `auth_required` |
| 403 with an `insufficient_scope` challenge | `failed` | `insufficient_scope` |
| 404 to a request carrying `MCP-Session-Id` (the session is gone; the instance ends, and queued calls start a new one) | `failed` | `server_exited` |
| Any other 4xx, a 3xx, or a 2xx that is not a readable JSON-RPC response | `failed` | `http_error` |
| 5xx | `uncertain` | `http_error` |
| The connection dropped after the request was sent, before its response | `uncertain` | `connection_lost` |
| Cancellation or the deadline while running | `uncertain` | `cancel_requested` or `deadline`, as today; the daemon posts `notifications/cancelled` with the request ID on the same session and stops reading the answer |

`failed` gains `auth_required`, `insufficient_scope`, and `http_error`; `uncertain` gains `connection_lost` and `http_error`. A call is never sent twice. A call that would start while its instance's OAuth credential is `login_required` is `failed` with `auth_required` without being sent; when a refresh before the call is refused, likewise.

### Capabilities on remote sources

- **`capability create --from AGENT/SERVER`** accepts a remote source once it is `shareable`, as any source. `--arg` with a remote source is 400 `--arg applies only to stdio sources`. `--env-file` supplies the variables that its headers reference, as above, and gives the capability its own instance.
- **`auth` in the capability view.** `GET /v1/capabilities`, `GET /v1/capabilities/{name}`, `capability show`, the `POST /v1/capabilities` response, and `shares --json` gain `auth`: null for a capability on a stdio or built-in source; otherwise `{mode, state, issuer, scope, account, registration, obtained_at, expires_at, own}`, where `own` is the record's `own_sign_in`, and the other fields are those of the credential the capability uses (its own when `own` is true, else the source's), computed as for sources.
- **`unavailable: ["auth"]`.** A capability whose credential is not usable is `unavailable` with exactly `["auth"]`: with `own` false, when its source is `login`; with `own` true, when its own credential is missing or `login_required`. A source whose only reason is `login` still counts as present for its capabilities, so they read `auth`, not `source`. A capability whose source is gone or not shareable for another reason reads `source`, as today.
- **Refusal.** A call to an operation of a capability that is `unavailable` with `auth` is refused at submission with 409 `{"code": "unavailable", "error": "the capability's sign-in has lapsed on its host"}`, before anything is persisted, and so is a call to a source (`AGENT/SERVER`) whose reason is `login`. A queued call that would start while that holds becomes `failed` with `auth_required`, instead of `rejected`.
- **Raw sources.** For the person's own machines, a remote source is called as any source, on the serving host's credential.

**The review.** For a capability on a remote source, the review's `Credentials:` line is replaced by one `Credential:` line, the first that applies:
- auth mode `none`: `Credential: none. AGENT/SERVER (URL_HOST) asks for no sign-in, so it serves anyone who can reach it. Sharing it lets the people you share with use the selected operations through this host, including when the server is only reachable from here (a local, home, VPN, or company network).`
- `headers`: `Credential: the token in the NAME header of AGENT/SERVER (from SOURCE).` for one header, or `Credential: the tokens in the NAME, NAME headers of AGENT/SERVER (from SOURCE).` for several, sorted by byte order; `SOURCE` is the definition's `source`. For a capability with its own `env_file`, followed on the same line by ` Values from the capability's environment file PATH override the variables those headers reference.`
- `oauth` with a usable credential: `Credential: Peerspan's own sign-in to ISSUER_HOST, scopes SCOPE, ACCOUNT, signed in on DATE.`, or with `own` true `Credential: this capability's own sign-in to ISSUER_HOST, scopes SCOPE, ACCOUNT, signed in on DATE.`, where `SCOPE` is the scope or `none`, `ACCOUNT` is `account LABEL`, or `account not labelled; Peerspan cannot see which account approved` without a label, and `DATE` is the `YYYY-MM-DD` of `obtained_at`;
- `oauth` otherwise: `Credential: the sign-in to AGENT/SERVER has lapsed; run peerspan sources login AGENT/SERVER` (with `own` true: `peerspan capability login NAME`);
- mode null: `Credential: unknown; Peerspan has not reached AGENT/SERVER yet.`

The reach statement is unchanged.

**`shares`.** Each capability on a remote source gets, in its text output, a line `  credential: TEXT`, where `TEXT` is the review's `Credential:` line without its `Credential: ` prefix.

**The guided share.** A source whose reason is `login` may be chosen, at a terminal or with `--from`. At a terminal, the CLI runs the sign-in (as `sources login SOURCE` without flags) right after the source is chosen and before the operations are asked; a failed sign-in exits 1 with nothing created. Without a terminal, such a source exits 1 with `SOURCE needs a sign-in first: run peerspan sources login SOURCE`, with nothing created.

<a id="remote-status"></a>
### Status

- **Counts.** `capabilities` in `GET /v1/status` gains `remote_sources`, the number of remote sources, and `signed_in`, the number of stored OAuth credentials (sources' and capabilities') whose `state` is not `login_required`.
- **Item 14** gains, with one item per subject as before:
  - for a remote source (subject `AGENT/SERVER`), command `peerspan sources login AGENT/SERVER` when: its credential is `login_required`, or `refresh_failed` with `refresh_failed_at` more than 1 hour ago; or it is `login` without a credential and has capabilities that use its sign-in;
  - otherwise, when it recorded an `insufficient_scope` in the last 24 hours, command `peerspan sources login AGENT/SERVER --scopes "SCOPES"` with the challenge's `scope`;
  - otherwise its existing causes and command, including a `snapshot_error` of `unauthorized` on a headers source (`peerspan sources refresh --agent AGENT`, after the owner updates the token);
  - for a capability with its own sign-in (subject `NAME`), command `peerspan capability login NAME` when its credential is missing, `login_required`, or `refresh_failed` for more than 1 hour; otherwise `peerspan capability login NAME --scopes "SCOPES"` for an `insufficient_scope` in the last 24 hours on its own instance; otherwise as before.

  The detail is free text and never holds tokens.

### Persistence

Database version 22 adds the following. Version 22 binaries migrate every version from 0 to 21 up to 22, and refuse anything above 22.

```sql
CREATE TABLE oauth_clients (issuer TEXT NOT NULL, redirect_uri TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(issuer, redirect_uri));
CREATE TABLE oauth_credentials (agent_id TEXT NOT NULL, server TEXT NOT NULL, capability TEXT NOT NULL DEFAULT '', record TEXT NOT NULL, PRIMARY KEY(agent_id, server, capability));
PRAGMA user_version = 22;
```

- **Migration** to 22 creates the two tables and sets the version, in the same transaction as any earlier version's migration, and rewrites no record. Older binaries reject version 22.
- **Records.** `tool_servers.record` gains `remote`, `headers`, `auth_mode`, `challenge`, and the health fields `insufficient_scope_at` and `insufficient_scope`; a capability's own snapshot may hold the health fields; capability records gain `own_sign_in` when true. Records without them read with the defaults: a remote record without `remote` reads, and is listed, with the http default under [Remote definitions](#remote-definitions), and without `headers` as `{}`; a stdio record with `remote` null and `headers` `{}`; mode null, no challenge, and false. `tool_values` holds the new value fields.
- **Activity:** `sources.login`, `sources.logout`, and `sources.token_refresh_failed`, with subject `AGENT_ID/SERVER`, or `AGENT_ID/SERVER@CAPABILITY` for a capability's own sign-in. Activity never holds tokens, codes, secrets, or header values.

### Older peers

Nothing on the wire changes except values: listings may show `unavailable: ["auth"]`, call records may carry the new `error` values, and a receiver may answer 409 `unavailable` with the new text. A caller of any earlier version shows them as it shows other values. A receiver older than this slice has no remote sources, so nothing it serves changes. An older CLI talking to this daemon sends definitions without `remote` and `headers`, which read with the defaults above.

### Verification

`conformance/capabilities.py` gains these cases, written from this section by an author independent of both implementations. They run across all four Go/Rust CLI and daemon pairings, with `--probe`, the Go coordinator, and OpenSSH; the agent tool cases also need `--node`. They use a fixture Streamable HTTP MCP server and a fixture OAuth authorization server, both in Python on loopback HTTP, which record every request (method, path, headers, and body) and can be told per test how to answer. The suite drives the authorization URL itself (the fixture approves at once and redirects), so it covers both the listener and the pasted address. Live runs against real providers are separate (below).

The fixtures can: require a static header; challenge with `WWW-Authenticate: Bearer` with and without `resource_metadata` and `scope`; serve protected resource metadata at the challenge URL, the path-inserted URL, and the root URL; serve RFC 8414 and OpenID Connect metadata at each well-known path; advertise or omit `S256`, `registration_endpoint`, and `revocation_endpoint`; answer DCR with and without a `client_secret`; check PKCE, `state`, `redirect_uri`, and `resource`; issue short-lived tokens and rotate refresh tokens; answer `invalid_grant`, `invalid_client`, a 5xx, and `insufficient_scope`; set and expire `MCP-Session-Id`; answer with JSON or SSE (with unrelated events and a `ping` request before the response); drop the connection after reading a call; return 3xx, 4xx, and 5xx; and serve oversized results.

It covers:
- **Discovery:** each harness's remote fields (`protocol`, the `oauth` hints, OpenCode `oauth: false`, `headersHelper`), headers as `literal`, `captured` with `variables`, and `missing`; Codex `http_headers`, `env_http_headers`, and `bearer_token_env_var`, and their precedence; OpenCode `{env:VAR}`; a URL with a reference; values (`headers.NAME`, `header_templates.NAME`, `url`) appearing in no listing, output, log, or activity; the environment file overriding a header only when it defines every referenced variable; a capability's `env_file` overriding header variables; a `PUT` without `remote` and `headers` accepted.
- **Reasons:** each reason in precedence order (`insecure_url` for `http` on another host and for loopback allowed, `sse`, `headers_helper`, `missing_env`, `login`), `remote` retired, and a record stored before this slice keeping `remote` until the next `PUT`.
- **Auth mode:** `none` and `headers` from a 2xx; `oauth` with the challenge stored and the reason `login` without a `snapshot_error`; `unauthorized` for a 401 with a configured `Authorization` header and for `oauth: false`; another failure's status in `snapshot_error`; `auth` in `sources --json` for each mode; the `sources` text lines.
- **Sign-in:** the full flow through the listener and through a pasted address, for a source and for a capability; protected resource metadata from each of the three places; authorization server metadata from each path in order, for issuers with and without a path; the `issuer` check; `S256` required; DCR with the exact request body and `Peerspan (HOST_LABEL)`, a returned secret used as `client_secret_post` and as `client_secret_basic`; `--client-id` with and without `--client-secret-file` (and the secret file's mode check); the harness `client_id` hint; one registration reused for a second source of the same issuer, and its port reused; scope choice in order; the authorization URL's parameters, the PKCE challenge matching the verifier at the token request, and `resource` equal to the canonical URL in both requests; `--account`; the output JSON and stderr line; `sources.login` activity; each refusal with its status, code, and text; `login_expired` after a wrong `state`, after a second use of a `login_id`, and for an unknown one; print mode with `--no-browser`; refusal without a terminal; a busy port falling back to paste.
- **Tokens:** no token, secret, or code in `sources --json`, `capability show`, `shares`, `status`, the review, logs, or activity; refresh before use with a short-lived token, with the rotated refresh token stored and the old one never reused; one refresh for several concurrent calls; `refresh_failed` on a 5xx with the request going ahead; `login_required` on `invalid_grant`, making the capability `unavailable` with `auth`, refused at submission with 409 and its text, with nothing persisted; queued calls failing with `auth_required` without being sent; a 401 to a call giving `auth_required`, never resent, and the next call refreshing first; `insufficient_scope` and item 14's command; tokens sent only to the MCP URL, never on a redirect; `sources.token_refresh_failed`.
- **Revocation:** `sources logout` with the confirmation, `--yes`, and refusal without either; revocation of both tokens with their hints; the message without a revocation endpoint; `deleted: false` without a credential; capabilities becoming `unavailable` with `auth`, and shares kept; a dropped source and a changed URL deleting credentials; `capability remove` deleting the capability's own credential.
- **Per-capability sign-in:** its own instance and snapshot, working while the source is signed out; `capability logout` making it `unavailable` with `auth` without falling back; `own` in `auth`.
- **Running:** headers and `Authorization` on every request; `MCP-Protocol-Version` and `MCP-Session-Id`; JSON and SSE answers, with a `ping` answered and other events dropped; the idle `DELETE`; a session 404 failing the call with `server_exited` and the next call starting a new session; each call outcome in the table, with exactly one request per call recorded by the fixture; cancellation and the deadline posting `notifications/cancelled`; the 2 MiB read and `result_too_large`; a connect failure as `failed` `server_exited`; no proxy used with `HTTPS_PROXY` set; a server that cannot complete `initialize` failing calls with `server_start_failed`.
- **Capabilities and calls:** `capability create` on each mode, `--arg` refused with its text; a full call by policy and by self from the CLI and through `call_capability`, and a raw source call from a trusted host it is open to; `auth` in the capability view and `shares --json`; the three review `Credential:` lines, the lapsed line, and the `shares` text line; the guided share refusing a `login` source without a terminal.
- **Status:** `remote_sources` and `signed_in`, and each new item 14 case with its command.
- **Migration:** a database at version 21 migrating to 22; with `--baseline18`, a version 18 database migrating to 22; a database at version 23 refused.
- **Older peers:** with `--baseline18`, an older caller calling a remote capability, and seeing `auth_required` as a failed call's `error`.

The slice 1 discovery cases that expected the reason `remote` follow this section instead.

`conformance/live_capability_agents.py` gains, separately from deterministic conformance and needing the owner's test accounts (decision 11): Linear by OAuth with DCR and GitHub by a PAT header, each with an owner call and an agent call, then `sources logout` and the next call failing with `auth_required`.

## Owner decisions

Every owner decision, with the options proposed, is also in the [owner decision log](decision-log.md).

Settled with the owner on 2026-10-17.
1. **Operations.** An MCP tool operation keeps the tool's name, as the server gives it. Owners cannot rename operations, and Peerspan-defined operations come with adapters. Resources are read through one `read` operation, and a tool named `read` cannot be selected in slice 1.
2. **Write tools.** They may be selected when creating a capability. The review marks them `(can change things)` and states the credential's reach. A narrower credential is optional, not required; argument rules are later work.
3. **Name uniqueness.** Each capability rule names the host that serves it, so a duplicate name on another host is never authorized by accident. Revised on 2026-10-18: the name is claimed in the person's policy at creation, so claimed names are unique across the person's hosts and `PERSON/CAPABILITY` is never ambiguous for them, even for the person's own machines. Unclaimed copies on several hosts are 409 `ambiguous` (decision 12). Status item 15 reports only a claim lost to a concurrent one.
4. **Confirmation.** Every `share` shows the review and asks for confirmation, not only the first. `--yes` skips it.
5. **Removal.** `capability remove` also withdraws the capability's shares, after confirmation. Every affected policy is signed before the record is deleted.
6. **Sources for the person's own machines.** Trusted machines may call raw sources, each as an implicit capability with every tool and resource, on the serving machine's credentials. The serving machine must also list the caller in its local open list, which starts empty and is never in policy, so the person key alone never opens a machine's sources. Sources are never shared with others.
7. **`--KEY VALUE`** options fill top-level scalar input properties, as in the CLI experience's `--repo acme/api` example. `call`'s own flags win on a clash.
8. **After `unshare`,** running calls finish, queued ones are refused at start, and the output says so.
9. **Agent registration.** `agent register --capability` is renamed `--label`, with `--capability` kept as an alias, to avoid two meanings of "capability". The API field is unchanged.

Settled with the owner on 2026-10-18:

10. **Claims.** Capabilities stay host-local, but their names are claimed in the person's signed policy at creation. The policy is the person's shared record, carried but not controlled by the coordinator. Creating a capability therefore needs the person key, and unshared capability names are visible to coordination.
11. **Concurrent edits are re-applied.** A host whose policy edit loses to a concurrent one signs it again on top of the winner. A withdrawal wins over a concurrent addition. See [Concurrent edits](coordination-contract.md#concurrent-edits).

Settled with the owner on 2026-10-19:

12. **Unsettled names are ambiguous.** When no policy binds a name and the person has it on several hosts, as with copies created before claims or whose claim could not be signed, `PERSON/CAPABILITY` is 409 `ambiguous` with the `HOST_ID/CAPABILITY` candidates, not 404.
13. **Agent capability tools (slice 2).** Attached agents reach capabilities through the shared adapter:
    - **Tools.** Four generic MCP tools, `list_capabilities`, `call_capability {address, operation, input}`, `call_status`, and `call_cancel`, rather than one MCP tool per remote operation. Remote descriptions appear only inside results.
    - **Opt-in per agent.** `attach` asks at a terminal whether the agent may call capabilities shared with the person; `--calls` and `--no-calls` answer without a prompt. The setting is stored on the adapter credential, as `directory` is.
    - **Rate limit.** `max_calls_per_hour` on the adapter credential, default 100, set at `attach`. Each call counts once when first persisted, never on retries, and a call over the limit is refused with 429 `rate_limited` and `retry_after`, as `max_sends_per_hour` is.
    - **The person's own machines.** Self access covers the person's capabilities on their other machines. Raw sources stay CLI-only.
    - **Waiting.** `call_capability` waits up to `wait` seconds, default 30 and at most 60 (now 15 in total, by decision 15), for a final state, then returns the call ID and state. A call that ends later produces a `call_update` event through live delivery, listed in `pending_work`, and `call_status` always answers.
    - **Large results.** At most 64 KiB of a result is returned inline, with `truncated: true` and `result_bytes`; `call_status {call_id, offset}` returns the next part.
    - **Uncertain calls.** An `uncertain` result tells the agent the call may or may not have taken effect, that it must not call again on its own, and that it should check the effect or ask the person. `rejected`, `expired`, and `cancelled` say the call never ran. Nothing is retried automatically.
    - **Out of scope:** approving each call, remote OAuth servers, capabilities inside delegation chains, tools provided by sessions, and streaming results.

Settled with the owner on 2026-10-20:

14. **Slice 2 details.**
    - **Re-attaching.** Reusing a credential with different call settings is refused and names the stored ones; replacing a credential asks again.
    - **Lost responses.** `call_capability` takes an optional `call_id`; repeating it returns the existing call.
    - **Waiting.** Superseded by decision 15.
    - **Visibility.** The four tools are always listed; without opt-in they refuse with `no_calls`.
    - **Across sessions.** Any session of the same agent can follow its calls, and `pending_work` lists unfinished calls from the agent's ended sessions.
    - **Status.** Nothing new this slice.
    - **Later, not in slice 2:** sharing with one agent as `PERSON/AGENT`, converted to the `agent:` form, and `call --from-agent`.

Settled with the owner on 2026-10-23:

15. **Call timing.**
    - **Wait limit.** `call_capability` returns within 15 seconds of being called, everything included, and answers `queued` or `running` when the call has not finished; the result then arrives as a `call_update` event. An agent may ask for less, never more. The limit is one constant in the daemon, changed in a release; the adapter and the tool description do not repeat it. An owner setting for it may be added later.
    - **Results without polling.** The caller's daemon holds a status request open at the serving host (`GET /peer/v1/calls/{id}?wait=10`), and the adapter's call request is held open at the daemon, so a result arrives as soon as it exists instead of on a once-a-second check. A push from the serving host to the caller may be added later; hosts that predate the held request are polled every second as before.

Settled with the owner on 2026-10-25:

16. **Slice 3.** Slice 3 covers four items, each designed in its own proposal. The owner accepted every recommendation in each proposal's "Owner decisions needed" list, so each proposal's recommended design is the design for its item. Each item's contract section, added when it is implemented, follows its proposal.
    - **Remote MCP servers and OAuth** ([proposal](capabilities-slice3-remote-proposal.md), decisions 1–12):
      - remote servers with no sign-in, fixed headers, or OAuth; for a server with no sign-in, the share review says plainly that it asks for no sign-in and serves anyone who can reach it, and that sharing extends that reach to the recipients through this host (added by the owner on 2026-10-25);
      - registration by dynamic client registration or an owner-supplied client ID, with Client ID Metadata Documents once Peerspan has a public domain;
      - the client name `Peerspan (HOST_LABEL)`;
      - no HTTP+SSE;
      - headless sign-in by a loopback listener or a pasted URL;
      - an optional sign-in per capability;
      - tokens stored like captured values;
      - calls never resent after an HTTP error;
      - `headersHelper` servers not shareable;
      - system TLS roots, with proxies ignored;
      - live acceptance against Linear and GitHub;
      - a lapsed sign-in marking the capability unavailable (`auth`).
    - **Approval of each call** ([proposal](capabilities-slice3-approval-proposal.md), decisions 1–12):
      - the requirement on the capability record, on the serving host;
      - approval on the serving host only, at a terminal, with no `--yes`;
      - it covers calls from other people and from the person's own agents;
      - the call stays `queued` on the wire, with an `approval` object;
      - one notice to the source agent's session, without the call's input;
      - each call approved on its own, with no exemptions;
      - the existing 15-minute call deadline;
      - no requirement by default, but the guided share asks when write tools are chosen;
      - at most 20 calls waiting per rule and caller.
    - **Sharing with one agent** ([proposal](capabilities-slice3-agent-shares-proposal.md), decisions 1–15):
      - an exact-name agent lookup route, with the directory as fallback;
      - the existing `agent:HOST_ID/AGENT_ID` principal;
      - a `--with` value with one `/` read as an agent address;
      - shares to one's own agents allowed on other hosts;
      - live labels in `shares`;
      - `call --from-agent` for any registered agent, accepting an ID or name and `--from-session`, invisible to the agent, refused for raw sources;
      - agent-only shares listed in the owner's `discover`;
      - `allow`/`deny` accepting `PERSON/AGENT` in this slice;
      - principals of agents that are gone kept until removed.
    - **Resource bounds and the `gh` source** ([proposal](capabilities-slice3-bounds-sources-proposal.md), decisions 1–17):
      - bounds on the capability, local to the serving host, as generic argument combinations;
      - create refused when an operation cannot carry a bound;
      - bounds shown to recipients;
      - `gh` repository bounds allowing exact names and `OWNER/*`;
      - a call that omits a bound argument refused;
      - `gh` as a built-in MCP server subcommand addressed `builtin/gh`, one source per github.com account;
      - the `gh` token captured at discovery;
      - the ten proposed operations, with no search, and diffs over 1 MB failing;
      - bounds changed by recreating the capability;
      - `gh` 2.81.0 or later, with `gh` telemetry off;
      - an internal registry of built-in sources;
      - a warning at create for bound repositories the token cannot see.
