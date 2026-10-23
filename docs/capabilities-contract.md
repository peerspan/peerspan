# Capabilities contract

Roadmap milestone 10, slice 1: sources, capabilities, sharing, and owner calls; and slice 2: [agent tools](#agent-tools-slice-2).
- **Public surface.** It follows the CLI experience agreed on 2026-10-16 in the system design (`docs-internal`, `docs/cli-spec.md`).
- **Background.** The [remote tools proposal](remote-tools-proposal.md) and [credentials for shared tools](tool-credentials.md) give the background. Their MCP-server sharing model is superseded.
- **What it builds on.** The [task contract](task-contract.md) for call records, retry, and polling; owner access policy in the [coordination contract](coordination-contract.md); and `attach`, self access, and status in the [launch contract](launch-contract.md).

Slice 1 covers MCP sources and owner calls from the CLI. [Slice 2](#agent-tools-slice-2) adds the agent-facing MCP tools. These come later:
- other source types, such as a `gh` adapter;
- optional resource bounds;
- approval of each call;
- remote OAuth servers.

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
| **Source** | Something this host can operate. In slice 1, an MCP server from an attached agent's configuration, identified as `AGENT/SERVER`. |
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

A **source** is an MCP server found in the configuration of an attached agent's harness, which this host can run. It is identified on this host as `AGENT/SERVER`, for example `claude-laptop/github`. Other source types, such as a `gh` adapter Peerspan ships, come in later slices.

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

- **`transport`.** `stdio`, or `remote` for any URL-based server (Claude Code `http` or `sse`, Codex `url`, OpenCode `type: "remote"`). A `remote` server is listed with `shareable: false` and the reason `remote` until slice 3.
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
- **`bounds`** is reserved for optional resource bounds, and is always `{}` in slice 1.
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
- `share` prints `{policy, capability, principal, created}`, where `created` says whether the guided share created the capability.
- `unshare` prints `{policy, capability, principal, removed}`, plus `note` when `removed` is 0.
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
| `GET /peer/v1/calls/{call_id}?wait=N&state=S` | none | The status record, with its `result` once final. Submitter only; anyone else gets 404. It remains available after revocation. With `wait`, an integer from 1 to 10, and `state`, the state the caller last stored, the receiver holds the request until the call's `state` differs from `S` (so `queued` to `running`, or to a final state), or `N` seconds have passed, and then answers. A call already final, a `state` that already differs, or a `wait` of 0 or absent answers at once; `wait` without `state` is held as if `state` were the call's state on arrival. A `wait` outside 0 to 10, or a `state` that is not a call state, is 400. A host that predates `wait` ignores it and answers at once. |
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

The receiver stores the request, the status record, and the result. Seven days after the call becomes final, the request's `input` and the result are deleted. The status record and `input_sha256` remain.

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
  - The daemon computes `shareable` and `reason`. Reasons, in precedence order, are `name`, `remote`, `disabled`, and `missing_env`.
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
- **Owner views are unchanged.** `GET /v1/discover` and `call` ignore `via` entries whose `from_agent` is not null (the remaining policy entries keep `from_agent: null` in `discover` JSON), and omit capabilities left with none, so the owner CLI never cites a rule it cannot use without an origin. There is no `call --from-agent`: an owner tests an agent-only share from that agent.
- **Naming the agent.** `share` and `unshare` take an agent only as `agent:HOST_ID/AGENT_ID` in this slice.
- **Budget.** Agent calls count against `max_calls_per_hour` of the receiver's rule exactly as owner calls do: per rule identity and caller, where the caller is the sender's bound person, or else its host ID.

### Adapter routes

All of them require the adapter's credential and lease, as `/adapter/v1/next` does. Without `calls` on the credential, each answers 403 `{code: "no_calls", error}`. They work before the channel is verified, except `call-updates/next`.

| Adapter request | Behavior |
| --- | --- |
| `GET /adapter/v1/capabilities` | `{capabilities: [ENTRY], unanswered: [{host_id, error}]}`. It queries hosts as `GET /v1/discover` does, in every network of this host, and keeps the entries of kind `capability` that have a `via` entry of kind `self`, or of kind `policy` with `from_agent` null or this session's agent. `ENTRY` is `{address, host_id, capability, operations, resources, state, unavailable}`, with `address` and the other fields as in `discover`. Sorted by address, then host ID. Sources never appear. |
| `POST /adapter/v1/calls` | `{call_id, address, operation, input}` and optional `wait`, an integer of at least 0. Persists and submits one call, then holds the response until the call is final or the wait ends (below), and returns 200 with the call view. |
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

**Results without polling.** For the first 60 seconds after any call, owner or agent, is accepted by its receiver, the daemon asks for its status with `GET /peer/v1/calls/{id}?wait=10&state=S`, where `S` is the state it has stored, one request at a time, each sent as soon as the previous answers, storing each answer's state. A stored final status is never replaced: an answer that arrives after the call became final, for example through a cancel, is discarded, and an answer whose state is earlier than the stored one (`running` stored, `queued` answered) is not stored. Held requests do not use the task polling slots. So a result reaches the daemon as soon as the receiver has it. An answer that comes back in under 1 second with the same non-final state that was sent, as from a host that predates `wait`, is followed by the next request 1 second later, not sooner; an answer with a new state is followed at once. After the 60 seconds it polls without `wait`, backing off from 1 to 60 seconds as for owner calls. The window is kept in memory: after a daemon restart, a call still in it is polled with the usual backoff.

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
  - a receiver that predates `wait` (a version 17 host) asked again no sooner than 1 second after each answer, and the call still returned final;
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

Before each harness's run Bob shares again. The report records each harness's version, the negotiated MCP revision, and the model's tool calls and answers, without claiming model behavior from notification acknowledgements alone.

## Owner decisions

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
