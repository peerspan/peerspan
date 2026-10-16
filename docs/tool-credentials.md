# Credentials for shared tools

Status: decisions settled with the owner on 2026-10-16 and listed under [Decisions](#decisions); everything else is analysis that shapes later work. It accompanies the [remote tools proposal](remote-tools-proposal.md), and it applies equally to any later feature where Peerspan runs something with an owner's credentials: host-launched sessions and isolated runtimes.

## The problem

When an owner shares an MCP server, a peer's call runs with whatever credential that server holds. The shared tool list limits **which** tools a peer may call. It does not limit **what** those tools can touch.

| Server | Shared tool | What it can reach |
| --- | --- | --- |
| GitHub | `create_issue` | Every repository the token can write to |
| Slack | `post_message` | Every channel the token's user is in, including direct messages |
| Postgres | `query` | Every table the role can read or write, from free-form SQL |
| Filesystem | `read_file` | Every directory the server was started with |
| AWS, GCP | any | Everything the profile's IAM policy allows |

## Where shared servers get their credentials

Peerspan discovers the servers an agent already uses from its harness configuration (see the proposal). The daemon runs each shared server itself, as a background service. The harness does not run it. Anything the harness supplies at run time, and that is not written in the configuration, therefore does not come along.

### Remote servers with OAuth

Remote servers are configured as a URL. The harness performs the OAuth login and keeps the token in its own credential storage, so the daemon has the URL but no token.

| Approach | Verdict |
| --- | --- |
| Read the harness's stored token | Rejected. The storage is undocumented and changes between versions, and the token was issued to the harness's OAuth client, so using it impersonates another application. |
| Route the call through the attached session | Not possible. In Claude Code only the model decides when a tool is called. A model-mediated call yields model output, not the tool's result, and makes a prompt the enforcement mechanism. |
| Peerspan as its own OAuth client | **Proposed.** The MCP authorization specification lets a client register itself dynamically. The first time an owner shares a remote server, Peerspan opens a browser once ("Authorize Peerspan to access Linear") and keeps its own token in host state. |

With its own client, Peerspan needs no running session, appears as itself in the provider's audit log, and can be revoked at the provider without logging the owner's agent out. The cost is one browser approval for each remote server, at the moment it is first shared.

### Local stdio servers

| How the secret is configured | Handling |
| --- | --- |
| Literal value, `"GITHUB_TOKEN": "ghp_…"` | The daemon runs as the same user and reads it. It never leaves the host: it is not in listings, activity records, logs, or anything sent to peers. |
| Variable reference, `"GITHUB_TOKEN": "${GITHUB_TOKEN}"` | The harness fills it in from the shell it was launched from. The daemon runs as a service with a different environment, as `install` already found with `SSH_AUTH_SOCK`. See [Decisions](#decisions). |
| Wrapper command, `op run -- server` or `aws-vault exec … -- server` | The command fetches its own secret, which works when the fetch is non-interactive. A fetch that waits for a fingerprint or password would hang a peer's call. Peerspan times out the start and shows the server in `status` as needing the owner. |

**A second copy of the server.** The daemon runs its own copy, separate from the one the harness runs. It starts in the project directory, so relative paths and project configuration resolve the same way. A server holding a local lock, such as a SQLite file, may conflict with the harness's copy.

**Configuration changes.** What is shared follows the harness configuration as it changes. A tool or server added later is never shared automatically.

## Narrowing what a credential can reach

The options below differ in who enforces the limit and in what they cost the owner.

1. **A narrower credential for each share, enforced by the provider (primary).** A share can run its own instance of the server, with its own credential and arguments. Examples:
   - a GitHub fine-grained token limited to `acme/api`;
   - a read-only Postgres role;
   - a filesystem server started on one directory;
   - the GitHub MCP server's own read-only and toolset options.

   The provider or the server enforces the limit, so this works even for free-form tools like SQL. The daemon already runs its own copy, so a copy per share costs little. The cost falls on the owner, who creates the narrower credential. For OAuth servers it can fold into the consent step: the provider's authorization screen can be where repositories, channels, or a team are chosen. How much it allows depends on the provider. GitHub Apps choose repositories per installation, while many OAuth scopes are coarse.

2. **Argument rules, enforced by Peerspan (secondary).** A rule binds argument values, such as `repo` = `acme/api` or `path` under `/srv/docs`, and the receiving host checks each call before running it. This covers any server with structured arguments. It cannot bound free-form arguments such as SQL, shell commands, or GraphQL. It also needs to know which argument names the resource, which differs per tool; GitHub, for example, splits `owner` and `repo`.

3. **Profiles for popular servers (convenience).** Peerspan ships knowledge of common servers, such as GitHub, Slack, Postgres, and the filesystem, so that `peerspan allow bob --tools github --repo acme/api` works without hand-written argument rules. It needs maintenance, and other servers fall back to options 1 and 2.

4. **Approval of each call (fallback).** Safe for anything outside a known scope, but it does not scale and fails while the owner is away.

5. **Isolated runtimes (later).** The server runs in a microVM holding only the credential given to that share. That contains a misbehaving server, but does not narrow the credential, so it complements option 1 rather than replacing it.

**Free-form tools.** Only options 1 and 5 bound free-form tools.

## Default

Sharing a server without a narrower credential shares only the tools the server marks read-only (MCP `readOnlyHint`). `allow` states the reach, for example: "bob can read every repository your GitHub token can." Write tools need either a narrower credential for the share (option 1) or approval of each call (option 4). Argument rules and profiles come later, to make the common cases a single command.

Two caveats:

- **The read-only flag is unverified.** It is a claim made by software the owner installed, and Peerspan cannot check it.
- **Read-only still reaches everything the credential can read.** A peer can read every repository, channel, or table the token covers. For that reason, sharing also asks the owner to confirm the reach (decision 4).

## What this means for later work

- **Host-launched sessions** start an agent with the owner's harness credentials. That is the same reach problem at the scale of a whole agent rather than one tool.
- **Isolated runtimes** need a rule for which credentials enter a runtime. The per-share credential is the natural unit: a runtime receives only the credentials of the shares it serves, and never the owner's environment.
- **Per-agent identity** with agent keys lets a provider or a narrower credential be tied to one agent rather than to the owner.
- **Argument rules** need a place in signed policy. Credentials themselves never go in policy, because policy is distributed through coordination. A rule names a local share profile, and the secret stays on the host.

## Decisions

Settled with the owner on 2026-10-16:

1. **Discovery, not registration.** Shared servers are discovered from the agent's harness configuration at `attach`. There is no separate registration step. Discovered servers start unshared, and sharing happens through `allow`.
2. **Read-only by default.** Without a narrower credential, a share covers read-only tools only, and `allow` states the credential's reach. Write tools need a narrower credential for the share or approval of each call. Argument rules and server profiles are later work.
3. **`${VAR}` secrets are captured at `attach`.** `attach` runs in the owner's shell and records the referenced values in host state, readable only by the owner. A per-user environment file that the daemon reads on each start is available as an alternative, and its values take precedence over captured ones. `status` reports authentication failures from shared servers and suggests running `attach` again, because a captured token can go stale.

4. **The owner confirms the reach.** The owner was concerned that read-only alone may be too permissive. So the first time a server is shared, `allow` states the credential's reach and the owner confirms it once.
5. **Trust is per machine.** An owner's own machines get shared tools only when marked trusted, because machines differ in access, scope, and role ([tools contract](tools-contract.md#authorization)).

## Open questions

- **Peerspan as an OAuth client.** Its client metadata, which providers support dynamic registration, and how per-share consent maps onto each provider's scopes.
- **Argument rules.** How they are written in signed policy without revealing more to the coordinator than necessary.
