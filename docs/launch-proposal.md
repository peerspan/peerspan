# Launch readiness: onboarding, status, and a smaller CLI

Status: implemented; decisions settled with the owner on 2026-10-08 (see [Decisions](#decisions)). This is roadmap milestone 7. It builds on person identity and owner policy (milestone 2b), direct policy propagation (2c), tasks (milestone 6), and the release bundle and [quick start](quick-start.md), which it replaced as the user path in slice 5.

The next setup milestone is implemented in [Guided setup: `peerspan up`](guided-setup-proposal.md), with a [baseline of the previous installed-bundle path](setup-baseline.md). Approved machine linking remains a later milestone.

## Problem

Getting two Claude Code sessions on two machines to talk takes about 15 commands today ([manual agent testing](manual-agent-testing.md)):
- **Services by hand.** Each user starts a coordinator and a daemon in foreground terminals, and copies the coordinator's address and key.
- **Identifiers by hand.** Users copy host IDs, agent IDs, grant IDs, and network IDs between machines and commands.
- **Expiries by hand.** Sessions, adapters, routes, grants, and invites each require an RFC3339 `--expires-at`, so a setup that pauses fails on stale timestamps.
- **Routes by hand.** Agents reach others only through a destinations file naming a host ID, an agent ID, and a grant ID for each target. It does not follow the team as it changes.
- **No overview.** Health is spread across `info`, `network list`, `network members`, `access sync --status`, `adapter connection`, `message list`, and `task list`.
- **A large surface.** The root help lists about 60 command forms, most of them for tests, recovery, or manual key exchange.

## Goals and non-goals

**Goals:**
- One path for a small team of 3 to 10 people. The same commands also cover one person with two machines and two people, with no steps the smaller setup does not need.
- About 5 commands per person from install to a working agent: install, create or join, attach, and, between people, allow.
- One `status` command that answers "is this working, and if not, what do I do next".
- Agents address teammates' agents by name, with no routes file.
- Every existing behavior stays available. The conformance suites keep running unchanged.

**Non-goals:**
- Hosted accounts, billing, or a web console.
- Package-manager distribution (Homebrew, apt). Launch ships the existing release bundle (`scripts/package-release.sh`), plus the user-service installer.
- Windows.
- Changing the access model: administrators still control membership only, and owners control access to their own agents ([access model](access-model.md)).

## The path

Each step names the size it applies to.

```sh
# Everyone: install the binary, then install and start the daemon as a user service.
peerspan install

# The first person (any size): creates the network on the hosted coordinator,
# admits themselves as its first person with the SSH key in ssh-agent, and binds this host.
peerspan network create acme

# The creator, once per teammate (pair, team) or per extra machine (solo):
peerspan invite bob            # prints: peerspan join peerspan-member-invite-v1....

# The teammate, or the creator's second machine:
peerspan join peerspan-member-invite-v1....

# Everyone: attach the current Claude Code project. This registers an agent named "claude" if needed.
peerspan attach claude

# Pair and team: allow others to reach your agents (messages and tasks by default).
peerspan allow bob             # one person
peerspan allow group:eng       # a group the administrators maintain
peerspan allow everyone        # every member of the network

peerspan status
```

- **Solo:** one person with two machines runs `install`, `network create` (or `join`), and `attach` on each. Their own hosts reach each other's agents with no policy (decision 3).
- **Pair:** each person also runs `allow <other>`.
- **Team:** an administrator invites each person once, and may delegate administration (`network delegate-admin`) and maintain groups (`network group set`). Owners `allow` a group or `everyone`.

Agents then reach each other by name: a Claude session asks to message `bob/claude` or delegate a task to it, and the owner can do the same with `peerspan send bob/claude ...` and `peerspan task bob/claude ...`.

## Commands

The CLI ships as `peerspan`. The binary also answers to `peerspan-host`, so existing scripts and suites keep working. The release bundle gains `bin/peerspan` beside `bin/peerspan-host`, and both find the bundled integrations as today. The root help lists only the commands below; `peerspan help advanced` lists everything else, unchanged.

| Command | Behavior |
| --- | --- |
| `install [--state DIR] [--no-start]` / `uninstall` | Installs a user service and starts it (see [Daemon service](#daemon-service)). Idempotent. `uninstall` stops and removes the service, and keeps the state. |
| `network create NAME [--as LABEL] [--coordinator HOST:PORT --coordinator-key KEY]` | Creates the network on the hosted coordinator by default. Admits the SSH key in ssh-agent as the first person, labeled `--as` (default: the login name), and binds this host. Without a usable ssh-agent key it fails with instructions, and `--no-person` stays advanced. |
| `invite LABEL [--expires-in DURATION]` | Issues a member invite (default 7 days) and prints a single `peerspan join ...` line. To add your own second machine, invite your own label. Administration is delegated after joining, with `network delegate-admin`. |
| `join TOKEN [--as LABEL]` | Joins, redeems or reuses the person, and binds this host to it. If the person already exists with this SSH key (a second machine), it binds without redeeming. |
| `attach HARNESS [--name NAME] [--directory DIR]` | Registers the agent if needed (default name: the harness, e.g. `claude`; owner: this host's person), then performs session setup for the current project. Reachable agents come from the directory, so no routes are written. Today's `session setup` options remain available. |
| `allow PRINCIPAL [--agent NAME] [--tasks/--no-tasks] [--files SIZE] [--delegate]` | Adds or extends a policy rule. `PRINCIPAL` is a person label, `group:NAME`, or `everyone` (the existing `network` principal). Without `--agent`, the rule is for `*`, meaning all of the owner's agents (decision 2). It defaults to messages and tasks; files and onward delegation are opt-in (decision 1). |
| `deny PRINCIPAL [--agent NAME]` | Removes the principal from the rule, or removes the rule when it was the last principal. |
| `block` / `unblock PERSON\|HOST` | Today's host-local blocks. |
| `agents` | The directory: which agents you can reach, and who can reach yours (see [Directory and addressing](#directory-and-addressing)). |
| `send TARGET TEXT` / `task TARGET TEXT [--file PATH ...]` | Owner sends and task submissions addressed by `person/agent`. |
| `status [--json]` | See [Status](#status). |

**Network defaulting.** Every command that takes `--network` accepts it as optional when the host belongs to exactly one network. With more than one, the command fails and lists them.

**Expiry defaults** (decision 5). `--expires-at` becomes optional everywhere, and every command that takes it also takes the relative `--expires-in` that `session setup` already accepts:
- invites default to 7 days;
- grants default to 30 days;
- adapter routes default to their session's expiry.

A session's adapter credential is issued for 24 hours, and the daemon extends it by 24 hours whenever the adapter has been connected within the current window. An explicit `--expires-at` or `--expires-in` is fixed and never extended. An expired session needs `attach` again, which reuses the agent.

This reverses the quick start's current rule that expiry is never silently renewed. Renewal stays bounded: it needs a connected adapter, the first extension, and then at most one per hour, is recorded as an `adapter.renewed` activity, `status` shows each session's current expiry, and revoking the adapter or detaching the session ends it at once.

## Daemon service

`peerspan install` writes and starts:
- **Linux:** a systemd user unit at `~/.config/systemd/user/peerspan.service` running `peerspan run`, restarting on failure, and enabled for the user's login. It does not enable lingering; `status` says how if the user wants the daemon running while logged out.
- **macOS:** a launchd agent at `~/Library/LaunchAgents/dev.peerspan.host.plist` with `RunAtLoad` and `KeepAlive`.

The service records the state directory, the peer listen address (default `0.0.0.0:7401`, chosen free if taken), and `--person-agent` from the installing shell's `SSH_AUTH_SOCK`. On Linux that socket changes between logins, so policy renewal can fail later. `status` reports this and `peerspan install` refreshes it. `run` stays available for foreground use. This fills the gap the quick start notes, that Peerspan has no per-user service installer.

## Hosted coordinator

The CLI carries a default coordinator address and public key, used whenever `network create` has no `--coordinator`. Joining always uses the coordinator named in the invite, so self-hosted networks need nothing new. The hosted coordinator is the ordinary `peerspan-coord`, and sees only membership, the map, and encrypted relay packets ([coordination contract](coordination-contract.md)).

Because it accepts networks from anyone, `peerspan-coord` gains limits, each a `run` flag with a default (decision 4):
- 50 members per network;
- 20 network creations per source IP per day;
- 10 GB of relayed traffic per network per calendar month.

Requests over a limit return 429 with the limit's name, and hosts surface it in `last_sync_error` and `status`. A host whose relay is cut off keeps its direct paths.

Operating the hosted instance (domain, key custody, monitoring) is outside this repository. Until it exists, builds take the default address and key from build-time variables, and a build without them requires `--coordinator`.

## Self access

A host bound to person P authorizes a request to one of its agents when the requester host is a current, unrevoked member also bound to P (decision 3). This covers every action:
- `message.append`;
- `task.submit` and `task.delegate`;
- artifacts up to 1,073,741,824 bytes.

It needs no policy or grant, blocks do not apply, and the authorization is recorded as `{kind: "self"}`. It is checked at submission, at handoff, and at acceptance, like any authorization, so unbinding a host ends it.

## Directory and addressing

The map already carries every person's newest policy to every member. The directory adds which hosts hold which agents, without publishing agent lists to the coordinator.

- **Peer route.** `GET /peer/v1/agents` returns the receiver's local agents that the authenticated caller may reach right now, through self access, a policy, or a grant: `[{name, agent_id, actions, max_message_bytes, max_artifact_bytes}]`. An agent the caller may not reach is never listed.
- **Discovery.** A host queries each member host bound to a person whose policy covers it, or to its own person. It refreshes every 5 minutes and when the map or a policy changes, and caches the result with its time.
- **Names.** An address is `person_label/agent_name`, or `person_label/agent_name@host_label` when that person has the name on more than one host. The short form then fails with a list of the qualified ones. Labels resolve through the current map.
- **Agents.** The adapter gains MCP `list_agents`, and `send_message` and `delegate_task` accept a `to` address in place of a route name. The host resolves the address, picks the cited authorization the target listed, and sends as today. Explicit routes keep working and take precedence by name.
- **Owner.** `peerspan agents` lists reachable agents with their actions and whether their host was reachable on the last refresh, then which principals can reach this person's agents according to its own policy.

Authorization is unchanged: the receiver still checks every request, so a stale directory entry yields the usual 403 or 404.

Slice 4 of the [launch contract](launch-contract.md) settles the details: names are unique per person, so the `@host` qualifier is replaced by a `HOST_ID/AGENT` form for rare duplicates; the peer route is per network; every member host is queried; MCP keeps its `send` tool and gains `to`; and only sessions created by `attach` may send by address, capped per hour.

## Status

`peerspan status` prints one screen, in order:
1. **Daemon:** running or not, service installed, version, host ID.
2. **Identity:** the bound person and label; whether ssh-agent holds that person's key, and whether the daemon can reach it for renewal.
3. **Networks:** for each, the coordinator connection and last sync time or error, member count, and how many peers are direct, relayed, or unreachable.
4. **Access:** this person's policy version and its expiry, pending sibling deliveries, and blocks.
5. **Agents:** each local agent, its attached sessions, and whether their adapters are connected.
6. **Attention:** recent problems, each with the command that addresses it. Examples: sends with an `unknown` outcome, failed tasks, a coordinator limit, a policy expiring within 7 days, an artifact quota above 90%.

It exits 0 when nothing needs attention, 1 when something does, and 2 when the daemon is not running. `--json` prints the same as one object. `GET /v1/status` serves it from the daemon, and the CLI adds the service and ssh-agent checks.

## Policy format change

Rules accept the agent name `*`, meaning every agent of the owner on any of their hosts. The signed statement is unchanged apart from allowing `*` where an agent name goes. A receiver applies the rule for the agent's name if one exists, and the `*` rule otherwise; the two are never combined. Older binaries accept `*` as an ordinary agent name that matches no agent, so they apply less access, never more; `*` becomes a reserved agent name (corrected in slice 3 of the [launch contract](launch-contract.md)). A conformance case covers a policy with `*`.

## Slices

Each slice is implemented in Go and Rust with shared conformance, as in earlier milestones.
1. **CLI shape:** the `peerspan` name, network defaulting, expiry defaults and session renewal, `status` and `GET /v1/status`, and `help advanced`.
2. **Service and coordinator:** `install`/`uninstall`, the hosted default from build variables, and coordinator limits with 429.
3. **Team onboarding:** `network create NAME`, `invite`, `join`, `allow`/`deny` with `everyone` and `*`, and self access.
4. **Directory and addressing:** `GET /peer/v1/agents`, discovery, `peerspan agents`, `send`/`task` by address, MCP `list_agents` and `to`, and `attach` without routes.
5. **Acceptance:** a scripted run from empty machines for solo, pair, and three-person setups, counting commands, plus one live run with three Claude Code sessions, all from installed release bundles. The [quick start](quick-start.md) is rewritten around the new path, and the manual testing guide moves to the advanced path.

## Decisions

Settled with the owner on 2026-10-08:
- **Audience:** onboarding targets a small team (3 to 10), and the same commands cover solo and pair use with nothing extra.
- **Coordinator:** a hosted default built into the CLI, overridable for self-hosting.
- **Daemon:** installed as a user service; foreground `run` stays.
- **CLI surface:** low-level commands stay, hidden behind `help advanced`.
- **Addressing:** a directory derived from authorization, with `person/agent` names; explicit routes stay as an advanced option.
- **Expiries** (5): optional everywhere, with defaults; sessions renew while live, reversing the quick start's no-renewal rule.
- **Name:** `peerspan`, with `peerspan-host` as an alias.
- **Agents:** `attach` registers the agent if needed.
- **Allow default** (1): messages and tasks; files and delegation opt-in.
- **Agent scope** (2): `allow` without `--agent` covers all of the owner's agents through `*`.
- **Self access** (3): everything, up to 1 GiB of artifacts, with no policy.
- **Hosted limits** (4): modest caps as configurable `peerspan-coord` flags, returning 429.

Settled with the owner on 2026-10-09, for slice 4:
- **Agent names:** unique per person across their hosts; `attach` picks a suffixed name when the default is taken.
- **Session reach:** `attach` sessions may reach any agent in the directory, at most 100 sends and delegations per hour by default.
- **Presence:** the directory shows whether an agent has a connected session.

## Open

- Who operates the hosted coordinator, under which domain, and how its key is held.
