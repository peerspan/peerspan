# Launch contract

Roadmap milestone 7. The design and its settled decisions are in the [launch proposal](launch-proposal.md). This contract grows one section per slice.

## Slice 1: CLI shape

### Name

The CLI is one binary that answers to `capsule` and `capsule-host`. Help and diagnostics name it after the base name it was invoked as, and behave identically otherwise. Builds keep producing `capsule-host`. The release bundle adds `bin/capsule` as a relative symbolic link to `capsule-host`, and both find the bundled integrations.

### Root help

The root help lists only these commands, in this order:
1. `status`;
2. `install` (added in slice 2);
3. `run`;
4. `network create`, `join`, `invite`, `list`, and `members`;
5. `access allow`, `deny`, and `show`;
6. `session setup`, `start`, and `doctor`;
7. `message send` and `task submit`.

It ends with one line pointing to `help advanced`. `help advanced` (and `--help-advanced` before any command) prints the full command list as the root help does today. Every hidden command still runs, and its own `--help` still works. Help wording is not a shared contract; the set of commands listed is, and `conformance/launch_cli.py` checks it. It parses a `Commands:` header followed by one line per command: two spaces, the command path, at least two spaces, and a description. Bare invocation, `--help`, and `help` print identical root help, and root help invoked as `capsule` never mentions `capsule-host`.

### Network defaulting

These commands accept their network as optional:
- **Flag:** every `--network ID`, except `network revoke`, `network rotate-root`, and `network remove-admin`;
- **Positional:** `network members`, `sync`, `persons`, and `groups`.

`network leave` and `network rotate-root` always need it explicitly.

When the network is omitted, the CLI reads `GET /v1/networks`:
- with exactly one network, it uses that network;
- with none, it fails with `not a member of any network`;
- with more than one, it fails and lists each `id` and `name`.

It never guesses by name.

### Expiry defaults

Every command that takes `--expires-at TIME` also takes `--expires-in DURATION`, with the syntax `session setup` already uses: whole minutes or hours from `1m` to `720h`. The two are mutually exclusive. With neither, these defaults apply:

| Command | Default |
| --- | --- |
| `grant create` | 30 days |
| `network invite`, `network invite-person` | 7 days |
| `adapter create`, `session setup` | renewable (below) |
| `adapter route add`, routes in a `session setup` routes file | follows the credential (below) |
| `message send --deadline` | 1 hour, the same as `task submit` |

The CLI resolves fixed defaults to an RFC3339 `expires_at` before calling the daemon, so those APIs are unchanged. Explicit values are never extended.

### Renewable credentials

- **API.** `POST /v1/adapters` and `POST /v1/adapters/setup` accept a request without `expires_at`. The credential is then **renewable**, with `expires_at` 24 hours from creation. Credential records gain `renewable` (boolean, always shown); existing records read as `false`.
- **Routes.** A route created without `expires_at`, by `POST /v1/adapter-routes` or within setup, takes its credential's `expires_at` and gains `follows_credential: true`. Route records always show `follows_credential`, and the create request accepts it: `true` means the same as omitting `expires_at`, and `false` changes nothing. Following is allowed only when the credential is renewable; otherwise it is a 400. In a setup with an explicit expiry, routes without one take the setup's fixed expiry, as before.
- **Renewal.** When a renewable credential, neither revoked nor expired, connects or renews its lease through `/adapter/v1/connect`, the daemon sets its `expires_at` to 24 hours from now. It does this only if that moves the expiry forward by at least 60 seconds. In the same transaction, every unrevoked route with `follows_credential` takes the new `expires_at`.
- **Activity.** The first renewal of a credential, and then at most one per hour, records `adapter.renewed` with the adapter ID as subject.
- **Expiry.** An expired renewable credential stays expired, exactly as a fixed one does. It is never renewed after expiry, including by recovery after a daemon restart.

No schema change is needed: these are fields of the JSON records.

### Status

`GET /v1/status` returns one object:

```json
{
  "host_id": "host_…",
  "version": "…",
  "networks": [{
    "id": "net_…", "name": "…",
    "coordinator": "HOST:PORT",
    "last_sync_at": "RFC3339 or null", "last_sync_error": "text or null",
    "members": 3,
    "person": {"id": "person_…", "label": "alice"},
    "policy": {"version": 4, "valid_until": "RFC3339"},
    "policy_deliveries_pending": 0
  }],
  "blocks": 0,
  "agents": [{
    "id": "agent_…", "name": "claude",
    "sessions": [{"id": "session_…", "integration": "claude-code", "adapter_id": "adapter_… or null",
                  "connection": "ready", "expires_at": "RFC3339 or null", "renewable": true}]
  }],
  "artifacts": {"quota": 10737418240, "stored_bytes": 0, "pending_bytes": 0},
  "attention": [{"kind": "…", "subject": "…", "detail": "…", "command": "…"}]
}
```

**Fields:**
- **`networks`:** sorted by ID.
  - `person` is this host's bound person, or null.
  - `policy` is that person's stored policy, or null.
  - `members` counts current, unrevoked members, this host included.
- **`agents`:** sorted by name, then ID. `sessions`, sorted by ID, lists only attached sessions and sessions with an unrevoked, unexpired credential. `connection` uses the values of `adapter connection`: `registered`, `ready`, `offline`, `detached`, `revoked`, or `expired`. A session without a credential shows null `adapter_id`, `connection`, and `expires_at`, and `renewable: false`.
- **`version`:** the implementation's version string. Its wording is not shared.

**Attention items**, in this order, each with its subject:
1. `coordination_error`: a network with a non-null `last_sync_error`. Subject: the network ID; command: `capsule network sync ID`.
2. `policy_expired`: this person's policy has passed `valid_until`. Command: `capsule access renew --network ID`.
3. `policy_expiring`: this person's policy has less than a quarter of its validity window left. The daemon renews it at that point, so this means renewal is failing, for example because the daemon cannot reach the person's ssh-agent. Command: `capsule access renew --network ID`.
4. `policy_delivery_failing`: a pending policy delivery that has failed at least once. Subject: `NETWORK/TARGET`; command: `capsule access sync --network ID`.
5. `credential_expiring`: an unrevoked, non-renewable credential with an attached session, expiring within 24 hours and not yet expired. Subject: the adapter ID; command: `capsule session setup --agent ID --harness INTEGRATION`.
6. `tasks_failed`: outbound tasks whose latest `task.updated` activity in the last 24 hours left them `failed`, `rejected`, or `expired`, including submissions the receiver refused. One item; subject: the count as a decimal string; command: `capsule task list`.
7. `artifact_quota`: stored plus pending bytes above 90% of the quota. Subject: `artifacts`; command: `capsule artifact prune`.

Within one kind, items are sorted by subject. `detail` is free text. `policy_expiring` excludes a policy that has already expired, which is `policy_expired`.

**`capsule status`** prints a readable summary; its layout is not shared. `--json` prints the daemon's object. Exit codes:
- 0 when `attention` is empty;
- 1 when it is not;
- 2 when the daemon cannot be reached. With `--json`, it then prints `{"daemon": "not running", "state": DIR}`.

### Verification

`conformance/launch_cli.py` runs across all Go/Rust CLI and daemon pairings, using the Go coordinator for network cases. It covers:
- **Name:** `capsule` and `capsule-host` behave alike, and the bundle link works through `installed_bundle.py`.
- **Help:** the root help's command set, and `help advanced` listing all of them.
- **Network defaulting:** with zero, one, and two networks, and the explicit-only commands.
- **Expiries:** `--expires-in` everywhere, each default, and mutual exclusion with `--expires-at`.
- **Renewable credentials:**
  - a credential's expiry advancing after a lease renewal more than 60 seconds later;
  - a following route moving with it;
  - `adapter.renewed` recorded once;
  - an explicit expiry never moving;
  - `follows_credential` refused on a fixed credential.
- **Status:** its shape, and each attention kind it can produce deterministically:
  - `coordination_error`, with the coordinator stopped;
  - `policy_expiring`, with a crafted policy near its end and no ssh-agent for the daemon;
  - `policy_delivery_failing`, with a sibling down;
  - `credential_expiring`;
  - `tasks_failed`;
  - `artifact_quota`, with a small `--artifact-quota`.
- **Exit codes:** 0, 1, and 2.

## Slice 2: service and coordinator

Decided with the owner on 2026-10-08:
- builds take the hosted coordinator from build-time variables until the hosted instance exists;
- `install` always enables systemd lingering on Linux;
- the installed daemon listens for peers on UDP port 7401 on all interfaces by default.

### Install

`capsule install [--state DIR] [--peer-listen IP:PORT] [--no-start]` installs the daemon as a user service and, unless `--no-start` is given, starts it and waits up to 10 seconds for the admin socket. It prints `{service, unit, state, peer_listen, linger, started}`.

- **Linux.** It writes `$XDG_CONFIG_HOME/systemd/user/capsule.service` (default `~/.config/systemd/user`), with:
  - `ExecStart=` exactly the binary's resolved real path, `--state DIR`, `run`, and `--peer-listen ADDR`;
  - `Restart=on-failure` and `WantedBy=default.target`;
  - `Environment=SSH_AUTH_SOCK=` the installing shell's value, when set.

  It then runs `systemctl --user daemon-reload`, then `systemctl --user enable --now capsule.service`, or `enable` alone with `--no-start`. Last, it runs `loginctl enable-linger` for the current user. A failed `loginctl` is not an error: `linger` is reported as `false`.
- **macOS.** It writes `~/Library/LaunchAgents/dev.capsule.host.plist` with `Label` `dev.capsule.host`, the same program arguments, `RunAtLoad`, and `KeepAlive`, then runs `launchctl bootstrap gui/UID PATH`. `linger` is always `null`.
- **Elsewhere,** or without `systemctl` or `launchctl` on `PATH`, it fails with `no supported service manager` and changes nothing.

**Defaults:**
- `--state` is the CLI's usual default.
- `--peer-listen` is the address in an existing unit. Otherwise it is `0.0.0.0:7401`, or the first port from 7401 to 7499 that binds on UDP. If none binds, the install fails.

**Behavior:**
- Install is idempotent. With an identical unit it only ensures the service is enabled and running. With a changed unit it rewrites the unit and restarts the service.
- It fails without changes when a daemon is already running on that state directory outside the service. It checks this only when the admin socket answers, by asking the manager whether the service is active.
- The CLI runs service tools found on `PATH`. Tests substitute recording stubs. The manager is chosen by which tool is present, `systemctl` first, then `launchctl`, rather than by OS name.
- **Output.** In the printed object, `service` is `systemd` or `launchd`, and `unit` is the unit file's path. `started` is true only if the admin socket answered within 10 seconds, so it is always false with `--no-start`. A timeout is not an error.
- **Sequences on Linux:**
  - With an identical unit, it runs `enable --now` (or `enable`), then `loginctl enable-linger`.
  - With a new or changed unit, it runs `daemon-reload` and `enable --now`, then `restart` if the unit changed, then `loginctl enable-linger`.
  - `--no-start` never starts or restarts the service.
- **Sequences on macOS:**
  - With a changed plist, it runs `bootout gui/UID/dev.capsule.host`, then `bootstrap`.
  - `--no-start` writes the plist without calling `launchctl`.
  - The plist carries no `SSH_AUTH_SOCK`, since launchd provides it.

`capsule uninstall` stops and disables the service:
- **Linux:** `systemctl --user disable --now capsule.service`;
- **macOS:** `launchctl bootout gui/UID/dev.capsule.host`.

It then removes the unit and prints `{service, unit, removed}`. It keeps the state directory and lingering. Uninstalling with nothing installed succeeds with `removed: false`. A failing `launchctl bootout` is ignored, but a failing `systemctl disable` is an error. With no manager on `PATH`, uninstall fails with `no supported service manager`.

### Status additions

- **`service`.** The CLI adds `service` to `capsule status --json`: `{manager, unit, installed, active, linger}`.
  - `manager` is `systemd`, `launchd`, or null.
  - `active` comes from `systemctl --user is-active` or `launchctl print`.
  - `linger` comes from `loginctl show-user USER --property=Linger`, and is null on macOS.
  - It is present even when the daemon is not running, in which case there are no attention items.
- **New attention items.** These follow the existing seven:
  8. `service_not_installed`: no unit, while the daemon runs outside a service. Added by the CLI; subject `service`; command `capsule install`.
  9. `linger_disabled`: Linux, unit installed, `linger` false. Added by the CLI; subject `service`; command `loginctl enable-linger`.
  10. `person_agent_unreachable`: this host is bound to a person who has a stored policy, and the daemon's `--person-agent` socket is unset, cannot be connected, or does not hold that person's key. Added by the daemon; subject: the network ID; command `capsule install`, which refreshes `SSH_AUTH_SOCK`.
  11. `coordinator_limit`: the network's coordinator reports a limit reached (below). Added by the daemon; subject `NETWORK/LIMIT`; command none (empty string).

### Hosted coordinator default

`network create` without `--coordinator` and `--coordinator-key` uses the build's default coordinator. Builds set it at compile time:
- **Go:** `-ldflags "-X …/internal/host.DefaultCoordinator=HOST:PORT -X …/internal/host.DefaultCoordinatorKey=KEY"`;
- **Rust:** the `CAPSULE_COORDINATOR` and `CAPSULE_COORDINATOR_KEY` environment variables at build time;
- **Release script:** `scripts/package-release.sh` passes the same two variables to either build.

A build without both values fails `network create` without the flags, with `this build has no default coordinator; pass --coordinator and --coordinator-key`. Giving only one of the two flags is a 400. `info` gains `default_coordinator`: `{address, public_key}`, or null.

### Coordinator limits

`capsule-coord run` gains three flags; 0 disables a limit.

| Flag | Default | Limit |
| --- | --- | --- |
| `--max-members N` | 50 | current, unrevoked member hosts per network |
| `--max-networks-per-ip N` | 20 | network registrations per source address in any 24 hours |
| `--relay-bytes-per-month BYTES` | 10,000,000,000 | relayed datagram bytes per network per UTC calendar month |

**Over a limit**, a request returns 429 with `{code: "limit", error, limit}`, where `limit` is `members`, `networks_per_ip`, or `relay_bytes`.

**Members.** A join (`POST …/members`) of a new host to a network already at `--max-members` returns 429. Retrying a join that already succeeded still returns 200. Admissions and persons are not counted.

**Registrations.**
- `POST /coord/v1/networks` counts only new networks. The idempotent 200 for a network that already exists is not counted.
- The source address is the TCP peer address: IPv4 in full, IPv6 by its /64.
- Counts persist across restarts.

**Relay bytes.**
- Each forwarded send frame's datagram length (only frames actually forwarded) is charged to the lowest-ID network the two hosts share, the same network hosts use to choose the relay.
- Once that network's monthly total reaches the limit, the coordinator drops its frames and answers the sender with `unreachable`, at most once per second per destination.
- Counters persist at least every 60 seconds and on orderly shutdown, so a crash may undercount by up to a minute of traffic.

**Usage.** `GET /coord/v1/networks/{network_id}/usage` is for members only, and returns 403 otherwise, including for an unknown network. It returns `{members, max_members, relay_bytes, max_relay_bytes, month}`, with `month` as `YYYY-MM` and 0 for a disabled limit.

**Host side.**
- After each successful sync, hosts fetch usage. They treat 404 as an older coordinator without limits.
- A host reports `coordinator_limit` for `members` when `members` ≥ `max_members`, and for `relay_bytes` when `relay_bytes` ≥ `max_relay_bytes`, for nonzero maxima.
- A 429 from create, join, or sync is reported as `last_sync_error` with the limit's name, and as `coordinator_limit`. The host remembers it until the next successful sync or join. A join refused with 429 stores no network, so it has no `last_sync_error`. The local API returns 429 `{code: "limit", limit}`, and status reports `coordinator_limit` under the network ID from the token. The default coordinator is applied by the daemon, so in a mixed pairing the daemon's build decides it.

**Coordinator schema.** Version 5 adds:

```sql
CREATE TABLE registrations (source TEXT NOT NULL, network_id TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE relay_usage (network_id TEXT NOT NULL, month TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(network_id, month));
PRAGMA user_version = 5;
```

### Verification

`conformance/launch_service.py` is written from this contract by an author independent of both implementations. It runs across all Go/Rust CLI and daemon pairings with the Go coordinator. Service tools are recording stubs on `PATH` with `HOME` and `XDG_CONFIG_HOME` redirected; a real `systemd --user` run is attempted only when available. It covers:
- **Install on Linux:**
  - unit contents;
  - the tool calls in order;
  - the default port, and the next free port when 7401 is taken;
  - `--peer-listen` kept from an existing unit;
  - idempotence, and a changed unit restarting;
  - a failing `loginctl` reported as `linger: false`;
  - refusal while a foreground daemon runs;
  - `no supported service manager`.
- **Install on macOS,** with the plist and the `launchctl` calls, selected by stubbing `launchctl` without `systemctl`.
- **Uninstall,** with and without a unit.
- **`status`:** `service`, and attention items 8 to 11.
- **Default coordinator:**
  - a build with and without default values;
  - one flag only;
  - `info.default_coordinator`.

  The suite builds Go and Rust test binaries with the variables set, using a coordinator it starts.
- **Limits:**
  - the member cap, including the idempotent rejoin;
  - the registration cap per source and across a coordinator restart;
  - the relay cap: a network over a small `--relay-bytes-per-month`, its frames dropped, `unreachable` sent, and the usage endpoint;
  - the 429 body;
  - each limit disabled with 0;
  - migration from version 4 to 5;
  - a host's `coordinator_limit` and `last_sync_error`.

## Slice 3: team onboarding

Decided with the owner on 2026-10-09:
- `network create` and `join` generate a person key when none is found (revised the same day from failing without one);
- `allow` sets a principal's access for an agent scope, rather than adding to it;
- self access works while out of sync with coordination;
- `deny` without `--agent` removes the principal from every rule.

### Commands

| Command | Behavior |
| --- | --- |
| `network create NAME [--as LABEL]` | `NAME` may be given positionally; `--name` still works, and giving both is an error. `--as` is the person and member label; it defaults to the login name (the user name of the effective user ID, else `$USER`), and `--member` remains as an alias. A person key is always used (below). Otherwise this is today's create, including admitting and binding the creator. |
| `invite LABEL [--expires-in D \| --expires-at T] [--network ID]` | Issues a member invite, like `network invite --member LABEL` with the slice 1 default of 7 days. Prints `{network_id, member, invite_expires_at, token, join}`, where `join` is the string `capsule join TOKEN`. |
| `join TOKEN` | Same as `network join --token TOKEN`, always with a person key (below). A person already admitted with this key (for example, on a second machine) is bound without a new admission, as today. |
| `allow PRINCIPAL [--agent NAME] [--no-tasks] [--files SIZE] [--delegate] [--network ID]` | Sets PRINCIPAL's access (below) and signs the next policy version. |
| `deny PRINCIPAL [--agent NAME] [--network ID]` | Removes PRINCIPAL (below) and signs the next policy version. |
| `block TARGET` / `unblock TARGET` | `TARGET` is a host ID (`host_…`), or else a person ID or label. Otherwise the same as `access block`/`unblock`. |

**Root help** now lists, in order:
1. `status` and `install`;
2. `run`;
3. `network create`, `join`, and `invite`;
4. `allow`, `deny`, `block`, and `unblock`;
5. `network list` and `network members`;
6. `access show`;
7. `session setup`, `start`, and `doctor`;
8. `message send` and `task submit`.

`network join`, `network invite`, `access allow`, and `access deny` move to `help advanced`, unchanged.

**Person keys.** `network create`, `network join`, and `join` choose a person key in this order:
1. `--person-key PATH`, as today; an unusable one is an error before any request;
2. the **generated key**, if `$XDG_CONFIG_HOME/capsule/person_ed25519` exists (default `~/.config/capsule`);
3. the only `ssh-ed25519` identity in `ssh-agent`;
4. otherwise, a newly generated key.

Every other command that signs as a person, such as `allow`, `deny`, `invite`, `network bind`, and `access renew`, uses steps 1 to 3 in the same order and never generates a key. With several `ssh-ed25519` identities in `ssh-agent` and no generated key, the command fails before any request. The error lists the keys' comments and fingerprints and says to pass `--person-key`. An existing generated key wins over an agent key, so a person's identity never changes because a key was later added to the agent. `--no-person` keeps today's host-only behavior and generates nothing.

**The generated key** is an unencrypted OpenSSH `ssh-ed25519` private key at `person_ed25519`, mode 0600, with its public key beside it at `person_ed25519.pub`, mode 0644, in a 0700 directory. Its comment is `capsule LABEL@HOSTNAME`. It is created only when step 4 is reached and the command is about to succeed, after argument validation, so a refused command leaves no key behind. It is never overwritten. Signatures use the same `SSHSIG` format as any person key, so nothing on the wire or in other hosts changes.

**Command output.** The response's `person` gains `key`: `{source, public_key, path}`, where `public_key` uses the same encoding as `person_public_key` in signed statements. With `--no-person`, `person` is as before slice 3.
- `source` is `option`, `generated`, `agent`, or `new`.
- `path` is the file, or null for an agent key.
- When `source` is `new`, `next` also says to back up the key, and to copy it to the user's other machines to use the same identity there.

**Second machines.** A second machine with neither the same key in its agent nor a copy of the generated key creates a different person. Its join's person part then reports the member label as taken, as it does today, and the host joins without a person. `next` says to copy `person_ed25519` from the first machine and run `network bind`.

**Renewal with a generated key.**
- `run` gains `--person-key-file PATH`. By default it is the generated key's path. The daemon reads the file whenever it renews and the file exists, so a key generated after the daemon started also works.
- The daemon renews a policy with that file when the file holds the bound person's key and the `--person-agent` socket does not.
- This is the only person key a daemon reads, and it reads it from the user's own configuration, never from its state directory. Keys held in `ssh-agent` are still never read by a daemon.
- Status item 10 (`person_agent_unreachable`) is not raised when this file holds the bound person's key.
- `install` passes no `--person-key-file`, relying on the default; the unit's `HOME` is the installing user's.

### Principals and sizes

`PRINCIPAL` in `allow`, `deny`, and `block` is one of:
- `everyone`, meaning the `network` principal;
- `network`;
- `group:NAME`;
- `person:PERSON`, or a bare `PERSON`, where PERSON is a person ID or label, resolved as `access allow` does today;
- `agent:HOST/AGENT`, unchanged.

A label matching no current person, or more than one, is an error, as is a person ID that is not a current person. `invite`, `allow`, `deny`, `block`, and `unblock` accept `--person-key PATH` like other signing commands.

`SIZE` is a byte count with an optional suffix: `K`, `M`, or `G`, meaning powers of 1024. It must be from 1 to 1,073,741,824 bytes.

### Policy rules

**The `*` agent.**
- A rule's agent may be `*`, meaning every agent of the owner on any of their hosts.
- For an agent named N, a receiver applies the rules naming N if there are any, and otherwise the `*` rules.
- `*` is reserved: `agent register` refuses it with 400.
- Older binaries read `*` as an ordinary name that matches no agent, so they apply less access, never more.

**Several rules per agent.** A policy may hold several rules with the same agent name. A request is authorized if any applicable rule allows it, as both implementations already evaluate. The limit is still 64 rules.

**`allow`.**
- The rule's **settings** are:
  - actions: `message.append`, then `task.submit` unless `--no-tasks` is given, and `task.delegate` with `--delegate` (which requires tasks);
  - `max_message_bytes` 65,536;
  - `max_artifact_bytes` from `--files`, default 0 (`--files` also requires tasks);
  - `allow_disconnected` false.
- The **scope** is `--agent NAME`, default `*`.
- **Starting from the current policy, it:**
  1. removes PRINCIPAL from every rule of that scope;
  2. adds it to the first remaining rule of that scope with identical settings, or else appends a new rule;
  3. drops rules left without principals.
- It then signs version + 1, valid for 7 days, and submits it.
- Allowing a principal that already has exactly these settings still signs a new version.
- It prints `{policy, principal, agent, actions, max_artifact_bytes}`, where `policy` is the signed policy object and `principal` is the resolved principal, for example `person:person_…` or `network`.

**`deny`.**
- It removes PRINCIPAL from every rule naming the given `--agent` (with `*` naming only the `*` rules), or from every rule without `--agent`. It drops empty rules and signs the next version.
- It prints `{policy, removed}`, where `removed` counts the rules the principal was removed from.
- When `removed` is 0, it also prints `note`. The note explains that access through a group or `everyone` is unaffected, and that `block` stops a person at once. It still exits 0 and signs no new version.

`access allow` and `access deny` behave as before for agents with at most one rule. When an agent has several rules, `access allow --agent N` replaces them all with one rule.

### Self access

**Rule.** A host bound to person P authorizes a request to one of its own agents when both hold in a network they share:
- the receiver is bound to P;
- the sender is a current, unrevoked member also bound to P.

It needs no grant or policy.

**Scope.** Self access allows every action, with these effective bounds:
- `max_message_bytes` 65,536;
- `max_artifact_bytes` 1,073,741,824;
- `delegable` true;
- `allow_disconnected` true.

Blocks do not apply.

**Rechecks.** It is checked at submission, at handoff, and at acceptance, like any authorization. Wherever a policy can authorize a chain's originator, self access can too, as described in the delegation chain contract.

**Wire.** Peer message and task requests gain a third form of authorization: exactly one of `grant_id`, `policy`, or `self`, where `self` is `{person_id}`, the sender's bound person. In a request with a delegation chain of two or more links, the authorization is the originator's, as for policies: `person_id` is the originator host's bound person, and the check applies to the originator host instead of the sender. The receiver returns 403 when either host is not bound to that person in a shared network. Older receivers reject `self` with 400.

**What senders cite.** Owner sends, owner task submissions, adapter routes, and delegations without `--grant` cite `self` when the target host is bound to this host's person in a shared network. Otherwise they cite the target owner's policy, as before. A route created this way records `authorization: "self"`. Route records always show `authorization`, which is `grant`, `policy`, or `self`, decided when the route is created. Each send through a route without a grant re-decides between `self` and policy from current bindings. `POST /v1/adapter-routes` accepts and ignores `authorization` in its request, as it does `follows_credential`. In `allow`, the rule settings compare actions as a set. The "first remaining rule" may be one that step 1 emptied, so re-allowing keeps a rule's position. `deny` keeps the current policy's validity duration.

### Verification

`conformance/launch_onboarding.py` is written from this contract by an author independent of both implementations. It runs across all Go/Rust CLI and daemon pairings, with the Go coordinator and OpenSSH. It covers:
- **Create:** `network create NAME` with `--as` and its default, positional and `--name` forms, and both together refused.
- **Person keys:**
  - generation with no agent and with an empty agent: file modes, comment, and `key.source` `new`;
  - reuse of the generated key on the next command, `generated`, even after an agent key appears;
  - the single agent key (`agent`) and `--person-key` (`option`);
  - two agent keys with no generated key refused, leaving no network, no membership, and no key file;
  - a refused command creating no key;
  - `--no-person` generating nothing;
  - a second machine with a different key reporting the taken label, then bound after copying the key;
  - policy renewal by a daemon with only the generated key (crafted near-expiry policy, no agent), and item 10 absent.
- **Invite and join:** `invite` output and its `join` line, used verbatim by `join`; a second machine of the same person bound without a new admission.
- **Root help:** the new command set; the moved commands still run.
- **`allow`:**
  - each principal form;
  - `SIZE` parsing and its bounds;
  - default and flag-set settings;
  - the set semantics: moving a principal between rules of a scope, sharing a rule with identical settings, dropping empty rules, and leaving other scopes alone;
  - flag dependencies (`--delegate` or `--files` with `--no-tasks` refused).
- **`deny`:** with and without `--agent`, `removed` counts, the zero-removal note and no new version, and access through a group still working afterwards.
- **`*` rules:** authorizing a message and a task to any agent; a named rule overriding `*` for its agent in both directions; `agent register` refusing `*`.
- **Self access:**
  - messages, tasks, delegation, and artifacts between two hosts of one person with no policy;
  - while the coordinator is stopped;
  - ended by unbinding a host;
  - refused for a host bound to a different person;
  - blocks not applying;
  - the `self` citation by owner CLI and adapter routes.
- **`block`/`unblock`:** by label and by host ID.

## Slice 4: directory and addressing

Decided with the owner on 2026-10-09:
- an agent's name is unique among its person's agents on all of their hosts, so `person/agent` names one agent;
- when `attach`'s default name is taken, it picks a suffixed name rather than failing;
- sessions created by `attach` may reach any agent in the directory, capped at 100 sends and delegations per hour;
- the directory shows whether each agent has a connected session.

Agent IDs remain the identity. Names are labels that let people and agents address an agent, and nothing authorizes by name.

### Names and addresses

**Addressable names.** An agent can be addressed when its name is 1–64 characters of lowercase ASCII letters, digits, `.`, `_`, and `-`, starting with a letter or digit. Other agents are listed by ID only. `attach` only creates addressable names. `agent register` is unchanged.

**Uniqueness.** A person's agents should have distinct names across all of that person's hosts. Names are not published to the coordinator, so this is enforced by `attach` through the directory (below), as well as it can be:
- `attach --name NAME` refuses a name that the person already uses on this host or on any of their hosts in the directory, and names the host that has it;
- a host of the person that could not be reached is reported by host ID in `unchecked_hosts`, and does not block the attach;
- a duplicate that slips through is reported by status item 12 (`agent_name_conflict`).

**Addresses** take two forms:
- `PERSON/AGENT`, where `PERSON` is a person label, compared with ASCII case folded, as person label uniqueness is;
- `HOST_ID/AGENT`, where the first part is a host ID (`host_` followed by its hex digits). It also addresses agents of hosts without a bound person, and picks one agent of a duplicate pair.

An address splits at its last `/`. Resolution searches the directory of every network this host belongs to, or only the one given with `--network` or the adapter's `network`. It fails with:
- `unknown`, after one synchronous refresh of the directory, when nothing matches;
- `ambiguous` when more than one agent matches, for example a duplicate name or a label used in two networks. The error lists each match as `HOST_ID/AGENT` with its network;
- `local` when the address names an agent on this host. Capsule has no local delivery.

### Peer route

`GET /peer/v1/networks/{network_id}/agents` returns the receiver's agents that the authenticated caller host may reach now, for callers that are current, unrevoked members of that network. Any other caller gets 403, and a network the receiver does not belong to returns 404. It returns 200 with an array sorted by name, then ID:

```json
[{
  "name": "claude", "agent_id": "agent_…", "connected": true,
  "authorizations": [
    {"kind": "self", "actions": ["message.append", "task.submit", "task.delegate"],
     "max_message_bytes": 65536, "max_artifact_bytes": 1073741824},
    {"kind": "policy", "actions": ["message.append", "task.submit"],
     "max_message_bytes": 65536, "max_artifact_bytes": 0, "from_agent": null},
    {"kind": "grant", "grant_id": "grant_…", "actions": ["task.submit"],
     "max_message_bytes": 65536, "max_artifact_bytes": 0, "expires_at": "RFC3339", "from_agent": null}
  ]
}]
```

- `authorizations` lists every current authorization of the caller for that agent, with the same predicates the receiver uses for a request: self access; each applicable rule of the receiver's bound person's newest verified policy (named rules, else `*` rules); and each unexpired, unrevoked grant to the caller host for that agent. Blocks apply to policies and grants, not to self access.
- A rule whose only matching principals are `agent:HOST/AGENT_ID` principals appears once per such agent, with `from_agent` set to that agent ID, and applies only to requests from that agent. A rule with any other matching principal appears once, with `from_agent` null. A grant's `from_agent` is its requester agent, or null.
- **Shapes are exact.** Entries are ordered self, then policy entries in rule order, then grants by grant ID. A self entry has exactly the keys shown, with the three actions; a policy entry has the rule's actions; a grant entry has `[ACTION]`, its one action.
- An agent with no authorizations is never listed. A caller with none receives `[]`.
- `connected` is true when the agent has an attached session whose adapter holds a valid lease.
- Agent names in the response are as registered, addressable or not.

Older receivers return 404 for this route. The caller records the host as `unsupported`, not as an error.

### Discovery

Each daemon keeps a directory per network, in memory:
- **Hosts queried:** every current, unrevoked member other than itself.
- **When:** at startup, every 5 minutes, within 10 seconds of a change to the network's map or to any stored policy, and on demand.
- **How:** at most 8 queries at once, each with a 5-second timeout, over the usual peer transport, relay included.
- **Failures:** a host that fails keeps its previous agents, marked with the time of the last success and the error.

`GET /v1/directory?network=ID` returns the cache for one network, with the slice 1 network defaulting:

```json
{
  "network_id": "net_…",
  "refreshed_at": "RFC3339 or null",
  "hosts": [{"host_id": "host_…", "person_id": "person_… or null", "person_label": "bob or null",
             "state": "ok", "refreshed_at": "RFC3339 or null", "error": "text or null"}],
  "agents": [{"address": "bob/claude", "host_id": "host_…", "person_id": "person_…", "person_label": "bob",
              "name": "claude", "agent_id": "agent_…", "connected": true, "authorizations": []}]
}
```

- `hosts` are sorted by host ID. `state` is `ok`, `error`, `unsupported`, or `pending` (never queried yet).
- `agents` are sorted by address, then host ID, with null addresses last, then by host ID and agent ID. `address` is `PERSON/AGENT`, or `HOST_ID/AGENT` when the host has no bound person or the name is duplicated within that person. It is null for names that are not addressable. `authorizations` is as served by the peer.
- Without `network`, a host in no network or in several gets 400, the latter listing them; an unknown network is 404.
- `POST /v1/directory/refresh?network=ID` with `{}` refreshes synchronously, waiting at most 10 seconds, and returns the same object.

### Sending by address

The owner API, the CLI, and the adapter API accept an address in place of a host and an agent:
- `POST /v1/outbound` and `POST /v1/tasks` accept `to`, with optional `network`, in place of `peer_host_id` and `target_agent_id`; giving both forms is 400.
- `POST /adapter/v1/send` and `POST /adapter/v1/delegations` accept `to`, with optional `network`, in place of `destination`; giving both is 400.

The daemon resolves the address before persisting anything. Resolution failures return 404 (`unknown`), 409 (`ambiguous`), or 400 (`local`), each with `{code, error, matches}`, where `matches` is empty unless ambiguous, and then lists `{address, network_id}` objects with `HOST_ID/AGENT` addresses, sorted by network ID, then address. A malformed address, or both forms given, is an ordinary 400.

**Choosing an authorization.** The daemon picks the first of these that allows the action (`message.append`, `task.submit`, or `task.delegate` for a forwarded task) for the request's origin agent:
1. self access, cited as `self`;
2. a policy entry whose `from_agent` is null or the origin agent, cited as the target owner's policy, as today;
3. the grant with the latest `expires_at` whose `from_agent` is null or the origin agent, cited by its ID.

When none allows it, the daemon refreshes that host once and tries again, then refuses with 403 `{code: "not_authorized"}` before persisting anything. An explicit `grant_id` (owner `--grant`) overrides the choice. Sizes and deadlines are checked by the receiver as before.

**Persistence.** The resolved host and agent ID are stored with the request, and the record shows `to` as given. Records not sent by address have no `to` key, so their shape is unchanged; the adapter's send status always has both `destination` and `to`, one of them null. Retries and status lookups use the stored target and never re-resolve. Request IDs, retries, idempotency, and replies work as for any send or task.

**Deadlines.** Adapter sends by address get 5 minutes and adapter delegations 1 hour, as route sends do, bounded by the credential's expiry.

### Directory sessions

A session's credential may be created with **directory access**. Then its adapter may send and delegate by address to any agent in the directory. This is a deliberate exception to the rule that credentials confer no arbitrary outbound messaging. Without directory access, which is the default for `session setup` and `adapter create`, sessions behave as before, and a `to` request returns 403 `{code: "no_directory"}`.

- `POST /v1/adapters/setup` gains optional `directory` (boolean, default false) and `max_sends_per_hour` (1 to 10,000, default 100; it requires `directory`). The adapter's record shows both.
- **Rate cap.** Each send and each delegation by address counts once when it is first persisted, never on retries. A request that would make more than `max_sends_per_hour` in the preceding 60 minutes for that credential returns 429 `{code: "rate_limited", error, retry_after}`, where `retry_after` is a whole number of seconds, at least 1, until the oldest counted request leaves the window. It persists nothing. Route sends keep their own budgets and are not counted.
- **Agent tools.** `GET /adapter/v1/agents` returns `[{address, network_id, connected, actions, max_message_bytes, max_artifact_bytes}]` from the directory, for addressable agents only. `actions` and the bounds are the union over the agent's authorizations, ignoring `from_agent` entries for other agents; an agent left with no actions is omitted. It returns 403 `no_directory` without directory access.
- **MCP.** The shared adapter adds `list_agents`. `send` and `delegate_task` accept `to` and optional `network` in place of `destination`, when the credential has directory access. `send_status` reports `to` for these sends. `list_destinations` stays, for routes.
- **Schema.** Storing `directory` and `max_sends_per_hour` with the credential, and `to` with outbound requests and tasks, is a shared schema migration, applied atomically and preserving existing state.

### Commands

| Command | Behavior |
| --- | --- |
| `attach HARNESS [--name NAME] [--directory DIR] [--expires-in D \| --expires-at T] [--max-sends-per-hour N] [--option KEY=VALUE ...] [--integrations DIR] [--runner PATH]` | Registers the agent if needed and sets up a directory session for the project at `--directory` (default: the current directory), below. |
| `agents [--network ID] [--refresh] [--json]` | Shows the directory (below). `--refresh` refreshes first. |
| `send TARGET TEXT [--network ID] [--grant ID] [--from-agent ID] [--deadline T]` | `message send` addressed by `TARGET`, an address. Prints the outbound record. |
| `task TARGET TEXT [--file PATH ...] [--network ID] [--grant ID] [--from-agent ID] [--deadline T]` | `task submit` addressed by `TARGET`. `--file` is `--artifact`, with the default media type. Prints the local task record. |
| `session start` / `session doctor` | `--directory` becomes optional: without it, they use the `attach` profile whose recorded workspace is the current directory, and fail when there is none. |

**`attach`.**
- `HARNESS` is an integration ID, or `claude`, which means `claude-code`. The base name is `claude` for `claude-code`, and otherwise the integration ID.
- **Profiles** live in `$XDG_CONFIG_HOME/capsule/sessions/HOST_ID/AGENT_NAME/`, and record the project's real path as `workspace`.
- **Re-attaching.** If a profile for this host already records this workspace, `attach` reuses its agent. If its credential is unexpired and unrevoked, `attach` changes nothing and reports `reused: true`. Otherwise it performs a new setup for the same agent and replaces the old profile once the setup succeeds.
- **Naming.** Otherwise, with `--name`, that name is used if free. A `--name` naming an agent on this host that no `attach` profile records is reused, so agents registered earlier can be attached. Without it, `attach` takes the first free name of:
  1. the base name;
  2. `BASE-PROJECT`, where `PROJECT` is the workspace's base name, if the base name is used on this host;
  3. `BASE-HOSTNAME`, with this machine's short host name, if it is used only on another host;
  4. then the last of these candidates that applied with `-2`, `-3`, and so on appended. The bare base name never gets a number.
  Names are free when neither this host nor any host of this person in the directory has them, after a synchronous directory refresh. Suffixes are lowercased, and characters outside the addressable set become `-`. The suffix is cut so that the whole name, including any `-N`, fits in 64 characters.
- **Registering.** A new agent is registered with that name and with this host's bound person's label as its owner (the login name if unbound).
- **Setup.** It then runs today's session setup with directory access, `max_sends_per_hour` (default 100), no routes, and a renewable credential (the slice 1 default) unless an expiry is given. Integration options pass through.
- **Output.** It prints `{agent: {id, name, address}, session_id, adapter_id, profile, workspace, reused, unchecked_hosts, next}`, where `address` is `PERSON/NAME` (or `HOST_ID/NAME` if this host has no bound person), and `next` is `capsule session start` for launch-capable integrations.
- **Refusals.** A taken `--name` is refused with 409 before any registration, and the error names the host that has it.

**`agents`** prints, for the network:
- **reachable:** each addressable agent in the directory with its address, actions, whether it is connected, and whether its host answered the last refresh;
- **mine:** this person's agents on this host and in the directory, with their addresses and connection;
- **inbound:** for each rule of this person's stored policy, its agent scope (`*` or a name), principals as labels where they resolve, actions, and `max_artifact_bytes`, plus a line saying that the person's own hosts reach everything.

Its readable layout is not shared. `--json` prints `{network_id, refreshed_at, reachable, mine, inbound, hosts}`. `reachable` uses `{address, host_id, agent_id, connected, host_state, actions}`, `mine` uses `{address, host_id, agent_id, connected}`, and `inbound` uses `{agent, principals, actions, max_artifact_bytes}`. Principals use their policy form, for example `person:person_…`. `hosts` is the directory's `hosts`.

**Root help** now lists, in order:
1. `status` and `install`;
2. `run`;
3. `network create`, `join`, and `invite`;
4. `attach`, `agents`, `send`, and `task`;
5. `allow`, `deny`, `block`, and `unblock`;
6. `network list` and `network members`;
7. `access show`;
8. `session start` and `doctor`.

`session setup`, `message send`, and `task submit` move to `help advanced`, unchanged.

### Status addition

12. `agent_name_conflict`: the directory shows a name used by more than one agent of this host's person, and this host has one of them. Added by the daemon; subject `NETWORK/NAME`; command `capsule attach HARNESS --name NEW` in that agent's project. It follows item 11.

### Verification

`conformance/launch_directory.py` is written from this contract by an author independent of both implementations. It runs across all Go/Rust CLI and daemon pairings, with `--probe`, the Go coordinator, `--node` for the MCP cases, and OpenSSH. It covers:
- **Peer route:**
  - listing through self access, a person rule, a `*` rule, a group rule, `everyone`, an `agent:` principal (`from_agent`), and a grant;
  - unlisted agents with no authorization, and `[]`;
  - blocks hiding policy and grant entries but not self;
  - `connected` before and after an adapter connects;
  - 403 for a non-member host, and 404 for an unknown network.
- **Discovery:**
  - a new agent appearing after `--refresh`;
  - a policy change reflected within 10 seconds without a refresh;
  - a stopped host keeping its agents with `state: error`.
- **Addresses:** both forms; case-folded labels; `unknown`, `ambiguous` (with an injected duplicate), and `local`; a host without a person addressed by host ID.
- **Sending:**
  - `send` and `task` by address under self, policy, and grant, and the authorization each cites;
  - `--grant` overriding the choice;
  - `not_authorized` persisting nothing;
  - a retry still reaching the stored target after the address would resolve elsewhere (the target host unbound, and the name registered on another host of that person).
- **Attach:**
  - default naming and each suffix rule, across two hosts of one person;
  - `--name` taken refused, with no registration;
  - re-attach reusing the agent with `reused: true`, and after expiry a new credential for the same agent;
  - `unchecked_hosts` with a sibling stopped;
  - `session start`/`doctor` without `--directory`.
- **Directory sessions:**
  - MCP `list_agents`, and `send` and `delegate_task` by `to` through the real adapter;
  - `no_directory` for a session from `session setup`;
  - the rate cap with a small `--max-sends-per-hour`, retries not counted, and route sends not counted.
- **Agents and status:** `agents --json` fields; item 12 with an injected duplicate.
- **Root help:** the new command set; the moved commands still run.
