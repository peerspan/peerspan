# Launch contract

Roadmap milestone 7. The design and its settled decisions are in the [launch proposal](launch-proposal.md). This contract grows one section per slice.

## Slice 1: CLI shape

### Name

The CLI is one binary that answers to `capsule` and `capsule-host`. Help and diagnostics name it after the base name it was invoked as, and behave identically otherwise. Builds keep producing `capsule-host`. The release bundle adds `bin/capsule` as a relative symbolic link to `capsule-host`, and both find the bundled integrations.

### Root help

The root help lists only these commands, in this order:
1. `status`;
2. `run`;
3. `network create`, `join`, `invite`, `list`, and `members`;
4. `access allow`, `deny`, and `show`;
5. `session setup`, `start`, and `doctor`;
6. `message send` and `task submit`.

It ends with one line pointing to `help advanced`. `help advanced` (and `--help-advanced` before any command) prints the full command list as the root help does today. Every hidden command still runs, and its own `--help` still works. Help wording is not a shared contract; the set of commands listed is, and `conformance/launch_cli.py` checks it.

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
- **Routes.** A route created without `expires_at`, by `POST /v1/adapters/{id}/routes` or within setup, takes its credential's `expires_at` and gains `follows_credential: true`. Route records always show `follows_credential`. It is allowed only when the credential is renewable; otherwise it is a 400.
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
- **`agents`:** sorted by name. `sessions` lists only attached sessions and sessions with an unrevoked, unexpired credential. `connection` uses the values of `adapter connection`: `registered`, `ready`, `offline`, `detached`, `revoked`, or `expired`.
- **`version`:** the implementation's version string. Its wording is not shared.

**Attention items**, in this order, each with its subject:
1. `coordination_error`: a network with a non-null `last_sync_error`. Subject: the network ID; command: `capsule network sync ID`.
2. `policy_expired`: this person's policy has passed `valid_until`. Command: `capsule access renew --network ID`.
3. `policy_expiring`: this person's policy has less than a quarter of its validity window left. The daemon renews it at that point, so this means renewal is failing, for example because the daemon cannot reach the person's ssh-agent. Command: `capsule access renew --network ID`.
4. `policy_delivery_failing`: a pending policy delivery that has failed at least once. Subject: `NETWORK/TARGET`; command: `capsule access sync --network ID`.
5. `credential_expiring`: an unrevoked, non-renewable credential with an attached session, expiring within 24 hours. Subject: the adapter ID; command: `capsule session setup …`.
6. `tasks_failed`: outbound tasks that became `failed`, `rejected`, or `expired` in the last 24 hours, as one item. Subject: the count; command: `capsule task list`.
7. `artifact_quota`: stored plus pending bytes above 90% of the quota. Command: `capsule artifact prune`.

Within one kind, items are sorted by subject. `detail` is free text.

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
