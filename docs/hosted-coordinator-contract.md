# Hosted coordinator contract

Roadmap milestone 8. The design and its settled decisions are in the [hosted coordinator proposal](hosted-coordinator-proposal.md). This contract grows one section per slice. `capsule-coord` is Go-only; host behavior applies to Go and Rust.

## Slice 1: operations

Decisions recorded in the proposal: one VM; key in the database with encrypted backups; a loopback health and metrics endpoint and structured logs.

### Ops listener

`capsule-coord run --listen HOST:PORT --ops-listen HOST:PORT` also serves plain HTTP on the ops address. The flag is optional; without it nothing extra listens.
- HOST must be a loopback IP literal (`127.0.0.0/8` or exactly `::1`). Anything else, including `localhost`, makes `run` exit 2 with `error: --ops-listen must be a loopback address` on stderr before listening on either address.
- `GET /healthz` returns 200 `{"status": "ok", "id": COORDINATOR_ID}` when a database read completes within 1 second, else 503 `{"status": "unavailable", "id": COORDINATOR_ID}`.
- `GET /metrics` returns the Prometheus text exposition format (`text/plain; version=0.0.4`).
- Other paths return 404 for any method, and other methods on these two paths return 405 with `Allow: GET` (HEAD included). The ops listener never serves the coordination API, and the coordination port never serves these paths (404).

**Metrics.** These names, types, and labels are the contract. Others may be added, such as Go runtime and process metrics. No label value is a network ID, host ID, person ID, or IP address.

| Name | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `capsule_coord_info` | gauge, always 1 | `version` | The build's version string. |
| `capsule_coord_networks` | gauge | — | Registered networks. |
| `capsule_coord_member_hosts` | gauge | — | Current member hosts across networks, excluding revoked and departed hosts. |
| `capsule_coord_relay_connections` | gauge | `alpn` | Open relay connections, by negotiated ALPN. |
| `capsule_coord_requests_total` | counter | `route`, `code` | Coordination API requests by route template and HTTP status. The template is the request path with the network ID replaced by `{network}`, such as `/coord/v1/networks` or `/coord/v1/networks/{network}/sync`. Unmatched paths and wrong methods use route `other`. |
| `capsule_coord_request_seconds` | histogram | `route` | Request duration in seconds, same routes, with Prometheus's default buckets. |
| `capsule_coord_relay_bytes_total` | counter | — | Relayed datagram bytes, as counted for `--relay-bytes-per-month`. |
| `capsule_coord_limit_refusals_total` | counter | `limit` | Refusals with 429, by limit: `members`, `networks_per_ip`, or `relay_bytes`. Relay drops count once per dropped frame. |
| `capsule_coord_changes_notified_total` | counter | — | `changed` frames sent. |

Gauges reflect the database and live connections at scrape time. Counters start at 0 when the process starts; `limit_refusals_total` is exposed for all three limits and `relay_connections` for every relay ALPN (`capsule-relay/1`, `/2`, and `/3`) from the start, at 0.

### Logs

Once listening, `run` writes one JSON object per line to stderr, replacing the earlier startup text. Failures before that (flags, state, the listen address) stay `error: ...` text lines with a nonzero exit. Every JSON line has `time` (RFC 3339 with fractional seconds, ending in `Z`), `level` (`info` or `error`), and `msg`:
- `start`: `id`, and the bound `listen` and `ops_listen` addresses (null without the flag). It is written once per run.
- `stop`: on shutdown, after connections close and their lines are written. It is the last line.
- `request`: one per coordination API request, after the response: `method`, `route` (the template above), `status`, `duration_ms` (a number, possibly fractional), `host` (the client certificate's host ID, always present), and `network` when the route has `{network}`.
- `relay`: one when a relay connection whose host key was read closes, including refused ones: `host`, `alpn`, `bytes_in` and `bytes_out` (relay frame bytes, headers included), and `duration_ms`.
- `error`: `error`, a description for the operator, and `network` and `host` when known. Requests answered with 500 and failures outside requests are errors; 4xx answers appear only as `request` lines.

Logs never contain IP addresses or ports of clients, statement or request bodies, keys (the coordinator's own public key included) or signatures, invite tokens, candidates, or relayed payloads. `listen` and `ops_listen` in `start` are the coordinator's own addresses.

### Backup and restore

`capsule-coord [--state DIR] backup FILE` writes a consistent copy of the database, including the private key, while a coordinator runs or not. It does not take the state lock.
- It writes to a temporary file in FILE's directory with mode 0600 and renames it into place. If FILE already exists it exits 1 and changes nothing.
- It prints `{"file": ABSOLUTE_PATH, "bytes": N, "id": COORDINATOR_ID, "user_version": V}` to stdout.
- Without a database in the state directory it exits 1.

`capsule-coord [--state DIR] restore [--replace] FILE` installs a backup as the state's database. Its checks run in this order, and each refusal exits 1 and changes nothing:
- It takes the state lock and exits 1 with `coordinator is running` if it is held.
- If the state already has a database, it exits 1 unless `--replace` is given.
- It checks FILE: SQLite `integrity_check` returns `ok`, the identity row exists, and its `user_version` is one this build opens.

Then it creates the state directory (0700) if needed and writes `coord.db` (0600) through a temporary file and rename. With `--replace`, the previous database is kept byte for byte as `coord.db.replaced-TIMESTAMP` (UTC, `YYYYMMDDTHHMMSSZ`) in the state directory, with its `-wal` file, if any, as `coord.db.replaced-TIMESTAMP-wal`; a name already taken is a refusal. Other `-wal` and `-shm` files are removed. It prints `{"id": COORDINATOR_ID, "user_version": V, "replaced": PATH_OR_NULL}`.

A restored coordinator has the backup's identity, so hosts that pin its key keep working when it serves the same address. Changes made after the backup are lost until slice 3 adds re-submission; the runbook keeps that window small with continuous replication.

### Deployment files

`deploy/coordinator/` holds:
- `capsule-coord.service`: a systemd system unit running `capsule-coord --state /var/lib/capsule-coord run --listen ${CAPSULE_COORD_LISTEN} --ops-listen 127.0.0.1:9464` and the limit flags from an `EnvironmentFile`, as a dedicated static user (Litestream runs as the same user, and the state directory must not be a symbolic link, so not `DynamicUser=`), with `StateDirectory=capsule-coord` (mode 0700), `Restart=on-failure`, and sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and no added capabilities when the port is 1024 or above).
- `capsule-coord.env.example`: the environment file's variables with comments.
- `litestream.yml` and `litestream.service`: continuous replication of `/var/lib/capsule-coord/coord.db` to an S3-compatible bucket, with credentials from an environment file. Litestream 0.5 has no client-side encryption, so replicas use S3 server-side encryption with a customer-provided key (SSE-C) held on the VM: the provider stores only ciphertext but sees the key with each request. The offline `backup` copy is encrypted client-side by the owner.
- `README.md`, the runbook: provisioning a VM with a static address and DNS name; opening TCP and UDP on the coordination port only; installing the binary and units; reading the key with `capsule-coord info` for `CAPSULE_COORDINATOR_KEY`; upgrades (replace the binary, restart, check `/healthz`); a restore drill from Litestream and from a `backup` file; alerts on `/healthz`, request errors, limit refusals, and disk; keeping an offline encrypted `backup` file after every key change; and, until slices 2 and 3, the warning that a leaked key cannot yet be replaced.

### Verification

`conformance/coord_ops.py` is written from this contract by an author independent of the implementation. It runs the Go coordinator with Go and Rust hosts and covers:
- the ops listener: `/healthz` shape, 404 and 405, the coordination port not serving ops paths, and refusal of a non-loopback `--ops-listen`;
- metrics: every listed name with its type and labels; `networks` and `member_hosts` after create, join, and revocation; `requests_total` for sync; `relay_connections` with relayed hosts; `relay_bytes_total` increasing with relay traffic; `limit_refusals_total` with `--max-members`; `changes_notified_total` after a policy change; and no label value equal to any network, host, or person ID or `127.0.0.1`;
- logs: every stderr line is a JSON object with the fields above; `start`, `request` for create, join, and sync, `relay`, and `stop`; and no client address, invite token, statement body, key, or message content anywhere in stderr;
- backup while hosts sync and relay continuously: the copy is 0600, opens, and has the same `id`; an existing FILE is refused;
- restore: refused while running, refused over an existing database without `--replace`, refused for a corrupt or non-coordinator file; with `--replace`, the previous database kept; then, a coordinator started on the restored state at the same address, Go and Rust hosts sync, join with a fresh invite, and exchange relayed messages without any host action;
- the deployment files: `systemd-analyze verify` on the unit where available, and `litestream.yml` parsing as YAML with the database path and an encrypted replica.

## Slice 2: successors

Decision recorded in the proposal: the operator's coordinator key may sign a successor that moves every network on the coordinator, and a move signed by the network root or a delegated administrator (slice 3) always takes precedence.

### Identities

A coordinator has an ordered list of identities, numbered from 0. Identity 0 is the existing key. Each later identity has an address and a key, which may be the previous key, and a successor statement signed by the previous identity's key. The coordinator database moves to version 6.

`capsule-coord [--state DIR] successor --address HOST:PORT [--new-key]` appends an identity:
- It takes the state lock, so the coordinator must be stopped: `coordinator is running` exits 1. A state without a database exits 1.
- `--address` must be a valid coordinator address (`HOST:PORT`, where HOST is an IP literal or a DNS name). With `--new-key` it generates a key; otherwise the new identity keeps the latest key, and an address equal to the latest identity's address exits 1 with `nothing changes`.
- It prints `{"sequence": N, "id": COORDINATOR_ID, "public_key": KEY, "address": ADDRESS, "successor": SUCCESSOR}`.

`info` keeps `id` and `public_key`, which are the latest identity's, and gains `identities`: `[{sequence, id, public_key, address}]` in order. Identity 0's `address` is null.

**Successor.** A successor is a strict JSON object with exactly `sequence`, `previous_public_key`, `address`, `public_key`, `signed_at`, and `signature`. `signature` is by `previous_public_key` over the statement with lines `capsule-coordinator-successor-v1`, `sequence` in decimal, `previous_public_key`, `address`, `public_key`, `signed_at`. Sequences start at 1; identity 0 has no successor. `signed_at` is informational and not interpreted. A chain of successors is valid from a key K when the first's `previous_public_key` is K, each signature verifies, every sequence is at least 1 and each is one more than the preceding, each later `previous_public_key` is the preceding `public_key`, and every address is a valid coordinator address.

**Test vector.** With previous seed `BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=` (public key `ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=`), new public key `bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=`, sequence 1, address `coord.example.com:7400`, and `signed_at` `2026-10-10T00:00:00Z`, the signature is `OyAcMcamcVZu8FBm5nnHoBUQ+qXiiCRP+KJSLFCMQxCnWRw+9mfJnd6is8Pikhz1+ob6Qr/0iZ/mN2kXxunICQ==`.

### Serving

`capsule-coord run --listen HOST:PORT` presents the latest identity. `--previous-listen SEQUENCE=HOST:PORT`, repeatable, also serves an earlier identity on another address, with its key, its STUN responder, and its relay. All listeners share one database and one relay, so hosts connected through different identities relay to each other. A sequence that is not an earlier identity exits 2 before listening.
- Responses to register, join, and sync gain `successors`: the chain from the identity the request reached to the latest, in order, or `[]` from the latest identity. The identity a request reached is, among the identities with the key its listener presents, the one whose address equals the request's `Host` header, or else the earliest of them. Hosts send `Host` equal to the pinned `coordinator_address`, so one listener can serve an old and a new name for the same key.
- The `start` log line gains `previous_listen`: `[{sequence, listen}]`, empty without the flag. `/healthz` reports the latest identity's `id`.
- Metric `capsule_coord_identity_hosts{sequence}` (gauge): distinct authenticated hosts that completed a request or opened a relay connection through that identity's listener in the last 24 hours, since the process started. Refused clients still count: a failed request does not establish that the host stopped using the old identity. Each identity retains at most 4,096 host IDs, with age-based cleanup on traffic as well as scrapes. Saturation adds one overflow marker, retained for 24 hours after the last untracked host, so a listener cannot report zero while an untracked host may still use it. It is how the operator tells when an old listener can stop; above the cap it is a bounded count rather than an exact cardinality.

### Hosts

On a register, join, or sync response with a non-empty `successors`, a host verifies the chain from the network's pinned `coordinator_public_key`:
- **Invalid:** it ignores the chain, keeps the pin, applies the map as usual, and sets `last_sync_error` to `invalid coordinator successor`.
- **Valid:** it records the chain's last entry as the network's `coordinator_pending`: `{address, public_key, sequence}`. It then syncs the network at the pending address with the pending key. If that sync succeeds, the pending address and key replace `coordinator_address` and `coordinator_public_key`, `coordinator_pending` becomes null, and the relay connection and STUN move to the new address. If it fails, the host keeps its pin and the pending entry, sets `last_sync_error` to a message starting `coordinator successor ADDRESS: ` (the pending address), and each later interval sync tries the pending coordinator first and the pinned one after it. A chain served by the coordinator the host just switched to is recorded as the pending entry in that sync and tried on the next one, not in the same one; an empty chain leaves a pending entry in place.

A pending entry survives restarts. A later valid chain from the pinned key replaces it. The network record gains `coordinator_pending`, null when nothing is pending, in `network list` and `GET /v1/networks`. Invites carry the pinned coordinator, which is the new one once the host has switched. A joiner whose invite names an earlier identity follows the chain in the join response the same way.

### Runbook

The deployment runbook gains a successor procedure:
- **Address change (same key):** run `successor --address NEW`, point the new name at the VM, and restart. One listener can serve both names, since the key is the same.
- **Key change:** run `successor --address NEW --new-key` with a new port or address, restart with `--listen NEW --previous-listen N=OLD`, update `CAPSULE_COORDINATOR_KEY` for new builds, take a new offline backup, and stop the old listener once `capsule_coord_identity_hosts` for it has been 0 for 30 days.
- **Leaked key:** sign a successor with a new key at once. Hosts that reach the operator first follow it; a successor signed with the leaked key to another coordinator can divert hosts only to an availability-only coordinator, and administrators recover with a signed move (slice 3).

### Verification

`conformance/coord_successor.py` is written from this contract by an author independent of both implementations. It runs the Go coordinator with every Go/Rust combination of a creator and a joiner host, and covers:
- `successor` refusals (running, nothing changes, an invalid address) and `info.identities`;
- an address change with the same key: both hosts switch within two sync intervals, `coordinator_pending` returns to null, and messages, relay, and change notifications keep working;
- a key change served with `--previous-listen`: hosts switch, a host that was stopped during the change follows on restart, a join with an invite issued before the change ends pinned to the new identity, and invites issued after it carry the new pin;
- two successors (0 to 2) applied while a host was stopped, followed in one step;
- an unreachable new address: hosts keep their pin with `coordinator_pending` set and a sync error, survive a restart, and switch once the new listener starts;
- `--previous-listen` refusals, the `start` line, and `capsule_coord_identity_hosts` per sequence;
- where the suite can serve a chain itself (for example a minimal coordinator stand-in), an invalid chain leaving the pin unchanged with `invalid coordinator successor`.

## Slice 3: moves and repair

Decisions recorded in the proposal: the network root or a delegated administrator signs a move of one network, which always takes precedence over successors; any member host re-submits what a coordinator lacks.

### The move statement

| Statement | Signed by | Lines |
| --- | --- | --- |
| Coordinator move | root or administrator | `capsule-coordinator-move-v1`, `network_id`, `sequence`, `address`, `public_key`, `moved_at` |

A move is a strict JSON object with `network_id`, `sequence`, `address`, `public_key`, `moved_at`, `signer` (`root` or the administrator's `person_public_key`), and `signature`, raw for the root and `SSHSIG` for an administrator, as for group definitions. `sequence` is a decimal integer of at least 1; for each network the valid move with the highest sequence applies. A move is valid when its signer is the current root or a current administrator at the time a coordinator or host verifies it, and `address` is a valid coordinator address. A host that has already switched because of a move stays switched if its signer later stops being an administrator.

**Test vector.** With the root seed `BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=` (network `net_c5b940ed3f65c391965de8295fc5d25f474fa57b48d36eb10ad363b8539c1b79`), sequence 1, address `coord.example.com:7400`, public key `bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=`, and `moved_at` `2026-10-10T00:00:00Z`, the root's raw signature is `IBmzYpyWsCU4IE5B4HhL9CMjdn2WlWUYWuJNjxWaoZ03ynlz2pCGzJ5i8Nj1LvEXm1936XDTB3o23GnvHN14CQ==`.

### Coordinator

- `POST /coord/v1/networks/{network}/moves` with `{move}`: the caller must be a member, otherwise 403. The coordinator stores a valid move whose sequence is higher than its current one (200), refuses a sequence that is not higher with 409, and an invalid move with 400.
- The map gains `move`, the current move or null.
- `POST /coord/v1/networks/import` with `{name, root_public_key, map}`, where `map` carries the signed fields of a map as the caller holds them (`members`, `rotations`, `attestations`, `revocations`, `persons`, `admins`, `groups`, `policies`, `move`, and every other signed field the map serves). The coordinator verifies each statement as on its own submission route, in dependency order, and merges: it adds what it lacks and keeps what it has when its own is newer. Entries that fail verification are skipped, not fatal. The caller must be a current member of the result, otherwise 403. An unknown network is registered (201) and counts toward `--max-networks-per-ip`; an existing one returns 200. Both return `{added, skipped, map}`, where `added` and `skipped` count statements. Members' addresses and candidates come from their own syncs.
- A coordinator keeps serving a network after a move away from it: syncs return the map with `move`, and joins still succeed, so invites issued before the move keep working while the old coordinator runs.

**Invite expiry during import.** An invite-backed host or person already recorded at this coordinator can be re-submitted after expiry. A missing record must pass the coordinator's current-time expiry check, even when its holder signed an earlier `joined_at`: that time is not proof of prior admission. A verified current-root attestation for the host and member label independently authorizes host recovery after expiry; a signed host/person admission also remains valid under its existing rules. Without such authorization, the entry is skipped, and a caller left without membership is refused with 403. An expired unused invite cannot establish membership through import.

### Moving a network

`capsule network move --coordinator HOST:PORT --coordinator-key KEY [--network ID]` (in `help advanced`) is run on a host whose operator is the root holder or a current administrator; it picks the signer as the other administrator commands do. It:
1. signs a move with sequence one more than the current one;
2. imports the network, including the move, into the new coordinator, and fails with nothing changed if that import fails, including when the coordinator there presents another key;
3. submits the move to the current coordinator, at most once, recording `accepted`, `refused`, or `unreachable`;
4. pushes the move to every other current member host it can reach (below);
5. syncs the new coordinator and switches its own pin.

It prints `{network_id, sequence, coordinator: {address, public_key}, imported: {added, skipped}, previous_coordinator: STATE, pushed: N, members: M}`. Without a reachable new coordinator it exits 1.

The CLI uses two local routes:
- `GET /v1/networks/{id}/move` returns `{move, next_sequence}`: the host's latest valid move or null, and the sequence a new move takes, one more than the higher of the applied sequence and the latest held move's.
- `POST /v1/networks/{id}/move` with exactly `{coordinator_address, coordinator_public_key, move}` runs the steps above and returns the printed object. With `move` null, the daemon signs with the root seed it holds, and a host without one returns 403, so the CLI exits nonzero. Otherwise `move` is a move the CLI signed with an administrator's person key through `ssh-agent` or `--person-key`; the daemon verifies it and refuses with 400 a move naming another address or key than the request.

`members` in the output counts the other current member hosts, and `pushed` those that accepted the push.

### Hosts

A host learns a move from the map's `move`, from a peer push, or from a peer lookup, and verifies it against its network state. A valid move with a sequence higher than the host's applied move sequence, naming an address or key other than its pin, becomes the pending coordinator: `coordinator_pending` gains `source`, `move` or `successor`, and `move_sequence` for a move (null for a successor); for a pending move, `sequence` equals `move_sequence`. Slice 2's checks of `coordinator_pending` accept these two fields. A pending move replaces any pending successor, and a successor never replaces a pending move. The host then switches as in slice 2: it syncs the pending coordinator, and if that coordinator answers 403 because it lacks the host, it imports (below) and syncs again. On the switch, the host records the move's sequence as applied. Successors then apply from the moved-to key as before.

**Peer route.** `GET /peer/v1/networks/{network}/move` returns `{move}` with the host's latest valid move, or 404 without one. `POST` on the same route with `{move}` delivers one and returns 200 once verified, storing it only if its sequence is higher than the host's held move, or 400 when invalid. A host that learns a move this way does not submit it to a coordinator; only the mover does. The caller must be a current member host of the network. A host whose syncs have failed for three intervals, with its pinned coordinator and with any pending one, asks each member it can reach on a direct path, at most once per interval.

### Repair

After each sync, a host compares the map with what it holds. It imports when the map lacks a statement it holds: a current member (including itself), a rotation or attestation, a revocation, a person, admission, or binding, an administrator delegation, a group or policy version higher than the map's, or a move with a higher sequence. A 403 or 404 for an unknown network also triggers an import, followed by a sync. A host imports at most once per network per sync interval. Import repairs restored state subject to the admission/expiry rules above; addresses wait for each member's own sync.

If a backup or destination coordinator lacks an invite-backed record whose invite has since expired, automatic import cannot prove its historical admission. The root holder or a current administrator must issue a fresh host/person admission (or the root holder supply a current host attestation). Records already in the backup still recover automatically. A future trusted admission-receipt protocol may remove this recovery step; joiner timestamps cannot substitute for it.

### Verification

`conformance/coord_move.py` is written from this contract by an author independent of both implementations. It runs Go coordinators (two or more) across Go/Rust combinations of the mover, another member, and a joiner, with OpenSSH for administrator signatures. It covers:
- the move statement's lines and the test vector, and both implementations accepting a move the other signed;
- `network move` signed by the root and by a delegated administrator: import, the previous coordinator accepting, pushes, and every member switching; `network members`, messages, policies, and change notifications working at the new coordinator;
- a move with the previous coordinator stopped: members learn it from the mover's push, or by peer lookup after their syncs fail;
- a move by a removed administrator refused; a move with a sequence not higher refused (409);
- precedence: a pending move replacing a pending successor and never the reverse; a successor of the moved-to coordinator followed afterwards;
- a join with an invite issued before the move, through the previous coordinator, ending at the new coordinator with its membership there;
- repair after a restore from an older backup: members, persons, a group, a policy, and a revocation made after the backup reappear at the coordinator without administrator action, and a member that joined after the backup syncs again;
- import refusals: a caller that is not a member (403) and invalid entries skipped.
- expired unused host/person invites cannot introduce missing records through import, including with backdated `joined_at`; recorded admissions remain reusable after expiry; current-root host attestations and fresh administrator admissions permit recovery without trusting the asserted time.

## Slice 4: launch

Decisions settled with the owner on 2026-10-10: Hetzner Cloud; a DNS name the owner provides; a runbook plus an install script run over SSH, with no infrastructure as code yet; the owner runs every outward-facing step with their own credentials; port 443 for TCP (coordination and relay) and UDP (STUN). Settled on 2026-10-11: the script also supports Ubuntu 24.04, uses ufw when it is active, and takes `--no-firewall`, so the coordinator can share a VM with other services.

### Coordinator release archive

`scripts/package-coordinator.sh VERSION` builds `capsule-coord` for the current Linux machine with `coord.Version` set to VERSION and writes `dist/capsule-coord-VERSION-linux-ARCH.tar.gz` and its `.sha256`, refusing to overwrite as `package-release.sh` does. The archive holds `capsule-coord-VERSION-linux-ARCH/bin/capsule-coord`, `share/capsule-coord/deploy/` (the files in `deploy/coordinator/`), and a `release.json` with `version`, `os`, `architecture`, and `source_revision`.

### Install script

`deploy/coordinator/install.sh` runs as root on Debian 12 or Ubuntu 24.04, from an extracted archive:
- `install.sh --listen 0.0.0.0:443` installs: the `capsule-coord` system user, `/usr/local/bin/capsule-coord`, the units and `/etc/capsule-coord/capsule-coord.env` (an existing env file is kept), the state directory, and Litestream at the pinned version after checking its published SHA-256. It enables and starts `capsule-coord`, waits up to 10 seconds for `/healthz`, and prints `{id, public_key, listen, litestream, firewall}` as JSON on stdout, where `litestream` is `enabled` or `not configured`, and `firewall` is `nftables`, `ufw`, or `none` (below).
- With a port below 1024, the unit gains `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, and nothing else.
- Litestream is enabled only when `/etc/capsule-coord/litestream.env` and the SSE-C key file both exist; otherwise its unit stays disabled and the script says so on stderr.
- **Firewall:** one of three, reported as `firewall`:
  - `ufw`, when ufw is installed and `ufw status` reports `Status: active`: the script adds `allow` rules for the coordination port over TCP and UDP, commented `capsule-coord`, and changes nothing else in ufw. It writes no nftables table.
  - `nftables`, otherwise: a dedicated nftables table, `inet capsule_coord`, included from `/etc/nftables.conf` and loaded at boot, allows inbound TCP 22, the coordination port over TCP and UDP, established traffic, loopback, and IPv6 neighbor discovery, and drops the rest. This mode is for a VM that runs only the coordinator. It needs `nft`.
  - `none`, with `--no-firewall`: the script changes no firewall, and the owner opens the coordination port over TCP and UDP themselves. This mode is for a VM whose firewall is managed some other way.

  Neither `ufw` nor `none` removes a table written by an earlier run. The runbook also sets the `nftables` rules as a Hetzner Cloud Firewall.
- **Idempotent:** running it again with the same arguments changes nothing and prints the same identity.
- `install.sh --upgrade` replaces the binary from the extracted archive, restarts, waits for `/healthz`, and prints the same JSON, with `firewall` `unchanged`: an upgrade never touches the firewall, and `--no-firewall` with `--upgrade` is a usage error (exit 2). The identity is unchanged. If health fails, it restores the previous binary, restarts, and exits 1.
- An existing env file naming another listen address, or `--listen` over a different installed binary, exits 1; `--upgrade` is for the latter. `--litestream-archive FILE` uses a local copy of the pinned Litestream release, still checked against its SHA-256.
- It never generates or prints the private key, never contacts anything except the Litestream download, and exits 1 on any distribution other than Debian 12 and Ubuntu 24.04.

### Runbook for Hetzner

`deploy/coordinator/README.md` gains a Hetzner section:
1. A CX22 (or larger) server on Debian 12 with primary IPv4 and IPv6, an SSH key, and the Cloud Firewall.
2. An Object Storage bucket in the same location, with its access keys, and a 32-byte SSE-C key generated on the VM (`/etc/capsule-coord/litestream-sse.key`, mode 0600), kept also in the owner's password manager. Without that key, the replicas cannot be read.
3. The owner's DNS name with A and AAAA records for the server.
4. Copying the archive, `install.sh --listen 0.0.0.0:443`, and recording `public_key`.
5. A first `capsule-coord backup`, encrypted offline.
6. Release bundles built with `CAPSULE_COORDINATOR=NAME:443` and `CAPSULE_COORDINATOR_KEY=KEY`.
7. A restore drill from the replica onto a second throwaway server before announcing.

### Acceptance against the hosted coordinator

Once the owner has deployed it and provided the name and key, `conformance/launch_acceptance.py` and `conformance/live_launch_agents.py` run with bundles built for it (their default coordinator), with consent for this machine to contact it. Both take `--coordinator HOST:PORT` and `--coordinator-key KEY` in place of the loopback coordinator they start otherwise; with them, `--output` is required and the results record the address and key. Their results are recorded as `docs/results/launch-acceptance-hosted.json` and `docs/results/launch-live-hosted.json`. Runs against a staging instance are recorded as `docs/results/launch-acceptance-staging.json` and `docs/results/launch-live-staging.json`.

### Verification

`conformance/coord_deploy.py` is written from this contract by an author independent of the implementation. It needs root and Docker, and runs everything locally: throwaway `debian:12` and `ubuntu:24.04` containers running systemd as their init, and a MinIO container serving TLS, which enforces SSE-C. It removes its containers, images it pulled, and networks when done. It covers:
- the archive's layout, `release.json`, checksum, refusal to overwrite, and `capsule_coord_info{version}`;
- `install.sh` in the container: the user, files and modes, the unit with exactly `CAP_NET_BIND_SERVICE` on port 443, both services' states with and without Litestream configured, the nftables rules, `/healthz`, and the printed JSON;
- re-running it (same identity, nothing changed), `--upgrade` (identity kept, version changed), and an upgrade whose binary fails health (rolled back, exit 1);
- Go and Rust hosts outside the container creating and joining a network through the container's port 443, and exchanging relayed messages;
- Litestream replicating with SSE-C to the local server, objects unreadable without the key, and the runbook's restore procedure into a fresh container keeping the identity, after which the hosts sync again (and repair, slice 3, restores anything after the last replicated transaction);
- on `ubuntu:24.04`: the same install, with ufw installed and active, adding exactly the two port rules, leaving other ufw rules in place, writing no `inet capsule_coord` table, and printing `firewall` `ufw`; re-running adds no duplicate rules;
- `--no-firewall` on either distribution: no nftables table, no ufw rule, and `firewall` `none`; `--no-firewall` with `--upgrade` exits 2;
- the script refusing other distributions (including `debian:11` and `ubuntu:22.04`) and making no network requests besides the Litestream download.
