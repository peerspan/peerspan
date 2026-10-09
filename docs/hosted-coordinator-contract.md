# Hosted coordinator contract

Roadmap milestone 8. The design and its settled decisions are in the [hosted coordinator proposal](hosted-coordinator-proposal.md). This contract grows one section per slice. `capsule-coord` is Go-only; host behavior applies to Go and Rust.

## Slice 1: operations

Decisions recorded in the proposal: one VM; key in the database with encrypted backups; a loopback health and metrics endpoint and structured logs.

### Ops listener

`capsule-coord run --listen HOST:PORT --ops-listen HOST:PORT` also serves plain HTTP on the ops address. The flag is optional; without it nothing extra listens.
- HOST must be a loopback IP literal (`127.0.0.0/8` or `::1`). Anything else makes `run` exit 2 with `--ops-listen must be a loopback address` before listening on either address.
- `GET /healthz` returns 200 `{"status": "ok", "id": COORDINATOR_ID}` when a database read completes within 1 second, else 503 `{"status": "unavailable", "id": COORDINATOR_ID}`.
- `GET /metrics` returns the Prometheus text exposition format (`text/plain; version=0.0.4`).
- Other paths return 404 and other methods 405. The ops listener never serves the coordination API, and the coordination port never serves these paths (404).

**Metrics.** These names, types, and labels are the contract. Others may be added, such as Go runtime and process metrics. No label value is a network ID, host ID, person ID, or IP address.

| Name | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `capsule_coord_info` | gauge, always 1 | `version` | The build's version string. |
| `capsule_coord_networks` | gauge | — | Registered networks. |
| `capsule_coord_member_hosts` | gauge | — | Current member hosts across networks, excluding revoked and departed hosts. |
| `capsule_coord_relay_connections` | gauge | `alpn` | Open relay connections, by negotiated ALPN. |
| `capsule_coord_requests_total` | counter | `route`, `code` | Coordination API requests by route template (such as `/coord/v1/networks/{network}/sync`) and HTTP status. Unmatched paths use route `other`. |
| `capsule_coord_request_seconds` | histogram | `route` | Request duration, same routes. |
| `capsule_coord_relay_bytes_total` | counter | — | Relayed datagram bytes, as counted for `--relay-bytes-per-month`. |
| `capsule_coord_limit_refusals_total` | counter | `limit` | Refusals with 429, by limit: `members`, `networks_per_ip`, or `relay_bytes`. Relay drops count once per dropped frame. |
| `capsule_coord_changes_notified_total` | counter | — | `changed` frames sent. |

Gauges reflect the database and live connections at scrape time. Counters start at 0 when the process starts.

### Logs

`run` writes one JSON object per line to stderr, replacing the earlier startup text. Every line has `time` (RFC 3339 with fractional seconds, UTC), `level` (`info` or `error`), and `msg`:
- `start`: `id`, `listen`, and `ops_listen` (null without the flag), once listening.
- `stop`: on shutdown, after connections close.
- `request`: one per coordination API request, after the response: `method`, `route` (the template above), `status`, `duration_ms`, and `network` and `host` when known (the path's network ID, and the client certificate's host ID).
- `relay`: one when a relay connection closes: `host`, `alpn`, `bytes_in`, `bytes_out`, `duration_ms`.
- `error`: `error`, a description for the operator, and `network` and `host` when known.

Logs never contain IP addresses or ports of clients, statement or request bodies, keys or signatures, invite tokens, candidates, or relayed payloads. `listen` and `ops_listen` in `start` are the coordinator's own addresses.

### Backup and restore

`capsule-coord [--state DIR] backup FILE` writes a consistent copy of the database, including the private key, while a coordinator runs or not. It does not take the state lock.
- It writes to a temporary file in FILE's directory with mode 0600 and renames it into place. If FILE already exists it exits 1 and changes nothing.
- It prints `{"file": ABSOLUTE_PATH, "bytes": N, "id": COORDINATOR_ID, "user_version": V}` to stdout.
- Without a database in the state directory it exits 1.

`capsule-coord [--state DIR] restore FILE` installs a backup as the state's database.
- It takes the state lock and exits 1 with `coordinator is running` if it is held.
- It checks FILE: SQLite `integrity_check` returns `ok`, the identity row exists, and its `user_version` is one this build opens. Otherwise it exits 1 and changes nothing.
- If the state already has a database, it exits 1 unless `--replace` is given. With `--replace`, the previous database is kept as `coord.db.replaced-TIMESTAMP` (UTC, `YYYYMMDDTHHMMSSZ`) in the state directory.
- It creates the state directory (0700) if needed, writes `coord.db` (0600) through a temporary file and rename, removes stale `-wal` and `-shm` files, and prints `{"id": COORDINATOR_ID, "user_version": V, "replaced": PATH_OR_NULL}`.

A restored coordinator has the backup's identity, so hosts that pin its key keep working when it serves the same address. Changes made after the backup are lost until slice 3 adds re-submission; the runbook keeps that window small with continuous replication.

### Deployment files

`deploy/coordinator/` holds:
- `capsule-coord.service`: a systemd system unit running `capsule-coord --state /var/lib/capsule-coord run --listen ${CAPSULE_COORD_LISTEN} --ops-listen 127.0.0.1:9464` and the limit flags from an `EnvironmentFile`, as a dedicated user, with `StateDirectory=capsule-coord` (mode 0700), `Restart=on-failure`, and sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and no added capabilities when the port is 1024 or above).
- `capsule-coord.env.example`: the environment file's variables with comments.
- `litestream.yml` and `litestream.service`: continuous replication of `/var/lib/capsule-coord/coord.db` to an S3-compatible bucket, with replicas encrypted at rest and credentials from an environment file.
- `README.md`, the runbook: provisioning a VM with a static address and DNS name; opening TCP and UDP on the coordination port only; installing the binary and units; reading the key with `capsule-coord info` for `CAPSULE_COORDINATOR_KEY`; upgrades (replace the binary, restart, check `/healthz`); a restore drill from Litestream and from a `backup` file; alerts on `/healthz`, request errors, limit refusals, and disk; keeping an offline encrypted `backup` file after every key change; and, until slices 2 and 3, the warning that a leaked key cannot yet be replaced.

### Verification

`conformance/coord_ops.py` is written from this contract by an author independent of the implementation. It runs the Go coordinator with Go and Rust hosts and covers:
- the ops listener: `/healthz` shape, 404 and 405, the coordination port not serving ops paths, and refusal of a non-loopback `--ops-listen`;
- metrics: every listed name with its type and labels; `networks` and `member_hosts` after create, join, and revocation; `requests_total` for sync; `relay_connections` with relayed hosts; `relay_bytes_total` increasing with relayed messages; `limit_refusals_total` with `--max-members`; `changes_notified_total` after a policy change; and no label value equal to any network, host, or person ID or `127.0.0.1`;
- logs: every stderr line is a JSON object with the fields above; `start`, `request` for create, join, and sync, `relay`, and `stop`; and no client address, invite token, statement body, key, or message content anywhere in stderr;
- backup while hosts sync and relay continuously: the copy is 0600, opens, and has the same `id`; an existing FILE is refused;
- restore: refused while running, refused over an existing database without `--replace`, refused for a corrupt or non-coordinator file; with `--replace`, the previous database kept; then, a coordinator started on the restored state at the same address, Go and Rust hosts sync, join with a fresh invite, and exchange relayed messages without any host action;
- the deployment files: `systemd-analyze verify` on the unit where available, and `litestream.yml` parsing as YAML with the database path and an encrypted replica.
