# Running the hosted coordinator

This runbook runs one `capsule-coord` on one Linux VM as a systemd service, with continuous encrypted replication of its database by Litestream. The behavior it relies on is in the [hosted coordinator contract](../../docs/hosted-coordinator-contract.md); the design is in the [proposal](../../docs/hosted-coordinator-proposal.md).

The coordinator is trusted for availability only: it cannot admit hosts or change access. Its private key, which every host pins, lives inside `coord.db`. Whoever holds the database holds the key, so treat `coord.db`, every `backup` file, and the Litestream bucket as secrets.

> **Moving the coordinator.** Hosts pin the coordinator's address and key. A signed successor (below) moves every network on this coordinator to a new address, a new key, or both, and hosts follow it on their next sync. A successor needs the current key, so losing the key without a backup still strands every network until administrators move their networks (milestone 8 slice 3), which is why this runbook keeps two independent copies.

## Files

| File | Installed as |
| --- | --- |
| `capsule-coord.service` | `/etc/systemd/system/capsule-coord.service` |
| `capsule-coord.env.example` | `/etc/capsule-coord/capsule-coord.env` |
| `litestream.yml` | `/etc/capsule-coord/litestream.yml` |
| `litestream.service` | `/etc/systemd/system/litestream.service` |

The service runs `capsule-coord --state /var/lib/capsule-coord run` as the `capsule-coord` user, with the coordination address and limits from the environment file and the ops listener (`/healthz`, `/metrics`) on `127.0.0.1:9464`. It logs one JSON object per line to the journal. Logs carry no client addresses, keys, tokens, or payloads.

## Provision

1. Create one VM (Linux with systemd, x86-64 or arm64) with a **static public address**. Give it a DNS name, such as `coord.example.com`, with A (and AAAA, if it has IPv6) records for that address. Hosts store the coordinator address at create and join; changing the name or port later takes a [successor](#successors).
2. Choose the coordination port; these files use `7400`. Hosts reach the coordinator directly: no load balancer, proxy, or TLS terminator may sit in front, since hosts authenticate with client certificates and the registration limit counts real source addresses.
3. Firewall: allow inbound **TCP and UDP on the coordination port only** (TCP for the API and relay, UDP for address discovery), plus SSH from your administration addresses. Do not open `9464`; the ops listener only binds loopback, and `capsule-coord` refuses any other ops address.
4. Create an S3-compatible bucket for Litestream that is **private**, with no public access, and an access key limited to that bucket. The provider must support server-side encryption with customer-provided keys (SSE-C); AWS S3 does, and other providers vary, so check before choosing one.

## Install

As root, on the VM:

```sh
# A dedicated system user; both services run as it.
useradd --system --home-dir /var/lib/capsule-coord --no-create-home --shell /usr/sbin/nologin capsule-coord

# The binary, built from the Go source (go/cmd/capsule-coord) for the VM's
# architecture. The version appears in capsule_coord_info:
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go -C go build -trimpath \
#     -ldflags "-X github.com/Cerebral-Systems/capsule/go/internal/coord.Version=VERSION" \
#     -o capsule-coord ./cmd/capsule-coord
install -m 0755 capsule-coord /usr/local/bin/capsule-coord

install -d -m 0755 /etc/capsule-coord
install -m 0644 capsule-coord.env.example /etc/capsule-coord/capsule-coord.env
$EDITOR /etc/capsule-coord/capsule-coord.env    # set CAPSULE_COORD_LISTEN and the limits
install -m 0644 capsule-coord.service /etc/systemd/system/capsule-coord.service

systemctl daemon-reload
systemctl enable --now capsule-coord
curl -fsS http://127.0.0.1:9464/healthz
```

`StateDirectory=` creates `/var/lib/capsule-coord` (mode 0700, owned by `capsule-coord`); the first start creates `coord.db` and the coordinator's key. Do not switch the unit to `DynamicUser=`: Litestream needs the same user, and `capsule-coord` refuses a state directory reached through a symbolic link.

**A port below 1024.** The unit adds no capabilities. To listen on, for example, port 443, add a drop-in with `systemctl edit capsule-coord`:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

### Read the key

```sh
capsule-coord --state /var/lib/capsule-coord info
```

prints `id` and `public_key`, which are the latest identity's, and `identities`: every identity in order with its `sequence`, `id`, `public_key`, and `address` (null for identity 0). `info` reads without the state lock, so it works while the service runs. Release bundles are built with the address and this key:

```sh
CAPSULE_COORDINATOR=coord.example.com:7400 \
CAPSULE_COORDINATOR_KEY=PUBLIC_KEY \
  scripts/package-release.sh go VERSION
```

### Litestream

These files are written for **Litestream v0.5.17**, installed from the release tarball (the `.deb` package installs its own `litestream.service`, which this unit replaces):

```sh
curl -fsSLO https://github.com/benbjohnson/litestream/releases/download/v0.5.17/litestream-0.5.17-linux-x86_64.tar.gz
# Check the archive against the checksum published with the release, then:
tar -xzf litestream-0.5.17-linux-x86_64.tar.gz litestream
install -m 0755 litestream /usr/local/bin/litestream
```

**Encryption at rest.** Litestream v0.5 has no client-side encryption (the age support of v0.3 was removed and is refused at startup), so replicas are encrypted with S3 server-side encryption using a customer-provided key (SSE-C): every object is encrypted by the provider with a key Litestream sends on each request, which the provider does not keep. Nothing in the bucket, including Litestream's own restore, can be read without the key. Generate it once and keep a copy offline with the backup files below:

```sh
head -c 32 /dev/urandom | base64 > /etc/capsule-coord/litestream-sse.key
chown capsule-coord:capsule-coord /etc/capsule-coord/litestream-sse.key
chmod 0400 /etc/capsule-coord/litestream-sse.key
```

Credentials and the bucket come from `/etc/capsule-coord/litestream.env` (mode 0600, owned by root), which `litestream.service` reads. Litestream reads the two credential variables itself and expands the others in `litestream.yml`:

```sh
LITESTREAM_ACCESS_KEY_ID=...
LITESTREAM_SECRET_ACCESS_KEY=...
LITESTREAM_BUCKET=capsule-coord-replica
LITESTREAM_PATH=coord
# Empty for AWS S3; the provider's endpoint URL otherwise.
LITESTREAM_ENDPOINT=
LITESTREAM_REGION=us-east-1
```

Then:

```sh
install -m 0644 litestream.yml /etc/capsule-coord/litestream.yml
install -m 0644 litestream.service /etc/systemd/system/litestream.service
systemctl daemon-reload
systemctl enable --now litestream
journalctl -u litestream -n 20
```

Litestream keeps its tracking files in `/var/lib/capsule-coord/.coord.db-litestream` and replicates about every second. Changes in the last seconds before losing the VM can be lost; hosts re-sync addresses on their own, and slice 3 adds re-submission of signed statements.

### Offline backup

After installing, and **after every key change** (each `successor --new-key`), write a `backup` file, encrypt it on the VM, and keep the encrypted copy offline, together with a copy of `litestream-sse.key`:

```sh
sudo -u capsule-coord capsule-coord --state /var/lib/capsule-coord backup /var/lib/capsule-coord/offline.db
gpg --symmetric --cipher-algo AES256 -o /root/coord-$(date -u +%Y%m%d).db.gpg /var/lib/capsule-coord/offline.db
shred -u /var/lib/capsule-coord/offline.db
# Copy /root/coord-YYYYMMDD.db.gpg to offline storage, then remove it from the VM.
```

`backup` works while the service runs, writes the file with mode 0600, refuses to overwrite an existing file, and prints `{"file", "bytes", "id", "user_version"}`. Check that `id` is the coordinator ID the bundles use. Keep the encrypted copy and its passphrase apart, and never let the unencrypted file leave the VM.

## Upgrade

```sh
install -m 0755 capsule-coord /usr/local/bin/capsule-coord.new
mv /usr/local/bin/capsule-coord.new /usr/local/bin/capsule-coord
systemctl restart capsule-coord
curl -fsS http://127.0.0.1:9464/healthz
curl -fsS http://127.0.0.1:9464/metrics | grep capsule_coord_info
```

A restart is a short outage; hosts keep working on their stored maps and retry syncs. A new build may upgrade the database on first start, after which an older build refuses it; take a `backup` before upgrading so a rollback can `restore` it.

## Restore

Practice both restores on a scratch VM (or a scratch state directory) before they are needed, and repeat the drill after major upgrades. A restored coordinator has the backup's identity, so hosts keep working when it serves the same address. Changes made after the backup are lost until slice 3 adds re-submission.

`restore` refuses to run while the coordinator holds the state lock, checks the file (SQLite `integrity_check`, the identity row, a supported version), refuses an existing database unless `--replace` is given, keeps the previous database as `coord.db.replaced-YYYYMMDDTHHMMSSZ`, and prints `{"id", "user_version", "replaced"}`.

**From Litestream:**

```sh
systemctl stop litestream capsule-coord
set -a; . /etc/capsule-coord/litestream.env; set +a
litestream restore -config /etc/capsule-coord/litestream.yml \
  -o /var/lib/capsule-coord/restored.db /var/lib/capsule-coord/coord.db
chown capsule-coord:capsule-coord /var/lib/capsule-coord/restored.db
chmod 0600 /var/lib/capsule-coord/restored.db
sudo -u capsule-coord capsule-coord --state /var/lib/capsule-coord restore --replace /var/lib/capsule-coord/restored.db
rm /var/lib/capsule-coord/restored.db
# Litestream's tracking files describe the replaced database: clear them so it
# takes a fresh snapshot. Optionally set a new LITESTREAM_PATH first to keep
# the old replica's history untouched.
litestream reset -config /etc/capsule-coord/litestream.yml /var/lib/capsule-coord/coord.db
systemctl start capsule-coord litestream
curl -fsS http://127.0.0.1:9464/healthz
```

On a new VM, install everything as above but restore before the first `systemctl start capsule-coord`, without `--replace`, then move the DNS name (or the static address) to the new VM.

**From a `backup` file:** copy the encrypted file to the VM, then:

```sh
systemctl stop litestream capsule-coord
gpg --decrypt -o /var/lib/capsule-coord/offline.db coord-YYYYMMDD.db.gpg
chown capsule-coord:capsule-coord /var/lib/capsule-coord/offline.db
chmod 0600 /var/lib/capsule-coord/offline.db
sudo -u capsule-coord capsule-coord --state /var/lib/capsule-coord restore --replace /var/lib/capsule-coord/offline.db
shred -u /var/lib/capsule-coord/offline.db
set -a; . /etc/capsule-coord/litestream.env; set +a
litestream reset -config /etc/capsule-coord/litestream.yml /var/lib/capsule-coord/coord.db
systemctl start capsule-coord litestream
```

Check that `/healthz` reports the expected `id`, that `capsule_coord_networks` and `capsule_coord_member_hosts` match what you expect, and that `capsule_coord_requests_total` for `/coord/v1/networks/{network}/sync` grows as hosts sync. Remove the `coord.db.replaced-*` file once the restore is confirmed; it also contains the key.

## Successors

A coordinator has an ordered list of identities, numbered from 0. Identity 0 is the key generated at first start. `successor` appends one, signed by the latest identity's key, naming a new address and either the latest key or, with `--new-key`, a new one. Hosts that sync verify the chain of successors from the key they pin, sync with the new address and key, and switch only once that sync succeeds; until then they keep their pin and show the new coordinator as `coordinator_pending` in `network list`. A successor grants nothing beyond availability.

`successor` takes the state lock, so stop the service first; it refuses with `coordinator is running` otherwise. It refuses an address that is not `HOST:PORT`, and, without `--new-key`, the latest identity's own address (`nothing changes`). It prints `{"sequence", "id", "public_key", "address", "successor"}`. Take a `backup` before running it, as for an upgrade.

`run --listen` presents the latest identity. `--previous-listen SEQUENCE=HOST:PORT`, repeatable, also serves an earlier identity on another address with its own key and STUN responder; every listener shares the database and the relay. Responses to hosts that reached an earlier identity carry the chain to the latest. The `start` log line lists the previous listeners, and `capsule_coord_identity_hosts{sequence}` counts the distinct hosts that used each identity's listener in the last 24 hours (since the process started).

**Address change (same key).** For a new DNS name on the same VM and port:

```sh
systemctl stop capsule-coord
sudo -u capsule-coord capsule-coord --state /var/lib/capsule-coord successor --address coord-new.example.com:7400
# Point coord-new.example.com at the VM (keep the old name pointing at it too).
systemctl start capsule-coord
curl -fsS http://127.0.0.1:9464/healthz
```

One listener serves both names, since the key is the same: a host that reaches it by the old name is served the chain and moves to the new name. Keep the old name resolving until hosts have moved. To change the port as well, serve the old port with `--previous-listen 0=0.0.0.0:OLD_PORT` (the sequence of the identity hosts used before) alongside `--listen` on the new one, and open both in the firewall.

**Key change.** Use a new port or address for the new key, since one listener presents one key:

```sh
systemctl stop capsule-coord
sudo -u capsule-coord capsule-coord --state /var/lib/capsule-coord successor --address coord.example.com:7401 --new-key
```

Then set `CAPSULE_COORD_LISTEN=0.0.0.0:7401` in the environment file, and serve the old port for the identity it presented with a drop-in (`systemctl edit capsule-coord`) that clears `ExecStart` and repeats it with `--previous-listen`, where N is that identity's sequence (`info` lists them):

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/capsule-coord --state /var/lib/capsule-coord run --listen ${CAPSULE_COORD_LISTEN} --previous-listen N=0.0.0.0:7400 --ops-listen 127.0.0.1:9464 --max-members ${CAPSULE_COORD_MAX_MEMBERS} --max-networks-per-ip ${CAPSULE_COORD_MAX_NETWORKS_PER_IP} --relay-bytes-per-month ${CAPSULE_COORD_RELAY_BYTES_PER_MONTH}
```

Open TCP and UDP on the new port, then:

```sh
systemctl start capsule-coord
curl -fsS http://127.0.0.1:9464/healthz          # reports the new identity's id
capsule-coord --state /var/lib/capsule-coord info # note the new public_key
```

Build new release bundles with the new address and `CAPSULE_COORDINATOR_KEY` set to the new key, and take a new offline encrypted `backup` (see above). Restoring a backup from before a successor loses that identity, so hosts that already switched cannot reach the restored coordinator. Watch `capsule_coord_identity_hosts{sequence="N"}`; once it has been 0 for 30 days, remove the `--previous-listen` flag, restart, and close the old port. Hosts that come back after that cannot follow and need their administrator to move the network (slice 3).

**Leaked key.** Sign a successor with a new key at once (the key change above) and restart. Hosts that reach this coordinator first follow it. Whoever holds the leaked key can sign a competing successor to a coordinator of their own, but a coordinator is trusted for availability only: it can divert hosts to a coordinator that denies them service, not change membership or access. Administrators recover diverted networks with a root-signed move (slice 3). Take a new offline backup: a backup from before a successor restores a coordinator without it, which hosts that already switched cannot reach.

## Monitor

Scrape `http://127.0.0.1:9464/metrics` with a local agent (for example, a Prometheus agent or Grafana Alloy on the VM that forwards to your monitoring), and alert on:
- **Health:** `/healthz` not 200 for 2 minutes, or the service not active. A 503 means a database read took over a second.
- **Request errors:** `rate(capsule_coord_requests_total{code=~"5.."}[10m]) > 0`; the journal has an `error` line with the cause.
- **Limit refusals:** `increase(capsule_coord_limit_refusals_total[1h]) > 0` by `limit` (`members`, `networks_per_ip`, `relay_bytes`): a network outgrowing the defaults, or abuse.
- **Disk:** the filesystem holding `/var/lib/capsule-coord` above 80% used. A full disk stops every write, including syncs.
- **Replication:** `litestream.service` not active, or `error` in its journal. Litestream serves its own metrics only if `addr` is set in `litestream.yml`; keep it on loopback if you add it.

Useful gauges: `capsule_coord_relay_connections` by ALPN, `capsule_coord_relay_bytes_total`, and, after a successor, `capsule_coord_identity_hosts` by sequence. Metric labels never carry network, host, or person IDs.
