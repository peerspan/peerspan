# Running the hosted coordinator

This runbook runs one `capsule-coord` on one Linux VM as a systemd service, with continuous encrypted replication of its database by Litestream. The behavior it relies on is in the [hosted coordinator contract](../../docs/hosted-coordinator-contract.md); the design is in the [proposal](../../docs/hosted-coordinator-proposal.md).

The coordinator is trusted for availability only: it cannot admit hosts or change access. Its private key, which every host pins, lives inside `coord.db`. Whoever holds the database holds the key, so treat `coord.db`, every `backup` file, and the Litestream bucket as secrets.

> **Moving the coordinator.** Hosts pin the coordinator's address and key. A signed successor (below) moves every network on this coordinator to a new address, a new key, or both, and hosts follow it on their next sync. A successor needs the current key, so losing the key without a backup still strands every network until administrators move their networks with `capsule network move`, which is why this runbook keeps two independent copies.

## Files

| File | Installed as |
| --- | --- |
| `capsule-coord.service` | `/etc/systemd/system/capsule-coord.service` |
| `capsule-coord.env.example` | `/etc/capsule-coord/capsule-coord.env` |
| `litestream.yml` | `/etc/capsule-coord/litestream.yml` |
| `litestream.service` | `/etc/systemd/system/litestream.service` |
| `install.sh` | not installed; run from the extracted release archive ([Hetzner Cloud](#hetzner-cloud)) |

The service runs `capsule-coord --state /var/lib/capsule-coord run` as the `capsule-coord` user, with the coordination address and limits from the environment file and the ops listener (`/healthz`, `/metrics`) on `127.0.0.1:9464`. It logs one JSON object per line to the journal. Logs carry no client addresses, keys, tokens, or payloads.

## Hetzner Cloud

The hosted coordinator runs on Hetzner Cloud, installed with `install.sh` from a release archive over SSH. Every step that touches the outside world (the Cloud Console or `hcloud`, DNS, the bucket, copying files) is the owner's, with the owner's credentials. These steps use `coord.example.com` for the owner's DNS name and port 443 for TCP (coordination and relay) and UDP (address discovery); the sections after this one describe the same pieces by hand.

**The release archive.** On a Linux build machine of the server's architecture (x86-64 for CX servers, arm64 for CAX):

```sh
scripts/package-coordinator.sh VERSION
# dist/capsule-coord-VERSION-linux-amd64.tar.gz and its .sha256
```

It builds `capsule-coord` with `capsule_coord_info{version="VERSION"}` and packs `bin/capsule-coord`, `share/capsule-coord/deploy/` (this directory, `install.sh` included), and `release.json` (`version`, `os`, `architecture`, `source_revision`). It refuses to overwrite an existing archive unless `CAPSULE_PACKAGE_OVERWRITE=1` is set.

**What `install.sh` does.** Run as root on Debian 12 or Ubuntu 24.04 from the extracted archive, `install.sh --listen 0.0.0.0:443`:
- creates the `capsule-coord` system user, installs `/usr/local/bin/capsule-coord`, both units, `/etc/capsule-coord/litestream.yml`, and `/etc/capsule-coord/capsule-coord.env` from the example with `CAPSULE_COORD_LISTEN` set (an existing env file is kept, and must name the same `--listen`), and the state directory (0700);
- for a port below 1024, installs the unit with `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` and `AmbientCapabilities=CAP_NET_BIND_SERVICE` and no other capability;
- downloads Litestream v0.5.17 from its GitHub release and checks the archive against the SHA-256 the release publishes in `checksums.txt` (pinned in the script) before installing `/usr/local/bin/litestream`; `--litestream-archive FILE` uses a copy of that same archive instead, checked the same way;
- sets up the firewall in one of three ways, reported as `firewall` in its output:
  - `nftables` (the default): loads a table, `inet capsule_coord` in `/etc/capsule-coord/nftables.nft` and included from `/etc/nftables.conf`, that accepts inbound TCP 22, TCP and UDP on the coordination port, established traffic, loopback (for `/healthz`), and IPv6 neighbor discovery, and drops everything else; it enables `nftables.service` so the rules return at boot. This drops every other service's traffic, so use it only on a VM that runs nothing else;
  - `ufw`, when ufw is active: adds `ufw allow PORT/tcp` and `PORT/udp` (commented `capsule-coord`) and leaves the rest of ufw alone;
  - `none`, with `--no-firewall`: changes no firewall; open TCP and UDP on the port yourself;
- enables and starts `capsule-coord`, waits up to 10 seconds for `/healthz`, and enables `litestream` only when both `/etc/capsule-coord/litestream.env` and `/etc/capsule-coord/litestream-sse.key` exist (it says on stderr when they do not);
- prints `{"id", "public_key", "listen", "litestream", "firewall"}` on stdout, with `litestream` either `enabled` or `not configured`.

Running it again with the same arguments changes nothing and prints the same identity. It never generates or prints the private key, contacts nothing but the Litestream download, refuses any system other than Debian 12 and Ubuntu 24.04, and refuses to replace a different installed binary: that is `install.sh --upgrade`.

### 1. Server

In the Cloud Console (or with `hcloud`), create a **CX22** (or larger) server running **Debian 12**, in the location you will use for Object Storage (for example `fsn1`), with a primary IPv4 and a primary IPv6 address and your SSH key. Create a **Cloud Firewall** with the same rules as `install.sh`, and apply it to the server:

| Direction | Protocol | Port | Sources |
| --- | --- | --- | --- |
| Inbound | TCP | 22 | your administration addresses (or any) |
| Inbound | TCP | 443 | any IPv4 and IPv6 |
| Inbound | UDP | 443 | any IPv4 and IPv6 |

Leave outbound open: Litestream reaches Object Storage over HTTPS. The primary IPs stay with the server while they are assigned to it, so DNS can name them. Do not open `9464`.

`install.sh` needs `curl` (or `wget`), and `nft` for its own firewall table, on the server, and installs no packages itself; if either is missing, run `apt-get install nftables curl` first.

### 2. Object Storage and the SSE-C key

Create an Object Storage bucket in the **same location**, private (no public access), for example `capsule-coord-replica`, and S3 credentials for it. Hetzner Object Storage supports SSE-C and does not keep the key; it does not support copying SSE-C encrypted objects, which Litestream v0.5.17 never does (it only puts, uploads in parts, gets, lists, and deletes).

On the server, as root, generate the 32-byte SSE-C key and write the environment file:

```sh
install -d -m 0755 /etc/capsule-coord
(umask 077; head -c 32 /dev/urandom | base64 > /etc/capsule-coord/litestream-sse.key)
cat /etc/capsule-coord/litestream-sse.key    # copy it into your password manager now

(umask 077; cat > /etc/capsule-coord/litestream.env) <<'ENV'
LITESTREAM_ACCESS_KEY_ID=...
LITESTREAM_SECRET_ACCESS_KEY=...
LITESTREAM_BUCKET=capsule-coord-replica
LITESTREAM_PATH=coord
LITESTREAM_ENDPOINT=https://fsn1.your-objectstorage.com
LITESTREAM_REGION=fsn1
ENV
```

`install.sh` gives the key to the `capsule-coord` user with mode 0600 and keeps the environment file root-only (0600). **Without the key, the replicas cannot be read**, restores included: keep it in the password manager as well as on the server. To install without replication for now, skip this step; `install.sh` reports `"litestream": "not configured"`, and running it again after this step enables Litestream.

### 3. DNS

At your DNS provider, create **A** and **AAAA** records for `coord.example.com` with the server's primary IPv4 and IPv6 addresses. `0.0.0.0:443` in the next step serves both: `capsule-coord` binds the IPv6 wildcard, which accepts IPv4 as well. Check from elsewhere with `dig +short coord.example.com A` and `AAAA`.

### 4. Install

From the build machine:

```sh
sha256sum -c capsule-coord-VERSION-linux-amd64.tar.gz.sha256
scp capsule-coord-VERSION-linux-amd64.tar.gz root@coord.example.com:
ssh root@coord.example.com
```

On the server:

```sh
tar -xzf capsule-coord-VERSION-linux-amd64.tar.gz
capsule-coord-VERSION-linux-amd64/share/capsule-coord/deploy/install.sh --listen 0.0.0.0:443
# {"id": "coord_...", "public_key": "...", "listen": "0.0.0.0:443", "litestream": "enabled"}
```

Record `public_key`: it is `CAPSULE_COORDINATOR_KEY` for every release bundle, and `capsule-coord --state /var/lib/capsule-coord info` prints it again at any time. Then check:

```sh
systemctl status capsule-coord litestream
curl -fsS --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9464/healthz
journalctl -u litestream -n 20      # no errors; replication about every second
nft list table inet capsule_coord
```

**Upgrades** use a newer archive the same way: extract it and run `install.sh --upgrade`. It takes no other arguments, replaces the binary, restarts, waits for `/healthz`, and prints the same JSON with the same identity. If the new binary does not become healthy within 10 seconds, it restores the previous binary, restarts it, and exits 1. Take a `backup` first (step 5), since a new build may upgrade the database in a way an older one refuses.

### 5. First offline backup

As in [Offline backup](#offline-backup): write a `backup` file on the server, encrypt it there, copy the encrypted file to offline storage, and remove both copies from the server. Check that `id` in its output matches the printed `id`. Do this again after every key change.

### 6. Release bundles

Build the release bundles for the hosted coordinator, with `KEY` the `public_key` from step 4:

```sh
CAPSULE_COORDINATOR=coord.example.com:443 CAPSULE_COORDINATOR_KEY=KEY scripts/package-release.sh go VERSION
CAPSULE_COORDINATOR=coord.example.com:443 CAPSULE_COORDINATOR_KEY=KEY scripts/package-release.sh rust VERSION
```

`network create` in those bundles then uses this coordinator without `--coordinator`.

### 7. Restore drill before announcing

Before announcing, restore the replica onto a **second, throwaway** server and check that it comes back with the same identity. The drill server holds the coordinator's key once restored: delete it afterwards, and do not point DNS at it.

1. Create a second CX22 on Debian 12 as in step 1, with the same Cloud Firewall. Do not create its Litestream files yet: with them, `install.sh` would start replicating the drill server's own new database into the production bucket path.
2. Copy the same archive and run `install.sh --listen 0.0.0.0:443`. It reports `"litestream": "not configured"` and a new, throwaway identity.
3. Write `/etc/capsule-coord/litestream.env` and `/etc/capsule-coord/litestream-sse.key` with the same values as step 2, the key from the password manager. Then restore:

   ```sh
   systemctl stop capsule-coord
   set -a; . /etc/capsule-coord/litestream.env; set +a
   litestream restore -config /etc/capsule-coord/litestream.yml \
     -o /var/lib/capsule-coord/restored.db /var/lib/capsule-coord/coord.db
   chown capsule-coord:capsule-coord /var/lib/capsule-coord/restored.db
   chmod 0600 /var/lib/capsule-coord/restored.db
   runuser -u capsule-coord -- capsule-coord --state /var/lib/capsule-coord restore --replace /var/lib/capsule-coord/restored.db
   rm /var/lib/capsule-coord/restored.db /var/lib/capsule-coord/coord.db.replaced-*
   systemctl start capsule-coord
   curl -fsS --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9464/healthz
   capsule-coord --state /var/lib/capsule-coord info
   ```

   `/healthz` and `info` must report the production `id` and `public_key`. Without the key file, or with another key, `litestream restore` fails: the bucket holds only ciphertext.
4. For a drill, stop here: leave `litestream` disabled (it would write to the production replica path), then delete the server. A drill can point a test host at it by IP to see it serve, but hosts that pin `coord.example.com` must not reach it.

**A real recovery** is the same on a new server, followed by a new `LITESTREAM_PATH` in `litestream.env` (such as `coord-2`, so the restored database starts a fresh replica and the old one stays intact until the new one is confirmed), `litestream reset -config /etc/capsule-coord/litestream.yml /var/lib/capsule-coord/coord.db`, running `install.sh --listen 0.0.0.0:443` again, which now reports the production identity and `"litestream": "enabled"`, and moving the DNS records (or the primary IPs) to the new server. Member hosts then sync with it as before and re-submit anything after the last replicated transaction ([Restore](#restore)).

### On a shared VM

The coordinator can share a VM, such as an existing DigitalOcean droplet, if that VM has a static public address, nothing already serving the chosen port over TCP or UDP, and only administrators you trust with the coordinator's key. Nothing may sit in front of the port (no proxy or TLS terminator). Then:
- Choose a free port before building bundles, since hosts pin it: 443 if nothing else serves it, or for example 7400.
- With ufw active (common on Ubuntu), run `install.sh --listen 0.0.0.0:PORT`: it adds the two ufw rules and nothing else. Without ufw, always pass `--no-firewall` and open TCP and UDP on the port in the firewall you use: the default `nftables` mode would drop the other services' traffic.
- Replication still needs an SSE-C bucket (step 2), which can be at any provider that supports it, such as Hetzner Object Storage or AWS S3; check before using another. DigitalOcean Spaces works: with Litestream v0.5.17 it accepts SSE-C on single and multipart uploads and refuses reads, HEAD requests, and restores without the key or with another one (`LITESTREAM_ENDPOINT=https://REGION.digitaloceanspaces.com`). s3cmd cannot send an SSE-C key, so test a provider with Litestream itself.

The steps above are otherwise the same. Skip the Cloud Firewall in step 1 unless the provider has an equivalent, in which case open the same port there.

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
curl -fsS --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9464/healthz
```

`StateDirectory=` creates `/var/lib/capsule-coord` (mode 0700, owned by `capsule-coord`); the first start creates `coord.db` and the coordinator's key. Do not switch the unit to `DynamicUser=`: Litestream needs the same user, and `capsule-coord` refuses a state directory reached through a symbolic link.

**A port below 1024.** The unit adds no capabilities. `install.sh` installs it with both capability lines set to `CAP_NET_BIND_SERVICE` for such a port. By hand, to listen on, for example, port 443, add a drop-in with `systemctl edit capsule-coord`:

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
chmod 0600 /etc/capsule-coord/litestream-sse.key
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

Litestream keeps its tracking files in `/var/lib/capsule-coord/.coord.db-litestream` and replicates about every second. Changes in the last seconds before losing the VM can be lost; hosts re-sync addresses on their own and re-submit the signed statements the coordinator lacks (see Restore).

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
curl -fsS --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9464/healthz
curl -fsS http://127.0.0.1:9464/metrics | grep capsule_coord_info
```

A restart is a short outage; hosts keep working on their stored maps and retry syncs. A new build may upgrade the database on first start, after which an older build refuses it; take a `backup` before upgrading so a rollback can `restore` it.

## Restore

Practice both restores on a scratch VM (or a scratch state directory) before they are needed, and repeat the drill after major upgrades. A restored coordinator has the backup's identity, so hosts keep working when it serves the same address. Every member host compares each map with the signed statements it holds and re-submits what the coordinator lacks through `POST /coord/v1/networks/import`. Members, persons, bindings, administrators, groups, policies, revocations, and moves can reappear within a sync interval of the members that hold them; each member's address and candidates wait for that member's next sync.

An invite-backed host or person missing from the backup can be imported automatically only while its invite remains valid, or with independent admission authority. A holder's backdated `joined_at` does not prove the invite was redeemed. If its invite has expired, the root holder or a current administrator must issue a fresh `network admit-host` or `network admit-person` for the existing key; a current-root host attestation also permits host recovery. Memberships already in the backup do not expire. The same rule applies when moving to a coordinator that lacks these records.

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
curl -fsS --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9464/healthz
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

Check that `/healthz` reports the expected `id`, that `capsule_coord_networks` and `capsule_coord_member_hosts` match what you expect, and that `capsule_coord_requests_total` for `/coord/v1/networks/{network}/sync` grows as hosts sync, and `capsule_coord_requests_total` for `/coord/v1/networks/import` shows members re-submitting what the backup lacked. Remove the `coord.db.replaced-*` file once the restore is confirmed; it also contains the key.

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
curl -fsS --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9464/healthz
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
curl -fsS --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9464/healthz          # reports the new identity's id
capsule-coord --state /var/lib/capsule-coord info # note the new public_key
```

Build new release bundles with the new address and `CAPSULE_COORDINATOR_KEY` set to the new key, and take a new offline encrypted `backup` (see above). Restoring a backup from before a successor loses that identity, so hosts that already switched cannot reach the restored coordinator. Watch `capsule_coord_identity_hosts{sequence="N"}`; once it has been 0 for 30 days, remove the `--previous-listen` flag, restart, and close the old port. Hosts that come back after that cannot follow and need their administrator to move the network with `capsule network move`.

**Leaked key.** Sign a successor with a new key at once (the key change above) and restart. Hosts that reach this coordinator first follow it. Whoever holds the leaked key can sign a competing successor to a coordinator of their own, but a coordinator is trusted for availability only: it can divert hosts to a coordinator that denies them service, not change membership or access. Administrators recover diverted networks with `capsule network move`, signed by the network root or a delegated administrator, which takes precedence over any successor. Take a new offline backup: a backup from before a successor restores a coordinator without it, which hosts that already switched cannot reach.

## Monitor

Scrape `http://127.0.0.1:9464/metrics` with a local agent (for example, a Prometheus agent or Grafana Alloy on the VM that forwards to your monitoring), and alert on:
- **Health:** `/healthz` not 200 for 2 minutes, or the service not active. A 503 means a database read took over a second.
- **Request errors:** `rate(capsule_coord_requests_total{code=~"5.."}[10m]) > 0`; the journal has an `error` line with the cause.
- **Limit refusals:** `increase(capsule_coord_limit_refusals_total[1h]) > 0` by `limit` (`members`, `networks_per_ip`, `relay_bytes`): a network outgrowing the defaults, or abuse.
- **Disk:** the filesystem holding `/var/lib/capsule-coord` above 80% used. A full disk stops every write, including syncs.
- **Replication:** `litestream.service` not active, or `error` in its journal. Litestream serves its own metrics only if `addr` is set in `litestream.yml`; keep it on loopback if you add it.

Useful gauges: `capsule_coord_relay_connections` by ALPN, `capsule_coord_relay_bytes_total`, and, after a successor, `capsule_coord_identity_hosts` by sequence. Metric labels never carry network, host, or person IDs.
