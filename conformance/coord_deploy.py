#!/usr/bin/env python3
"""Exercise the hosted coordinator launch files (milestone 8 slice 4) in throwaway Docker containers.

Written from docs/hosted-coordinator-contract.md ("Slice 4: launch", whose Verification subsection names
this suite) alone, with context from slices 1 to 3 of that contract, the hosted coordinator proposal, and the
coordination contract, independently of the coordinator and host implementations and of the deployment files'
sources. The only deployment files it reads are the ones shipped inside the archive it builds, as an operator
would: `litestream.yml` (to learn which variables the Litestream environment file needs) and the runbook
`README.md` (for the SSE-C key and the restore procedure from the replica).

Needs root, Docker, openssl, tcpdump, and nsenter. Everything runs locally: a `debian:12` image with systemd
as init (built as `peerspan-m8s4-suite-debian12-systemd`), privileged with a private cgroup namespace (the
cgroup v2 setup Docker needs for systemd), on its own bridge network with fixed addresses; a MinIO server
(`cgr.dev/chainguard/minio`, since the upstream MinIO images are no longer published) serving TLS with a CA
the suite generates; an `ubuntu:24.04` image with systemd as init and ufw (built as
`peerspan-m8s4-suite-ubuntu2404-systemd`, ufw's module loading and sysctl file emptied); and `debian:11` and
`ubuntu:22.04` containers for the distribution refusal. Every container, image,
network, and volume the suite creates is named `peerspan-m8s4-suite-*`; all are removed at the end, as are
the base images it pulled, unless `--keep`. Inside the systemd image, units that would act on the shared
machine's kernel through a privileged container (sysctl, binfmt, module loading, audit, udev) are masked.
install.sh, nftables, ufw, and systemctl only ever run inside containers. Hosts run on this machine with HOME
and XDG_CONFIG_HOME redirected under a temporary directory; the real ~/.config/peerspan is never touched.

Sections:

- archive: `scripts/package-coordinator.sh VERSION` writes `dist/peerspan-coord-VERSION-linux-ARCH.tar.gz`
  and `.sha256` (checked with `sha256sum -c` from dist/, as the quick start checks bundles); every member
  under `peerspan-coord-VERSION-linux-ARCH/`; `bin/peerspan-coord` executable; `share/peerspan-coord/deploy/`
  byte for byte the files of the repository's `deploy/coordinator/` (compared by digest), including
  install.sh (executable), the units, the env example, litestream.yml, and README.md; `release.json` with
  exactly version, os `linux`, architecture ARCH, and source_revision (the repository's HEAD); a second run
  with the same VERSION refused with the outputs unchanged, and accepted with PEERSPAN_PACKAGE_OVERWRITE=1
  as package-release.sh does (Q1); a second VERSION built for the upgrade;
- install: in a fresh Debian 12 container, `install.sh --listen 0.0.0.0:443` from the extracted archive:
  exit 0; stdout exactly `{id, public_key, listen, litestream, firewall}` with listen `0.0.0.0:443`, litestream
  `not configured`, firewall `nftables`, and the identity equal to `peerspan-coord info` and `/healthz`; stderr saying Litestream
  is not configured; no private key material in either stream; the static `peerspan-coord` system user;
  `/usr/local/bin/peerspan-coord` equal to the archive's binary; both units installed; the env file; the
  state directory (0700, owned by the user, not a symbolic link) and coord.db (0600); Litestream installed at
  a 0.5 version whose binary equals the published release's (fetched from GitHub by the suite and checked
  against the release's published checksums, when reachable); the installed unit equal to the shipped one
  plus exactly `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
  the running process with exactly that capability in its ambient and bounding sets, running as the user;
  `peerspan-coord` enabled and active, `litestream` disabled and inactive; the coordinator listening on TCP
  and UDP 443 and the ops listener on 127.0.0.1:9464 only; `peerspan_coord_info{version}` equal to VERSION;
- firewall: the input hook is in the table `inet peerspan_coord`, included from /etc/nftables.conf, with
  nftables.service enabled; it drops by default, accepts established traffic, TCP 22, TCP 443, and
  UDP 443, and nothing else (loopback and ICMP accepts reported, Q2); from this machine TCP 443 connects,
  STUN on UDP 443 answers, TCP 22 is refused rather than dropped (the container has no sshd), and TCP 9464,
  TCP 8443, and UDP 9999 are dropped;
- hosts: a Go and a Rust host, relay-only (as coord_ops.py runs them), create and join networks through the
  container's 443 (published on this machine's address on the suite network) both ways. Their CLIs run on this
  machine; each daemon runs in its own network namespace (a plain debian:12 container on its own network,
  with the binary and state mounted), because hosts sharing this machine's interfaces find each other
  directly and the contract asks for relayed messages (Go creator with Rust joiner, and the reverse), see each
  other, and exchange relayed messages both ways while `peerspan_coord_relay_connections` counts both and
  `peerspan_coord_relay_bytes_total` grows;
- re-run: the same command again prints the same JSON and changes nothing: binaries, units, env file (with
  a marker line the suite added, so an existing env file is kept), user, state directory modes, nftables
  ruleset, unit states, and the running service (same InvocationID, Q3);
- upgrade: `install.sh --upgrade` from the second VERSION's archive: exit 0, the same JSON with firewall
  `unchanged`, the nftables ruleset untouched, the new binary
  in place, the service restarted, `peerspan_coord_info{version}` the new VERSION, hosts syncing again;
- failed upgrade: `--upgrade` from an archive whose `peerspan-coord run` never serves: exit 1, the previous
  binary restored, the service active with the same identity and version, hosts syncing;
- upgrade with --no-firewall: `--upgrade --no-firewall` (either order) exits 2 and changes nothing;
- ubuntu with ufw: in an Ubuntu 24.04 container with ufw active and two rules of its own (22/tcp, 8080/tcp), the
  same install checks with firewall `ufw`; `ufw show added` gains exactly two allow rules for 443 over TCP and
  UDP commented peerspan-coord and loses none; the rest of ufw (defaults, logging, its other files) unchanged;
  no `inet peerspan_coord` table and /etc/nftables.conf unchanged (Q12); from this machine 443/tcp connects,
  STUN answers, 8080 is refused (its rule kept), 9464 dropped; a re-run prints the same JSON and adds no
  duplicate; `--upgrade` prints firewall `unchanged` and leaves ufw alone;
- no firewall (debian): `--no-firewall` in a fresh Debian container: firewall `none`, the install checks, no
  table, ruleset, /etc/nftables.conf, and nftables.service unchanged; a re-run the same; `--upgrade
  --no-firewall` exits 2; a default install then loads the table, and `--no-firewall` after it keeps it;
- no firewall (ubuntu): `--no-firewall` with ufw active: firewall `none`, no ufw rule or table, nothing in
  ufw changed (443 stays dropped from outside); `--upgrade --no-firewall` exits 2;
- no outside requests: every install.sh run above with a capture (first install, re-run, both upgrades in
  the Debian container, and the Ubuntu and --no-firewall installs) is captured with tcpdump inside the container's network namespace; the only outward traffic
  initiated is DNS for GitHub release names and TCP 443 to addresses those names resolved to (Q4); the
  only other packets the container sends are replies from port 443;
- litestream: an env file and a 32-byte SSE-C key created as the runbook says, the MinIO CA trusted by the
  container, and install.sh run again: litestream `enabled` and the unit enabled and active, the identity
  unchanged; replicas appear in the bucket; every object refuses a read without SSE-C headers and with a
  wrong key, reads with the key, reports SSE-C, and its plaintext appears nowhere on MinIO's disk;
- restore: after replication settles, Litestream is stopped and a Go host joins (beyond the last replicated
  transaction); the first container is removed; a fresh container at the same address follows the
  runbook's restore procedure from the replica; it serves the same identity, the hosts sync again without
  action, the late member reappears at the coordinator through repair (seen by a Rust host joining with a
  fresh invite), and relayed messages flow;
- other distributions: install.sh in `debian:11` and `ubuntu:22.04` containers (without a network) exits 1
  and creates nothing.

Questions are marked `Q<n>` and listed in the suite-questions file given to the owner. Exits non-zero
listing every failed section.
"""
import argparse
import base64
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))

from coordination import wait_for  # noqa: E402
from coord_ops import Metrics, OpsHost  # noqa: E402
from host_service import die_with_parent, stop_all  # noqa: E402
from peer_messaging import request_id, set_probe, timestamp  # noqa: E402

PREFIX = 'peerspan-m8s4-suite-'
BASE_IMAGE = 'debian:12'
MINIO_IMAGE = 'cgr.dev/chainguard/minio:latest'
UBUNTU_IMAGE = 'ubuntu:24.04'
OTHER_IMAGES = ('debian:11', 'ubuntu:22.04')
SYSTEMD_IMAGE = PREFIX + 'debian12-systemd'
UBUNTU_SYSTEMD_IMAGE = PREFIX + 'ubuntu2404-systemd'
STATE = '/var/lib/peerspan-coord'
ENV_FILE = '/etc/peerspan-coord/peerspan-coord.env'
LITESTREAM_ENV = '/etc/peerspan-coord/litestream.env'
SSE_KEY = '/etc/peerspan-coord/litestream-sse.key'
BINARY = '/usr/local/bin/peerspan-coord'
LISTEN = '0.0.0.0:443'
OPS = '127.0.0.1:9464'
BUCKET = 'peerspan-m8s4-suite-replicas'
MINIO_USER = 'peerspansuite'
MINIO_PASSWORD = secrets.token_hex(16)
CAP_NET_BIND_SERVICE = 1 << 10
INSTALL_FIELDS = {'id', 'public_key', 'listen', 'litestream', 'firewall'}
FIREWALL_VALUES = {'nftables', 'ufw', 'none', 'unchanged'}
# Q4: the contract names "the Litestream download" without a location; Litestream publishes its releases
# (and their SHA-256 checksums) on GitHub, so these names are the download's.
DOWNLOAD_NAMES = re.compile(r'^(github\.com|[a-z0-9.-]+\.github\.com|[a-z0-9.-]+\.githubusercontent\.com)$')

# Packages in the systemd image: what a Debian 12 cloud server has (Q5: nftables, curl, wget, openssl, and
# ca-certificates are assumed present on the Hetzner image, since the script may not install anything).
DOCKERFILE = """FROM debian:12
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update \\
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus nftables curl wget ca-certificates \\
      openssl iproute2 procps tar gzip xz-utils bzip2 unzip less \\
 && apt-get clean && rm -rf /var/lib/apt/lists/* \\
 && systemctl mask systemd-sysctl.service systemd-binfmt.service proc-sys-fs-binfmt_misc.automount \\
      proc-sys-fs-binfmt_misc.mount systemd-modules-load.service kmod-static-nodes.service \\
      systemd-journald-audit.socket getty.target console-getty.service systemd-firstboot.service \\
      systemd-udevd.service systemd-udev-trigger.service apt-daily.timer apt-daily-upgrade.timer \\
      e2scrub_all.timer fstrim.timer systemd-remount-fs.service sys-kernel-config.mount \\
      sys-kernel-debug.mount sys-kernel-tracing.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
"""

# Ubuntu 24.04 with systemd as init and ufw installed (enabled by the suite, as on a VM where ufw is active), plus
# nftables so the suite can list tables. ufw's module loading (IPT_MODULES) and its sysctl file are emptied: in
# a privileged container they would act on the shared machine's kernel. Neither is part of ufw's rules.
UBUNTU_DOCKERFILE = """FROM ubuntu:24.04
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update \\
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ufw iptables nftables curl wget \\
      ca-certificates openssl iproute2 procps tar gzip xz-utils bzip2 unzip less \\
 && apt-get clean && rm -rf /var/lib/apt/lists/* \\
 && sed -i 's/^IPT_MODULES=.*/IPT_MODULES=""/' /etc/default/ufw && : > /etc/ufw/sysctl.conf \\
 && systemctl mask systemd-sysctl.service systemd-binfmt.service proc-sys-fs-binfmt_misc.automount \\
      proc-sys-fs-binfmt_misc.mount systemd-modules-load.service kmod-static-nodes.service \\
      systemd-journald-audit.socket getty.target console-getty.service systemd-firstboot.service \\
      systemd-udevd.service systemd-udev-trigger.service apt-daily.timer apt-daily-upgrade.timer \\
      e2scrub_all.timer fstrim.timer systemd-remount-fs.service sys-kernel-config.mount \\
      sys-kernel-debug.mount sys-kernel-tracing.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
"""


class Failure(AssertionError):
    pass


class Skip(Exception):
    pass


def need(condition, rule, *detail):
    """Assert one contract rule, naming it in the failure."""
    if not condition:
        raise Failure(f'hosted coordinator contract, slice 4: {rule}'
                      + (': ' + ' | '.join(repr(d)[:900] for d in detail) if detail else ''))


def eventually(predicate, timeout, rule, describe=None):
    try:
        return wait_for(predicate, timeout=timeout, message=rule)
    except AssertionError:
        need(False, rule, describe() if describe else 'timed out')


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(Path(path).read_bytes())


def run(argv, timeout=120, check=False, **kwargs):
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout, **kwargs)
    if check and result.returncode != 0:
        raise AssertionError(f'{argv!r} exited {result.returncode}: {result.stdout[-800:]} {result.stderr[-800:]}')
    return result


def parse_time(value):
    from datetime import datetime
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def unit_directives(text):
    """The multiset of `Section/Key=Value` directives of a unit (and its drop-ins), continuation lines joined."""
    out, section = [], None
    for line in re.sub(r'\\\n', ' ', text).splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            continue
        if '=' in line:
            key, value = line.split('=', 1)
            out.append(f'{section}/{key.strip()}={" ".join(value.split())}')
    return sorted(out)


def multiset_minus(a, b):
    rest = list(b)
    out = []
    for item in a:
        if item in rest:
            rest.remove(item)
        else:
            out.append(item)
    return out


# --- Docker ------------------------------------------------------------------------------------------------

class Docker:
    def __init__(self, keep):
        self.keep = keep
        self.containers, self.networks, self.images, self.pulled = [], [], [], []

    def __call__(self, *args, timeout=300, check=True, input=None):
        result = subprocess.run(['docker', *map(str, args)], capture_output=True, text=input is None or
                                isinstance(input, str), timeout=timeout, input=input)
        if check and result.returncode != 0:
            raise AssertionError(f'docker {" ".join(map(str, args))[:300]} exited {result.returncode}: '
                                 f'{(result.stderr or "")[-800:]}')
        return result

    def has_image(self, image):
        return self('image', 'inspect', image, check=False).returncode == 0

    def ensure_image(self, image):
        if not self.has_image(image):
            self('pull', image, timeout=900)
            self.pulled.append(image)

    def network(self):
        """A bridge network on a free 10.231.N.0/24 (fixed addresses need a configured subnet)."""
        used = []
        routes = run(['ip', '-4', 'route']).stdout
        for token in re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', routes):
            used.append(ipaddress.ip_network(token, strict=False))
        name = PREFIX + 'net-' + secrets.token_hex(3)
        for _ in range(40):
            subnet = ipaddress.ip_network(f'10.231.{random.randint(2, 250)}.0/24')
            if any(subnet.overlaps(u) for u in used):
                continue
            result = self('network', 'create', '--driver', 'bridge', '--subnet', str(subnet), name, check=False)
            if result.returncode == 0:
                self.networks.append(name)
                return name, subnet
        raise AssertionError('no free subnet for the suite network')

    def remove_container(self, name):
        self('rm', '-f', '-v', name, check=False, timeout=120)
        if name in self.containers:
            self.containers.remove(name)

    def cleanup(self):
        report = []
        if self.keep:
            return ['kept (--keep): containers ' + ', '.join(self.containers) + '; networks ' +
                    ', '.join(self.networks) + '; images ' + ', '.join(self.images + self.pulled)]
        for name in list(self.containers):
            self.remove_container(name)
            report.append(f'container {name}')
        for name in self.networks:
            self('network', 'rm', name, check=False)
            report.append(f'network {name}')
        for image in self.images + self.pulled:
            self('rmi', '-f', image, check=False)
            report.append(f'image {image}')
        # Anything else carrying the prefix (volumes, stray containers from an interrupted run of this suite).
        leftovers = self('ps', '-a', '--filter', f'name={PREFIX}', '--format', '{{.Names}}', check=False).stdout
        for name in leftovers.split():
            if name.startswith(PREFIX):
                self('rm', '-f', '-v', name, check=False)
        for name in self('volume', 'ls', '--format', '{{.Name}}', check=False).stdout.split():
            if name.startswith(PREFIX):
                self('volume', 'rm', '-f', name, check=False)
        return report


class Container:
    """A container on the suite network; exec runs as root."""

    def __init__(self, docker, name, ip):
        self.docker, self.name, self.ip = docker, name, ip

    def sh(self, script, timeout=120, check=False, cwd=None, user=None):
        args = ['exec']
        if cwd:
            args += ['-w', cwd]
        if user:
            args += ['-u', user]
        return self.docker(*args, self.name, 'sh', '-c', script, timeout=timeout, check=check)

    def out(self, script, timeout=120):
        result = self.sh(script, timeout=timeout)
        need(result.returncode == 0, f'(suite) `{script[:120]}` in {self.name} succeeds', result.returncode,
             result.stdout[-500:], result.stderr[-500:])
        return result.stdout

    def read(self, path):
        result = self.docker('exec', self.name, 'cat', path, check=False)
        return result.stdout if result.returncode == 0 else None

    def read_bytes(self, path):
        result = subprocess.run(['docker', 'exec', self.name, 'cat', path], capture_output=True, timeout=60)
        return result.stdout if result.returncode == 0 else None

    def write(self, path, content, mode='0600'):
        data = content.encode() if isinstance(content, str) else content
        result = subprocess.run(['docker', 'exec', '-i', self.name, 'sh', '-c',
                                 f'umask 077; cat > {shlex.quote(path)} && chmod {mode} {shlex.quote(path)}'],
                                input=data, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr

    def copy_in(self, source, destination):
        self.docker('cp', str(source), f'{self.name}:{destination}', timeout=300)

    def pid(self):
        return self.docker('inspect', '-f', '{{.State.Pid}}', self.name).stdout.strip()

    def stat(self, path):
        """(kind, mode, owner, group) or None; kind from stat -c %F."""
        result = self.sh(f'stat -c "%F|%a|%U|%G" {shlex.quote(path)}')
        if result.returncode != 0:
            return None
        kind, mode, owner, group = result.stdout.strip().split('|')
        return kind, int(mode, 8), owner, group

    def healthz(self):
        result = self.sh(f'curl -s -m 5 -w "\\n%{{http_code}}" http://{OPS}/healthz')
        if result.returncode != 0:
            return None, None
        body, _, code = result.stdout.rpartition('\n')
        try:
            return int(code), json.loads(body)
        except (ValueError, json.JSONDecodeError):
            return int(code) if code.isdigit() else None, body

    def metrics(self):
        result = self.sh(f'curl -s -m 5 http://{OPS}/metrics')
        need(result.returncode == 0 and result.stdout, '/metrics answers on the ops listener', result.stderr)
        return Metrics(result.stdout)

    def info(self):
        result = self.sh(f'runuser -u peerspan-coord -- {BINARY} --state {STATE} info')
        need(result.returncode == 0, '`peerspan-coord info` reads the installed state', result.returncode,
             result.stderr[-500:])
        return json.loads(result.stdout)

    def show(self, unit, *properties):
        result = self.sh(f'systemctl show {unit} ' + ' '.join(f'-p {p}' for p in properties))
        values = {}
        for line in result.stdout.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                values[key] = value
        return values

    def unit_state(self, unit):
        enabled = self.sh(f'systemctl is-enabled {unit}').stdout.strip()
        active = self.sh(f'systemctl is-active {unit}').stdout.strip()
        return enabled, active


# --- an S3 client for MinIO (signature version 4) ----------------------------------------------------------

class S3:
    def __init__(self, host, port, access, secret, cafile, region='us-east-1'):
        self.host, self.port, self.access, self.secret, self.region = host, port, access, secret, region
        self.context = ssl.create_default_context(cafile=str(cafile))

    def request(self, method, path, query=None, body=b'', headers=None):
        from datetime import datetime, timezone
        query, headers = query or {}, dict(headers or {})
        now = datetime.now(timezone.utc)
        amzdate, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
        payload = hashlib.sha256(body).hexdigest()
        headers.update({'host': f'{self.host}:{self.port}', 'x-amz-date': amzdate, 'x-amz-content-sha256': payload})
        canonical_path = urllib.parse.quote(path, safe='/-_.~')
        qs = '&'.join(f'{urllib.parse.quote(k, safe="-_.~")}={urllib.parse.quote(str(v), safe="-_.~")}'
                      for k, v in sorted(query.items()))
        lower = {k.lower(): str(v).strip() for k, v in headers.items()}
        signed = ';'.join(sorted(lower))
        canonical = '\n'.join([method, canonical_path, qs, ''.join(f'{k}:{lower[k]}\n' for k in sorted(lower)),
                               signed, payload])
        scope = f'{day}/{self.region}/s3/aws4_request'
        to_sign = '\n'.join(['AWS4-HMAC-SHA256', amzdate, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        import hmac
        k = ('AWS4' + self.secret).encode()
        for part in (day, self.region, 's3', 'aws4_request'):
            k = hmac.new(k, part.encode(), hashlib.sha256).digest()
        signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
        headers['Authorization'] = (f'AWS4-HMAC-SHA256 Credential={self.access}/{scope}, SignedHeaders={signed}, '
                                    f'Signature={signature}')
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=30)
        try:
            connection.request(method, canonical_path + ('?' + qs if qs else ''), body, headers)
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            connection.close()

    def objects(self, bucket):
        keys, token = [], None
        while True:
            query = {'list-type': '2'}
            if token:
                query['continuation-token'] = token
            status, _, body = self.request('GET', f'/{bucket}', query=query)
            assert status == 200, (status, body[:300])
            text = body.decode()
            keys += [(urllib.parse.unquote(k), int(s)) for k, s in
                     re.findall(r'<Contents><Key>(.*?)</Key>.*?<Size>(\d+)</Size>', text)]
            match = re.search(r'<NextContinuationToken>(.*?)</NextContinuationToken>', text)
            if not match:
                return keys
            token = match.group(1)


def ssec(key):
    return {'x-amz-server-side-encryption-customer-algorithm': 'AES256',
            'x-amz-server-side-encryption-customer-key': base64.b64encode(key).decode(),
            'x-amz-server-side-encryption-customer-key-md5': base64.b64encode(hashlib.md5(key).digest()).decode()}


# --- packet capture inside a container's network namespace ------------------------------------------------

PACKET = re.compile(r'\b(IP6?) (\S+) > (\S+): (.*)$')


def split_endpoint(text):
    host, _, port = text.rstrip(':').rpartition('.')
    return host, port


class Capture:
    """tcpdump in a container's network namespace (run from this machine with nsenter), written to a pcap."""

    def __init__(self, container, path):
        self.container, self.path = container, path
        self.process = subprocess.Popen(['nsenter', '-t', container.pid(), '-n', 'tcpdump', '-i', 'any', '-nn',
                                         '-U', '-s', '256', '-w', str(path)], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE)
        time.sleep(1.5)
        assert self.process.poll() is None, self.process.stderr.read()

    def stop(self):
        time.sleep(1)
        self.process.terminate()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def analyse(self, container_ip, resolvers):
        """(violations, names queried, connections made) for packets the container itself sent outward."""
        text = run(['tcpdump', '-r', self.path, '-nn'], timeout=120).stdout
        queries, answers, names = {}, {}, set()
        lines = []
        for line in text.splitlines():
            match = PACKET.search(line)
            if not match:
                continue
            family, source, destination, rest = match.groups()
            (src, sport), (dst, dport) = split_endpoint(source), split_endpoint(destination)
            lines.append((family, src, sport, dst, dport, rest, line))
            dns = re.match(r'(\d+)\+? (?:\[[^\]]*\] )?(A|AAAA)\? (\S+?)\.? \(', rest)
            if dport == '53' and dns:
                queries[dns.group(1)] = dns.group(3).lower()
                names.add(dns.group(3).lower())
            if sport == '53':
                ident = rest.split(' ', 1)[0].rstrip('*-$|')
                for address in re.findall(r'\bA (\d+\.\d+\.\d+\.\d+)', rest) + re.findall(r'\bAAAA ([0-9a-f:]+)',
                                                                                         rest):
                    answers.setdefault(ident, set()).add(address)
        allowed_names = {n for n in names if DOWNLOAD_NAMES.match(n)}
        allowed_ips = set()
        for ident, name in queries.items():
            if name in allowed_names:
                allowed_ips |= answers.get(ident, set())
        violations, connections = [], set()
        for family, src, sport, dst, dport, rest, line in lines:
            if src != container_ip:
                continue
            if dst.startswith('127.') or dst == '::1' or dst == container_ip:
                continue
            if dport == '53' and dst in resolvers:
                continue  # DNS queries; their names are checked below
            if sport == '443':
                continue  # replies of the coordination service (TCP and STUN)
            if rest.startswith('Flags [S],'):
                connections.add(f'{dst}:{dport}')
                if dport != '443' or dst not in allowed_ips:
                    violations.append(line)
                continue
            if rest.startswith('Flags ') and f'{dst}:{dport}' in connections:
                continue  # the rest of an allowed connection
            if rest.startswith('Flags ') and dst in allowed_ips and dport == '443':
                continue
            if rest.startswith('ICMP') or rest.startswith('ICMP6'):
                continue  # errors about traffic received
            violations.append(line)
        for name in names - allowed_names:
            violations.append(f'DNS query for {name}')
        return violations, sorted(names), sorted(connections)


# --- hosts in their own network namespaces ----------------------------------------------------------------

class IsolatedHost(OpsHost):
    """A relay-only host whose daemon runs in a debian:12 container on its own network (the binary, the suite
    directory, and its configuration mounted at the same paths), so its only way to another host is the
    coordinator's relay. Its CLI runs on this machine against the admin socket in the shared state directory.
    Q11: hosts sharing this machine's interfaces advertise them as candidates and connect directly, so the
    contract's "relayed messages" needs each daemon in a namespace of its own."""

    def start(self, command='run'):
        subprocess.run(['docker', 'rm', '-f', self.container], capture_output=True, timeout=60)
        env = self.daemon_env()
        extra = {k: v for k, v in env.items() if os.environ.get(k) != v and k not in ('PATH',)}
        extra.setdefault('HOME', env.get('HOME', '/root'))
        argv = ['docker', 'run', '--rm', '--init', '--name', self.container, '--network', self.network]
        for path in self.mounts:
            argv += ['-v', f'{path}:{path}']
        for key, value in sorted(extra.items()):
            argv += ['-e', f'{key}={value}']
        argv += [BASE_IMAGE, str(self.binary), '--state', str(self.state), command, *self.daemon_args]
        self.process = subprocess.Popen(argv, stdout=self.logs, stderr=self.logs, preexec_fn=die_with_parent)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.logs.seek(0)
                raise AssertionError(f'host exited at startup: {self.logs.read().decode()[-2000:]}')
            try:
                status, identity = self.call('GET', '/v1/host')
                if status == 200:
                    return identity
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.2)
        raise AssertionError('host did not become ready')


# --- the suite --------------------------------------------------------------------------------------------

class Suite:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.repo = args.repo
        self.docker = Docker(args.keep)
        self.results = []
        self.hosts, self.ids, self.agents, self.grants = {}, {}, {}, {}
        self.binaries = {'Go': args.go, 'Rust': args.rust}
        self.dist_created = []
        stamp = time.strftime('%Y%m%d%H%M%S', time.gmtime())
        self.v1 = f'0.0.0-m8s4suite.{stamp}'
        self.v2 = f'0.0.1-m8s4suite.{stamp}'
        self.archives = {}
        self.capture_notes = []
        self.coord = None
        self.identity = None
        self.state = {}
        self.violations = []
        self.capture_failures = []

    # infrastructure

    def section(self, name, function, *requires):
        missing = [r for r in requires if not self.state.get(r)]
        if missing:
            self.results.append((name, False, f'skipped: needs {", ".join(missing)}'))
            print(f'FAIL [{name}]: skipped, needs {", ".join(missing)}', flush=True)
            return False
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=8)
            self.results.append((name, False, detail))
            print(f'FAIL [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        self.state[name] = True
        print(f'PASS [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}', flush=True)
        return True

    def run(self):
        self.section('docker setup', self.setup_docker)
        self.section('archive', self.check_archive)
        self.section('install', self.check_install, 'docker setup', 'archive')
        self.section('firewall', self.check_firewall, 'install')
        self.section('hosts', self.check_hosts, 'install')
        self.section('re-run', self.check_rerun, 'install')
        self.section('upgrade', self.check_upgrade, 'install')
        self.section('failed upgrade', self.check_failed_upgrade, 'install')
        self.section('upgrade with --no-firewall', self.check_upgrade_no_firewall, 'install')
        self.section('ubuntu with ufw', self.check_ubuntu_ufw, 'docker setup', 'archive')
        self.section('no firewall (debian)', self.check_no_firewall_debian, 'docker setup', 'archive')
        self.section('no firewall (ubuntu)', self.check_no_firewall_ubuntu, 'docker setup', 'archive')
        self.section('no outside requests', self.check_requests, 'install')
        self.section('litestream', self.check_litestream, 'install')
        self.section('restore from the replica', self.check_restore, 'litestream', 'hosts')
        self.section('other distributions', self.check_other_distribution, 'docker setup', 'archive')

    def close(self):
        try:
            stop_all(tuple(self.hosts.values()))
        finally:
            if not self.args.keep:
                for path in self.dist_created:
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
            report = self.docker.cleanup()
            print('cleanup: ' + ('; '.join(report) if report else 'nothing to remove') +
                  ('' if self.args.keep else f'; removed {len(self.dist_created)} dist files'), flush=True)

    # docker

    def setup_docker(self):
        need(os.geteuid() == 0, '(suite) runs as root')
        for tool in ('docker', 'openssl', 'tcpdump', 'nsenter', 'ip', 'sha256sum'):
            need(shutil.which(tool), f'(suite) needs {tool}')
        for image in (BASE_IMAGE, MINIO_IMAGE, UBUNTU_IMAGE, *OTHER_IMAGES):
            self.docker.ensure_image(image)
        tags = []
        for label, dockerfile, repository in (('image', DOCKERFILE, SYSTEMD_IMAGE),
                                              ('ubuntu-image', UBUNTU_DOCKERFILE, UBUNTU_SYSTEMD_IMAGE)):
            build = self.root / label
            build.mkdir()
            (build / 'Dockerfile').write_text(dockerfile)
            tag = f'{repository}:{secrets.token_hex(3)}'
            self.docker('build', '-q', '-t', tag, str(build), timeout=1200)
            self.docker.images.append(tag)
            tags.append(tag)
        self.image, self.ubuntu_image = tags
        tag = ', '.join(tags)
        self.network, self.subnet = self.docker.network()
        hosts = list(self.subnet.hosts())
        self.gateway = str(hosts[0])
        self.coord_ip, self.minio_ip = str(hosts[9]), str(hosts[19])
        # Further systemd containers (Ubuntu with ufw, --no-firewall on each distribution), not published.
        self.spare_ips = [str(hosts[n]) for n in (29, 39, 49, 59)]
        # Hosts reach the container's 443 through a port published on this machine's address on the suite network.
        # Each host daemon runs in its own network namespace (a container on its own network, see IsolatedHost)
        # and Docker's proxy stands between it and the coordinator, so hosts have no direct path to each other
        # and their messages take the relay.
        probe = socket.socket()
        probe.bind((self.gateway, 0))
        self.coord_port = probe.getsockname()[1]
        probe.close()
        self.coord_address = f'{self.gateway}:{self.coord_port}'
        # Real resolvers for the containers (Docker's embedded resolver depends on NAT rules in the container's
        # namespace, which a VM firewall script may legitimately flush).
        self.resolvers = []
        for line in Path('/etc/resolv.conf').read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'nameserver':
                try:
                    if ipaddress.ip_address(parts[1]).version == 4 and not ipaddress.ip_address(parts[1]).is_loopback:
                        self.resolvers.append(parts[1])
                except ValueError:
                    pass
        if not self.resolvers:
            self.resolvers = ['1.1.1.1', '8.8.8.8']
        self.start_minio()
        return f'image {tag}, network {self.network} ({self.subnet}), resolvers {", ".join(self.resolvers)}'

    def start_minio(self):
        certs = self.root / 'minio-certs'
        certs.mkdir()
        ssl_run = lambda *a: run(['openssl', *a], check=True, cwd=certs)  # noqa: E731
        ssl_run('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key',
                '-out', 'ca.crt', '-days', '2', '-subj', '/CN=peerspan-m8s4-suite-ca')
        ssl_run('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'private.key',
                '-out', 'server.csr', '-subj', '/CN=minio')
        (certs / 'ext').write_text(f'subjectAltName=IP:{self.minio_ip},DNS:minio\nbasicConstraints=CA:FALSE\n'
                                   'extendedKeyUsage=serverAuth\n')
        ssl_run('x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out',
                'public.crt', '-days', '2', '-extfile', 'ext')
        served = self.root / 'minio-served'
        served.mkdir()
        for name in ('public.crt', 'private.key'):
            shutil.copy(certs / name, served / name)
            os.chmod(served / name, 0o644)
        self.ca = certs / 'ca.crt'
        name = PREFIX + 'minio'
        self.docker('run', '-d', '--name', name, '--network', self.network, '--ip', self.minio_ip, '-e',
                    f'MINIO_ROOT_USER={MINIO_USER}', '-e', f'MINIO_ROOT_PASSWORD={MINIO_PASSWORD}', '-v',
                    f'{served}:/certs:ro', MINIO_IMAGE, 'server', '/data', '--certs-dir', '/certs', '--address',
                    ':9000')
        self.docker.containers.append(name)
        self.minio = name
        self.s3 = S3(self.minio_ip, 9000, MINIO_USER, MINIO_PASSWORD, self.ca)

        def up():
            try:
                return self.s3.request('PUT', f'/{BUCKET}')[0] in (200, 409)
            except OSError:
                return False
        eventually(up, 60, '(suite) MinIO answers over TLS and creates the bucket',
                   lambda: self.docker('logs', name, check=False).stderr[-500:])

    def start_debian(self, label, image=None, ip=None):
        """A systemd container: the coordinator's (published on this machine) unless another ip is given."""
        name = PREFIX + label
        self.docker.remove_container(name)
        publish = [] if ip else ['-p', f'{self.gateway}:{self.coord_port}:443/tcp', '-p',
                                 f'{self.gateway}:{self.coord_port}:443/udp']
        ip = ip or self.coord_ip
        self.docker('run', '-d', '--name', name, '--hostname', label, '--network', self.network, '--ip', ip,
                    *publish, '--privileged', '--cgroupns=private', '--tmpfs', '/run', '--tmpfs', '/run/lock',
                    image or self.image)
        self.docker.containers.append(name)
        c = Container(self.docker, name, ip)

        def booted():
            state = c.sh('systemctl is-system-running').stdout.strip()
            return state in ('running', 'degraded')
        eventually(booted, 90, f'(suite) systemd boots in {name}',
                   lambda: c.sh('systemctl --failed --no-legend; systemctl is-system-running').stdout)
        c.out('printf "%s" ' + shlex.quote(''.join(f'nameserver {r}\n' for r in self.resolvers)) +
              ' > /etc/resolv.conf')
        return c

    def extract(self, c, version, directory='/root'):
        archive = self.archives[version]['path']
        c.copy_in(archive, f'/root/{archive.name}')
        c.out(f'cd {directory} && tar -xzf /root/{archive.name}')
        return f'{directory}/{self.archives[version]["top"]}'

    def install(self, c, top, *args, capture=None):
        """Run the archive's install.sh as root with cwd at the extracted archive: (code, stdout, stderr)."""
        script = f'{top}/share/peerspan-coord/deploy/install.sh'
        cap = None
        if capture:
            cap = Capture(c, self.root / f'{capture}.pcap')
        try:
            result = c.sh(f'{shlex.quote(script)} ' + ' '.join(shlex.quote(a) for a in args), cwd=top,
                          timeout=600)
        finally:
            if cap:
                cap.stop()
                violations, names, connections = cap.analyse(c.ip, set(self.resolvers))
                self.capture_notes.append(f'{capture}: names {names or "none"}, connections {connections or "none"}')
                if violations:
                    self.violations.append((capture, violations))
        (self.root / 'logs').mkdir(exist_ok=True)
        (self.root / 'logs' / f'install-{secrets.token_hex(3)}.txt').write_text(
            f'{args}\nexit {result.returncode}\n--- stdout\n{result.stdout}\n--- stderr\n{result.stderr}\n')
        return result.returncode, result.stdout, result.stderr

    def printed(self, stdout, rule):
        try:
            value = json.loads(stdout)
        except json.JSONDecodeError:
            value = None
        need(isinstance(value, dict) and set(value) == INSTALL_FIELDS,
             f'{rule}: install.sh prints {{id, public_key, listen, litestream, firewall}} as JSON on stdout',
             stdout[-600:])
        need(value['firewall'] in FIREWALL_VALUES, f'{rule}: firewall is nftables, ufw, none, or unchanged', value)
        return value

    def no_private_key(self, streams, public_key, rule):
        """No base64 or hex value of 32 or 64 bytes other than the public key (a seed or private key)."""
        for text in streams:
            # The coordinator id (coord_ + a SHA-256 in hex) and SHA-256 digests are hex; seeds and keys in this
            # project are base64, and hex 128 would be a 64-byte private key.
            for token in re.findall(r'(?<![A-Za-z0-9+/_])(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==|[0-9a-fA-F]{128})'
                                    r'(?![A-Za-z0-9+/=])', text):
                if token == public_key:
                    continue
                need(False, f'{rule}: install.sh never prints the private key (a 32- or 64-byte value other than '
                     'the public key appeared)', token[:12] + '...')

    # 1. the archive

    def package(self, version, env=None):
        script = self.repo / 'scripts' / 'package-coordinator.sh'
        need(script.exists(), 'scripts/package-coordinator.sh exists', str(script))
        e = dict(os.environ)
        e.pop('PEERSPAN_PACKAGE_OVERWRITE', None)
        e.update(env or {})
        return run(['bash', str(script), version], timeout=1800, cwd=self.repo, env=e)

    def check_archive(self):
        dist = self.repo / 'dist'
        machine = os.uname().machine
        arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine, machine)
        notes = []
        for version in (self.v1, self.v2):
            stem = f'peerspan-coord-{version}-linux-{arch}'
            path, checksum = dist / f'{stem}.tar.gz', dist / f'{stem}.tar.gz.sha256'
            need(not path.exists() and not checksum.exists(), '(suite) the version is fresh', str(path))
            result = self.package(version)
            for p in (path, checksum):
                if p.exists():
                    self.dist_created.append(p)
            need(result.returncode == 0, f'package-coordinator.sh {version} succeeds', result.returncode,
                 result.stdout[-800:], result.stderr[-800:])
            need(path.exists() and checksum.exists(), f'it writes dist/{stem}.tar.gz and its .sha256 (ARCH {arch} '
                 'as package-release.sh names it)', sorted(p.name for p in dist.iterdir() if version in p.name))
            check = run(['sha256sum', '-c', checksum.name], cwd=dist)
            need(check.returncode == 0, 'the .sha256 verifies with `sha256sum -c` from dist/', check.stdout,
                 check.stderr)
            need(checksum.read_text().split()[0] == sha256_file(path), 'the .sha256 holds the archive\'s digest')
            with tarfile.open(path) as tar:
                members = tar.getmembers()
                names = [m.name.rstrip('/') for m in members]
                need(all(n == stem or n.startswith(stem + '/') for n in names),
                     f'every archive member is under {stem}/', [n for n in names if not n.startswith(stem)][:5])
                files = {m.name[len(stem) + 1:]: m for m in members if m.isfile()}
                need('bin/peerspan-coord' in files and files['bin/peerspan-coord'].mode & 0o111,
                     'the archive holds an executable bin/peerspan-coord', sorted(files))
                need('release.json' in files, 'the archive holds release.json', sorted(files))
                release = json.loads(tar.extractfile(files['release.json']).read())
                deploy = {n[len('share/peerspan-coord/deploy/'):]: m for n, m in files.items()
                          if n.startswith('share/peerspan-coord/deploy/')}
                digests = {n: sha256_bytes(tar.extractfile(m).read()) for n, m in deploy.items()}
                install_mode = deploy['install.sh'].mode if 'install.sh' in deploy else 0
                out = self.root / f'archive-{version}'
                out.mkdir()
                extract_all(tar, out)
            for required in ('install.sh', 'peerspan-coord.service', 'peerspan-coord.env.example', 'litestream.yml',
                             'litestream.service', 'README.md'):
                need(required in deploy, f'share/peerspan-coord/deploy/ holds {required}', sorted(deploy))
            need(install_mode & 0o111, 'install.sh is executable in the archive', oct(install_mode))
            source = self.repo / 'deploy' / 'coordinator'
            repo_files = {str(p.relative_to(source)): sha256_file(p) for p in source.rglob('*') if p.is_file()}
            need(repo_files == digests, 'share/peerspan-coord/deploy/ holds exactly the files in deploy/coordinator/, '
                 'byte for byte', sorted(set(repo_files) ^ set(digests)),
                 sorted(n for n in repo_files if n in digests and repo_files[n] != digests[n]))
            head = run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], check=True).stdout.strip()
            need(isinstance(release, dict) and set(release) == {'version', 'os', 'architecture', 'source_revision'},
                 'release.json has exactly version, os, architecture, and source_revision', release)
            need(release['version'] == version and release['os'] == 'linux' and release['architecture'] == arch,
                 'release.json names the version, linux, and the architecture', release, arch)
            # Q6: source_revision is the commit the archive was built from; a dirty tree may add a suffix.
            need(isinstance(release['source_revision'], str) and release['source_revision'].startswith(head[:12])
                 or head.startswith(str(release['source_revision'])[:12]),
                 'release.json source_revision is the repository\'s revision', release['source_revision'], head)
            self.archives[version] = {'path': path, 'top': stem, 'dir': out / stem, 'release': release,
                                      'binary': sha256_file(out / stem / 'bin' / 'peerspan-coord')}
            notes.append(f'{path.name} ({path.stat().st_size} bytes, revision {release["source_revision"]})')
        # Refusing to overwrite.
        path = self.archives[self.v1]['path']
        checksum = Path(str(path) + '.sha256')
        before = (sha256_file(path), sha256_file(checksum), path.stat().st_mtime_ns, checksum.stat().st_mtime_ns)
        result = self.package(self.v1)
        need(result.returncode != 0, 'package-coordinator.sh refuses to overwrite an existing archive',
             result.returncode, result.stderr[-500:])
        after = (sha256_file(path), sha256_file(checksum), path.stat().st_mtime_ns, checksum.stat().st_mtime_ns)
        need(before == after, 'a refused run leaves the archive and its .sha256 unchanged')
        # Q1: "as package-release.sh does" includes its explicit PEERSPAN_PACKAGE_OVERWRITE=1.
        result = self.package(self.v1, {'PEERSPAN_PACKAGE_OVERWRITE': '1'})
        need(result.returncode == 0, 'with PEERSPAN_PACKAGE_OVERWRITE=1 the archive is rebuilt, as package-release.sh '
             'does (Q1)', result.returncode, result.stderr[-500:])
        check = run(['sha256sum', '-c', checksum.name], cwd=path.parent)
        need(check.returncode == 0, 'the rebuilt pair verifies', check.stdout, check.stderr)
        # Use the rebuilt archive from here on.
        with tarfile.open(path) as tar:
            out = self.root / f'archive-{self.v1}-rebuilt'
            out.mkdir()
            extract_all(tar, out)
        self.archives[self.v1]['dir'] = out / self.archives[self.v1]['top']
        self.archives[self.v1]['binary'] = sha256_file(self.archives[self.v1]['dir'] / 'bin' / 'peerspan-coord')
        return '; '.join(notes)

    # 2. install

    def check_install(self):
        c = self.coord = self.start_debian('coord-a')
        top = self.extract(c, self.v1)
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN, capture='install')
        need(code == 0, 'install.sh --listen 0.0.0.0:443 exits 0', code, stdout[-600:], stderr[-1500:])
        out = self.printed(stdout, 'install')
        self.identity = out
        need(out['firewall'] == 'nftables', 'on Debian 12 without ufw or --no-firewall, firewall is `nftables`', out)
        self.check_installed(c, out, stdout, stderr, self.v1, 'install')
        # Litestream.
        exec_start = c.show('litestream', 'ExecStart').get('ExecStart', '')
        match = re.search(r'path=(\S+)', exec_start)
        need(match, 'the litestream unit runs a Litestream binary', exec_start)
        self.litestream_bin = match.group(1)
        version = c.sh(f'{self.litestream_bin} version').stdout.strip()
        need(re.match(r'^v?0\.5\.\d+', version), 'Litestream 0.5 is installed (the pinned version)', version)
        notes = [f'Litestream {version} at {self.litestream_bin}', self.verify_litestream(version)]
        return '; '.join(n for n in notes if n)

    def check_installed(self, c, out, stdout, stderr, version, rule):
        """The checks of a first install without Litestream configured, on either distribution."""
        need(out['listen'] == LISTEN, f'{rule}: the printed listen is the --listen address', out)
        need(out['litestream'] == 'not configured', f'{rule}: litestream is `not configured` without its env and '
             'key', out)
        need('litestream' in stderr.lower(), f'{rule}: without Litestream configured the script says so on stderr',
             stderr)
        self.no_private_key((stdout, stderr), out['public_key'], rule)
        info = c.info()
        need(info['id'] == out['id'] and info['public_key'] == out['public_key'],
             f'{rule}: the printed id and public_key are the coordinator\'s (`peerspan-coord info`)', info, out)
        status, body = c.healthz()
        need(status == 200 and body == {'status': 'ok', 'id': out['id']}, f'{rule}: /healthz answers ok with the id',
             status, body)
        # The user.
        passwd = c.sh('getent passwd peerspan-coord').stdout.strip().split(':')
        need(len(passwd) == 7, f'{rule}: install.sh creates the peerspan-coord user', passwd)
        need(int(passwd[2]) < 1000 and passwd[6].endswith(('nologin', 'false')),
             f'{rule}: peerspan-coord is a system user without a login shell', passwd)
        need(c.sh('getent group peerspan-coord').returncode == 0, f'{rule}: peerspan-coord has its group')
        # Files and modes.
        st = c.stat(BINARY)
        need(st and st[0] == 'regular file' and st[2] == 'root' and st[1] & 0o111 and not st[1] & 0o022,
             f'{rule}: {BINARY} is an executable owned by root, not group or world writable', st)
        need(sha256_bytes(c.read_bytes(BINARY)) == self.archives[version]['binary'],
             f'{rule}: {BINARY} is the archive\'s binary')
        st = c.stat(ENV_FILE)
        need(st and st[0] == 'regular file' and not st[1] & 0o002, f'{rule}: {ENV_FILE} is installed, not world '
             'writable', st)
        env = c.read(ENV_FILE) or ''
        need(re.search(r'^\s*PEERSPAN_COORD_LISTEN\s*=\s*"?0\.0\.0\.0:443"?\s*$', env, re.M),
             f'{rule}: the env file sets PEERSPAN_COORD_LISTEN to the --listen address', env)
        st = c.stat(STATE)
        need(st and st[0] == 'directory' and st[1] == 0o700 and st[2] == 'peerspan-coord',
             f'{rule}: {STATE} is a directory (not a symbolic link), 0700, owned by peerspan-coord', st)
        st = c.stat(f'{STATE}/coord.db')
        need(st and st[1] == 0o600 and st[2] == 'peerspan-coord', f'{rule}: coord.db is 0600, owned by peerspan-coord',
             st)
        paths = {}
        for unit in ('peerspan-coord', 'litestream'):
            fragment = c.show(unit, 'FragmentPath').get('FragmentPath', '')
            need(fragment and c.stat(fragment), f'{rule}: the {unit} unit is installed', fragment)
            st = c.stat(fragment)
            need(st[2] == 'root' and not st[1] & 0o022, f'{rule}: the {unit} unit is owned by root, not writable by '
                 'others', st)
            paths[unit] = fragment
        if c is self.coord:
            self.unit_paths = paths
        # The unit gains exactly CAP_NET_BIND_SERVICE for port 443.
        shipped = (self.archives[version]['dir'] / 'share' / 'peerspan-coord' / 'deploy' /
                   'peerspan-coord.service').read_text()
        installed = c.out('systemctl cat peerspan-coord')
        added = multiset_minus(unit_directives(installed), unit_directives(shipped))
        removed = multiset_minus(unit_directives(shipped), unit_directives(installed))
        # Q7: "gains ... and nothing else" read as the installed unit (with drop-ins) being the shipped unit plus
        # exactly these two directives; the shipped unit's empty `AmbientCapabilities=` and
        # `CapabilityBoundingSet=` (no capabilities, slice 1) may be the lines that gain the value.
        removed = [r for r in removed if r not in ('Service/AmbientCapabilities=', 'Service/CapabilityBoundingSet=')]
        need(sorted(added) == ['Service/AmbientCapabilities=CAP_NET_BIND_SERVICE',
                               'Service/CapabilityBoundingSet=CAP_NET_BIND_SERVICE'] and not removed,
             f'{rule}: with port 443 the unit gains exactly AmbientCapabilities= and CapabilityBoundingSet= '
             'CAP_NET_BIND_SERVICE, and nothing else (Q7)', added, removed)
        props = c.show('peerspan-coord', 'AmbientCapabilities', 'CapabilityBoundingSet', 'User', 'MainPID',
                       'NoNewPrivileges', 'DynamicUser')
        need(props.get('AmbientCapabilities') == 'cap_net_bind_service'
             and props.get('CapabilityBoundingSet') == 'cap_net_bind_service',
             f'{rule}: systemd applies exactly cap_net_bind_service as ambient and bounding set', props)
        need(props.get('User') == 'peerspan-coord' and props.get('DynamicUser') == 'no',
             f'{rule}: the service runs as the static peerspan-coord user', props)
        status_text = c.out(f'cat /proc/{props["MainPID"]}/status')
        fields = dict(line.split(':', 1) for line in status_text.splitlines() if ':' in line)
        uid = fields['Uid'].split()[0]
        need(uid == passwd[2], f'{rule}: the coordinator process runs as peerspan-coord', fields['Uid'], passwd[2])
        for field in ('CapAmb', 'CapBnd', 'CapEff', 'CapPrm'):
            need(int(fields[field].strip(), 16) == CAP_NET_BIND_SERVICE,
                 f'{rule}: the coordinator process\'s {field} is exactly CAP_NET_BIND_SERVICE', fields[field])
        # Service states without Litestream.
        need(c.unit_state('peerspan-coord') == ('enabled', 'active'), f'{rule}: peerspan-coord is enabled and active',
             c.unit_state('peerspan-coord'))
        need(c.unit_state('litestream') == ('disabled', 'inactive'),
             f'{rule}: without Litestream configured its unit stays disabled (and inactive)',
             c.unit_state('litestream'))
        # Sockets.
        sockets = c.out('ss -Hlntup')
        listening = {(line.split()[0], line.split()[4]) for line in sockets.splitlines() if 'peerspan-coord' in line}
        wildcard = {'0.0.0.0:443', '*:443', '[::]:443'}
        need(any(('tcp', a) in listening for a in wildcard) and any(('udp', a) in listening for a in wildcard),
             f'{rule}: the coordinator listens on TCP and UDP 443 on every address', sockets)
        need(('tcp', OPS) in listening, f'{rule}: the ops listener is on 127.0.0.1:9464', sockets)
        need(not any(a.endswith(':9464') and a != OPS for _, a in listening), f'{rule}: the ops port is loopback '
             'only', sockets)
        metrics = c.metrics()
        versions = metrics.series('peerspan_coord_info')
        need(len(versions) == 1 and versions[0][0].get('version') == version and versions[0][1] == 1,
             f'{rule}: peerspan_coord_info{{version}} is the archive\'s VERSION', versions)

    def verify_litestream(self, version):
        """The installed Litestream binary equals the published release's, checked against its checksums."""
        tag = version if version.startswith('v') else 'v' + version
        tag = tag.split()[0]
        try:
            with urllib.request.urlopen(f'https://api.github.com/repos/benbjohnson/litestream/releases/tags/{tag}',
                                        timeout=30) as response:
                release = json.loads(response.read())
            assets = {a['name']: a['browser_download_url'] for a in release['assets']}
            machine = os.uname().machine
            arch_names = {'x86_64': ('amd64', 'x86_64'), 'aarch64': ('arm64', 'aarch64')}.get(machine, (machine,))
            tarball = [n for n in assets if 'linux' in n and n.endswith('.tar.gz') and any(a in n for a in arch_names)]
            sums = [n for n in assets if 'checksum' in n.lower() or n.endswith('.sha256')]
            if not tarball:
                return f'(no published linux tarball found for {tag}; binary not compared)'
            with urllib.request.urlopen(assets[tarball[0]], timeout=120) as response:
                data = response.read()
            published = None
            for name in sums:
                with urllib.request.urlopen(assets[name], timeout=60) as response:
                    text = response.read().decode()
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[-1].lstrip('*') == tarball[0]:
                        published = parts[0]
                    elif len(parts) == 1 and name.startswith(tarball[0]):
                        published = parts[0]
        except (OSError, KeyError, ValueError) as error:
            return f'(published Litestream release not reachable from this machine: {error}; binary not compared)'
        need(published == sha256_bytes(data), '(suite) the published Litestream tarball matches its checksum',
             tarball[0], published)
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            member = [m for m in tar.getmembers() if m.isfile() and m.name.split('/')[-1] == 'litestream']
            binary = tar.extractfile(member[0]).read()
        installed = self.coord.read_bytes(self.litestream_bin)
        need(sha256_bytes(installed) == sha256_bytes(binary), 'the installed Litestream is the published release '
             f'{tarball[0]}, whose published SHA-256 matches')
        return f'binary equal to published {tarball[0]}'

    # 3. firewall

    def check_firewall(self):
        c = self.coord
        ruleset = json.loads(c.out('nft -j list ruleset'))['nftables']
        chains = {}
        for item in ruleset:
            if 'chain' in item and item['chain'].get('hook') == 'input':
                ch = item['chain']
                chains[(ch['family'], ch['table'], ch['name'])] = ch
        need(chains, 'nftables has an input hook chain', ruleset[:5])
        need(any(k[:2] == ('inet', 'peerspan_coord') for k in chains),
             'the input hook chain is in the dedicated table `inet peerspan_coord`', sorted(chains))
        boot = self.nft_boot_tables(c)
        need('peerspan_coord' in boot, 'the `inet peerspan_coord` table is included from /etc/nftables.conf',
             c.read('/etc/nftables.conf'))
        need(c.unit_state('nftables')[0] == 'enabled', 'nftables.service is enabled, so the table loads at boot',
             c.unit_state('nftables'))
        families = {f for f, _, _ in chains}
        need('inet' in families or {'ip', 'ip6'} <= families, 'the input filter covers IPv4 and IPv6', families)
        dropping = [k for k, ch in chains.items() if ch.get('policy') == 'drop']
        need(dropping, 'the input chain drops by default', chains)
        accepted, notes = set(), []
        established = False
        for item in ruleset:
            rule = item.get('rule')
            if not rule or (rule['family'], rule['table'], rule['chain']) not in chains:
                continue
            expr = rule.get('expr', [])
            text = json.dumps(expr)
            if not any('accept' in e for e in expr):
                continue
            ports, protos = [], []
            for e in expr:
                match = e.get('match')
                if not match:
                    continue
                left, right = match.get('left', {}), match.get('right')
                if not isinstance(left, dict):
                    continue
                payload = left.get('payload', {})
                if payload.get('field') == 'dport':
                    if payload.get('protocol') in ('tcp', 'udp'):
                        protos.append(payload['protocol'])
                    values = right.get('set') if isinstance(right, dict) and 'set' in right else [right]
                    ports += values
                if 'meta' in left and left['meta'].get('key') in ('l4proto', 'protocol', 'nfproto'):
                    values = right.get('set') if isinstance(right, dict) and 'set' in right else [right]
                    protos += [v for v in values if v in ('tcp', 'udp')]
                if 'ct' in left and left['ct'].get('key') == 'state' and 'established' in json.dumps(right):
                    established = True
            if ports:
                for p in ports:
                    for proto in protos or ['any']:
                        if isinstance(p, dict) and 'range' in p:
                            p = tuple(p['range'])
                        accepted.add((proto, p))
                continue
            if 'established' in text:
                continue
            if '"lo"' in text:
                notes.append('loopback accepted (Q2)')
                continue
            if 'icmp' in text:
                notes.append('ICMP accepted: ' + text[:120] + ' (Q2)')
                continue
            need(False, 'the input chain accepts nothing but established traffic, TCP 22, and TCP and UDP on the '
                 'coordination port', text[:600])
        need(established, 'the input chain accepts established traffic', chains)
        need(accepted == {('tcp', 22), ('tcp', 443), ('udp', 443)},
             'the input chain accepts exactly TCP 22, TCP 443, and UDP 443', sorted(accepted, key=str))
        # From this machine.
        ip = c.ip

        def tcp(port):
            return self.tcp(ip, port)
        need(tcp(443) == 'open', 'TCP 443 is reachable from outside')
        need(tcp(22) == 'refused', 'TCP 22 is allowed (refused by the kernel, as the container has no sshd, rather '
             'than dropped)')
        for port in (9464, 8443, 80):
            need(tcp(port) == 'dropped', f'TCP {port} is dropped')
        need(self.stun(ip, 443), 'STUN on UDP 443 answers from outside')
        need(self.udp_dropped(ip, 9999), 'UDP 9999 is dropped (no port-unreachable answer)')
        status, body = c.healthz()
        need(status == 200, '/healthz still answers on loopback inside the VM', status, body)
        return '; '.join(sorted(set(notes))) or 'exactly 22/tcp, 443/tcp, 443/udp, established'

    def nft_boot_tables(self, c):
        """/etc/nftables.conf with the files it includes, as loaded at boot."""
        conf = c.read('/etc/nftables.conf') or ''
        text = conf
        for pattern in re.findall(r'^\s*include\s+"([^"]+)"', conf, re.M):
            text += c.sh(f'cat {pattern}').stdout
        return text

    def peerspan_table(self, c):
        """Whether nftables holds the table `inet peerspan_coord`."""
        result = c.sh('nft list tables')
        need(result.returncode == 0, '(suite) `nft list tables` works in the container', result.stderr)
        return bool(re.search(r'^table inet peerspan_coord$', result.stdout, re.M))

    def tcp(self, ip, port, timeout=4):
        started = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return 'open'
        except ConnectionRefusedError:
            return 'refused'
        except (socket.timeout, TimeoutError):
            return 'dropped' if time.monotonic() - started >= timeout - 0.5 else 'error'
        except OSError as error:
            return f'error {error}'

    def stun(self, ip, port):
        transaction = secrets.token_bytes(12)
        request = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + transaction
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            for _ in range(3):
                s.sendto(request, (ip, port))
                try:
                    data, _ = s.recvfrom(2048)
                except (socket.timeout, TimeoutError):
                    continue
                if data[:2] == b'\x01\x01' and data[8:20] == transaction:
                    return True
        return False

    def udp_dropped(self, ip, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            for _ in range(2):
                try:
                    s.send(b'peerspan-m8s4-suite')
                    s.recv(100)
                    return False
                except ConnectionRefusedError:
                    return False
                except (socket.timeout, TimeoutError):
                    continue
        return True

    # 4. hosts

    def host(self, name, implementation):
        h = IsolatedHost(self.binaries[implementation], self.root / name, self.root / f'user-{name}')
        h.implementation = implementation
        h.network, _ = self.docker.network()
        h.container = PREFIX + 'host-' + name
        h.mounts = [str(self.root), str(h.config_home), str(self.binaries[implementation])]
        self.docker.containers.append(h.container)
        self.hosts[name] = h
        identity = h.start()
        self.ids[name] = identity['id']
        return h

    def network_record(self, name, net):
        status, body = self.hosts[name].call('GET', '/v1/networks')
        assert status == 200, (status, body)
        return {n['id']: n for n in body}.get(net)

    def members(self, name, net):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{net}/members')
        assert status == 200, (status, body)
        return {m['host_id'] for m in body}

    def agent(self, name):
        if name not in self.agents:
            self.agents[name] = self.hosts[name].cli('agent', 'register', '--name', 'deploy', '--owner', name)
        return self.agents[name]

    def send(self, sender, receiver, timeout=120):
        """A message under a connected-only grant, retried until accepted (as coord_ops.py sends)."""
        key = (receiver, sender)
        if key not in self.grants:
            self.grants[key] = self.hosts[receiver].grant({'id': self.ids[sender]}, self.agent(receiver), allow=False)
        rid = request_id()
        s = self.hosts[sender]
        out = s.cli('message', 'send', '--peer', self.ids[receiver], '--grant', self.grants[key]['id'], '--agent',
                    self.agent(receiver)['id'], '--deadline', timestamp(), '--content',
                    f'deploy {sender}->{receiver} {secrets.token_hex(4)}', '--request', rid)
        deadline = time.monotonic() + timeout
        while out['state'] != 'accepted' and time.monotonic() < deadline:
            time.sleep(1)
            out = s.cli('message', 'retry', '--peer', self.ids[receiver], rid)
        need(out['state'] == 'accepted', f'a relayed message {sender} ({self.hosts[sender].implementation}) → '
             f'{receiver} ({self.hosts[receiver].implementation}) is accepted', out)

    def join(self, creator, joiner, net, label):
        token = self.hosts[creator].cli('invite', label, '--network', net)['token']
        out = self.hosts[joiner].cli('join', token)
        need(out.get('id') == net, f'{joiner} ({self.hosts[joiner].implementation}) joins through the container',
             out)

    def synced_after(self, names, moment, timeout, rule, nets=None):
        for name in names:
            for net in (nets or [self.net1]):
                def ok(name=name, net=net):
                    r = self.network_record(name, net)
                    return (r and r.get('last_sync_error') is None and r.get('last_sync_at')
                            and parse_time(r['last_sync_at']) > moment)
                eventually(ok, timeout, f'{rule}: {name} ({self.hosts[name].implementation}) syncs again',
                           lambda name=name, net=net: self.network_record(name, net))

    def check_hosts(self):
        key = self.identity['public_key']
        self.host('alice', 'Go')
        self.host('bob', 'Rust')
        created = self.hosts['alice'].cli('network', 'create', 'deploy-go', '--as', 'alice', '--coordinator',
                                          self.coord_address, '--coordinator-key', key)
        self.net1 = created['id']
        self.join('alice', 'bob', self.net1, 'bob')
        created = self.hosts['bob'].cli('network', 'create', 'deploy-rust', '--as', 'bob', '--coordinator',
                                        self.coord_address, '--coordinator-key', key)
        self.net2 = created['id']
        self.join('bob', 'alice', self.net2, 'alice')
        both = {self.ids['alice'], self.ids['bob']}
        for net in (self.net1, self.net2):
            for name in ('alice', 'bob'):
                eventually(lambda name=name, net=net: both <= self.members(name, net), 90,
                           f'{name} sees both members of each network through the container')
                r = self.network_record(name, net)
                need(r['coordinator_address'] == self.coord_address and r['coordinator_public_key'] == key,
                     'hosts pin the container\'s address and the printed public_key', r)
        before = self.coord.metrics().value('peerspan_coord_relay_bytes_total')
        eventually(lambda: self.coord.metrics().value('peerspan_coord_relay_connections') >= 2, 60,
                   'peerspan_coord_relay_connections counts both relay-only hosts',
                   lambda: self.coord.metrics().series('peerspan_coord_relay_connections'))
        for sender, receiver in (('alice', 'bob'), ('bob', 'alice')):
            self.send(sender, receiver)
        after = self.coord.metrics().value('peerspan_coord_relay_bytes_total')
        need(after > before, 'relay_bytes_total grows with the messages (they are relayed)', before, after)
        self.state['hosts up'] = True
        return f'networks {self.net1[:16]}… (Go creator) and {self.net2[:16]}… (Rust creator); relayed ' \
               f'{after - before:.0f} bytes'

    # 5. re-run, upgrades

    def snapshot(self):
        c = self.coord
        files = [BINARY, ENV_FILE, self.litestream_bin, *self.unit_paths.values()]
        listing = c.out('for f in ' + ' '.join(shlex.quote(f) for f in files) +
                        '; do stat -c "%n %F %a %U %G %s" "$f"; sha256sum "$f"; done; '
                        f'stat -c "%n %F %a %U %G" {STATE} {STATE}/coord.db /etc/peerspan-coord; '
                        'ls -la /etc/peerspan-coord; getent passwd peerspan-coord; getent group peerspan-coord; '
                        'find /etc/systemd/system -name "*peerspan*" -o -name "*litestream*" | sort; '
                        'systemctl cat peerspan-coord litestream')
        ruleset = re.sub(r'counter packets \d+ bytes \d+', 'counter', c.out('nft list ruleset'))
        units = (c.unit_state('peerspan-coord'), c.unit_state('litestream'))
        invocation = c.show('peerspan-coord', 'InvocationID', 'MainPID')
        mtimes = c.out('stat -c "%n %Y" ' + ' '.join(shlex.quote(f) for f in files))
        return {'files': listing, 'nftables': ruleset, 'units': units, 'service': invocation}, mtimes

    def check_rerun(self):
        c = self.coord
        c.out(f'printf "# peerspan-m8s4-suite marker\\n" >> {ENV_FILE}')
        before, mtimes_before = self.snapshot()
        code, stdout, stderr = self.install(c, f'/root/{self.archives[self.v1]["top"]}', '--listen', LISTEN,
                                            capture='re-run')
        need(code == 0, 're-running install.sh with the same arguments exits 0', code, stderr[-800:])
        out = self.printed(stdout, 're-run')
        need(out == self.identity, 're-running prints the same JSON (same identity)', out, self.identity)
        after, mtimes_after = self.snapshot()
        need('peerspan-m8s4-suite marker' in (c.read(ENV_FILE) or ''), 'an existing env file is kept')
        for key in ('files', 'nftables', 'units'):
            need(before[key] == after[key], f're-running changes nothing ({key})',
                 diff_text(before[key], after[key]))
        # Q3: "changes nothing" read as including the running service, which is not restarted.
        need(before['service'] == after['service'], 're-running does not restart the running coordinator (Q3)',
             before['service'], after['service'])
        notes = 'nothing changed'
        if mtimes_before != mtimes_after:
            notes += '; files rewritten with the same content (modification times changed, Q3)'
        return notes

    def check_upgrade(self):
        c = self.coord
        top = self.extract(c, self.v2)
        invocation = c.show('peerspan-coord', 'InvocationID')['InvocationID']
        ruleset = self.snapshot()[0]['nftables']
        moment = utcnow()
        code, stdout, stderr = self.install(c, top, '--upgrade', capture='upgrade')
        need(code == 0, 'install.sh --upgrade exits 0', code, stderr[-800:])
        out = self.printed(stdout, 'upgrade')
        need(out == {**self.identity, 'firewall': 'unchanged'}, '--upgrade prints the same JSON with firewall '
             '`unchanged`; the identity is unchanged', out, self.identity)
        need(self.snapshot()[0]['nftables'] == ruleset, '--upgrade never touches the firewall (nftables ruleset)')
        need(sha256_bytes(c.read_bytes(BINARY)) == self.archives[self.v2]['binary'],
             '--upgrade replaces the binary with the extracted archive\'s')
        need(c.show('peerspan-coord', 'InvocationID')['InvocationID'] != invocation, '--upgrade restarts the service')
        status, body = c.healthz()
        need(status == 200 and body == {'status': 'ok', 'id': self.identity['id']}, '/healthz after the upgrade',
             status, body)
        versions = c.metrics().series('peerspan_coord_info')
        need(len(versions) == 1 and versions[0][0].get('version') == self.v2,
             'peerspan_coord_info{version} is the new VERSION after --upgrade', versions)
        need(c.info()['public_key'] == self.identity['public_key'], 'the key is unchanged after --upgrade')
        if self.state.get('hosts up'):
            self.synced_after(('alice', 'bob'), moment, 60, 'after the upgrade')
        return f'version {self.v2}'

    def check_failed_upgrade(self):
        c = self.coord
        current = sha256_bytes(c.read_bytes(BINARY))
        source = f'/root/{self.archives[self.v2]["top"]}'
        bad = '/root/peerspan-m8s4-suite-bad'
        # A binary that behaves for every subcommand but never serves: `run` sleeps without listening.
        c.out(f'rm -rf {bad} && cp -a {source} {bad} && mkdir -p /opt/peerspan-m8s4-suite && '
              f'cp {source}/bin/peerspan-coord /opt/peerspan-m8s4-suite/real-coord && '
              f'chmod 0755 /opt/peerspan-m8s4-suite /opt/peerspan-m8s4-suite/real-coord')
        c.write(f'{bad}/bin/peerspan-coord', '#!/bin/sh\nfor a in "$@"; do [ "$a" = run ] && exec sleep 600; done\n'
                'exec /opt/peerspan-m8s4-suite/real-coord "$@"\n', mode='0755')
        moment = utcnow()
        code, stdout, stderr = self.install(c, bad, '--upgrade', capture='failed-upgrade')
        need(code == 1, 'an upgrade whose binary fails health exits 1', code, stdout[-400:], stderr[-800:])
        need(sha256_bytes(c.read_bytes(BINARY)) == current, 'the previous binary is restored')
        eventually(lambda: c.healthz()[0] == 200, 30, 'the service is healthy again after the rollback',
                   lambda: c.sh('systemctl status peerspan-coord --no-pager').stdout[-600:])
        need(c.unit_state('peerspan-coord') == ('enabled', 'active'), 'the service is active after the rollback',
             c.unit_state('peerspan-coord'))
        need(c.healthz()[1] == {'status': 'ok', 'id': self.identity['id']}, 'the identity is unchanged')
        versions = c.metrics().series('peerspan_coord_info')
        need(versions and versions[0][0].get('version') == self.v2, 'the running version is the previous one',
             versions)
        if self.state.get('hosts up'):
            self.synced_after(('alice', 'bob'), moment, 60, 'after the rollback')
        return 'rolled back, exit 1'

    def check_upgrade_no_firewall(self):
        """`--no-firewall` with `--upgrade` is a usage error (exit 2), in either order, and changes nothing."""
        c = self.coord
        # The other archive, so that an upgrade wrongly carried out would show in the binary.
        top = f'/root/{self.archives[self.v1]["top"]}'
        binary = sha256_bytes(c.read_bytes(BINARY))
        invocation = c.show('peerspan-coord', 'InvocationID')['InvocationID']
        ruleset = self.snapshot()[0]['nftables']
        for args in (('--upgrade', '--no-firewall'), ('--no-firewall', '--upgrade')):
            code, stdout, stderr = self.install(c, top, *args)
            need(code == 2, f'install.sh {" ".join(args)} is a usage error (exit 2)', code, stdout[-300:],
                 stderr[-500:])
            need(sha256_bytes(c.read_bytes(BINARY)) == binary, f'{" ".join(args)} leaves the binary in place')
            need(c.show('peerspan-coord', 'InvocationID')['InvocationID'] == invocation,
                 f'{" ".join(args)} does not restart the service')
            need(self.snapshot()[0]['nftables'] == ruleset, f'{" ".join(args)} leaves the firewall alone')
        return 'exit 2 in both orders'

    # ufw on Ubuntu 24.04

    def start_ubuntu(self, label, ip):
        """An Ubuntu 24.04 systemd container with ufw active and two rules of its own (as on a shared VM)."""
        c = self.start_debian(label, self.ubuntu_image, ip)
        release = c.out('. /etc/os-release; echo "$ID $VERSION_ID"').strip()
        need(release == 'ubuntu 24.04', '(suite) the container is Ubuntu 24.04', release)
        c.out("ufw allow 22/tcp >/dev/null && ufw allow 8080/tcp comment 'other-service' >/dev/null")
        enable = c.sh('ufw --force enable')
        status = c.sh('ufw status')
        need('Status: active' in status.stdout, '(suite) ufw can be enabled in the Ubuntu container',
             enable.returncode, enable.stdout[-500:], enable.stderr[-800:], status.stdout[-500:],
             status.stderr[-500:])
        need(self.tcp(c.ip, 9464) == 'dropped', '(suite) ufw is in effect (an unlisted port is dropped)')
        return c

    def ufw_rules(self, c):
        """The user rules, as `ufw show added` prints them (one command per rule)."""
        result = c.sh('ufw show added')
        need(result.returncode == 0, '(suite) `ufw show added` works', result.stderr)
        return [line.strip() for line in result.stdout.splitlines() if line.strip().startswith('ufw ')]

    def ufw_rest(self, c):
        """Everything of ufw but its user rules: status header (defaults, logging) and its other files."""
        status = c.out('ufw status verbose').split('\nTo ')[0]
        files = c.out('cd /etc && sha256sum default/ufw ufw/ufw.conf ufw/sysctl.conf ufw/before.rules '
                      'ufw/before6.rules ufw/after.rules ufw/after6.rules; ls -1 /etc/ufw /etc/ufw/applications.d')
        return status, files

    def ufw_firewall_state(self, c):
        return {'rules': self.ufw_rules(c), 'rest': self.ufw_rest(c), 'table': self.peerspan_table(c),
                'nftables.conf': c.read('/etc/nftables.conf')}

    def check_ubuntu_ufw(self):
        c = self.start_ubuntu('ubuntu-ufw', self.spare_ips[0])
        before = self.ufw_firewall_state(c)
        need(not before['table'], '(suite) no peerspan_coord table before the install')
        top = self.extract(c, self.v1)
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN, capture='ubuntu-install')
        need(code == 0, 'on Ubuntu 24.04 install.sh --listen 0.0.0.0:443 exits 0', code, stdout[-600:],
             stderr[-1500:])
        out = self.printed(stdout, 'ubuntu')
        need(out['firewall'] == 'ufw', 'with ufw installed and active, firewall is `ufw`', out)
        self.check_installed(c, out, stdout, stderr, self.v1, 'ubuntu')
        after = self.ufw_firewall_state(c)
        removed = multiset_minus(before['rules'], after['rules'])
        added = multiset_minus(after['rules'], before['rules'])
        need(not removed, 'ufw: the other ufw rules stay in place', removed, after['rules'])
        rule = re.compile(r"ufw allow (?:in )?(?:443/(tcp|udp)|proto (tcp|udp) (?:from any )?to any port 443)"
                          r" comment '?peerspan-coord'?")
        protocols = sorted(next(p for p in m.groups() if p) for m in map(rule.fullmatch, added) if m)
        need(len(added) == 2 and protocols == ['tcp', 'udp'], 'ufw: install.sh adds exactly two allow rules, the '
             'coordination port over TCP and over UDP, commented peerspan-coord', added)
        need(after['rest'] == before['rest'], 'ufw: nothing else in ufw changes (defaults, logging, its other files, '
             'still active)', diff_text(before['rest'], after['rest']))
        need(not after['table'], 'ufw: install.sh writes no `inet peerspan_coord` nftables table')
        # Q12: "writes no nftables table" read as including /etc/nftables.conf (which loads tables at boot).
        need(after['nftables.conf'] == before['nftables.conf'], 'ufw: /etc/nftables.conf is unchanged (Q12)',
             diff_text(before['nftables.conf'], after['nftables.conf']))
        # The rules in effect, from this machine.
        need(self.tcp(c.ip, 443) == 'open', 'ufw: TCP 443 is reachable from outside')
        need(self.stun(c.ip, 443), 'ufw: STUN on UDP 443 answers from outside')
        need(self.tcp(c.ip, 8080) == 'refused', 'ufw: the existing rule (8080/tcp) still allows its port (refused, '
             'as nothing listens, rather than dropped)')
        need(self.tcp(c.ip, 9464) == 'dropped', 'ufw: an unlisted port is still dropped')
        # Re-running adds no duplicate rules.
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN, capture='ubuntu-re-run')
        need(code == 0, 'ufw: re-running install.sh exits 0', code, stderr[-800:])
        need(self.printed(stdout, 'ubuntu re-run') == out, 'ufw: re-running prints the same JSON', stdout)
        need(self.ufw_firewall_state(c) == after, 'ufw: re-running adds no duplicate rules and changes nothing',
             diff_text(after, self.ufw_firewall_state(c)))
        # An upgrade never touches the firewall.
        top2 = self.extract(c, self.v2)
        code, stdout, stderr = self.install(c, top2, '--upgrade', capture='ubuntu-upgrade')
        need(code == 0, 'ufw: install.sh --upgrade exits 0', code, stderr[-800:])
        need(self.printed(stdout, 'ubuntu upgrade') == {**out, 'firewall': 'unchanged'},
             'ufw: --upgrade prints the same JSON with firewall `unchanged`', stdout)
        need(sha256_bytes(c.read_bytes(BINARY)) == self.archives[self.v2]['binary'],
             'ufw: --upgrade replaces the binary')
        need(self.ufw_firewall_state(c) == after, 'ufw: --upgrade leaves the ufw rules and nftables alone',
             diff_text(after, self.ufw_firewall_state(c)))
        self.docker.remove_container(c.name)
        return 'added: ' + '; '.join(added)

    # --no-firewall

    def check_no_firewall_debian(self):
        c = self.start_debian('nofw-debian', None, self.spare_ips[1])

        def firewall():
            return {'ruleset': c.out('nft list ruleset'), 'nftables.conf': c.read('/etc/nftables.conf'),
                    'nftables.service': c.unit_state('nftables')}
        before = firewall()
        top = self.extract(c, self.v1)
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN, '--no-firewall',
                                            capture='no-firewall-debian')
        need(code == 0, 'Debian: install.sh --listen 0.0.0.0:443 --no-firewall exits 0', code, stdout[-600:],
             stderr[-1500:])
        out = self.printed(stdout, 'Debian --no-firewall')
        need(out['firewall'] == 'none', 'Debian: with --no-firewall, firewall is `none`', out)
        self.check_installed(c, out, stdout, stderr, self.v1, 'Debian --no-firewall')
        need(not self.peerspan_table(c), 'Debian: --no-firewall writes no `inet peerspan_coord` table')
        need(firewall() == before, 'Debian: --no-firewall changes no firewall (ruleset, /etc/nftables.conf, '
             'nftables.service)', diff_text(before, firewall()))
        need(self.tcp(c.ip, 443) == 'open', 'Debian: TCP 443 is reachable with no firewall written')
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN, '--no-firewall')
        need(code == 0 and self.printed(stdout, 'Debian --no-firewall re-run') == out,
             'Debian: re-running with --no-firewall prints the same JSON', code, stdout, stderr[-500:])
        need(firewall() == before, 'Debian: re-running with --no-firewall changes no firewall')
        binary = sha256_bytes(c.read_bytes(BINARY))
        top2 = self.extract(c, self.v2)
        code, stdout, stderr = self.install(c, top2, '--upgrade', '--no-firewall')
        need(code == 2, 'Debian: --upgrade --no-firewall exits 2', code, stdout[-300:], stderr[-500:])
        need(sha256_bytes(c.read_bytes(BINARY)) == binary, 'Debian: the refused upgrade leaves the binary')
        # Neither `ufw` nor `none` removes a table written by an earlier run.
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN)
        need(code == 0 and self.printed(stdout, 'Debian default after --no-firewall')['firewall'] == 'nftables',
             'Debian: install.sh without --no-firewall then writes the nftables table', code, stdout,
             stderr[-500:])
        need(self.peerspan_table(c), 'Debian: the `inet peerspan_coord` table is loaded')
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN, '--no-firewall')
        need(code == 0 and self.printed(stdout, 'Debian --no-firewall after nftables')['firewall'] == 'none',
             'Debian: --no-firewall after an nftables install exits 0 with firewall `none`', code, stdout,
             stderr[-500:])
        need(self.peerspan_table(c), '`none` does not remove a table written by an earlier run')
        self.docker.remove_container(c.name)
        return 'no table, ruleset unchanged; upgrade with --no-firewall exit 2; earlier table kept'

    def check_no_firewall_ubuntu(self):
        c = self.start_ubuntu('nofw-ubuntu', self.spare_ips[2])
        before = self.ufw_firewall_state(c)
        top = self.extract(c, self.v1)
        code, stdout, stderr = self.install(c, top, '--listen', LISTEN, '--no-firewall',
                                            capture='no-firewall-ubuntu')
        need(code == 0, 'Ubuntu: install.sh --listen 0.0.0.0:443 --no-firewall exits 0', code, stdout[-600:],
             stderr[-1500:])
        out = self.printed(stdout, 'Ubuntu --no-firewall')
        need(out['firewall'] == 'none', 'Ubuntu: with --no-firewall (ufw active), firewall is `none`', out)
        self.check_installed(c, out, stdout, stderr, self.v1, 'Ubuntu --no-firewall')
        after = self.ufw_firewall_state(c)
        need(after['rules'] == before['rules'], 'Ubuntu: --no-firewall adds no ufw rule', before['rules'],
             after['rules'])
        need(not after['table'], 'Ubuntu: --no-firewall writes no `inet peerspan_coord` table')
        need(after == before, 'Ubuntu: --no-firewall changes no firewall', diff_text(before, after))
        need(self.tcp(c.ip, 443) == 'dropped', 'Ubuntu: with ufw active and no rule added, TCP 443 stays closed '
             'until the owner opens it')
        binary = sha256_bytes(c.read_bytes(BINARY))
        top2 = self.extract(c, self.v2)
        code, stdout, stderr = self.install(c, top2, '--upgrade', '--no-firewall')
        need(code == 2, 'Ubuntu: --upgrade --no-firewall exits 2', code, stdout[-300:], stderr[-500:])
        need(sha256_bytes(c.read_bytes(BINARY)) == binary, 'Ubuntu: the refused upgrade leaves the binary')
        need(self.ufw_firewall_state(c) == before, 'Ubuntu: the refused upgrade changes no firewall')
        self.docker.remove_container(c.name)
        return 'no ufw rule, no table; upgrade with --no-firewall exit 2'

    def check_requests(self):
        need(self.capture_notes, '(suite) install.sh runs were captured')
        need(not self.violations, 'install.sh contacts nothing except the Litestream download (Q4)',
             [(name, v[:6]) for name, v in self.violations])
        return '; '.join(self.capture_notes)

    # 6. Litestream

    def litestream_env(self):
        """The Litestream env file: the variables litestream.yml (as shipped) references, filled for MinIO."""
        deploy = self.archives[self.v1]['dir'] / 'share' / 'peerspan-coord' / 'deploy'
        text = (deploy / 'litestream.yml').read_text()
        values_text = '\n'.join(line.split('#', 1)[0] for line in text.splitlines())
        names = set(re.findall(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', values_text)) | set(
            re.findall(r'\$([A-Za-z_][A-Za-z0-9_]*)', values_text))
        example = deploy / 'litestream.env.example'
        if example.exists():
            names |= set(re.findall(r'^\s*#?\s*([A-Z_][A-Z0-9_]*)=', example.read_text(), re.M))
        values = {}
        unknown = []
        for name in sorted(names):
            upper = name.upper()
            if 'SECRET' in upper:
                values[name] = MINIO_PASSWORD
            elif 'ACCESS_KEY' in upper or upper.endswith('_KEY_ID'):
                values[name] = MINIO_USER
            elif 'BUCKET' in upper:
                values[name] = BUCKET
            elif 'ENDPOINT' in upper or upper.endswith('_URL') and 'S3' in upper:
                values[name] = f'https://{self.minio_ip}:9000'
            elif 'REGION' in upper:
                values[name] = 'us-east-1'
            elif upper.endswith('PATH') and 'KEY' not in upper:
                values[name] = 'peerspan-coord'
            elif 'FORCE_PATH_STYLE' in upper:
                values[name] = 'true'
            elif 'SSE' in upper and 'PATH' in upper or 'KEY_FILE' in upper:
                values[name] = SSE_KEY
            else:
                unknown.append(name)
        need(not unknown, '(suite) every variable of the shipped litestream.yml is understood', unknown, text)
        # Litestream also reads these for S3 credentials.
        values.setdefault('LITESTREAM_ACCESS_KEY_ID', MINIO_USER)
        values.setdefault('LITESTREAM_SECRET_ACCESS_KEY', MINIO_PASSWORD)
        return ''.join(f'{k}={v}\n' for k, v in sorted(values.items())), text

    def runbook(self):
        return (self.archives[self.v1]['dir'] / 'share' / 'peerspan-coord' / 'deploy' / 'README.md').read_text()

    def runbook_key_commands(self):
        """The runbook's Hetzner step 2 commands that create the SSE-C key (its `cat` for the password manager
        and its env file heredoc, which the suite writes with MinIO's values, left out)."""
        section = runbook_section(self.runbook(), r'2\.')
        lines = []
        for line in shell_lines(section or ''):
            if re.match(r'^(cat|LITESTREAM_|ENV$|\(umask 077; cat)', line):
                continue
            if 'litestream-sse.key' in line or line.startswith('install -d'):
                lines.append(line)
        return lines

    def configure_litestream(self, c):
        env, _ = self.litestream_env()
        c.write(LITESTREAM_ENV, env, mode='0600')
        c.copy_in(self.ca, '/usr/local/share/ca-certificates/peerspan-m8s4-suite-ca.crt')
        c.out('update-ca-certificates >/dev/null')
        commands = self.runbook_key_commands()
        if commands:
            c.out('set -e; ' + '; '.join(commands))
        else:
            # Q8: the runbook gives no command; a 32-byte key in raw bytes, mode 0600.
            c.out(f'head -c 32 /dev/urandom > {SSE_KEY} && chmod 0600 {SSE_KEY}')
        st = c.stat(SSE_KEY)
        need(st and st[1] == 0o600, 'the SSE-C key file is mode 0600 (runbook)', st)
        raw = c.read_bytes(SSE_KEY)
        self.sse_key_raw = raw
        key = raw if len(raw) == 32 else None
        if key is None:
            try:
                decoded = base64.b64decode(raw.strip(), validate=True)
                key = decoded if len(decoded) == 32 else None
            except ValueError:
                key = None
            if key is None and re.fullmatch(rb'[0-9a-fA-F]{64}\s*', raw):
                key = bytes.fromhex(raw.strip().decode())
        need(key is not None, 'the SSE-C key is 32 bytes (raw, base64, or hex)', len(raw))
        return key, commands

    def check_litestream(self):
        c = self.coord
        self.sse_key, commands = self.configure_litestream(c)
        moment = utcnow()
        code, stdout, stderr = self.install(c, f'/root/{self.archives[self.v2]["top"]}', '--listen', LISTEN)
        need(code == 0, 'install.sh with Litestream configured exits 0', code, stderr[-800:])
        out = self.printed(stdout, 'with Litestream')
        need(out['litestream'] == 'enabled', 'litestream is `enabled` once its env file and key exist', out)
        need({k: out[k] for k in ('id', 'public_key', 'listen')} ==
             {k: self.identity[k] for k in ('id', 'public_key', 'listen')}, 'the identity is unchanged', out)
        need(out['firewall'] == 'nftables', 'install.sh --listen again reports firewall `nftables`', out)
        eventually(lambda: c.unit_state('litestream') == ('enabled', 'active'), 30,
                   'the litestream unit is enabled and active', lambda: c.sh('systemctl status litestream '
                                                                             '--no-pager; journalctl -u litestream '
                                                                             '-n 30 --no-pager').stdout[-1500:])
        need(c.unit_state('peerspan-coord') == ('enabled', 'active'), 'peerspan-coord stays enabled and active')
        user = c.show('litestream', 'User').get('User')
        need(user == 'peerspan-coord', 'Litestream runs as the coordinator\'s user', user)
        if self.state.get('hosts up'):
            # A change to replicate.
            self.hosts['alice'].cli('agent', 'register', '--name', 'replicated', '--owner', 'alice')
            self.synced_after(('alice', 'bob'), moment, 60, 'with Litestream running')
        eventually(lambda: self.s3.objects(BUCKET), 120, 'Litestream writes replicas to the bucket',
                   lambda: c.sh('journalctl -u litestream -n 40 --no-pager').stdout[-2000:])
        time.sleep(5)
        objects = self.s3.objects(BUCKET)
        plaintexts = []
        for name, size in objects:
            path = f'/{BUCKET}/{name}'
            status, _, body = self.s3.request('GET', path)
            need(status in (400, 403), f'an object is unreadable without the SSE-C key ({name})', status, body[:200])
            status, _, _ = self.s3.request('GET', path, headers=ssec(secrets.token_bytes(32)))
            need(status in (400, 403), f'an object is unreadable with a wrong key ({name})', status)
            status, headers, body = self.s3.request('GET', path, headers=ssec(self.sse_key))
            need(status == 200, f'an object reads with the SSE-C key ({name})', status, body[:200])
            need(headers.get('x-amz-server-side-encryption-customer-algorithm') == 'AES256',
                 'the object is stored with SSE-C (AES256)', headers)
            if len(body) >= 64:
                plaintexts.append(body)
        # The provider stores only ciphertext: no 64-byte run of any plaintext on MinIO's disk.
        disk = self.root / 'minio-disk'
        if disk.exists():
            shutil.rmtree(disk)
        self.docker('cp', f'{self.minio}:/data', str(disk))
        stored = b''.join(p.read_bytes() for p in disk.rglob('*') if p.is_file())
        for body in plaintexts:
            for offset in range(0, len(body) - 64, max(64, len(body) // 16)):
                need(body[offset:offset + 64] not in stored, 'MinIO\'s disk holds no plaintext of a replica')
        self.state['replicating'] = True
        return f'{len(objects)} objects; key commands from the runbook: {commands or "none (Q8)"}'

    # 7. restore from the replica

    def check_restore(self):
        a = self.coord
        # Let replication settle, then stop it: changes from here are beyond the last replicated transaction.
        time.sleep(15)
        count = len(self.s3.objects(BUCKET))
        a.out('systemctl stop litestream')
        self.host('carol', 'Go')
        self.join('alice', 'carol', self.net1, 'carol')
        carol = self.ids['carol']
        eventually(lambda: carol in self.members('bob', self.net1), 90, 'bob sees carol before the restore')
        # The first server goes away.
        self.docker('stop', '-t', '20', a.name, timeout=120)
        if not self.args.keep:
            self.docker.remove_container(a.name)
        else:
            self.docker('rename', a.name, a.name + '-old')
            self.docker.containers[self.docker.containers.index(a.name)] = a.name + '-old'
            self.docker('network', 'disconnect', self.network, a.name + '-old')
        b = self.coord = self.start_debian('coord-b')
        steps = self.runbook_restore(b)
        moment = utcnow()
        info = b.info()
        need(info['id'] == self.identity['id'] and info['public_key'] == self.identity['public_key'],
             'the restored coordinator keeps the identity', info, self.identity)
        status, body = b.healthz()
        need(status == 200 and body == {'status': 'ok', 'id': self.identity['id']}, '/healthz on the restored server',
             status, body)
        need(b.unit_state('peerspan-coord') == ('enabled', 'active'), 'peerspan-coord runs on the restored server',
             b.unit_state('peerspan-coord'))
        self.synced_after(('alice', 'bob', 'carol'), moment, 120, 'after the restore', nets=[self.net1])
        self.synced_after(('alice', 'bob'), moment, 120, 'after the restore', nets=[self.net2])
        # Repair: carol joined after the last replicated transaction; a fresh joiner learns it from the coordinator.
        self.host('erin', 'Rust')
        self.join('alice', 'erin', self.net1, 'erin')
        everyone = {self.ids[n] for n in ('alice', 'bob', 'carol', 'erin')}
        eventually(lambda: everyone <= self.members('erin', self.net1), 120,
                   'repair: carol, who joined after the last replicated transaction, reappears at the restored '
                   'coordinator (erin, joining fresh, sees her)', lambda: sorted(self.members('erin', self.net1)))
        for sender, receiver in (('alice', 'bob'), ('bob', 'carol'), ('carol', 'erin'), ('erin', 'alice')):
            self.send(sender, receiver)
        return f'{count} objects before the stop; runbook steps: {steps}'

    def runbook_restore(self, b):
        """The runbook's restore onto a second server (Hetzner step 7), as a real recovery: install.sh without the
        Litestream files (a new throwaway identity), the env file and the key from the password manager, the
        step's restore commands, then `litestream reset` and install.sh again, which reports the production
        identity with Litestream enabled."""
        top = self.extract(b, self.v2)
        code, stdout, stderr = self.install(b, top, '--listen', LISTEN)
        need(code == 0, 'runbook step 7.2: install.sh on the second server exits 0', code, stderr[-800:])
        fresh = self.printed(stdout, 'runbook step 7.2')
        need(fresh['litestream'] == 'not configured' and fresh['id'] != self.identity['id'],
             'runbook step 7.2: a new throwaway identity, litestream not configured', fresh)
        self.configure_litestream_fresh(b)
        section = runbook_section(self.runbook(), r'7\.')
        need(section and re.search(r'litestream restore', section), 'the runbook has a restore drill from the '
             'replica (Hetzner step 7)', (section or '')[:400])
        commands = shell_lines(section)
        need(commands, 'the runbook\'s restore drill has commands', section[:800])
        # Q9: the runbook's `curl` right after `systemctl start` is retried for up to 10 seconds, as an operator
        # typing it would.
        script = '\n'.join(
            'for i in $(seq 1 40); do ' + line + ' && break; sleep 0.25; done; ' + line
            if line.startswith('curl ') and '/healthz' in line else line for line in commands)
        result = b.sh('set -e\n' + script, cwd='/root', timeout=600)
        need(result.returncode == 0, 'the runbook\'s restore commands succeed', result.returncode,
             result.stdout[-800:], result.stderr[-1500:])
        need(self.identity['id'] in result.stdout and self.identity['public_key'] in result.stdout,
             'the runbook\'s /healthz and info report the production id and public_key', result.stdout[-800:])
        # A real recovery continues: reset Litestream's tracking and run install.sh again.
        recovery = re.search(r'\*\*A real recovery\*\*(.*?)(?:\n\n|$)', self.runbook(), re.S)
        need(recovery and 'litestream reset' in recovery.group(1) and 'install.sh --listen' in recovery.group(1),
             'the runbook\'s real recovery resets Litestream and runs install.sh again',
             recovery.group(0)[:400] if recovery else None)
        reset = re.search(r'`(litestream reset [^`]+)`', recovery.group(1)).group(1)
        result = b.sh(f'set -a; . {LITESTREAM_ENV}; set +a; {reset}', timeout=120)
        need(result.returncode == 0, f'`{reset}` succeeds', result.returncode, result.stderr[-600:])
        code, stdout, stderr = self.install(b, top, '--listen', LISTEN)
        need(code == 0, 'install.sh after the restore exits 0', code, stderr[-800:])
        out = self.printed(stdout, 'after the restore')
        need(out == {**self.identity, 'litestream': 'enabled'}, 'install.sh after the restore reports the '
             'production identity with litestream enabled', out, self.identity)
        eventually(lambda: b.unit_state('litestream') == ('enabled', 'active'), 30,
                   'Litestream replicates again on the restored server', lambda: b.unit_state('litestream'))
        return [*commands, reset, 'install.sh --listen 0.0.0.0:443']

    def configure_litestream_fresh(self, b):
        """The fresh server gets the env file and the same SSE-C key (from the owner's password manager)."""
        env, _ = self.litestream_env()
        b.out('install -d -m 0755 /etc/peerspan-coord')
        b.write(LITESTREAM_ENV, env, mode='0600')
        b.write(SSE_KEY, self.sse_key_file_bytes(), mode='0600')
        b.copy_in(self.ca, '/usr/local/share/ca-certificates/peerspan-m8s4-suite-ca.crt')
        b.out('update-ca-certificates >/dev/null')

    def sse_key_file_bytes(self):
        return self.sse_key_raw if getattr(self, 'sse_key_raw', None) else self.sse_key

    # 8. other distributions

    def check_other_distribution(self):
        notes = []
        for image in OTHER_IMAGES:
            label = re.sub(r'[^a-z0-9]+', '', image)
            name = PREFIX + label
            self.docker('create', '--name', name, '--network', 'none', image, 'sleep', 'infinity')
            self.docker.containers.append(name)
            self.docker('start', name)
            c = Container(self.docker, name, None)
            top = self.extract(c, self.v1)
            before = c.out('ls -a /usr/local/bin /etc /var/lib | sha256sum; getent passwd | sha256sum')
            result = c.sh(f'./share/peerspan-coord/deploy/install.sh --listen {LISTEN}', cwd=top, timeout=120)
            need(result.returncode == 1, f'install.sh exits 1 on another distribution ({image})', result.returncode,
                 result.stdout[-300:], result.stderr[-500:])
            after = c.out('ls -a /usr/local/bin /etc /var/lib | sha256sum; getent passwd | sha256sum')
            need(before == after, f'a refused install on {image} changes nothing (no user, binary, '
                 '/etc/peerspan-coord, or state)')
            need(c.sh('getent passwd peerspan-coord').returncode != 0 and c.sh(f'test -e {BINARY}').returncode != 0,
                 f'no peerspan-coord user or binary on {image}')
            last = result.stderr.strip().splitlines()[-1][:120] if result.stderr.strip() else 'exit 1'
            notes.append(f'{image}: {last}')
            self.docker.remove_container(name)
        return '; '.join(notes)


# --- the runbook's restore procedure ------------------------------------------------------------------------

def runbook_section(readme, number):
    """The text under the runbook's `### N. ...` heading, up to the next heading of that level or higher."""
    lines = readme.splitlines()
    for i, line in enumerate(lines):
        if re.match(r'^###\s+' + number + r'\s', line):
            body = []
            for following in lines[i + 1:]:
                if re.match(r'^#{1,3}\s', following):
                    break
                body.append(following)
            return '\n'.join(body)
    return None


def shell_lines(section):
    out = []
    for block in re.findall(r'```(?:sh|bash|shell|console)?\n(.*?)```', section, re.S):
        block = '\n'.join(line.strip() for line in block.splitlines())
        joined = re.sub(r'\\\n\s*', ' ', block)
        for line in joined.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            out.append(line.lstrip('$ ').strip())
    return out


def extract_all(tar, directory):
    try:
        tar.extractall(directory, filter='tar')
    except TypeError:
        tar.extractall(directory)


def diff_text(a, b):
    a_lines, b_lines = str(a).splitlines(), str(b).splitlines()
    return [line for line in b_lines if line not in a_lines][:8] + ['--'] + \
        [line for line in a_lines if line not in b_lines][:8]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--go', type=Path, required=True, help='Go peerspan-host')
    parser.add_argument('--rust', type=Path, required=True, help='Rust peerspan-host')
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent,
                        help='repository root, for scripts/package-coordinator.sh (default: this checkout)')
    parser.add_argument('--probe', type=Path, help='peerspan-peer-probe (optional; set for shared helpers)')
    parser.add_argument('--keep', action='store_true', help='keep containers, networks, images, and dist files')
    parser.add_argument('--logs', type=Path, help='save install outputs and host logs here when a section fails')
    args = parser.parse_args()
    args.go, args.rust, args.repo = (p.resolve(strict=True) for p in (args.go, args.rust, args.repo))
    if args.probe:
        set_probe(args.probe.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix='peerspan-coord-deploy-') as temporary:
        suite = Suite(args, Path(temporary))
        try:
            suite.run()
        except Exception:
            detail = traceback.format_exc(limit=8)
            suite.results.append(('suite', False, detail))
            print(f'FAIL [suite]: {detail}', flush=True)
        finally:
            if args.logs and not all(ok for _, ok, _ in suite.results):
                save_logs(suite, args.logs)
            try:
                suite.close()
            except Exception as error:
                suite.results.append(('shutdown', False, repr(error)))
                print(f'FAIL [shutdown]: {error!r}', flush=True)
    failures = [(name, detail) for name, ok, detail in suite.results if not ok]
    print('==== summary', flush=True)
    for name, detail in failures:
        last = detail.strip().splitlines()[-1] if detail.strip() else ''
        print(f'FAIL [{name}]: {last[:1200]}', flush=True)
    if failures:
        raise SystemExit(f'{len(failures)} section(s) failed')
    print('PASS all sections', flush=True)


def save_logs(suite, directory):
    directory.mkdir(parents=True, exist_ok=True)
    logs = suite.root / 'logs'
    if logs.exists():
        for path in logs.iterdir():
            shutil.copy2(path, directory / path.name)
    for name, h in suite.hosts.items():
        try:
            h.logs.seek(0)
            (directory / f'{name}.log').write_bytes(h.logs.read())
        except (OSError, ValueError, AttributeError):
            pass
    if suite.coord is not None:
        for unit in ('peerspan-coord', 'litestream'):
            try:
                text = suite.coord.sh(f'journalctl -u {unit} --no-pager -n 400').stdout
                (directory / f'journal-{unit}.log').write_text(text)
            except Exception:
                pass
    for path in suite.root.glob('*.pcap'):
        shutil.copy2(path, directory / path.name)


if __name__ == '__main__':
    main()
