#!/usr/bin/env python3
"""Exercise hosted coordinator operations (milestone 8 slice 1) with the Go coordinator and Go and Rust hosts.

Written from docs/hosted-coordinator-contract.md ("Slice 1: operations", whose Verification paragraph
names this suite) alone, with context from the hosted coordinator proposal, the coordination contract
(relay, revocation), and the launch contract (coordinator limits, change notifications), independently of
the coordinator and host implementations. Hosts are driven through their CLIs and local APIs, and the
coordinator through raw TLS clients and relay connections built as the earlier suites build them.

Sections:

- ops listener: `/healthz` shape and id; 404 for other paths with any method; 405 with `Allow: GET` for
  other methods (HEAD included) on `/healthz` and `/metrics`; the ops listener not serving the coordination
  API; the coordination port answering 404 for the ops paths; other loopback literals accepted; a
  non-loopback or non-literal `--ops-listen` (including `localhost`) refused with exit 2 and the text line
  `error: --ops-listen must be a loopback address` before anything listens; no extra listener without the
  flag; `limit_refusals_total` (all three limits) and `relay_connections` (every relay ALPN: `/1`, `/2`,
  and `/3`) exposed at 0 from the start;
- metrics: every listed name with its type and label names, and default histogram buckets; `networks` and
  `member_hosts` before and after create, joins, and a revocation; `limit_refusals_total{limit="members"}`
  after a join refused under `--max-members`; `relay_connections` by ALPN for running hosts (on version 3)
  and a raw version 1 connection; `relay_bytes_total` growing with relay traffic (a raw relayed datagram, and joins
  and messages); `requests_total` for sync, an unmatched path, and a wrong method (both route `other`);
  `changes_notified_total` after a policy change; no label value equal to a network, host, or person ID,
  or an IP address;
- backup while serving: backups taken while hosts sync every second and exchange messages, and a raw relay
  connection relays datagrams continuously: exit 0, the printed object, mode 0600, an absolute path for a
  relative FILE, an intact SQLite file with the printed user_version, the coordinator's id, and no
  temporary files left;
- backup refusals: an existing FILE refused unchanged, a state without a database refused;
- restore refused while running: `coordinator is running` for `--replace FILE`, `FILE --replace`, and
  `FILE`, nothing changed;
- restore refusals: a backup of a stopped coordinator; over an existing database without `--replace` (a
  valid and a corrupt FILE); corrupt or non-coordinator files (random bytes, empty, truncated, a host
  database, a SQLite file without the identity row, an unsupported user_version, a missing file) with
  `--replace` before or after FILE; each changing nothing;
- restore and keep working: into a new state directory (0700, coord.db 0600, `replaced` null, same
  identity), then `restore FILE --replace` over it; with `--replace` over the old state (previous database
  kept byte for byte as `coord.db.replaced-YYYYMMDDTHHMMSSZ`, with its -wal if any, other -wal and -shm
  removed); then a coordinator on the restored state at the same address: Go and Rust hosts sync again, a
  new host joins with a fresh invite, and messages flow in every direction under connected-only grants,
  with no host restarted or reconfigured;
- restore keeps a leftover -wal: a coordinator SIGKILLed after raw registrations and joins; a replaced
  name already taken refused unchanged; then the previous database and its -wal kept byte for byte as
  `coord.db.replaced-TIMESTAMP` and `-wal`, the -shm removed (skipped, and said so, if the kill leaves no
  -wal);
- logs: every stderr line of every `run` is a JSON object with `time` (ending in `Z`), `level`, and `msg`;
  one `start` (id, listen, ops_listen) and one final `stop` (except for the killed run); `request` lines
  (with `host` always, and `network` for `{network}` routes) for create, join, sync, an unmatched path,
  and a wrong method; `relay` lines for a closed and a refused relay connection; no `error` line for a 4xx
  answer; and none of the collected secrets (invite tokens and their seeds and signatures, host, root,
  person, and coordinator public keys, person private key material, statement signatures and policy JSON,
  message contents, relayed payloads, client ports) or any `127.0.0.1` outside the start line's own
  listen fields;
- deployment files: `systemd-analyze verify` on both units in a scratch root where available, the unit's
  contract settings (a static dedicated user, shared with Litestream), the environment example,
  `litestream.yml` parsing as YAML with the database path and SSE-C replicas, and the runbook's presence.

The creator (alice) and the revoked host (erin) run the --creator implementation (default Go); bob, the
stopped watcher, and the post-restore joiner (dave) run the other. Needs openssl and PyYAML; systemd-analyze
is optional. Everything runs under a temporary directory with HOME and XDG_CONFIG_HOME redirected per host;
the real ~/.config/peerspan and systemd are never touched. Exits non-zero listing every failed section.

Questions settled in the contract are checked as written; the few still open (the exact /healthz body, Q9,
and how limit flags reach ExecStart, Q7) are marked with a `Q<n>` comment.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))

from coordination import decode_token, wait_for  # noqa: E402
from host_service import die_with_parent, stop_all  # noqa: E402
from launch_directory import DirectoryHost  # noqa: E402
from launch_push import RawRelay, V1, V2, SEND, seed_of  # noqa: E402

V3 = 'peerspan-relay/3'
from launch_service import Key, RawNetwork, token_membership  # noqa: E402
from peer_messaging import available_port, request_id, set_probe, timestamp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / 'deploy' / 'coordinator'
INTERVAL = 1
LOOPBACK_REFUSAL = 'error: --ops-listen must be a loopback address'
DEFAULT_BUCKETS = {'0.005', '0.01', '0.025', '0.05', '0.1', '0.25', '0.5', '1', '2.5', '5', '10', '+Inf'}
SYNC_ROUTE = '/coord/v1/networks/{network}/sync'
CREATE_ROUTE = '/coord/v1/networks'
JOIN_ROUTE = '/coord/v1/networks/{network}/members'
METRICS = {
    'peerspan_coord_info': ('gauge', {'version'}),
    'peerspan_coord_networks': ('gauge', set()),
    'peerspan_coord_member_hosts': ('gauge', set()),
    'peerspan_coord_relay_connections': ('gauge', {'alpn'}),
    'peerspan_coord_requests_total': ('counter', {'route', 'code'}),
    'peerspan_coord_request_seconds': ('histogram', {'route'}),
    'peerspan_coord_relay_bytes_total': ('counter', set()),
    'peerspan_coord_limit_refusals_total': ('counter', {'limit'}),
    'peerspan_coord_changes_notified_total': ('counter', set()),
}
LIMITS = {'members', 'networks_per_ip', 'relay_bytes'}
TIME = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$')
IPV4 = re.compile(r'(?<![\d.])\d{1,3}(\.\d{1,3}){3}(?![\d.])')
REPLACED = re.compile(r'^coord\.db\.replaced-(\d{8}T\d{6}Z)$')


class Failure(AssertionError):
    pass


def need(condition, rule, *detail):
    """Assert one contract rule, naming it in the failure."""
    if not condition:
        raise Failure(f'hosted coordinator contract, slice 1: {rule}'
                      + (': ' + ' | '.join(repr(d)[:700] for d in detail) if detail else ''))


def eventually(predicate, timeout, rule, describe=None):
    try:
        return wait_for(predicate, timeout=timeout, message=rule)
    except AssertionError:
        need(False, rule, describe() if describe else 'timed out')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def utcnow():
    return datetime.now(timezone.utc)


def parse_time(value):
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)', value or '')
    assert match, value
    fraction = (match.group(2) or '.0')[:7]
    zone = '+00:00' if match.group(3) == 'Z' else match.group(3)
    return datetime.fromisoformat(match.group(1) + fraction + zone)


# --- the coordinator ---------------------------------------------------------------------------------------

class OpsCoordinator:
    """`peerspan-coord run`, with stdout and stderr kept in files for the log checks."""

    def __init__(self, binary, state, logdir, name, port=None, ops=None, flags=()):
        self.binary, self.state, self.logdir, self.name = str(binary), Path(state), Path(logdir), name
        self.port = port or available_port()
        self.address = f'127.0.0.1:{self.port}'
        self.ops = ops  # 'HOST:PORT' or None
        self.flags = tuple(flags)
        self.process = None
        self.runs = []  # (stderr path, address, ops, id)
        self.killed = set()  # stderr paths of runs ended with SIGKILL, which write no stop line

    @property
    def ops_port(self):
        return int(self.ops.rsplit(':', 1)[1]) if self.ops else None

    @property
    def ops_host(self):
        return self.ops.rsplit(':', 1)[0].strip('[]') if self.ops else None

    def info(self):
        result = subprocess.run([self.binary, '--state', str(self.state), 'info'], capture_output=True, text=True,
                                timeout=60)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def start(self):
        index = len(self.runs)
        err = self.logdir / f'{self.name}-{index}.stderr'
        out = self.logdir / f'{self.name}-{index}.stdout'
        command = [self.binary, '--state', str(self.state), 'run', '--listen', self.address]
        if self.ops:
            command += ['--ops-listen', self.ops]
        command += list(self.flags)
        with open(err, 'wb') as e, open(out, 'wb') as o:
            self.process = subprocess.Popen(command, stdout=o, stderr=e, preexec_fn=die_with_parent)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f'coordinator exited: {err.read_text(errors="replace")[-2000:]}')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=0.5):
                    pass
                if self.ops:
                    with socket.create_connection((self.ops_host, self.ops_port), timeout=0.5):
                        pass
                identity = self.info()
                self.runs.append((err, self.address, self.ops, identity['id']))
                return identity
            except OSError:
                time.sleep(0.05)
        raise AssertionError('coordinator did not become ready')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError('coordinator did not stop on SIGTERM')

    def kill(self):
        self.process.kill()
        self.process.wait(timeout=60)
        self.killed.add(self.runs[-1][0])

    @property
    def running(self):
        return self.process is not None and self.process.poll() is None


def coord_command(binary, state, *args, cwd=None):
    return subprocess.run([str(binary), '--state', str(state), *args], capture_output=True, text=True,
                          timeout=120, cwd=cwd)


def ops_request(host, port, method, path, body=None):
    """A plain HTTP request to the ops listener: (status, headers, body bytes)."""
    connection = http.client.HTTPConnection(host, port, timeout=30)
    try:
        connection.request(method, path, body)
        response = connection.getresponse()
        return response.status, response.headers, response.read()
    finally:
        connection.close()


class Clients:
    """Client-side ports of every connection this suite opens to a coordinator, for the log checks."""
    ports = set()


def tls_request(port, key, method, path, body=None):
    """One coordination API request over TLS with key's client certificate: (status, body)."""
    raw = socket.create_connection(('127.0.0.1', port), timeout=30)
    Clients.ports.add(raw.getsockname()[1])
    tls = key.context('http/1.1').wrap_socket(raw)
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
    connection.sock = tls
    try:
        payload = json.dumps(body).encode() if body is not None else None
        connection.request(method, path, payload, {'Content-Type': 'application/json'})
        response = connection.getresponse()
        data = response.read()
        try:
            return response.status, json.loads(data) if data else None
        except json.JSONDecodeError:
            return response.status, data.decode(errors='replace')
    finally:
        connection.close()


def process_sockets(pid):
    """{(proto, local ip hex, port)} of TCP listeners and bound UDP sockets owned by pid."""
    inodes = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[8:-1])
    found = set()
    for proto in ('tcp', 'tcp6', 'udp', 'udp6'):
        try:
            lines = Path(f'/proc/net/{proto}').read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            local, state, inode = fields[1], fields[3], fields[9]
            if inode not in inodes:
                continue
            if proto.startswith('tcp') and state != '0A':
                continue
            ip, port = local.split(':')
            found.add((proto, ip, int(port, 16)))
    return found


# --- metrics ------------------------------------------------------------------------------------------------

LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"\s*,?')
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+\S+)?$')


def unescape(value):
    return value.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')


def parse_labels(text):
    labels, position = {}, 0
    while position < len(text):
        match = LABEL.match(text, position)
        assert match, f'unparseable labels {text!r}'
        labels[match.group(1)] = unescape(match.group(2))
        position = match.end()
    return labels


class Metrics:
    def __init__(self, text):
        self.types, self.samples = {}, []
        for line in text.splitlines():
            if not line.strip():
                continue
            if line.startswith('#'):
                parts = line.split(None, 3)
                if len(parts) >= 4 and parts[1] == 'TYPE':
                    self.types[parts[2]] = parts[3].strip()
                continue
            match = SAMPLE.match(line)
            assert match, f'unparseable metrics line {line!r}'
            self.samples.append((match.group(1), parse_labels(match.group(2) or ''), float(match.group(3))))

    def series(self, name):
        return [(labels, value) for n, labels, value in self.samples if n == name]

    def value(self, name, **labels):
        """The sum of the series of name whose labels include the given ones (0 when absent)."""
        return sum(v for l, v in self.series(name) if all(l.get(k) == w for k, w in labels.items()))


def scrape(coord):
    status, headers, body = ops_request(coord.ops_host, coord.ops_port, 'GET', '/metrics')
    content_type = headers.get('Content-Type') or ''
    need(status == 200, 'GET /metrics returns 200', status)
    need(content_type.startswith('text/plain') and 'version=0.0.4' in content_type,
         'GET /metrics returns the Prometheus text exposition format (text/plain; version=0.0.4)', content_type)
    return Metrics(body.decode())


def check_metric_shapes(metrics, names=METRICS):
    """Every listed name with its type and label names."""
    for name in names:
        kind, labels = METRICS[name]
        need(metrics.types.get(name) == kind, f'{name} is a {kind}', metrics.types.get(name))
        if kind == 'histogram':
            buckets, sums, counts = (metrics.series(name + suffix) for suffix in ('_bucket', '_sum', '_count'))
            need(buckets and sums and counts, f'{name} has _bucket, _sum, and _count samples')
            for l, _ in buckets:
                need(set(l) == labels | {'le'}, f'{name}_bucket labels are {sorted(labels)} and le', l)
            for route in {l['route'] for l, _ in counts}:
                les = {float(l['le']) if l['le'] != '+Inf' else '+Inf' for l, _ in buckets if l['route'] == route}
                want = {float(b) if b != '+Inf' else '+Inf' for b in DEFAULT_BUCKETS}
                need(les == want, f'{name} uses Prometheus\'s default buckets', route, sorted(map(str, les)))
            for l, _ in sums + counts:
                need(set(l) == labels, f'{name} _sum/_count labels are {sorted(labels)}', l)
            for l, count in counts:
                inf = [v for b, v in buckets if b.get('le') == '+Inf' and b.get('route') == l.get('route')]
                need(inf == [count], f'{name} +Inf bucket equals _count', l, inf, count)
        else:
            series = metrics.series(name)
            need(series, f'{name} is exposed', [n for n in metrics.types])
            for l, _ in series:
                need(set(l) == labels, f'{name} labels are exactly {sorted(labels)}', l)


def check_label_values(metrics, forbidden_ids):
    """No label value is a network ID, host ID, person ID, or IP address."""
    for name, labels, _ in metrics.samples:
        for key, value in labels.items():
            need(value not in forbidden_ids, 'no label value is a network, host, or person ID', name, key, value)
            need(not re.match(r'^(net|host|person)_[0-9a-f]{16,}', value),
                 'no label value is a network, host, or person ID', name, key, value)
            need('127.0.0.1' not in value and not IPV4.search(value) and '::1' not in value,
                 'no label value is an IP address', name, key, value)
    for labels, _ in metrics.series('peerspan_coord_limit_refusals_total'):
        need(labels['limit'] in LIMITS, 'limit_refusals_total limit is members, networks_per_ip, or relay_bytes',
             labels)
    for labels, _ in metrics.series('peerspan_coord_requests_total'):
        need(labels['route'] == 'other' or labels['route'].startswith('/coord/'),
             'requests_total routes are coordination API route templates or other', labels)
        need(re.fullmatch(r'\d{3}', labels['code']), 'requests_total code is the HTTP status', labels)
    info = metrics.series('peerspan_coord_info')
    need(len(info) == 1 and info[0][1] == 1 and info[0][0]['version'],
         'peerspan_coord_info is one gauge, always 1, with the version', info)


# --- hosts --------------------------------------------------------------------------------------------------

class OpsHost(DirectoryHost):
    """A daemon reachable only through the relay (peer listener on 0.0.0.0, so no advertised address),
    syncing every second."""

    def __init__(self, binary, state, home):
        super().__init__(binary, binary, state, home)
        self.daemon_args = ('--peer-listen', f'0.0.0.0:{self.port}', '--coordination-interval', str(INTERVAL))

    def start(self, command='run'):
        try:
            return super().start(command)
        except AssertionError:
            # A loaded machine may need more than the shared helper's readiness window; keep waiting on the same
            # process unless it exited.
            if self.process is None or self.process.poll() is not None:
                raise
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and self.process.poll() is None:
            try:
                status, identity = self.call('GET', '/v1/host')
                if status == 200:
                    return identity
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.2)
        raise AssertionError('host did not become ready')


# --- the suite ----------------------------------------------------------------------------------------------

class Suite:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.coord_binary = str(args.coord)
        impl = {'Go': args.go, 'Rust': args.rust}
        self.x = impl[args.creator]
        self.y = impl['Rust' if args.creator == 'Go' else 'Go']
        self.x_name = args.creator
        self.y_name = 'Rust' if args.creator == 'Go' else 'Go'
        self.logs = root / 'logs'
        self.logs.mkdir()
        self.certs = root / 'certs'
        self.certs.mkdir()
        self.keys = root / 'keys'
        self.keys.mkdir()
        self.results = []
        self.coordinators = []
        self.hosts = {}
        self.raws = []
        self.secret_values = {}  # value -> description, never to appear in coordinator stderr
        self.label_ids = set()   # network, host, and person IDs, never label values
        self.grants = {}
        self.agents = {}
        self.ids = {}
        self.scenario = False
        self.backup_file = None
        self.relay_seen = None

    # infrastructure

    def section(self, name, function):
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=6)
            self.results.append((name, False, detail))
            print(f'FAIL [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}', flush=True)
        return True

    def secret(self, value, what):
        if isinstance(value, str) and len(value) >= 8:
            self.secret_values[value] = what

    def coordinator(self, name, state, **kwargs):
        c = OpsCoordinator(self.coord_binary, state, self.logs, name, **kwargs)
        self.coordinators.append(c)
        return c

    def host(self, name, binary):
        h = OpsHost(binary, self.root / name, self.root / f'user-{name}')
        self.hosts[name] = h
        return h

    def start_host(self, name):
        identity = self.hosts[name].start()
        self.ids[name] = identity['id']
        self.label_ids.add(identity['id'])
        self.secret(identity['public_key'], f'{name} host public key')
        return identity

    def members(self, name):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{self.net}/members')
        assert status == 200, (status, body)
        for m in body:
            for candidate in m.get('candidates') or []:
                self.secret(candidate, 'a member candidate')
            if m.get('address'):
                self.secret(m['address'], 'a member address')
            membership = m.get('membership') or {}
            for field in ('host_signature', 'invite_signature', 'invite_public_key'):
                self.secret(membership.get(field), f'membership {field}')
            if m.get('person_id'):
                self.label_ids.add(m['person_id'])
        return {m['host_id']: m for m in body}

    def network(self, name):
        status, body = self.hosts[name].call('GET', '/v1/networks')
        assert status == 200, (status, body)
        return {n['id']: n for n in body}.get(self.net)

    def collect_token(self, token):
        self.secret(token, 'an invite token')
        try:
            _, fields = decode_token(token)
        except Exception:
            return
        for field in ('invite_seed', 'invite_signature', 'invite_public_key', 'root_public_key',
                      'coordinator_public_key', 'person_seed', 'admission_signature'):
            self.secret(fields.get(field), f'invite token {field}')
        for value in fields.values():
            if isinstance(value, str) and len(value) >= 40 and not value.startswith(('net_', 'host_', 'person_')) \
                    and ':' not in value:
                self.secret(value, 'an invite token field')

    def collect_person_key(self, name):
        key = self.hosts[name].config / 'peerspan' / 'person_ed25519'
        if key.exists():
            for line in key.read_text().splitlines():
                if not line.startswith('-----') and len(line) >= 20:
                    self.secret(line, f'{name} person private key material')
        public = key.with_name('person_ed25519.pub')
        if public.exists():
            parts = public.read_text().split()
            if len(parts) >= 2:
                self.secret(parts[1], f'{name} person public key')

    def invite_and_join(self, name, label):
        token = self.hosts['alice'].cli('invite', label, '--network', self.net)['token']
        self.collect_token(token)
        out = self.hosts[name].cli('join', token)
        need(out.get('id') == self.net, f'{name} joins', out)
        person = (out.get('person') or {}).get('person_id')
        if person:
            self.label_ids.add(person)
        self.collect_person_key(name)
        return out

    def all_see(self, names, host_ids, timeout=90):
        eventually(lambda: all(set(host_ids) <= set(self.members(n)) for n in names), timeout,
                   'every running member sees ' + ', '.join(sorted(host_ids)))

    def agent(self, name):
        if name not in self.agents:
            self.agents[name] = self.hosts[name].cli('agent', 'register', '--name', 'ops', '--owner', name)
            self.label_ids.add(self.agents[name]['id'])
        return self.agents[name]

    def grant(self, receiver, sender, connected_only=False):
        key = (receiver, sender, connected_only)
        if key not in self.grants:
            identity = {'id': self.ids[sender]}
            self.grants[key] = self.hosts[receiver].grant(identity, self.agent(receiver), allow=not connected_only)
        return self.grants[key]

    def send(self, sender, receiver, content, connected_only=False, timeout=90):
        """Send one message until accepted (retrying the same request), as relay.py does."""
        self.secret(content, 'message content')
        grant = self.grant(receiver, sender, connected_only)
        rid = request_id()
        s = self.hosts[sender]
        out = s.cli('message', 'send', '--peer', self.ids[receiver], '--grant', grant['id'], '--agent',
                    self.agent(receiver)['id'], '--deadline', timestamp(), '--content', content, '--request', rid)
        deadline = time.monotonic() + timeout
        while out['state'] != 'accepted' and time.monotonic() < deadline:
            time.sleep(1)
            out = s.cli('message', 'retry', '--peer', self.ids[receiver], rid)
        need(out['state'] == 'accepted', f'a relayed message {sender}→{receiver} is accepted', out)
        return out

    def raw(self, seed, alpn):
        r = RawRelay(self.c1, seed, self.certs, alpn)
        Clients.ports.add(r.connection.getsockname()[1])
        self.raws.append(r)
        return r

    # 1. ops listener

    def check_ops_listener(self):
        state = self.root / 'c0'
        c0 = self.coordinator('c0', state, ops=f'127.0.0.1:{available_port()}')
        identity = c0.start()
        self.secret(identity['public_key'], 'coordinator public key')
        try:
            m = scrape(c0)
            check_metric_shapes(m, [n for n in METRICS if n != 'peerspan_coord_request_seconds'
                                    and n != 'peerspan_coord_requests_total'])
            need({l['limit'] for l, _ in m.series('peerspan_coord_limit_refusals_total')} == LIMITS
                 and m.value('peerspan_coord_limit_refusals_total') == 0,
                 'limit_refusals_total is exposed for all three limits from the start, at 0',
                 m.series('peerspan_coord_limit_refusals_total'))
            need({l['alpn'] for l, _ in m.series('peerspan_coord_relay_connections')} == {V1, V2, V3}
                 and m.value('peerspan_coord_relay_connections') == 0,
                 'relay_connections is exposed for every relay ALPN (peerspan-relay/1, /2, and /3) from the start, '
                 'at 0',
                 m.series('peerspan_coord_relay_connections'))
            status, _, body = ops_request(c0.ops_host, c0.ops_port, 'GET', '/healthz')
            need(status == 200, 'GET /healthz returns 200 when a database read completes', status, body)
            health = json.loads(body)
            # Q9 (open): the body is exactly {status, id}.
            need(health == {'status': 'ok', 'id': identity['id']},
                 'GET /healthz returns {"status": "ok", "id": COORDINATOR_ID}', health, identity['id'])
            for path in ('/', '/nope', '/healthz/', '/healthz/x', '/metrics/x', '/coord/v1/networks',
                         '/coord/v1/networks/net_x/sync'):
                status, _, _ = ops_request(c0.ops_host, c0.ops_port, 'GET', path)
                need(status == 404, f'other paths return 404 on the ops listener (GET {path})', status)
            # Other paths return 404 for any method.
            for method, path in (('POST', '/coord/v1/networks'), ('PUT', '/nope'), ('DELETE', '/nope'),
                                 ('HEAD', '/nope'), ('POST', '/coord/v1/networks/net_x/sync')):
                status, _, _ = ops_request(c0.ops_host, c0.ops_port, method, path, b'{}' if method in ('POST', 'PUT')
                                           else None)
                need(status == 404, f'other paths return 404 for any method on the ops listener ({method} {path})',
                     status)
            for method in ('POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'):
                for path in ('/healthz', '/metrics'):
                    status, headers, _ = ops_request(c0.ops_host, c0.ops_port, method, path,
                                                     b'' if method in ('POST', 'PUT', 'PATCH') else None)
                    need(status == 405, f'other methods return 405 ({method} {path})', status)
                    need((headers.get('Allow') or '').replace(' ', '') == 'GET',
                         f'405 carries Allow: GET ({method} {path})', headers.get('Allow'))
            # A TLS client gets nothing from the ops listener: it is plain HTTP.
            key = Key(self.keys)
            try:
                tls_request(c0.ops_port, key, 'POST', '/coord/v1/networks', {})
                need(False, 'the ops listener serves plain HTTP only, never the TLS coordination API')
            except (OSError, http.client.HTTPException):
                pass
            # The coordination port never serves the ops paths.
            for method, path in (('GET', '/healthz'), ('GET', '/metrics'), ('POST', '/healthz')):
                status, body = tls_request(c0.port, key, method, path)
                need(status == 404, f'the coordination port never serves {path} (404)', method, status, body)
            # The ops listener binds only the given loopback address.
            sockets = process_sockets(c0.process.pid)
            ops_sockets = {s for s in sockets if s[2] == c0.ops_port}
            need(ops_sockets and all(s[0] == 'tcp' and s[1] == '0100007F' for s in ops_sockets),
                 'the ops listener listens on its loopback address only', sorted(sockets))
            need(all(s[2] in (c0.port, c0.ops_port) for s in sockets),
                 'nothing listens besides the coordination and ops addresses', sorted(sockets))
        finally:
            c0.stop()

        # Other loopback literals are accepted.
        loopbacks = [f'127.0.0.2:{available_port()}']
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                probe.bind(('::1', 0))
                loopbacks.append(f'[::1]:{probe.getsockname()[1]}')
        except OSError:
            pass
        for index, address in enumerate(loopbacks):
            c = self.coordinator(f'c0-alt{index}', state, ops=address)
            identity = c.start()
            try:
                status, _, body = ops_request(c.ops_host, c.ops_port, 'GET', '/healthz')
                need(status == 200 and json.loads(body)['id'] == identity['id'],
                     f'a loopback --ops-listen {address} serves /healthz', status, body)
            finally:
                c.stop()

        # Non-loopback or non-literal hosts are refused with exit 2 before listening on either address.
        for address in (f'0.0.0.0:{available_port()}', f'[::]:{available_port()}', f'localhost:{available_port()}',
                        f'192.0.2.1:{available_port()}', f'example.com:{available_port()}'):
            port = available_port()
            result = subprocess.run([self.coord_binary, '--state', str(state), 'run', '--listen',
                                     f'127.0.0.1:{port}', '--ops-listen', address],
                                    capture_output=True, text=True, timeout=60)
            need(result.returncode == 2, f'a non-loopback --ops-listen {address} makes run exit 2',
                 result.returncode, result.stderr[-500:])
            need(LOOPBACK_REFUSAL in result.stderr.splitlines(),
                 f'the refusal is the text line "{LOOPBACK_REFUSAL}" on stderr', result.stderr[-500:])
            need('"start"' not in result.stderr, 'the refusal happens before listening (no start line)',
                 result.stderr[-500:])

        # Without the flag nothing extra listens, and start has a null ops_listen.
        c = self.coordinator('c0-plain', state)
        c.start()
        try:
            sockets = process_sockets(c.process.pid)
            need(sockets and all(s[2] == c.port for s in sockets),
                 'without --ops-listen nothing listens besides the coordination address', sorted(sockets), c.port)
        finally:
            c.stop()
        return f'loopbacks accepted: {", ".join(loopbacks)}'

    # 2. the scenario and metrics

    def setup(self):
        self.s1 = self.root / 's1'
        self.c1 = self.coordinator('c1', self.s1, ops=f'127.0.0.1:{available_port()}', flags=('--max-members', '4'))
        self.coord_info = self.c1.start()
        self.secret(self.coord_info['public_key'], 'coordinator public key')
        for name, binary in (('alice', self.x), ('bob', self.y), ('erin', self.x), ('w', self.y), ('dave', self.y)):
            self.host(name, binary)
        for name in ('alice', 'bob', 'erin', 'w'):
            self.start_host(name)
        return f'alice and erin run {self.x_name}; bob, w, and dave run {self.y_name}'

    def check_metrics(self):
        soft = []

        def expect(condition, rule, *detail):
            if not condition:
                soft.append(f'{rule}: ' + ' | '.join(repr(d)[:300] for d in detail))

        def gauge_becomes(name, value, rule, timeout=30, **labels):
            try:
                wait_for(lambda: scrape(self.c1).value(name, **labels) == value, timeout=timeout, message=rule)
            except AssertionError:
                expect(False, rule, scrape(self.c1).value(name, **labels), value)

        m = scrape(self.c1)
        expect(m.value('peerspan_coord_networks') == 0 and m.value('peerspan_coord_member_hosts') == 0,
               'networks and member_hosts are 0 before any registration',
               m.value('peerspan_coord_networks'), m.value('peerspan_coord_member_hosts'))
        expect(m.value('peerspan_coord_limit_refusals_total') == 0 and m.value('peerspan_coord_relay_bytes_total') == 0
               and m.value('peerspan_coord_changes_notified_total') == 0, 'counters start at 0')
        expect({l['limit'] for l, _ in m.series('peerspan_coord_limit_refusals_total')} == LIMITS,
               'limit_refusals_total is exposed for all three limits from the start',
               m.series('peerspan_coord_limit_refusals_total'))
        expect({l['alpn'] for l, _ in m.series('peerspan_coord_relay_connections')} == {V1, V2, V3},
               'relay_connections is exposed for every relay ALPN (peerspan-relay/1, /2, and /3) from the start',
               m.series('peerspan_coord_relay_connections'))
        a, c1 = self.hosts['alice'], self.c1

        # Create.
        created = a.cli('network', 'create', 'team', '--as', 'alice', '--coordinator', c1.address,
                        '--coordinator-key', self.coord_info['public_key'])
        self.net = created['id']
        self.label_ids.add(self.net)
        self.secret(created.get('root_public_key'), 'root public key')
        person = created.get('person') or {}
        if person.get('person_id'):
            self.label_ids.add(person['person_id'])
        self.collect_person_key('alice')
        with sqlite3.connect(f'file:{a.state / "host.db"}?mode=ro', uri=True) as db:
            for (seed,) in db.execute('SELECT root_seed FROM networks WHERE root_seed IS NOT NULL'):
                self.secret(base64.b64encode(bytes(seed)).decode(), 'root seed')
        need(self.network('alice')['last_sync_error'] is None, 'alice registers the network', self.network('alice'))
        created_relay_bytes = scrape(c1).value('peerspan_coord_relay_bytes_total')
        gauge_becomes('peerspan_coord_networks', 1, 'networks is 1 after create')
        gauge_becomes('peerspan_coord_member_hosts', 1, 'member_hosts is 1 after create')

        # Joins.
        for count, (name, label) in enumerate((('bob', 'bob'), ('erin', 'erin'), ('w', 'watcher')), start=2):
            self.invite_and_join(name, label)
            gauge_becomes('peerspan_coord_member_hosts', count, f'member_hosts is {count} after {name} joins')
        self.all_see(['alice', 'bob', 'erin', 'w'], [self.ids[n] for n in ('alice', 'bob', 'erin', 'w')])
        # The watcher's daemon stops; its key stays a member, used below for a raw relay connection.
        self.hosts['w'].stop()
        expect(scrape(c1).value('peerspan_coord_networks') == 1, 'networks stays 1 after joins')

        # A join refused at --max-members 4.
        before = scrape(c1).value('peerspan_coord_limit_refusals_total', limit='members')
        token = a.cli('network', 'invite', '--network', self.net, '--member', 'extra', '--expires-at', timestamp(600),
                      '--host-only')['token']
        self.collect_token(token)
        extra = Key(self.keys)
        self.secret(extra.b64, 'a raw host public key')
        self.label_ids.add(extra.host_id)
        membership = token_membership(token, extra, self.keys)
        self.secret(membership['host_signature'], 'membership host signature')
        status, body = tls_request(c1.port, extra, 'POST', f'/coord/v1/networks/{self.net}/members',
                                   {'membership': membership, 'address': '', 'candidates': []})
        need(status == 429 and isinstance(body, dict) and body.get('limit') == 'members',
             'a join over --max-members returns 429 with limit members (launch contract)', status, body)
        m = scrape(c1)
        expect(m.value('peerspan_coord_limit_refusals_total', limit='members') == before + 1,
               'limit_refusals_total{limit="members"} counts the refused join', before,
               m.series('peerspan_coord_limit_refusals_total'))
        expect(m.value('peerspan_coord_member_hosts') == 4, 'member_hosts is unchanged by a refused join',
               m.value('peerspan_coord_member_hosts'))

        # Relay connections: one version 3 connection per running member host (hosts offer /3 first, and a
        # version 3 coordinator selects it).
        gauge_becomes('peerspan_coord_relay_connections', 3,
                      'relay_connections{alpn="peerspan-relay/3"} counts the three running member hosts',
                      timeout=60, alpn=V3)
        relayed_before = scrape(c1).value('peerspan_coord_relay_bytes_total')
        raw = self.raw(seed_of(self.hosts['w']), (V1,))
        need(raw.selected == V1, 'a version 1 relay connection', raw.selected)
        gauge_becomes('peerspan_coord_relay_connections', 1, 'relay_connections{alpn="peerspan-relay/1"} counts '
                      'an open version 1 connection', alpn=V1)
        # A datagram forwarded to alice is charged; its payload is never logged.
        marker = ('ops-datagram-' + secrets.token_hex(12)).encode()
        datagram = marker + b'.' * (200 - len(marker))
        self.secret(marker.decode(), 'a relayed payload')
        time.sleep(5.5)  # the relay's membership cache refreshes at least every 5 seconds
        raw.connection.sendall(struct.pack('>BH', SEND, 32 + len(datagram)) + bytes.fromhex(self.ids['alice'][5:])
                               + datagram)
        try:
            wait_for(lambda: scrape(c1).value('peerspan_coord_relay_bytes_total') >= relayed_before + len(datagram),
                     timeout=30, message='relay bytes')
        except AssertionError:
            expect(False, 'relay_bytes_total grows by a forwarded datagram\'s length', relayed_before,
                   scrape(c1).value('peerspan_coord_relay_bytes_total'), raw.kinds())
        raw.close()
        self.relay_seen = (self.ids['w'], V1, len(datagram))
        try:
            wait_for(lambda: scrape(c1).value('peerspan_coord_relay_connections', alpn=V1) == 0, timeout=30,
                     message='closed')
        except AssertionError:
            expect(False, 'relay_connections{alpn="peerspan-relay/1"} drops when the connection closes',
                   scrape(c1).series('peerspan_coord_relay_connections'))

        # Relayed messages. Hosts here advertise no address, so every peer connection starts on the relay, but
        # hosts move relayed connections onto a direct path once one is found (coordination contract, Direct
        # paths through NAT), and on one machine one always is. So the increase is measured from creation, across
        # the joins, the directory refreshes they cause, and these messages, not per message.
        self.send('bob', 'alice', 'ops-content-' + secrets.token_hex(8))
        self.send('alice', 'bob', 'ops-content-' + secrets.token_hex(8))
        after = scrape(c1).value('peerspan_coord_relay_bytes_total')
        expect(after - len(datagram) > created_relay_bytes, 'relay_bytes_total increases with relayed messages',
               created_relay_bytes, after)

        # Sync requests.
        before = scrape(c1).value('peerspan_coord_requests_total', route=SYNC_ROUTE, code='200')
        synced = self.hosts['bob'].cli('network', 'sync', self.net)
        need(synced['last_sync_error'] is None, 'bob syncs', synced)
        after = scrape(c1).value('peerspan_coord_requests_total', route=SYNC_ROUTE, code='200')
        expect(after > before, f'requests_total{{route="{SYNC_ROUTE}",code="200"}} counts syncs', before, after)
        expect(scrape(c1).value('peerspan_coord_request_seconds_count', route=SYNC_ROUTE) > 0,
               'request_seconds observes sync durations')

        # An unmatched path.
        status, _ = tls_request(c1.port, extra, 'GET', '/nope/' + secrets.token_hex(4))
        expect(status == 404, 'an unmatched coordination path is 404', status)
        expect(scrape(c1).value('peerspan_coord_requests_total', route='other', code='404') >= 1,
               'unmatched paths use route other', scrape(c1).series('peerspan_coord_requests_total'))
        # A wrong method on a known path also uses route other.
        before = scrape(c1).value('peerspan_coord_requests_total', route='other')
        status, _ = tls_request(c1.port, extra, 'GET', '/coord/v1/networks')
        expect(status in (404, 405), 'GET on the create path is refused', status)
        expect(scrape(c1).value('peerspan_coord_requests_total', route='other') == before + 1
               and scrape(c1).value('peerspan_coord_requests_total', route=CREATE_ROUTE, code=str(status)) == 0,
               'wrong methods use route other', scrape(c1).series('peerspan_coord_requests_total'))
        self.wrong_method_status = status
        # A non-member's relay connection is refused; it is still logged as a relay line.
        stranger = Key(self.keys)
        self.label_ids.add(stranger.host_id)
        self.secret(stranger.b64, 'a raw host public key')
        refused = self.raw(stranger.seed, (V2, V1))
        wait_for(lambda: not refused.open, timeout=15, message='a non-member relay connection closed')
        self.stranger = stranger.host_id
        self.extra = extra.host_id

        # A policy change notifies members.
        def stable():
            first = scrape(c1).value('peerspan_coord_changes_notified_total')
            time.sleep(1.5)
            return first == scrape(c1).value('peerspan_coord_changes_notified_total')
        wait_for(stable, timeout=60, message='changes_notified_total settles')
        before = scrape(c1).value('peerspan_coord_changes_notified_total')
        out = self.hosts['bob'].cli('allow', 'everyone', '--agent', 'ops', '--network', self.net)
        policy = out.get('policy') or {}
        self.secret(policy.get('signature'), 'policy signature')
        self.secret(policy.get('person_public_key'), 'bob person public key')
        if policy:
            self.secret(json.dumps(policy), 'policy JSON')
            self.secret(json.dumps(policy, separators=(',', ':')), 'policy JSON')
        try:
            wait_for(lambda: scrape(c1).value('peerspan_coord_changes_notified_total') > before, timeout=30,
                     message='changed')
        except AssertionError:
            expect(False, 'changes_notified_total increases after a policy change', before,
                   scrape(c1).value('peerspan_coord_changes_notified_total'))

        # A revocation.
        a.cli('network', 'revoke', '--network', self.net, '--host', self.ids['erin'])
        gauge_becomes('peerspan_coord_member_hosts', 3, 'member_hosts excludes a revoked host')
        self.hosts['erin'].stop()
        self.all_see(['alice', 'bob'], [self.ids['alice'], self.ids['bob']])
        eventually(lambda: self.ids['erin'] not in self.members('alice') and self.ids['erin'] not in self.members('bob'),
                   60, 'members drop the revoked host')
        expect(scrape(c1).value('peerspan_coord_networks') == 1, 'networks stays 1 after a revocation')
        self.members('bob')
        self.scenario = True

        m = scrape(c1)
        try:
            check_metric_shapes(m)
            check_label_values(m, self.label_ids)
        except Failure as error:
            soft.append(str(error))
        need(not soft, 'metrics', *soft)
        return (f"relay_bytes_total {m.value('peerspan_coord_relay_bytes_total'):.0f}, changes_notified_total "
                f"{m.value('peerspan_coord_changes_notified_total'):.0f}")

    # 3. backup while serving

    def check_backup_serving(self):
        need(self.scenario, 'needs the metrics scenario')
        backups = self.root / 'backups'
        backups.mkdir()
        stop = threading.Event()
        exchanged = []
        errors = []

        def traffic():
            pairs = [('bob', 'alice'), ('alice', 'bob')]
            i = 0
            while not stop.is_set():
                sender, receiver = pairs[i % 2]
                i += 1
                try:
                    self.send(sender, receiver, 'ops-content-' + secrets.token_hex(8), timeout=30)
                    exchanged.append(time.monotonic())
                except Exception as error:  # noqa: BLE001 - reported below
                    errors.append(repr(error)[:300])
                time.sleep(0.2)
        # Continuous relayed datagrams as well: the watcher's key (its daemon is stopped) sends through the relay to
        # alice, so the relay carries traffic throughout even when the hosts' own connections have gone direct.
        pump = self.raw(seed_of(self.hosts['w']), (V1,))
        marker = ('ops-datagram-' + secrets.token_hex(12)).encode()
        self.secret(marker.decode(), 'a relayed payload')
        datagram = marker + b'.' * (300 - len(marker))
        frame = struct.pack('>BH', SEND, 32 + len(datagram)) + bytes.fromhex(self.ids['alice'][5:]) + datagram
        pumped = []

        def relay_pump():
            while not stop.is_set():
                try:
                    pump.connection.sendall(frame)
                    pumped.append(1)
                except OSError as error:
                    errors.append(f'relay pump: {error!r}')
                    return
                time.sleep(0.05)
        before = scrape(self.c1)
        thread = threading.Thread(target=traffic, daemon=True)
        thread.start()
        pump_thread = threading.Thread(target=relay_pump, daemon=True)
        pump_thread.start()
        outputs = []
        try:
            time.sleep(3)
            for index, relative in enumerate((False, True, False)):
                name = f'coord-{index}.backup'
                target = name if relative else str(backups / name)
                result = coord_command(self.coord_binary, self.s1, 'backup', target, cwd=backups)
                need(result.returncode == 0, 'backup succeeds while the coordinator runs', result.returncode,
                     result.stderr[-500:])
                outputs.append(self.check_backup_file(result, backups / name))
                time.sleep(2)
        finally:
            stop.set()
            thread.join(timeout=90)
            pump_thread.join(timeout=10)
            pump.close()
        after = scrape(self.c1)
        need(len(exchanged) >= 3, 'relayed messages flowed during the backups', len(exchanged), errors[:3])
        need(after.value('peerspan_coord_relay_bytes_total') >= before.value('peerspan_coord_relay_bytes_total')
             + len(datagram) * len(pumped) // 2, 'the coordinator relayed continuously during the backups',
             before.value('peerspan_coord_relay_bytes_total'), after.value('peerspan_coord_relay_bytes_total'),
             len(pumped))
        need(after.value('peerspan_coord_requests_total', route=SYNC_ROUTE)
             > before.value('peerspan_coord_requests_total', route=SYNC_ROUTE) + 4, 'hosts synced during the backups')
        leftovers = sorted(p.name for p in backups.iterdir())
        need(leftovers == sorted(f'coord-{i}.backup' for i in range(3)),
             'backup writes through a temporary file renamed into place, leaving nothing else', leftovers)
        self.backup_file = backups / 'coord-2.backup'
        self.user_version = outputs[-1]['user_version']
        return (f'{len(exchanged)} messages and {len(pumped)} relayed datagrams during 3 backups ({len(errors)} send '
                f'errors); user_version {self.user_version}')

    def check_backup_file(self, result, path):
        out = json.loads(result.stdout)
        need(set(out) == {'file', 'bytes', 'id', 'user_version'},
             'backup prints {"file", "bytes", "id", "user_version"}', out)
        need(os.path.isabs(out['file']) and os.path.realpath(out['file']) == os.path.realpath(path),
             'backup prints FILE as an absolute path', out['file'], str(path))
        need(path.exists() and out['bytes'] == path.stat().st_size, 'bytes is the file size', out,
             path.stat().st_size if path.exists() else None)
        need(out['id'] == self.coord_info['id'], 'backup prints the coordinator id', out['id'])
        need(mode(path) == 0o600, 'the backup has mode 0600', oct(mode(path)))
        need(isinstance(out['user_version'], int) and out['user_version'] > 0, 'user_version is the schema version',
             out)
        connection = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        try:
            check = connection.execute('PRAGMA integrity_check').fetchall()
            version = connection.execute('PRAGMA user_version').fetchone()[0]
        finally:
            connection.close()
        need(check == [('ok',)], 'the backup opens as an intact SQLite database', check)
        need(version == out['user_version'], 'the printed user_version is the copy\'s', version, out)
        return out

    # 4. backup refusals

    def check_backup_refusals(self):
        need(self.scenario, 'needs the metrics scenario')
        directory = self.root / 'backup-refusals'
        directory.mkdir()
        existing = directory / 'existing.backup'
        existing.write_bytes(b'keep me')
        result = coord_command(self.coord_binary, self.s1, 'backup', str(existing))
        need(result.returncode == 1, 'backup to an existing FILE exits 1', result.returncode, result.stderr[-300:])
        need(existing.read_bytes() == b'keep me', 'an existing FILE is unchanged')
        need(sorted(p.name for p in directory.iterdir()) == ['existing.backup'],
             'a refused backup leaves no temporary file', sorted(p.name for p in directory.iterdir()))
        empty = self.root / 'empty-state'
        empty.mkdir(mode=0o700)
        target = directory / 'none.backup'
        result = coord_command(self.coord_binary, empty, 'backup', str(target))
        need(result.returncode == 1, 'backup without a database in the state directory exits 1', result.returncode)
        need(not target.exists(), 'a refused backup writes no FILE')
        need(not (empty / 'coord.db').exists(), 'backup does not create a database')

    # 5. restore refused while running

    def check_restore_running(self):
        need(self.backup_file is not None, 'needs a backup')
        before = sorted(p.name for p in self.s1.iterdir())
        file = str(self.backup_file)
        for args in (('--replace', file), (file, '--replace'), (file,)):
            result = coord_command(self.coord_binary, self.s1, 'restore', *args)
            need(result.returncode == 1, 'restore while the coordinator runs exits 1', args, result.returncode,
                 result.stderr[-300:])
            # The lock is the first check, so the reason is the same with or without --replace.
            need('coordinator is running' in result.stderr, 'restore says "coordinator is running"', args,
                 result.stderr[-300:])
        need(not [p for p in self.s1.iterdir() if p.name.startswith('coord.db.replaced-')],
             'a refused restore keeps no replaced database', sorted(p.name for p in self.s1.iterdir()))
        status, _, body = ops_request(self.c1.ops_host, self.c1.ops_port, 'GET', '/healthz')
        need(status == 200 and json.loads(body)['id'] == self.coord_info['id'],
             'the running coordinator keeps serving after a refused restore', status, body)
        return f'state files {before}'

    # 6. restore refusals

    def check_restore_refusals(self):
        need(self.backup_file is not None, 'needs a backup')
        self.c1.stop()
        # A backup of a stopped coordinator.
        stopped = self.root / 'backups' / 'stopped.backup'
        result = coord_command(self.coord_binary, self.s1, 'backup', str(stopped))
        need(result.returncode == 0, 'backup works while no coordinator runs', result.returncode, result.stderr[-300:])
        self.check_backup_file(result, stopped)

        database = self.s1 / 'coord.db'
        original = sha256(database)

        def state_files():
            # A state lock file is the lock's own business (restore takes the lock), not a change to the state.
            return sorted(p.name for p in self.s1.iterdir() if 'lock' not in p.name)
        listing = state_files()

        def unchanged(what):
            need(sha256(database) == original, f'{what} leaves coord.db unchanged')
            need(state_files() == listing, f'{what} leaves the state directory unchanged', state_files(), listing)

        result = coord_command(self.coord_binary, self.s1, 'restore', str(self.backup_file))
        need(result.returncode == 1, 'restore over an existing database without --replace exits 1', result.returncode,
             result.stderr[-300:])
        unchanged('a restore without --replace')
        corrupt = self.root / 'corrupt-no-replace.db'
        corrupt.write_bytes(secrets.token_bytes(8192))
        result = coord_command(self.coord_binary, self.s1, 'restore', str(corrupt))
        need(result.returncode == 1, 'restore of a corrupt FILE over an existing database without --replace exits 1',
             result.returncode, result.stderr[-300:])
        unchanged('a corrupt restore without --replace')

        bad = self.root / 'bad'
        bad.mkdir()
        files = {}
        files['random bytes'] = bad / 'random.db'
        files['random bytes'].write_bytes(secrets.token_bytes(65536))
        files['an empty file'] = bad / 'empty.db'
        files['an empty file'].write_bytes(b'')
        data = self.backup_file.read_bytes()
        files['a truncated backup'] = bad / 'truncated.db'
        files['a truncated backup'].write_bytes(data[:len(data) // 2])
        files['a host database'] = bad / 'host.db'
        source = sqlite3.connect(f'file:{self.hosts["alice"].state / "host.db"}?mode=ro', uri=True)
        target = sqlite3.connect(files['a host database'])
        source.backup(target)
        source.close()
        target.close()
        files['a SQLite file without the identity row'] = bad / 'noidentity.db'
        connection = sqlite3.connect(files['a SQLite file without the identity row'])
        connection.execute('CREATE TABLE unrelated (x INTEGER)')
        connection.execute(f'PRAGMA user_version = {int(self.user_version)}')
        connection.commit()
        connection.close()
        files['an unsupported user_version'] = bad / 'future.db'
        files['an unsupported user_version'].write_bytes(data)
        connection = sqlite3.connect(files['an unsupported user_version'])
        connection.execute('PRAGMA user_version = 9999')
        connection.commit()
        connection.close()
        files['a missing file'] = bad / 'missing.db'
        for index, (what, path) in enumerate(files.items()):
            # restore [--replace] FILE; the flag after FILE is exercised too.
            args = ('--replace', str(path)) if index % 2 == 0 else (str(path), '--replace')
            result = coord_command(self.coord_binary, self.s1, 'restore', *args)
            need(result.returncode == 1, f'restore of {what} exits 1, even with --replace', args, result.returncode,
                 result.stderr[-300:])
            unchanged(f'a refused restore of {what}')
        return f'{len(files)} bad files refused'

    # 7. restore and keep working

    def check_restore_works(self):
        need(self.backup_file is not None and not self.c1.running, 'needs a backup and a stopped coordinator')
        # Into a new state directory.
        fresh = self.root / 'fresh' / 'state'
        fresh.parent.mkdir()
        result = coord_command(self.coord_binary, fresh, 'restore', str(self.backup_file))
        need(result.returncode == 0, 'restore into a new state directory succeeds', result.returncode,
             result.stderr[-500:])
        out = json.loads(result.stdout)
        need(set(out) == {'id', 'user_version', 'replaced'}, 'restore prints {"id", "user_version", "replaced"}', out)
        need(out['id'] == self.coord_info['id'] and out['replaced'] is None and out['user_version'] == self.user_version,
             'a restore without a previous database has the backup\'s id and user_version, and replaced null', out)
        need(mode(fresh) == 0o700, 'restore creates the state directory with mode 0700', oct(mode(fresh)))
        need(mode(fresh / 'coord.db') == 0o600, 'coord.db has mode 0600', oct(mode(fresh / 'coord.db')))
        info = coord_command(self.coord_binary, fresh, 'info')
        need(info.returncode == 0 and json.loads(info.stdout) == self.coord_info,
             'the restored state has the backup\'s identity', info.stdout, info.stderr[-300:])
        # restore FILE --replace (the flag after the positional) over that state.
        before = sha256(fresh / 'coord.db')
        result = coord_command(self.coord_binary, fresh, 'restore', str(self.backup_file), '--replace')
        need(result.returncode == 0, 'restore FILE --replace succeeds', result.returncode, result.stderr[-500:])
        out = json.loads(result.stdout)
        kept = Path(out.get('replaced') or '')
        kept = kept if kept.is_absolute() else fresh / kept
        need(REPLACED.match(kept.name) and kept.exists() and sha256(kept) == before,
             'restore FILE --replace keeps the previous database byte for byte', out)

        # Over the old state, with --replace.
        database = self.s1 / 'coord.db'
        previous = sha256(database)
        wal = self.s1 / 'coord.db-wal'
        previous_wal = wal.read_bytes() if wal.exists() else None
        shm = self.s1 / 'coord.db-shm'
        if not shm.exists():
            shm.write_bytes(b'stale shm')
        started = utcnow()
        result = coord_command(self.coord_binary, self.s1, 'restore', '--replace', str(self.backup_file))
        need(result.returncode == 0, 'restore --replace succeeds', result.returncode, result.stderr[-500:])
        out = json.loads(result.stdout)
        need(set(out) == {'id', 'user_version', 'replaced'}, 'restore prints {"id", "user_version", "replaced"}', out)
        need(out['id'] == self.coord_info['id'] and out['user_version'] == self.user_version,
             'restore prints the backup\'s id and user_version', out)
        replaced = Path(out['replaced'] or '')
        if not replaced.is_absolute():
            replaced = self.s1 / replaced
        match = REPLACED.match(replaced.name)
        need(match and replaced.parent.resolve() == self.s1.resolve(),
             'the previous database is kept as coord.db.replaced-YYYYMMDDTHHMMSSZ in the state directory', out)
        moment = datetime.strptime(match.group(1), '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
        need(started - timedelta(seconds=5) <= moment <= utcnow() + timedelta(seconds=5),
             'the replaced timestamp is the UTC time of the restore', match.group(1), started)
        need(replaced.exists() and sha256(replaced) == previous, 'the previous database is kept byte for byte')
        kept_wal = replaced.with_name(replaced.name + '-wal')
        if previous_wal is None:
            need(not kept_wal.exists(), 'no replaced -wal without a previous -wal')
        else:
            need(kept_wal.exists() and kept_wal.read_bytes() == previous_wal,
                 'the previous database\'s -wal is kept as coord.db.replaced-TIMESTAMP-wal')
        need(mode(database) == 0o600, 'coord.db has mode 0600', oct(mode(database)))
        for suffix in ('-wal', '-shm'):
            need(not (self.s1 / f'coord.db{suffix}').exists(), f'restore removes a stale coord.db{suffix}',
                 sorted(p.name for p in self.s1.iterdir()))
        need(mode(self.s1) == 0o700, 'the state directory stays 0700', oct(mode(self.s1)))

        # A coordinator on the restored state at the same address; hosts keep working.
        last = {n: parse_time(self.network(n)['last_sync_at']) for n in ('alice', 'bob')}
        c2 = self.coordinator('c2', self.s1, port=self.c1.port, ops=f'127.0.0.1:{available_port()}',
                              flags=('--max-members', '4'))
        self.c2 = c2
        restarted = utcnow()
        need(c2.start() == self.coord_info, 'the restored coordinator has the backup\'s identity')
        m = scrape(c2)
        need(m.value('peerspan_coord_limit_refusals_total') == 0, 'counters start at 0 when the process starts',
             m.series('peerspan_coord_limit_refusals_total'))
        status, _, body = ops_request(c2.ops_host, c2.ops_port, 'GET', '/healthz')
        need(status == 200 and json.loads(body) == {'status': 'ok', 'id': self.coord_info['id']},
             '/healthz on the restored coordinator', status, body)

        def synced(name):
            n = self.network(name)
            return (n and n['last_sync_error'] is None and n['last_sync_at']
                    and parse_time(n['last_sync_at']) > max(restarted, last[name]))
        for name in ('alice', 'bob'):
            eventually(lambda name=name: synced(name), 90,
                       f'{name} ({self.hosts[name].binary}) syncs with the restored coordinator without host action',
                       lambda name=name: self.network(name))
        self.start_host('dave')
        self.invite_and_join('dave', 'dave')
        self.all_see(['alice', 'bob', 'dave'], [self.ids[n] for n in ('alice', 'bob', 'dave')])
        need(scrape(c2).value('peerspan_coord_member_hosts') == 4, 'member_hosts on the restored coordinator',
             scrape(c2).value('peerspan_coord_member_hosts'))
        # Connected-only grants: each receiver must have synced recently with the restored coordinator.
        for sender, receiver in (('bob', 'alice'), ('alice', 'bob'), ('dave', 'alice'), ('alice', 'dave'),
                                 ('bob', 'dave'), ('dave', 'bob')):
            self.send(sender, receiver, 'ops-content-' + secrets.token_hex(8), connected_only=True, timeout=120)
        self.members('alice')
        m = scrape(c2)
        check_label_values(m, self.label_ids)
        return (f"relay_bytes_total {m.value('peerspan_coord_relay_bytes_total'):.0f} after restore; "
                f"{self.x_name} and {self.y_name} hosts synced, dave joined")

    # 7b. a leftover -wal from a killed coordinator

    def check_restore_wal(self):
        need(self.backup_file is not None, 'needs a backup')
        state = self.root / 's3'
        c3 = self.coordinator('c3', state)
        c3.start()
        # Writes the coordinator has not checkpointed: registrations, joins, and syncs by raw clients.
        for index in range(3):
            founder = Key(self.keys)
            self.secret(founder.b64, 'a raw host public key')
            network = RawNetwork(self.keys, f'wal{index}')
            self.secret(network.root.b64, 'a raw root public key')
            status, body = network.register(c3, founder)
            need(status == 201, 'a raw registration', status, body)
            for member in range(2):
                joiner = Key(self.keys)
                self.secret(joiner.b64, 'a raw host public key')
                status, body = network.join(c3, joiner)
                need(status == 201, 'a raw join', status, body)
        c3.kill()
        database, wal, shm = state / 'coord.db', state / 'coord.db-wal', state / 'coord.db-shm'
        if not (wal.exists() and wal.stat().st_size > 0):
            return 'SKIPPED: SIGKILL after writes left no non-empty coord.db-wal, so the kept -wal case did not run'
        previous, previous_wal = sha256(database), wal.read_bytes()
        # A replaced name already taken is a refusal: occupy every name the next seconds could produce.
        now = utcnow()
        taken = [state / f"coord.db.replaced-{(now + timedelta(seconds=d)).strftime('%Y%m%dT%H%M%SZ')}"
                 for d in range(-2, 30)]
        for path in taken:
            path.write_bytes(b'taken')
        result = coord_command(self.coord_binary, state, 'restore', '--replace', str(self.backup_file))
        need(result.returncode == 1, 'restore --replace onto a replaced name already taken exits 1',
             result.returncode, result.stdout[-300:], result.stderr[-300:])
        need(sha256(database) == previous and wal.read_bytes() == previous_wal
             and all(p.read_bytes() == b'taken' for p in taken), 'a refused restore changes nothing')
        for path in taken:
            path.unlink()
        result = coord_command(self.coord_binary, state, 'restore', '--replace', str(self.backup_file))
        need(result.returncode == 0, 'restore --replace over a killed coordinator\'s state', result.returncode,
             result.stderr[-500:])
        out = json.loads(result.stdout)
        replaced = Path(out['replaced'])
        replaced = replaced if replaced.is_absolute() else state / replaced
        need(REPLACED.match(replaced.name) and sha256(replaced) == previous,
             'the previous database is kept byte for byte', out)
        kept = replaced.with_name(replaced.name + '-wal')
        need(kept.exists() and kept.read_bytes() == previous_wal,
             'the previous database\'s -wal is kept as coord.db.replaced-TIMESTAMP-wal',
             sorted(p.name for p in state.iterdir()))
        need(not wal.exists() and not shm.exists(), 'other -wal and -shm files are removed',
             sorted(p.name for p in state.iterdir()))
        # The kept pair opens as the previous database, with the killed coordinator's writes.
        copy = self.root / 'kept-pair'
        copy.mkdir()
        shutil.copy2(replaced, copy / 'coord.db')
        shutil.copy2(kept, copy / 'coord.db-wal')
        connection = sqlite3.connect(copy / 'coord.db')
        try:
            check = connection.execute('PRAGMA integrity_check').fetchall()
        finally:
            connection.close()
        need(check == [('ok',)], 'the kept database and -wal open together', check)
        info = coord_command(self.coord_binary, state, 'info')
        need(info.returncode == 0 and json.loads(info.stdout) == self.coord_info, 'the restored state has the '
             'backup\'s identity', info.stdout, info.stderr[-300:])
        return f'kept a {len(previous_wal)}-byte -wal'

    # 8. logs

    def check_logs(self):
        for c in self.coordinators:
            c.stop()
        need(self.coordinators, 'no coordinator ran')
        notes = []
        clients = {f'127.0.0.1:{p}' for p in Clients.ports}
        for c in self.coordinators:
            for err, address, ops, coordinator_id in c.runs:
                text = err.read_text(errors='replace')
                lines = [line for line in text.splitlines() if line.strip()]
                need(lines, f'{err.name}: run writes log lines to stderr')
                entries = []
                for line in lines:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        need(False, f'{err.name}: every stderr line is a JSON object', line[:300])
                    need(isinstance(entry, dict), f'{err.name}: every stderr line is a JSON object', line[:300])
                    need(isinstance(entry.get('time'), str) and TIME.match(entry['time']),
                         'time is RFC 3339 with fractional seconds, UTC', entry.get('time'))
                    need(entry.get('level') in ('info', 'error'), 'level is info or error', entry)
                    need(isinstance(entry.get('msg'), str), 'every line has msg', entry)
                    entries.append(entry)
                starts = [e for e in entries if e['msg'] == 'start']
                need(len(starts) == 1, f'{err.name}: one start line', starts)
                start = starts[0]
                need(start.get('id') == coordinator_id and start.get('listen') == address
                     and 'ops_listen' in start and start['ops_listen'] == ops,
                     'start has id, listen, and ops_listen (null without the flag)', start, address, ops)
                if err not in c.killed:
                    need(entries[-1]['msg'] == 'stop', f'{err.name}: stop is logged on shutdown, last', entries[-1])
                    need(sum(e['msg'] == 'stop' for e in entries) == 1, f'{err.name}: one stop line')
                for e in entries:
                    if e['msg'] == 'request':
                        need(isinstance(e.get('method'), str) and isinstance(e.get('route'), str)
                             and isinstance(e.get('status'), int) and isinstance(e.get('duration_ms'), (int, float)),
                             'request has method, route, status, and duration_ms', e)
                        need(e['route'] == 'other' or (e['route'].startswith('/coord/') and 'net_' not in e['route']
                                                       and 'host_' not in e['route']),
                             'request route is the template, or other', e)
                        need(isinstance(e.get('host'), str) and e['host'].startswith('host_'),
                             'request has host (the client certificate\'s host ID)', e)
                        if '{network}' in e['route']:
                            need(isinstance(e.get('network'), str) and e['network'],
                                 'request has network for a route with a network ID', e)
                    elif e['msg'] == 'relay':
                        need(isinstance(e.get('host'), str) and e['host'].startswith('host_')
                             and e.get('alpn') in (V1, V2, V3) and isinstance(e.get('bytes_in'), int)
                             and isinstance(e.get('bytes_out'), int)
                             and isinstance(e.get('duration_ms'), (int, float)),
                             'relay has host, alpn, bytes_in, bytes_out, and duration_ms', e)
                    elif e['msg'] == 'error' or e['level'] == 'error':
                        need(isinstance(e.get('error'), str) and e['error'], 'error lines have error', e)
                # Secrets.
                for value, what in self.secret_values.items():
                    need(value not in text, f'{err.name}: logs never contain {what}', value[:60])
                for entry in entries:
                    scrubbed = dict(entry)
                    if entry['msg'] == 'start':
                        scrubbed.pop('listen', None)
                        scrubbed.pop('ops_listen', None)
                    flat = json.dumps(scrubbed)
                    need('127.0.0.1' not in flat and '::1' not in flat,
                         'logs never contain client addresses (127.0.0.1 outside start)', flat[:300])
                    for client in clients:
                        need(client not in flat, 'logs never contain client addresses and ports', client)
                if c is getattr(self, 'c1', None) and self.scenario:
                    notes.append(self.check_c1_lines(entries))
                if c is getattr(self, 'c2', None) and 'dave' in self.ids:
                    self.find(entries, 'join on the restored coordinator', msg='request', method='POST',
                              route=JOIN_ROUTE, status=201, network=self.net, host=self.ids['dave'])
                    self.find(entries, 'sync on the restored coordinator', msg='request', route=SYNC_ROUTE,
                              status=200, network=self.net)
        return '; '.join(n for n in notes if n)

    def find(self, entries, what, **fields):
        found = [e for e in entries if all(e.get(k) == v for k, v in fields.items())]
        need(found, f'a {what} line', fields)
        return found

    def check_c1_lines(self, entries):
        self.find(entries, 'request for create', msg='request', method='POST', route=CREATE_ROUTE, status=201,
                  host=self.ids['alice'])
        for name in ('bob', 'erin', 'w'):
            self.find(entries, f'request for {name}\'s join', msg='request', method='POST', route=JOIN_ROUTE,
                      status=201, network=self.net, host=self.ids[name])
        self.find(entries, 'request for sync', msg='request', method='POST', route=SYNC_ROUTE, status=200,
                  network=self.net, host=self.ids['bob'])
        self.find(entries, 'request for the refused join', msg='request', route=JOIN_ROUTE, status=429,
                  network=self.net)
        self.find(entries, 'request for an unmatched path', msg='request', route='other', status=404)
        host, alpn, size = self.relay_seen
        relays = self.find(entries, 'relay line for the closed version 1 connection', msg='relay', host=host, alpn=alpn)
        self.find(entries, 'relay line for a refused (non-member) relay connection', msg='relay', host=self.stranger)
        self.find(entries, 'request line for a wrong method (route other)', msg='request', route='other',
                  method='GET', status=self.wrong_method_status, host=self.extra)
        errors = [e for e in entries if e['msg'] == 'error' or e['level'] == 'error']
        need(not [e for e in errors if e.get('host') == self.extra or (isinstance(e.get('status'), int)
                                                                       and 400 <= e['status'] < 500)],
             '4xx answers appear only as request lines, not errors', errors[:5])
        # bytes_in counts relay frame bytes, headers included, so at least the datagram sent.
        need(any(r['bytes_in'] >= size for r in relays), 'relay bytes_in counts the forwarded datagram', relays, size)
        hosts = {e['host'] for e in entries if e['msg'] == 'relay'}
        need(self.ids['alice'] in hosts or self.ids['bob'] in hosts,
             'relay lines for hosts\' connections closed at shutdown', sorted(hosts))
        return f"c1: {sum(e['msg'] == 'request' for e in entries)} request and {sum(e['msg'] == 'relay' for e in entries)} relay lines"

    # 9. deployment files

    def check_deploy(self):
        names = ['peerspan-coord.service', 'peerspan-coord.env.example', 'litestream.yml', 'litestream.service',
                 'README.md']
        missing = [n for n in names if not (DEPLOY / n).is_file()]
        need(not missing, 'deploy/coordinator/ holds the five files', missing)
        unit = parse_unit((DEPLOY / 'peerspan-coord.service').read_text())
        service = unit.get('Service', {})
        exec_start = ' '.join(service.get('ExecStart', []))
        normalized = re.sub(r'\s+', ' ', exec_start)
        for part in ('peerspan-coord', '--state /var/lib/peerspan-coord', ' run ', '--listen ${PEERSPAN_COORD_LISTEN}',
                     '--ops-listen 127.0.0.1:9464'):
            need(part in normalized, f'ExecStart runs peerspan-coord with {part.strip()}', normalized)
        need(normalized.index('--state') < normalized.index(' run '), 'ExecStart puts --state before run', normalized)
        need(service.get('EnvironmentFile'), 'the unit reads an EnvironmentFile', service)
        env_text = (DEPLOY / 'peerspan-coord.env.example').read_text()
        defined = {m.group(1): m.group(2) for m in re.finditer(r'^\s*#?\s*([A-Z][A-Z0-9_]*)=(.*)$', env_text, re.M)}
        need(any(line.strip().startswith('#') for line in env_text.splitlines()), 'the environment example has comments')
        referenced = set(re.findall(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', exec_start)) | \
            set(re.findall(r'\$([A-Za-z_][A-Za-z0-9_]*)', exec_start))
        need('PEERSPAN_COORD_LISTEN' in defined, 'the environment example sets PEERSPAN_COORD_LISTEN', sorted(defined))
        undefined = sorted(referenced - set(defined))
        need(not undefined, 'every variable ExecStart uses is in the environment example', undefined)
        # Q7: each limit flag reaches ExecStart, literally or through a variable from the environment file.
        expanded = normalized + ' ' + ' '.join(defined.get(v, '') for v in referenced)
        for flag in ('--max-members', '--max-networks-per-ip', '--relay-bytes-per-month'):
            need(flag in expanded or any(flag[2:].replace('-', '_').upper() in v for v in referenced),
                 f'the limit flag {flag} comes from the environment file', normalized, sorted(referenced))
        user = (service.get('User') or [''])[-1]
        dynamic = (service.get('DynamicUser') or ['no'])[-1].lower() in ('yes', 'true', '1', 'on')
        need(user and user not in ('root', '0') and not dynamic,
             'the unit runs as a dedicated static user (User=, not DynamicUser=)', user, dynamic)
        need((service.get('StateDirectory') or [''])[-1] == 'peerspan-coord', 'StateDirectory=peerspan-coord',
             service.get('StateDirectory'))
        need((service.get('StateDirectoryMode') or [''])[-1] in ('0700', '700'), 'StateDirectoryMode 0700',
             service.get('StateDirectoryMode'))
        need((service.get('Restart') or [''])[-1] == 'on-failure', 'Restart=on-failure', service.get('Restart'))
        truthy = ('yes', 'true', '1', 'on')
        need((service.get('NoNewPrivileges') or [''])[-1].lower() in truthy, 'NoNewPrivileges', service)
        need((service.get('ProtectSystem') or [''])[-1] == 'strict', 'ProtectSystem=strict', service)
        need((service.get('ProtectHome') or [''])[-1].lower() in truthy + ('read-only', 'tmpfs'), 'ProtectHome',
             service)
        need((service.get('PrivateTmp') or [''])[-1].lower() in truthy, 'PrivateTmp', service)
        listen = defined.get('PEERSPAN_COORD_LISTEN', '').strip().strip('"\'')
        port = int(listen.rsplit(':', 1)[1]) if re.search(r':\d+$', listen) else None
        if port is None or port >= 1024:
            added = [v for v in service.get('AmbientCapabilities', []) if v.strip()]
            need(not added, 'no added capabilities for a port of 1024 or above', added, listen)
        # Litestream.
        try:
            import yaml
        except ImportError:
            need(False, 'PyYAML is needed to parse litestream.yml')
        config = yaml.safe_load((DEPLOY / 'litestream.yml').read_text())
        need(isinstance(config, dict) and isinstance(config.get('dbs'), list), 'litestream.yml has dbs', config)
        entries = [d for d in config['dbs'] if isinstance(d, dict) and d.get('path') == '/var/lib/peerspan-coord/coord.db']
        need(entries, 'litestream.yml replicates /var/lib/peerspan-coord/coord.db', config['dbs'])
        replicas = []
        for entry in entries:
            replicas += entry.get('replicas') or []
            if isinstance(entry.get('replica'), dict):
                replicas.append(entry['replica'])
        s3 = [r for r in replicas if isinstance(r, dict)
              and (r.get('type') == 's3' or str(r.get('url', '')).startswith('s3://') or r.get('bucket'))]
        need(s3, 'litestream.yml has an S3-compatible replica', replicas)

        def sse_c(replica):
            # S3 server-side encryption with a customer-provided key: a non-empty SSE-C key setting.
            return any(re.search(r'sse[-_]?c\b|sse[-_]?customer', str(k), re.I) and v for k, v in replica.items())
        need(all(sse_c(r) for r in s3), 'replicas use S3 SSE-C (a customer-provided key)', s3)
        for r in s3:
            for k in ('access-key-id', 'secret-access-key'):
                if r.get(k):
                    need(str(r[k]).startswith('$'), f'litestream credentials come from the environment ({k})', r[k])
        litestream = parse_unit((DEPLOY / 'litestream.service').read_text()).get('Service', {})
        need('litestream' in ' '.join(litestream.get('ExecStart', [])) and
             'replicate' in ' '.join(litestream.get('ExecStart', [])), 'litestream.service runs litestream replicate',
             litestream.get('ExecStart'))
        need(litestream.get('EnvironmentFile'), 'litestream.service takes credentials from an environment file',
             litestream)
        need((litestream.get('User') or [''])[-1] == user, 'Litestream runs as the same user as peerspan-coord',
             litestream.get('User'), user)
        readme = (DEPLOY / 'README.md').read_text()
        for phrase in ('peerspan-coord info', 'PEERSPAN_COORDINATOR_KEY', '/healthz', 'restore', 'backup'):
            need(phrase in readme, f'the runbook covers {phrase}')
        need(re.search(r'\bUDP\b', readme), 'the runbook covers opening TCP and UDP on the coordination port')
        notes = self.verify_units()
        return notes

    def verify_units(self):
        analyze = shutil.which('systemd-analyze')
        system_units = Path('/usr/lib/systemd/system')
        if not analyze or not system_units.is_dir():
            return 'systemd-analyze unavailable: verify skipped'
        root = self.root / 'unit-root'
        shutil.copytree(system_units, root / 'usr/lib/systemd/system', symlinks=True)
        units = root / 'etc/systemd/system'
        units.mkdir(parents=True)
        for name in ('peerspan-coord.service', 'litestream.service'):
            text = (DEPLOY / name).read_text()
            (units / name).write_text(text)
            for line in parse_unit(text).get('Service', {}).get('ExecStart', []):
                executable = line.strip().split()[0].lstrip('-@+!:')
                if executable.startswith('/'):
                    stub = root / executable.lstrip('/')
                    stub.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2('/bin/true', stub)
        for name in ('peerspan-coord.service', 'litestream.service'):
            result = subprocess.run([analyze, 'verify', '--man=no', f'--root={root}', name], capture_output=True,
                                    text=True, timeout=120)
            own = [line for line in (result.stdout + result.stderr).splitlines()
                   if name in line and 'symlink' not in line]
            need(result.returncode == 0 and not own, f'systemd-analyze verify {name}', result.returncode, own)
        return 'systemd-analyze verify passed for both units'

    # running

    def run(self):
        self.section('ops listener', self.check_ops_listener)
        if self.section('setup', self.setup):
            self.section('metrics', self.check_metrics)
            self.section('backup while serving', self.check_backup_serving)
            self.section('backup refusals', self.check_backup_refusals)
            self.section('restore refused while running', self.check_restore_running)
            self.section('restore refusals', self.check_restore_refusals)
            self.section('restore and keep working', self.check_restore_works)
            self.section('restore keeps a leftover -wal', self.check_restore_wal)
        self.section('logs', self.check_logs)
        self.section('deployment files', self.check_deploy)

    def close(self):
        for raw in self.raws:
            raw.close()
        try:
            stop_all(tuple(self.hosts.values()))
        finally:
            for c in self.coordinators:
                try:
                    c.stop()
                except Exception:
                    if c.process is not None:
                        c.process.kill()

    def save_logs(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        for path in self.logs.iterdir():
            shutil.copy2(path, directory / path.name)
        for name, h in self.hosts.items():
            try:
                h.logs.seek(0)
                (directory / f'{name}.log').write_bytes(h.logs.read())
            except (OSError, ValueError):
                pass


def parse_unit(text):
    """{section: {key: [values]}} from a systemd unit, joining continuation lines."""
    sections, current = {}, None
    joined = re.sub(r'\\\n', ' ', text)
    for line in joined.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            current = sections.setdefault(line[1:-1], {})
            continue
        if '=' in line and current is not None:
            key, value = line.split('=', 1)
            current.setdefault(key.strip(), []).append(value.strip())
    return sections


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--coord', type=Path, required=True, help='peerspan-coord')
    parser.add_argument('--go', type=Path, required=True, help='Go peerspan-host')
    parser.add_argument('--rust', type=Path, required=True, help='Rust peerspan-host')
    parser.add_argument('--probe', type=Path, help='peerspan-peer-probe (optional; set for shared helpers)')
    parser.add_argument('--creator', choices=('Go', 'Rust'), default='Go',
                        help='implementation of the network creator and the revoked host; the others run the other')
    parser.add_argument('--logs', type=Path, help='save coordinator and host logs here when a section fails')
    args = parser.parse_args()
    args.coord, args.go, args.rust = (p.resolve(strict=True) for p in (args.coord, args.go, args.rust))
    if args.probe:
        set_probe(args.probe.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix='peerspan-coord-ops-') as temporary:
        suite = Suite(args, Path(temporary))
        try:
            suite.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            suite.results.append(('suite', False, detail))
            print(f'FAIL [suite]: {detail}', flush=True)
        finally:
            if args.logs and not all(ok for _, ok, _ in suite.results):
                suite.save_logs(args.logs)
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


if __name__ == '__main__':
    main()
