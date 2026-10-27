#!/usr/bin/env python3
"""Exercise the launch service and coordinator (milestone 7 slice 2) across CLI/daemon pairings.

Written from docs/launch-contract.md ("Slice 2: service and coordinator")
alone. Each check's message names the contract rule it enforces.

Coordinator checks run once against the Go peerspan-coord, with raw clients
that sign enrollment statements through OpenSSL and speak the coordination
API and relay frames directly:

- the member cap, its idempotent rejoin, and the 429 body;
- the registration cap per source address, the idempotent 200 not counted,
  and counts across a restart;
- the relay cap: charging the lowest-ID shared network, frames dropped,
  `unreachable` at most once per second, the usage endpoint (members only),
  and the counter across an orderly restart;
- every limit disabled with 0, and the defaults reported by usage;
- migration of the coordinator database from version 4 to 5.

Every Go/Rust CLI and daemon pairing then covers, with recording stubs for
systemctl, loginctl, and launchctl on PATH and HOME and XDG_CONFIG_HOME
redirected:

- install on Linux: unit contents, the tool calls in order, the default port
  and the next free one, `--peer-listen` kept from an existing unit,
  idempotence, a changed unit restarting, a failing loginctl, refusal while a
  foreground daemon runs, and `no supported service manager`;
- install on macOS, selected by stubbing launchctl without systemctl;
- uninstall with and without a unit;
- `status`: `service`, and attention items 8 to 11;
- a host's `coordinator_limit` and `last_sync_error`, and the member cap
  with real hosts;
- the default coordinator: Go and Rust daemons built with the build
  variables pointing at a coordinator this suite starts, and the given
  binaries as builds without them. The daemon applies the default, so the
  pairing's CLI drives both daemon builds;
- `install` listed in root help right after `status`.

The stubs model a service manager closely enough for the CLI to wait on: the
systemctl stub starts ExecStart from the unit it loaded at the last
`daemon-reload` (or from disk when none was loaded), like systemd. A real
`systemd --user` run is opt-in with --real-systemd, because it installs into
the invoking user's own service manager and enables lingering for them.

Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen), OpenSSL, Go, and Cargo.
Unresolved questions about the contract are listed in the suite questions
file kept with milestone 7 slice 2; checks that depend on a reading of an open
question say so in a comment.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import secrets
import shlex
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from support import Coordinator, decode_token, wait_for
from host_service import die_with_parent, stop_all
from peer_messaging import PeerHost, available_port, set_probe
from persons import Agent, ssh_key
from policy import PolicyHost

REPO = Path(__file__).resolve().parent.parent
GO_PACKAGE = 'github.com/peerspan/peerspan/go/internal/host'
RELAY_ALPN = 'peerspan-relay/1'
SEND, RECEIVE, UNREACHABLE = 1, 2, 3
ATTENTION_ORDER = ['coordination_error', 'policy_expired', 'policy_expiring', 'policy_delivery_failing',
                   'credential_expiring', 'tasks_failed', 'artifact_quota', 'service_not_installed',
                   'linger_disabled', 'person_agent_unreachable', 'coordinator_limit',
                   # Items 12 to 15 (launch, live delivery, and capabilities contracts).
                   'agent_name_conflict', 'channel_unverified', 'capability_failing', 'capability_name_conflict']
CLI_KINDS = {'service_not_installed', 'linger_disabled'}
INSTALL_KEYS = {'service', 'unit', 'state', 'peer_listen', 'linger', 'started'}
UNINSTALL_KEYS = {'service', 'unit', 'removed'}
SERVICE_KEYS = {'manager', 'unit', 'installed', 'active', 'linger'}
USAGE_KEYS = {'members', 'max_members', 'relay_bytes', 'max_relay_bytes', 'month'}
NO_DEFAULT = 'this build has no default coordinator; pass --coordinator and --coordinator-key'
# Calls that change a service manager's state; queries may come in between.
SYSTEMCTL_QUERIES = {'is-active', 'is-enabled', 'is-failed', 'show', 'status', 'cat', 'list-units',
                     'list-unit-files', 'show-environment', 'is-system-running'}
LOGINCTL_QUERIES = {'show-user', 'user-status', 'list-users', 'show-session', 'list-sessions'}
LAUNCHCTL_QUERIES = {'print', 'list', 'print-disabled', 'blame', 'managername', 'version'}


def rule(text, detail=None):
    """An assertion message naming the contract rule."""
    return f'launch contract, slice 2: {text}' + (f' -- got {detail!r}' if detail is not None else '')


def rfc3339(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


def now():
    return datetime.now(timezone.utc)


# Ed25519 through OpenSSL, for raw enrollment fixtures.

class Key:
    """An Ed25519 key with OpenSSL files, a host ID, and a TLS client certificate."""

    def __init__(self, directory, seed=None):
        self.seed = seed or secrets.token_bytes(32)
        name = secrets.token_hex(6)
        self.directory = directory
        der, self.pem = directory / f'{name}.der', directory / f'{name}.pem'
        der.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + self.seed)
        subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', str(der), '-out', str(self.pem)],
                       check=True, capture_output=True, timeout=10)
        self.public = subprocess.run(['openssl', 'pkey', '-in', str(self.pem), '-pubout', '-outform', 'DER'],
                                     check=True, capture_output=True, timeout=10).stdout[-32:]
        self.b64 = base64.b64encode(self.public).decode()
        self.host_id = 'host_' + hashlib.sha256(self.public).hexdigest()
        self.raw_id = hashlib.sha256(self.public).digest()
        self.cert = None

    def sign(self, lines):
        message = self.directory / f'{secrets.token_hex(6)}.msg'
        message.write_bytes('\n'.join(lines).encode())
        signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(self.pem), '-rawin', '-in',
                                    str(message)], check=True, capture_output=True, timeout=10).stdout
        message.unlink()
        assert len(signature) == 64, signature
        return base64.b64encode(signature).decode()

    def context(self, alpn):
        if self.cert is None:
            self.cert = self.directory / f'{secrets.token_hex(6)}.cert'
            subprocess.run(['openssl', 'req', '-new', '-x509', '-key', str(self.pem), '-out', str(self.cert),
                            '-subj', '/CN=launch-service-fixture', '-days', '1'],
                           check=True, capture_output=True, timeout=10)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        # The fixture tests limits, not pinning, which the host suites cover.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(self.cert, self.pem)
        context.set_alpn_protocols([alpn])
        return context


def host_key(host, directory):
    """A Key for a disposable host's own identity."""
    with sqlite3.connect(host.state / 'host.db') as connection:
        seed = connection.execute('SELECT private_key FROM identity').fetchone()[0][:32]
    return Key(directory, bytes(seed))


def coord_call(coord, key, method, path, body=None, source=None):
    """One coordination API request with key's client certificate; returns (status, body)."""
    raw = socket.create_connection(('127.0.0.1', coord.port), timeout=10,
                                   source_address=(source, 0) if source else None)
    tls = key.context('http/1.1').wrap_socket(raw)
    connection = http.client.HTTPConnection('127.0.0.1', coord.port, timeout=10)
    connection.sock = tls
    try:
        payload = json.dumps(body).encode() if body is not None else None
        connection.request(method, path, payload, {'Content-Type': 'application/json'})
        response = connection.getresponse()
        data = response.read()
        return response.status, (json.loads(data) if data else None)
    finally:
        connection.close()


class RawNetwork:
    """A network whose root key this suite holds, registered and joined by raw clients."""

    def __init__(self, directory, name='raw'):
        self.directory = directory
        self.root = Key(directory)
        self.id = 'net_' + hashlib.sha256(self.root.public).hexdigest()
        self.name = name

    def membership(self, host, member):
        invite = Key(self.directory)
        expires = rfc3339(now() + timedelta(days=30))
        signature = self.root.sign(['peerspan-invite-v1', self.id, invite.b64, member, expires])
        return member_statement(self.id, member, invite, expires, signature, host)

    def register(self, coord, host, source=None):
        body = {'name': self.name, 'root_public_key': self.root.b64, 'membership': self.membership(host, 'founder'),
                'address': '', 'candidates': []}
        self.registration = body
        return coord_call(coord, host, 'POST', '/coord/v1/networks', body, source=source)

    def join(self, coord, host, membership=None):
        membership = membership or self.membership(host, 'member')
        return coord_call(coord, host, 'POST', f'/coord/v1/networks/{self.id}/members',
                          {'membership': membership, 'address': '', 'candidates': []})


def member_statement(network_id, member, invite, expires, invite_signature, host):
    joined = rfc3339(now() - timedelta(seconds=5))
    return {'network_id': network_id, 'member': member, 'invite_public_key': invite.b64,
            'invite_expires_at': expires, 'invite_signature': invite_signature, 'host_public_key': host.b64,
            'joined_at': joined,
            'host_signature': invite.sign(['peerspan-member-v1', network_id, invite.b64, host.b64, joined])}


def token_membership(token, host, directory):
    """A membership for a raw host under a real host-only invite token."""
    prefix, fields = decode_token(token)
    assert prefix == 'peerspan-invite-v1', prefix
    invite = Key(directory, base64.b64decode(fields['invite_seed']))
    assert invite.b64 == fields['invite_public_key']
    return member_statement(fields['network_id'], fields['member'], invite, fields['invite_expires_at'],
                            fields['invite_signature'], host)


def usage(coord, key, network_id):
    return coord_call(coord, key, 'GET', f'/coord/v1/networks/{network_id}/usage')


def check_limit_body(status, body, limit, context):
    assert status == 429, rule(f'over a limit, {context} returns 429', (status, body))
    assert isinstance(body, dict) and set(body) == {'code', 'error', 'limit'}, \
        rule('the 429 body is {code, error, limit}', body)
    assert body['code'] == 'limit' and isinstance(body['error'], str) and body['error'], \
        rule('the 429 body has code "limit" and an error', body)
    assert body['limit'] == limit, rule(f'the 429 limit names {limit}', body)


def check_usage(coord, key, network_id, **expected):
    status, body = usage(coord, key, network_id)
    assert status == 200, rule('usage returns 200 to a member', (status, body))
    assert set(body) == USAGE_KEYS, rule('usage is {members, max_members, relay_bytes, max_relay_bytes, month}', body)
    assert body['month'] == now().strftime('%Y-%m'), rule('usage month is the UTC YYYY-MM', body)
    for name, value in expected.items():
        assert body[name] == value, rule(f'usage {name} is {value}', body)
    return body


# Raw relay connections.

class Relay:
    def __init__(self, coord, key):
        self.key = key
        self.connection = key.context(RELAY_ALPN).wrap_socket(
            socket.create_connection(('127.0.0.1', coord.port), timeout=5))
        assert self.connection.selected_alpn_protocol() == RELAY_ALPN

    def send(self, destination, datagram):
        self.connection.sendall(struct.pack('>BH', SEND, 32 + len(datagram)) + destination.raw_id + datagram)

    def frames(self, seconds):
        """Every frame received within seconds, as (type, payload)."""
        received = []
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            self.connection.settimeout(remaining)
            try:
                header = self._exact(3)
            except (socket.timeout, TimeoutError):
                break
            kind, size = struct.unpack('>BH', header)
            self.connection.settimeout(5)
            received.append((kind, self._exact(size)))
        return received

    def first(self, seconds):
        """The first frame within seconds, as a one-item list, or []."""
        self.connection.settimeout(seconds)
        try:
            header = self._exact(3)
        except (socket.timeout, TimeoutError):
            return []
        kind, size = struct.unpack('>BH', header)
        self.connection.settimeout(5)
        return [(kind, self._exact(size))]

    def _exact(self, size):
        data = b''
        while len(data) < size:
            chunk = self.connection.recv(size - len(data))
            if not chunk:
                raise AssertionError('relay connection closed')
            data += chunk
        return data

    def close(self):
        self.connection.close()


class LimitCoordinator(Coordinator):
    """peerspan-coord run with limit flags."""

    def __init__(self, binary, state, flags=(), port=None):
        super().__init__(binary, state)
        self.flags = tuple(flags)
        if port is not None:
            self.port, self.address = port, f'127.0.0.1:{port}'

    def start(self):
        self.process = subprocess.Popen([self.binary, '--state', str(self.state), 'run', '--listen', self.address,
                                         *self.flags], stdout=self.logs, stderr=self.logs,
                                        preexec_fn=die_with_parent)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.logs.seek(0)
                raise AssertionError(f'coordinator exited: {self.logs.read().decode()}')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=0.2):
                    return self.info()
            except OSError:
                time.sleep(0.02)
        raise AssertionError('coordinator did not become ready')

    def stop(self):
        super().stop()
        if self.process is not None:
            assert self.process.returncode == 0, f'coordinator exit status {self.process.returncode}'

    def close(self):
        # Cleanup must not mask an earlier failure.
        try:
            super().stop()
        finally:
            self.logs.close()


def eventually(predicate, timeout, message, describe=None):
    """wait_for, failing with the contract rule and the last observed value."""
    try:
        return wait_for(predicate, timeout=timeout, message=message)
    except AssertionError:
        raise AssertionError(rule(message, describe() if describe else None)) from None


def wait_relay_ready():
    # The coordinator checks membership on every frame or from a cache
    # refreshed at least every 5 seconds (coordination contract, Relay).
    # Polling with frames would spend the relay budget under test.
    time.sleep(5.5)


# Coordinator checks, independent of host pairings.

def check_member_cap(coord_binary, root):
    coord = LimitCoordinator(coord_binary, root / 'coord-members', ['--max-members', '3'])
    try:
        coord.start()
        net = RawNetwork(root)
        founder, second, third, fourth = (Key(root) for _ in range(4))
        status, body = net.register(coord, founder)
        assert status == 201, (status, body)
        check_usage(coord, founder, net.id, members=1, max_members=3)
        joins = {}
        for host in (second, third):
            joins[host] = net.membership(host, 'member')
            status, body = net.join(coord, host, joins[host])
            assert status == 201, rule('a join below --max-members succeeds', (status, body))
        status, body = net.join(coord, fourth)
        check_limit_body(status, body, 'members', 'a join of a new host to a network at --max-members')
        status, body = net.join(coord, second, joins[second])
        assert status == 200, rule('retrying a join that already succeeded returns 200 at the cap', (status, body))
        check_usage(coord, third, net.id, members=3, max_members=3, relay_bytes=0)
        status, body = usage(coord, fourth, net.id)
        assert status == 403, rule('usage is for members only; a refused joiner gets 403', (status, body))
        status, body = usage(coord, fourth, 'net_' + '0' * 64)
        # Literal reading: "for members only, and returns 403 otherwise",
        # including for an unknown network (see suite questions).
        assert status == 403, rule('usage of a network the caller is not a member of returns 403', (status, body))
        # The cap is per network.
        other = RawNetwork(root, 'other')
        status, body = other.register(coord, fourth)
        assert status == 201, rule('--max-members counts per network', (status, body))
        coord.stop()
        coord.start()
        status, body = net.join(coord, Key(root))
        check_limit_body(status, body, 'members', 'a join at the cap after a restart')
    finally:
        coord.close()


def check_registration_cap(coord_binary, root):
    coord = LimitCoordinator(coord_binary, root / 'coord-registrations', ['--max-networks-per-ip', '2'])
    try:
        coord.start()
        host = Key(root)
        first, second, third = RawNetwork(root, 'a'), RawNetwork(root, 'b'), RawNetwork(root, 'c')
        for network in (first, second):
            status, body = network.register(coord, host)
            assert status == 201, rule('registrations below --max-networks-per-ip succeed', (status, body))
        status, body = coord_call(coord, host, 'POST', '/coord/v1/networks', first.registration)
        assert status == 200, rule('the idempotent registration of an existing network returns 200 at the cap',
                                   (status, body))
        status, body = third.register(coord, host)
        check_limit_body(status, body, 'networks_per_ip', 'a third registration from one IPv4 source')
        # The source address is the TCP peer address: another IPv4 address has
        # its own count.
        elsewhere = Key(root)
        fourth = RawNetwork(root, 'd')
        status, body = fourth.register(coord, elsewhere, source='127.0.0.2')
        assert status == 201, rule('registrations count per source address (127.0.0.2 is a different source)',
                                   (status, body))
        # Counts persist across restarts.
        coord.stop()
        coord.start()
        status, body = RawNetwork(root, 'e').register(coord, host)
        check_limit_body(status, body, 'networks_per_ip', 'a registration over the cap after a restart')
        status, body = coord_call(coord, host, 'POST', '/coord/v1/networks', second.registration)
        assert status == 200, rule('the idempotent 200 is not counted, after a restart too', (status, body))
        status, body = RawNetwork(root, 'f').register(coord, elsewhere, source='127.0.0.2')
        assert status == 201, rule('a second source keeps its own count across a restart', (status, body))
        status, body = RawNetwork(root, 'g').register(coord, elsewhere, source='127.0.0.2')
        check_limit_body(status, body, 'networks_per_ip', 'a third registration from 127.0.0.2')
        # A refused network was not registered: its founder is not a member.
        status, body = usage(coord, host, third.id)
        assert status == 403, rule('a refused registration creates no network', (status, body))
    finally:
        coord.close()


def check_relay_cap(coord_binary, root):
    limit = 3000
    coord = LimitCoordinator(coord_binary, root / 'coord-relay', ['--relay-bytes-per-month', str(limit)])
    relays = []
    try:
        coord.start()
        x, y, z = Key(root), Key(root), Key(root)
        low, high = sorted((RawNetwork(root, 'p'), RawNetwork(root, 'q')), key=lambda n: n.id)
        for network in (low, high):
            assert network.register(coord, x)[0] == 201
            assert network.join(coord, y)[0] == 201
        assert high.join(coord, z)[0] == 201
        rx, ry, rz = Relay(coord, x), Relay(coord, y), Relay(coord, z)
        relays += [rx, ry, rz]
        wait_relay_ready()

        # Forwarded datagrams are charged to the lowest-ID shared network.
        for index in range(3):
            datagram = bytes([index]) * 1000
            rx.send(y, datagram)
            frames = ry.first(2)
            assert frames == [(RECEIVE, x.raw_id + datagram)], \
                rule('frames below the relay limit are forwarded unchanged', frames)
        check_usage(coord, y, low.id, relay_bytes=3000, max_relay_bytes=limit)
        check_usage(coord, y, high.id, relay_bytes=0, max_relay_bytes=limit)
        assert rx.frames(0.2) == [], 'no unreachable while under the limit'

        # The monthly total reached the limit: frames are dropped, and the
        # sender gets unreachable at most once per second per destination.
        rx.send(y, b'd' * 1000)
        first = rx.first(1.5)
        assert first == [(UNREACHABLE, y.raw_id)], \
            rule('over the relay limit the coordinator answers the sender with unreachable', first)
        for _ in range(4):
            rx.send(y, b'e' * 500)
        extra = rx.frames(0.3)
        assert extra == [], rule('unreachable is sent at most once per second per destination', [(k, p.hex()[:16]) for k, p in extra])
        assert ry.frames(0.5) == [], rule('frames of a network over its relay limit are dropped')
        time.sleep(1.1)  # past the one-second window
        rx.send(y, b'f' * 10)
        again = rx.frames(1.5)
        assert again == [(UNREACHABLE, y.raw_id)], rule('later dropped frames are answered again after a second', again)
        ry.send(x, b'g' * 10)
        assert ry.frames(1.5) == [(UNREACHABLE, x.raw_id)], rule('the limit applies to the network, in both directions')
        assert rx.frames(0.3) == [], rule('dropped frames are not delivered')
        # Literal reading: only forwarded frames are charged (see suite questions).
        check_usage(coord, x, low.id, relay_bytes=3000)

        # A pair whose only shared network is the other one is unaffected.
        rx.send(z, b'h' * 700)
        assert rz.first(2) == [(RECEIVE, x.raw_id + b'h' * 700)], \
            rule('frames are charged to the lowest-ID network the two hosts share, not the sender\'s lowest')
        check_usage(coord, z, high.id, relay_bytes=700)
        check_usage(coord, z, high.id, members=3)

        # Counters persist on orderly shutdown.
        for relay in relays:
            relay.close()
        relays.clear()
        coord.stop()
        coord.start()
        check_usage(coord, x, low.id, relay_bytes=3000)
        check_usage(coord, x, high.id, relay_bytes=700)
        rx, ry = Relay(coord, x), Relay(coord, y)
        relays += [rx, ry]
        wait_relay_ready()
        rx.send(y, b'i' * 10)
        assert rx.frames(1.5) == [(UNREACHABLE, y.raw_id)], rule('the relay limit holds after a restart')
        assert ry.frames(0.3) == []
    finally:
        for relay in relays:
            relay.close()
        coord.close()


def check_defaults_and_disabled(coord_binary, root):
    coord = LimitCoordinator(coord_binary, root / 'coord-defaults')
    try:
        coord.start()
        host = Key(root)
        net = RawNetwork(root)
        assert net.register(coord, host)[0] == 201
        check_usage(coord, host, net.id, members=1, max_members=50, relay_bytes=0, max_relay_bytes=10_000_000_000)
    finally:
        coord.close()

    coord = LimitCoordinator(coord_binary, root / 'coord-disabled',
                             ['--max-members', '0', '--max-networks-per-ip', '0', '--relay-bytes-per-month', '0'])
    relays = []
    try:
        coord.start()
        host = Key(root)
        # More than the default 20 registrations from one source.
        networks = [RawNetwork(root, f'n{i}') for i in range(21)]
        for network in networks:
            status, body = network.register(coord, host)
            assert status == 201, rule('--max-networks-per-ip 0 disables the registration limit', (status, body))
        # More than the default 50 members in one network.
        net = networks[0]
        members = [Key(root) for _ in range(50)]
        for member in members:
            status, body = net.join(coord, member)
            assert status == 201, rule('--max-members 0 disables the member limit', (status, body))
        check_usage(coord, host, net.id, members=51, max_members=0, max_relay_bytes=0)
        a, b = members[0], members[1]
        ra, rb = Relay(coord, a), Relay(coord, b)
        relays += [ra, rb]
        wait_relay_ready()
        for index in range(4):
            ra.send(b, bytes([index]) * 1400)
        frames = rb.frames(2)
        assert len(frames) == 4 and all(kind == RECEIVE for kind, _ in frames), \
            rule('--relay-bytes-per-month 0 disables the relay limit', frames)
        assert ra.frames(0.3) == []
    finally:
        for relay in relays:
            relay.close()
        coord.close()


def check_migration(coord_binary, root):
    coord = LimitCoordinator(coord_binary, root / 'coord-migration', ['--max-networks-per-ip', '2'])
    try:
        coord.start()
        host = Key(root)
        net = RawNetwork(root)
        assert net.register(coord, host)[0] == 201
        coord.stop()
        database = coord.state / 'coord.db'
        with sqlite3.connect(database) as connection:
            assert connection.execute('PRAGMA user_version').fetchone()[0] == 7, \
                rule('coordinator schema version 7 (approved linking transport)')
            check_schema(connection)
            # Model the public version4 schema, removing every newer fixture
            # table without depending on private schema7 bookkeeping names.
            version4 = {'identity', 'networks', 'members', 'member_candidates', 'statements'}
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for table in tables:
                if table not in version4:
                    connection.execute('DROP TABLE "' + table.replace('"', '""') + '"')
            connection.execute('PRAGMA user_version = 4')
        connection.close()
        coord.start()
        with sqlite3.connect(database) as connection:
            assert connection.execute('PRAGMA user_version').fetchone()[0] == 7, \
                rule('version 7 migrates version 4 state')
            check_schema(connection)
        connection.close()
        status, body = coord_call(coord, host, 'POST', f'/coord/v1/networks/{net.id}/sync',
                                  {'address': '', 'candidates': []})
        assert status == 200, rule('a network from version 4 state still syncs after migration', (status, body))
        check_usage(coord, host, net.id, members=1, relay_bytes=0)
        second, third = RawNetwork(root, 'b'), RawNetwork(root, 'c')
        assert second.register(coord, host)[0] == 201
        status, body = third.register(coord, host)
        # Registrations before the migration were never recorded, so this is
        # the second recorded one.
        assert status == 201, rule('registrations count from the migration on', (status, body))
        status, body = RawNetwork(root, 'd').register(coord, host)
        check_limit_body(status, body, 'networks_per_ip', 'the registration limit after migration')
        with sqlite3.connect(database) as connection:
            recorded = {row[0] for row in connection.execute('SELECT network_id FROM registrations')}
        connection.close()
        assert {second.id, third.id} <= recorded, rule('new registrations are stored in registrations', recorded)
    finally:
        coord.close()


def check_schema(connection):
    columns = {row[1]: row for row in connection.execute('PRAGMA table_info(registrations)')}
    assert list(columns) == ['source', 'network_id', 'created_at'], rule('the registrations table', list(columns))
    assert all(columns[c][3] == 1 for c in columns), rule('registrations columns are NOT NULL')
    columns = {row[1]: row for row in connection.execute('PRAGMA table_info(relay_usage)')}
    assert list(columns) == ['network_id', 'month', 'bytes'], rule('the relay_usage table', list(columns))
    assert [columns[c][5] for c in ('network_id', 'month', 'bytes')] == [1, 2, 0], \
        rule('relay_usage has PRIMARY KEY(network_id, month)')


def check_coordinator(coord_binary):
    failed = []
    for check_part in (check_member_cap, check_registration_cap, check_relay_cap, check_defaults_and_disabled,
                       check_migration):
        with tempfile.TemporaryDirectory(prefix='peerspan-launch-coord-') as temporary:
            try:
                check_part(coord_binary, Path(temporary))
                print(f'  ok coordinator: {check_part.__name__}', flush=True)
            except Exception:
                failed.append(check_part.__name__)
                print(f'  FAIL coordinator: {check_part.__name__}', flush=True)
                traceback.print_exc()
                sys.stderr.flush()
    if failed:
        raise AssertionError(f'coordinator: failed checks: {", ".join(failed)}')
    print('PASS coordinator: member cap and idempotent rejoin, registration cap per source and across restart, '
          'relay cap with unreachable and usage, 429 bodies, limits disabled with 0, migration from 4 to 5', flush=True)


# Service-manager stubs.

STUB = r'''#!{python}
# Recording stub for {tool}, written by conformance/launch_service.py.
import json, os, plistlib, shlex, signal, subprocess, sys, time
STATE = {state!r}
TOOL = os.path.basename(sys.argv[0])
ARGS = sys.argv[1:]
with open(os.path.join(STATE, 'calls.jsonl'), 'a') as log:
    log.write(json.dumps({{'tool': TOOL, 'args': ARGS}}) + '\n')

def path(name):
    return os.path.join(STATE, name)

def read(name):
    try:
        with open(path(name)) as f:
            return f.read()
    except FileNotFoundError:
        return None

def write(name, text):
    with open(path(name), 'w') as f:
        f.write(text)

def remove(name):
    try:
        os.unlink(path(name))
    except FileNotFoundError:
        pass

def running():
    pid = read('pid')
    if not pid:
        return None
    try:
        with open(f'/proc/{{int(pid)}}/stat') as f:
            if f.read().split(') ')[-1].startswith('Z'):
                return None
        return int(pid)
    except (FileNotFoundError, ValueError):
        return None

def launch(argv, environment):
    env = dict(os.environ)
    env.update(environment)
    logs = open(path('daemon.log'), 'ab')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=logs, stderr=logs, env=env,
                               start_new_session=True)
    write('pid', str(process.pid))
    with open(path('pids'), 'a') as f:
        f.write(f'{{process.pid}}\n')
    starts = int(read('starts') or '0') + 1
    write('starts', str(starts))

def stop():
    pid = running()
    remove('pid')
    if pid is None:
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(160):
        if not os.path.exists(f'/proc/{{pid}}'):
            return
        with open(f'/proc/{{pid}}/stat') as f:
            if f.read().split(') ')[-1].startswith('Z'):
                return
        time.sleep(0.05)
    os.kill(pid, signal.SIGKILL)

def unit_file():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.environ['HOME'], '.config')
    candidates = [os.path.join(base, 'systemd', 'user', 'peerspan.service'),
                  os.path.join(os.environ['HOME'], '.config', 'systemd', 'user', 'peerspan.service')]
    for candidate in candidates:
        if os.path.exists(candidate):
            with open(candidate) as f:
                return f.read()
    return None

def systemd_start():
    if running():
        return 0
    unit = read('loaded')
    if unit is None:
        unit = unit_file()
    if unit is None:
        print('Failed to start peerspan.service: Unit peerspan.service not found.', file=sys.stderr)
        return 5
    argv, environment = None, {{}}
    for line in unit.splitlines():
        line = line.strip()
        if line.startswith('ExecStart='):
            argv = shlex.split(line[len('ExecStart='):])
        elif line.startswith('Environment='):
            for item in shlex.split(line[len('Environment='):]):
                key, _, value = item.partition('=')
                environment[key] = value
    launch(argv, environment)
    return 0

def systemctl():
    words = [a for a in ARGS if not a.startswith('-')]
    verb = words[0] if words else ''
    if verb == 'daemon-reload':
        unit = unit_file()
        if unit is None:
            remove('loaded')
        else:
            write('loaded', unit)
        return 0
    if verb == 'enable':
        if unit_file() is None and read('loaded') is None:
            print('Failed to enable unit: Unit file peerspan.service does not exist.', file=sys.stderr)
            return 1
        write('enabled', 'yes')
        return systemd_start() if '--now' in ARGS else 0
    if verb == 'disable':
        if read('disable-fails') is not None:
            print('Failed to disable unit: Access denied', file=sys.stderr)
            return 1
        remove('enabled')
        if '--now' in ARGS:
            stop()
        return 0
    if verb in ('start', 'reenable'):
        return systemd_start()
    if verb == 'stop':
        stop()
        return 0
    if verb in ('restart', 'reload-or-restart', 'try-restart', 'try-reload-or-restart', 'reload'):
        if verb.startswith('try') and not running():
            return 0
        stop()
        return systemd_start()
    if verb == 'is-active':
        print('active' if running() else 'inactive')
        return 0 if running() else 3
    if verb == 'is-enabled':
        print('enabled' if read('enabled') else 'disabled')
        return 0 if read('enabled') else 1
    if verb == 'show':
        pid = running() or 0
        values = {{'MainPID': str(pid), 'ActiveState': 'active' if pid else 'inactive',
                  'SubState': 'running' if pid else 'dead', 'UnitFileState': 'enabled' if read('enabled') else 'disabled',
                  'LoadState': 'loaded' if (unit_file() or read('loaded')) else 'not-found', 'Id': 'peerspan.service'}}
        wanted = []
        for index, arg in enumerate(ARGS):
            if arg.startswith('--property='):
                wanted += arg.split('=', 1)[1].split(',')
            elif arg in ('-p', '--property') and index + 1 < len(ARGS):
                wanted += ARGS[index + 1].split(',')
            elif arg.startswith('-p') and len(arg) > 2:
                wanted += arg[2:].split(',')
        for name in wanted or list(values):
            print(values.get(name, '') if '--value' in ARGS else f'{{name}}={{values.get(name, "")}}')
        return 0
    if verb == 'status':
        print('peerspan.service', 'active (running)' if running() else 'inactive (dead)')
        return 0 if running() else 3
    return 0

def loginctl():
    words = [a for a in ARGS if not a.startswith('-')]
    verb = words[0] if words else ''
    if verb == 'enable-linger':
        if read('loginctl-fails') is not None:
            print('Could not enable linger: Access denied', file=sys.stderr)
            return 1
        write('linger', 'yes')
        return 0
    if verb == 'disable-linger':
        remove('linger')
        return 0
    if verb == 'show-user':
        value = 'yes' if read('linger') else 'no'
        print(value if '--value' in ARGS else f'Linger={{value}}')
        return 0
    return 0

def launchctl():
    verb = ARGS[0] if ARGS else ''
    label = 'gui/{uid}/dev.peerspan.host'
    if verb == 'bootstrap':
        if read('loaded') is not None:
            print('Bootstrap failed: 5: Input/output error', file=sys.stderr)
            return 5
        with open(ARGS[2], 'rb') as f:
            plist = plistlib.load(f)
        write('loaded', ARGS[2])
        launch(plist['ProgramArguments'], plist.get('EnvironmentVariables', {{}}))
        return 0
    if verb == 'bootout':
        if read('loaded') is None:
            print('Boot-out failed: 3: No such process', file=sys.stderr)
            return 3
        remove('loaded')
        stop()
        return 0
    if verb == 'kickstart':
        if read('loaded') is None:
            return 113
        if '-k' in ARGS:
            stop()
        if not running():
            with open(read('loaded'), 'rb') as f:
                plist = plistlib.load(f)
            launch(plist['ProgramArguments'], plist.get('EnvironmentVariables', {{}}))
        return 0
    if verb == 'print':
        if read('loaded') is None:
            print(f'Could not find service "dev.peerspan.host" in domain for user gui: {uid}', file=sys.stderr)
            return 113
        pid = running()
        print(f'{{label}} = {{{{')
        print('\tactive count = ' + ('1' if pid else '0'))
        print('\tstate = ' + ('running' if pid else 'not running'))
        if pid:
            print(f'\tpid = {{pid}}')
        print('}}')
        return 0
    return 0

sys.exit({{'systemctl': systemctl, 'loginctl': loginctl, 'launchctl': launchctl}}[TOOL]())
'''


class Stubs:
    """A directory of recording service-tool stubs with their own state."""

    def __init__(self, directory, tools):
        self.bin = directory / 'bin'
        self.state = directory / 'state'
        self.bin.mkdir(parents=True)
        self.state.mkdir()
        for tool in tools:
            script = self.bin / tool
            script.write_text(STUB.format(python=sys.executable, tool=tool, state=str(self.state), uid=os.getuid()))
            script.chmod(0o755)

    def calls(self, tool=None):
        path = self.state / 'calls.jsonl'
        if not path.exists():
            return []
        calls = [json.loads(line) for line in path.read_text().splitlines()]
        return [(c['tool'], c['args']) for c in calls if tool is None or c['tool'] == tool]

    def changes(self):
        """Calls that change service-manager state, in order."""
        found = []
        for tool, args in self.calls():
            words = [a for a in args if not a.startswith('-')]
            verb = words[0] if words else ''
            if tool == 'systemctl' and verb in SYSTEMCTL_QUERIES:
                continue
            if tool == 'loginctl' and verb in LOGINCTL_QUERIES:
                continue
            if tool == 'launchctl' and verb in LAUNCHCTL_QUERIES:
                continue
            found.append((tool, args))
        return found

    def clear(self):
        (self.state / 'calls.jsonl').unlink(missing_ok=True)

    def pid(self):
        path = self.state / 'pid'
        if not path.exists():
            return None
        pid = int(path.read_text())
        try:
            if (Path(f'/proc/{pid}/stat').read_text().split(') ')[-1]).startswith('Z'):
                return None
        except FileNotFoundError:
            return None
        return pid

    def starts(self):
        path = self.state / 'starts'
        return int(path.read_text()) if path.exists() else 0

    def fail_loginctl(self):
        (self.state / 'loginctl-fails').write_text('')

    def fail_disable(self, failing=True):
        flag = self.state / 'disable-fails'
        flag.write_text('') if failing else flag.unlink(missing_ok=True)

    def kill_all(self):
        path = self.state / 'pids'
        if not path.exists():
            return
        for line in path.read_text().split():
            try:
                os.kill(int(line), signal.SIGKILL)
            except ProcessLookupError:
                pass


def daemon_environ(pid):
    raw = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
    return dict(item.decode().partition('=')[::2] for item in raw if item)


def first_free_udp(start=7401, end=7499):
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                udp.bind(('0.0.0.0', port))
            except OSError:
                continue
            return port
    raise AssertionError('no free UDP port from 7401 to 7499 for the suite')


def parse_unit(text):
    """{section: [(key, value)]} of a systemd unit."""
    sections, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            sections.setdefault(current, [])
        else:
            key, _, value = line.partition('=')
            sections.setdefault(current, []).append((key.strip(), value.strip()))
    return sections


def unit_values(sections, section, key):
    return [value for k, value in sections.get(section, []) if k == key]


def unit_environment(sections):
    found = {}
    for value in unit_values(sections, 'Service', 'Environment'):
        for item in shlex.split(value):
            name, _, setting = item.partition('=')
            found[name] = setting
    return found


def admin_ready(state):
    try:
        connection = http.client.HTTPConnection('localhost', timeout=2)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(str(Path(state) / 'admin.sock'))
        connection.sock = sock
        connection.request('GET', '/v1/host')
        return connection.getresponse().status == 200
    except OSError:
        return False


class Cli:
    """The pairing's CLI with a redirected HOME, config directory, and PATH."""

    def __init__(self, binary, link_dir, home, path, config=None, agent_socket=None):
        self.binary = Path(binary)
        self.program = link_dir / 'peerspan'
        if not self.program.exists():
            self.program.symlink_to(self.binary)
        self.home, self.path, self.config, self.agent_socket = home, path, config, agent_socket
        home.mkdir(parents=True, exist_ok=True)

    def env(self):
        env = {k: v for k, v in os.environ.items() if k not in ('SSH_AUTH_SOCK', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME')}
        env['HOME'] = str(self.home)
        env['PATH'] = self.path
        if self.config is not None:
            env['XDG_CONFIG_HOME'] = str(self.config)
        if self.agent_socket is not None:
            env['SSH_AUTH_SOCK'] = self.agent_socket
        return env

    def run(self, *args, state=None, timeout=30):
        prefix = ['--state', str(state)] if state is not None else []
        return subprocess.run([str(self.program), *prefix, *args], capture_output=True, text=True,
                              timeout=timeout, env=self.env())

    def json(self, *args, state=None, what=None):
        result = self.run(*args, state=state)
        assert result.returncode == 0, rule(what or ' '.join(args) + ' succeeds', (result.stdout, result.stderr))
        return json.loads(result.stdout)

    def status(self, state):
        result = self.run('status', '--json', state=state)
        value = json.loads(result.stdout) if result.stdout.strip() else None
        return result.returncode, value, result.stderr


def check_service_object(value, expected, context):
    service = value.get('service') if isinstance(value, dict) else None
    assert isinstance(service, dict) and set(service) == SERVICE_KEYS, \
        rule(f'status --json has service {{manager, unit, installed, active, linger}} ({context})', value)
    for key, wanted in expected.items():
        # `active` is compared as a boolean: the literal reading (suite questions).
        assert service[key] == wanted and type(service[key]) is type(wanted), \
            rule(f'service.{key} is {wanted!r} ({context})', service)
    return service


def kinds(value):
    return [(i['kind'], i['subject']) for i in value['attention']]


def check_attention_order(value):
    for item in value['attention']:
        assert set(item) == {'kind', 'subject', 'detail', 'command'}, rule('attention items have four fields', item)
        assert item['kind'] in ATTENTION_ORDER, rule('known attention kinds', item)
    keys = [(ATTENTION_ORDER.index(i['kind']), i['subject']) for i in value['attention']]
    assert keys == sorted(keys), rule('items 8 to 11 follow the existing seven, sorted by subject within a kind', keys)


def check_install_output(out, unit, state, peer_listen, linger, started, service='systemd'):
    assert set(out) == INSTALL_KEYS, rule('install prints {service, unit, state, peer_listen, linger, started}', out)
    assert out['service'] == service, rule(f'install output service is {service}', out)
    assert Path(out['unit']) == Path(unit), rule('install prints the unit path', (out['unit'], str(unit)))
    assert Path(out['state']).resolve() == Path(state).resolve(), rule('install prints the state directory', out)
    assert out['peer_listen'] == peer_listen, rule(f'install peer_listen is {peer_listen}', out)
    assert out['linger'] is linger, rule(f'install linger is {linger}', out)
    assert out['started'] is started, rule(f'install started is {started}', out)


def check_unit(unit, cli_binary, state, peer_listen, ssh_auth_sock):
    assert unit.exists(), rule('install writes $XDG_CONFIG_HOME/systemd/user/peerspan.service', str(unit))
    sections = parse_unit(unit.read_text())
    [exec_start] = unit_values(sections, 'Service', 'ExecStart') or [None]
    assert exec_start, rule('the unit has ExecStart in [Service]', sections)
    # Literal reading: exactly these arguments (suite questions, Q1).
    expected = [os.path.realpath(cli_binary), '--state', str(Path(state).resolve()), 'run', '--peer-listen',
                peer_listen]
    assert shlex.split(exec_start) == expected, \
        rule('ExecStart is the resolved real path, --state, run, and --peer-listen', (exec_start, expected))
    assert unit_values(sections, 'Service', 'Restart') == ['on-failure'], rule('Restart=on-failure', sections)
    assert unit_values(sections, 'Install', 'WantedBy') == ['default.target'], rule('WantedBy=default.target', sections)
    environment = unit_environment(sections)
    if ssh_auth_sock is None:
        assert 'SSH_AUTH_SOCK' not in environment, rule('no SSH_AUTH_SOCK when the shell has none', environment)
    else:
        assert environment.get('SSH_AUTH_SOCK') == ssh_auth_sock, \
            rule('Environment=SSH_AUTH_SOCK= the installing shell\'s value', environment)
    return unit.read_text()


def systemctl(*args):
    return ('systemctl', ['--user', *args])


def check_linger_call(call):
    tool, args = call
    assert tool == 'loginctl' and args[:1] == ['enable-linger'] and len(args) <= 2, \
        rule('install last runs loginctl enable-linger for the current user', call)
    if len(args) == 2:
        assert args[1] in (os.environ.get('USER', ''), str(os.getuid()), _user_name()), \
            rule('enable-linger names the current user', call)


def _user_name():
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


def check_install_linux(cli_binary, daemon_binary, root, cleanup):
    links = root / 'links'
    links.mkdir()
    base_path = os.environ.get('PATH', '')

    # Port taken; explicit --state; XDG_CONFIG_HOME set; SSH_AUTH_SOCK set; --no-start.
    stubs = Stubs(root / 'stubs-a', ['systemctl', 'loginctl'])
    cleanup.append(stubs)
    config = root / 'config-a'
    cli = Cli(cli_binary, links, root / 'home-a', f'{stubs.bin}:{base_path}', config=config,
              agent_socket=str(root / 'agent-one.sock'))
    state = root / 'state-a'
    unit = config / 'systemd' / 'user' / 'peerspan.service'
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            holder.bind(('0.0.0.0', 7401))
        except OSError:
            pass  # already taken by something else
        expected = first_free_udp()
        assert expected != 7401
        out = cli.json('install', '--state', str(state), '--no-start', what='install --no-start succeeds')
    finally:
        holder.close()
    address = f'0.0.0.0:{expected}'
    check_install_output(out, unit, state, address, True, False)
    assert stubs.pid() is None, rule('--no-start never starts the service')
    first_unit = check_unit(unit, cli_binary, state, address, str(root / 'agent-one.sock'))
    changes = stubs.changes()
    assert changes[:2] == [systemctl('daemon-reload'), systemctl('enable', 'peerspan.service')] and len(changes) == 3, \
        rule('install --no-start runs daemon-reload, enable (without --now), then loginctl enable-linger', changes)
    check_linger_call(changes[2])
    assert stubs.pid() is None and not admin_ready(state), rule('--no-start does not start the service')
    code, value, _ = cli.status(state)
    assert code == 2, rule('status exits 2 when the daemon is not running', (code, value))
    assert value.get('daemon') == 'not running', value
    assert not value.get('attention'), rule('a not-running status has no attention items', value)
    check_service_object(value, {'manager': 'systemd', 'installed': True, 'active': False, 'linger': True},
                         'installed, not started')
    assert Path(value['service']['unit']) == unit, rule('service.unit is the unit path', value['service'])

    # Without --peer-listen, the existing unit's address is kept even though
    # 7401 is free again; the identical unit is only enabled and started.
    stubs.clear()
    out = cli.json('install', '--state', str(state), what='a repeated install succeeds')
    check_install_output(out, unit, state, address, True, True)
    assert unit.read_text() == first_unit, rule('--peer-listen defaults to the address in an existing unit')
    assert admin_ready(state), rule('install starts the service and waits for the admin socket')
    pid = stubs.pid()
    assert pid is not None
    changes = stubs.changes()
    assert changes[:1] == [systemctl('enable', '--now', 'peerspan.service')] and len(changes) == 2, \
        rule('with an identical unit, install runs enable --now, then loginctl enable-linger', changes)
    check_linger_call(changes[1])
    # Idempotence while running: nothing restarts.
    stubs.clear()
    starts = stubs.starts()
    out = cli.json('install', '--state', str(state), what='an idempotent install succeeds')
    check_install_output(out, unit, state, address, True, True)
    assert unit.read_text() == first_unit and stubs.pid() == pid and stubs.starts() == starts, \
        rule('install is idempotent: an identical unit does not restart the running service', stubs.changes())
    changes = stubs.changes()
    assert changes[:1] == [systemctl('enable', '--now', 'peerspan.service')] and len(changes) == 2, \
        rule('with an identical unit, install runs enable --now, then loginctl enable-linger', changes)
    check_linger_call(changes[1])

    # A changed unit (a new SSH_AUTH_SOCK) is rewritten and restarts the service.
    cli.agent_socket = str(root / 'agent-two.sock')
    stubs.clear()
    out = cli.json('install', '--state', str(state), what='install with a changed unit succeeds')
    check_install_output(out, unit, state, address, True, True)
    check_unit(unit, cli_binary, state, address, str(root / 'agent-two.sock'))
    new_pid = eventually(lambda: stubs.pid() if stubs.pid() not in (None, pid) else None, 10,
                         'a changed unit rewrites the unit and restarts the service', stubs.changes)
    assert daemon_environ(new_pid).get('SSH_AUTH_SOCK') == str(root / 'agent-two.sock'), \
        rule('the restarted service runs the rewritten unit (daemon-reload before restart)', stubs.changes())
    eventually(lambda: admin_ready(state), 10, 'the restarted service serves the admin socket')
    changes = stubs.changes()
    assert changes[:3] == [systemctl('daemon-reload'), systemctl('enable', '--now', 'peerspan.service'),
                           systemctl('restart', 'peerspan.service')] and len(changes) == 4, \
        rule('with a changed unit, install runs daemon-reload, enable --now, restart, then loginctl enable-linger',
             changes)
    check_linger_call(changes[3])

    # A changed unit with --no-start: rewritten, never restarted.
    cli.agent_socket = str(root / 'agent-three.sock')
    stubs.clear()
    out = cli.json('install', '--state', str(state), '--no-start', what='install --no-start with a changed unit')
    # started: --no-start does not wait for the admin socket (suite questions, Q2).
    check_install_output(out, unit, state, address, True, False)
    check_unit(unit, cli_binary, state, address, str(root / 'agent-three.sock'))
    changes = stubs.changes()
    assert changes[:2] == [systemctl('daemon-reload'), systemctl('enable', 'peerspan.service')] \
        and len(changes) == 3, rule('--no-start never starts or restarts the service', changes)
    check_linger_call(changes[2])
    assert stubs.pid() == new_pid, rule('--no-start never restarts the service')

    # Status for the installed and running service: nothing needs attention.
    code, value, _ = cli.status(state)
    check_service_object(value, {'manager': 'systemd', 'installed': True, 'active': True, 'linger': True},
                         'installed and running')
    assert not [k for k in kinds(value) if k[0] in CLI_KINDS], rule('no service items for a running service', value)
    assert code == (1 if value['attention'] else 0), (code, value['attention'])

    # Defaults: --state and the default port, with XDG_CONFIG_HOME unset.
    stubs_b = Stubs(root / 'stubs-b', ['systemctl', 'loginctl'])
    cleanup.append(stubs_b)
    home = root / 'home-b'
    cli_b = Cli(cli_binary, links, home, f'{stubs_b.bin}:{base_path}')
    default_state = home / '.local' / 'state' / 'peerspan' / 'host'
    default_unit = home / '.config' / 'systemd' / 'user' / 'peerspan.service'
    expected = first_free_udp()
    out = cli_b.json('install', what='install with defaults succeeds')
    port = f'0.0.0.0:{expected}'
    check_install_output(out, default_unit, default_state, port, True, True)
    if expected == 7401:
        assert out['peer_listen'] == '0.0.0.0:7401', rule('the default peer address is 0.0.0.0:7401', out)
    check_unit(default_unit, cli_binary, default_state, port, None)
    changes = stubs_b.changes()
    assert changes[:2] == [systemctl('daemon-reload'), systemctl('enable', '--now', 'peerspan.service')] \
        and len(changes) == 3, \
        rule('install runs daemon-reload, enable --now peerspan.service, then loginctl enable-linger', changes)
    check_linger_call(changes[2])
    assert admin_ready(default_state), rule('install waits for the admin socket of the started daemon')
    stubs_b.clear()
    code, value, _ = cli_b.status(None)
    check_service_object(value, {'manager': 'systemd', 'installed': True, 'active': True, 'linger': True},
                         'default state')
    queries = [args for tool, args in stubs_b.calls('loginctl')]
    users = {os.environ.get('USER', ''), _user_name(), str(os.getuid())} - {''}
    # Option order is not significant to loginctl: the verb, the user, and the property.
    assert any(len(a) == 3 and a[0] == 'show-user' and '--property=Linger' in a and users & set(a) for a in queries), \
        rule('linger comes from loginctl show-user USER --property=Linger', queries)
    assert any('is-active' in args for _, args in stubs_b.calls('systemctl')), \
        rule('active comes from systemctl --user is-active', stubs_b.calls('systemctl'))
    assert Path(value['service']['unit']) == default_unit, rule('service.unit with the default config directory')

    # Uninstall stops and disables the service, removes the unit, keeps state and lingering.
    stubs_b.clear()
    out = cli_b.json('uninstall', what='uninstall succeeds')
    assert set(out) == UNINSTALL_KEYS and out['removed'] is True, rule('uninstall prints {service, unit, removed}', out)
    assert out['service'] == 'systemd', rule('uninstall output service is systemd', out)
    assert Path(out['unit']) == default_unit, rule('uninstall prints the unit path', out)
    changes = stubs_b.changes()
    assert changes == [systemctl('disable', '--now', 'peerspan.service')], \
        rule('uninstall runs systemctl --user disable --now peerspan.service and keeps lingering', changes)
    assert not default_unit.exists(), rule('uninstall removes the unit')
    assert default_state.is_dir() and (default_state / 'host.db').exists(), rule('uninstall keeps the state directory')
    assert stubs_b.pid() is None
    code, value, _ = cli_b.status(None)
    assert code == 2, rule('status exits 2 after uninstall stops the daemon', (code, value))
    assert not value.get('attention'), rule('a not-running status has no attention items', value)
    check_service_object(value, {'manager': 'systemd', 'installed': False, 'active': False, 'linger': True},
                         'after uninstall')
    out = cli_b.json('uninstall', what='uninstall with nothing installed succeeds')
    assert set(out) == UNINSTALL_KEYS and out['removed'] is False, \
        rule('uninstalling with nothing installed succeeds with removed: false', out)

    # A failing loginctl is reported as linger: false; status asks for lingering.
    stubs_c = Stubs(root / 'stubs-c', ['systemctl', 'loginctl'])
    cleanup.append(stubs_c)
    stubs_c.fail_loginctl()
    cli_c = Cli(cli_binary, links, root / 'home-c', f'{stubs_c.bin}:{base_path}', config=root / 'config-c')
    state_c = root / 'state-c'
    listen = f'127.0.0.1:{available_port()}'
    unit_c = root / 'config-c' / 'systemd' / 'user' / 'peerspan.service'
    out = cli_c.json('install', '--state', str(state_c), '--peer-listen', listen,
                     what='install succeeds even when loginctl fails')
    check_install_output(out, unit_c, state_c, listen, False, True)
    check_unit(unit_c, cli_binary, state_c, listen, None)
    assert stubs_c.changes()[-1][0] == 'loginctl', rule('loginctl enable-linger runs last', stubs_c.changes())
    code, value, _ = cli_c.status(state_c)
    check_service_object(value, {'manager': 'systemd', 'installed': True, 'active': True, 'linger': False},
                         'linger disabled')
    check_attention_order(value)
    [item] = [i for i in value['attention'] if i['kind'] == 'linger_disabled'] or [None]
    assert item and item['subject'] == 'service' and item['command'] == 'loginctl enable-linger', \
        rule('linger_disabled: subject service, command loginctl enable-linger', value['attention'])
    assert not [i for i in value['attention'] if i['kind'] == 'service_not_installed'], \
        rule('service_not_installed only without a unit', value['attention'])
    assert code == 1, rule('status exits 1 with attention', code)
    # A failing systemctl disable is an error.
    stubs_c.fail_disable()
    result = cli_c.run('uninstall')
    assert result.returncode != 0, rule('a failing systemctl disable fails uninstall', (result.stdout, result.stderr))
    stubs_c.fail_disable(False)
    cli_c.json('uninstall', what='uninstall succeeds')
    assert state_c.is_dir()

    # Refusal while a foreground daemon runs on that state directory.
    stubs_d = Stubs(root / 'stubs-d', ['systemctl', 'loginctl'])
    cleanup.append(stubs_d)
    cli_d = Cli(cli_binary, links, root / 'home-d', f'{stubs_d.bin}:{base_path}', config=root / 'config-d')
    foreground = PeerHost(daemon_binary, root / 'state-d')
    try:
        foreground.start()
        result = cli_d.run('install', '--state', str(foreground.state))
        assert result.returncode != 0, rule('install fails while a daemon runs outside the service', result.stdout)
        unit_d = root / 'config-d' / 'systemd' / 'user' / 'peerspan.service'
        assert not unit_d.exists() and stubs_d.changes() == [], \
            rule('a refused install changes nothing', stubs_d.changes())
        assert any('is-active' in args for _, args in stubs_d.calls('systemctl')), \
            rule('install asks the manager whether the service is active when the admin socket answers',
                 stubs_d.calls())
        code, value, _ = cli_d.status(foreground.state)
        check_service_object(value, {'manager': 'systemd', 'installed': False, 'active': False}, 'foreground daemon')
        check_attention_order(value)
        items = [i for i in value['attention'] if i['kind'] in CLI_KINDS]
        assert [(i['kind'], i['subject'], i['command']) for i in items] == \
            [('service_not_installed', 'service', 'peerspan install')], \
            rule('service_not_installed: no unit while the daemon runs outside a service', value['attention'])
        assert code == 1, rule('status exits 1 with attention', code)
        status, daemon_view = foreground.call('GET', '/v1/status')
        assert status == 200 and 'service' not in daemon_view, rule('the CLI, not the daemon, adds service', daemon_view)
        assert not [i for i in daemon_view['attention'] if i['kind'] in CLI_KINDS], \
            rule('items 8 and 9 are added by the CLI', daemon_view['attention'])
    finally:
        stop_all([foreground])

    # No supported service manager.
    empty = root / 'empty-bin'
    empty.mkdir()
    cli_e = Cli(cli_binary, links, root / 'home-e', str(empty))
    result = cli_e.run('install', '--state', str(root / 'state-e'))
    assert result.returncode != 0 and 'no supported service manager' in result.stderr, \
        rule('without systemctl or launchctl, install fails with no supported service manager',
             (result.stdout, result.stderr))
    assert not (root / 'home-e' / '.config').exists() and not (root / 'home-e' / 'Library').exists(), \
        rule('a failed install changes nothing')
    assert not (root / 'state-e').exists() or not any((root / 'state-e').iterdir()), \
        rule('a failed install changes nothing (state)')
    code, value, _ = cli_e.status(root / 'state-e')
    assert code == 2, (code, value)
    check_service_object(value, {'manager': None}, 'no service manager')
    result = cli_e.run('uninstall')
    assert result.returncode != 0 and 'no supported service manager' in result.stderr, \
        rule('with no manager on PATH, uninstall fails with no supported service manager',
             (result.stdout, result.stderr))


def check_install_macos(cli_binary, root, cleanup):
    links = root / 'links-mac'
    links.mkdir()
    stubs = Stubs(root / 'stubs-mac', ['launchctl'])
    cleanup.append(stubs)
    home = root / 'home-mac'
    # Only launchctl on PATH: no systemctl and no loginctl. The shell has an
    # SSH_AUTH_SOCK, which the plist must not carry.
    cli = Cli(cli_binary, links, home, str(stubs.bin), agent_socket=str(root / 'mac-agent.sock'))
    state = root / 'state-mac'
    listen = f'127.0.0.1:{available_port()}'
    plist_path = home / 'Library' / 'LaunchAgents' / 'dev.peerspan.host.plist'
    uid = os.getuid()

    def check_plist(address):
        assert plist_path.exists(), rule('install writes ~/Library/LaunchAgents/dev.peerspan.host.plist')
        with plist_path.open('rb') as f:
            plist = plistlib.load(f)
        expected = [os.path.realpath(cli_binary), '--state', str(state.resolve()), 'run', '--peer-listen', address]
        assert plist.get('ProgramArguments') == expected, rule('the plist has the same program arguments', plist)
        assert plist.get('RunAtLoad') is True, rule('the plist sets RunAtLoad', plist)
        assert plist.get('KeepAlive') not in (None, False, {}), rule('the plist sets KeepAlive', plist)
        # The bootout target gui/UID/dev.peerspan.host names the job by this label.
        assert plist.get('Label') == 'dev.peerspan.host', rule('the plist label matches gui/UID/dev.peerspan.host', plist)
        assert 'SSH_AUTH_SOCK' not in json.dumps(plist, default=str), \
            rule('the plist carries no SSH_AUTH_SOCK, since launchd provides it', plist)

    out = cli.json('install', '--state', str(state), '--peer-listen', listen, what='install with launchctl succeeds')
    check_install_output(out, plist_path, state, listen, None, True, service='launchd')
    check_plist(listen)
    changes = stubs.changes()
    assert changes == [('launchctl', ['bootstrap', f'gui/{uid}', str(plist_path)])], \
        rule('install runs launchctl bootstrap gui/UID on the plist', changes)
    assert admin_ready(state), rule('install waits for the admin socket')
    pid = stubs.pid()
    code, value, _ = cli.status(state)
    check_service_object(value, {'manager': 'launchd', 'installed': True, 'active': True, 'linger': None},
                         'launchd')
    assert Path(value['service']['unit']) == plist_path, rule('service.unit is the plist path', value['service'])
    assert any(args[:1] == ['print'] for _, args in stubs.calls('launchctl')), \
        rule('active comes from launchctl print', stubs.calls())
    assert not [k for k in kinds(value) if k[0] in CLI_KINDS], rule('no service items on macOS when running', value)

    # A changed plist: bootout, then bootstrap.
    moved = f'127.0.0.1:{available_port()}'
    stubs.clear()
    out = cli.json('install', '--state', str(state), '--peer-listen', moved, what='install with a changed plist')
    check_install_output(out, plist_path, state, moved, None, True, service='launchd')
    check_plist(moved)
    changes = stubs.changes()
    assert [args[0] for _, args in changes] == ['bootout', 'bootstrap'] and \
        changes[1] == ('launchctl', ['bootstrap', f'gui/{uid}', str(plist_path)]), \
        rule('with a changed plist, install runs bootout, then bootstrap', changes)
    assert stubs.pid() not in (None, pid), rule('a changed plist restarts the service')

    stubs.clear()
    out = cli.json('uninstall', what='uninstall with launchctl succeeds')
    assert set(out) == UNINSTALL_KEYS and out['removed'] is True and Path(out['unit']) == plist_path, \
        rule('uninstall prints {service, unit, removed}', out)
    assert out['service'] == 'launchd', rule('uninstall output service is launchd', out)
    assert stubs.changes() == [('launchctl', ['bootout', f'gui/{uid}/dev.peerspan.host'])], \
        rule('uninstall runs launchctl bootout gui/UID/dev.peerspan.host', stubs.changes())
    assert not plist_path.exists() and state.is_dir(), rule('uninstall removes the plist and keeps state')
    # The stub's bootout now fails (nothing loaded); a failing bootout is ignored.
    out = cli.json('uninstall', what='uninstall with nothing installed succeeds (a failing bootout is ignored)')
    assert out['removed'] is False, rule('uninstalling with nothing installed reports removed: false', out)

    # --no-start writes the plist without calling launchctl.
    stubs.clear()
    out = cli.json('install', '--state', str(state), '--peer-listen', listen, '--no-start',
                   what='install --no-start with launchctl')
    check_install_output(out, plist_path, state, listen, None, False, service='launchd')
    check_plist(listen)
    assert stubs.calls('launchctl') == [], rule('--no-start writes the plist without calling launchctl', stubs.calls())
    assert stubs.pid() is None


def check_real_systemd(cli_binary, root):
    """Opt-in: install into the invoking user's real systemd --user manager."""
    config = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    unit = config / 'systemd' / 'user' / 'peerspan.service'
    assert not unit.exists(), f'refusing --real-systemd: {unit} already exists'
    state = root / 'real-state'
    listen = f'127.0.0.1:{available_port()}'
    env = dict(os.environ)
    result = subprocess.run([str(cli_binary), 'install', '--state', str(state), '--peer-listen', listen],
                            capture_output=True, text=True, timeout=60, env=env)
    try:
        assert result.returncode == 0, rule('install with a real systemd --user', (result.stdout, result.stderr))
        out = json.loads(result.stdout)
        assert out['started'] is True and admin_ready(state), rule('the real service started', out)
        active = subprocess.run(['systemctl', '--user', 'is-active', 'peerspan.service'], capture_output=True,
                                text=True, timeout=10).stdout.strip()
        assert active == 'active', rule('systemd reports the service active', active)
        result = subprocess.run([str(cli_binary), '--state', str(state), 'status', '--json'], capture_output=True,
                                text=True, timeout=30, env=env)
        check_service_object(json.loads(result.stdout), {'manager': 'systemd', 'installed': True, 'active': True},
                             'real systemd')
    finally:
        result = subprocess.run([str(cli_binary), 'uninstall'], capture_output=True, text=True, timeout=60, env=env)
        assert result.returncode == 0 and json.loads(result.stdout)['removed'] is True, \
            rule('uninstall with a real systemd --user', (result.stdout, result.stderr))
        assert not unit.exists()


# Hosts in networks, for attention items 10 and 11 and host-side limits.

class LimitHost(PolicyHost):
    """A daemon of one implementation, driven by the pairing's CLI through Cli."""

    def __init__(self, daemon_binary, state, cli):
        super().__init__(daemon_binary, state)
        self.client = cli

    def run_cli(self, *args):
        return self.client.run(*args, state=self.state)

    def cli(self, *args, success=True):
        result = self.run_cli(*args)
        assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
        return json.loads(result.stdout) if success else result.stderr

    def status(self):
        code, value, stderr = self.client.status(self.state)
        assert code in (0, 1) and value is not None, (code, value, stderr)
        assert code == (1 if value['attention'] else 0), rule('status exits 1 exactly when attention is nonempty')
        check_attention_order(value)
        return value


def member_record(host, network_id):
    with sqlite3.connect(host.state / 'host.db') as connection:
        rows = connection.execute('SELECT host_id, record FROM network_members WHERE network_id = ?',
                                  (network_id,)).fetchall()
    connection.close()
    identity = host.call('GET', '/v1/host')[1]['id']
    return json.loads(next(record for host_id, record in rows if host_id == identity))


def check_hosts(coord_binary, cli_binary, daemon_binary, root, cleanup):
    links = root / 'links-hosts'
    links.mkdir()
    stubs = Stubs(root / 'stubs-hosts', ['systemctl', 'loginctl'])
    cleanup.append(stubs)
    path = f'{stubs.bin}:{os.environ.get("PATH", "")}'
    (root / 'keys').mkdir()
    pat_key = ssh_key(root / 'keys', 'pat')
    other_key = ssh_key(root / 'keys', 'other')
    (root / 'agent').mkdir()
    (root / 'agent-other').mkdir()
    agent, other_agent = Agent(root / 'agent'), Agent(root / 'agent-other')
    agent.add(pat_key[0])
    other_agent.add(other_key[0])
    coord = LimitCoordinator(coord_binary, root / 'coord-hosts',
                             ['--max-members', '2', '--max-networks-per-ip', '2', '--relay-bytes-per-month', '1000'])
    alice = LimitHost(daemon_binary, root / 'alice',
                      Cli(cli_binary, links, root / 'home-alice', path, agent_socket=agent.socket))
    bob = LimitHost(daemon_binary, root / 'bob', Cli(cli_binary, links, root / 'home-bob', path))
    carol = LimitHost(daemon_binary, root / 'carol', Cli(cli_binary, links, root / 'home-carol', path))
    hosts = [alice, bob, carol]
    relays = []
    try:
        coordinator = coord.start()
        flags = ('--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
        a, b, c = alice.start(), bob.start(), carol.start()

        # alice's network one, with her person pat and a stored policy; her
        # daemon has no ssh-agent.
        one = alice.cli('network', 'create', '--name', 'one', '--member', 'pat', *flags)['id']
        alice.cli('access', 'allow', '--network', one, '--agent', 'reviewer', '--principal', 'network')
        # bob joins as a separate member; carol's join exceeds --max-members 2.
        invite = alice.cli('network', 'invite', '--network', one, '--member', 'bob', '--host-only',
                           '--expires-in', '1h')
        assert bob.cli('network', 'join', '--token', invite['token'])['id'] == one
        invite = alice.cli('network', 'invite', '--network', one, '--member', 'carol', '--host-only',
                           '--expires-in', '1h')
        refused = carol.run_cli('network', 'join', '--token', invite['token'])
        assert refused.returncode != 0, rule('a join over --max-members fails (persons are not counted)',
                                             refused.stdout)
        status, body = carol.call('POST', '/v1/networks/join', {'token': invite['token']})
        assert status == 429 and body.get('code') == 'limit' and body.get('limit') == 'members', \
            rule('a join refused with 429 returns local 429 {code: "limit", limit}', (status, body))
        assert carol.cli('network', 'list') == [], rule('a join refused with 429 stores no network')
        value = carol.status()
        assert [(i['kind'], i['subject']) for i in value['attention'] if i['kind'] == 'coordinator_limit'] == \
            [('coordinator_limit', f'{one}/members')], \
            rule('status reports coordinator_limit under the network ID from the token', kinds(value))
        assert value['networks'] == [], rule('a refused join has no network and no last_sync_error', value['networks'])

        # Retrying bob's join, which already succeeded, returns 200 at the cap.
        bob_key = host_key(bob, root)
        own = member_record(bob, one)
        status, body = coord_call(coord, bob_key, 'POST', f'/coord/v1/networks/{one}/members',
                                  {'membership': own['membership'], 'address': '', 'candidates': []})
        assert status == 200, rule('retrying a join that already succeeded still returns 200', (status, body))
        check_usage(coord, bob_key, one, members=2, max_members=2, max_relay_bytes=1000)

        # Network relay: alice and a raw member, which relays 1000 bytes to alice.
        relay_net = alice.cli('network', 'create', '--name', 'relay', '--member', 'alice', '--no-person', *flags)['id']
        token = alice.cli('network', 'invite', '--network', relay_net, '--member', 'x', '--host-only',
                          '--expires-in', '1h')['token']
        x = Key(root)
        status, body = coord_call(coord, x, 'POST', f'/coord/v1/networks/{relay_net}/members',
                                  {'membership': token_membership(token, x, root), 'address': '', 'candidates': []})
        assert status == 201, (status, body)
        rx = Relay(coord, x)
        relays.append(rx)
        target = host_key(alice, root)

        def charged():
            rx.send(target, b'r' * 1000)
            rx.frames(0.5)
            return usage(coord, x, relay_net)[1]['relay_bytes'] >= 1000
        eventually(charged, 20, 'relayed datagram bytes are charged to the network',
                   lambda: usage(coord, x, relay_net))

        # A third registration from this address exceeds --max-networks-per-ip 2.
        three = alice.cli('network', 'create', '--name', 'three', '--member', 'alice', '--no-person', *flags)
        assert three['last_sync_error'] and 'networks_per_ip' in three['last_sync_error'], \
            rule('a 429 from create is reported as last_sync_error with the limit name', three)
        three = three['id']

        expected_alice = sorted([f'{one}/members', f'{relay_net}/members', f'{relay_net}/relay_bytes',
                                 f'{three}/networks_per_ip'])

        def limits(host, wanted):
            value = host.status()
            found = sorted(i['subject'] for i in value['attention'] if i['kind'] == 'coordinator_limit')
            return value if found == wanted else None
        for network in (one, relay_net):
            alice.cli('network', 'sync', network)
        value = eventually(lambda: limits(alice, expected_alice), 20,
                           f'hosts report coordinator_limit {expected_alice} (members, relay_bytes, 429 from create)',
                           lambda: kinds(alice.status()))
        for item in value['attention']:
            if item['kind'] == 'coordinator_limit':
                assert item['command'] == '', rule('coordinator_limit has an empty command', item)
        network = next(n for n in value['networks'] if n['id'] == three)
        assert 'networks_per_ip' in (network['last_sync_error'] or ''), \
            rule('the refused registration stays in last_sync_error', network)
        assert kinds(value) == [('coordination_error', three), ('service_not_installed', 'service'),
                                ('person_agent_unreachable', one)] + \
            [('coordinator_limit', s) for s in expected_alice], \
            rule('alice\'s attention items, in order', kinds(value))
        [item] = [i for i in value['attention'] if i['kind'] == 'person_agent_unreachable']
        assert item['command'] == 'peerspan install', rule('person_agent_unreachable command is peerspan install', item)
        status, daemon_view = alice.call('GET', '/v1/status')
        daemon_kinds = [i['kind'] for i in daemon_view['attention']]
        assert 'person_agent_unreachable' in daemon_kinds and 'coordinator_limit' in daemon_kinds, \
            rule('items 10 and 11 are added by the daemon', daemon_kinds)
        assert not CLI_KINDS & set(daemon_kinds), rule('items 8 and 9 are added by the CLI', daemon_kinds)

        bob.cli('network', 'sync', one)
        eventually(lambda: limits(bob, [f'{one}/members']), 20, 'the joiner reports coordinator_limit for members',
                   lambda: kinds(bob.status()))
        assert not [i for i in bob.status()['attention'] if i['kind'] == 'person_agent_unreachable'], \
            rule('person_agent_unreachable only for a host bound to a person with a policy')

        # person_agent_unreachable: socket that cannot be connected, an agent
        # without the person's key, then one with it.
        def unreachable_items():
            return [i for i in alice.status()['attention'] if i['kind'] == 'person_agent_unreachable']
        def subjects():
            return [i['subject'] for i in unreachable_items()]
        alice.restart(1, flag_socket=str(root / 'missing.sock'))
        eventually(lambda: subjects() == [one], 10, 'person_agent_unreachable when --person-agent cannot be connected',
                   subjects)
        alice.restart(1, agent_socket=other_agent.socket)
        eventually(lambda: subjects() == [one], 10,
                   'person_agent_unreachable when the agent does not hold the person\'s key', subjects)
        alice.restart(1, agent_socket=agent.socket)
        eventually(lambda: subjects() == [], 10,
                   'no person_agent_unreachable when the daemon\'s agent (SSH_AUTH_SOCK) holds the person\'s key',
                   subjects)
        alice.restart(1, flag_socket=agent.socket)
        eventually(lambda: subjects() == [], 10, 'no person_agent_unreachable with --person-agent holding the key',
                   subjects)

        # The member cap counts current, unrevoked members: revoking bob frees a place.
        alice.cli('network', 'revoke', '--network', one, '--host', b['id'])
        invite = alice.cli('network', 'invite', '--network', one, '--member', 'carol', '--host-only',
                           '--expires-in', '1h')
        joined = carol.run_cli('network', 'join', '--token', invite['token'])
        assert joined.returncode == 0, rule('a revoked member no longer counts toward --max-members',
                                            (joined.stdout, joined.stderr))
    finally:
        for relay in relays:
            relay.close()
        try:
            stop_all(hosts)
        finally:
            coord.close()
            agent.stop()
            other_agent.stop()


def check_root_help(cli_binary, root):
    result = subprocess.run([str(cli_binary), 'help'], capture_output=True, text=True, timeout=10)
    lines = result.stdout.splitlines()
    assert result.returncode == 0 and 'Commands:' in lines, result.stdout
    paths = []
    for line in lines[lines.index('Commands:') + 1:]:
        if not line.strip():
            break
        paths.append(line.strip().split('  ')[0])
    assert paths[:3] == ['status', 'up', 'install'], rule('guided up appears after status, then install', paths)


# Default coordinator.

class Builds:
    """Go and Rust peerspan-host test builds with the default coordinator set, built in the background."""

    def __init__(self, directory, address, key, languages):
        self.directory = directory
        self.address, self.key = address, key
        self.results, self.errors = {}, {}
        self.threads = [threading.Thread(target=self._build, args=(language,), daemon=True) for language in languages]
        for thread in self.threads:
            thread.start()

    def _build(self, language):
        try:
            if language == 'Go':
                output = self.directory / 'go' / 'peerspan-host'
                flags = f'-X {GO_PACKAGE}.DefaultCoordinator={self.address} -X {GO_PACKAGE}.DefaultCoordinatorKey={self.key}'
                command = ['go', '-C', str(REPO / 'go'), 'build', '-ldflags', flags, '-o', str(output), './cmd/peerspan-host']
                env = dict(os.environ)
            else:
                target = self.directory / 'rust-target'
                output = target / 'debug' / 'peerspan-host'
                command = ['cargo', 'build', '--locked', '--manifest-path', str(REPO / 'rust' / 'Cargo.toml'),
                           '--target-dir', str(target)]
                env = dict(os.environ, PEERSPAN_COORDINATOR=self.address, PEERSPAN_COORDINATOR_KEY=self.key)
            result = subprocess.run(command, capture_output=True, text=True, timeout=1800, env=env)
            if result.returncode != 0:
                raise RuntimeError(f'{language} default-coordinator build failed:\n{result.stderr[-4000:]}')
            self.results[language] = output
        except Exception as error:  # reported when the build is needed
            self.errors[language] = error

    def get(self, language):
        for thread in self.threads:
            thread.join()
        if language in self.errors:
            raise self.errors[language]
        return self.results[language]


def check_default_coordinator(cli_binary, plain_daemon, default_daemon, default_coord, root):
    """The daemon applies the default coordinator, so the pairing's CLI drives both daemon builds."""
    links = root / 'links-default'
    links.mkdir()
    cli = Cli(cli_binary, links, root / 'home-default', os.environ.get('PATH', ''))

    # A daemon built without default values.
    host = PeerHost(plain_daemon, root / 'plain')
    try:
        host.start()
        info = cli.json('info', state=host.state)
        assert 'default_coordinator' in info and info['default_coordinator'] is None, \
            rule('info.default_coordinator is null in a build without default values '
                 '(pass --go/--rust binaries built without them)', info)
        result = cli.run('network', 'create', '--name', 'n', '--member', 'm', state=host.state)
        assert result.returncode != 0 and NO_DEFAULT in result.stderr, \
            rule(f'a build without both values fails network create without the flags with "{NO_DEFAULT}"',
                 (result.stdout, result.stderr))
        check_one_flag(cli, host, default_coord)
        assert cli.json('network', 'list', state=host.state) == []
    finally:
        stop_all([host])

    # A daemon built with default values: the coordinator this suite started.
    host = PeerHost(default_daemon, root / 'default')
    try:
        host.start()
        info = cli.json('info', state=host.state)
        assert info.get('default_coordinator') == {'address': default_coord.address,
                                                   'public_key': default_coord.public_key}, \
            rule('info.default_coordinator is {address, public_key} from the build variables', info)
        created = cli.json('network', 'create', '--name', 'hosted', '--member', 'm', state=host.state,
                           what='network create without the flags uses the build\'s default coordinator')
        assert created['coordinator_address'] == default_coord.address and \
            created['coordinator_public_key'] == default_coord.public_key, \
            rule('network create without the flags uses the default coordinator', created)
        assert created['last_sync_error'] is None and created['last_sync_at'], \
            rule('the network registers with the default coordinator', created)
        check_one_flag(cli, host, default_coord)
        assert len(cli.json('network', 'list', state=host.state)) == 1
    finally:
        stop_all([host])


def check_one_flag(cli, host, coord):
    for flags in (('--coordinator', coord.address), ('--coordinator-key', coord.public_key)):
        result = cli.run('network', 'create', '--name', 'n', '--member', 'm', *flags, state=host.state)
        assert result.returncode != 0, rule(f'giving only {flags[0]} is refused', (result.stdout, result.stderr))


class DefaultCoordinator:
    def __init__(self, coord_binary, directory):
        self.coord = LimitCoordinator(coord_binary, directory / 'coord-default')
        info = self.coord.start()
        self.address, self.public_key = self.coord.address, info['public_key']

    def close(self):
        self.coord.close()


def check(coord_binary, cli_binary, daemon_binary, label, builds, default_coord, real_systemd):
    name = f'{label[0]} CLI, {label[1]} daemon'
    sections = [
        ('install on Linux', lambda root, cleanup: check_install_linux(cli_binary, daemon_binary, root, cleanup)),
        ('install on macOS', lambda root, cleanup: check_install_macos(cli_binary, root, cleanup)),
        ('attention items and host-side limits',
         lambda root, cleanup: check_hosts(coord_binary, cli_binary, daemon_binary, root, cleanup)),
        ('root help', lambda root, cleanup: check_root_help(cli_binary, root)),
        ('default coordinator', lambda root, cleanup: check_default_coordinator(
            cli_binary, daemon_binary, builds.get(label[1]), default_coord, root)),
    ]
    if real_systemd:
        sections.append(('real systemd', lambda root, cleanup: check_real_systemd(cli_binary, root)))
    failed = []
    for section, run in sections:
        with tempfile.TemporaryDirectory(prefix='peerspan-launch-service-') as temporary:
            cleanup = []
            try:
                run(Path(temporary), cleanup)
                print(f'  ok {name}: {section}', flush=True)
            except Exception:
                failed.append(section)
                print(f'  FAIL {name}: {section}', flush=True)
                traceback.print_exc()
                sys.stderr.flush()
            finally:
                for stubs in cleanup:
                    stubs.kill_all()
    if failed:
        raise AssertionError(f'{name}: failed sections: {", ".join(failed)}')
    print(f'PASS {name}: install and uninstall (systemd and launchd stubs), service status, '
          'attention items 8 to 11, host-side coordinator limits, root help, default coordinator', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, help='required unless every --pairing is Go/Go')
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--pairing', action='append',
                        help='CLI/daemon implementations, such as Go/Rust; repeatable; default all four')
    parser.add_argument('--build-dir', type=Path,
                        help='where to build the default-coordinator test binaries (reused across runs); '
                             'default: a temporary directory')
    parser.add_argument('--real-systemd', action='store_true',
                        help='also install into your real systemd --user manager (enables lingering for you)')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve() if args.rust else None}
    pairings = args.pairing or [f'{c}/{d}' for c in binaries for d in binaries]
    parsed = []
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        if cli not in binaries or daemon not in binaries:
            parser.error(f'unknown pairing {pairing}')
        if binaries[cli] is None or binaries[daemon] is None:
            parser.error(f'pairing {pairing} needs --rust')
        parsed.append((cli, daemon))
    coord_binary = args.coord.resolve()
    languages = sorted({daemon for _, daemon in parsed})
    with tempfile.TemporaryDirectory(prefix='peerspan-launch-builds-') as temporary:
        build_dir = args.build_dir.resolve() if args.build_dir else Path(temporary)
        build_dir.mkdir(parents=True, exist_ok=True)
        default_coord = DefaultCoordinator(coord_binary, Path(temporary))
        try:
            builds = Builds(build_dir, default_coord.address, default_coord.public_key, languages)
            failures = []
            # Each part reports its own failure and the rest still run.
            parts = [('coordinator', lambda: check_coordinator(coord_binary))]
            for cli, daemon in parsed:
                parts.append((f'{cli} CLI, {daemon} daemon',
                              lambda cli=cli, daemon=daemon: check(coord_binary, binaries[cli], binaries[daemon],
                                                                   (cli, daemon), builds, default_coord,
                                                                   args.real_systemd)))
            for name, part in parts:
                try:
                    part()
                except Exception as error:
                    failures.append(name)
                    print(f'FAIL {name}: {error}', flush=True)
        finally:
            default_coord.close()
    if failures:
        sys.exit(f'FAILED: {", ".join(failures)}')


if __name__ == '__main__':
    main()
