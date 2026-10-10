#!/usr/bin/env python3
"""Exercise coordinator successors (milestone 8 slice 2) with the Go coordinator and Go and Rust hosts.

Written from docs/hosted-coordinator-contract.md ("Slice 2: successors", whose Verification subsection names
this suite) alone, with context from slice 1 of that contract, the hosted coordinator proposal, and the
coordination contract (transport, relay, STUN, invite tokens), independently of the coordinator and host
implementations. Hosts are driven through their CLIs and local APIs; the coordinator through its CLI, raw TLS
clients, raw relay connections, STUN requests, its ops listener, and its stderr log.

Sections, run once:

- successor test vector: the contract's vector reproduced (a self-check of the statement encoding the
  stand-in below signs with);
- successor command: refused on a state without a database (exit 1, none created); `info.identities` for a
  fresh state (identity 0 with a null address); refused while the coordinator runs (`coordinator is
  running`, exit 1); invalid addresses refused with nothing appended; an address change with the same key
  (DNS name, IPv4 and IPv6 literals); `nothing changes` (exit 1) for the latest address without
  `--new-key`; `--new-key` with the same address; the printed `{sequence, id, public_key, address,
  successor}`; each successor a strict object with exactly the six fields, sequences from 1, signed by the
  previous identity's key over the contract's lines, forming a valid chain; `info` reporting the latest key
  with every identity in order; database version 6;
- serving: `--previous-listen` refused with exit 2 and no start line for the latest identity, a later or
  nonexistent sequence, and a negative one; the `start` line's `previous_listen` (empty without the flag);
  each listener presenting its identity's key; `successors` on register, join, and sync (the chain from the
  identity reached, `[]` from the latest), including the identity chosen by the `Host` header among those
  with the listener's key (and the earliest for an unknown Host); one database across listeners; STUN on
  each listener's UDP port; relaying between hosts connected through different identities; `/healthz`
  reporting the latest id; and `capsule_coord_identity_hosts{sequence}` counting distinct hosts per listener.

Sections, per creator/joiner pairing (default all four Go/Rust combinations; alice and frank run the
creator's implementation, bob, carol, dave, and erin the joiner's):

- address change with the same key, as the runbook does it: `successor --address localhost:PORT` for a
  network pinned to `127.0.0.1:PORT`, restarted with the same single listener; alice and bob switch within
  two sync intervals with `coordinator_pending` back to null; connected-only messages both ways; relay
  connections in place (raw relay datagrams to them are not answered `unreachable`, while a stopped
  member's are); and a change notification reaching a host whose interval sync is far off;
- key change: `successor --address NEW --new-key` served with `--previous-listen 1=OLD`; running hosts
  switch; a host stopped during the change follows on restart; a join with an invite issued before the
  change ends pinned to the new identity; an invite issued after it carries the new pin, and its joiner is
  pinned there; messages among them;
- two successors applied while a host was stopped: frank, pinned to identity 0, follows to identity 2
  without ever pinning identity 1, with the start line's `previous_listen` and the per-sequence gauge
  (frank on identity 0, everyone on identity 2);
- unreachable new address: hosts keep their pin with `coordinator_pending` set (in `network list` and
  `GET /v1/networks`) and `last_sync_error` starting `coordinator successor ADDRESS: `; the pending entry
  survives a restart while the coordinator is down; hosts switch once the new listener starts, and invites
  then carry the new pin;
- invalid chain (coordinator stand-in): a Python TLS stand-in presenting a key this suite holds, proxying
  to the real coordinator with the host's own client key and replacing `successors` with chains it signs,
  with the host's interval sync far off so every sync is one the suite asks for. Each invalid chain (bad
  signature, wrong signer, wrong first key, sequence 0, sequence gap, repeated sequence, broken link,
  invalid address, extra field, missing field) leaves the pin with `invalid coordinator successor` while
  the map still applies; a valid chain to an unreachable address (with a `signed_at` that is not a time)
  becomes pending with `coordinator successor ADDRESS: `; an empty chain leaves it; a later valid chain to
  a second stand-in replaces it and the host switches; that stand-in's own chain is recorded as pending in
  that sync and followed on the next. Run for the creator and the joiner host.

Needs openssl. HOME and XDG_CONFIG_HOME are redirected per host under a temporary directory; the real
~/.config/capsule and systemd are never touched. Open questions are marked with `Q<n>` comments and listed
in the suite-questions file given to the owner. Exits non-zero listing every failed section.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import shutil
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

sys.path.insert(0, str(Path(__file__).resolve().parent))

from coord_ops import OpsCoordinator, OpsHost, coord_command, ops_request, scrape, tls_request  # noqa: E402
from coordination import decode_token, wait_for  # noqa: E402
from host_service import stop_all  # noqa: E402
from launch_push import RawRelay, V2, SEND, RECEIVE, UNREACHABLE, CHANGED, seed_of  # noqa: E402
from launch_service import Key, RawNetwork, token_membership  # noqa: E402
from peer_messaging import available_port, request_id, set_probe, timestamp  # noqa: E402

INTERVAL = 2           # --coordination-interval for hosts
SLACK = 8.0            # added to "two sync intervals" for a loaded shared machine (see --slack)
NOTIFY_INTERVAL = 600  # a host whose interval sync cannot explain a prompt update
INVALID = 'invalid coordinator successor'
SUCCESSOR_FIELDS = {'sequence', 'previous_public_key', 'address', 'public_key', 'signed_at', 'signature'}
SPKI_ED25519 = bytes.fromhex('302a300506032b6570032100')
RFC3339 = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$')


class Failure(AssertionError):
    pass


def need(condition, rule, *detail):
    """Assert one contract rule, naming it in the failure."""
    if not condition:
        raise Failure(f'hosted coordinator contract, slice 2: {rule}'
                      + (': ' + ' | '.join(repr(d)[:900] for d in detail) if detail else ''))


def eventually(predicate, timeout, rule, describe=None):
    """Poll until predicate holds; returns the seconds it took."""
    started = time.monotonic()
    try:
        wait_for(predicate, timeout=timeout, message=rule)
    except AssertionError:
        need(False, rule + f' (within {timeout:.0f}s)', describe() if describe else 'timed out')
    return time.monotonic() - started


def coord_id(public_b64):
    return 'coord_' + hashlib.sha256(base64.b64decode(public_b64)).hexdigest()


def canonical_key(value):
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode() == value


def rfc3339_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


# --- Ed25519 through OpenSSL --------------------------------------------------------------------------------

def verify(public_b64, lines, signature_b64, directory):
    """True when signature_b64 is public_b64's Ed25519 signature over the lines joined by \\n."""
    try:
        public, signature = base64.b64decode(public_b64, validate=True), base64.b64decode(signature_b64,
                                                                                          validate=True)
    except Exception:
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    name = secrets.token_hex(6)
    der, pem, msg, sig = (directory / f'{name}.pub.der', directory / f'{name}.pub.pem', directory / f'{name}.msg',
                          directory / f'{name}.sig')
    der.write_bytes(SPKI_ED25519 + public)
    subprocess.run(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', str(der), '-out', str(pem)], check=True,
                   capture_output=True, timeout=10)
    msg.write_bytes('\n'.join(lines).encode())
    sig.write_bytes(signature)
    result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(pem), '-rawin', '-in',
                             str(msg), '-sigfile', str(sig)], capture_output=True, timeout=10)
    for path in (der, pem, msg, sig):
        path.unlink()
    return result.returncode == 0


def successor_lines(s):
    return ['capsule-coordinator-successor-v1', str(s['sequence']), s['previous_public_key'], s['address'],
            s['public_key'], s['signed_at']]


def sign_successor(signer, sequence, previous_public_key, address, public_key, signed_at=None):
    """A successor statement signed by signer (a Key), which need not hold previous_public_key."""
    s = {'sequence': sequence, 'previous_public_key': previous_public_key, 'address': address,
         'public_key': public_key, 'signed_at': signed_at or rfc3339_now()}
    s['signature'] = signer.sign(successor_lines(s))
    return s


def coord_request(port, key, method, path, body=None, host_header=None):
    """One coordination API request with key's client certificate and an optional Host header: (status, body)."""
    raw = socket.create_connection(('127.0.0.1', port), timeout=30)
    tls = key.context('http/1.1').wrap_socket(raw)
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
    connection.sock = tls
    headers = {'Content-Type': 'application/json'}
    if host_header:
        headers['Host'] = host_header
    try:
        connection.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
        response = connection.getresponse()
        data = response.read()
        try:
            return response.status, json.loads(data) if data else None
        except json.JSONDecodeError:
            return response.status, data.decode(errors='replace')
    finally:
        connection.close()


VECTOR = {'seed': 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=', 'previous': 'ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=',
          'public': 'bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=', 'address': 'coord.example.com:7400',
          'signed_at': '2026-10-10T00:00:00Z',
          'signature': 'OyAcMcamcVZu8FBm5nnHoBUQ+qXiiCRP+KJSLFCMQxCnWRw+9mfJnd6is8Pikhz1+ob6Qr/0iZ/mN2kXxunICQ=='}


def presented_key(port, key, host='127.0.0.1'):
    """The Ed25519 public key (Base64) in the certificate a TLS listener presents."""
    raw = socket.create_connection((host, port), timeout=15)
    tls = key.context('http/1.1').wrap_socket(raw)
    try:
        der = tls.getpeercert(binary_form=True)
    finally:
        tls.close()
    index = der.find(SPKI_ED25519)
    assert index >= 0, 'no Ed25519 key in the presented certificate'
    return base64.b64encode(der[index + len(SPKI_ED25519):index + len(SPKI_ED25519) + 32]).decode()


def stun(port, host='127.0.0.1'):
    """One STUN Binding request; returns the XOR-MAPPED-ADDRESS (ip, port) and the local (ip, port)."""
    txid = secrets.token_bytes(12)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(('127.0.0.1', 0))
        udp.settimeout(3)
        local = udp.getsockname()
        for _ in range(3):
            udp.sendto(struct.pack('>HHI', 0x0001, 0, 0x2112A442) + txid, (host, port))
            try:
                data, _ = udp.recvfrom(2048)
            except socket.timeout:
                continue
            kind, length, cookie = struct.unpack('>HHI', data[:8])
            if kind != 0x0101 or cookie != 0x2112A442 or data[8:20] != txid:
                continue
            position = 20
            while position + 4 <= 20 + length:
                attribute, size = struct.unpack('>HH', data[position:position + 4])
                value = data[position + 4:position + 4 + size]
                if attribute == 0x0020 and value[1] == 0x01:
                    xport = struct.unpack('>H', value[2:4])[0] ^ 0x2112
                    xip = bytes(b ^ m for b, m in zip(value[4:8], struct.pack('>I', 0x2112A442)))
                    return (socket.inet_ntoa(xip), xport), local
                position += 4 + size + (-size % 4)
        return None, local


def start_lines(path):
    lines = []
    for line in Path(path).read_text(errors='replace').splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and entry.get('msg') == 'start':
            lines.append(entry)
    return lines


class Port:
    """An object with a port, for helpers that take a coordinator."""

    def __init__(self, port):
        self.port = port


# --- the coordinator ----------------------------------------------------------------------------------------

class Coordinator(OpsCoordinator):
    """`capsule-coord run` with an ops listener and any `--listen` and `--previous-listen` set per run."""

    def __init__(self, binary, state, logdir, name):
        super().__init__(binary, state, logdir, name, ops=f'127.0.0.1:{available_port()}')
        self.previous = {}

    def serve(self, listen, previous=None):
        """Start with --listen 127.0.0.1:listen and --previous-listen SEQ=127.0.0.1:PORT for each item."""
        self.stop()
        self.port = listen
        self.address = f'127.0.0.1:{listen}'
        self.previous = dict(previous or {})
        self.flags = tuple(a for seq, port in sorted(self.previous.items())
                           for a in ('--previous-listen', f'{seq}=127.0.0.1:{port}'))
        identity = self.start()
        for port in self.previous.values():
            deadline = time.monotonic() + 30
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise AssertionError(f'previous listener 127.0.0.1:{port} did not start')
                    time.sleep(0.05)
        return identity

    def successor(self, address, new_key=False):
        args = ['successor', '--address', address] + (['--new-key'] if new_key else [])
        return coord_command(self.binary, self.state, *args)

    def append(self, address, new_key=False):
        result = self.successor(address, new_key)
        need(result.returncode == 0, f'successor --address {address}{" --new-key" if new_key else ""} succeeds',
             result.returncode, result.stderr[-600:])
        return json.loads(result.stdout)

    def last_start(self):
        lines = start_lines(self.runs[-1][0])
        need(len(lines) == 1, 'run writes one start line', lines)
        return lines[0]

    def identity_hosts(self):
        """{sequence: value} of capsule_coord_identity_hosts at scrape time. Q8: whether a sequence with no
        listener or no hosts has a series is not specified; callers treat an absent series as 0."""
        m = scrape(self)
        need(m.types.get('capsule_coord_identity_hosts') == 'gauge', 'capsule_coord_identity_hosts is a gauge',
             m.types.get('capsule_coord_identity_hosts'))
        values = {}
        for labels, value in m.series('capsule_coord_identity_hosts'):
            need(set(labels) == {'sequence'} and re.fullmatch(r'\d+', labels['sequence']),
                 'capsule_coord_identity_hosts has exactly the label sequence, a decimal identity number', labels)
            values[int(labels['sequence'])] = value
        return values


def check_successor_object(s, sequence, previous_key, address, public_key, directory):
    need(isinstance(s, dict) and set(s) == SUCCESSOR_FIELDS,
         'a successor is a strict object with exactly sequence, previous_public_key, address, public_key, '
         'signed_at, and signature', s)
    need(s['sequence'] == sequence and isinstance(s['sequence'], int), 'the successor names its sequence', s, sequence)
    need(s['previous_public_key'] == previous_key, "previous_public_key is the previous identity's key", s,
         previous_key)
    need(s['address'] == address, 'the successor names the new address', s, address)
    need(s['public_key'] == public_key, "the successor names the new identity's key", s, public_key)
    need(isinstance(s['signed_at'], str) and RFC3339.match(s['signed_at']), 'signed_at is an RFC3339 time', s)
    need(verify(previous_key, successor_lines(s), s['signature'], directory),
         'signature is by previous_public_key over capsule-coordinator-successor-v1, sequence, '
         'previous_public_key, address, public_key, signed_at', s)


def chain_valid(chain, start_key, directory):
    """The contract's chain validity, as this suite reads it (used to check the coordinator's own chains)."""
    key, sequence = start_key, None
    for s in chain:
        if set(s) != SUCCESSOR_FIELDS or s['previous_public_key'] != key:
            return False
        if sequence is not None and s['sequence'] != sequence + 1:
            return False
        if not verify(key, successor_lines(s), s['signature'], directory):
            return False
        key, sequence = s['public_key'], s['sequence']
    return True


# --- the coordinator stand-in --------------------------------------------------------------------------------

class StandIn:
    """A TLS listener presenting a key this suite holds, proxying every coordination request to a real
    coordinator with one host's own client key, and replacing `successors` in register, join, and sync
    responses with a chain this suite chooses. Relay connections are closed after the handshake; there is
    no STUN responder."""

    ROUTES = re.compile(r'^/coord/v1/networks(/net_[0-9a-f]{64}/(members|sync))?$')

    def __init__(self, directory, signer, client, upstream):
        self.signer, self.client, self.upstream = signer, client, upstream  # upstream: a callable -> port
        self.port = available_port()
        self.address = f'127.0.0.1:{self.port}'
        self.chain = []
        self.requests = []
        cert = directory / f'standin-{secrets.token_hex(4)}.cert'
        subprocess.run(['openssl', 'req', '-new', '-x509', '-key', str(signer.pem), '-out', str(cert), '-subj',
                        '/CN=capsule-coordinator-standin', '-days', '30'], check=True, capture_output=True, timeout=10)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(cert, signer.pem)
        self.context.set_alpn_protocols(['http/1.1', 'capsule-relay/2', 'capsule-relay/1'])
        # Q5: the stand-in does not request a client certificate (Python cannot accept an unverifiable
        # self-signed one); it proxies with the one host's key it serves.
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', self.port))
        self.listener.listen(64)
        self.stopping = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.stopping:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        try:
            connection.settimeout(30)
            tls = self.context.wrap_socket(connection, server_side=True)
        except (OSError, ssl.SSLError):
            connection.close()
            return
        try:
            if tls.selected_alpn_protocol() not in (None, 'http/1.1'):
                return
            reader = tls.makefile('rb')
            while not self.stopping:
                line = reader.readline(65536)
                if not line or not line.strip():
                    return
                method, path, _ = line.decode('latin-1').split(' ', 2)
                # A client may send the absolute form (https://HOST:PORT/path); forward the path alone.
                path = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*', '', path) or '/'
                headers = {}
                while True:
                    h = reader.readline(65536)
                    if not h or h in (b'\r\n', b'\n'):
                        break
                    name, _, value = h.decode('latin-1').partition(':')
                    headers[name.strip().lower()] = value.strip()
                if 'chunked' in headers.get('transfer-encoding', '').lower():
                    body = b''
                    while True:
                        size = int(reader.readline(1024).split(b';')[0].strip() or b'0', 16)
                        if size == 0:
                            while reader.readline(65536) not in (b'\r\n', b'\n', b''):
                                pass
                            break
                        body += reader.read(size)
                        reader.readline(16)
                else:
                    body = reader.read(int(headers.get('content-length') or 0))
                status, payload = self._forward(method, path, body)
                self.requests.append((method, path, status))
                tls.sendall(f'HTTP/1.1 {status} {http.client.responses.get(status, "Status")}\r\n'
                            f'Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n'.encode()
                            + payload)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _forward(self, method, path, body):
        try:
            raw = socket.create_connection(('127.0.0.1', self.upstream()), timeout=10)
            tls = self.client.context('http/1.1').wrap_socket(raw)
            connection = http.client.HTTPConnection('127.0.0.1', timeout=10)
            connection.sock = tls
            try:
                connection.request(method, path, body or None, {'Content-Type': 'application/json'})
                response = connection.getresponse()
                status, data = response.status, response.read()
            finally:
                connection.close()
        except (OSError, http.client.HTTPException):
            return 502, b'{"code": "unavailable", "error": "stand-in upstream unreachable"}'
        if method == 'POST' and self.ROUTES.match(path.split('?')[0]) and 200 <= status < 300:
            try:
                value = json.loads(data)
            except json.JSONDecodeError:
                value = None
            if isinstance(value, dict):
                value['successors'] = self.chain
                data = json.dumps(value).encode()
        return status, data

    def close(self):
        self.stopping = True
        try:
            self.listener.close()
        except OSError:
            pass


# --- coordinator-only sections ---------------------------------------------------------------------------------

class CoordinatorChecks:
    def __init__(self, suite):
        self.suite = suite
        self.root = suite.root / 'coordinator'
        self.root.mkdir()
        self.keys = suite.keys

    def check_vector(self):
        """The contract's successor test vector, reproduced through OpenSSL (a self-check of this suite's
        statement encoding, which the stand-in relies on)."""
        signer = Key(self.keys, base64.b64decode(VECTOR['seed']))
        need(signer.b64 == VECTOR['previous'], 'the vector seed derives the previous public key', signer.b64)
        s = sign_successor(signer, 1, VECTOR['previous'], VECTOR['address'], VECTOR['public'], VECTOR['signed_at'])
        need(s['signature'] == VECTOR['signature'], 'the successor test vector signature', s['signature'])
        need(verify(VECTOR['previous'], successor_lines(s), VECTOR['signature'], self.keys),
             'the successor test vector verifies')
        return 'reproduced'

    def check_successor_command(self):
        s = self.suite
        # A state without a database.
        for name, make in (('missing', False), ('empty', True)):
            empty = self.root / f'no-db-{name}'
            if make:
                empty.mkdir(mode=0o700)
            result = coord_command(s.args.coord, empty, 'successor', '--address', '127.0.0.1:7443')
            need(result.returncode == 1, f'successor on a state without a database exits 1 ({name} directory)',
                 result.returncode, result.stdout[-300:], result.stderr[-300:])
            need(not (empty / 'coord.db').exists(), 'successor on a state without a database creates none')
        state = self.root / 'state-a'
        c = s.coordinator('cmd', state)
        c.serve(available_port())
        info = c.info()
        need(info.get('identities') == [{'sequence': 0, 'id': info['id'], 'public_key': info['public_key'],
                                         'address': None}],
             'info gains identities, with identity 0 (the existing key) and a null address', info)
        k0 = info['public_key']
        need(info['id'] == coord_id(k0), 'the coordinator ID derives from its key', info)
        # Refused while running: the state lock.
        for args in ((f'127.0.0.1:{available_port()}', False), (f'127.0.0.1:{available_port()}', True)):
            result = c.successor(*args)
            need(result.returncode == 1 and 'coordinator is running' in result.stderr,
                 'successor exits 1 with "coordinator is running" while the coordinator runs', args,
                 result.returncode, result.stderr[-400:])
        need(c.info()['identities'] == info['identities'], 'a refused successor appends nothing', c.info())
        c.stop()

        # Invalid addresses append nothing. Q2: the exit status is not specified; the suite requires nonzero.
        for address in ('', 'nope', '127.0.0.1', '127.0.0.1:', ':7443', '127.0.0.1:abc', '127.0.0.1:65536',
                        'http://127.0.0.1:7443', 'bad host:7443', '[::1]', '127.0.0.1:7443/x', 'a/b:7443'):
            for new_key in (False, True):
                result = c.successor(address, new_key)
                need(result.returncode != 0, 'an invalid --address is refused', address, new_key, result.returncode,
                     result.stdout[-300:])
        need(c.info()['identities'] == info['identities'], 'invalid addresses append nothing', c.info())

        # Valid appends.
        directory = self.keys
        expected = [{'sequence': 0, 'id': info['id'], 'public_key': k0, 'address': None}]
        chain = []
        latest_key = k0
        for index, (address, new_key) in enumerate((
                ('coord-successor.example.test:7443', False),   # DNS name, same key
                ('coord-successor.example.test:7443', True),    # same address, new key
                ('[::1]:7443', False),                          # IPv6 literal, same key
                ('127.0.0.1:7443', False)), start=1):           # IPv4 literal, same key
            out = c.append(address, new_key)
            need(set(out) == {'sequence', 'id', 'public_key', 'address', 'successor'},
                 'successor prints {sequence, id, public_key, address, successor}', out)
            need(out['sequence'] == index, 'identities are numbered in order', out, index)
            need(out['address'] == address, 'the printed address is the new address', out)
            need(canonical_key(out['public_key']) and out['id'] == coord_id(out['public_key']),
                 'the printed id derives from the printed key', out)
            if new_key:
                need(out['public_key'] != latest_key, '--new-key generates a key', out, latest_key)
            else:
                need(out['public_key'] == latest_key, 'without --new-key the new identity keeps the latest key', out,
                     latest_key)
            check_successor_object(out['successor'], index, latest_key, address, out['public_key'], directory)
            chain.append(out['successor'])
            latest_key = out['public_key']
            expected.append({'sequence': index, 'id': out['id'], 'public_key': out['public_key'], 'address': address})
            if index == 1:
                # The latest address without --new-key: nothing changes.
                result = c.successor(address)
                need(result.returncode == 1 and 'nothing changes' in result.stderr,
                     'an address equal to the latest identity\'s exits 1 with "nothing changes"', result.returncode,
                     result.stderr[-400:])
        result = c.successor('127.0.0.1:7443')
        need(result.returncode == 1 and 'nothing changes' in result.stderr,
             'an address equal to the latest identity\'s exits 1 with "nothing changes" (after a key change)',
             result.returncode, result.stderr[-400:])
        need(chain_valid(chain, k0, directory), 'the printed successors form a valid chain from identity 0', chain)
        info = c.info()
        need(info.get('identities') == expected, 'info.identities lists every identity in order', info.get('identities'),
             expected)
        need(info['public_key'] == latest_key and info['id'] == coord_id(latest_key),
             "info's id and public_key are the latest identity's", info)
        with sqlite3.connect(f'file:{state / "coord.db"}?mode=ro', uri=True) as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
        need(version == 6, 'the coordinator database moves to version 6', version)
        return f'{len(expected)} identities'

    def check_serving(self):
        s = self.suite
        directory = self.keys
        state = self.root / 'state-b'
        c = s.coordinator('serve', state)
        p0, p2, latest = available_port(), available_port(), available_port()
        info0 = c.serve(available_port())
        k0 = info0['public_key']
        start = c.last_start()
        need(start.get('previous_listen') == [], 'the start line gains previous_listen, empty without the flag', start)
        c.stop()
        s1 = c.append('coord-successor.example.test:7443')                 # 1: same key, a name
        s2 = c.append(f'127.0.0.1:{p2}', new_key=True)                      # 2: new key
        s3 = c.append(f'127.0.0.1:{latest}')                                # 3: same key as 2, new address
        k2 = s2['public_key']
        chain = [s1['successor'], s2['successor'], s3['successor']]

        # Refusals: the latest, a later, a nonexistent, and a negative sequence.
        for value in ('3', '4', '9', '-1'):
            port = available_port()
            result = subprocess.run([c.binary, '--state', str(state), 'run', '--listen', f'127.0.0.1:{latest}',
                                     '--previous-listen', f'0=127.0.0.1:{p0}', '--previous-listen',
                                     f'{value}=127.0.0.1:{port}'], capture_output=True, text=True, timeout=60)
            need(result.returncode == 2, f'--previous-listen {value}=... (not an earlier identity) exits 2',
                 result.returncode, result.stderr[-500:])
            need('"start"' not in result.stderr, 'the refusal happens before listening (no start line)',
                 result.stderr[-500:])

        # Serving three identities.
        c.serve(latest, {0: p0, 2: p2})
        start = c.last_start()
        previous = start.get('previous_listen')
        # Q4: the order of previous_listen is not specified; compared by sequence.
        need(isinstance(previous, list) and all(isinstance(e, dict) and set(e) == {'sequence', 'listen'}
                                                for e in previous)
             and sorted(previous, key=lambda e: e['sequence']) == [
                 {'sequence': 0, 'listen': f'127.0.0.1:{p0}'}, {'sequence': 2, 'listen': f'127.0.0.1:{p2}'}],
             'the start line lists previous_listen as [{sequence, listen}]', start)
        status, _, body = ops_request(c.ops_host, c.ops_port, 'GET', '/healthz')
        need(status == 200 and json.loads(body).get('id') == coord_id(k2), "/healthz reports the latest identity's id",
             status, body, coord_id(k2))
        probe = Key(directory)
        for port, key, what in ((latest, k2, 'the latest listener'), (p0, k0, "identity 0's listener"),
                                (p2, k2, "identity 2's listener")):
            need(presented_key(port, probe) == key, f'{what} presents its identity\'s key', port)
        for port in (latest, p0, p2):
            mapped, local = stun(port)
            need(mapped == local, f'each listener answers STUN on its UDP port ({port})', mapped, local)

        # successors on register, join, and sync; one database.
        ra, rb, rc = Key(directory), Key(directory), Key(directory)
        net = RawNetwork(directory, 'successor-raw')
        body = {'name': net.name, 'root_public_key': net.root.b64, 'membership': net.membership(ra, 'founder'),
                'address': '', 'candidates': []}
        status, out = tls_request(latest, ra, 'POST', '/coord/v1/networks', body)
        need(status == 201 and out.get('successors') == [], 'register on the latest listener: successors []', status,
             out)
        status, out = tls_request(p0, rb, 'POST', f'/coord/v1/networks/{net.id}/members',
                                  {'membership': net.membership(rb, 'b'), 'address': '', 'candidates': []})
        need(status == 201 and out.get('successors') == chain,
             "join on identity 0's listener: successors is the chain from identity 0 to the latest", status, out)
        need({m['host_id'] for m in out['members']} == {ra.host_id, rb.host_id},
             'all listeners share one database', out.get('members'))
        status, out = tls_request(p0, ra, 'POST', f'/coord/v1/networks/{net.id}/sync', {'address': '', 'candidates': []})
        need(status == 200 and out.get('successors') == chain, "sync on identity 0's listener: the chain from 0", status,
             out)
        status, out = tls_request(latest, rc, 'POST', f'/coord/v1/networks/{net.id}/members',
                                  {'membership': net.membership(rc, 'c'), 'address': '', 'candidates': []})
        need(status == 201 and out.get('successors') == [], 'join on the latest listener: successors []', status, out)
        status, out = tls_request(p2, rb, 'POST', f'/coord/v1/networks/{net.id}/sync', {'address': '', 'candidates': []})
        need(status == 200 and out.get('successors') == chain[2:],
             "sync on identity 2's listener: the chain from identity 2 (one successor)", status, out)
        status, out = tls_request(latest, rc, 'POST', f'/coord/v1/networks/{net.id}/sync',
                                  {'address': '', 'candidates': []})
        need(status == 200 and out.get('successors') == [], 'sync on the latest listener: successors []', status, out)
        # The identity a request reached: among the identities with the listener's key, the one whose address is
        # the Host header, or else the earliest.
        for port, key, host, want, what in (
                (latest, rc, f'127.0.0.1:{p2}', chain[2:], "the latest listener with identity 2's address as Host"),
                (latest, rc, 'unknown.example.test:1', chain[2:],
                 'the latest listener with an unknown Host (the earliest identity with its key, 2)'),
                (p0, rb, 'coord-successor.example.test:7443', chain[1:],
                 "identity 0's listener with identity 1's address (same key) as Host"),
                (p2, rb, f'127.0.0.1:{latest}', [], "identity 2's listener with the latest identity's address as Host")):
            status, out = coord_request(port, key, 'POST', f'/coord/v1/networks/{net.id}/sync',
                                        {'address': '', 'candidates': []}, host_header=host)
            need(status == 200 and out.get('successors') == want, f'sync on {what}: the chain from the identity '
                 'reached', status, out, [w['sequence'] for w in want])
        net2 = RawNetwork(directory, 'successor-raw-2')
        rd = Key(directory)
        status, out = tls_request(p2, rd, 'POST', '/coord/v1/networks',
                                  {'name': net2.name, 'root_public_key': net2.root.b64,
                                   'membership': net2.membership(rd, 'founder'), 'address': '', 'candidates': []})
        need(status == 201 and out.get('successors') == chain[2:],
             "register on identity 2's listener: the chain from identity 2", status, out)

        # One relay across listeners: rb through identity 0, rc through identity 2.
        time.sleep(5.5)  # the relay's membership cache refreshes at least every 5 seconds
        relay_b = RawRelay(Port(p0), rb.seed, directory, (V2,))
        relay_c = RawRelay(Port(p2), rc.seed, directory, (V2,))
        s.raws += [relay_b, relay_c]
        payload = b'successor-relay-' + secrets.token_bytes(16)
        received = []

        def delivered():
            relay_b.connection.sendall(struct.pack('>BH', SEND, 32 + len(payload)) + rc.raw_id + payload)
            time.sleep(0.5)
            with relay_c.lock:
                received[:] = [p for _, kind, p in relay_c.frames if kind == RECEIVE]
            return any(p == rb.raw_id + payload for p in received)
        eventually(delivered, 30, 'hosts connected through different identities relay to each other (one relay)',
                   lambda: (relay_b.kinds(), relay_c.kinds(), relay_b.open, relay_c.open))

        # identity_hosts: 0 = {ra, rb}, 2 = {rb (sync), rc (relay), rd}, 3 = {ra, rc}; 1 has no listener.
        want = {0: 2, 2: 3, 3: 2}
        values = {}

        def counted():
            values.update(c.identity_hosts())
            return all(values.get(k, 0) == v for k, v in want.items()) and values.get(1, 0) == 0
        eventually(counted, 30, 'capsule_coord_identity_hosts{sequence} counts distinct hosts per listener',
                   lambda: (values, want))
        for relay in (relay_b, relay_c):
            relay.close()
        c.stop()
        return f'identity_hosts {dict(sorted(values.items()))}'


# --- per pairing ---------------------------------------------------------------------------------------------

class Pairing:
    def __init__(self, suite, creator, joiner):
        self.suite = suite
        self.label = f'{creator}/{joiner}'
        self.x, self.y = suite.binaries[creator], suite.binaries[joiner]
        self.root = suite.root / f'pairing-{creator}-{joiner}'
        self.root.mkdir()
        self.keys = suite.keys
        self.hosts, self.ids, self.agents, self.grants = {}, {}, {}, {}
        self.bound = 2 * INTERVAL + suite.args.slack
        self.timings = {}

    # helpers

    def host(self, name, binary):
        h = OpsHost(binary, self.root / name, self.root / f'user-{name}')
        h.daemon_args = ('--peer-listen', f'0.0.0.0:{h.port}', '--coordination-interval', str(INTERVAL))
        self.hosts[name] = h
        self.suite.all_hosts.append(h)
        return h

    def start(self, name, interval=None):
        h = self.hosts[name]
        if interval is not None:
            h.daemon_args = (*h.daemon_args[:2], '--coordination-interval', str(interval))
        identity = h.start()
        self.ids[name] = identity['id']
        return identity

    def record(self, name, net=None):
        status, body = self.hosts[name].call('GET', '/v1/networks')
        assert status == 200, (status, body)
        return {n['id']: n for n in body}.get(net or self.net)

    def members(self, name, net=None):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{net or self.net}/members')
        assert status == 200, (status, body)
        return {m['host_id'] for m in body}

    def pinned(self, name, address, key, net=None, error_null=True):
        r = self.record(name, net)
        return (r is not None and r.get('coordinator_address') == address and r.get('coordinator_public_key') == key
                and 'coordinator_pending' in r and r['coordinator_pending'] is None
                and (not error_null or r.get('last_sync_error') is None))

    def await_switch(self, names, address, key, rule, since=None, net=None):
        since = since or time.monotonic()
        for name in names:
            eventually(lambda: self.pinned(name, address, key, net), self.bound - (time.monotonic() - since),
                       f'{rule}: {name} pins {address} with coordinator_pending null and no sync error',
                       lambda: self.record(name, net))
            self.timings.setdefault(rule, {})[name] = round(time.monotonic() - since, 1)

    def invite(self, label, inviter='alice'):
        return self.hosts[inviter].cli('invite', label, '--network', self.net)['token']

    def join(self, name, token):
        out = self.hosts[name].cli('join', token)
        need(out.get('id') == self.net, f'{name} joins', out)
        return out

    def raw_member(self, port, label):
        """A raw host key joined with a host-only invite from alice, through the listener on port."""
        token = self.hosts['alice'].cli('network', 'invite', '--network', self.net, '--member', label, '--expires-at',
                                        timestamp(600), '--host-only')['token']
        key = Key(self.keys)
        status, out = tls_request(port, key, 'POST', f'/coord/v1/networks/{self.net}/members',
                                  {'membership': token_membership(token, key, self.keys), 'address': '',
                                   'candidates': []})
        need(status == 201, f'a raw member joins ({label})', status, out)
        return key

    def agent(self, name):
        if name not in self.agents:
            self.agents[name] = self.hosts[name].cli('agent', 'register', '--name', 'succ', '--owner', name)
        return self.agents[name]

    def send(self, sender, receiver, timeout=120):
        """A connected-only message, retried with the same request ID until accepted."""
        key = (receiver, sender)
        if key not in self.grants:
            self.grants[key] = self.hosts[receiver].grant({'id': self.ids[sender]}, self.agent(receiver), allow=False)
        rid = request_id()
        s = self.hosts[sender]
        out = s.cli('message', 'send', '--peer', self.ids[receiver], '--grant', self.grants[key]['id'], '--agent',
                    self.agent(receiver)['id'], '--deadline', timestamp(), '--content',
                    f'successor {sender}->{receiver} {secrets.token_hex(4)}', '--request', rid)
        deadline = time.monotonic() + timeout
        while out['state'] != 'accepted' and time.monotonic() < deadline:
            time.sleep(1)
            out = s.cli('message', 'retry', '--peer', self.ids[receiver], rid)
        need(out['state'] == 'accepted', f'a connected-only message {sender}→{receiver} is accepted', out)

    # phases

    def setup(self):
        s = self.suite
        self.coord = s.coordinator(f'c-{self.label.replace("/", "-")}', self.root / 'coord')
        self.p = {i: available_port() for i in range(4)}
        self.p['other'] = available_port()
        identity = self.coord.serve(self.p[0])
        self.k = {0: identity['public_key']}
        self.addr = {i: f'127.0.0.1:{port}' for i, port in self.p.items()}
        # Identity 1 is the runbook's address change: a new name for the same listener (localhost resolves to
        # 127.0.0.1 only here), so one listener serves both names and the Host header tells them apart.
        self.addr[1] = f'localhost:{self.p[0]}'
        for name, binary in (('alice', self.x), ('bob', self.y), ('carol', self.y), ('dave', self.y),
                             ('erin', self.y), ('frank', self.x)):
            self.host(name, binary)
        for name in ('alice', 'bob', 'carol', 'frank'):
            self.start(name)
        created = self.hosts['alice'].cli('network', 'create', 'successors', '--as', 'alice', '--coordinator',
                                          self.addr[0], '--coordinator-key', self.k[0])
        self.net = created['id']
        for name in ('bob', 'carol', 'frank'):
            self.join(name, self.invite(name))
        everyone = {self.ids[n] for n in ('alice', 'bob', 'carol', 'frank')}
        for name in ('alice', 'bob', 'carol', 'frank'):
            eventually(lambda: everyone <= self.members(name), 90, f'{name} sees every member')
            r = self.record(name)
            need('coordinator_pending' in r and r['coordinator_pending'] is None,
                 'the network record gains coordinator_pending, null when nothing is pending', r)
            listed = {n['id']: n for n in self.hosts[name].cli('network', 'list')}.get(self.net)
            need(listed is not None and 'coordinator_pending' in listed and listed['coordinator_pending'] is None,
                 'network list shows coordinator_pending, null when nothing is pending', listed)
        # frank stays stopped through identities 1 and 2, pinned to identity 0.
        self.hosts['frank'].stop()
        return f'alice and frank run {self.suite.name_of[self.x]}; bob, carol, dave, erin run {self.suite.name_of[self.y]}'

    def address_change(self):
        c = self.coord
        c.stop()
        out = c.append(self.addr[1])
        need(out['sequence'] == 1 and out['public_key'] == self.k[0], 'an address change keeps the key', out)
        self.k[1] = self.k[0]
        self.s1 = out['successor']
        # The runbook: point the new name at the same machine and restart; one listener serves both names.
        c.serve(self.p[0])
        since = time.monotonic()
        self.await_switch(['alice', 'bob'], self.addr[1], self.k[0], 'address change: hosts switch within two sync '
                          'intervals', since)
        self.send('alice', 'bob')
        self.send('bob', 'alice')

        # Relay: a raw member; datagrams to alice and bob are forwarded (no unreachable), while those to frank (a
        # stopped member) are answered unreachable.
        raw = self.raw_member(self.p[0], 'relay-check')
        time.sleep(5.5)
        relay = RawRelay(c, raw.seed, self.keys, (V2,))
        self.suite.raws.append(relay)
        verdict = {}

        def answered(name):
            target = bytes.fromhex(self.ids[name][5:])
            mark = time.monotonic()
            relay.connection.sendall(struct.pack('>BH', SEND, 32 + 40) + target + secrets.token_bytes(40))
            time.sleep(2.5)
            with relay.lock:
                return any(kind == UNREACHABLE and p == target and t >= mark for t, kind, p in relay.frames)

        def relay_state():
            verdict.update({n: answered(n) for n in ('alice', 'bob', 'frank')})
            return verdict == {'alice': False, 'bob': False, 'frank': True}
        eventually(relay_state, 60, "hosts' relay connections move to the new address (a stopped member is "
                   'unreachable, running hosts are not)', lambda: verdict)

        # Change notifications: bob's interval sync is far off, so only a changed frame explains a prompt update.
        self.hosts['bob'].stop()
        self.start('bob', NOTIFY_INTERVAL)
        eventually(lambda: self.pinned('bob', self.addr[1], self.k[0]), self.bound, 'bob keeps the new pin on restart')
        time.sleep(3)  # bob's relay connection to the new address
        with relay.lock:
            before = len([1 for _, kind, _ in relay.frames if kind == CHANGED])
        newcomer = self.raw_member(self.p[0], 'notify-check')
        took = eventually(lambda: newcomer.host_id in self.members('bob'), 10,
                          'change notifications keep working: bob learns of a join without an interval sync',
                          lambda: sorted(self.members('bob')))
        with relay.lock:
            after = len([1 for _, kind, _ in relay.frames if kind == CHANGED])
        need(after > before, 'the coordinator sends changed', before, after)
        relay.close()
        self.hosts['bob'].stop()
        self.start('bob', INTERVAL)
        return f'switch times {self.timings.get("address change: hosts switch within two sync intervals")}; ' \
               f'notified in {took:.1f}s'

    def key_change(self):
        c = self.coord
        token_before = self.invite('dave')
        self.hosts['carol'].stop()
        c.stop()
        out = c.append(self.addr[2], new_key=True)
        need(out['sequence'] == 2 and out['public_key'] != self.k[1], 'a key change has a new key', out)
        self.k[2] = out['public_key']
        self.s2 = out['successor']
        c.serve(self.p[2], {1: self.p[0]})
        since = time.monotonic()
        self.await_switch(['alice', 'bob'], self.addr[2], self.k[2], 'key change: running hosts switch', since)
        since = time.monotonic()
        self.start('carol')
        self.await_switch(['carol'], self.addr[2], self.k[2], 'key change: a host stopped during the change follows '
                          'on restart', since)
        # A join with an invite issued before the change names identity 1.
        _, fields = decode_token(token_before)
        need(fields['coordinator_address'] == self.addr[1] and fields['coordinator_public_key'] == self.k[1],
             'an invite issued before the change carries the then-pinned coordinator', fields)
        self.start('dave')
        since = time.monotonic()
        self.join('dave', token_before)
        self.await_switch(['dave'], self.addr[2], self.k[2], 'key change: a join with an invite issued before the '
                          'change ends pinned to the new identity', since)
        token_after = self.invite('erin')
        _, fields = decode_token(token_after)
        need(fields['coordinator_address'] == self.addr[2] and fields['coordinator_public_key'] == self.k[2],
             'invites issued after the change carry the new pin', fields)
        self.start('erin')
        self.join('erin', token_after)
        eventually(lambda: self.pinned('erin', self.addr[2], self.k[2]), self.bound,
                   'a joiner with a post-change invite is pinned to the new identity', lambda: self.record('erin'))
        everyone = {self.ids[n] for n in ('alice', 'bob', 'carol', 'dave', 'erin')}
        for name in ('alice', 'bob', 'carol', 'dave', 'erin'):
            eventually(lambda: everyone <= self.members(name), 60, f'{name} sees every running member')
        self.send('alice', 'dave')
        self.send('dave', 'bob')
        self.send('carol', 'alice')
        return f'switch times {self.timings}'

    def two_successors(self):
        c = self.coord
        # Identities 0 and 1 share a key and a listening address; one previous listener serves both.
        c.serve(self.p[2], {0: self.p[0]})
        start = c.last_start()
        need(start.get('previous_listen') == [{'sequence': 0, 'listen': self.addr[0]}],
             'the start line lists the previous listener', start)
        running = ('alice', 'bob', 'carol', 'dave', 'erin')
        values = {}

        def settled():
            values.clear()
            values.update(c.identity_hosts())
            return values.get(2, 0) == len(running) and values.get(0, 0) == 0 and values.get(1, 0) == 0
        eventually(settled, 30, 'capsule_coord_identity_hosts: every running host on the latest listener, none on '
                   'the old ones', lambda: values)
        seen = set()
        since = time.monotonic()
        self.start('frank')

        def switched():
            r = self.record('frank')
            seen.add(r.get('coordinator_address'))
            return self.pinned('frank', self.addr[2], self.k[2])
        eventually(switched, self.bound, 'frank, pinned to identity 0, follows two successors on restart',
                   lambda: self.record('frank'))
        self.timings['two successors'] = round(time.monotonic() - since, 1)
        need(self.addr[1] not in seen, 'frank never pins the intermediate identity', seen)

        def counted():
            values.clear()
            values.update(c.identity_hosts())
            return values.get(0, 0) == 1 and values.get(2, 0) == len(running) + 1
        eventually(counted, 30, 'capsule_coord_identity_hosts{sequence} counts frank on identity 0 and everyone on 2',
                   lambda: values)
        need(values.get(1, 0) == 0, 'capsule_coord_identity_hosts: no host on identity 1, which has no listener',
             values)
        self.send('frank', 'alice')
        return f'followed in {self.timings["two successors"]}s; identity_hosts {dict(sorted(values.items()))}'

    def unreachable(self):
        c = self.coord
        c.stop()
        out = c.append(self.addr[3], new_key=True)
        self.k[3] = out['public_key']
        pending = {'address': self.addr[3], 'public_key': self.k[3], 'sequence': 3}
        # Q1: --listen elsewhere, so that nothing listens at the new identity's address.
        c.serve(self.p['other'], {2: self.p[2]})
        names = ('alice', 'bob', 'carol', 'dave', 'erin', 'frank')

        def waiting(name):
            r = self.record(name)
            # Q3: the pinned sync that follows succeeds; the suite reads the error as staying until the pending
            # coordinator answers.
            return (r['coordinator_pending'] == pending and r['coordinator_address'] == self.addr[2]
                    and r['coordinator_public_key'] == self.k[2]
                    and (r['last_sync_error'] or '').startswith(f'coordinator successor {self.addr[3]}: '))
        for name in names:
            eventually(lambda: waiting(name), self.bound + 2 * INTERVAL,
                       f'{name} keeps its pin with coordinator_pending set and last_sync_error "coordinator successor ADDRESS: ..."', lambda: self.record(name))
        r = self.record('bob')
        need(set(r['coordinator_pending']) == {'address', 'public_key', 'sequence'},
             'coordinator_pending is {address, public_key, sequence}', r)
        listed = {n['id']: n for n in self.hosts['bob'].cli('network', 'list')}[self.net]
        need(listed['coordinator_pending'] == pending, 'network list shows coordinator_pending', listed)
        # Hosts keep working on their pin.
        self.send('alice', 'bob')
        # The pending entry survives a restart, with the coordinator down so nothing can relearn it.
        c.stop()
        self.hosts['bob'].stop()
        self.start('bob')
        r = self.record('bob')
        need(r['coordinator_pending'] == pending and r['coordinator_address'] == self.addr[2],
             'a pending entry survives restarts', r)
        time.sleep(2 * INTERVAL)
        r = self.record('bob')
        need(r['coordinator_pending'] == pending and r['coordinator_address'] == self.addr[2],
             'a pending entry survives restarts (after failed syncs)', r)
        # The new listener starts.
        c.serve(self.p[3], {2: self.p[2]})
        since = time.monotonic()
        self.await_switch(list(names), self.addr[3], self.k[3], 'unreachable new address: hosts switch once the new '
                          'listener starts', since)
        _, fields = decode_token(self.invite('later'))
        need(fields['coordinator_address'] == self.addr[3] and fields['coordinator_public_key'] == self.k[3],
             'invites carry the pinned coordinator, the new one once switched', fields)
        self.send('bob', 'frank')
        return f'switch times {self.timings.get("unreachable new address: hosts switch once the new listener starts")}'

    def standin(self, name):
        """A network pinned to a stand-in whose key this suite holds: invalid chains, a pending entry, an empty
        chain, and a two-step valid chain (stand-in, second stand-in, real coordinator)."""
        h = self.hosts[name]
        # Every sync below is one this suite asks for: the interval sync is far off.
        h.stop()
        self.start(name, NOTIFY_INTERVAL)
        need(self.coord.running, 'the coordinator runs for the stand-in to proxy to')
        real_key = self.coord.info()['public_key']
        real_address = self.coord.address
        client = Key(self.keys, seed_of(h))
        signer, second = Key(self.keys), Key(self.keys)
        upstream = lambda: self.coord.port  # noqa: E731
        st = StandIn(self.keys, signer, client, upstream)
        st2 = StandIn(self.keys, second, client, upstream)
        self.suite.standins += [st, st2]
        created = h.cli('network', 'create', f'standin-{name}', '--as', name, '--coordinator', st.address,
                        '--coordinator-key', signer.b64)
        net = created['id']

        def sync():
            return h.cli('network', 'sync', net)

        def state():
            return self.record(name, net)
        eventually(lambda: sync()['last_sync_error'] is None and self.pinned(name, st.address, signer.b64, net), 60,
                   f'{name} registers and syncs through the stand-in', state)
        need(any(p == '/coord/v1/networks' for _, p, _ in st.requests), 'the network registered through the stand-in',
             st.requests)
        other, link, extra_key = Key(self.keys), Key(self.keys), Key(self.keys)
        good = sign_successor(signer, 1, signer.b64, real_address, real_key)
        raw_signature = base64.b64decode(good['signature'])
        tampered = dict(good, signature=base64.b64encode(bytes([raw_signature[0] ^ 1]) + raw_signature[1:]).decode())
        variants = {
            'bad signature': [tampered],
            'signed by another key': [sign_successor(other, 1, signer.b64, real_address, real_key)],
            'first previous_public_key is not the pinned key': [sign_successor(other, 1, other.b64, real_address,
                                                                               real_key)],
            'sequence 0': [sign_successor(signer, 0, signer.b64, real_address, real_key)],
            'sequence gap': [sign_successor(signer, 1, signer.b64, '127.0.0.1:9', link.b64),
                             sign_successor(link, 3, link.b64, real_address, real_key)],
            'repeated sequence': [sign_successor(signer, 1, signer.b64, '127.0.0.1:9', link.b64),
                                  sign_successor(link, 1, link.b64, real_address, real_key)],
            'broken link': [sign_successor(signer, 1, signer.b64, '127.0.0.1:9', link.b64),
                            sign_successor(extra_key, 2, extra_key.b64, real_address, real_key)],
            'invalid address': [sign_successor(signer, 1, signer.b64, 'not an address', real_key)],
            'extra field': [dict(good, note='x')],
            'missing field': [{k: v for k, v in good.items() if k != 'signed_at'}],
        }
        raw = self.standin_raw_member(h, net)
        applied = False
        for variant, chain in variants.items():
            st.chain = []
            r = sync()
            need(r['last_sync_error'] is None and r['coordinator_pending'] is None,
                 f'a sync with an empty chain succeeds before {variant}', r)
            st.chain = chain
            r = sync()
            need(r['last_sync_error'] == INVALID and r['coordinator_address'] == st.address
                 and r['coordinator_public_key'] == signer.b64 and r['coordinator_pending'] is None,
                 f'an invalid chain ({variant}) is ignored: the pin stays, coordinator_pending stays null, '
                 f'last_sync_error is "{INVALID}"', r)
            if not applied:
                need(raw.host_id in self.members(name, net),
                     'with an invalid chain the host still applies the map as usual', sorted(self.members(name, net)))
                applied = True
        need(self.record(name, net)['coordinator_address'] == st.address, 'the pin is unchanged after every invalid '
             'chain')

        # A valid chain to an unreachable coordinator becomes pending. Q6: signed_at is not interpreted, so a
        # value that is not a time is accepted.
        dead = f'127.0.0.1:{available_port()}'
        st.chain = [sign_successor(signer, 1, signer.b64, dead, other.b64, signed_at='informational only')]
        r = sync()
        want = {'address': dead, 'public_key': other.b64, 'sequence': 1}
        need(r['coordinator_pending'] == want and r['coordinator_address'] == st.address
             and r['coordinator_public_key'] == signer.b64,
             'a valid chain to an unreachable coordinator becomes pending and the pin stays', r)
        need((r['last_sync_error'] or '').startswith(f'coordinator successor {dead}: '),
             'a failing pending coordinator sets last_sync_error "coordinator successor ADDRESS: ..."', r)
        # An empty chain leaves the pending entry in place.
        st.chain = []
        r = sync()
        need(r['coordinator_pending'] == want and r['coordinator_address'] == st.address,
             'an empty chain leaves a pending entry in place', r)
        # A later valid chain from the pinned key replaces it: to a second stand-in, whose own chain leads to the
        # real coordinator. The second chain is followed on the next sync, not in the same one.
        st.chain = [sign_successor(signer, 1, signer.b64, st2.address, second.b64, signed_at='2099-12-31T23:59:59Z')]
        st2.chain = [sign_successor(second, 2, second.b64, real_address, real_key)]
        r = sync()
        # The switched-to coordinator's chain is recorded as the pending entry in that sync and tried on the next.
        need(r['coordinator_address'] == st2.address and r['coordinator_public_key'] == second.b64
             and r['last_sync_error'] is None,
             'a later valid chain from the pinned key replaces the pending entry, and the host switches '
             '(a suite-signed successor accepted)', r)
        need(r['coordinator_pending'] == {'address': real_address, 'public_key': real_key, 'sequence': 2},
             'a chain served by the coordinator just switched to is recorded as the pending entry in that sync', r)
        need(any(path.endswith(f'/{net}/sync') for _, path, _ in st2.requests), 'the switch synced at the new '
             'coordinator', st2.requests)
        r = sync()
        need(r['coordinator_address'] == real_address and r['coordinator_public_key'] == real_key
             and r['coordinator_pending'] is None and r['last_sync_error'] is None,
             'a chain served by the coordinator just switched to is tried on the next sync', r)
        listed = {n['id']: n for n in h.cli('network', 'list')}[net]
        need(listed['coordinator_address'] == real_address and listed['coordinator_pending'] is None,
             'network list shows the switched pin', listed)
        st.close()
        st2.close()
        return f'{len(variants)} invalid chains ignored; pending, empty chain, and a two-step switch'

    def standin_raw_member(self, h, net):
        """A raw member joined directly on the real coordinator, to see the stand-in's map applied."""
        token = h.cli('network', 'invite', '--network', net, '--member', f'raw-{secrets.token_hex(2)}', '--expires-at',
                      timestamp(600), '--host-only')['token']
        key = Key(self.keys)
        status, out = tls_request(self.coord.port, key, 'POST', f'/coord/v1/networks/{net}/members',
                                  {'membership': token_membership(token, key, self.keys), 'address': '',
                                   'candidates': []})
        need(status == 201, 'a raw member joins the stand-in network on the real coordinator', status, out)
        return key

    def ensure_coordinator(self):
        if not self.coord.running:
            latest = self.coord.info()['identities'][-1]
            port = int(latest['address'].rsplit(':', 1)[1]) if latest['address'] else self.p[0]
            self.coord.serve(port)

    def run(self):
        s = self.suite
        tag = f'{self.label}'
        if not s.section(f'{tag} setup', self.setup):
            return
        for name, phase in (('address change with the same key', self.address_change),
                            ('key change with --previous-listen', self.key_change),
                            ('two successors while stopped', self.two_successors),
                            ('unreachable new address', self.unreachable)):
            if not s.section(f'{tag} {name}', phase):
                break
        for name in ('alice', 'bob'):
            def phase(name=name):
                self.ensure_coordinator()
                for other in ('alice', 'bob'):
                    if self.hosts[other].process is None or self.hosts[other].process.poll() is not None:
                        self.start(other, INTERVAL)
                return self.standin(name)
            s.section(f'{tag} invalid chain via stand-in ({name}, {s.name_of[self.hosts[name].binary]})', phase)
        try:
            stop_all(tuple(self.hosts.values()))
        except Exception as error:
            s.results.append((f'{tag} shutdown', False, repr(error)))
            print(f'FAIL [{tag} shutdown]: {error!r}', flush=True)
        self.coord.stop()


# --- the suite -----------------------------------------------------------------------------------------------

class Suite:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.binaries = {'Go': str(args.go), 'Rust': str(args.rust)}
        self.name_of = {v: k for k, v in self.binaries.items()}
        self.logs = root / 'logs'
        self.logs.mkdir()
        self.keys = root / 'keys'
        self.keys.mkdir()
        self.results = []
        self.coordinators = []
        self.all_hosts = []
        self.raws = []
        self.standins = []

    def section(self, name, function):
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=8)
            self.results.append((name, False, detail))
            print(f'FAIL [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}', flush=True)
        return True

    def coordinator(self, name, state):
        c = Coordinator(self.args.coord, state, self.logs, name)
        self.coordinators.append(c)
        return c

    def run(self):
        checks = CoordinatorChecks(self)
        self.section('successor test vector', checks.check_vector)
        self.section('successor command', checks.check_successor_command)
        self.section('serving', checks.check_serving)
        pairings = [tuple(p.split('/')) for p in self.args.pairing] if self.args.pairing else \
            [('Go', 'Go'), ('Go', 'Rust'), ('Rust', 'Go'), ('Rust', 'Rust')]
        for creator, joiner in pairings:
            Pairing(self, creator, joiner).run()

    def close(self):
        for raw in self.raws:
            raw.close()
        for st in self.standins:
            st.close()
        try:
            stop_all(tuple(self.all_hosts))
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
        for h in self.all_hosts:
            try:
                h.logs.seek(0)
                (directory / f'{h.state.parent.name}-{h.state.name}.log').write_bytes(h.logs.read())
            except (OSError, ValueError):
                pass


def main():
    global INTERVAL
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--coord', type=Path, required=True, help='capsule-coord')
    parser.add_argument('--go', type=Path, required=True, help='Go capsule-host')
    parser.add_argument('--rust', type=Path, required=True, help='Rust capsule-host')
    parser.add_argument('--probe', type=Path, help='capsule-peer-probe (optional; set for shared helpers)')
    parser.add_argument('--pairing', action='append', choices=('Go/Go', 'Go/Rust', 'Rust/Go', 'Rust/Rust'),
                        help='CREATOR/JOINER to run (repeatable); default all four')
    parser.add_argument('--interval', type=int, default=INTERVAL, help='hosts\' --coordination-interval (seconds)')
    parser.add_argument('--slack', type=float, default=SLACK,
                        help='seconds added to "within two sync intervals" for a loaded machine')
    parser.add_argument('--logs', type=Path, help='save coordinator and host logs here when a section fails')
    args = parser.parse_args()
    INTERVAL = args.interval
    args.coord, args.go, args.rust = (p.resolve(strict=True) for p in (args.coord, args.go, args.rust))
    if args.probe:
        set_probe(args.probe.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix='capsule-coord-successor-') as temporary:
        suite = Suite(args, Path(temporary))
        try:
            suite.run()
        except Exception:
            detail = traceback.format_exc(limit=8)
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
