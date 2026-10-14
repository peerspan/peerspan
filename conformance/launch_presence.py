#!/usr/bin/env python3
"""Exercise presence notifications through the coordinator relay (milestone 7 slice 6).

Written from docs/launch-contract.md ("Slice 6: presence notifications" and its Verification list, with the
directory and peer route of slice 4 and the change notifications of slice 5), the relay protocol in
docs/coordination-contract.md, `connected` and `channel` in docs/live-delivery-contract.md, and the leases of
docs/adapter-recovery-contract.md, independently of both implementations. Runs every Go/Rust pairing X/Y with
one Go coordinator per pairing. alice's host a1 (the network's creator, whose presence changes), carol's host
c1, and the stopped key holders w3 and m run X; bob's host b1, dave's host d1 (started without
--peer-listen), erin's version 2 host vh, and the stopped key holders w2, w4, and m2 run Y. Every host's CLI is
its daemon's implementation, every host has its own HOME and XDG_CONFIG_HOME, and every daemon runs with a
30-second coordination interval, so nothing but a notification refreshes a directory within 2 seconds.
Directories are read with `GET /v1/directory`, never the refresh endpoint, so a missing notification is not
masked.

Fixtures (the suite cannot see inside the hosts, so it watches and shapes their traffic):
- **Coordinator front.** The hosts' networks pin a coordinator address and key that belong to a TLS front run
  by this suite. The front identifies each connecting host by the process that owns the TCP connection (its
  `--state`), opens the same connection to the Go coordinator with that host's key, offering exactly the
  protocols the host offered, and serves the host the protocol the coordinator selected. It records, with
  arrival times, the protocols each host offered and every relay frame in both directions, and can inject a
  frame into a host's relay connection or close it. For erin's host it withholds `capsule-relay/3`, so that a
  real daemon runs on a version 2 connection. The coordinator itself is unchanged and stays reachable.
- **Raw relay clients** (TLS with a stopped member's key, as conformance/launch_push.py builds them) connect to
  the coordinator directly, to observe what it forwards and to send `presence` frames of their own: w3
  (team, version 3), w4 (team, version 3), w2 (team, versions 2 and 1), and m and m2 (members only of a
  second network, side, version 3). a1 is in both networks.
- **A UDP delay front** before alice's peer listener: a1 advertises its address (`--advertise`), and the suite
  can delay a1's peer packets towards other hosts, so that one directory query takes a known time.
- Sessions use the real Node adapter (`capsule_ready`, a clean exit, a killed adapter) or raw adapter clients
  (bearer token and instance, as the recovery contract allows) where a lease must be held or dropped exactly.

Sections, per pairing:
- version 3 negotiation: the coordinator selects `capsule-relay/3` when offered and `/2` when only `/2` and
  `/1` are offered; every host offers `/3`, then `/2`, then `/1`, and runs on version 3 (erin's on 2);
- capsule_ready: a session verifying shows `connected: true`, `channel: verified` on every other member within 2
  seconds, including the member without --peer-listen; the peer route agrees; a1 sent `presence` (0x06, the
  network ID) for each of its networks, the coordinator forwarded it (0x06, a1's 32-byte host ID, then the
  network ID) to every other version 3 member, and not back to a1;
- unverified lease: a lease without verification shows `channel: unverified`, `connected: false` within 2
  seconds; once it lapses after its last renewal, `channel: null` within 2 seconds of the lapse;
- only the changed host: a registration on a1 (then on c1) refreshes only that host's entry; the other hosts'
  `refreshed_at` are unchanged;
- receiver ignoring: `presence` injected into bob's relay connection for a network bob is not in, or from a
  host bob does not know as a member, refreshes nothing; one for a1 in the team network refreshes a1's entry;
- one query in flight: with a1's answers delayed, six `presence` frames for a1 within half a second give one
  query and exactly one more after it, not overlapping;
- burst: connects, verifications, a detach, a revocation, and a registration in quick succession end in the
  correct final state on every member within 2 seconds of the last; a1 sends at most one `presence` per network
  per 250 ms and announces the last change; the coordinator forwards at most one per (network, source) per
  connection per 250 ms;
- detach, revocation, registration: each reflected within 2 seconds;
- clean adapter exit and killed adapter: each `connected: false` within 2 seconds of the lease lapsing;
- version 2 host: erin's version 2 connection carries no `presence` either way, and a raw version 2 and version
  1 connection receive none; erin's directory shows a change after `agents --refresh`; a `presence` sent on a
  version 2 connection is not forwarded;
- coordinator forwarding: a member's `presence` forwarded to every other member on version 3 and not echoed;
  none forwarded from a non-member of the network, for a network the sender is not in, or for an unknown
  network (without a reply, the connection kept); forwarding coalesced per 250 ms with the last one delivered;
- restart: a restart of a1's daemon reflected on the others without `--refresh` (its leases did not survive),
  a1 announcing each of its networks on its new relay connection, the same for a relay connection the front
  closes, and the recovered adapter (still verified) shown again.

Needs openssl, capsule-peer-probe, Node with the claude-channel adapter's dependencies installed, and Linux
(/proc, to identify the process behind a connection). Exits non-zero listing every failed section.
"""
import argparse
import base64
from datetime import datetime, timezone
import heapq
import json
import os
from pathlib import Path
import queue
import secrets
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import traceback

from agent_adapter import Channel
from coordination import Coordinator, wait_for
from host_service import UnixHTTPConnection, stop_all
from launch_directory import DirectoryHost
from launch_onboarding import Failure, need, parse_time
from launch_push import seed_of, tls_context
from peer_messaging import fixture_context, set_probe, timestamp, wire

INTERVAL = 30
BOUND = 2.0  # "within 2 seconds"
SLACK = 0.3  # polling period, the front's forwarding, and local API latency
COALESCE = 0.25
JITTER = 0.05
DELAY = 1.3  # how long a1's delayed answers take to reach the other hosts
V1, V2, V3 = 'capsule-relay/1', 'capsule-relay/2', 'capsule-relay/3'
RELAY_PROTOCOLS = (V3, V2, V1)
SEND, RECEIVE, UNREACHABLE, PING, CHANGED, PRESENCE = 1, 2, 3, 4, 5, 6
OBSERVERS = ('b1', 'c1', 'd1')  # running version 3 members other than a1


def raw_id(host_id):
    """A host ID in a frame: the 32 raw bytes the `host_` form spells in hex."""
    return bytes.fromhex(host_id[len('host_'):])


def frame(kind, payload=b''):
    return struct.pack('>BH', kind, len(payload)) + payload


def presence_to_relay(network):
    return frame(PRESENCE, network.encode())


def presence_to_host(source, network):
    return frame(PRESENCE, raw_id(source) + network.encode())


class Framer:
    """Splits a relay byte stream into (kind, payload, raw) frames."""

    def __init__(self):
        self.buffer = b''

    def feed(self, data):
        self.buffer += data
        frames = []
        while len(self.buffer) >= 3:
            kind, size = struct.unpack('>BH', self.buffer[:3])
            if len(self.buffer) < 3 + size:
                break
            frames.append((kind, self.buffer[3:3 + size], self.buffer[:3 + size]))
            self.buffer = self.buffer[3 + size:]
        return frames


def write(sock, data):
    """Write all of data to a non-blocking (TLS) socket."""
    view = memoryview(data)
    while len(view):
        try:
            sent = sock.send(view)
            view = view[sent:]
        except (ssl.SSLWantWriteError, BlockingIOError):
            select.select([], [sock], [], 0.05)
        except ssl.SSLWantReadError:
            select.select([sock], [], [], 0.05)


def offered_protocols(sock, timeout=5):
    """The ALPN protocols in the TLS ClientHello waiting on sock, read without consuming it."""
    deadline = time.monotonic() + timeout
    data = b''
    while time.monotonic() < deadline:
        data = sock.recv(16384, socket.MSG_PEEK)
        if not data:
            return None
        if len(data) >= 5 and len(data) >= 5 + struct.unpack('>H', data[3:5])[0]:
            break
        time.sleep(0.005)
    try:
        if data[0] != 22:
            return None
        hello = data[5:]
        if hello[0] != 1:
            return None
        p = 4 + 2 + 32
        p += 1 + hello[p]
        p += 2 + struct.unpack('>H', hello[p:p + 2])[0]
        p += 1 + hello[p]
        end = p + 2 + struct.unpack('>H', hello[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            kind, size = struct.unpack('>HH', hello[p:p + 4])
            body = hello[p + 4:p + 4 + size]
            if kind == 16:
                names, q = [], 2
                while q < 2 + struct.unpack('>H', body[:2])[0]:
                    names.append(body[q + 1:q + 1 + body[q]].decode())
                    q += 1 + body[q]
                return names
            p += 4 + size
        return []
    except (IndexError, struct.error, UnicodeDecodeError):
        return None


def owner_state(local_port, server_port, candidates=()):
    """The --state directory of the local process that owns the client end of a loopback TCP connection."""
    inode = None
    with open('/proc/net/tcp') as table:
        for line in table.readlines()[1:]:
            parts = line.split()
            if parts[1] == f'0100007F:{local_port:04X}' and parts[2] == f'0100007F:{server_port:04X}':
                inode = parts[9]
    if inode is None:
        return None
    link = f'socket:[{inode}]'
    pids = [str(p) for p in candidates if p] + [p for p in os.listdir('/proc') if p.isdigit()]
    for pid in pids:
        try:
            for fd in os.listdir(f'/proc/{pid}/fd'):
                try:
                    if os.readlink(f'/proc/{pid}/fd/{fd}') == link:
                        argv = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                        if b'--state' in argv:
                            return Path(argv[argv.index(b'--state') + 1].decode()).resolve()
                        return None
                except OSError:
                    continue
        except OSError:
            continue
    return None


def certificate(seed, directory):
    name = secrets.token_hex(4)
    key_der, cert, key = directory / f'{name}.key.der', directory / f'{name}.cert.pem', directory / f'{name}.key.pem'
    key_der.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + seed)
    subprocess.run(['openssl', 'req', '-new', '-x509', '-key', str(key_der), '-keyform', 'DER', '-out', str(cert),
                    '-subj', '/CN=presence-front', '-days', '2'], check=True, capture_output=True, timeout=10)
    subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', str(key_der), '-out', str(key)],
                   check=True, capture_output=True, timeout=10)
    public = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'], check=True,
                            capture_output=True, timeout=10).stdout[-32:]
    return cert, key, base64.b64encode(public).decode()


class Link:
    """One host connection through the front: plain bytes for the coordination API, frames for the relay."""

    def __init__(self, name, offered, protocol, down, up):
        self.name, self.offered, self.protocol, self.down, self.up = name, offered, protocol, down, up
        self.relay = bool(protocol) and protocol.startswith('capsule-relay/')
        self.opened = time.monotonic()
        self.closed_at = None
        self.sent = []  # (time, kind, payload): host → coordinator
        self.delivered = []  # (time, kind, payload): coordinator → host, injected frames included
        self.injected = []  # (time, raw)
        self.injections = queue.Queue()
        self.lock = threading.Lock()
        self.stopping = False
        threading.Thread(target=self.pump, daemon=True).start()

    @property
    def open(self):
        return self.closed_at is None

    def pump(self):
        from_host, from_coord = Framer(), Framer()
        try:
            self.down.setblocking(False)
            self.up.setblocking(False)
            while not self.stopping:
                ready = [s for s in (self.down, self.up) if s.pending()]
                if not ready:
                    ready, _, _ = select.select([self.down, self.up], [], [], 0.02)
                for sock in ready:
                    try:
                        data = sock.recv(65536)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                        continue
                    if not data:
                        return
                    now = time.monotonic()
                    if sock is self.down:
                        if self.relay:
                            with self.lock:
                                self.sent += [(now, kind, payload) for kind, payload, _ in from_host.feed(data)]
                        write(self.up, data)
                    elif self.relay:
                        frames = from_coord.feed(data)
                        with self.lock:
                            self.delivered += [(now, kind, payload) for kind, payload, _ in frames]
                        if frames:
                            write(self.down, b''.join(raw for _, _, raw in frames))
                    else:
                        write(self.down, data)
                while not self.injections.empty():
                    raw, done = self.injections.get()
                    write(self.down, raw)
                    now = time.monotonic()
                    with self.lock:
                        self.injected.append((now, raw))
                        self.delivered.append((now, raw[0], raw[3:]))
                    done.put(now)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            self.closed_at = time.monotonic()
            for sock in (self.down, self.up):
                try:
                    sock.close()
                except OSError:
                    pass

    def inject(self, raw):
        done = queue.Queue()
        self.injections.put((raw, done))
        return done.get(timeout=5)

    def close(self):
        self.stopping = True
        try:
            self.down.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class Front:
    """A TLS front with its own coordinator key, passing each host's connection through to the Go coordinator."""

    def __init__(self, coord, directory):
        self.coord, self.directory = coord, directory
        directory.mkdir()
        self.cert, self.key, self.public_key = certificate(secrets.token_bytes(32), directory)
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(64)
        self.port = self.listener.getsockname()[1]
        self.address = f'127.0.0.1:{self.port}'
        self.hosts = {}  # resolved state directory → (name, host)
        self.downgrade = set()  # host names served without capsule-relay/3
        self.links = []
        self.errors = []
        self.contexts = {}
        self.lock = threading.Lock()
        self.stopping = False
        threading.Thread(target=self.serve, daemon=True).start()

    def add(self, name, host):
        self.hosts[str(Path(host.state).resolve())] = (name, host)

    def context(self, protocol):
        if protocol not in self.contexts:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(self.cert, self.key)
            if protocol:
                context.set_alpn_protocols([protocol])
            self.contexts[protocol] = context
        return self.contexts[protocol]

    def serve(self):
        while not self.stopping:
            try:
                client, address = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.admit, args=(client, address), daemon=True).start()

    def admit(self, client, address):
        up = down = None
        try:
            client.settimeout(10)
            pids = [h.process.pid for _, h in self.hosts.values() if h.process is not None]
            state = owner_state(address[1], self.port, pids)
            if state is None or str(state) not in self.hosts:
                raise OSError(f'unknown client process for port {address[1]} ({state})')
            name, host = self.hosts[str(state)]
            offered = offered_protocols(client)
            if offered is None:
                raise OSError(f'{name}: no TLS ClientHello')
            offer = [p for p in offered if not (name in self.downgrade and p == V3)]
            up = tls_context(seed_of(host), self.directory, offer).wrap_socket(
                socket.create_connection(('127.0.0.1', self.coord.port), timeout=10))
            protocol = up.selected_alpn_protocol()
            down = self.context(protocol).wrap_socket(client, server_side=True)
            link = Link(name, offered, protocol, down, up)
            with self.lock:
                self.links.append(link)
        except Exception as error:  # a refused or failed connection; the host retries as usual
            self.errors.append((time.monotonic(), repr(error)[:300]))
            for sock in (down, up, client):
                try:
                    if sock is not None:
                        sock.close()
                except OSError:
                    pass

    def relay_links(self, name):
        with self.lock:
            return [link for link in self.links if link.name == name and link.relay]

    def current(self, name):
        links = [link for link in self.relay_links(name) if link.open]
        return links[-1] if links else None

    def sent(self, name, since=0.0, kind=PRESENCE):
        found = []
        for link in self.relay_links(name):
            with link.lock:
                found += [(t, p) for t, k, p in link.sent if k == kind and t >= since]
        return sorted(found)

    def delivered(self, name, since=0.0, kind=PRESENCE):
        found = []
        for link in self.relay_links(name):
            with link.lock:
                found += [(t, p) for t, k, p in link.delivered if k == kind and t >= since]
        return sorted(found)

    def stop(self):
        self.stopping = True
        self.listener.close()
        for link in list(self.links):
            link.close()


class UdpDelay:
    """A UDP front for a peer listener; packets from the listener back to its clients wait `delay` seconds."""

    def __init__(self, target_port):
        self.target = ('127.0.0.1', target_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.delay = 0.0
        self.upstreams = {}  # client address → socket towards the listener
        self.clients = {}  # upstream socket → client address
        self.pending = []
        self.sequence = 0
        self.stopping = False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stopping:
            timeout = 0.05
            if self.pending:
                timeout = max(0.0, min(timeout, self.pending[0][0] - time.monotonic()))
            readable, _, _ = select.select([self.sock, *self.clients], [], [], timeout)
            for sock in readable:
                try:
                    data, address = sock.recvfrom(65536)
                except OSError:
                    continue
                if sock is self.sock:
                    upstream = self.upstreams.get(address)
                    if upstream is None:
                        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        upstream.bind(('127.0.0.1', 0))
                        upstream.connect(self.target)
                        self.upstreams[address], self.clients[upstream] = upstream, address
                    try:
                        upstream.send(data)
                    except OSError:
                        pass
                else:
                    self.sequence += 1
                    heapq.heappush(self.pending, (time.monotonic() + self.delay, self.sequence, self.clients[sock],
                                                  data))
            while self.pending and self.pending[0][0] <= time.monotonic():
                _, _, address, data = heapq.heappop(self.pending)
                try:
                    self.sock.sendto(data, address)
                except OSError:
                    pass

    def stop(self):
        self.stopping = True


class Relay:
    """A raw relay connection straight to the coordinator: records frames with arrival times, sends frames from
    its own thread, and pings every 10 seconds."""

    def __init__(self, coord, seed, directory, alpn):
        context = tls_context(seed, directory, alpn)
        self.connection = context.wrap_socket(socket.create_connection(('127.0.0.1', coord.port), timeout=5))
        self.selected = self.connection.selected_alpn_protocol()
        self.frames = []
        self.sent = []
        self.outbox = queue.Queue()
        self.closed_at = None
        self.lock = threading.Lock()
        self.stopping = False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        framer = Framer()
        last_ping = time.monotonic()
        self.connection.settimeout(0.02)
        try:
            while not self.stopping:
                while not self.outbox.empty():
                    raw, done = self.outbox.get()
                    self.connection.sendall(raw)
                    now = time.monotonic()
                    self.sent.append((now, raw))
                    last_ping = now
                    done.put(now)
                if time.monotonic() - last_ping > 10:
                    self.connection.sendall(frame(PING))
                    last_ping = time.monotonic()
                try:
                    chunk = self.connection.recv(65536)
                except (socket.timeout, TimeoutError, ssl.SSLWantReadError):
                    continue
                if not chunk:
                    break
                now = time.monotonic()
                with self.lock:
                    self.frames += [(now, kind, payload) for kind, payload, _ in framer.feed(chunk)]
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.closed_at = time.monotonic()

    @property
    def open(self):
        return self.closed_at is None

    def send(self, raw):
        done = queue.Queue()
        self.outbox.put((raw, done))
        try:
            return done.get(timeout=5)
        except queue.Empty:
            return None

    def received(self, kind=PRESENCE, since=0.0):
        with self.lock:
            return [(t, p) for t, k, p in self.frames if k == kind and t >= since]

    def kinds(self, since=0.0):
        with self.lock:
            return sorted({k for t, k, _ in self.frames if t >= since})

    def close(self):
        self.stopping = True
        try:
            self.connection.close()
        except OSError:
            pass


class RawAdapter:
    """A raw adapter client with one instance; it renews its lease from a thread while `renewing`."""

    def __init__(self, host, credential):
        self.host, self.token, self.adapter = host, credential['token'], credential['adapter']
        self.instance = 'instance_' + secrets.token_hex(32)
        self.renewing = False
        self.last_renewal = None
        self.thread = None

    def request(self, method, path, body=None):
        connection = UnixHTTPConnection(self.host.state / 'adapter.sock', timeout=15)
        try:
            payload = json.dumps(body).encode() if body is not None else None
            connection.request(method, path, payload, {'Authorization': 'Bearer ' + self.token,
                                                       'X-Capsule-Instance': self.instance,
                                                       'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = response.read()
            try:
                return response.status, json.loads(data)
            except json.JSONDecodeError:
                return response.status, data.decode(errors='replace')
        finally:
            connection.close()

    def connect(self):
        status, body = self.request('POST', '/adapter/v1/connect', {
            'adapter_id': self.adapter['id'], 'session_id': self.adapter['session_id'], 'instance_id': self.instance})
        if status == 200:
            self.last_renewal = time.monotonic()
        return status, body

    def ready(self):
        """As the adapter does once the model calls capsule_ready with the matching nonce."""
        return self.request('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})

    def renew(self):
        self.renewing = True

        def loop():
            while self.renewing:
                time.sleep(4)
                if self.renewing:
                    try:
                        self.connect()
                    except OSError:
                        pass
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.renewing = False
        if self.thread is not None:
            self.thread.join(timeout=6)


def race(observers, until):
    """Poll each predicate concurrently until `until` (monotonic); {name: monotonic time it first held, or None}."""
    results = {}

    def watch(name, predicate):
        while time.monotonic() < until:
            try:
                if predicate():
                    results[name] = time.monotonic()
                    return
            except Exception:  # a host briefly busy; keep polling
                pass
            time.sleep(0.05)
        results[name] = None
    threads = [threading.Thread(target=watch, args=item, daemon=True) for item in observers.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


class PresenceHost(DirectoryHost):
    """A host with a 30-second coordination interval, with or without a peer listener, optionally advertising
    another address for it."""

    def __init__(self, daemon, cli, state, home, listen=True, advertise=None):
        super().__init__(daemon, cli, state, home)
        self.listen = listen
        flags = ('--peer-listen', self.address) if listen else ()
        if advertise:
            flags += ('--advertise', advertise)
        self.daemon_args = flags + ('--coordination-interval', str(INTERVAL))


class Pairing:
    def __init__(self, label, x, y, coord_binary, node, root):
        self.label, self.x, self.y, self.node, self.root = label, x, y, node, root
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.hosts = {}
        self.raws = []
        self.channels = []
        self.adapters = []
        self.results = []
        self.notes = []
        self.front = self.delay = None
        self.script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'
        self.certs = root / 'certs'
        self.certs.mkdir()

    # --- infrastructure -----------------------------------------------------------------------------------

    def host(self, name, binary, listen=True, advertise=None):
        h = PresenceHost(binary, binary, self.root / name, self.root / f'user-{name}', listen, advertise)
        self.hosts[name] = h
        self.front.add(name, h)
        return h

    def section(self, name, function):
        started = time.monotonic()
        self.notes = []
        try:
            notes = function() or ''
        except Exception as error:  # report and continue with the next section
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=5)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        notes = '; '.join([*self.notes, notes] if notes else self.notes)
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}',
              flush=True)
        return True

    def relay(self, name, alpn):
        r = Relay(self.coord, seed_of(self.hosts[name]), self.certs, alpn)
        self.raws.append(r)
        return r

    def members(self, name, network=None):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{network or self.net}/members')
        assert status == 200, (status, body)
        return {m['host_id']: m for m in body}

    def policy_version(self, name, person):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{self.net}/policy?person={person}')
        return body['version'] if status == 200 else 0

    def directory(self, name, network=None):
        status, body = self.hosts[name].directory(network or self.net)
        assert status == 200 and isinstance(body, dict), (name, status, body)
        return body

    def state(self, name, agent_id):
        """(connected, channel) of an agent in a host's directory, or None when it is not listed."""
        for entry in self.directory(name)['agents']:
            if entry['agent_id'] == agent_id:
                return entry['connected'], entry.get('channel')
        return None

    def refreshed(self, name):
        """{host_id: refreshed_at} of a host's directory entries."""
        return {h['host_id']: h['refreshed_at'] for h in self.directory(name)['hosts']}

    def register(self, name, agent, owner):
        return self.hosts[name].cli('agent', 'register', '--name', agent, '--owner', owner)

    def setup(self, agent, name='a1', expires=3600):
        status, body = self.hosts[name].call('POST', '/v1/adapters/setup', {
            'agent_id': agent['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
            'expires_at': timestamp(expires)})
        need(status == 201 and isinstance(body, dict) and body.get('credential', {}).get('token'),
             'POST /v1/adapters/setup', status, body)
        return body['credential']

    def adapter(self, agent, verify=True, renew=True):
        """A raw adapter for a new session of agent on a1: connected, verified if asked, renewing."""
        raw = RawAdapter(self.hosts['a1'], self.setup(agent))
        self.adapters.append(raw)
        status, body = raw.connect()
        need(status == 200, 'POST /adapter/v1/connect takes a lease', status, body)
        if verify:
            status, body = raw.ready()
            need(200 <= status < 300, 'POST /adapter/v1/ready verifies the channel', status, body)
        if renew:
            raw.renew()
        return raw

    def lease_end(self, adapter_id):
        """The monotonic time at which an adapter's lease lapses, from the owner's connection object."""
        status, body = self.hosts['a1'].call('GET', f'/v1/adapters/{adapter_id}/connection')
        need(status == 200 and isinstance(body, dict) and body.get('lease_expires_at'),
             'the connection object reports the lease time', status, body)
        value = body['lease_expires_at']
        # A whole-second time may have dropped up to a second of the lease.
        extra = 0.0 if '.' in value else 1.0
        return time.monotonic() + (parse_time(value) - datetime.now(timezone.utc)).total_seconds() + extra

    def reflected(self, what, predicate, origin, observers=OBSERVERS, bound=BOUND):
        """Every observer's directory satisfies predicate(name) within `bound` seconds of origin (monotonic)."""
        times = race({n: (lambda n=n: predicate(n)) for n in observers}, until=origin + bound + SLACK + 3)
        seconds = {n: (round(t - origin, 2) if t is not None else None) for n, t in times.items()}
        late = {n: s for n, s in seconds.items() if s is None or s > bound + SLACK}
        need(not late, f'{what}: reflected in GET /v1/directory on every other member within {bound:g} seconds '
             '(seconds per host; None: not within the wait)', seconds)
        self.notes.append(f"{what} {max(seconds.values()):.2f}s")
        return seconds

    def wait_state(self, agent, expected, observers=OBSERVERS, timeout=10, what='state'):
        """A precondition: every observer shows (connected, channel) for agent within timeout seconds."""
        try:
            wait_for(lambda: all(self.state(n, agent['id']) == expected for n in observers), timeout=timeout,
                     message=what)
        except AssertionError:
            need(False, f'{what}: a presence change on a1 shows {expected} for {agent["name"]} on every other '
                 f'member (precondition, {timeout}s; host: shown)', {n: self.state(n, agent['id']) for n in observers})

    def announced(self, mark, what, networks=None):
        """a1 sent presence (0x06, a network ID as UTF-8) for each network after mark."""
        networks = networks or (self.net, self.side)
        sent = self.front.sent('a1', mark)
        payloads = {p for _, p in sent}
        missing = [n for n in networks if n.encode() not in payloads]
        need(not missing, f'{what}: after a presence change in a network, the host sends presence (0x06, the network '
             'ID as UTF-8) for that network on its relay connection, for each network the change touches '
             '(networks missing)', missing, sorted(payloads))
        stray = [p for p in payloads if p not in {self.net.encode(), self.side.encode()}]
        need(not stray, f'{what}: a host sends presence only with one of its network IDs as the payload', stray)
        return sent

    def forwarded(self, mark, source, network, receivers, what):
        """The coordinator forwarded presence (source host ID, then the network ID) to every receiver."""
        payload = raw_id(self.ids[source]) + network.encode()

        def arrived():
            return all(any(p == payload for _, p in self.front.delivered(r, mark)) for r in receivers)
        try:
            wait_for(arrived, timeout=BOUND + 1, message='forwarded presence')
        except AssertionError:
            pass
        missing = [r for r in receivers if not any(p == payload for _, p in self.front.delivered(r, mark))]
        need(not missing, f'{what}: the coordinator forwards presence (0x06, the source host ID as 32 bytes, then '
             'the network ID as UTF-8) to the version 3 relay connection of every other member of the network '
             '(receivers missing it)', missing)

    # --- sections ------------------------------------------------------------------------------------------

    def check_negotiation(self):
        stranger = secrets.token_bytes(32)  # the protocol is selected in the handshake, before membership
        three = Relay(self.coord, stranger, self.certs, (V3, V2, V1))
        self.raws.append(three)
        need(three.selected == V3, 'Hosts offer capsule-relay/3, then /2, then /1. A coordinator that knows version '
             '3 selects it', three.selected)
        two = Relay(self.coord, secrets.token_bytes(32), self.certs, (V2, V1))
        self.raws.append(two)
        need(two.selected == V2, 'a coordinator still selects version 2 when a host offers only /2 and /1',
             two.selected)
        need([r.selected for r in (self.w3, self.w4, self.m3, self.m2, self.w2)] == [V3, V3, V3, V3, V2],
             'raw member connections negotiated as offered',
             [r.selected for r in (self.w3, self.w4, self.m3, self.m2, self.w2)])
        offers, selected = {}, {}
        for name in ('a1', *OBSERVERS, 'vh'):
            links = self.front.relay_links(name)
            need(links, f'{name} keeps a relay connection to its coordinator (through the front)',
                 self.front.errors[-5:])
            offers[name] = [p for p in links[-1].offered if p.startswith('capsule-relay/')]
            selected[name] = links[-1].protocol
        wrong = {n: o for n, o in offers.items() if o != [V3, V2, V1]}
        need(not wrong, 'Hosts offer capsule-relay/3, then /2, then /1 (relay protocols offered, in order)', wrong)
        expected = {n: V3 for n in ('a1', *OBSERVERS)} | {'vh': V2}
        need(selected == expected, 'every host runs on version 3, and erin\'s host on version 2 when its coordinator '
             'does not offer 3', selected)
        return f'offers {offers["a1"]}'

    def check_ready(self):
        agent = self.agents['ready']
        credential = self.setup(agent)
        mark = time.monotonic()
        channel = Channel(self.node, self.script, self.hosts['a1'], credential, self.root / 'mcp-ready')
        self.channels.append(channel)
        self.ready = (channel, credential)
        origin = time.monotonic()  # capsule_ready has returned
        self.reflected('capsule_ready', lambda n: self.state(n, agent['id']) == (True, 'verified'), origin)
        status, listing = wire(self.hosts['a1'], fixture_context(self.hosts['b1']), 'GET',
                               f'/peer/v1/networks/{self.net}/agents')
        need(status == 200, 'the peer route answers bob\'s host', status, listing)
        served = {e['agent_id']: (e['connected'], e.get('channel')) for e in listing}
        need(served.get(agent['id']) == (True, 'verified'), 'the peer route serves the verified session',
             served.get(agent['id']))
        self.announced(mark, 'capsule_ready')
        self.forwarded(mark, 'a1', self.net, OBSERVERS, 'capsule_ready')
        need(any(p == raw_id(self.ids['a1']) + self.net.encode() for _, p in self.w3.received(since=mark)),
             'capsule_ready: forwarded to a raw version 3 member too', self.w3.received(since=mark))
        echoed = [p for _, p in self.front.delivered('a1', mark) if p[:32] == raw_id(self.ids['a1'])]
        need(not echoed, 'The coordinator forwards to every other member: not back to the sender', echoed)

    def check_unverified(self):
        agent = self.agents['plain']
        raw = self.adapter(agent, verify=False, renew=False)
        origin = time.monotonic()
        self.reflected('a lease without verification', lambda n: self.state(n, agent['id']) == (False, 'unverified'),
                       origin)
        lapse = self.lease_end(raw.adapter['id'])
        self.reflected('the unverified lease lapsing after its last renewal',
                       lambda n: self.state(n, agent['id']) == (False, None), lapse)

    def check_only_changed(self):
        notes = []
        for changed, owner, observers in (('a1', 'alice', OBSERVERS), ('c1', 'carol', ('a1', 'b1', 'd1'))):
            # A moment without refreshes, so that an unchanged refreshed_at means no query.
            for attempt in range(5):
                before = {n: self.refreshed(n) for n in observers}
                tops = {n: self.directory(n)['refreshed_at'] for n in observers}
                time.sleep(1.2)
                if all(self.refreshed(n) == before[n] for n in observers):
                    break
            agent = self.register(changed, f'only-{changed}-{secrets.token_hex(2)}', owner)
            origin = time.monotonic()
            self.reflected(f'a registration on {changed}', lambda n: self.state(n, agent['id']) is not None, origin,
                           observers)
            time.sleep(0.5)
            for n in observers:
                after = self.refreshed(n)
                need(after.get(self.ids[changed]) != before[n].get(self.ids[changed]),
                     f'{n} refreshed the changed host {changed} (its entry\'s refreshed_at advanced)',
                     before[n].get(self.ids[changed]), after.get(self.ids[changed]))
                touched = {h: (before[n].get(h), t) for h, t in after.items()
                           if h != self.ids[changed] and t != before[n].get(h)}
                need(not touched, f'Only the changed host is queried: other hosts\' entries in {n}\'s directory keep '
                     'their refreshed_at (host: (before, after))', touched)
                top = self.directory(n)['refreshed_at']
                if top != tops[n]:
                    notes.append(f'{n} top-level refreshed_at moved')
        return '; '.join(notes) or 'top-level refreshed_at unchanged'

    def check_ignoring(self):
        b1 = self.front.current('b1')
        need(b1 is not None and b1.protocol == V3, 'needs bob\'s host on a version 3 relay connection',
             b1 and b1.protocol)
        stranger = 'host_' + secrets.token_hex(32)
        for attempt in range(5):
            before = self.refreshed('b1')
            time.sleep(1.2)
            if self.refreshed('b1') == before:
                break
        b1.inject(presence_to_host(self.ids['a1'], self.side))  # a network bob's host is not in
        b1.inject(presence_to_host(self.ids['m'], self.net))  # a host bob's host does not know as a member
        b1.inject(presence_to_host(stranger, self.net))  # a host nobody knows
        time.sleep(BOUND + 0.5)
        after = self.refreshed('b1')
        need(after.get(self.ids['a1']) == before.get(self.ids['a1']),
             'A receiving host ignores presence for a network it is not in (a1\'s entry in the team network was not '
             'refreshed)', before.get(self.ids['a1']), after.get(self.ids['a1']))
        need(self.ids['m'] not in after and stranger not in after,
             'A receiving host ignores presence from a host it does not know as a member (no entry added)',
             sorted(after))
        need(after == before, 'ignored presence refreshes no entry', before, after)
        need(b1.open, 'presence for another network or an unknown host is a valid frame: the connection stays open')
        status, body = self.hosts['b1'].directory(self.side)
        need(status == 404, 'bob\'s host has no directory for the side network', status, body)
        time.sleep(1.2)
        injected = b1.inject(presence_to_host(self.ids['a1'], self.net))
        times = race({'b1': lambda: self.refreshed('b1').get(self.ids['a1']) != before.get(self.ids['a1'])},
                     until=injected + BOUND + SLACK + 2)
        need(times['b1'] is not None and times['b1'] - injected <= BOUND + SLACK,
             'On presence from a current member, the receiving host refreshes that host\'s entry at once',
             times['b1'] and round(times['b1'] - injected, 2))
        return f"control refreshed in {times['b1'] - injected:.2f}s"

    def check_in_flight(self):
        b1 = self.front.current('b1')
        need(b1 is not None and b1.protocol == V3, 'needs bob\'s host on a version 3 relay connection',
             b1 and b1.protocol)
        a1 = self.ids['a1']
        # Warm up the path from bob's host to a1's advertised address, undelayed.
        self.delay.delay = 0.0
        before = self.refreshed('b1').get(a1)
        time.sleep(1.2)
        b1.inject(presence_to_host(a1, self.net))
        wait_for(lambda: self.refreshed('b1').get(a1) != before, timeout=8, message='a warm-up refresh')
        time.sleep(1.2)
        samples = []
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                try:
                    entry = {h['host_id']: h for h in self.directory('b1')['hosts']}[a1]
                    samples.append((time.monotonic(), entry['refreshed_at'], entry['state']))
                except Exception:
                    pass
                time.sleep(0.03)
        initial = self.refreshed('b1').get(a1)
        self.delay.delay = DELAY
        try:
            poller = threading.Thread(target=sample, daemon=True)
            poller.start()
            start = time.monotonic()
            for _ in range(6):
                b1.inject(presence_to_host(a1, self.net))
                time.sleep(0.1)
            time.sleep(3 * DELAY + 3)
            stop.set()
            poller.join(timeout=3)
        finally:
            self.delay.delay = 0.0
        changes, last = [], initial
        for t, value, state in samples:
            if value != last:
                changes.append((round(t - start, 2), value, state))
                last = value
        need(changes, 'six presence frames for a1 refresh its entry', initial, samples[-1:] if samples else None)
        need(changes[0][0] <= DELAY + BOUND + SLACK, 'the first query starts at once (its answer delayed by '
             f'{DELAY}s)', changes)
        need(len(changes) <= 2, 'At most one query per (network, host) is in flight; presence arriving during one '
             'causes one more query after it: no more than two refreshes', changes)
        need(len(changes) == 2, 'a presence arriving during a query causes one more query after it', changes)
        gap = changes[1][0] - changes[0][0]
        need(gap >= DELAY * 0.75, 'the second query starts after the first ends (queries do not overlap): the second '
             f'refresh comes at least the delayed answer time ({DELAY}s) after the first', changes)
        return f'refreshes at {[c[0] for c in changes]}s'

    def check_burst(self):
        a1 = self.hosts['a1']
        agents = [self.agents[f'burst{i}'] for i in range(4)]
        credentials = [self.setup(agent) for agent in agents]
        raws = [RawAdapter(a1, c) for c in credentials]
        self.adapters += raws
        time.sleep(0.5)
        mark = time.monotonic()
        spans = []

        def step(function, *args):
            begin = time.monotonic()
            value = function(*args)
            spans.append((begin, time.monotonic()))
            return value
        step(raws[0].connect)
        step(raws[0].ready)
        step(raws[1].connect)
        step(raws[2].connect)
        step(raws[2].ready)
        step(a1.cli, 'session', 'detach', credentials[2]['adapter']['session_id'])
        step(raws[3].connect)
        step(raws[3].ready)
        step(a1.cli, 'adapter', 'revoke', credentials[3]['adapter']['id'])
        late = step(self.register, 'a1', 'burst4', 'alice')
        origin = time.monotonic()
        raws[0].renew()
        raws[1].renew()
        final = {agents[0]['id']: (True, 'verified'), agents[1]['id']: (False, 'unverified'),
                 agents[2]['id']: (False, None), agents[3]['id']: (False, None), late['id']: (False, None)}

        def settled(n):
            return all(self.state(n, agent_id) == expected for agent_id, expected in final.items())
        self.reflected('a burst ending', settled, origin)
        connected_only = (lambda n: (self.state(n, agents[2]['id']) or (None,))[0] is False
                          and (self.state(n, agents[3]['id']) or (None,))[0] is False)
        need(all(connected_only(n) for n in OBSERVERS), 'detached and revoked sessions are not connected')
        time.sleep(COALESCE * 3)
        sent = [t for t, p in self.front.sent('a1', mark) if p == self.net.encode()]
        need(sent, 'the burst produces presence from a1', sent)
        gaps = [round(b - a, 3) for a, b in zip(sent, sent[1:])]
        need(all(g >= COALESCE - JITTER for g in gaps), 'A host sends at most one presence per network per 250 '
             'milliseconds (gaps between a1\'s presence frames)', gaps)
        last_start = spans[-1][0]
        need(sent[-1] >= last_start, 'Later changes in that window are sent together once it ends, so the last change '
             'is always announced (a1\'s last presence after the last change began)',
             round(sent[-1] - mark, 3), round(last_start - mark, 3))
        notes = [f'a1 sent {len(sent)} for {len(spans)} changes in {spans[-1][1] - mark:.2f}s, gaps {gaps}']
        for n in OBSERVERS:
            got = [t for t, p in self.front.delivered(n, mark) if p == raw_id(self.ids['a1']) + self.net.encode()]
            need(got, f'{n} receives a1\'s presence', got)
            g = [round(b - a, 3) for a, b in zip(got, got[1:])]
            need(all(x >= COALESCE - JITTER for x in g), 'The coordinator forwards at most one presence per (network, '
                 f'source host) per receiving connection per 250 milliseconds ({n})', g)
            need(got[-1] >= sent[-1] - JITTER, f'later presence frames are coalesced into the next, not lost: {n} '
                 'receives one after a1\'s last', round(got[-1] - mark, 3), round(sent[-1] - mark, 3))
            notes.append(f'{n} got {len(got)}')
        raws[0].stop()
        raws[1].stop()
        return '; '.join(notes)

    def check_session_changes(self):
        a1 = self.hosts['a1']
        notes = {}
        for name, command in (('det', 'detach'), ('rev', 'revoke')):
            agent = self.agents[name]
            raw = self.adapter(agent)
            self.wait_state(agent, (True, 'verified'), what='connected')
            if command == 'detach':
                a1.cli('session', 'detach', raw.adapter['session_id'])
            else:
                a1.cli('adapter', 'revoke', raw.adapter['id'])
            origin = time.monotonic()
            raw.stop()
            self.reflected(f'a {command}', lambda n, agent=agent: (self.state(n, agent['id']) or (None,))[0] is False,
                           origin)
            notes[command] = {n: self.state(n, agent['id']) for n in OBSERVERS}
        agent = self.register('a1', 'fresh', 'alice')
        origin = time.monotonic()
        self.reflected('an agent registration', lambda n: self.state(n, agent['id']) is not None, origin)
        return f"after detach/revoke (connected, channel): {notes['detach']['b1']}, {notes['revoke']['b1']}"

    def check_clean_exit(self):
        need(getattr(self, 'ready', None), 'needs the capsule_ready section\'s session')
        channel, credential = self.ready
        agent = self.agents['ready']
        self.wait_state(agent, (True, 'verified'), what='still connected')
        channel.close()  # stdin closes; the adapter exits cleanly
        self.channels.remove(channel)
        lapse = self.lease_end(credential['adapter']['id'])
        self.notes.append(f'lease lapses {lapse - time.monotonic():.1f}s after the exit')
        self.reflected('a clean adapter exit', lambda n: (self.state(n, agent['id']) or (None,))[0] is False, lapse)

    def check_killed(self):
        agent = self.agents['crash']
        credential = self.setup(agent)
        channel = Channel(self.node, self.script, self.hosts['a1'], credential, self.root / 'mcp-crash')
        self.wait_state(agent, (True, 'verified'), what='connected')
        channel.process.kill()
        channel.process.wait(timeout=5)
        lapse = self.lease_end(credential['adapter']['id'])
        self.notes.append(f'lease lapses {lapse - time.monotonic():.1f}s after the kill')
        self.reflected('a killed adapter', lambda n: (self.state(n, agent['id']) or (None,))[0] is False, lapse)

    def check_version_two(self):
        notes = []
        links = self.front.relay_links('vh')
        need(links and all(link.protocol == V2 for link in links), 'erin\'s host runs on version 2',
             [link.protocol for link in links])
        mark = time.monotonic()
        # erin's own presence change: a host on a version 2 connection sends no presence.
        self.register('vh', 'erin-agent', 'erin')
        agent = self.register('a1', 'v2seen', 'alice')
        origin = time.monotonic()
        self.reflected('a registration (control)', lambda n: self.state(n, agent['id']) is not None, origin)
        time.sleep(1.0)
        seen = self.state('vh', agent['id']) is not None
        notes.append(f'erin\'s directory {"showed" if seen else "did not show"} it without a refresh')
        frames = [(link.protocol, k, round(t - mark, 2)) for link in links
                  for t, k, _ in link.sent + link.delivered if k == PRESENCE]
        need(not frames, 'Version 1 and 2 connections never carry 0x06: none sent or received by erin\'s host over '
             'the whole run', frames)
        out = self.hosts['vh'].cli('agents', '--refresh', '--json', '--network', self.net)
        need(any(r.get('agent_id') == agent['id'] for r in out.get('reachable', [])),
             'A host on a version 2 connection learns of others\' presence through the refreshes it already does: '
             'agents --refresh shows the change', out.get('reachable'))
        need(self.state('vh', agent['id']) is not None, 'the refreshed directory shows it', None)
        # Raw version 2 and version 1 connections.
        need(not self.w2.received(), 'a raw version 2 connection received no presence through the whole run',
             self.w2.received())
        need(self.w2.open, 'the raw version 2 connection stays open')
        one = self.relay('w2', (V1,))  # replaces the version 2 connection, one relay connection per host
        need(one.selected == V1, 'a version 1 connection is still served', one.selected)
        wait_for(lambda: not self.w2.open, timeout=5, message='the older w2 connection closed')
        mark = time.monotonic()
        self.register('a1', 'v1probe', 'alice')
        time.sleep(BOUND)
        need(not one.received(), 'Version 1 connections never carry 0x06', one.received())
        need(one.open, 'the version 1 connection is kept', one.closed_at)
        one.close()
        two = self.relay('w2', (V2, V1))
        need(two.selected == V2, 'version 2 selected', two.selected)
        mark = time.monotonic()
        two.send(presence_to_relay(self.net))
        time.sleep(BOUND)
        source = raw_id(self.ids['w2'])
        relayed = [p for _, p in self.w3.received(since=mark) if p[:32] == source]
        relayed += [p for n in OBSERVERS for _, p in self.front.delivered(n, mark) if p[:32] == source]
        need(not relayed, 'presence sent on a version 2 connection is not forwarded (0x06 is not a version 2 frame)',
             relayed)
        need(not two.open, 'An unknown frame type closes the connection: 0x06 on a version 2 connection',
             two.kinds())
        return '; '.join(notes)

    def check_forwarding(self):
        w3, w4, m3, m2 = self.w3, self.w4, self.m3, self.m2
        raws = {'w3': w3, 'w4': w4, 'm': m3, 'm2': m2}
        need(all(r.open and r.selected == V3 for r in raws.values()), 'raw version 3 member connections open',
             {n: (r.selected, r.open) for n, r in raws.items()})
        # Hosts behind the front receive too, once they run on version 3 (checked by the negotiation section).
        hosts = [n for n in ('a1', *OBSERVERS) if getattr(self.front.current(n), 'protocol', None) == V3]
        notes = [f'hosts on version 3: {hosts}']

        def got(receiver, mark, payload=None):
            frames = raws[receiver].received(since=mark) if receiver in raws else self.front.delivered(receiver, mark)
            return [p for _, p in frames if payload is None or p == payload]

        def reached(mark, source, network, receivers, what):
            payload = raw_id(self.ids[source]) + network.encode()
            try:
                wait_for(lambda: all(got(r, mark, payload) for r in receivers), timeout=BOUND + 1, message=what)
            except AssertionError:
                pass
            missing = [r for r in receivers if not got(r, mark, payload)]
            need(not missing, f'{what}: the coordinator forwards presence (0x06, the source host ID as 32 bytes, then '
                 'the network ID as UTF-8) to the current version 3 relay connection of every other current member of '
                 'the network (receivers missing it)', missing, {r: got(r, mark) for r in missing})

        # A member's presence reaches every other member, raw or host, and not the sender or outsiders.
        mark = time.monotonic()
        w3.send(presence_to_relay(self.net))
        reached(mark, 'w3', self.net, ['w4', *hosts], 'a member\'s presence')
        time.sleep(0.5)
        need(not got('w3', mark), 'The coordinator forwards to every other member: not back to the sender',
             got('w3', mark))
        need(not self.front.delivered('vh', mark), 'not forwarded to a version 2 connection',
             self.front.delivered('vh', mark))
        need(not got('m', mark) and not got('m2', mark), 'not forwarded to hosts outside the network',
             got('m', mark), got('m2', mark))
        # Frames the coordinator must drop.
        mark = time.monotonic()
        m3.send(presence_to_relay(self.net))  # from a non-member of the team network (m is only in side)
        w3.send(presence_to_relay(self.side))  # for a network the sender is not in (side: m, m2, and a1)
        w3.send(presence_to_relay('net_' + '0' * 64))  # for a network nobody is in
        time.sleep(BOUND + 0.5)
        stray = {r: got(r, mark) for r in [*raws, 'a1', *OBSERVERS, 'vh'] if got(r, mark)}
        need(not stray, 'The coordinator forwards a presence only when the sending host is a current member of that '
             'network, and drops other presence frames: none from a non-member, for a network the sender is not '
             'in, or for an unknown network (receiver: payloads)',
             {r: [(p[:32].hex()[:12], p[32:]) for p in ps] for r, ps in stray.items()})
        need(w3.open and m3.open, 'dropped presence frames do not close the connection', w3.closed_at, m3.closed_at)
        replies = w3.kinds(since=mark) + m3.kinds(since=mark)
        need(not [k for k in replies if k != PING], 'It drops other presence frames without a reply', replies)
        # Control: m's presence in the side network reaches the other side members.
        mark = time.monotonic()
        m3.send(presence_to_relay(self.side))
        reached(mark, 'm', self.side, ['m2', *(['a1'] if 'a1' in hosts else [])], 'presence in the side network')
        # Coalescing per (network, source host) per receiving connection.
        time.sleep(1.0)
        mark = time.monotonic()
        sent_times = []
        for _ in range(8):
            sent_times.append(w3.send(presence_to_relay(self.net)))
            time.sleep(0.1)
        time.sleep(COALESCE * 3)
        payload = raw_id(self.ids['w3']) + self.net.encode()
        for r in ('w4', *hosts):
            frames = raws[r].received(since=mark) if r in raws else self.front.delivered(r, mark)
            times = [t for t, p in frames if p == payload]
            gaps = [round(b - a, 3) for a, b in zip(times, times[1:])]
            need(times, f'{r} receives the burst', times)
            need(all(g >= COALESCE - JITTER for g in gaps), 'The coordinator forwards at most one presence per '
                 f'(network, source host) per receiving connection per 250 milliseconds ({r})', gaps)
            need(len(times) < len(sent_times), f'later presence frames are coalesced into the next ({r})', len(times))
            need(times[-1] >= sent_times[-1] - JITTER, f'coalesced, not lost: one is delivered after the last sent '
                 f'({r})', round(times[-1] - mark, 3), round(sent_times[-1] - mark, 3))
            if r == 'w4':
                notes.append(f'8 sent in {sent_times[-1] - mark:.2f}s, w4 got {len(times)}, gaps {gaps}')
        need(hosts == ['a1', *OBSERVERS], 'hosts receive forwarded presence on version 3 (hosts on version 3)', hosts)
        return '; '.join(notes)

    def check_restart(self):
        a1 = self.hosts['a1']
        agent = self.agents['rst']
        raw = self.adapter(agent)
        self.wait_state(agent, (True, 'verified'), what='connected')
        raw.stop()
        mark = time.monotonic()
        a1.stop()
        a1.start()
        origin = time.monotonic()
        self.reflected('a restart of a1\'s daemon', lambda n: (self.state(n, agent['id']) or (None,))[0] is False,
                       origin)
        link = self.front.current('a1')
        need(link is not None and link.opened >= mark, 'a1 reconnects its relay after the restart',
             link and link.opened)
        early = [p for t, p in self.front.sent('a1', link.opened) if t <= link.opened + BOUND]
        missing = [n for n in (self.net, self.side) if n.encode() not in early]
        need(not missing, 'After it starts, the host sends one presence for each of its networks on that coordinator '
             '(networks missing)', missing)
        # The same instance recovers its session, still verified, within the startup window.
        status, body = raw.connect()
        need(status == 200, 'the original adapter instance recovers its session after the restart', status, body)
        origin = time.monotonic()
        raw.renew()
        self.reflected('the recovered session', lambda n: self.state(n, agent['id']) == (True, 'verified'), origin)
        # A relay connection that the front closes, then re-established by a1.
        old = self.front.current('a1')
        old.close()
        wait_for(lambda: (self.front.current('a1') or old) is not old, timeout=40,
                 message='a1 re-establishing its relay connection')
        link = self.front.current('a1')
        time.sleep(BOUND)
        early = [p for t, p in self.front.sent('a1', link.opened) if t <= link.opened + BOUND]
        missing = [n for n in (self.net, self.side) if n.encode() not in early]
        need(not missing, 'After any relay connection is (re)established, the host sends one presence for each of '
             'its networks on that coordinator (networks missing)', missing)
        raw.stop()
        return f're-established after {link.opened - old.closed_at:.1f}s'

    # --- the pairing ---------------------------------------------------------------------------------------

    def run(self):
        x, y = self.x, self.y
        self.coord.start()
        self.front = Front(self.coord, self.root / 'front')
        a1 = self.host('a1', x)
        # a1 advertises the delay front's address for its peer listener.
        self.delay = UdpDelay(a1.port)
        a1.daemon_args = ('--peer-listen', a1.address, '--advertise', f'127.0.0.1:{self.delay.port}',
                          '--coordination-interval', str(INTERVAL))
        for name, binary, listen in (('b1', y, True), ('c1', x, True), ('d1', y, False), ('vh', y, True),
                                     ('w3', x, True), ('w2', y, True), ('w4', y, True), ('m', x, True),
                                     ('m2', y, True)):
            self.host(name, binary, listen)
        self.front.downgrade.add('vh')
        self.ids = {n: h.start()['id'] for n, h in self.hosts.items()}
        created = a1.cli('network', 'create', 'team', '--as', 'alice', '--coordinator', self.front.address,
                         '--coordinator-key', self.front.public_key)
        self.net = created['id']
        need(created['person'] and created['person'].get('bound'), 'create binds alice', created)
        self.person = {'alice': created['person']['person_id']}
        for name, label in (('b1', 'bob'), ('c1', 'carol'), ('d1', 'dave'), ('vh', 'erin')):
            token = a1.cli('invite', label, '--network', self.net)['token']
            out = self.hosts[name].cli('join', token)
            need(out.get('person') and out['person'].get('bound'), f'{name} joined bound as {label}', out)
            self.person[label] = out['person']['person_id']
        for name in ('w3', 'w2', 'w4'):
            token = a1.cli('invite', name, '--network', self.net)['token']
            self.hosts[name].cli('network', 'join', '--token', token, '--no-person')
        self.side = a1.cli('network', 'create', 'side', '--as', 'alice', '--coordinator', self.front.address,
                           '--coordinator-key', self.front.public_key)['id']
        for name in ('m', 'm2'):
            token = a1.cli('invite', name, '--network', self.side)['token']
            self.hosts[name].cli('network', 'join', '--token', token, '--no-person')
        team = ('a1', 'b1', 'c1', 'd1', 'vh', 'w3', 'w2', 'w4')
        wait_for(lambda: all(set(self.ids[n] for n in team) <= set(self.members(n)) for n in team), timeout=70,
                 message='every member sees the team network')
        wait_for(lambda: {self.ids['m'], self.ids['m2']} <= set(self.members('a1', self.side)), timeout=40,
                 message='m and m2 in the side network')
        # The key holders' daemons stop; their keys stay members, used by raw relay connections.
        for name in ('w3', 'w2', 'w4', 'm', 'm2'):
            self.hosts[name].stop()
        version = a1.cli('allow', 'everyone', '--network', self.net)['policy']['version']
        cversion = self.hosts['c1'].cli('allow', 'everyone', '--network', self.net)['policy']['version']
        wait_for(lambda: all(self.policy_version(n, self.person['alice']) >= version for n in ('b1', 'c1', 'd1', 'vh'))
                 and all(self.policy_version(n, self.person['carol']) >= cversion for n in ('a1', 'b1', 'd1')),
                 timeout=40, message='the policies reaching every member')
        self.agents = {name: self.register('a1', name, 'alice') for name in
                       ('ready', 'plain', 'crash', 'det', 'rev', 'rst', 'burst0', 'burst1', 'burst2', 'burst3')}
        self.register('c1', 'cagent', 'carol')
        changed = time.monotonic()
        for name in ('a1', *OBSERVERS, 'vh'):
            status, body = self.hosts[name].directory(self.net, refresh=True)
            need(status == 200, f'{name} refreshes its directory', status, body)
        wait_for(lambda: all(self.state(n, self.agents['burst3']['id']) is not None for n in (*OBSERVERS, 'vh')),
                 timeout=30, message='alice\'s agents in every directory')
        # Refreshes triggered by the joins and policies run within 10 seconds of them; let them finish.
        time.sleep(max(0.0, changed + 16 - time.monotonic()))
        self.w3 = self.relay('w3', (V3, V2, V1))
        self.w2 = self.relay('w2', (V2, V1))
        self.w4 = self.relay('w4', (V3, V2, V1))
        self.m3 = self.relay('m', (V3, V2, V1))
        self.m2 = self.relay('m2', (V3, V2, V1))

        self.section('version 3 negotiation', self.check_negotiation)
        self.section('capsule_ready', self.check_ready)
        self.section('only the changed host', self.check_only_changed)
        self.section('receiver ignoring', self.check_ignoring)
        self.section('one query in flight', self.check_in_flight)
        self.section('unverified lease', self.check_unverified)
        self.section('burst', self.check_burst)
        self.section('detach, revocation, registration', self.check_session_changes)
        self.section('clean adapter exit', self.check_clean_exit)
        self.section('killed adapter', self.check_killed)
        self.section('version 2 host', self.check_version_two)
        self.section('coordinator forwarding', self.check_forwarding)
        self.section('restart', self.check_restart)

    def save_logs(self, directory):
        target = directory / self.label.replace('/', '-')
        target.mkdir(parents=True, exist_ok=True)
        for name, h in [*self.hosts.items(), ('coord', self.coord)]:
            try:
                h.logs.seek(0)
                (target / f'{name}.log').write_bytes(h.logs.read())
            except (OSError, ValueError):
                pass
        if self.front is not None:
            lines = [f'{round(t, 2)} {e}' for t, e in self.front.errors]
            for link in self.front.links:
                lines.append(f'{link.name} {link.protocol} offered={link.offered} opened={round(link.opened, 2)} '
                             f'closed={link.closed_at and round(link.closed_at, 2)} sent={len(link.sent)} '
                             f'delivered={len(link.delivered)}')
            (target / 'front.log').write_text('\n'.join(lines) + '\n')

    def close(self):
        try:
            for raw in self.adapters:
                raw.renewing = False
            for raw in self.raws:
                raw.close()
            for channel in self.channels:
                if channel.process.poll() is None:
                    channel.process.kill()
            stop_all(tuple(self.hosts.values()))
        finally:
            if self.front is not None:
                self.front.stop()
            if self.delay is not None:
                self.delay.stop()
            self.coord.stop()
            self.coord.logs.close()


def run_pairing(coord_binary, x, y, node, label, logs=None):
    with tempfile.TemporaryDirectory(prefix='capsule-presence-') as temporary:
        pairing = Pairing(label, x, y, coord_binary, node, Path(temporary))
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [setup]: {detail}', flush=True)
        finally:
            if logs and not all(ok for _, ok, _ in pairing.results):
                pairing.save_logs(logs)
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        print(f'---- {label}: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} sections passed '
              f'in {time.monotonic() - started:.0f}s', flush=True)
        return pairing.results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, help='required unless every --pairing is Go/Go')
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    parser.add_argument('--node', type=Path, required=True, help='Node for the real MCP adapter')
    parser.add_argument('--pairing', action='append',
                        help='X/Y, such as Go/Rust: alice\'s and carol\'s hosts run X, bob\'s, dave\'s, and erin\'s Y; '
                             'repeatable; default all four')
    parser.add_argument('--logs', type=Path, help='save daemon, coordinator, and front logs of failing pairings here')
    args = parser.parse_args()
    set_probe(args.probe.resolve())
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve() if args.rust else None}
    pairings = args.pairing or [f'{a}/{b}' for a in binaries for b in binaries]
    for pairing in pairings:
        a, _, b = pairing.partition('/')
        if a not in binaries or b not in binaries:
            parser.error(f'unknown pairing {pairing}')
        if binaries[a] is None or binaries[b] is None:
            parser.error(f'pairing {pairing} needs --rust')
    failures = []
    for pairing in pairings:
        a, _, b = pairing.partition('/')
        label = f'{a}/{b}'
        for name, ok, detail in run_pairing(args.coord.resolve(), binaries[a], binaries[b], args.node.resolve(),
                                            label, args.logs):
            if not ok:
                failures.append(f'{label} [{name}]: {detail.strip().splitlines()[-1] if detail.strip() else ""}')
    print('==== summary', flush=True)
    for line in failures:
        print('FAIL ' + line[:1200], flush=True)
    if failures:
        raise SystemExit(f'{len(failures)} section(s) failed')
    print('PASS all sections', flush=True)


if __name__ == '__main__':
    main()
