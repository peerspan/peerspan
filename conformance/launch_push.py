#!/usr/bin/env python3
"""Exercise coordinator change notifications and onward hops by address (milestone 7 slice 5).

Written from docs/launch-contract.md ("Slice 5: acceptance": "Change notifications", "Onward hops
by address", and the Verification paragraph naming this suite), the relay protocol in
docs/coordination-contract.md, and docs/delegation-chain-contract.md, independently of both
implementations. Runs every Go/Rust pairing X/Y with one Go coordinator per pairing: alice's host
(the network's creator), carol's host, and the stopped watcher hosts run X; bob's host, dave's host
(started without --peer-listen), and the later joiners run Y. Every host's CLI is its daemon's
implementation, every host has its own HOME and XDG_CONFIG_HOME (so persons use generated keys,
and nothing touches the real ~/.config/peerspan), and every daemon runs with a 30-second
coordination interval, so only a notification can deliver a change within 2 seconds.

A raw TLS client offering relay ALPNs (as conformance/relay.py builds one) observes frames with the
key of a member host whose daemon is stopped. The same client, holding a running host's key,
displaces that host's relay connection for a moment (one relay connection per host is current), so
the fallbacks are exercised while that host cannot be notified. Each pairing reports these sections:

- version 2 negotiation: `peerspan-relay/2` selected when offered first, `peerspan-relay/1` when
  only it is offered;
- changes reach members: a join, a binding, a policy, a group change, and a revocation each
  reaching every other running member within 2 seconds, with `changed` (0x05, the network ID)
  on a version 2 connection, and the host that made the change synced too;
- version 1 host: no `changed` on a version 1 connection through all those changes, the
  connection kept, and an interval-style sync still serving the changes;
- plain sync: no `changed` for syncs that change nothing or only an address;
- coalescing: a burst of concurrent changes gives at most one `changed` per 250 ms, with the
  last change still notified and reaching every member;
- no --peer-listen: a host without a peer listener notified within 2 seconds;
- fallback allow: `allow` by a label admitted moments earlier, with the creator unnotified;
- fallback directory: a synchronous directory refresh retrying a host that answered 403, a current
  member whose connection failed authentication (it does not know the new host yet), and a sibling
  (bound to this host's person in its map) whose answer has no `self` entry;
- fallback send: a send by address citing a policy submitted moments earlier;
- onward hops: `delegation_depth` on an address delegation (link 0 shape, including the network the
  address resolved in), a forward by the receiver by address with a two-link chain at the final
  receiver, where only the originator may submit tasks to the target and the forward cites the
  target owner's policy, a forward to the originator's own person citing `self`, refusal without
  `allow --delegate`, the 400 cases (nonzero depth only) persisting nothing, an explicit 0 accepted
  with `destination` and `parent_task_id`, and MCP `delegate_task` with `delegation_depth` through
  the real adapter.

Needs openssl, peerspan-peer-probe, and Node for the MCP case. Exits non-zero listing every failed section.
"""
import argparse
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import traceback

from agent_adapter import Channel, adapter_call, instance_for
from coordination import Coordinator, wait_for
from host_service import stop_all
from launch_directory import DirectoryHost
from launch_onboarding import Failure, need, parse_time
from peer_messaging import set_probe, timestamp
from tasks import task_id, tool

INTERVAL = 30
BOUND = 2.0  # "within 2 seconds"
SLACK = 0.3  # polling period plus local API latency
V1, V2 = 'peerspan-relay/1', 'peerspan-relay/2'
SEND, RECEIVE, UNREACHABLE, PING, CHANGED = 1, 2, 3, 4, 5
COALESCE = 0.25
JITTER = 0.05
LINK_KEYS = {'network_id', 'index', 'previous', 'issuer_host_id', 'audience_host_id', 'task_id',
             'originator_agent_id', 'principals', 'deadline', 'depth', 'signature'}


def seed_of(host):
    with sqlite3.connect(host.state / 'host.db') as connection:
        return bytes(connection.execute('SELECT private_key FROM identity').fetchone()[0][:32])


_certificates = {}


def tls_context(seed, directory, alpn):
    """A TLS 1.3 client context proving the Ed25519 key for seed, offering alpn, without pinning."""
    if seed not in _certificates:
        name = secrets.token_hex(4)
        key_der, cert, key = (directory / f'{name}.key.der', directory / f'{name}.cert.pem',
                              directory / f'{name}.key.pem')
        key_der.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + seed)
        subprocess.run(['openssl', 'req', '-new', '-x509', '-key', str(key_der), '-keyform', 'DER', '-out',
                        str(cert), '-subj', '/CN=push-fixture', '-days', '1'], check=True, capture_output=True,
                       timeout=10)
        subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', str(key_der), '-out', str(key)],
                       check=True, capture_output=True, timeout=10)
        _certificates[seed] = (cert, key)
    cert, key = _certificates[seed]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    # The daemons pin the coordinator key; this fixture observes the protocol.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(list(alpn))
    return context


class RawRelay:
    """A raw relay connection: records every frame with its arrival time, and pings every 10 seconds."""

    def __init__(self, coord, seed, directory, alpn=(V2, V1)):
        context = tls_context(seed, directory, alpn)
        self.connection = context.wrap_socket(socket.create_connection(('127.0.0.1', coord.port), timeout=5))
        self.selected = self.connection.selected_alpn_protocol()
        self.opened = time.monotonic()
        self.frames = []
        self.closed_at = None
        self.lock = threading.Lock()
        self.stopping = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        buffer = b''
        last_ping = time.monotonic()
        self.connection.settimeout(0.1)
        while not self.stopping:
            if time.monotonic() - last_ping > 10:
                try:
                    self.connection.sendall(struct.pack('>BH', PING, 0))
                except OSError:
                    break
                last_ping = time.monotonic()
            try:
                chunk = self.connection.recv(65536)
            except (socket.timeout, TimeoutError, ssl.SSLWantReadError):
                continue
            except (OSError, ssl.SSLError):
                break
            if not chunk:
                break
            now = time.monotonic()
            buffer += chunk
            while len(buffer) >= 3:
                kind, size = struct.unpack('>BH', buffer[:3])
                if len(buffer) < 3 + size:
                    break
                with self.lock:
                    self.frames.append((now, kind, buffer[3:3 + size]))
                buffer = buffer[3 + size:]
        self.closed_at = time.monotonic()

    def changed(self, since=0.0):
        with self.lock:
            return [(t, payload) for t, kind, payload in self.frames if kind == CHANGED and t >= since]

    def kinds(self):
        with self.lock:
            return sorted({kind for _, kind, _ in self.frames})

    @property
    def open(self):
        return self.closed_at is None

    def close(self):
        self.stopping = True
        self.thread.join(timeout=3)
        try:
            self.connection.close()
        except OSError:
            pass


class Holder:
    """Holds a running host's relay slot: whenever the host reconnects and displaces this client, it
    reconnects at once, so changed frames for that host land here rather than at the host."""

    def __init__(self, coord, seed, directory):
        self.coord, self.seed, self.directory = coord, seed, directory
        self.connections = []
        self.stopping = False
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.ready.wait(10)

    def _loop(self):
        while not self.stopping:
            try:
                raw = RawRelay(self.coord, self.seed, self.directory)
            except OSError:
                time.sleep(0.01)
                continue
            self.connections.append(raw)
            self.ready.set()
            while raw.open and not self.stopping:
                time.sleep(0.005)

    def changed(self):
        return sorted(f for raw in self.connections for f in raw.changed())

    def close(self):
        self.stopping = True
        self.thread.join(timeout=5)
        for raw in self.connections:
            raw.close()
        return len(self.connections)


def coord_sync(coord, seed, directory, network, address=''):
    """POST /coord/v1/networks/{id}/sync as the host whose key is seed (a version 1 host's interval sync)."""
    connection = http.client.HTTPSConnection('127.0.0.1', coord.port, timeout=10,
                                             context=tls_context(seed, directory, ['http/1.1']))
    try:
        connection.request('POST', f'/coord/v1/networks/{network}/sync',
                           json.dumps({'address': address, 'candidates': []}).encode(),
                           {'Content-Type': 'application/json'})
        response = connection.getresponse()
        data = response.read()
        try:
            return response.status, json.loads(data)
        except json.JSONDecodeError:
            return response.status, data.decode(errors='replace')
    finally:
        connection.close()


def race(observers, timeout=8.0):
    """Poll each predicate concurrently from now; {name: seconds until it first held, or None}."""
    start = time.monotonic()
    results = {}

    def watch(name, predicate):
        while time.monotonic() - start < timeout:
            try:
                if predicate():
                    results[name] = round(time.monotonic() - start, 2)
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


def late(times):
    return {name: t for name, t in times.items() if t is None or t > BOUND + SLACK}


class PushHost(DirectoryHost):
    """A host with a 30-second coordination interval, with or without a peer listener."""

    def __init__(self, daemon, cli, state, home, listen=True):
        super().__init__(daemon, cli, state, home)
        self.listen = listen
        interval = ('--coordination-interval', str(INTERVAL))
        self.daemon_args = (('--peer-listen', self.address) if listen else ()) + interval


class Pairing:
    def __init__(self, label, x, y, coord_binary, node, root):
        self.label, self.x, self.y, self.node, self.root = label, x, y, node, root
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.hosts = {}
        self.running = []  # names of running hosts that are members of the network
        self.raws = []
        self.channels = []
        self.results = []
        self.script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'
        self.certs = root / 'certs'
        self.certs.mkdir()

    # --- infrastructure -----------------------------------------------------------------------------------

    def host(self, name, binary, listen=True):
        h = PushHost(binary, binary, self.root / name, self.root / f'user-{name}', listen=listen)
        self.hosts[name] = h
        return h

    def section(self, name, function):
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:  # report and continue with the next section
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=5)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}',
              flush=True)
        return True

    def raw(self, name, alpn=(V2, V1)):
        r = RawRelay(self.coord, seed_of(self.hosts[name]), self.certs, alpn)
        self.raws.append(r)
        return r

    def members(self, name, network=None):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{network or self.net}/members')
        assert status == 200, (status, body)
        return {m['host_id']: m for m in body}

    def policy_version(self, name, person):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{self.net}/policy?person={person}')
        return body['version'] if status == 200 else 0

    def group_version(self, name, group):
        status, body = self.hosts[name].call('GET', f'/v1/networks/{self.net}/groups')
        assert status == 200, (status, body)
        return {g['name']: g['version'] for g in body}.get(group, 0)

    def last_sync(self, name):
        status, body = self.hosts[name].call('GET', '/v1/networks')
        assert status == 200, (status, body)
        return {n['id']: n for n in body}[self.net]['last_sync_at']

    def others(self, *excluded):
        return [n for n in self.running if n not in excluded]

    def invite(self, label, network=None):
        out = self.hosts['a1'].cli('invite', label, '--network', network or self.net)
        return out['token']

    def join(self, name, label, network=None, person=True):
        token = self.invite(label, network)
        h = self.hosts[name]
        if person:
            out = h.cli('join', token)
            need(out.get('person') and out['person'].get('bound'), f'{name} joined bound as {label}', out)
        else:
            out = h.cli('network', 'join', '--token', token, '--no-person')
        return out

    def all_see(self, host_ids, timeout=70, network=None, names=None):
        def seen():
            return all(set(host_ids) <= set(self.members(n, network)) for n in (names or self.running))
        wait_for(seen, timeout=timeout, message='every running member sees ' + ', '.join(sorted(host_ids)))

    def quiet(self, raw, period=1.0, timeout=15):
        """Wait until raw has received no changed frame for period seconds."""
        def calm():
            frames = raw.changed()
            return not frames or time.monotonic() - frames[-1][0] >= period
        wait_for(calm, timeout=timeout, message='no changed frames for a moment')

    def setup_session(self, name, agent):
        h = self.hosts[name]
        status, body = h.call('POST', '/v1/adapters/setup', {
            'agent_id': agent['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
            'expires_at': timestamp(3600), 'directory': True})
        need(status == 201 and isinstance(body, dict) and body.get('credential', {}).get('token'),
             'POST /v1/adapters/setup with directory: true', status, body)
        self.secrets[body['credential']['token']] = body['credential']
        return body['credential']

    # --- sections ------------------------------------------------------------------------------------------

    def check_negotiation(self):
        v2 = self.raw('w2', (V2, V1))
        need(v2.selected == V2, 'Hosts offer peerspan-relay/2 before peerspan-relay/1, and coordinators select '
             'version 2 when offered', v2.selected)
        v1 = self.raw('w1', (V1,))
        need(v1.selected == V1, 'A version 1 host (offering only peerspan-relay/1) gets version 1', v1.selected)
        # A stranger's key: the protocol is selected in the handshake, then a non-member is closed.
        only = RawRelay(self.coord, secrets.token_bytes(32), self.certs, (V2,))
        self.raws.append(only)
        need(only.selected == V2, 'coordinators select version 2 when offered', only.selected)
        wait_for(lambda: not only.open, timeout=5, message='a non-member closed after the handshake')
        need(v2.open and v1.open, 'member relay connections stay open', v2.closed_at, v1.closed_at)
        self.v2, self.v1 = v2, v1

    def notified(self, what, started, net=None):
        """The version 2 watcher received changed with the network ID after started."""
        payload = (net or self.net).encode()
        frames = wait_for(lambda: [f for f in self.v2.changed(started) if f[1] == payload], timeout=BOUND + 1,
                          message=f'changed after {what}') if self.v2.open else []
        need(frames, f'{what}: the coordinator sends changed (0x05, the network ID as UTF-8) on the version 2 '
             'relay connection of every member host', self.v2.changed(started))

    def measured(self, what, times):
        need(not late(times), f'{what} reaches every other member within 2 seconds, with a 30-second interval',
             times)
        self.notes.append(f"{what} {max(times.values()):.2f}s")
        self.latency[what] = times

    def check_changes(self):
        self.notes, self.latency = [], {}
        need(getattr(self, 'v2', None) and self.v2.open, 'needs the version 2 watcher')
        hosts = self.hosts

        # A join.
        e1 = hosts['e1']
        self.ids['e1'] = e1.start()['id']
        token = self.invite('erin')
        started = time.monotonic()
        out = e1.cli('join', token)
        need(out.get('id') == self.net, 'join', out)
        times = race({n: (lambda n=n: self.ids['e1'] in self.members(n)) for n in self.others()})
        self.running.append('e1')
        self.notified('a join', started)
        self.measured('join', times)

        # A binding: alice's second machine, joined without a person, then bound with alice's copied key.
        a2 = hosts['a2']
        self.ids['a2'] = a2.start()['id']
        self.join('a2', 'alice', person=False)
        self.running.append('a2')
        self.all_see([self.ids['a2']], timeout=40)
        target = a2.config / 'peerspan'
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in ('person_ed25519', 'person_ed25519.pub'):
            shutil.copy2(hosts['a1'].config / 'peerspan' / name, target / name)
        started = time.monotonic()
        out = a2.cli('network', 'bind', '--network', self.net)
        need(out.get('person_id') == self.person['alice'], 'network bind binds a2 to alice', out)
        times = race({n: (lambda n=n: self.members(n)[self.ids['a2']].get('person_id') == self.person['alice'])
                      for n in self.others('a2')})
        self.notified('a binding', started)
        self.measured('binding', times)

        # A policy, made on bob's host; bob's host is notified too.
        before = self.last_sync('b1')
        wall = datetime.now(timezone.utc).replace(microsecond=0)
        started = time.monotonic()
        out = hosts['b1'].cli('allow', 'carol', '--agent', 'claude', '--network', self.net)
        version = out['policy']['version']
        times = race({n: (lambda n=n: self.policy_version(n, self.person['bob']) >= version)
                      for n in self.others('b1')})
        self.notified('a policy', started)
        own = race({'b1': lambda: (lambda v: v and v != before and parse_time(v) >= wall)(self.last_sync('b1'))})
        self.measured('policy', times)
        need(not late(own), 'changed goes to every member host of that network, the host that made the change '
             'included (bob\'s last_sync_at advances)', own, before, self.last_sync('b1'))

        # A group change, made by the administrator.
        started = time.monotonic()
        out = hosts['a1'].cli('network', 'group', 'set', '--network', self.net, '--group', 'reviewers',
                              '--person', 'bob')
        version = out.get('version', 1)
        times = race({n: (lambda n=n: self.group_version(n, 'reviewers') >= version) for n in self.others('a1')})
        self.notified('a group change', started)
        self.measured('group', times)

        # A revocation of erin's host.
        started = time.monotonic()
        hosts['a1'].cli('network', 'revoke', '--network', self.net, '--host', self.ids['e1'])
        self.running.remove('e1')
        times = race({n: (lambda n=n: self.ids['e1'] not in self.members(n)) for n in self.others('a1')})
        self.notified('a revocation', started)
        e1.stop()
        self.measured('revocation', times)
        return '; '.join(self.notes)

    def check_version_one(self):
        v1 = getattr(self, 'v1', None)
        need(v1 is not None, 'needs the version 1 watcher')
        need(not v1.changed(), 'Version 1 connections never receive 0x05', v1.changed())
        need(v1.open, 'the version 1 connection is kept through changes', v1.closed_at)
        need(CHANGED not in v1.kinds(), 'Version 1 connections never receive 0x05', v1.kinds())
        status, view = coord_sync(self.coord, seed_of(self.hosts['w1']), self.certs, self.net)
        need(status == 200 and isinstance(view, dict), 'a version 1 host still syncs at its interval', status, view)
        ids = {m['host_id'] for m in view.get('members', [])}
        need(self.ids['a2'] in ids and self.ids['e1'] not in ids and 'reviewers' in json.dumps(view.get('groups')),
             'an interval sync serves the changes a version 1 host was not notified of', sorted(ids))
        return f'v1 frames {v1.kinds()}'

    def check_plain_sync(self):
        need(getattr(self, 'v2', None) and self.v2.open, 'needs the version 2 watcher')
        self.quiet(self.v2)
        started = time.monotonic()
        for name in ('b1', 'd1', 'c1'):
            out = self.hosts[name].cli('network', 'sync', self.net)
            need(out.get('last_sync_error') is None, f'{name} syncs', out)
        seed = seed_of(self.hosts['w1'])
        for address in ('127.0.0.1:9', ''):
            status, _ = coord_sync(self.coord, seed, self.certs, self.net, address)
            need(status == 200, 'a sync updating only the address', status)
        # A negative observation needs a bounded wait: a changed would arrive within a round trip.
        time.sleep(1.5)
        frames = self.v2.changed(started)
        need(not frames, 'Plain syncs that only update an address or candidates are not changes: no changed',
             [round(t - started, 2) for t, _ in frames])

    def check_coalescing(self):
        need(getattr(self, 'v2', None) and self.v2.open, 'needs the version 2 watcher')
        self.quiet(self.v2)
        a1 = self.hosts['a1']
        count = 8
        spans = [None] * count

        # Changes from several hosts at once: group changes by the administrator, and policies.
        commands = [('a1', ('network', 'group', 'set', '--network', self.net, '--group', f'burst{i}', '--person',
                            'carol')) for i in range(count - 3)]
        commands += [(n, ('allow', 'everyone', '--agent', 'burst', '--network', self.net)) for n in ('b1', 'c1', 'd1')]
        before = {n: self.policy_version('a1', self.person[label]) for n, label in
                  (('b1', 'bob'), ('c1', 'carol'), ('d1', 'dave'))}

        def change(i):
            name, args = commands[i]
            begin = time.monotonic()
            result = self.hosts[name].run(*args)
            spans[i] = (begin, time.monotonic(), result.returncode, result.stderr[-300:])
        burst_start = time.monotonic()
        threads = [threading.Thread(target=change, args=(i,)) for i in range(count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        failed = [s for s in spans if s[2] != 0]
        need(not failed, 'the burst of group changes succeeds', failed)
        labels = {'b1': 'bob', 'c1': 'carol', 'd1': 'dave'}

        def complete(n):
            return (all(self.group_version(n, f'burst{i}') for i in range(count - 3))
                    and all(self.policy_version(n, self.person[labels[o]]) > before[o] for o in labels if o != n))
        times = race({n: (lambda n=n: complete(n)) for n in self.others()})
        need(not late(times), 'a burst of changes still reaches every member within 2 seconds of its end '
             '(later changes coalesced into the next changed, not lost)', times)
        time.sleep(COALESCE * 2)  # let a coalesced notification that is due arrive
        frames = [t for t, payload in self.v2.changed(burst_start) if payload == self.net.encode()]
        gaps = [round(b - a, 3) for a, b in zip(frames, frames[1:])]
        need(frames, 'the burst produces changed', frames)
        need(all(g >= COALESCE - JITTER for g in gaps), 'at most one changed per network per connection per '
             '250 milliseconds', gaps)
        need(len(frames) <= count, 'later changes are coalesced', len(frames), count)
        last_start = max(s[0] for s in spans)
        need(frames[-1] >= last_start, 'the last change of a burst is notified (coalesced into the next changed)',
             round(frames[-1] - burst_start, 3), round(last_start - burst_start, 3))
        return (f'{count} changes in {max(s[1] for s in spans) - burst_start:.2f}s gave {len(frames)} changed, '
                f'gaps {gaps}')

    def check_no_listener(self):
        d1 = self.hosts['d1']
        need(not d1.listen, 'd1 runs without --peer-listen')
        started = time.monotonic()
        out = self.hosts['a1'].cli('network', 'group', 'set', '--network', self.net, '--group', 'quiet',
                                   '--person', 'dave')
        version = out.get('version', 1)
        times = race({'d1': lambda: self.group_version('d1', 'quiet') >= version})
        need(not late(times), 'Every host that is a member keeps its relay connection, including hosts without '
             '--peer-listen: notified within 2 seconds', times)
        earlier = {what: t.get('d1') for what, t in getattr(self, 'latency', {}).items()}
        return f"d1 {times['d1']}s; earlier {earlier}"

    def check_fallback_allow(self):
        a1, f1 = self.hosts['a1'], self.hosts['f1']
        self.ids['f1'] = f1.start()['id']
        token = self.invite('frank')
        # Hold alice's relay slot, so the coordinator's changed for frank's join goes here, not to alice.
        hold = Holder(self.coord, seed_of(a1), self.certs)
        joined = f1.cli('join', token)
        need(joined['person'] and joined['person'].get('bound'), 'frank joins bound', joined)
        self.person['frank'] = joined['person']['person_id']
        knew = self.ids['f1'] in self.members('a1')
        result = a1.run('allow', 'frank', '--agent', 'fx', '--network', self.net)
        held = len(hold.changed())
        displaced = hold.close()
        self.running.append('f1')
        need(result.returncode == 0, '`allow` syncs the network once when a person label does not resolve, and '
             'resolves again before failing', result.stdout[-400:], result.stderr[-400:])
        out = json.loads(result.stdout)
        need(out.get('principal') == f"person:{self.person['frank']}", 'allow resolves the new label', out)
        return (f'alice knew frank before the allow: {knew} (held slot got {held} changed, '
                f'{displaced} connections)')

    def check_fallback_directory(self):
        a1, b1, g1 = self.hosts['a1'], self.hosts['b1'], self.hosts['g1']
        # A second network, so that g1 is already a known host to bob's host when it joins the first: bob's host
        # then answers its directory query with 403 until it syncs, rather than failing the handshake.
        side = a1.cli('network', 'create', 'side', '--as', 'alice', '--coordinator', self.coord.address,
                      '--coordinator-key', self.coord_key)['id']
        self.ids['g1'] = g1.start()['id']
        self.join('g1', 'grace', network=side)
        self.join('b1', 'bob', network=side)
        self.all_see([self.ids['g1'], self.ids['b1']], network=side, names=['a1', 'b1', 'g1'], timeout=70)
        token = self.invite('grace')
        hold = Holder(self.coord, seed_of(b1), self.certs)  # bob's host is not notified of grace's join
        # Once bob's host has reconnected and been displaced again, its next attempt waits out its backoff.
        try:
            wait_for(lambda: len(hold.connections) >= 2, timeout=5, message='bob\'s host reconnecting')
        except AssertionError:
            pass
        g1.cli('join', token)
        joined = time.monotonic()
        result = {}

        def refresh():
            begin = time.monotonic()
            result['knew'] = self.ids['g1'] in self.members('b1')
            result['response'] = g1.directory(self.net, refresh=True)
            result['seconds'] = round(time.monotonic() - begin, 2)
        thread = threading.Thread(target=refresh)
        thread.start()
        # Bob's host learns of grace's join 0.7 seconds later, as a notification would, so a retry 2 seconds
        # after a 403 finds it.
        time.sleep(max(0.0, joined + 0.7 - time.monotonic()))
        b1.cli('network', 'sync', self.net)
        thread.join(timeout=30)
        hold.close()
        self.running.append('g1')
        status, body = result.get('response', (None, None))
        need(status == 200, 'POST /v1/directory/refresh returns the directory', status, body)
        hosts = {h['host_id']: h for h in body['hosts']}
        need(hosts.get(self.ids['b1'], {}).get('state') == 'ok', 'A synchronous directory refresh retries a host '
             'that answered 403 once, 2 seconds later', hosts.get(self.ids['b1']), result.get('seconds'))
        need(hosts.get(self.ids['a1'], {}).get('state') == 'ok', 'alice\'s host answered too',
             hosts.get(self.ids['a1']))
        return f"refresh took {result['seconds']}s; bob's host knew grace when it began: {result['knew']}"

    def check_fallback_unknown(self):
        b1, h1 = self.hosts['b1'], self.hosts['h1']
        # A brand-new host shares no network with bob's host, so until bob's host syncs it fails the new host's
        # peer authentication instead of answering 403.
        self.ids['h1'] = h1.start()['id']
        token = self.invite('henry')
        hold = Holder(self.coord, seed_of(b1), self.certs)  # bob's host is not notified of henry's join
        try:
            wait_for(lambda: len(hold.connections) >= 2, timeout=5, message='bob\'s host reconnecting')
        except AssertionError:
            pass
        h1.cli('join', token)
        joined = time.monotonic()
        result = {}

        def refresh():
            begin = time.monotonic()
            result['knew'] = self.ids['h1'] in self.members('b1')
            result['response'] = h1.directory(self.net, refresh=True)
            result['seconds'] = round(time.monotonic() - begin, 2)
        thread = threading.Thread(target=refresh)
        thread.start()
        time.sleep(max(0.0, joined + 0.7 - time.monotonic()))
        b1.cli('network', 'sync', self.net)
        thread.join(timeout=30)
        hold.close()
        self.running.append('h1')
        status, body = result.get('response', (None, None))
        need(status == 200, 'POST /v1/directory/refresh returns the directory', status, body)
        entry = {h['host_id']: h for h in body['hosts']}.get(self.ids['b1'])
        need((entry or {}).get('state') == 'ok', 'A synchronous directory refresh retries a host once, 2 seconds '
             'later, when it is a current member in this host\'s map but its connection failed authentication',
             entry, result.get('seconds'))
        return f"refresh took {result['seconds']}s; bob's host knew henry when it began: {result['knew']}"

    def check_fallback_sibling(self):
        a2, a3 = self.hosts['a2'], self.hosts['a3']
        need('a2' in self.running, 'needs alice\'s second host, bound in the binding case')
        helper = a2.cli('agent', 'register', '--name', 'helper', '--owner', 'alice')
        self.helper = helper
        self.ids['a3'] = a3.start()['id']
        # Alice's third machine joins without a person; her second host learns of the join.
        self.join('a3', 'alice', person=False)
        self.running.append('a3')
        wait_for(lambda: self.ids['a3'] in self.members('a2'), timeout=40, message='a3 known to a2')
        target = a3.config / 'peerspan'
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in ('person_ed25519', 'person_ed25519.pub'):
            shutil.copy2(self.hosts['a1'].config / 'peerspan' / name, target / name)
        # Alice's second host is not notified of the binding, so it answers a3 with [] rather than self.
        hold = Holder(self.coord, seed_of(a2), self.certs)
        try:
            wait_for(lambda: len(hold.connections) >= 2, timeout=5, message='a2 reconnecting')
        except AssertionError:
            pass
        bound = a3.cli('network', 'bind', '--network', self.net)
        need(bound.get('person_id') == self.person['alice'], 'network bind binds a3 to alice', bound)
        started = time.monotonic()
        result = {}

        def refresh():
            begin = time.monotonic()
            result['knew'] = self.members('a2')[self.ids['a3']].get('person_id') == self.person['alice']
            result['response'] = a3.directory(self.net, refresh=True)
            result['seconds'] = round(time.monotonic() - begin, 2)
        thread = threading.Thread(target=refresh)
        thread.start()
        # Alice's second host learns of the binding 0.7 seconds later, so a retry 2 seconds later finds it.
        time.sleep(max(0.0, started + 0.7 - time.monotonic()))
        a2.cli('network', 'sync', self.net)
        thread.join(timeout=30)
        hold.close()
        status, body = result.get('response', (None, None))
        need(status == 200, 'POST /v1/directory/refresh returns the directory', status, body)
        mine = [a for a in body['agents'] if a['agent_id'] == helper['id']]
        need(mine and any(z.get('kind') == 'self' for z in mine[0]['authorizations']),
             'A synchronous directory refresh retries a host once, 2 seconds later, when this host\'s map shows '
             'it bound to this host\'s own person but its answer has no self entry', mine,
             {h['host_id']: h['state'] for h in body['hosts']}.get(self.ids['a2']), result.get('seconds'))
        return (f"refresh took {result['seconds']}s; alice's second host knew the binding when it began: "
                f"{result['knew']}")

    def check_fallback_send(self):
        c1, f1 = self.hosts['c1'], self.hosts['f1']
        need('frank' in self.person, 'needs frank, joined by the allow fallback')
        fx = f1.cli('agent', 'register', '--name', 'fx', '--owner', 'frank')
        wait_for(lambda: self.ids['f1'] in self.members('c1'), timeout=40, message='frank\'s host known to carol')
        need(self.policy_version('c1', self.person['frank']) == 0, 'carol\'s host holds no policy of frank yet')
        hold = Holder(self.coord, seed_of(c1), self.certs)  # carol's host is not notified of frank's policy
        out = f1.cli('allow', 'carol', '--agent', 'fx', '--network', self.net)
        version = out['policy']['version']
        knew = self.policy_version('c1', self.person['frank'])
        result = c1.run('send', 'frank/fx', 'right after the allow', '--network', self.net)
        hold.close()
        need(result.returncode == 0, 'Before refusing a send by address with not_authorized, the daemon syncs the '
             'network once, so it cites the newest policy', result.stdout[-400:], result.stderr[-400:])
        record = json.loads(result.stdout)
        need(record['request'].get('policy') == {'person_id': self.person['frank'], 'version': version}
             and record['request']['target_agent_id'] == fx['id'],
             'the send cites the policy submitted moments earlier', record['request'].get('policy'), version)
        rid = record['request']['request_id']

        def settled():
            status, r = c1.call('GET', f"/v1/outbound/{self.ids['f1']}/{rid}")
            return r if status == 200 and r['state'] != 'unknown' else None
        final = settled() if record['state'] != 'unknown' else wait_for(settled, timeout=40, message='outcome')
        need((final or record)['state'] == 'accepted', 'the send is accepted', final or record)
        return f'carol\'s host held frank\'s policy version {knew or None} when the send began'

    def check_onward(self):
        a1, b1, c1 = self.hosts['a1'], self.hosts['b1'], self.hosts['c1']
        ids, agent, person = self.ids, self.agent, self.person
        notes = []
        # Alice's and bob's hosts also share a network with a lower ID than the team network, which carol is
        # not in, so link 0 must name the network the address resolved in, not the lowest shared one.
        lowest = None
        if self.net > 'net_1':  # otherwise a lower ID is too unlikely to find quickly
            for attempt in range(24):
                candidate = a1.cli('network', 'create', f'low{attempt}', '--as', 'alice', '--coordinator',
                                   self.coord.address, '--coordinator-key', self.coord_key)['id']
                if candidate < self.net:
                    lowest = candidate
                    break
        if lowest:
            self.join('b1', 'bob', network=lowest)
            wait_for(lambda: ids['b1'] in self.members('a1', lowest), timeout=40,
                     message='bob in the lower network')
        else:
            notes.append(f'no lower shared network made (team network {self.net[:12]}...)')
        # bob allows alice without onward delegation. carol allows tasks only for alice, the originator; bob gets
        # messages only (so that carol's agent is listed in bob's directory and the address resolves). A forward
        # by address needs no authorization of the forwarder's own, and cites carol's policy.
        version = b1.cli('allow', 'alice', '--agent', 'claude', '--network', self.net)['policy']['version']
        c1.cli('allow', 'alice', '--agent', 'claude', '--network', self.net)
        cv = c1.cli('allow', 'bob', '--agent', 'claude', '--no-tasks', '--network', self.net)['policy']['version']
        wait_for(lambda: self.policy_version('a1', person['bob']) >= version, timeout=40, message='bob\'s policy')
        wait_for(lambda: self.policy_version('b1', person['carol']) >= cv, timeout=40, message='carol\'s policy')
        ta = self.setup_session('a1', agent['a1'])['token']
        tb = self.setup_session('b1', agent['b1'])['token']
        tc = self.setup_session('c1', agent['c1'])['token']

        def delegate(token, host, body, expect=200, rule='delegation'):
            status, value = adapter_call(host, token, 'POST', '/adapter/v1/delegations', body, timeout=20)
            need(status == expect, rule, status, value)
            return value

        def nothing(token, host, tid, rule):
            status, value = adapter_call(host, token, 'GET', f'/adapter/v1/delegations/{tid}')
            need(status == 404, rule + ': nothing persisted', status, value)

        def link0(record, tid, depth, rule):
            chain = record.get('delegation')
            need(isinstance(chain, list) and len(chain) == 1, f'{rule}: a nonzero depth creates link 0', record)
            link = chain[0]
            need(LINK_KEYS <= set(link), 'a link has the delegation chain contract\'s fields', link)
            expected = {'index': 0, 'previous': 'none', 'depth': depth, 'principals': ['network'],
                        'issuer_host_id': ids['a1'], 'audience_host_id': ids['b1'], 'task_id': tid,
                        'network_id': self.net, 'originator_agent_id': agent['a1']['id']}
            wrong = {k: (link.get(k), v) for k, v in expected.items() if link.get(k) != v}
            need(not wrong, f'{rule}: link 0 with that depth, principals network, the session\'s agent as '
                 'originator, and the network the address resolved in (not the lowest network the hosts share) '
                 '(field: (got, expected))', wrong)
            return link

        def claim(token, host, tid):
            def next_task():
                status, value = adapter_call(host, token, 'POST', '/adapter/v1/tasks/next', {})
                need(status == 200, 'tasks/next', status, value)
                return value if value and value['task']['task_id'] == tid else None
            return wait_for(next_task, timeout=40, message=f'{tid} handed off')

        def act(token, host, tid, op, body=None):
            status, value = adapter_call(host, token, 'POST', f'/adapter/v1/tasks/{tid}/{op}', body or {})
            need(status == 200, f'{op} {tid}', status, value)
            return value

        # The 400 cases: with a route destination, with parent_task_id, and out of range.
        a1.cli('adapter', 'route', 'add', '--adapter', self.adapter_id(a1, ta), '--name', 'bob-route', '--peer',
               ids['b1'], '--agent', agent['b1']['id'], '--expires-in', '30m', '--action', 'task.submit')
        for body, rule in (
                ({'destination': 'bob-route', 'delegation_depth': 1}, 'delegation_depth with destination is 400'),
                ({'to': 'bob/claude', 'delegation_depth': 3}, 'delegation_depth is 0 to 2'),
                ({'to': 'bob/claude', 'delegation_depth': -1}, 'delegation_depth is 0 to 2')):
            tid = task_id()
            delegate(ta, a1, {**body, 'task_id': tid, 'input': 'refused'}, 400, rule)
            nothing(ta, a1, tid, rule)
        # An explicit 0 is accepted with destination, as the default.
        tid = task_id()
        routed = delegate(ta, a1, {'destination': 'bob-route', 'delegation_depth': 0, 'task_id': tid,
                                   'input': 'through the route'}, 200,
                          'an explicit delegation_depth 0 is accepted with destination')
        need(not routed.get('delegation'), 'the route delegation carries no link (route depth 0)', routed)

        # Depth 0, explicitly: no chain.
        tid = task_id()
        record = delegate(ta, a1, {'to': 'bob/claude', 'task_id': tid, 'input': 'no hops', 'delegation_depth': 0})
        need(not record.get('delegation'), 'delegation_depth 0 creates no link', record)
        need(record.get('to') == 'bob/claude', 'the record shows to as given', record)
        claim(tb, b1, tid)
        act(tb, b1, tid, 'accept')
        delegate(tb, b1, {'to': 'carol/claude', 'parent_task_id': tid, 'task_id': task_id(), 'input': 'onward'}, 403, 'a task without a chain cannot be passed on')
        act(tb, b1, tid, 'complete', {'status': 'succeeded', 'output': 'done'})

        # Depth 1, but bob has not allowed onward delegation.
        tid = task_id()
        record = delegate(ta, a1, {'to': 'bob/claude', 'task_id': tid, 'input': 'one hop', 'delegation_depth': 1})
        link0(record, tid, 1, 'delegation_depth 1')
        handoff = claim(tb, b1, tid)
        need(handoff.get('delegable') is False, 'The receiving owner must still allow onward delegation: without '
             'allow --delegate the task is not delegable', handoff.get('delegable'))
        act(tb, b1, tid, 'accept')
        child = task_id()
        delegate(tb, b1, {'to': 'carol/claude', 'parent_task_id': tid, 'task_id': child, 'input': 'onward'}, 403,
                 'a forward of a task that is not delegable is refused')
        nothing(tb, b1, child, 'a refused forward')
        act(tb, b1, tid, 'complete', {'status': 'succeeded', 'output': 'done'})

        # bob allows onward delegation; a depth-1 task is forwarded by address.
        version = b1.cli('allow', 'alice', '--agent', 'claude', '--delegate', '--network', self.net)['policy']['version']
        wait_for(lambda: self.policy_version('a1', person['bob']) >= version, timeout=40, message='bob\'s policy')
        parent = task_id()
        record = delegate(ta, a1, {'to': 'bob/claude', 'task_id': parent, 'input': 'review, pass part on',
                                   'delegation_depth': 1})
        first = link0(record, parent, 1, 'delegation_depth 1')
        handoff = claim(tb, b1, parent)
        need(handoff.get('delegable') is True and handoff['task'].get('delegation') == record['delegation'],
             'the receiver gets link 0 and the task is delegable under allow --delegate', handoff)
        act(tb, b1, parent, 'accept')
        child = task_id()
        delegate(tb, b1, {'to': 'carol/claude', 'parent_task_id': parent, 'task_id': child, 'input': 'x',
                          'delegation_depth': 1}, 400, 'delegation_depth with parent_task_id is 400')
        nothing(tb, b1, child, 'delegation_depth with parent_task_id')
        forward = delegate(tb, b1, {'to': 'carol/claude', 'parent_task_id': parent, 'task_id': child,
                                    'input': 'your part', 'delegation_depth': 0}, 200,
                           'a forward by the receiver by address (an explicit delegation_depth 0 accepted with '
                           'parent_task_id), with only the originator authorized by carol')
        need((forward['request'].get('policy') or {}).get('person_id') == person['carol']
             and forward['request'].get('grant_id') is None and forward['request'].get('self') is None,
             'A forward by address cites the target owner\'s policy when the originator\'s person is not the '
             'target\'s; the forwarder does not choose from its directory', forward['request'])
        need(forward.get('to') == 'carol/claude'
             and forward.get('parent') == {'sender_host_id': ids['a1'], 'task_id': parent},
             'the forward record shows to and its parent', forward)
        chain = forward.get('delegation') or []
        need(len(chain) == 2 and chain[0] == first, 'the forward carries the whole chain plus the new link', chain)
        link = chain[1]
        need(link['index'] == 1 and link['issuer_host_id'] == ids['b1'] and link['audience_host_id'] == ids['c1']
             and link['depth'] == 0 and link['principals'] == ['network'] and link['task_id'] == child
             and link['originator_agent_id'] == agent['a1']['id'], 'the new link copies principals and the '
             'originator, with depth one less', link)
        settled = wait_for(lambda: (lambda s, r: r if s == 200 and r.get('submit_state') != 'unknown' else None)(
            *adapter_call(b1, tb, 'GET', f'/adapter/v1/delegations/{child}')), timeout=40, message='forward outcome')
        need(settled['submit_state'] == 'accepted', 'the forward is accepted by the final receiver', settled)
        received = claim(tc, c1, child)
        chain = received['task'].get('delegation') or []
        need(len(chain) == 2 and chain[0]['issuer_host_id'] == ids['a1'] and chain[1]['issuer_host_id'] == ids['b1'],
             'carol\'s task carries a two-link chain originating at alice', chain)
        need(received.get('originator_person_id') == person['alice']
             and (received['task'].get('origin') or {}).get('agent_id') == agent['b1']['id'],
             'the originator is alice, the origin bob\'s agent', received)
        act(tc, c1, child, 'accept')
        act(tc, c1, child, 'complete', {'status': 'succeeded', 'output': 'carol\'s part'})
        act(tb, b1, parent, 'complete', {'status': 'succeeded', 'output': 'with carol\'s part'})

        # A forward to an agent of the originator's own person cites self.
        if getattr(self, 'helper', None):
            av = a1.cli('allow', 'bob', '--agent', 'helper', '--no-tasks', '--network', self.net)['policy']['version']
            wait_for(lambda: self.policy_version('b1', person['alice']) >= av, timeout=40,
                     message='alice\'s policy at bob\'s host')
            again = task_id()
            delegate(ta, a1, {'to': 'bob/claude', 'task_id': again, 'input': 'pass to my helper',
                              'delegation_depth': 1})
            claim(tb, b1, again)
            act(tb, b1, again, 'accept')
            onward = delegate(tb, b1, {'to': 'alice/helper', 'parent_task_id': again, 'task_id': task_id(),
                                       'input': 'helper part'}, 200, 'a forward by address to the originator\'s '
                              'own person')
            need(onward['request'].get('self') == {'person_id': person['alice']}
                 and onward['request'].get('policy') is None and onward['request'].get('grant_id') is None,
                 'A forward by address cites self when the originator host\'s bound person is the target host\'s '
                 'bound person', onward['request'])
            notes.append('self-cited forward')

        # Depth 2.
        tid = task_id()
        link0(delegate(ta, a1, {'to': 'bob/claude', 'task_id': tid, 'input': 'two hops', 'delegation_depth': 2}),
              tid, 2, 'delegation_depth 2')

        # MCP delegate_task with to and delegation_depth, through the real adapter.
        secret = self.secret_of(a1, ta)
        channel = Channel(self.node, self.script, a1, secret, self.root / 'mcp-alice')
        self.channels.append(channel)
        failed, submitted = tool(channel, 'delegate_task', {'to': 'bob/claude', 'input': 'from mcp',
                                                            'delegation_depth': 1})
        need(not failed and isinstance(submitted, dict) and submitted.get('task_id'),
             'MCP delegate_task accepts delegation_depth with to', submitted)
        status, record = adapter_call(a1, ta, 'GET', f"/adapter/v1/delegations/{submitted['task_id']}")
        need(status == 200, 'the MCP delegation is recorded', status, record)
        link0(record, submitted['task_id'], 1, 'MCP delegate_task delegation_depth 1')
        notes.append('depth 0/1/2, forward by address, MCP')
        return '; '.join(notes)

    def adapter_id(self, host, token):
        return instance_for(host, token)['adapter']['id']

    def secret_of(self, host, token):
        return self.secrets[token]

    # --- the pairing ---------------------------------------------------------------------------------------

    def run(self):
        x, y = self.x, self.y
        self.coord_key = self.coord.start()['public_key']
        for name, binary, listen in (('a1', x, True), ('b1', y, True), ('c1', x, True), ('d1', y, False),
                                     ('w1', x, True), ('w2', y, True)):
            self.host(name, binary, listen)
        for name, binary in (('e1', y), ('a2', y), ('f1', y), ('g1', x), ('a3', x), ('h1', y)):
            self.host(name, binary)
        self.ids = {n: self.hosts[n].start()['id'] for n in ('a1', 'b1', 'c1', 'd1', 'w1', 'w2')}
        created = self.hosts['a1'].cli('network', 'create', 'team', '--as', 'alice', '--coordinator',
                                       self.coord.address, '--coordinator-key', self.coord_key)
        self.net = created['id']
        need(created['person'] and created['person'].get('bound'), 'create binds alice', created)
        self.person = {'alice': created['person']['person_id']}
        self.running = ['a1']
        for name, label in (('b1', 'bob'), ('c1', 'carol'), ('d1', 'dave')):
            self.person[label] = self.join(name, label)['person']['person_id']
            self.running.append(name)
        for name in ('w1', 'w2'):
            self.join(name, name, person=False)
            self.running.append(name)
        self.all_see([self.ids[n] for n in self.running])
        # The watchers' daemons stop; their keys stay members, observed through raw relay connections.
        for name in ('w1', 'w2'):
            self.hosts[name].stop()
            self.running.remove(name)
        self.agent = {n: self.hosts[n].cli('agent', 'register', '--name', 'claude', '--owner', label)
                      for n, label in (('a1', 'alice'), ('b1', 'bob'), ('c1', 'carol'))}
        self.secrets = {}

        self.section('version 2 negotiation', self.check_negotiation)
        self.section('changes reach members', self.check_changes)
        self.section('version 1 host', self.check_version_one)
        self.section('plain sync', self.check_plain_sync)
        self.section('coalescing', self.check_coalescing)
        self.section('no --peer-listen', self.check_no_listener)
        self.section('fallback: allow by a new label', self.check_fallback_allow)
        self.section('fallback: directory refresh retrying 403', self.check_fallback_directory)
        self.section('fallback: directory refresh retrying an authentication failure', self.check_fallback_unknown)
        self.section('fallback: directory refresh retrying a sibling without self', self.check_fallback_sibling)
        self.section('fallback: send citing a new policy', self.check_fallback_send)
        self.section('onward hops by address', self.check_onward)

    def save_logs(self, directory):
        target = directory / self.label.replace('/', '-')
        target.mkdir(parents=True, exist_ok=True)
        # A Go coordinator prints every goroutine's stack on SIGQUIT, which shows where a stuck one waits.
        process = self.coord.process
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGQUIT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        for name, h in [*self.hosts.items(), ('coord', self.coord)]:
            try:
                h.logs.seek(0)
                (target / f'{name}.log').write_bytes(h.logs.read())
            except (OSError, ValueError):
                pass

    def close(self):
        try:
            for raw in self.raws:
                raw.close()
            for channel in self.channels:
                try:
                    channel.close()
                except Exception:
                    if channel.process.poll() is None:
                        channel.process.kill()
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()


def run_pairing(coord_binary, x, y, node, label, logs=None):
    with tempfile.TemporaryDirectory(prefix='peerspan-push-') as temporary:
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
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--node', type=Path, required=True, help='Node for the MCP delegate_task case')
    parser.add_argument('--pairing', action='append',
                        help='X/Y, such as Go/Rust: alice\'s and carol\'s hosts run X, bob\'s and dave\'s Y; '
                             'repeatable; default all four')
    parser.add_argument('--logs', type=Path, help='save daemon and coordinator logs of failing pairings here')
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
