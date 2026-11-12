"""Opaque counted UDP and genuine public contact setup for slim fixtures.

No host implementation imports, TLS termination, protocol row edits or authority
construction. The daemon alone signs each contact and verifies its import.
"""
import atexit
import base64
import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from harness import b64url_json, check, parse_time, rfc3339


class CountedUDP:
    """Forward QUIC bytes unchanged, counting both directions and every path."""
    def __init__(self, target):
        self.target = target
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        while self.socket.getsockname()[1] == target[1]:
            self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('127.0.0.1', 0))
        self.address = '127.0.0.1:' + str(self.socket.getsockname()[1])
        self.lock, self.done = threading.Lock(), threading.Event()
        self.routes = {}
        self.received_datagrams = self.received_bytes = 0
        self.returned_datagrams = self.returned_bytes = 0
        self.thread = threading.Thread(target=self._forward, daemon=True)
        self.thread.start()
        atexit.register(self.close)

    def _forward(self):
        try:
            while not self.done.is_set():
                upstreams = {upstream: client for client, upstream in self.routes.items()}
                ready, _, _ = select.select([self.socket, *upstreams], [], [], .02)
                for source in ready:
                    if source is self.socket:
                        data, client = self.socket.recvfrom(65536)
                        with self.lock:
                            self.received_datagrams += 1
                            self.received_bytes += len(data)
                        if client not in self.routes:
                            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            upstream.bind(('127.0.0.1', 0))
                            upstream.connect(self.target)
                            self.routes[client] = upstream
                        try:
                            self.routes[client].send(data)
                        except OSError:
                            pass
                    else:
                        try:
                            data = source.recv(65536)
                        except OSError:
                            continue
                        with self.lock:
                            self.returned_datagrams += 1
                            self.returned_bytes += len(data)
                        self.socket.sendto(data, upstreams[source])
        except OSError:
            pass

    def counts(self):
        with self.lock:
            return (self.received_datagrams, self.received_bytes,
                    self.returned_datagrams, self.returned_bytes)

    def close(self):
        if self.done.is_set():
            return
        self.done.set()
        self.thread.join(timeout=1)
        self.socket.close()
        for upstream in self.routes.values():
            upstream.close()


_LOADED = time.monotonic()  # SLIM_TRACE timestamps only


def refresh_owed_directories(hosts, network_ids):
    """DIR-1: one whole-network on-demand refresh per running host and network.

    The launch contract counts it as the refresh owed for every change made
    before it started, so a later quiet wait cannot be followed by a background
    refresh owed for an earlier step. Callers pass every network their fixture
    participants are in, and still wait for quiet afterwards; no counter or
    carrier is filtered. Only the directory refresh is called: no network view,
    which would also observe provider state.
    """
    def refresh(local):
        for network_id in network_ids:
            began = time.monotonic()
            status, view = local.api('POST', '/v1/directory/refresh?network=' + network_id, {}, timeout=12)
            if os.environ.get('SLIM_TRACE'):
                print(f'  [{local.name}] DIR-1 refresh {time.monotonic() - began:.2f}s at +{began - _LOADED:.1f}s', file=sys.stderr, flush=True)
            check(status == 200 and isinstance(view, dict) and view.get('network_id') == network_id,
                  'DIR-1 whole-network on-demand directory refresh')
    _each_running(hosts, refresh)  # a stopped host owes none


def _each_running(hosts, action):
    """Run ACTION(host) for every running host side by side; a stopped host is skipped."""
    running = [local for local in hosts if getattr(local, 'process', None) is not None]
    with ThreadPoolExecutor(max_workers=max(1, len(running))) as pool:
        for done in [pool.submit(action, local) for local in running]:
            done.result()


def sync_networks(hosts, network_ids):
    """SYNC-1: one explicit POST /v2/networks/{id}/sync per running host and network.

    The spec (section 10, Timing) restarts that network's background interval,
    so its next background sync is at least 60 s later. The sync's own bound
    is 30 s; a stopped peer costs at most 5 s of it."""
    def sync(local):
        for network_id in network_ids:
            began = time.monotonic()
            status, body = local.api('POST', '/v2/networks/' + network_id + '/sync', {}, timeout=35)
            if os.environ.get('SLIM_TRACE'):
                print(f'  [{local.name}] SYNC-1 sync {time.monotonic() - began:.2f}s at +{began - _LOADED:.1f}s', file=sys.stderr, flush=True)
            check(status == 200 and isinstance(body, dict), 'SYNC-1 explicit network sync')
    _each_running(hosts, sync)


def refresh_then_quiet(hosts, network_ids, quiet, state, attempts=3, sync=True):
    """Precondition of a measured no-traffic step: one explicit sync (SYNC-1)
    and then one whole-network directory refresh (DIR-1) per running host,
    then the suite's unchanged QUIET. A change stored after the refresh
    started still owes a refresh (launch contract), so when STATE (the
    suite's complete participant snapshot) changed across refresh and quiet,
    repeat the pass; usually the first pass is the only one. SYNC=False
    leaves out the explicit sync, only for a caller whose daemons just
    started (their first background sync is a full interval away) and whose
    step measures retained local corruption that a sync would repair."""
    for attempt in range(attempts):
        if sync:
            sync_networks(hosts, network_ids)
        before = state()
        refresh_owed_directories(hosts, network_ids)
        quiet()
        if state() == before:
            return
        if os.environ.get('SLIM_TRACE'):
            print(f'  DIR-1 state changed across refresh {attempt + 1}; repeating', file=sys.stderr, flush=True)
    check(False, 'participant state kept changing across SYNC-1/DIR-1 passes')


def peer_address(h):
    return h.counted_peer.address if getattr(h, 'counted_peer', None) else h.peer_address


def configure_terminal_peers(h, issuer):
    """Supported config/restart only after the terminal fixture applications."""
    for local in (h, issuer):
        identity = local.id, local.public_key
        local.counted_peer = CountedUDP(('127.0.0.1', local.peer_port))
        index = local.extra_args.index('--transport-config') + 1
        original = local.extra_args[index]
        config = json.loads(original.read_text())
        config['advertise_quic'] = [local.counted_peer.address]
        path = local.root / 'terminal-transport.json'
        path.write_text(json.dumps(config, separators=(',', ':')))
        path.chmod(0o600)
        local.extra_args[index] = path
        local.restart(kill=True)
        check((local.id, local.public_key) == identity, 'transport restart changed participant identity')


def peer_request(suite, local, remote, method, path, body=None):
    args = [str(suite.probe_bin), '--state', str(local.state), '--address', peer_address(remote),
            '--alpn', 'peerspan-peer/1', '--path', path, '--method', method]
    if body is not None:
        args.append('--body-stdin')
    try:
        result = subprocess.run(args, input=b'' if body is None else json.dumps(body, separators=(',', ':')).encode(),
                                capture_output=True, timeout=15)
    except subprocess.TimeoutExpired:
        check(False, 'genuine normal peer setup exceeded its bounded request')
    check(result.returncode == 0, 'genuine normal peer setup transport failed')
    try:
        reply = json.loads(result.stdout)
    except ValueError:
        check(False, 'genuine normal peer setup returned malformed response')
    check(reply.get('status') == 200 and isinstance(reply.get('body'), dict),
          'genuine authenticated normal peer setup did not return HTTP200')
    return reply['body']


def exchange_current_contacts(suite, h, issuer, network_id, request_deadline=None):
    """Use actual signed short handoffs, authenticated import and retained GET."""
    issued_bounds = []
    views = {}
    for local in (h, issuer):
        status, view = local.api('GET', '/v2/networks/' + network_id, timeout=8)
        check(status == 200, 'current participant network setup observation')
        views[id(local)] = view
    for local, remote in ((h, issuer), (issuer, h)):
        status, issued = local.api('POST', '/v2/networks/' + network_id + '/invitations', {
            'member': 'Transport setup', 'expected_person_public_key': views[id(remote)]['person_public_key'],
            'expires_at': rfc3339(local.now() + timedelta(seconds=65))}, timeout=8)
        check(status == 201, 'genuine contact-only transport handoff failed')
        expires = parse_time(issued['expires_at'])
        if request_deadline is not None:
            check(expires < parse_time(request_deadline), 'short contact handoff exceeds original cleanup deadline')
        issued_bounds.append(issued['expires_at'])
        envelope = b64url_json(issued['invitation'], 'psi2-')
        invitation = json.loads(base64.b64decode(envelope['payload_base64'], validate=True))
        candidates = [contact for contact in invitation['contacts']
                      if contact['host_public_key'] == local.public_key and contact['context_id'] == views[id(local)]['context_id']
                      and json.loads(base64.b64decode(contact['payload_base64'], validate=True))['quic_addresses'] == [peer_address(local)]]
        check(candidates, 'handoff lacks an exact signed current participant contact')
        contact = max(candidates, key=lambda value: int(value['sequence']))
        hints = json.loads(base64.b64decode(contact['payload_base64'], validate=True))
        check(hints['quic_addresses'] == [peer_address(local)] and parse_time(contact['expires_at']) > local.now(),
              'genuine signed contact lacks the counted live QUIC hint')
        imported = peer_request(suite, local, remote, 'POST', '/peer/v2/networks/' + network_id + '/contact', {'contact': contact})
        check(imported == {'contact': contact}, 'authenticated import changed actual signed contact')
        retained = peer_request(suite, local, remote, 'GET', '/peer/v2/networks/' + network_id + '/contacts')
        check(contact in retained['contacts'], 'participant did not retain the actual counted signed hint')
        catalog = peer_request(suite, local, remote, 'GET', '/peer/v2/networks/' + network_id + '/catalog')
        check('catalog' in catalog, 'normal peer catalog200 lacked genuine public catalog')
    return issued_bounds
