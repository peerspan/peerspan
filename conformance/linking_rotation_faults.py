#!/usr/bin/env python3
"""Independent accepted-rotation / failed-following-sync persistence check.

The disposable coordinator's own TLS key is matched by public derivation, never
by a private schema name. Signed proof bytes are forwarded unchanged. Only the
outer unsigned descriptor names this stand-in's actual pinned listening port.
"""

import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import traceback

from linking_backups import rows
from linking_hosts import Ceremony, checked, full_chain, need
from linking_management import network, pending_rotations, rotation_event_count
from linking_readers import FixtureSigner, b64, unb64, wire
from launch_service import Key, host_key
from peer_messaging import available_port


def own_coordinator_seed(runtime, expected):
    candidates = set()
    with sqlite3.connect(runtime.state / 'coord.db') as db:
        for _, _, row in rows(db):
            for value in row:
                if isinstance(value, str):
                    try:
                        value = unb64(value)
                    except ValueError:
                        continue
                if isinstance(value, bytes) and len(value) in (32, 64):
                    for seed in (value[:32], value[-32:]):
                        if b64(FixtureSigner(seed).public) == expected:
                            candidates.add(seed)
    need(len(candidates) == 1, 'one disposable coordinator seed independently derives its CLI-reported public key')
    return candidates.pop()


class RotationFault:
    def __init__(self, runtime, directory, port, signer, client):
        self.runtime, self.client = runtime, client
        self.address = f'127.0.0.1:{port}'
        self.rotation_forwarded = False
        self.failed_syncs = 0
        self.errors = []
        self.trace = []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def handle_request(self):
                try:
                    if 'chunked' in self.headers.get('Transfer-Encoding', '').lower():
                        body = b''
                        while True:
                            count = int(self.rfile.readline().split(b';')[0], 16)
                            if not count:
                                while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                                    pass
                                break
                            body += self.rfile.read(count)
                            self.rfile.read(2)
                    else:
                        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    status, payload = outer.forward(self.command, self.path, body)
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (OSError, http.client.HTTPException):
                    self.close_connection = True

            do_GET = do_POST = do_DELETE = handle_request

        self.server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.server.daemon_threads = True
        cert = directory / 'rotation-fault.cert'
        subprocess.run(['openssl', 'req', '-new', '-x509', '-key', str(signer.pem), '-out', str(cert),
                        '-subj', '/CN=disposable-coordinator-fault', '-days', '1'],
                       check=True, capture_output=True, timeout=10)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert, signer.pem)
        context.set_alpn_protocols(['http/1.1'])
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def forward(self, method, path, body):
        with self.lock:
            if self.rotation_forwarded and method == 'POST' and path.endswith('/sync'):
                self.failed_syncs += 1
                self.trace.append({'method': method, 'path': path, 'status': 503, 'controlled': True})
                return 503, wire({'code': 'unavailable', 'error': 'controlled sync failure after rotation acceptance',
                                  'details': {'request_id': '-', 'stage': '-', 'required_ids': [], 'next': []}})
        raw = socket.create_connection(('127.0.0.1', self.runtime.port), timeout=8)
        tls = self.client.context('http/1.1').wrap_socket(raw)
        connection = http.client.HTTPConnection('127.0.0.1', self.runtime.port, timeout=8)
        connection.sock = tls
        try:
            connection.request(method, path, body or None, {'Content-Type': 'application/json'})
            response = connection.getresponse()
            status, payload = response.status, response.read()
        finally:
            connection.close()
        try:
            value = json.loads(payload)
        except ValueError:
            self.trace.append({'method': method, 'path': path, 'status': status, 'json': False})
            return status, payload
        try:
            submitted = json.loads(body)
        except ValueError:
            submitted = {}
        self.trace.append({'method': method, 'path': path, 'status': status,
                           'response_format': value.get('format') if isinstance(value, dict) else None,
                           'submitted_kinds': sorted({entry.get('kind', '-') for entry in
                               submitted.get('catalog', {}).get('objects', [])})})
        if isinstance(value, dict) and value.get('format') == 2 and isinstance(value.get('network'), dict):
            original_entries = value['catalog']['objects']
            value['network']['coordinator_address'] = self.address
            payload = wire(value)
            need(json.loads(payload)['catalog']['objects'] == original_entries,
                 'fault transport never modifies exact signed catalog body bytes')
            contains_rotation = any(entry.get('kind') == 'rotation' for entry in submitted.get('catalog', {}).get('objects', []))
            if 200 <= status < 300 and method == 'POST' and not path.endswith('/sync') and contains_rotation:
                with self.lock:
                    self.rotation_forwarded = True
        return status, payload

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def check(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    c.b.stop()
    c.c.stop()
    before = network(c.a, c.network)
    events = rotation_event_count(c.a, c.network)
    original_catalog = c.a.public_catalog(c.network)
    keys = c.root / 'transport-fault'
    keys.mkdir()
    signer = Key(keys, own_coordinator_seed(c.runtime, c.coordinator_key))
    client = host_key(c.a, keys)
    old_port = c.runtime.port
    c.runtime.stop()
    result = c.a.run('network', 'rotate-root', c.network, sock=None)
    need(result.returncode != 0, 'unreachable initial rotation retains its approved pending operation')
    pending = pending_rotations(c.a, c.network)
    need(len(pending) == 1, 'exact pending root transition exists before transport fault')
    new_seed = unb64(pending[0]['root_seed'])
    new_public = b64(FixtureSigner(new_seed).public)
    c.a.stop()
    c.runtime.port = available_port()
    c.runtime.start()
    fault = RotationFault(c.runtime, keys, old_port, signer, client)
    try:
        c.a.start()
        view = c.a.cli('network', 'sync', c.network, sock=None)
        if fault.rotation_forwarded and fault.failed_syncs == 0:
            need(view['root_epoch'] == before['root_epoch'] + 1 and not pending_rotations(c.a, c.network),
                 'accepted pending completion installs the root before a separate ordinary sync')
            # A verified accepted rotation response can itself complete the
            # first sync. Exercise the following ordinary operation explicitly.
            view = c.a.cli('network', 'sync', c.network, sock=None)
        (c.root / 'fault-transport-public.json').write_text(json.dumps(
            {'trace': fault.trace, 'rotation_forwarded': fault.rotation_forwarded,
             'failed_syncs': fault.failed_syncs, 'root_epoch': view['root_epoch'],
             'last_sync_error': view['last_sync_error']}, indent=2) + '\n')
        need(fault.rotation_forwarded and fault.failed_syncs > 0,
             'actual rotation response succeeds before a subsequent ordinary sync receives controlled503')
        need(view['root_epoch'] == before['root_epoch'] + 1 and view['last_sync_error'] is not None and
             not pending_rotations(c.a, c.network),
             'failure metadata preserves the accepted current root epoch and completed pending operation')
        with sqlite3.connect(c.a.state / 'host.db') as db:
            seed = bytes(db.execute('SELECT root_seed FROM networks WHERE id=?', (c.network,)).fetchone()[0])
        need(seed == new_seed and b64(FixtureSigner(seed).public) == new_public,
             'accepted public epoch and its exact new private root seed remain atomic after following failure')
        need(all(entry in c.a.public_catalog(c.network)['objects'] for entry in original_catalog['objects']) and
             rotation_event_count(c.a, c.network) == events + 1,
             'subsequent error retains all old signed proofs and one applied root transition')
    finally:
        fault.close()
    c.runtime.stop()
    c.runtime.port = old_port
    c.runtime.start()
    recovered = c.a.cli('network', 'sync', c.network, sock=None)
    need(recovered['root_epoch'] == before['root_epoch'] + 1 and recovered['last_sync_error'] is None and
         rotation_event_count(c.a, c.network) == events + 1,
         'ordinary later recovery clears transport error without applying or signing a second rotation')
    c.no_secrets()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--rust', required=True)
    parser.add_argument('--pair', action='append', choices=('go-go', 'rust-rust'))
    parser.add_argument('--work-dir', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='peerspan-rotation-fault-') as temporary:
        root = args.work_dir or Path(temporary)
        if args.work_dir:
            root.mkdir(parents=True, exist_ok=False)
        failures = 0
        for pair in args.pair or ('go-go', 'rust-rust'):
            c = None
            try:
                c = Ceremony(args, root / pair, *pair.split('-'))
                check(c)
                print('PASS ' + pair + ': accepted root rotation survives later ordinary sync503', flush=True)
            except Exception:
                failures += 1
                traceback.print_exc()
            finally:
                if c:
                    c.close()
        return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())
