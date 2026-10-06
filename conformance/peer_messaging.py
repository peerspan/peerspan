#!/usr/bin/env python3
"""Exercise real Go/Rust peer daemons using isolated state and QUIC fixtures.

Requires built binaries, Python's standard library, and capsule-peer-probe for
raw-wire requests. Private keys used here belong only to disposable hosts.
"""
import argparse
import base64
import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import select
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time

from host_service import Host


def timestamp(seconds=600):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def request_id():
    return 'request_' + secrets.token_hex(16)


def available_port():
    """A loopback port currently free for both UDP (peers) and TCP (coordinator)."""
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1', 0))
            port = udp.getsockname()[1]
            with socket.socket() as tcp:
                try:
                    tcp.bind(('127.0.0.1', port))
                except OSError:
                    continue
            return port
    raise AssertionError('no free loopback port')


# Path to capsule-peer-probe, set by each suite's main.
PROBE = None


def set_probe(path):
    global PROBE
    PROBE = str(path)


class PeerHost(Host):
    def __init__(self, binary, state):
        self.port = available_port()
        self.address = f'127.0.0.1:{self.port}'
        super().__init__(binary, state, ('--peer-listen', self.address))

    def configure(self, other, identity, address=None):
        return self.cli('peer', 'add', '--id', identity['id'], '--public-key', identity['public_key'],
                        '--address', address or other.address)

    def grant(self, identity, agent, allow=True, size=65536, expiration=None):
        args = ['grant', 'create', '--peer', identity['id'], '--agent', agent['id'],
                '--expires-at', expiration or timestamp(1200), '--max-message-bytes', str(size)]
        if allow:
            args.append('--allow-disconnected')
        return self.cli(*args)

    def submit(self, identity, agent, grant, content='hello', rid=None, deadline=None):
        return self.cli('message', 'send', '--peer', identity['id'], '--agent', agent['id'],
                        '--grant', grant['id'], '--deadline', deadline or timestamp(),
                        '--content', content, '--request', rid or request_id())


def fixture_context(host, temporary=None):
    """A raw-wire client identity for this disposable host, using its real key."""
    connection = sqlite3.connect(host.state / 'host.db')
    try:
        key = connection.execute('SELECT private_key FROM identity').fetchone()[0]
    finally:
        connection.close()
    return {'seed_hex': bytes(key[:32]).hex()}


def wire(host, context, method, path, body=None, raw=None):
    """Send one peer request through capsule-peer-probe, without pin checks."""
    assert PROBE, 'set_probe() was not called'
    payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
    if isinstance(payload, str):
        payload = payload.encode()
    args = [PROBE, '--seed-hex', context['seed_hex'], '--address', f'127.0.0.1:{host.port}',
            '--method', method, '--path', path]
    if payload is not None:
        args.append('--body-stdin')
    result = subprocess.run(args, input=payload, capture_output=True, timeout=15)
    if result.returncode != 0:
        raise OSError('probe failed: ' + result.stderr.decode(errors='replace').strip())
    value = json.loads(result.stdout)
    return value['status'], value['body']


class DropResponse:
    """Opaque UDP proxy that drops the receiver's packets once it commits a message.

    QUIC handshake and request packets pass untouched. SQLite observation belongs
    to the test harness only and makes this an actual lost-receipt scenario.
    """
    def __init__(self, receiver, rid):
        self.receiver, self.rid = receiver, rid
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(('127.0.0.1', 0))
        self.upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upstream.connect(('127.0.0.1', self.receiver.port))
        self.address = f'127.0.0.1:{self.client.getsockname()[1]}'
        self.failed = None
        self.dropped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def committed(self):
        connection = sqlite3.connect(self.receiver.state / 'host.db')
        try:
            return connection.execute('SELECT COUNT(*) FROM received_messages WHERE request_id = ?',
                                      (self.rid,)).fetchone()[0] > 0
        finally:
            connection.close()

    def run(self):
        sender = None
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([self.client, self.upstream], [], [], 0.2)
                if self.client in ready:
                    data, sender = self.client.recvfrom(65535)
                    self.upstream.send(data)
                if self.upstream in ready:
                    try:
                        data = self.upstream.recv(65535)
                    except ConnectionRefusedError:
                        continue
                    if self.committed():
                        self.dropped.set()
                        return
                    if sender is not None:
                        self.client.sendto(data, sender)
        except Exception as error:
            self.failed = error
        finally:
            self.client.close()
            self.upstream.close()

    def close(self):
        self.thread.join(timeout=20)
        assert not self.thread.is_alive()
        assert self.failed is None, self.failed
        assert self.dropped.is_set(), 'relay did not observe acceptance before dropping response'


def check(sender_binary, receiver_binary, label):
    with tempfile.TemporaryDirectory(prefix='capsule-peers-') as directory:
        temporary = Path(directory)
        sender, receiver = PeerHost(sender_binary, temporary / 'sender'), PeerHost(receiver_binary, temporary / 'receiver')
        stranger = PeerHost(sender_binary, temporary / 'stranger')
        try:
            a, b, c = sender.start(), receiver.start(), stranger.start()
            sender.configure(receiver, b)
            receiver.configure(sender, a)
            sa = sender.cli('agent', 'register', '--name', 'bob', '--owner', 'bob')
            ra = receiver.cli('agent', 'register', '--name', 'alice', '--owner', 'alice')
            other = receiver.cli('agent', 'register', '--name', 'other', '--owner', 'alice')
            grant = receiver.grant(a, ra)
            assert sender.cli('peer', 'list')[0]['id'] == b['id']
            assert receiver.cli('grant', 'list')[0] == grant
            context = fixture_context(sender, temporary)

            out = sender.submit(b, ra, grant)
            assert out['state'] == 'accepted', out
            receipt = out['receipt']
            assert receipt['sender_host_id'] == a['id'] and receipt['receiver_host_id'] == b['id']
            assert receipt['target_agent_id'] == ra['id']
            assert sender.cli('message', 'inspect', '--peer', b['id'], out['request']['request_id']) == out
            assert wire(receiver, context, 'GET', '/peer/v1/receipts/' + out['request']['request_id'])[1] == receipt
            assert len(receiver.cli('message', 'list')) == 1

            # Retry the actual wire operation, bypassing the sender's accepted shortcut.
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                retries = list(executor.map(lambda _: wire(receiver, context, 'POST', '/peer/v1/messages', out['request']), range(6)))
            assert all(status == 200 and value == receipt for status, value in retries)
            changed = dict(out['request'], content='changed')
            assert wire(receiver, context, 'POST', '/peer/v1/messages', changed)[0] == 409
            assert len(receiver.cli('message', 'list')) == 1
            assert len([event for event in receiver.cli('activity') if event['kind'] == 'message.accepted']) == 1

            # Trust is separate from access, and grants are directional.
            reverse = receiver.submit(a, sa, grant)
            assert reverse['state'] == 'rejected', reverse
            assert sender.cli('message', 'list') == []
            assert sender.submit(b, other, grant)['state'] == 'rejected'
            closed = receiver.grant(a, ra, allow=False)
            assert sender.submit(b, ra, closed)['state'] == 'rejected'
            small = receiver.grant(a, ra, size=3)
            assert sender.submit(b, ra, small, content='éé')['state'] == 'rejected'
            assert sender.submit(b, ra, grant, deadline=timestamp(-1))['state'] == 'rejected'
            assert sender.submit(b, ra, grant, deadline=timestamp(5000))['state'] == 'rejected'
            soon = receiver.grant(a, ra, expiration=timestamp(1))
            time.sleep(1.1)
            assert sender.submit(b, ra, soon)['state'] == 'rejected'

            # The peer surface cannot reach any local administrative route.
            for path in ['/v1/host', '/v1/agents', '/v1/peers', '/v1/grants', '/v1/messages', '/v1/activity']:
                assert wire(receiver, context, 'GET', path)[0] == 404, path
            for body in [dict(out['request'], request_id=request_id(), unknown=True),
                         dict(out['request'], request_id=request_id(), content=None),
                         dict(out['request'], request_id='invalid'),
                         dict(out['request'], request_id=request_id(), content='x' * 65537)]:
                assert wire(receiver, context, 'POST', '/peer/v1/messages', body)[0] == 400
            for raw in [b'{"content":"\xff"}', 'null', '{} {}', '{', '{"content":"' + 'x' * (1 << 20) + '"}']:
                assert wire(receiver, context, 'POST', '/peer/v1/messages', raw=raw)[0] == 400
            assert receiver.call('POST', '/v1/peers', dict(id=b['id'], public_key=a['public_key'], address=sender.address))[0] == 400

            # An unknown caller fails the receiver's TLS identity allowlist.
            stranger.configure(receiver, b)
            unknown = stranger.submit(b, ra, grant)
            assert unknown['state'] == 'unknown', unknown
            # A configured expected key must not be replaced by a different host at that address.
            sender.configure(receiver, c, address=receiver.address)
            wrong_pin = sender.submit(c, ra, grant)
            assert wrong_pin['state'] == 'unknown', wrong_pin
            sender.configure(receiver, b)

            # Message persistence rolls back if activity insertion fails.
            connection = sqlite3.connect(receiver.state / 'host.db')
            connection.execute("CREATE TRIGGER fail_peer_event BEFORE INSERT ON events WHEN NEW.kind = 'message.accepted' BEGIN SELECT RAISE(ABORT, 'injected'); END")
            connection.commit()
            failed = sender.submit(b, ra, grant)
            assert failed['state'] == 'unknown', failed
            assert len(receiver.cli('message', 'list')) == 1
            connection.execute('DROP TRIGGER fail_peer_event')
            connection.commit()
            connection.close()
            recovered = sender.cli('message', 'retry', '--peer', b['id'], failed['request']['request_id'])
            assert recovered['state'] == 'accepted'

            # Drop a real response after durable acceptance, then restart both hosts.
            rid = request_id()
            relay = DropResponse(receiver, rid)
            sender.configure(receiver, b, address=relay.address)
            uncertain = sender.submit(b, ra, grant, rid=rid)
            relay.close()
            assert uncertain['state'] == 'unknown', uncertain
            assert any(message['request']['request_id'] == rid for message in receiver.cli('message', 'list'))
            sender.configure(receiver, b)
            sender.stop(crash=True)
            receiver.stop(crash=True)
            # Also prove both implementations can reopen each other's v2 state.
            sender.binary, receiver.binary = str(receiver_binary), str(sender_binary)
            assert sender.start() == a and receiver.start() == b
            assert sender.cli('message', 'inspect', '--peer', b['id'], rid)['state'] == 'unknown'
            recovered = sender.cli('message', 'retry', '--peer', b['id'], rid)
            assert recovered['state'] == 'accepted', recovered
            assert len([message for message in receiver.cli('message', 'list') if message['request']['request_id'] == rid]) == 1

            # A receipt remains available to its sender after local revocation.
            revoked = receiver.cli('grant', 'revoke', grant['id'])
            assert receiver.cli('grant', 'revoke', grant['id']) == revoked
            assert sender.submit(b, ra, grant)['state'] == 'rejected'
            assert wire(receiver, context, 'GET', '/peer/v1/receipts/' + rid)[0] == 200
            assert wire(receiver, context, 'POST', '/peer/v1/messages', recovered['request'])[0] == 403
            receiver.configure(stranger, c)
            valid_for_sender = receiver.grant(a, ra)
            assert stranger.submit(b, ra, valid_for_sender)['state'] == 'rejected'
            stranger_context = fixture_context(stranger, temporary)
            assert wire(receiver, stranger_context, 'GET', '/peer/v1/receipts/' + rid)[0] == 404

            # Recover a missing sender receipt without resubmitting revoked work.
            connection = sqlite3.connect(sender.state / 'host.db')
            record = dict(recovered, state='unknown', receipt=None, error=None)
            connection.execute('UPDATE outbound_messages SET record = ? WHERE peer = ? AND request_id = ?',
                               (json.dumps(record), b['id'], rid))
            connection.commit()
            connection.close()
            refreshed = sender.cli('message', 'refresh', '--peer', b['id'], rid)
            assert refreshed['state'] == 'accepted' and refreshed['receipt'] == recovered['receipt']
            # Receipt persistence and sender activity also form one transaction.
            connection = sqlite3.connect(sender.state / 'host.db')
            connection.execute("CREATE TRIGGER fail_receipt_event BEFORE INSERT ON events WHEN NEW.kind = 'message.accepted' BEGIN SELECT RAISE(ABORT, 'injected'); END")
            connection.commit()
            atomic_id = request_id()
            status, error = sender.call('POST', '/v1/outbound', {
                'peer_host_id': b['id'], 'request_id': atomic_id, 'grant_id': valid_for_sender['id'],
                'target_agent_id': ra['id'], 'deadline': timestamp(), 'content': 'atomic receipt',
            })
            assert status == 500 and error == {'code': 'internal', 'error': 'internal error'}
            assert sender.cli('message', 'inspect', '--peer', b['id'], atomic_id)['state'] == 'unknown'
            assert any(message['request']['request_id'] == atomic_id for message in receiver.cli('message', 'list'))
            connection.execute('DROP TRIGGER fail_receipt_event')
            connection.commit()
            connection.close()
            assert sender.cli('message', 'refresh', '--peer', b['id'], atomic_id)['state'] == 'accepted'
            assert len(receiver.cli('message', 'list')) == 4

            # Worst-case JSON escaping must remain readable through the CLI.
            large_ids = []
            for _ in range(3):
                large_id = request_id()
                large_ids.append(large_id)
                message = dict(request_id=large_id, grant_id=valid_for_sender['id'],
                               target_agent_id=ra['id'], deadline=timestamp(), content='\x00' * 65536)
                assert wire(receiver, context, 'POST', '/peer/v1/messages', message)[0] == 200
            initial_page = receiver.cli('message', 'list')
            assert len(initial_page) < 7
            seen = []
            cursor = 0
            while page := receiver.cli('message', 'list', '--after', str(cursor), '--limit', '2'):
                assert len(page) <= 2
                assert all(item['sequence'] > cursor for item in page)
                seen.extend(item['request']['request_id'] for item in page)
                cursor = page[-1]['sequence']
            assert len(seen) == 7 and len(set(seen)) == 7
            assert set(large_ids) <= set(seen)
            for query in ['after=-1', 'after=bad', 'limit=0', 'limit=1001']:
                assert receiver.call('GET', '/v1/messages?' + query)[0] == 400
        finally:
            for host in (sender, receiver, stranger):
                host.stop()
                host.logs.close()
    print(f'PASS {label}: mTLS identity pins, directional grants, disconnected access, atomic acceptance, lost receipts, restart, deduplication, revocation', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    args = parser.parse_args()
    set_probe(args.probe.resolve(strict=True))
    go, rust = args.go.resolve(strict=True), args.rust.resolve(strict=True)
    for sender, receiver, label in [(go, go, 'Go→Go'), (rust, rust, 'Rust→Rust'), (go, rust, 'Go→Rust'), (rust, go, 'Rust→Go')]:
        check(sender, receiver, label)


if __name__ == '__main__':
    main()
