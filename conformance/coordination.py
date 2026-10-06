#!/usr/bin/env python3
"""Exercise signed enrollment and coordination with real Go/Rust hosts.

Runs one Go capsule-coord with hosts in every creator/joiner pairing. Uses only
Python's standard library and temporary state. A row written straight into the
coordinator database models a compromised coordinator.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time

from peer_messaging import PeerHost, available_port, timestamp
from host_service import die_with_parent
from agent_adapter import adapter_call, credential

INTERVAL = 1


class CoordHost(PeerHost):
    def __init__(self, binary, state):
        super().__init__(binary, state)
        self.daemon_args = (*self.daemon_args, '--coordination-interval', str(INTERVAL))


class Coordinator:
    def __init__(self, binary, state):
        self.binary, self.state = str(binary), state
        self.port = available_port()
        self.address = f'127.0.0.1:{self.port}'
        self.process = None
        self.logs = tempfile.TemporaryFile()

    def info(self):
        result = subprocess.run([self.binary, '--state', str(self.state), 'info'],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def start(self):
        self.process = subprocess.Popen([self.binary, '--state', str(self.state), 'run', '--listen', self.address],
                                        stdout=self.logs, stderr=self.logs, preexec_fn=die_with_parent)
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
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=8)


def wait_for(predicate, timeout=10, message='condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError(f'timed out waiting for {message}')


def decode_token(token):
    prefix, encoded = token.split('.', 1)
    return prefix, json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))


def encode_token(prefix, fields):
    data = json.dumps(fields, separators=(',', ':')).encode()
    return prefix + '.' + base64.urlsafe_b64encode(data).decode().rstrip('=')


def send(sender, receiver_id, grant, agent, content):
    return sender.cli('message', 'send', '--peer', receiver_id, '--grant', grant['id'], '--agent', agent['id'],
                      '--deadline', timestamp(), '--content', content)


def check(coord_binary, creator_binary, joiner_binary, label):
    with tempfile.TemporaryDirectory(prefix='capsule-coordination-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        alice = CoordHost(creator_binary, root / 'alice')
        bob = CoordHost(joiner_binary, root / 'bob')
        carol = CoordHost(joiner_binary, root / 'carol')
        try:
            coordinator = coord.start()
            assert coordinator['id'].startswith('coord_') and coord.info() == coordinator
            a, b, c = alice.start(), bob.start(), carol.start()

            # Create, invite, and join.
            network = alice.cli('network', 'create', '--name', 'team', '--member', 'alice',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            assert network['id'].startswith('net_') and network['administrator'] is True
            assert network['last_sync_at'] is not None and network['last_sync_error'] is None, network
            net = network['id']
            status, _ = bob.call('POST', f'/v1/networks/{net}/invites', {'member': 'bob', 'expires_at': timestamp(600)})
            assert status == 404
            assert alice.call('POST', f'/v1/networks/{net}/invites', {'member': 'bob', 'expires_at': timestamp(31 * 86400)})[0] == 400
            invite = alice.cli('network', 'invite', '--network', net, '--member', 'bob', '--expires-at', timestamp(600))
            assert invite['network_id'] == net and invite['member'] == 'bob' and invite['token'].startswith('capsule-invite-v1.')
            joined = bob.cli('network', 'join', '--token', invite['token'])
            assert joined['id'] == net and joined['administrator'] is False and joined['member'] == 'bob'
            assert joined['coordinator_public_key'] == coordinator['public_key'] and joined['name'] == 'team'
            assert bob.call('POST', '/v1/networks/join', {'token': invite['token']})[0] == 409

            synced = alice.cli('network', 'sync', net)
            assert synced['last_sync_error'] is None, synced
            members = alice.cli('network', 'members', net)
            assert [m['host_id'] for m in members] == sorted([a['id'], b['id']]), members
            entry = next(m for m in members if m['host_id'] == b['id'])
            assert entry['member'] == 'bob' and entry['address'] == bob.address and entry['public_key'] == b['public_key']
            assert entry['membership']['host_public_key'] == b['public_key']
            assert [m['host_id'] for m in bob.cli('network', 'members', net)] == [m['host_id'] for m in members]
            assert alice.cli('peer', 'list') == [] and bob.cli('peer', 'list') == []
            kinds = [(e['kind'], e['subject_id']) for e in alice.cli('activity')]
            assert ('network.created', net) in kinds and ('network.invite_issued', net) in kinds
            assert ('network.member_added', b['id']) in kinds and ('network.member_added', a['id']) not in kinds
            assert ('network.joined', net) in [(e['kind'], e['subject_id']) for e in bob.cli('activity')]

            # Message exchange without peer add, under a grant without allow_disconnected.
            agent = alice.cli('agent', 'register', '--name', 'alice', '--owner', 'alice')
            connected_grant = alice.grant(b, agent, allow=False)
            assert connected_grant['allow_disconnected'] is False
            assert send(bob, a['id'], connected_grant, agent, 'over membership')['state'] == 'accepted'
            # Handoff uses the same predicate: while synced, a connected-only
            # grant's message reaches the adapter.
            session = alice.cli('session', 'attach', '--agent', agent['id'], '--integration', 'test')
            token = credential(alice, session)['token']
            status, handoff = adapter_call(alice, token, 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['request']['content'] == 'over membership', handoff
            delivered = handoff['delivery']['id']
            held = send(bob, a['id'], connected_grant, agent, 'held')
            assert held['state'] == 'accepted'
            assert alice.call('POST', '/v1/grants', {'requester_host_id': c['id'], 'target_agent_id': agent['id'],
                                                     'expires_at': timestamp(600), 'max_message_bytes': 10})[0] == 404

            # Invite reuse, expired invites, and tampered tokens.
            status, error = carol.call('POST', '/v1/networks/join', {'token': invite['token']})
            assert status == 409 and error['code'] == 'conflict', (status, error)
            assert carol.cli('network', 'list') == []
            short = alice.cli('network', 'invite', '--network', net, '--member', 'late', '--expires-at', timestamp(2))
            time.sleep(2.5)
            assert carol.call('POST', '/v1/networks/join', {'token': short['token']})[0] == 400
            fresh = alice.cli('network', 'invite', '--network', net, '--member', 'carol', '--expires-at', timestamp(600))
            prefix, fields = decode_token(fresh['token'])
            # coordinator_address is unsigned: pointing it at a closed port
            # proves that each rejection below happened before any contact.
            fields['coordinator_address'] = f'127.0.0.1:{available_port()}'
            assert carol.call('POST', '/v1/networks/join', {'token': encode_token(prefix, fields)})[0] == 503
            for field, value in [('member', 'mallory'), ('network_name', ' padded'),
                                 ('invite_seed', base64.b64encode(secrets.token_bytes(32)).decode()),
                                 ('invite_signature', base64.b64encode(secrets.token_bytes(64)).decode()),
                                 ('root_public_key', b['public_key']), ('coordinator_public_key', 'AAAA')]:
                tampered = dict(fields, **{field: value})
                assert carol.call('POST', '/v1/networks/join', {'token': encode_token(prefix, tampered)})[0] == 400, field
            for bad in ['', 'capsule-invite-v1.', fresh['token'] + 'x', fresh['token'].replace('capsule-invite-v1.', 'capsule-invite-v2.')]:
                assert carol.call('POST', '/v1/networks/join', {'token': bad})[0] == 400, bad
            assert carol.cli('network', 'list') == []
            assert carol.cli('network', 'join', '--token', fresh['token'])['id'] == net

            # A compromised coordinator inserts a host that holds no invite.
            rogue_key = secrets.token_bytes(32)
            rogue_id = 'host_' + hashlib.sha256(rogue_key).hexdigest()
            forged = dict(entry['membership'], host_public_key=base64.b64encode(rogue_key).decode(),
                          invite_public_key=base64.b64encode(secrets.token_bytes(32)).decode())
            database = sqlite3.connect(coord.state / 'coord.db')
            database.execute('INSERT INTO members VALUES (?, ?, ?, ?, ?, ?)',
                             (net, rogue_id, forged['invite_public_key'], json.dumps(forged), '127.0.0.1:9', timestamp(0)))
            database.commit()
            database.close()
            assert alice.cli('network', 'sync', net)['last_sync_error'] is None
            ids = [m['host_id'] for m in alice.cli('network', 'members', net)]
            assert ids == sorted([a['id'], b['id'], c['id']]) and rogue_id not in ids, ids
            assert alice.call('POST', '/v1/grants', {'requester_host_id': rogue_id, 'target_agent_id': agent['id'],
                                                     'expires_at': timestamp(600), 'max_message_bytes': 10})[0] == 404

            # Coordinator outage: connected-only grants lapse after three intervals.
            disconnected_grant = alice.grant(b, agent, allow=True)
            brief = bob.cli('message', 'send', '--peer', a['id'], '--grant', connected_grant['id'], '--agent', agent['id'],
                            '--deadline', timestamp(3), '--content', 'brief')
            assert brief['state'] == 'accepted'
            coord.stop()
            wait_for(lambda: alice.cli('network', 'list')[0]['last_sync_error'] is not None, message='sync failure')
            time.sleep(3 * INTERVAL + 1)
            # A lapsed connected state is retryable: 503, recorded as unknown.
            stale = send(bob, a['id'], connected_grant, agent, 'stale')
            assert stale['state'] == 'unknown' and 'HTTP 503' in stale['error'], stale
            assert send(bob, a['id'], disconnected_grant, agent, 'outage')['state'] == 'accepted'
            # Once stale, a connected-only message stays queued without a
            # delivery record; one whose deadline passed is blocked for good.
            # The disconnected grant's message is handed off past them.
            status, handoff = adapter_call(alice, token, 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['request']['content'] == 'outage', handoff
            states = {r['delivery']['request_id']: r['delivery']['state'] for r in alice.cli('delivery', 'list')}
            assert held['request']['request_id'] not in states, states
            assert states[brief['request']['request_id']] == 'blocked', states
            assert sorted(states.values()) == ['blocked', 'unknown', 'unknown'], states
            assert adapter_call(alice, token, 'POST', '/adapter/v1/next', {}) == (200, None)
            # A reply to content delivered while synced needs only final bounds.
            status, reply = adapter_call(alice, token, 'POST', f'/adapter/v1/deliveries/{delivered}/reply',
                                         {'content': 'answered during outage'})
            assert status == 200, reply

            # Host restart keeps verified members. The creator's v3 state is
            # reopened by the joiner's implementation, which must still treat
            # it as the administrator.
            alice.stop(crash=True)
            alice.binary = str(joiner_binary)
            assert alice.start() == a
            assert [m['host_id'] for m in alice.cli('network', 'members', net)] == ids
            assert alice.cli('network', 'list')[0]['administrator'] is True
            assert send(bob, a['id'], disconnected_grant, agent, 'after restart')['state'] == 'accepted'
            still_stale = send(bob, a['id'], connected_grant, agent, 'still stale')
            assert still_stale['state'] == 'unknown', still_stale

            # Coordinator restart: syncing resumes and connected grants work again.
            assert coord.start() == coordinator
            wait_for(lambda: alice.cli('network', 'list')[0]['last_sync_error'] is None, message='resumed sync')
            assert send(bob, a['id'], connected_grant, agent, 'reconnected')['state'] == 'accepted'
            # Retrying the same request after reconnection succeeds.
            retried = bob.cli('message', 'retry', '--peer', a['id'], stale['request']['request_id'])
            assert retried['state'] == 'accepted', retried
            # The other stale send is accepted by the sender's automatic retry.
            wait_for(lambda: bob.cli('message', 'inspect', '--peer', a['id'], still_stale['request']['request_id'])
                     ['state'] == 'accepted', timeout=60, message='automatic retry of the stale send')
            assert len(alice.cli('message', 'list')) == 8
            # Recover the same authorized instance after daemon restart; syncing
            # allows the queued connected-only message to be handed off.
            from agent_adapter import instance_for
            assert adapter_call(alice, token, 'POST', '/adapter/v1/connect', {
                'instance_id': instance_for(alice, token)['instance']})[0] == 200
            status, handoff = adapter_call(alice, token, 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['request']['request_id'] == held['request']['request_id'], handoff
            late_invite = alice.cli('network', 'invite', '--network', net, '--member', 'dave', '--expires-at', timestamp(600))
            assert decode_token(late_invite['token'])[1]['root_public_key'] == network['root_public_key']
        finally:
            for process in (alice, bob, carol):
                process.stop()
                process.logs.close()
            coord.stop()
            coord.logs.close()
    print(f'PASS {label}: signed enrollment, invite reuse/expiry/tampering, injected members, '
          'connected grants and handoff, coordinator outage, host and coordinator restart', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--coord', type=Path, required=True)
    args = parser.parse_args()
    implementations = [(name, path.resolve(strict=True)) for name, path in (('Go', args.go), ('Rust', args.rust)) if path]
    if not implementations:
        parser.error('provide --go, --rust, or both')
    coord = args.coord.resolve(strict=True)
    for creator_name, creator in implementations:
        for joiner_name, joiner in implementations:
            check(coord, creator, joiner, f'{creator_name} creator, {joiner_name} joiners')


if __name__ == '__main__':
    main()
