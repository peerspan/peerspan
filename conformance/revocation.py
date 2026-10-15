#!/usr/bin/env python3
"""Exercise signed revocation, leaving, and root rotation with real hosts.

Runs one Go coordinator with Go and Rust hosts in every creator/joiner pairing.
Coordinator omission and forks are simulated by editing the coordinator's
SQLite database directly. Ed25519 fixtures are signed with OpenSSL. Uses
Python's standard library and temporary state only.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import time

from coordination import Coordinator, wait_for
from peer_messaging import PeerHost, request_id, set_probe, timestamp
from relay import raw_relay, read_frame

INTERVAL = 1


class GovHost(PeerHost):
    def __init__(self, binary, state):
        super().__init__(binary, state)
        self.daemon_args = (*self.daemon_args, '--coordination-interval', str(INTERVAL))

    def seed(self):
        with sqlite3.connect(self.state / 'host.db') as connection:
            return connection.execute('SELECT private_key FROM identity').fetchone()[0][:32]


def b64(data):
    return base64.b64encode(data).decode()


def openssl_key(seed, directory):
    path = directory / (secrets.token_hex(4) + '.der')
    path.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + seed)
    path.chmod(0o600)
    return path


def public_key(seed, directory):
    out = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', str(openssl_key(seed, directory)),
                          '-pubout', '-outform', 'DER'], capture_output=True, check=True).stdout
    return out[-32:]


def sign(seed, message, directory):
    data = directory / (secrets.token_hex(4) + '.msg')
    data.write_bytes(message.encode())
    return subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-keyform', 'DER', '-inkey',
                           str(openssl_key(seed, directory)), '-in', str(data)], capture_output=True, check=True).stdout


def decode_token(token):
    encoded = token.split('.', 1)[1]
    return json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))


def coord_db(coord):
    return sqlite3.connect(coord.state / 'coord.db')


def member_ids(host, network):
    return {m['host_id'] for m in host.cli('network', 'members', network)}


def join(admin, network, joiner, label='member'):
    invite = admin.cli('network', 'invite', '--network', network, '--member', label, '--expires-at', timestamp(600))
    joined = joiner.cli('network', 'join', '--token', invite['token'])
    assert joined['id'] == network
    return invite


def send(sender, receiver_id, agent, grant, content):
    return sender.cli('message', 'send', '--peer', receiver_id, '--grant', grant['id'], '--agent', agent['id'],
                      '--deadline', timestamp(), '--content', content, '--request', request_id())


def check(coord_binary, creator_binary, joiner_binary, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-revocation-') as directory:
        root = Path(directory)
        coord = Coordinator(coord_binary, root / 'coord')
        alice = GovHost(creator_binary, root / 'alice')
        joiners = {name: GovHost(joiner_binary, root / name) for name in ('bob', 'carol', 'dave', 'erin', 'frank')}
        bob, carol, dave, erin, frank = joiners.values()
        hosts = [alice, *joiners.values()]
        try:
            coordinator = coord.start()
            ids = {}
            for host in hosts:
                ids[host] = host.start()['id']
            network = alice.cli('network', 'create', '--name', 'team', '--member', 'alice',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            net = network['id']
            erin_invite = None
            for host in (bob, carol, erin, frank):
                invite = join(alice, net, host)
                if host is erin:
                    erin_invite = invite
            for host in (alice, bob, carol, erin, frank):
                host.cli('network', 'sync', net)
            assert ids[bob] in member_ids(carol, net)

            # Bob can message Alice, then loses access the moment he is revoked,
            # including on the already-open QUIC connection.
            agent = alice.cli('agent', 'register', '--name', 'agent', '--owner', 'alice')
            grant = alice.cli('grant', 'create', '--peer', ids[bob], '--agent', agent['id'],
                              '--expires-at', timestamp(1200), '--allow-disconnected')
            assert send(bob, ids[alice], agent, grant, 'before')['state'] == 'accepted'
            assert alice.call('POST', f'/v1/networks/{net}/revocations', {'host_id': ids[alice]})[0] == 409
            assert carol.call('POST', f'/v1/networks/{net}/revocations', {'host_id': ids[bob]})[0] == 403
            revoked = alice.cli('network', 'revoke', '--network', net, '--host', ids[bob])
            assert revoked['kind'] == 'host' and revoked['submitted'] is True, revoked
            # A repeat returns the stored revocation, with no second event.
            assert alice.cli('network', 'revoke', '--network', net, '--host', ids[bob]) == revoked
            assert [e['kind'] for e in alice.cli('activity')].count('network.host_revoked') == 1
            after = send(bob, ids[alice], agent, grant, 'after')
            assert after['state'] == 'rejected', after
            assert [m['request']['content'] for m in alice.cli('message', 'list')] == ['before']
            kinds = [(e['kind'], e['subject_id']) for e in alice.cli('activity')]
            assert ('network.host_revoked', ids[bob]) in kinds
            # Other members drop Bob on their next sync; Bob can no longer sync or relay.
            carol.cli('network', 'sync', net)
            assert ids[bob] not in member_ids(carol, net)
            assert bob.cli('network', 'sync', net)['last_sync_error'] is not None
            relay = raw_relay(coord, bob.seed(), root)
            assert read_frame(relay, 5) == 'closed'
            relay.close()

            # Sticky: a coordinator that loses the revocation and serves Bob again
            # does not restore him, before or after a restart.
            with coord_db(coord) as db:
                db.execute("DELETE FROM statements WHERE kind = 'host'")
            bob_record = next(m for m in bob.cli('network', 'members', net) if m['host_id'] == ids[bob])
            with coord_db(coord) as db:
                db.execute('INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
                           (net, ids[bob], bob_record['membership']['invite_public_key'],
                            json.dumps(bob_record['membership']), '', timestamp(0)))
            carol.cli('network', 'sync', net)
            assert ids[bob] not in member_ids(carol, net)
            carol.stop(crash=True)
            assert carol.start()['id'] == ids[carol]
            assert ids[bob] not in member_ids(carol, net)
            with coord_db(coord) as db:
                restored = db.execute("SELECT COUNT(*) FROM statements WHERE kind = 'host'").fetchone()[0]
            assert restored == 1, 'revocation was not resubmitted to the coordinator'

            # A revoked invite blocks joins and drops a host that already used it.
            unused = alice.cli('network', 'invite', '--network', net, '--member', 'dave', '--expires-at', timestamp(600))
            invite_revoked = alice.cli('network', 'revoke-invite', '--network', net, '--invite', unused['invite_public_key'])
            assert invite_revoked['kind'] == 'invite', invite_revoked
            assert dave.call('POST', '/v1/networks/join', {'token': unused['token']})[0] == 403
            alice.cli('network', 'revoke-invite', '--network', net, '--invite', erin_invite['invite_public_key'])
            assert ids[erin] not in member_ids(alice, net)
            carol.cli('network', 'sync', net)
            assert ids[erin] not in member_ids(carol, net)

            # Leaving: the administrator cannot; Carol's departure reaches Alice.
            assert alice.call('POST', f'/v1/networks/{net}/leave')[0] == 409
            left = carol.cli('network', 'leave', net)
            assert left == {'network_id': net, 'submitted': True}, left
            assert carol.cli('network', 'list') == []
            alice.cli('network', 'sync', net)
            assert ids[carol] not in member_ids(alice, net)
            assert ('network.member_left', ids[carol]) in [(e['kind'], e['subject_id']) for e in alice.cli('activity')]

            # Root rotation: Frank stays valid through his attestation; an invite
            # issued before the rotation is refused; a new one works.
            stale = alice.cli('network', 'invite', '--network', net, '--member', 'dave', '--expires-at', timestamp(600))
            with sqlite3.connect(alice.state / 'host.db') as db:
                genesis_seed = db.execute('SELECT root_seed FROM networks WHERE id = ?', (net,)).fetchone()[0]
            rotated = alice.cli('network', 'rotate-root', net)
            assert rotated['root_epoch'] == 1 and rotated['current_root_public_key'] != rotated['root_public_key'], rotated
            synced = frank.cli('network', 'sync', net)
            assert synced['last_sync_error'] is None and synced['root_epoch'] == 1, synced
            assert synced['current_root_public_key'] == rotated['current_root_public_key']
            assert member_ids(frank, net) == {ids[alice], ids[frank]}
            assert dave.call('POST', '/v1/networks/join', {'token': stale['token']})[0] != 201
            join(alice, net, dave, 'dave')
            frank.cli('network', 'sync', net)
            assert ids[dave] in member_ids(frank, net)

            # A member injected with only an old-root chain is ignored.
            token = decode_token(stale['token'])
            rogue_seed = secrets.token_bytes(32)
            rogue_public = b64(public_key(rogue_seed, root))
            joined_at = timestamp(0)
            statement = '\n'.join(['peerspan-member-v1', net, token['invite_public_key'], rogue_public, joined_at])
            forged = {'network_id': net, 'member': token['member'], 'invite_public_key': token['invite_public_key'],
                      'invite_expires_at': token['invite_expires_at'], 'invite_signature': token['invite_signature'],
                      'host_public_key': rogue_public, 'joined_at': joined_at,
                      'host_signature': b64(sign(base64.b64decode(token['invite_seed']), statement, root))}
            rogue_id = 'host_' + hashlib.sha256(base64.b64decode(rogue_public)).hexdigest()
            with coord_db(coord) as db:
                db.execute('INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
                           (net, rogue_id, token['invite_public_key'], json.dumps(forged), '', timestamp(0)))
            frank.cli('network', 'sync', net)
            assert rogue_id not in member_ids(frank, net)

            # A forked rotation is refused, and the persisted chain is kept.
            other_root = b64(public_key(secrets.token_bytes(32), root))
            rotated_at = timestamp(0)
            fork_statement = '\n'.join(['peerspan-root-rotate-v1', net, '1', network['root_public_key'], other_root, rotated_at])
            fork = {'network_id': net, 'epoch': 1, 'previous_root_public_key': network['root_public_key'],
                    'root_public_key': other_root, 'rotated_at': rotated_at,
                    'signature': b64(sign(genesis_seed, fork_statement, root))}
            with coord_db(coord) as db:
                original = db.execute("SELECT statement FROM statements WHERE kind = 'rotation' AND subject = '1'").fetchone()[0]
                db.execute("UPDATE statements SET statement = ? WHERE kind = 'rotation' AND subject = '1'", (json.dumps(fork),))
            refused = frank.cli('network', 'sync', net)
            assert refused['last_sync_error'] and 'root chain conflict' in refused['last_sync_error'], refused
            assert refused['current_root_public_key'] == rotated['current_root_public_key']
            with coord_db(coord) as db:
                db.execute("UPDATE statements SET statement = ? WHERE kind = 'rotation' AND subject = '1'", (original,))
            assert frank.cli('network', 'sync', net)['last_sync_error'] is None

            # Leaving takes effect locally even while the coordinator is down.
            coord.stop()
            offline = frank.cli('network', 'leave', net)
            assert offline == {'network_id': net, 'submitted': False}, offline
            assert frank.cli('network', 'list') == []
        finally:
            for host in hosts:
                host.stop()
                host.logs.close()
            coord.stop()
            coord.logs.close()
    print(f'PASS {label}: revocation (immediate, open connection, relay, sticky across omission and restart), '
          'invite revocation, leave (online and offline), root rotation with attestations, fork refusal', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for creator in binaries:
        for joiner in binaries:
            check(args.coord.resolve(), binaries[creator], binaries[joiner], f'{creator} creator, {joiner} joiners')


if __name__ == '__main__':
    main()
