#!/usr/bin/env python3
"""Exercise the capsule-coord relay with real Go/Rust hosts.

Runs one Go coordinator with hosts in every sender/receiver pairing. Hosts that
listen on an unspecified address advertise no direct address, so they are
reachable only through the relay. Raw relay connections use OpenSSL-generated
certificates for disposable hosts' own keys. Uses Python's standard library and
temporary state only.
"""
import argparse
import json
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import time

from agent_adapter import adapter_call, credential
from coordination import Coordinator, wait_for
from peer_messaging import PeerHost, available_port, request_id, set_probe, timestamp

INTERVAL = 1
RELAY_ALPN = 'capsule-relay/1'
SEND, RECEIVE, UNREACHABLE, PING = 1, 2, 3, 4


class RelayHost(PeerHost):
    """A host with an explicit peer bind and advertised address, or no listener."""

    def __init__(self, binary, state, listen='0.0.0.0', advertise=None):
        super().__init__(binary, state)
        args = ['--coordination-interval', str(INTERVAL)]
        if listen is not None:
            self.address = f'{listen}:{self.port}'
            args = ['--peer-listen', self.address, *args]
        if advertise is not None:
            args += ['--advertise', advertise]
        self.daemon_args = tuple(args)

    def seed(self):
        with sqlite3.connect(self.state / 'host.db') as connection:
            return connection.execute('SELECT private_key FROM identity').fetchone()[0][:32]


def raw_relay(coord, seed, temporary):
    """Open a raw relay connection proving the key for seed."""
    name = secrets.token_hex(4)
    key_der, cert_pem, key_pem = (temporary / f'{name}.key.der', temporary / f'{name}.cert.pem',
                                  temporary / f'{name}.key.pem')
    key_der.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + seed)
    subprocess.run(['openssl', 'req', '-new', '-x509', '-key', str(key_der), '-keyform', 'DER', '-out', str(cert_pem),
                    '-subj', '/CN=relay-fixture', '-days', '1'], check=True, capture_output=True, timeout=5)
    subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', str(key_der), '-out', str(key_pem)],
                   check=True, capture_output=True, timeout=5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    # The daemons pin the coordinator key; this fixture tests the relay protocol.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(cert_pem, key_pem)
    context.set_alpn_protocols([RELAY_ALPN])
    connection = context.wrap_socket(socket.create_connection(('127.0.0.1', coord.port), timeout=5))
    assert connection.selected_alpn_protocol() == RELAY_ALPN
    return connection


def raw_id(host_id):
    return bytes.fromhex(host_id.removeprefix('host_'))


def read_frame(connection, timeout):
    """Return (type, payload), None on timeout, or 'closed'."""
    connection.settimeout(timeout)
    try:
        header = connection.recv(3)
        if len(header) < 3:
            return 'closed'
        kind, size = struct.unpack('>BH', header)
        payload = b''
        while len(payload) < size:
            chunk = connection.recv(size - len(payload))
            if not chunk:
                return 'closed'
            payload += chunk
        return kind, payload
    except (socket.timeout, TimeoutError):
        return None
    except (ConnectionError, ssl.SSLError, OSError):
        return 'closed'


def join(administrator, network, joiner, member):
    invite = administrator.cli('network', 'invite', '--network', network, '--member', member,
                               '--expires-at', timestamp(600))
    assert joiner.cli('network', 'join', '--token', invite['token'])['id'] == network


def send(sender, receiver, agent, grant, content='hello'):
    return sender.cli('message', 'send', '--peer', receiver['id'], '--grant', grant['id'], '--agent', agent['id'],
                      '--deadline', timestamp(), '--content', content, '--request', request_id())


def check(coord_binary, sender_binary, receiver_binary, label):
    with tempfile.TemporaryDirectory(prefix='capsule-relay-') as directory:
        root = Path(directory)
        coord = Coordinator(coord_binary, root / 'coord')
        alice = RelayHost(receiver_binary, root / 'alice')
        bob = RelayHost(sender_binary, root / 'bob')
        dead = available_port()
        carol = RelayHost(receiver_binary, root / 'carol', listen='127.0.0.1', advertise=f'127.0.0.1:{dead}')
        erin = RelayHost(sender_binary, root / 'erin', listen=None)
        dave = RelayHost(receiver_binary, root / 'dave')
        hosts = (alice, bob, carol, erin, dave)
        try:
            coordinator = coord.start()
            a, b, c, e, d = (host.start() for host in hosts)
            net = alice.cli('network', 'create', '--name', 'team', '--member', 'alice', '--coordinator', coord.address,
                            '--coordinator-key', coordinator['public_key'])['id']
            for host, member in ((bob, 'bob'), (carol, 'carol'), (erin, 'erin')):
                join(alice, net, host, member)
            other = dave.cli('network', 'create', '--name', 'other', '--member', 'dave', '--coordinator', coord.address,
                             '--coordinator-key', coordinator['public_key'])['id']
            for host in (alice, bob, carol, erin):
                assert host.cli('network', 'sync', net)['last_sync_error'] is None
            members = {m['host_id']: m['address'] for m in alice.cli('network', 'members', net)}
            assert members[a['id']] == '' and members[b['id']] == '' and members[e['id']] == '', members
            assert members[c['id']] == f'127.0.0.1:{dead}', members
            agents = {host: host.cli('agent', 'register', '--name', 'relay', '--owner', 'test')
                      for host in (alice, bob, carol, erin)}

            # Two members without direct addresses exchange messages, receipts,
            # and adapter replies through the relay, in both directions.
            to_alice = alice.grant(b, agents[alice])
            sent = wait_for(lambda: (lambda out: out if out['state'] == 'accepted' else None)(
                send(bob, a, agents[alice], to_alice)), timeout=20, message='relayed send')
            rid = sent['request']['request_id']
            assert bob.cli('message', 'refresh', '--peer', a['id'], rid)['state'] == 'accepted'
            assert any(m['request']['request_id'] == rid for m in alice.cli('message', 'list'))
            session = alice.cli('session', 'attach', '--agent', agents[alice]['id'], '--integration', 'test')
            token = credential(alice, session)['token']
            status, handoff = adapter_call(alice, token, 'POST', '/adapter/v1/next', {})
            assert status == 200 and handoff['request']['request_id'] == rid, handoff
            status, reply = adapter_call(alice, token, 'POST', f"/adapter/v1/deliveries/{handoff['delivery']['id']}/reply",
                                         {'content': 'relayed reply'})
            assert status == 200, reply
            fetched = bob.cli('message', 'reply', '--peer', a['id'], rid)
            assert fetched['state'] == 'replied' and fetched['reply']['content'] == 'relayed reply', fetched
            to_bob = bob.grant(a, agents[bob])
            assert send(alice, b, agents[bob], to_bob)['state'] == 'accepted'

            # A dead direct address falls back to the relay.
            to_carol = carol.grant(b, agents[carol])
            assert send(bob, c, agents[carol], to_carol)['state'] == 'accepted'

            # A host without --peer-listen sends through the relay but accepts
            # no inbound connections.
            from_erin = alice.grant(e, agents[alice])
            assert send(erin, a, agents[alice], from_erin)['state'] == 'accepted'
            to_erin = erin.grant(a, agents[erin])
            refused = send(alice, e, agents[erin], to_erin)
            assert refused['state'] == 'unknown', refused
            assert erin.cli('message', 'list') == []

            # A non-member's relay connection is refused after the handshake.
            stranger = raw_relay(coord, secrets.token_bytes(32), root)
            assert read_frame(stranger, 5) == 'closed'
            stranger.close()
            # Forwarding is refused between hosts that share no network: Erin
            # (team) cannot reach Dave (other), though both are connected.
            fixture = raw_relay(coord, erin.seed(), root)
            fixture.sendall(struct.pack('>BH', SEND, 32 + 5) + raw_id(d['id']) + b'hello')
            assert read_frame(fixture, 5) == (UNREACHABLE, raw_id(d['id']))
            fixture.sendall(struct.pack('>BH', PING, 0))
            fixture.sendall(struct.pack('>BH', RECEIVE, 0))
            assert read_frame(fixture, 5) == 'closed', 'an invalid frame type did not close the connection'
            fixture.close()
            assert dave.cli('network', 'list')[0]['id'] == other

            # Hosts reconnect after a coordinator restart and relayed exchanges resume.
            coord.stop()
            assert coord.start() == coordinator
            resumed = send(bob, a, agents[alice], to_alice, 'after restart')
            deadline = time.monotonic() + 45
            while resumed['state'] != 'accepted' and time.monotonic() < deadline:
                time.sleep(1)
                resumed = bob.cli('message', 'retry', '--peer', a['id'], resumed['request']['request_id'])
            assert resumed['state'] == 'accepted', resumed
        finally:
            for host in hosts:
                host.stop()
                host.logs.close()
            coord.stop()
            coord.logs.close()
    print(f'PASS {label}: relay-only exchange and replies, direct fallback, dial-only sender, '
          'non-member and cross-network refusal, coordinator restart', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    args = parser.parse_args()
    set_probe(args.probe.resolve())
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    if binaries['Go'] == binaries['Rust']:
        binaries = {'Go': binaries['Go']}
    for sender in binaries:
        for receiver in binaries:
            check(args.coord.resolve(), binaries[sender], binaries[receiver], f'{sender}→{receiver}')


if __name__ == '__main__':
    main()
