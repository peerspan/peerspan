#!/usr/bin/env python3
"""Exercise persons and host binding (milestone 2b slice 1) with real hosts.

Runs one Go coordinator with Go and Rust hosts in every creator/joiner pairing.
Person keys are OpenSSH ssh-ed25519 keys: the suite starts a real ssh-agent
per run, also signs with --person-key key files, and checks every person
signature the hosts store with `ssh-keygen -Y verify`. Coordinator omission is
simulated by editing the coordinator's SQLite database. Needs OpenSSH
(ssh-agent, ssh-add, ssh-keygen); everything else is Python's standard library
and temporary state.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import textwrap
import time

from coordination import Coordinator, wait_for
from host_service import die_with_parent, stop_all
from peer_messaging import PeerHost, set_probe, timestamp

INTERVAL = 1
NAMESPACE = 'capsule-person-v1'


class PersonHost(PeerHost):
    def __init__(self, binary, state):
        super().__init__(binary, state)
        self.daemon_args = (*self.daemon_args, '--coordination-interval', str(INTERVAL))


class Agent:
    """A real ssh-agent on a temporary socket, killed with the suite."""

    def __init__(self, directory):
        self.socket = str(directory / 'agent.sock')
        self.process = subprocess.Popen(['ssh-agent', '-D', '-a', self.socket], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, preexec_fn=die_with_parent)
        wait_for(lambda: os.path.exists(self.socket), message='ssh-agent socket')

    def add(self, key):
        subprocess.run(['ssh-add', str(key)], env={**os.environ, 'SSH_AUTH_SOCK': self.socket},
                       check=True, capture_output=True, timeout=10)

    def stop(self):
        self.process.send_signal(signal.SIGTERM)
        self.process.wait(timeout=5)


def ssh_key(directory, name):
    path = directory / name
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', str(path)],
                   check=True, capture_output=True, timeout=10)
    line = (directory / (name + '.pub')).read_text().split()
    raw = base64.b64decode(line[1])[-32:]
    return path, ' '.join(line[:2]), base64.b64encode(raw).decode()


def person_id(raw_b64):
    return 'person_' + hashlib.sha256(base64.b64decode(raw_b64)).hexdigest()


def coord_db(coord):
    return sqlite3.connect(coord.state / 'coord.db')


def host_statements(host, network, kind):
    with sqlite3.connect(host.state / 'host.db') as db:
        return [json.loads(r[0]) for r in db.execute(
            'SELECT record FROM network_statements WHERE network_id = ? AND kind = ?', (network, kind))]


def ssh_verify(statement_lines, signature_b64, ssh_public, directory):
    """Check a stored SSHSIG with OpenSSH itself."""
    message = directory / 'message'
    message.write_bytes('\n'.join(statement_lines).encode())
    armored = directory / 'message.sig'
    armored.write_text('-----BEGIN SSH SIGNATURE-----\n' + '\n'.join(textwrap.wrap(signature_b64, 76)) +
                       '\n-----END SSH SIGNATURE-----\n')
    allowed = directory / 'allowed'
    allowed.write_text('person ' + ssh_public + '\n')
    with open(message, 'rb') as stdin:
        result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'person', '-n', NAMESPACE,
                                 '-s', str(armored)], stdin=stdin, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def ssh_sign(statement_lines, key, directory):
    """Sign as the person with OpenSSH, returning the unarmored SSHSIG blob."""
    message = directory / 'forged'
    message.write_bytes('\n'.join(statement_lines).encode())
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', NAMESPACE, '-q', str(message)],
                   check=True, capture_output=True, timeout=10)
    armored = (directory / 'forged.sig').read_text()
    (directory / 'forged.sig').unlink()
    return ''.join(line for line in armored.splitlines() if not line.startswith('-----'))


def binding_lines(b, kind='bind'):
    at = b['bound_at'] if kind == 'bind' else b['unbound_at']
    return [f'capsule-host-{kind}-v1', b['network_id'], b['person_public_key'], b['host_public_key'], at]


def member(host, network, host_id):
    return next(m for m in host.cli('network', 'members', network) if m['host_id'] == host_id)


def check(coord_binary, creator_binary, joiner_binary, label):
    with tempfile.TemporaryDirectory(prefix='capsule-persons-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        alice = PersonHost(creator_binary, root / 'alice')
        bob = PersonHost(joiner_binary, root / 'bob')
        carol = PersonHost(joiner_binary, root / 'carol')
        dave = PersonHost(joiner_binary, root / 'dave')
        agent = Agent(root)
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        os.environ['SSH_AUTH_SOCK'] = agent.socket
        try:
            coordinator = coord.start()
            a, b, c, d = alice.start(), bob.start(), carol.start(), dave.start()
            network = alice.cli('network', 'create', '--name', 'team', '--member', 'alice',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            net = network['id']
            invite = alice.cli('network', 'invite', '--network', net, '--member', 'bob', '--expires-at', timestamp(600))
            bob.cli('network', 'join', '--token', invite['token'])

            # Host admitted by public key joins with the descriptor; an
            # unadmitted host is refused.
            refused = carol.cli('network', 'admit', '--network', net, '--host', d['public_key'], '--member', 'dave',
                                success=False)
            assert 'forbidden' in refused or 'not found' in refused.lower(), refused
            admitted = alice.cli('network', 'admit', '--network', net, '--host', c['public_key'], '--member', 'carol')
            assert admitted['host_id'] == c['id'] and admitted['descriptor'].startswith('capsule-network-v1.')
            assert dave.call('POST', '/v1/networks/join', {'descriptor': admitted['descriptor']})[0] == 403
            joined = carol.cli('network', 'join', '--descriptor', admitted['descriptor'])
            assert joined['id'] == net and joined['member'] == 'carol', joined
            alice.cli('network', 'sync', net)
            entry = member(alice, net, c['id'])
            assert entry['admission'] is not None and entry['membership'] is None, entry

            # Persons: pat via ssh-agent, admitted by public key; quinn by a
            # one-time person invite, signing with a key file.
            pat_key, pat_ssh, pat_raw = ssh_key(root, 'pat')
            agent.add(pat_key)
            shown = bob.cli('person', 'show')
            assert shown == {'person_id': person_id(pat_raw), 'public_key': pat_raw, 'ssh_public_key': pat_ssh}, shown
            assert bob.cli('network', 'admit', '--network', net, '--person', pat_ssh, '--member', 'pat',
                           success=False)
            pat = alice.cli('network', 'admit', '--network', net, '--person', str(root / 'pat.pub'), '--member', 'pat')
            assert pat['person_id'] == person_id(pat_raw)
            quinn_key, quinn_ssh, quinn_raw = ssh_key(root, 'quinn')
            person_invite = alice.cli('network', 'invite-person', '--network', net, '--member', 'quinn',
                                      '--expires-at', timestamp(600))
            assert person_invite['token'].startswith('capsule-person-invite-v1.')
            redeemed = bob.cli('network', 'redeem-person', '--token', person_invite['token'],
                               '--person-key', str(quinn_key))
            assert redeemed['person_id'] == person_id(quinn_raw)
            # Invite reuse is refused; an expired person invite fails locally.
            assert carol.call('POST', '/v1/networks/redeem-person',
                              {'token': person_invite['token'], 'person_public_key': pat_raw})[0] == 409
            expiring = alice.cli('network', 'invite-person', '--network', net, '--member', 'late',
                                 '--expires-at', timestamp(2))
            time.sleep(3)
            assert carol.call('POST', '/v1/networks/redeem-person',
                              {'token': expiring['token'], 'person_public_key': pat_raw})[0] == 400

            # Binding with host consent, through the agent and a key file.
            bound = bob.cli('network', 'bind', '--network', net)
            assert bound['person_id'] == person_id(pat_raw) and bound['host_id'] == b['id'], bound
            del os.environ['SSH_AUTH_SOCK']
            carol.cli('network', 'bind', '--network', net, '--person-key', str(pat_key))
            os.environ['SSH_AUTH_SOCK'] = agent.socket
            # A binding naming another host, from an unadmitted person, or a
            # second binding are refused.
            bob_binding = host_statements(bob, net, 'binding')
            assert len(bob_binding) == 1
            assert carol.call('POST', f'/v1/networks/{net}/bindings', {'binding': bob_binding[0]})[0] == 400
            stranger_key, _, _ = ssh_key(root, 'stranger')
            denied = carol.cli('network', 'bind', '--network', net, '--person-key', str(stranger_key), success=False)
            assert 'forbidden' in denied or 'not admitted' in denied, denied
            second = bob.cli('network', 'bind', '--network', net, '--person-key', str(quinn_key), success=False)
            assert 'conflict' in second.lower() or 'already bound' in second, second
            for host in (alice, bob, carol):
                host.cli('network', 'sync', net)
            for host_id in (b['id'], c['id']):
                m = member(alice, net, host_id)
                assert m['person_id'] == person_id(pat_raw) and m['person_member'] == 'pat', m
            persons = {p['person_id']: p for p in alice.cli('network', 'persons', net)}
            assert sorted(persons[person_id(pat_raw)]['hosts']) == sorted([b['id'], c['id']]), persons
            assert persons[person_id(quinn_raw)]['member'] == 'quinn' and persons[person_id(quinn_raw)]['hosts'] == []
            # Every stored person signature verifies with OpenSSH itself, and
            # every stored binding carries the bound host's own signature.
            for statement in host_statements(alice, net, 'binding'):
                ssh_verify(binding_lines(statement), statement['signature'], pat_ssh, root)
                assert len(base64.b64decode(statement['host_signature'])) == 64, statement
            # A compromised coordinator serves a binding of alice that alice
            # never signed, with a valid person signature from pat: hosts
            # verify the host signature themselves and ignore it.
            forged = {'network_id': net, 'person_public_key': pat_raw, 'host_public_key': a['public_key'],
                      'bound_at': timestamp(0), 'signature': '', 'host_signature': base64.b64encode(bytes(64)).decode()}
            forged['signature'] = ssh_sign(binding_lines(forged), pat_key, root)
            ssh_verify(binding_lines(forged), forged['signature'], pat_ssh, root)
            with coord_db(coord) as db:
                db.execute('INSERT INTO statements (network_id, kind, subject, statement) VALUES (?, ?, ?, ?)',
                           (net, 'binding', a['public_key'], json.dumps(forged)))
            for host in (alice, bob, carol):
                host.cli('network', 'sync', net)
                assert member(host, net, a['id'])['person_id'] is None, host.binary
            with coord_db(coord) as db:
                db.execute("DELETE FROM statements WHERE kind = 'binding' AND subject = ?", (a['public_key'],))

            # Unbinding is sticky, enforced at once, and survives omission and
            # restart; removing a person ends its bindings permanently.
            unbound = bob.cli('network', 'unbind', '--network', net, '--host', c['id'])
            assert unbound['kind'] == 'unbind', unbound
            unbinding = [s for s in host_statements(bob, net, 'unbind')]
            assert len(unbinding) == 1
            ssh_verify(binding_lines(unbinding[0], 'unbind'), unbinding[0]['signature'], pat_ssh, root)
            removed = alice.cli('network', 'remove-person', '--network', net, '--person', person_id(quinn_raw))
            assert removed['kind'] == 'person', removed
            for host in (alice, bob, carol):
                host.cli('network', 'sync', net)
            with coord_db(coord) as db:
                db.execute("DELETE FROM statements WHERE kind IN ('person', 'unbind')")
            for host in (alice, bob, carol):
                host.cli('network', 'sync', net)
                assert member(host, net, c['id'])['person_id'] is None
                assert person_id(quinn_raw) not in {p['person_id'] for p in host.cli('network', 'persons', net)}
            assert carol.cli('network', 'bind', '--network', net, '--person-key', str(pat_key), success=False)
            bob.stop(crash=True)
            bob.start()
            bob.cli('network', 'sync', net)
            assert member(bob, net, c['id'])['person_id'] is None
            assert member(bob, net, b['id'])['person_id'] == person_id(pat_raw)
            readmit = alice.cli('network', 'admit', '--network', net, '--person', quinn_ssh, '--member', 'quinn',
                                success=False)
            assert readmit

            # Rotation renews the admitted host and the remaining person.
            rotated = alice.cli('network', 'rotate-root', net)
            assert rotated['root_epoch'] == 1, rotated
            for host in (bob, carol):
                synced = host.cli('network', 'sync', net)
                assert synced['root_epoch'] == 1 and synced['last_sync_error'] is None, synced
            entry = member(bob, net, c['id'])
            assert entry['admission']['epoch'] == 1, entry
            assert {p['person_id'] for p in bob.cli('network', 'persons', net)} == {person_id(pat_raw)}
            assert member(carol, net, b['id'])['person_id'] == person_id(pat_raw)
            kinds = [(e['kind'], e['subject_id']) for e in alice.cli('activity', '--limit', '1000')]
            for event in [('network.host_admitted', c['id']), ('network.person_admitted', person_id(pat_raw)),
                          ('network.host_bound', b['id']), ('network.host_unbound', c['id']),
                          ('network.person_removed', person_id(quinn_raw))]:
                assert event in kinds, (event, kinds)
        finally:
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            stop_all((alice, bob, carol, dave))
            coord.stop()
            coord.logs.close()
            agent.stop()
    print(f'PASS {label}: persons by key and invite, admitted hosts by descriptor, consented bindings, '
          'OpenSSH-verified SSHSIG, host-signed bindings, sticky unbinding and removal, rotation renewal', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for creator in binaries:
        for joiner in binaries:
            check(args.coord.resolve(), binaries[creator], binaries[joiner], f'{creator} creator, {joiner} joiners')


if __name__ == '__main__':
    main()
