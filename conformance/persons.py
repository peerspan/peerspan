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

from support import Coordinator, wait_for
from host_service import die_with_parent, stop_all
from peer_messaging import PeerHost, set_probe, timestamp

INTERVAL = 1
NAMESPACE = 'peerspan-person-v1'


class PersonHost(PeerHost):
    keep_agent = True

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


def root_sign(host, network, lines, directory):
    """Sign statement lines with the administrator's current root seed, via OpenSSL."""
    with sqlite3.connect(host.state / 'host.db') as db:
        seed = db.execute('SELECT root_seed FROM networks WHERE id = ?', (network,)).fetchone()[0]
    key = Path(directory) / 'root-signing.der'
    key.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + bytes(seed))
    key.chmod(0o600)
    message = Path(directory) / 'root-message'
    message.write_bytes('\n'.join(lines).encode())
    signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-keyform', 'DER', '-inkey', str(key),
                                '-in', str(message)], capture_output=True, check=True, timeout=10).stdout
    key.unlink()
    return base64.b64encode(signature).decode()


def binding_lines(b, kind='bind'):
    at = b['bound_at'] if kind == 'bind' else b['unbound_at']
    return [f'peerspan-host-{kind}-v1', b['network_id'], b['person_public_key'], b['host_public_key'], at]


def member(host, network, host_id):
    return next(m for m in host.cli('network', 'members', network) if m['host_id'] == host_id)


def check(coord_binary, creator_binary, joiner_binary, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-persons-') as temporary:
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
            network = alice.cli('network', 'create', '--name', 'team', '--member', 'alice', '--no-person',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            net = network['id']
            invite = alice.cli('network', 'invite', '--network', net, '--member', 'bob', '--expires-at', timestamp(600))
            bob.cli('network', 'join', '--token', invite['token'], '--no-person')

            # Host admitted by public key joins with the descriptor; an
            # unadmitted host is refused.
            refused = carol.cli('network', 'admit', '--network', net, '--host', d['public_key'], '--member', 'dave',
                                success=False)
            assert 'forbidden' in refused or 'not found' in refused.lower(), refused
            admitted = alice.cli('network', 'admit', '--network', net, '--host', c['public_key'], '--member', 'carol')
            assert admitted['host_id'] == c['id'] and admitted['descriptor'].startswith('peerspan-network-v1.')
            assert dave.call('POST', '/v1/networks/join', {'descriptor': admitted['descriptor']})[0] == 403
            joined = carol.cli('network', 'join', '--descriptor', admitted['descriptor'], '--no-person')
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
            # Person labels are unique ignoring ASCII case: the administrator
            # refuses locally, and the coordinator refuses an invite redeemed
            # under a label taken after the invite was issued.
            rhea_key, rhea_ssh, rhea_raw = ssh_key(root, 'rhea')
            taken = alice.cli('network', 'admit', '--network', net, '--person', rhea_ssh, '--member', 'PAT',
                              success=False)
            assert 'conflict' in taken.lower() or 'taken' in taken, taken
            assert 'conflict' in alice.cli('network', 'invite-person', '--network', net, '--member', 'Pat',
                                           '--expires-at', timestamp(600), success=False).lower()
            late_label = alice.cli('network', 'invite-person', '--network', net, '--member', 'Rhea',
                                   '--expires-at', timestamp(600))
            sam_key, sam_ssh, sam_raw = ssh_key(root, 'sam')
            alice.cli('network', 'admit', '--network', net, '--person', sam_ssh, '--member', 'rhea')
            assert bob.call('POST', '/v1/networks/redeem-person',
                            {'token': late_label['token'], 'person_public_key': rhea_raw})[0] == 409
            quinn_key, quinn_ssh, quinn_raw = ssh_key(root, 'quinn')
            person_invite = alice.cli('network', 'invite-person', '--network', net, '--member', 'quinn',
                                      '--expires-at', timestamp(600))
            assert person_invite['token'].startswith('peerspan-person-invite-v1.')
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
            # Bob's own binding: carol's may already have arrived by sync.
            bob_binding = [s for s in host_statements(bob, net, 'binding') if s.get('host_public_key') == b['public_key']]
            assert len(bob_binding) == 1, [(b.get('person_public_key'), b.get('host_public_key')) for b in bob_binding]
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
            # Removing quinn frees the label for a different key.
            new_quinn = alice.cli('network', 'admit', '--network', net, '--person', rhea_ssh, '--member', 'QUINN')
            assert new_quinn['person_id'] == person_id(rhea_raw)

            # Rotation renews the admitted host and the remaining person.
            rotated = alice.cli('network', 'rotate-root', net)
            assert rotated['root_epoch'] == 1, rotated
            for host in (bob, carol):
                synced = host.cli('network', 'sync', net)
                assert synced['root_epoch'] == 1 and synced['last_sync_error'] is None, synced
            entry = member(bob, net, c['id'])
            assert entry['admission']['epoch'] == 1, entry
            assert {p['person_id'] for p in bob.cli('network', 'persons', net)} == {
                person_id(pat_raw), person_id(sam_raw), person_id(rhea_raw)}
            assert member(carol, net, b['id'])['person_id'] == person_id(pat_raw)
            assert not any(p['label_conflict'] for p in bob.cli('network', 'persons', net))
            # A misbehaving coordinator serves a second current person under a
            # conflicting label: hosts keep both and flag them.
            _, _, tia_raw = ssh_key(root, 'tia')
            admission = {'network_id': net, 'epoch': 1, 'person_public_key': tia_raw, 'member': 'pAt',
                         'admitted_at': timestamp(0)}
            admission['signature'] = root_sign(alice, net, ['peerspan-person-admit-v1', net, '1', tia_raw, 'pAt',
                                                            admission['admitted_at']], root)
            with coord_db(coord) as db:
                db.execute('INSERT INTO statements (network_id, kind, subject, statement) VALUES (?, ?, ?, ?)',
                           (net, 'person_admission', tia_raw, json.dumps({'admission': admission, 'membership': None})))
            for host in (bob, carol):
                host.cli('network', 'sync', net)
                flagged = {p['person_id']: p['label_conflict'] for p in host.cli('network', 'persons', net)}
                assert flagged[person_id(tia_raw)] and flagged[person_id(pat_raw)], (host.binary, flagged)
                assert not flagged[person_id(sam_raw)], flagged
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


def use_agent(agent):
    """Point the CLI at one agent, or at none."""
    if agent is None:
        os.environ.pop('SSH_AUTH_SOCK', None)
    else:
        os.environ['SSH_AUTH_SOCK'] = agent.socket


def check_one_command(coord_binary, creator_binary, joiner_binary, label):
    """The default flows: create, then one member invite and one join per machine."""
    with tempfile.TemporaryDirectory(prefix='peerspan-onecmd-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        hosts = {name: PersonHost(creator_binary if name == 'alice' else joiner_binary, root / name)
                 for name in ('alice', 'bob', 'bob2', 'carol', 'dave', 'erin', 'frank', 'gina')}
        (root / 'keys').mkdir()
        keys = {name: ssh_key(root / 'keys', name) for name in ('alice', 'bob', 'carol', 'dave', 'dave2', 'erin', 'frank', 'gina')}
        agents = {}
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        try:
            for name in ('alice', 'bob', 'dave', 'erin', 'frank', 'gina'):
                (root / f'agent-{name}').mkdir()
                agents[name] = Agent(root / f'agent-{name}')
                agents[name].add(keys[name][0])
            agents['dave'].add(keys['dave2'][0])  # several identities
            coordinator = coord.start()
            ids = {name: host.start() for name, host in hosts.items()}
            alice = hosts['alice']

            def invite(member, *extra):
                return alice.cli('network', 'invite', '--network', net, '--member', member,
                                 '--expires-at', timestamp(600), *extra)

            # Create with an agent: the creator is admitted and bound in one command.
            use_agent(agents['alice'])
            created = alice.cli('network', 'create', '--name', 'team', '--member', 'alice',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            net = created['id']
            alice_id = person_id(keys['alice'][2])
            person = created['person']
            assert person['person_id'] == alice_id and person['admitted'] and person['bound'] and not person['skipped'], person

            # One member invite, one join: host, person, and binding.
            bob_invite = invite('bob')
            assert bob_invite['token'].startswith('peerspan-member-invite-v1.'), bob_invite
            use_agent(agents['bob'])
            joined = hosts['bob'].cli('network', 'join', '--token', bob_invite['token'])
            bob_id = person_id(keys['bob'][2])
            person = joined['person']
            assert joined['id'] == net and person['person_id'] == bob_id and person['admitted'] and person['bound'], joined
            assert not person['skipped'], joined
            # Bob's second machine binds to the already-admitted Bob.
            joined = hosts['bob2'].cli('network', 'join', '--token', invite('bob')['token'])
            assert joined['person']['bound'] and joined['person']['admitted'] and joined['person']['skipped'] is None, joined

            # Host-only join: the reason and exact next command are reported, and
            # the token's person half stays redeemable. (Without --no-person a
            # key is now generated; launch_onboarding.py covers that.)
            use_agent(None)
            carol_invite = invite('carol')
            joined = hosts['carol'].cli('network', 'join', '--token', carol_invite['token'], '--no-person')
            person = joined['person']
            assert joined['id'] == net and not person['admitted'] and not person['bound'], joined
            assert person['skipped'] and person['next'], person
            hosts['carol'].cli('network', 'redeem-person', '--token', carol_invite['token'], '--person-key', str(keys['carol'][0]))
            bound = hosts['carol'].cli('network', 'bind', '--network', net, '--person-key', str(keys['carol'][0]))
            assert bound['person_id'] == person_id(keys['carol'][2]), bound

            # --no-person skips the person part. (Several agent identities are now
            # refused without it; launch_onboarding.py covers that.)
            use_agent(agents['dave'])
            joined = hosts['dave'].cli('network', 'join', '--token', invite('dave')['token'], '--no-person')
            assert joined['id'] == net and joined['person']['skipped'] and not joined['person']['bound'], joined
            use_agent(agents['erin'])
            joined = hosts['erin'].cli('network', 'join', '--token', invite('erin')['token'], '--no-person')
            assert joined['person']['skipped'] and not joined['person']['bound'], joined

            # A taken label skips the person part without undoing the host join.
            use_agent(agents['frank'])
            joined = hosts['frank'].cli('network', 'join', '--token', invite('BOB')['token'])
            person = joined['person']
            assert joined['id'] == net and person['person_id'] == person_id(keys['frank'][2]), joined
            # skipped/next wording differs between implementations; check presence.
            assert not person['admitted'] and not person['bound'] and person['skipped'] and person['next'], person

            # A host-only invite joins the host; an unadmitted person is reported.
            host_only = invite('gina', '--host-only')
            assert host_only['token'].startswith('peerspan-invite-v1.'), host_only
            use_agent(agents['gina'])
            joined = hosts['gina'].cli('network', 'join', '--token', host_only['token'])
            person = joined['person']
            assert joined['id'] == net and not person['admitted'] and person['skipped'] and person['next'], person

            alice.cli('network', 'sync', net)
            members = {m['host_id']: m['person_id'] for m in alice.cli('network', 'members', net)}
            assert members[ids['alice']['id']] == alice_id and members[ids['bob']['id']] == bob_id, members
            assert members[ids['bob2']['id']] == bob_id and members[ids['carol']['id']] == person_id(keys['carol'][2])
            for name in ('dave', 'erin', 'frank', 'gina'):
                assert members[ids[name]['id']] is None, (name, members)
            persons = {p['person_id']: p for p in alice.cli('network', 'persons', net)}
            assert sorted(persons[bob_id]['hosts']) == sorted([ids['bob']['id'], ids['bob2']['id']]), persons
            assert set(persons) == {alice_id, bob_id, person_id(keys['carol'][2])}, persons
            for statement in host_statements(alice, net, 'binding'):
                ssh_key_line = next(k[1] for k in keys.values() if k[2] == statement['person_public_key'])
                ssh_verify(binding_lines(statement), statement['signature'], ssh_key_line, root)
        finally:
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            stop_all(tuple(hosts.values()))
            coord.stop()
            coord.logs.close()
            for agent in agents.values():
                agent.stop()
    print(f'PASS {label}: one-command create and member-invite join with an agent, second machine, '
          'no-agent / several-keys / --no-person / taken-label / host-only skips with exact next commands', flush=True)


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
            check_one_command(args.coord.resolve(), binaries[creator], binaries[joiner],
                              f'{creator} creator, {joiner} joiners')


if __name__ == '__main__':
    main()
