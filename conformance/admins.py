#!/usr/bin/env python3
"""Exercise administrators and groups (milestone 2b slice 2) with real hosts.

Runs one Go coordinator with Go and Rust hosts in every creator/joiner pairing.
Administrators sign through the CLI with real ssh-agents; the root moves to an
SSH key file. Forged statements, and statements by an administrator removed
with --revoke-admitted, are injected into the coordinator's SQLite database
and must be ignored by every host. Needs OpenSSH (ssh-agent, ssh-add,
ssh-keygen).
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from coordination import Coordinator
from host_service import stop_all
from peer_messaging import set_probe, timestamp
from persons import Agent, PersonHost, coord_db, person_id, ssh_key, ssh_sign, ssh_verify, use_agent


def persons(host, network):
    return {p['person_id']: p for p in host.cli('network', 'persons', network)}


def member_ids(host, network):
    return {m['host_id'] for m in host.cli('network', 'members', network)}


def groups(host, network):
    return {g['name']: g for g in host.cli('network', 'groups', network)}


def record(host, network):
    return next(n for n in host.cli('network', 'list') if n['id'] == network)


def statements(host, network, kind):
    with sqlite3.connect(host.state / 'host.db') as db:
        return [json.loads(r[0]) for r in db.execute(
            'SELECT record FROM network_statements WHERE network_id = ? AND kind = ?', (network, kind))]


def group_lines(g):
    return ['capsule-group-v1', g['network_id'], g['name'], str(g['version']), g['defined_at'], *g['members']]


def inject(coord, kind, subject, statement):
    with coord_db(coord) as db:
        db.execute('INSERT OR REPLACE INTO statements (network_id, kind, subject, statement) VALUES (?, ?, ?, ?)',
                   (statement['network_id'], kind, subject, json.dumps(statement)))


def check(coord_binary, creator_binary, joiner_binary, label):
    with tempfile.TemporaryDirectory(prefix='capsule-admins-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        names = ('alice', 'bob', 'carol', 'dave', 'erin', 'frank')
        hosts = {name: PersonHost(creator_binary if name == 'alice' else joiner_binary, root / name) for name in names}
        (root / 'keys').mkdir()
        keys = {name: ssh_key(root / 'keys', name) for name in ('pat', 'quinn', 'rhea', 'sam', 'uma', 'stranger', 'sshroot')}
        agents = {}
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        try:
            for name in ('pat', 'quinn', 'rhea'):
                (root / f'agent-{name}').mkdir()
                agents[name] = Agent(root / f'agent-{name}')
                agents[name].add(keys[name][0])
            coordinator = coord.start()
            ids = {name: host.start() for name, host in hosts.items()}
            alice, bob, carol, dave, erin, frank = (hosts[n] for n in names)
            pat_id, quinn_id, rhea_id, sam_id = (person_id(keys[n][2]) for n in ('pat', 'quinn', 'rhea', 'sam'))

            # Create delegates the creator's person (pat, label alice).
            use_agent(agents['pat'])
            created = alice.cli('network', 'create', '--name', 'team', '--member', 'alice',
                                '--coordinator', coord.address, '--coordinator-key', coordinator['public_key'])
            net = created['id']
            assert created['person']['admitted'] and created['person']['bound'], created
            assert persons(alice, net)[pat_id]['administrator'], persons(alice, net)
            invite = alice.cli('network', 'invite', '--network', net, '--member', 'alice', '--expires-at', timestamp(600))
            joined = bob.cli('network', 'join', '--token', invite['token'])
            assert joined['person']['bound'] and not joined['administrator'], joined

            # Pat administers from bob, which holds no root seed, with only the
            # SSH key: a host admission, and a member invite that admits quinn.
            admitted = bob.cli('network', 'admit', '--network', net, '--host', ids['carol']['public_key'], '--member', 'carol')
            carol.cli('network', 'join', '--descriptor', admitted['descriptor'], '--no-person')
            dave_invite = bob.cli('network', 'invite', '--network', net, '--member', 'quinn', '--expires-at', timestamp(600))
            use_agent(agents['quinn'])
            joined = dave.cli('network', 'join', '--token', dave_invite['token'])
            assert joined['person']['admitted'] and joined['person']['bound'], joined
            use_agent(agents['pat'])
            person_invite = bob.cli('network', 'invite-person', '--network', net, '--member', 'tess',
                                    '--expires-at', timestamp(600))
            assert person_invite['token'].startswith('capsule-person-invite-v1.'), person_invite
            for statement in statements(bob, net, 'host_admission'):
                if statement['host_public_key'] == ids['carol']['public_key']:
                    ssh_verify(['capsule-host-admit-v1', net, '0', statement['host_public_key'], 'carol',
                                statement['admitted_at']], statement['signature'], keys['pat'][1], root)

            # A non-administrator is refused with 403, through the CLI and the API.
            use_agent(agents['quinn'])
            refused = dave.cli('network', 'admit', '--network', net, '--host', ids['erin']['public_key'],
                               '--member', 'erin', success=False)
            assert 'forbidden' in refused, refused
            assert dave.call('POST', f'/v1/networks/{net}/hosts',
                             {'host_public_key': ids['erin']['public_key'], 'member': 'erin'})[0] == 403

            # The root delegates quinn (by label) and rhea; quinn admits erin
            # and versions a group; rhea admits sam.
            alice.cli('network', 'admit', '--network', net, '--person', keys['rhea'][1], '--member', 'rhea')
            delegated = alice.cli('network', 'delegate-admin', '--network', net, '--person', 'QUINN')
            assert delegated['person_id'] == quinn_id, delegated
            alice.cli('network', 'delegate-admin', '--network', net, '--person', rhea_id)
            dave.cli('network', 'sync', net)
            erin_admitted = dave.cli('network', 'admit', '--network', net, '--host', ids['erin']['public_key'],
                                     '--member', 'erin')
            erin.cli('network', 'join', '--descriptor', erin_admitted['descriptor'], '--no-person')
            use_agent(agents['rhea'])
            carol.cli('network', 'sync', net)
            carol.cli('network', 'admit', '--network', net, '--person', keys['sam'][1], '--member', 'sam')

            # Groups: pat's versions 1 and 2, the root's 3, quinn's 4.
            use_agent(agents['pat'])
            bob.cli('network', 'sync', net)
            first = bob.cli('network', 'group', 'set', '--network', net, '--group', 'backend', '--person', 'alice',
                            '--person', quinn_id)
            assert first['version'] == 1 and first['members'] == sorted([pat_id, quinn_id]), first
            assert bob.cli('network', 'group', 'set', '--network', net, '--group', 'backend', '--person', 'alice')['version'] == 2
            stale = next(g for g in statements(bob, net, 'group') if g['name'] == 'backend')
            assert bob.call('POST', f'/v1/networks/{net}/groups', {'group': stale})[0] == 409
            alice.cli('network', 'sync', net)
            assert alice.cli('network', 'group', 'set', '--network', net, '--group', 'backend', '--person', 'rhea')['version'] == 3
            use_agent(agents['quinn'])
            dave.cli('network', 'sync', net)
            fourth = dave.cli('network', 'group', 'set', '--network', net, '--group', 'backend', '--person', 'quinn')
            assert fourth['version'] == 4 and fourth['signer'] == keys['quinn'][2], fourth
            ssh_verify(group_lines(next(g for g in statements(dave, net, 'group') if g['name'] == 'backend')),
                       fourth_signature(dave, net), keys['quinn'][1], root)
            # Deletion: no members.
            dave.cli('network', 'group', 'set', '--network', net, '--group', 'ops', '--person', 'sam')
            dave.cli('network', 'group', 'set', '--network', net, '--group', 'ops')
            for host in (alice, bob, carol, dave, erin):
                host.cli('network', 'sync', net)
                listed = groups(host, net)
                assert listed['backend']['version'] == 4 and 'ops' not in listed, (host.binary, listed)
            # A conflicting label (only a misbehaving coordinator can serve
            # one) makes resolution fail with the candidates listed.
            twin = {'network_id': net, 'epoch': 0, 'person_public_key': keys['stranger'][2], 'member': 'SAM',
                    'admitted_at': timestamp(0)}
            twin['signature'] = ssh_sign(['capsule-person-admit-v1', net, '0', twin['person_public_key'], 'SAM',
                                          twin['admitted_at']], keys['pat'][0], root)
            with coord_db(coord) as db:
                db.execute('INSERT INTO statements (network_id, kind, subject, statement) VALUES (?, ?, ?, ?)',
                           (net, 'person_admission', twin['person_public_key'],
                            json.dumps({'admission': twin, 'membership': None})))
            use_agent(agents['pat'])
            for host in (alice, bob):
                host.cli('network', 'sync', net)
                ambiguous = host.cli('network', 'group', 'set', '--network', net, '--group', 'ops', '--person', 'sam',
                                     success=False)
                assert 'ambiguous' in ambiguous and sam_id in ambiguous, ambiguous
            with coord_db(coord) as db:
                db.execute("DELETE FROM statements WHERE kind = 'person_admission' AND subject = ?", (keys['stranger'][2],))

            # A current administrator cannot be removed as a person.
            conflict = alice.cli('network', 'remove-person', '--network', net, '--person', rhea_id, success=False)
            assert 'conflict' in conflict.lower() or 'administrator' in conflict, conflict
            # Removing rhea keeps exactly what rhea signed, listed by digest;
            # rhea can sign nothing new, even backdated.
            alice.cli('network', 'remove-admin', '--network', net, '--person', 'rhea')
            removal = next(r for r in statements(alice, net, 'admin_removal') if r['person_public_key'] == keys['rhea'][2])
            assert not removal['revoke_admitted'] and len(removal['kept']) == 1, removal
            backdated = {'network_id': net, 'epoch': 0, 'host_public_key': ids['frank']['public_key'], 'member': 'frank',
                         'admitted_at': '2020-01-01T00:00:00Z'}
            backdated['signature'] = ssh_sign(['capsule-host-admit-v1', net, '0', backdated['host_public_key'], 'frank',
                                               backdated['admitted_at']], keys['rhea'][0], root)
            with coord_db(coord) as db:
                db.execute('INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at, '
                           "admission) VALUES (?, ?, ?, '', '', ?, ?)",
                           (net, ids['frank']['id'], 'admission:' + backdated['host_public_key'], timestamp(0),
                            json.dumps(backdated)))
            for host in (alice, bob, carol):
                host.cli('network', 'sync', net)
                assert ids['frank']['id'] not in member_ids(host, net), host.binary
                assert sam_id in persons(host, net), host.binary
            with coord_db(coord) as db:
                db.execute('DELETE FROM members WHERE host_id = ?', (ids['frank']['id'],))
            use_agent(agents['rhea'])
            carol.cli('network', 'sync', net)
            assert not persons(carol, net)[rhea_id]['administrator'] and sam_id in persons(carol, net)
            assert 'forbidden' in carol.cli('network', 'admit', '--network', net, '--host', ids['frank']['public_key'],
                                            '--member', 'frank', success=False)
            # One removal per administrator: a second plain one is refused; an
            # escalation to --revoke-admitted is allowed and drops sam.
            again = alice.cli('network', 'remove-admin', '--network', net, '--person', rhea_id, success=False)
            assert 'conflict' in again.lower() or 'already' in again, again
            alice.cli('network', 'remove-admin', '--network', net, '--person', rhea_id, '--revoke-admitted')
            for host in (alice, bob, carol):
                host.cli('network', 'sync', net)
                assert sam_id not in persons(host, net), host.binary
            removed_events = [e for e in alice.cli('activity', '--limit', '1000')
                              if e['kind'] == 'network.admin_removed' and e['subject_id'] == rhea_id]
            assert len(removed_events) == 2, removed_events
            # Removing quinn with --revoke-admitted drops erin, and backend
            # reverts to the root's version 3.
            removed = alice.cli('network', 'remove-admin', '--network', net, '--person', quinn_id, '--revoke-admitted')
            assert removed['kind'] == 'admin' and removed['submitted'], removed
            assert ids['erin']['id'] not in member_ids(alice, net)
            for host in (alice, bob, carol, dave):
                host.cli('network', 'sync', net)
                assert ids['erin']['id'] not in member_ids(host, net), host.binary
                assert groups(host, net)['backend']['version'] == 3, (host.binary, groups(host, net))
                assert not persons(host, net)[quinn_id]['administrator']
            # Forged statements and ones by quinn, injected at the
            # coordinator, are ignored by hosts.
            for signer, version in (('quinn', 5), ('stranger', 6)):
                forged = {'network_id': net, 'name': 'backend', 'version': version, 'defined_at': timestamp(0),
                          'members': [quinn_id]}
                forged['signature'] = ssh_sign(group_lines(forged), keys[signer][0], root)
                inject(coord, 'group', f'backend {version:020d}', forged)
            # Revocations and members are served as stored: a revocation of
            # carol and an admitted member, signed by quinn or forged.
            for signer in ('quinn', 'stranger'):
                revocation = {'network_id': net, 'host_public_key': ids['carol']['public_key'], 'revoked_at': timestamp(0)}
                revocation['signature'] = ssh_sign(['capsule-revoke-host-v1', net, revocation['host_public_key'],
                                                    revocation['revoked_at']], keys[signer][0], root)
                inject(coord, 'host', ids['carol']['public_key'], revocation)
                _, _, mallory_raw = ssh_key(root / 'keys', f'mallory-{signer}')
                admission = {'network_id': net, 'epoch': 0, 'host_public_key': mallory_raw, 'member': 'mallory',
                             'admitted_at': timestamp(0)}
                admission['signature'] = ssh_sign(['capsule-host-admit-v1', net, '0', mallory_raw, 'mallory',
                                                   admission['admitted_at']], keys[signer][0], root)
                mallory_id = 'host_' + hashlib.sha256(base64.b64decode(mallory_raw)).hexdigest()
                with coord_db(coord) as db:
                    db.execute('INSERT INTO members (network_id, host_id, invite_public_key, membership, address, '
                               'updated_at, admission) VALUES (?, ?, ?, \'\', \'\', ?, ?)',
                               (net, mallory_id, 'admission:' + mallory_raw, timestamp(0), json.dumps(admission)))
                for host in (alice, bob, carol, dave):
                    host.cli('network', 'sync', net)
                    assert groups(host, net)['backend']['version'] == 3, (host.binary, groups(host, net))
                    current = member_ids(host, net)
                    assert ids['carol']['id'] in current and mallory_id not in current, (host.binary, signer)
                with coord_db(coord) as db:
                    db.execute("DELETE FROM statements WHERE kind = 'host' AND subject = ?", (ids['carol']['public_key'],))
                    db.execute('DELETE FROM members WHERE host_id = ?', (mallory_id,))

            # Rotate the root to an SSH key file: the creator's host deletes
            # its seed; administrators keep working; root actions take --root-key.
            rotated = alice.cli('network', 'rotate-root', net, '--to-ssh', '--root-key', str(keys['sshroot'][0]))
            assert rotated['root_epoch'] == 1 and rotated['root_ssh'] and not rotated['administrator'], rotated
            with sqlite3.connect(alice.state / 'host.db') as db:
                assert db.execute('SELECT root_seed FROM networks WHERE id = ?', (net,)).fetchone()[0] is None
            for host in (bob, carol, dave):
                synced = host.cli('network', 'sync', net)
                assert synced['root_epoch'] == 1 and synced['root_ssh'] and synced['last_sync_error'] is None, synced
            assert ids['carol']['id'] in member_ids(bob, net) and ids['dave']['id'] in member_ids(bob, net)
            use_agent(agents['pat'])
            assert persons(bob, net)[pat_id]['administrator']
            admitted = bob.cli('network', 'admit', '--network', net, '--host', ids['frank']['public_key'], '--member', 'frank')
            frank.cli('network', 'join', '--descriptor', admitted['descriptor'], '--no-person')
            # The root-signed group (backend, version 3) was renewed by the new root.
            renewed = groups(bob, net)['backend']
            assert renewed['version'] == 3 and renewed['signer'] == keys['sshroot'][2], renewed
            uma_id = person_id(keys['uma'][2])
            alice.cli('network', 'admit', '--network', net, '--person', keys['uma'][1], '--member', 'uma',
                      '--person-key', str(keys['pat'][0]) + '.pub')
            refused = alice.cli('network', 'delegate-admin', '--network', net, '--person', 'uma', success=False)
            assert 'root-key' in refused, refused
            alice.cli('network', 'delegate-admin', '--network', net, '--person', 'uma', '--root-key', str(keys['sshroot'][0]))
            bob.cli('network', 'sync', net)
            assert persons(bob, net)[uma_id]['administrator']
            for d in statements(bob, net, 'admin'):
                if d['person_public_key'] == keys['uma'][2]:
                    ssh_verify(['capsule-admin-delegate-v1', net, '1', d['person_public_key'], d['delegated_at']],
                               d['signature'], keys['sshroot'][1], root)
            kinds = {(e['kind'], e['subject_id']) for e in bob.cli('activity', '--limit', '1000')}
            for event in [('network.admin_delegated', quinn_id), ('network.admin_removed', quinn_id),
                          ('network.group_updated', 'backend')]:
                assert event in kinds, (event, kinds)
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
    print(f'PASS {label}: creator delegated, administration from a second machine by SSH key, 403 for '
          'non-administrators, delegation and removal with and without --revoke-admitted, group versions, '
          'deletion, revert and ambiguity, rotate-root --to-ssh, injected statements ignored', flush=True)


def fourth_signature(host, network):
    return next(g for g in statements(host, network, 'group') if g['name'] == 'backend')['signature']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    parser.add_argument('--pairing', action='append', help='creator/joiner, such as Go/Rust; default all')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for creator in binaries:
        for joiner in binaries:
            if args.pairing and f'{creator}/{joiner}' not in args.pairing:
                continue
            check(args.coord.resolve(), binaries[creator], binaries[joiner], f'{creator} creator, {joiner} joiners')


if __name__ == '__main__':
    main()
