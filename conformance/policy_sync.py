#!/usr/bin/env python3
"""Exercise direct policy propagation among an owner's hosts (roadmap 2c).

Runs one Go coordinator with every Go/Rust combination of an owner's two
hosts (alice and bob, both bound to pat), plus a third host (carol, bound to
quinn) as the sender, with real ssh-agents. It covers:

- a withdrawal signed on alice while the coordinator is stopped: bob stores
  it by direct push and refuses carol under the withdrawn rule, and the
  coordinator receives it once restarted;
- bob offline during a push (with the coordinator stopped too), catching up on
  restart by its start-up sync;
- concurrent same-version policies signed on each sibling converging on the
  lower statement hash;
- refusal of pushes and fetches from a non-sibling, and of lower versions;
- `access sync` and `access sync --status`;
- migration from database version 11 to 12, and refusal of version 13.

The coordinator is stopped and restarted to simulate one that withholds a
policy. States are polled; no daemon flag beyond --coordination-interval is
needed. Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen).
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from coordination import Coordinator, wait_for
from host_service import stop_all
from peer_messaging import fixture_context, set_probe, timestamp, wire
from persons import Agent, coord_db, person_id, ssh_key, ssh_verify, use_agent
from policy import PolicyHost, crafted, policy_lines, policy_of, send, show

DELIVERY_FIELDS = {'target', 'version', 'state', 'attempts', 'next_attempt_at', 'error', 'delivered_at'}


def policy_hash(p):
    return hashlib.sha256('\n'.join(policy_lines(p)).encode()).hexdigest()


def status(host, net, sync=False):
    args = ['access', 'sync', '--network', net]
    return host.cli(*args) if sync else host.cli(*args, '--status')


def deliveries(value):
    for d in value['deliveries']:
        assert set(d) == DELIVERY_FIELDS, d
    return {d['target']: d for d in value['deliveries']}


def events(host):
    return [(e['kind'], e['subject_id']) for e in host.cli('activity', '--limit', '1000')]


def stored(host, net, pid):
    """The policy a host holds for a person, without expires_soon."""
    code, value = host.call('GET', f'/v1/networks/{net}/policy?person={pid}')
    return policy_of(value) if code == 200 else None


def user_version(host):
    with sqlite3.connect(host.state / 'host.db') as db:
        return db.execute('PRAGMA user_version').fetchone()[0]


def check(coord_binary, first_binary, second_binary, sender_binary, label):
    with tempfile.TemporaryDirectory(prefix='capsule-policy-sync-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        alice = PolicyHost(first_binary, root / 'alice')
        bob = PolicyHost(second_binary, root / 'bob')
        carol = PolicyHost(sender_binary, root / 'carol')
        hosts = (alice, bob, carol)
        (root / 'keys').mkdir()
        keys = {name: ssh_key(root / 'keys', name) for name in ('pat', 'quinn')}
        agents = {}
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        try:
            for name in keys:
                (root / f'agent-{name}').mkdir()
                agents[name] = Agent(root / f'agent-{name}')
                agents[name].add(keys[name][0])
            pat_key, pat_id = keys['pat'][2], person_id(keys['pat'][2])
            quinn_id = person_id(keys['quinn'][2])
            coordinator = coord.start()
            ids = {host: host.start()['id'] for host in hosts}
            a, b, c = ids[alice], ids[bob], ids[carol]

            # Pat creates the network on alice and joins bob as a second machine;
            # quinn joins carol.
            use_agent(agents['pat'])
            net = alice.cli('network', 'create', '--name', 'team', '--member', 'pat', '--coordinator', coord.address,
                            '--coordinator-key', coordinator['public_key'])['id']
            for host, name in ((bob, 'pat'), (carol, 'quinn')):
                invite = alice.cli('network', 'invite', '--network', net, '--member', name, '--expires-at', timestamp())
                use_agent(agents[name])
                assert host.cli('network', 'join', '--token', invite['token'])['person']['bound']
            for host in hosts:
                host.cli('network', 'sync', net)
            members = {m['host_id']: m['person_id'] for m in alice.cli('network', 'members', net)}
            assert members == {a: pat_id, b: pat_id, c: quinn_id}, members
            reviewer = bob.cli('agent', 'register', '--name', 'reviewer', '--owner', 'pat')
            alice.cli('agent', 'register', '--name', 'reviewer', '--owner', 'pat')

            # A policy signed on alice reaches bob directly and the coordinator.
            use_agent(agents['pat'])
            v1 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn')
            assert v1['version'] == 1, v1
            ssh_verify(policy_lines(v1), v1['signature'], keys['pat'][1], root)
            wait_for(lambda: stored(bob, net, pat_id) == v1, message='push of v1')

            def all_delivered(host, version):
                d = deliveries(status(host, net))
                return d if d and all(x['state'] == 'delivered' and x['version'] == version for x in d.values()) else None
            d = wait_for(lambda: all_delivered(alice, 1), message='v1 deliveries')
            assert set(d) == {'coordinator', b}, d
            carol.cli('network', 'sync', net)
            assert stored(carol, net, pat_id) == v1
            out = send(carol, b, reviewer)
            assert out['state'] == 'accepted' and out['request']['policy'] == {'person_id': pat_id, 'version': 1}, out

            # A withdrawal while the coordinator is stopped: bob stores it by
            # push and refuses carol, who still cites version 1.
            coord.stop()
            v2 = alice.cli('access', 'deny', '--network', net, '--agent', 'reviewer')
            assert v2['version'] == 2 and v2['rules'] == [], v2
            assert stored(alice, net, pat_id) == v2
            wait_for(lambda: stored(bob, net, pat_id) == v2, message='push of the withdrawal')
            refused = send(carol, b, reviewer, content='withdrawn')
            assert refused['state'] == 'rejected' and 'HTTP 403' in refused['error'], refused
            assert refused['request']['policy'] == {'person_id': pat_id, 'version': 1}, refused
            pending = deliveries(status(alice, net))['coordinator']
            assert pending['state'] == 'pending' and pending['version'] == 2 and pending['attempts'] >= 1, pending
            assert pending['error'] and pending['next_attempt_at'] and pending['delivered_at'] is None, pending
            assert deliveries(status(alice, net))[b]['state'] == 'delivered'
            # Once restarted, the coordinator receives it by retry.
            coord.start()
            wait_for(lambda: deliveries(status(alice, net))['coordinator']['state'] == 'delivered', timeout=30,
                     message='coordinator delivery after restart')
            with coord_db(coord) as db:
                served = json.loads(db.execute("SELECT statement FROM statements WHERE network_id = ? AND kind = 'policy' "
                                               "AND subject = ?", (net, pat_key)).fetchone()[0])
            assert served == v2, served
            carol.cli('network', 'sync', net)
            assert stored(carol, net, pat_id) == v2

            # Bob offline during a push catches up at start-up by syncing with
            # alice, before alice's backed-off retry. The coordinator is stopped
            # too, so that the sync is bob's only source.
            coord.stop()
            bob.stop()
            v3 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn')
            assert v3['version'] == 3

            def backed_off():
                x = deliveries(status(alice, net))[b]
                if x['state'] != 'pending' or x['version'] != 3 or not x['error'] or not x['next_attempt_at']:
                    return None
                due = datetime.fromisoformat(x['next_attempt_at'].replace('Z', '+00:00'))
                return x if due - datetime.now(timezone.utc) > timedelta(seconds=4) else None
            wait_for(backed_off, timeout=60, message='backed-off delivery to bob')
            bob.start()
            wait_for(lambda: stored(bob, net, pat_id) == v3, timeout=8, message='start-up sync')
            assert ('network.policy_synced', f'{pat_id}/{a}') in events(bob), events(bob)
            # access sync retries alice's pending delivery, which completes.
            d = deliveries(status(alice, net, sync=True))
            assert d[b]['state'] == 'delivered' and d[b]['version'] == 3 and d[b]['error'] is None, d
            assert d[b]['next_attempt_at'] is None and d[b]['delivered_at'] and d[b]['attempts'] >= 2, d
            # access sync also retries the backed-off coordinator delivery.
            coord.start()
            wait_for(lambda: deliveries(status(alice, net, sync=True))['coordinator']['state'] == 'delivered',
                     timeout=30, message='coordinator delivery of v3')
            for host in hosts:
                host.cli('network', 'sync', net)
            assert send(carol, b, reviewer, content='caught up')['state'] == 'accepted'

            # Concurrent same-version policies, one signed on each sibling while
            # the other is down and the coordinator is stopped, converge on the
            # lower statement hash.
            coord.stop()
            bob.stop()
            x = alice.cli('access', 'allow', '--network', net, '--agent', 'x', '--principal', 'network')
            alice.stop()
            bob.start()
            y = bob.cli('access', 'allow', '--network', net, '--agent', 'y', '--principal', 'network')
            assert x['version'] == y['version'] == 4 and x['signature'] != y['signature'], (x, y)
            winner, loser = sorted((x, y), key=policy_hash)
            alice.start()
            for host in (alice, bob, alice):
                status(host, net, sync=True)
            for host in (alice, bob):
                wait_for(lambda: stored(host, net, pat_id) == winner, message='tie-break convergence')
                view = status(host, net)
                assert view['person_id'] == pat_id and view['version'] == 4 and view['sha256'] == policy_hash(winner), view
            # The coordinator keeps the first it accepts and refuses the other
            # with 409, which completes that delivery; hosts keep the winner.
            coord.start()
            for host in (alice, bob):
                wait_for(lambda: deliveries(status(host, net, sync=True))['coordinator']['state'] == 'delivered',
                         timeout=30, message='coordinator delivery of the same version')
            with coord_db(coord) as db:
                served = json.loads(db.execute("SELECT statement FROM statements WHERE network_id = ? AND kind = 'policy' "
                                               "AND subject = ?", (net, pat_key)).fetchone()[0])
            assert served in (x, y), served
            for host in (alice, bob):
                host.cli('network', 'sync', net)
                assert stored(host, net, pat_id) == winner
            # The equal-version loser is refused locally on both.
            for host in (alice, bob):
                assert host.call('POST', f'/v1/networks/{net}/policy', {'policy': loser})[0] == 409
                assert host.call('POST', f'/v1/networks/{net}/policy', {'policy': winner}) == (201, winner)

            # Peer routes: a non-sibling is refused; a sibling's lower version is
            # reported, not stored; an invalid policy is refused.
            as_carol, as_alice = fixture_context(carol), fixture_context(alice)
            assert wire(bob, as_carol, 'POST', f'/peer/v1/networks/{net}/policies', {'policy': winner})[0] == 403
            assert wire(bob, as_carol, 'GET', f'/peer/v1/networks/{net}/policies/{pat_id}')[0] == 403
            assert wire(carol, as_alice, 'POST', f'/peer/v1/networks/{net}/policies', {'policy': winner})[0] == 403
            assert wire(bob, as_alice, 'GET', f'/peer/v1/networks/{net}/policies/{quinn_id}')[0] == 403
            assert wire(bob, as_alice, 'GET', f'/peer/v1/networks/{net}/policies/{pat_id}') == (200, winner)
            head = {'person_id': pat_id, 'version': 4, 'sha256': policy_hash(winner)}
            assert wire(bob, as_alice, 'POST', f'/peer/v1/networks/{net}/policies', {'policy': v1}) == (200, head)
            assert wire(bob, as_alice, 'POST', f'/peer/v1/networks/{net}/policies', {'policy': loser}) == (200, head)
            tampered = {**winner, 'version': 9}
            assert wire(bob, as_alice, 'POST', f'/peer/v1/networks/{net}/policies', {'policy': tampered})[0] == 400
            now = datetime.now(timezone.utc)
            expired = crafted(winner, 9, now - timedelta(days=3), now - timedelta(days=1), keys['pat'][0], root)
            assert wire(bob, as_alice, 'POST', f'/peer/v1/networks/{net}/policies', {'policy': expired})[0] == 400
            assert wire(bob, as_alice, 'POST', f'/peer/v1/networks/{net}/policies', {'policy': winner, 'x': 1})[0] == 400
            assert stored(bob, net, pat_id) == winner
            assert alice.call('POST', f'/v1/networks/{net}/policy', {'policy': v1})[0] == 409

            # access sync and its status.
            for host, sibling in ((alice, b), (bob, a)):
                view = status(host, net, sync=True)
                assert set(view) == {'person_id', 'version', 'sha256', 'deliveries'}, view
                assert [d['target'] for d in view['deliveries']] == sorted(['coordinator', sibling]), view
                assert all(d['state'] == 'delivered' and d['version'] == 4 for d in view['deliveries']), view
                assert status(host, net) == view
            quinn_view = status(carol, net)
            assert quinn_view == {'person_id': quinn_id, 'version': None, 'sha256': None, 'deliveries': []}, quinn_view
            assert alice.call('GET', '/v1/networks/net_missing/policy/sync')[0] == 404
            kinds = set(events(alice)) | set(events(bob))
            for kind, subject in (('network.policy_delivered', f'{pat_id}/{b}'),
                                  ('network.policy_delivered', f'{pat_id}/coordinator'),
                                  ('network.policy_delivered', f'{pat_id}/{a}'),
                                  ('network.policy_updated', pat_id)):
                assert (kind, subject) in kinds, (kind, subject)

            # Migration from version 11, and refusal of version 15.
            for host in (alice, bob):
                assert user_version(host) == 14
                host.stop()
                with sqlite3.connect(host.state / 'host.db') as db:
                    db.execute('DROP TABLE policy_deliveries')
                    db.execute('DROP TABLE directory_sends')
                    db.execute('PRAGMA user_version = 11')
                host.start()
                assert user_version(host) == 14
                assert stored(host, net, pat_id) == winner
                assert status(host, net)['deliveries'] == []
                host.stop()
                with sqlite3.connect(host.state / 'host.db') as db:
                    db.execute('PRAGMA user_version = 15')
                try:
                    host.start()
                    opened = True
                except AssertionError as error:
                    assert 'exited at startup' in str(error), error
                    opened = False
                assert not opened, 'version 15 opened'
                with sqlite3.connect(host.state / 'host.db') as db:
                    db.execute('PRAGMA user_version = 14')
                host.start()
            assert len(status(alice, net, sync=True)['deliveries']) == 0
        finally:
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            stop_all(hosts)
            coord.stop()
            coord.logs.close()
            for agent in agents.values():
                agent.stop()
    print(f'PASS {label}: withdrawal pushed with the coordinator stopped and refused, coordinator delivery on '
          'restart; start-up sync after an offline push; same-version tie-break; non-sibling and lower-version '
          'refusals; access sync and status; v11 to v13 migration', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    parser.add_argument('--pairing', action='append',
                        help="the owner's two hosts, such as Go/Rust; default all. The sender runs the "
                             "other language from the first host")
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for first in binaries:
        for second in binaries:
            if args.pairing and f'{first}/{second}' not in args.pairing:
                continue
            sender = 'Rust' if first == 'Go' else 'Go'
            check(args.coord.resolve(), binaries[first], binaries[second], binaries[sender],
                  f"{first}/{second} owner hosts, {sender} sender")


if __name__ == '__main__':
    main()
