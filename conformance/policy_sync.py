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
- `access sync` and `access sync --status` (now with `edits`);
- migration from database version 11 to the current version (18), and refusal of the next.

A second run per combination (check_edits, with alice, bob, carol, and later dave, eve, and fred, more of pat's
machines) covers Concurrent edits (coordination contract, including PR #15's owner scope and retired entries):
- the edit route ({policy, version, seq}, null and 0 without a policy, 404 for an unknown network or a host not
  bound), increasing numbers, two reservations with the older submission refused as `edit_conflict`, the CLI
  retrying after an `edit_conflict` (another reservation is taken at its first signature, through an ssh-agent
  proxy), an unknown and a lapsed number refused with 400, edit numbers in `edits` and `access sync --status`;
- renewals copying `edits` (`access renew` and the daemon's renewal);
- both capability shares present after re-applying, each signed from the same version while the other sibling and
  the coordinator are stopped;
- an `unshare` racing a sibling's renewal: refused on the withdrawing host at once while unsettled, settled after;
- an addition racing a removal of its rule: dropped, item 17, `network.policy_edit_dropped`, closed, and never
  re-applied when a later policy is stored;
- without a renewal key: item 16, the edit route folding the edit in, and the next CLI edit settling it;
- a change of owner: edits suspended (kept, not re-applied) while the owner is removed by an administrator, and
  resumed when the removal is undone by --revoke-admitted; suspended on a binding to another person and never
  signed into either policy;
- entries of an administrator-revoked host, and of a host whose invite an administrator revoked, kept; entries of
  a root-revoked host, a host whose invite the root revoked, and a departed host dropped by the next signer;
- concurrent edits of two rules of one agent with different settings, each keeping its own addition;
- several rules for one agent with different settings accepted in v2; two with the same agent and settings
  refused with 400; a v1 policy with such duplicates combined into one rule with united principals when renewed
  as v2 (by `access renew` and by the daemon);
- migration from version 16 to 17 (policy_edits keyed by network, person, and seq), and refusal of 18.

Where the suite must make a race come out one way, it signs the competing policy itself (a renewal, or an edit
from the other host's edit route, as that host's CLI would) and chooses issued_at so its statement hash is lower.
A lapsed reservation is made by moving its persisted reserved_at back 11 minutes while the daemon is stopped.

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
import socket
import subprocess
import sqlite3
import struct
import sys
import tempfile
import threading
import time

from coordination import Coordinator, wait_for
from host_service import AGENT_CALL_TABLES, CAPABILITY_TABLES, POLICY_EDIT_TABLES, SCHEMA_VERSION, stop_all
from peer_messaging import fixture_context, set_probe, timestamp, wire
from persons import Agent, coord_db, person_id, ssh_key, ssh_sign, ssh_verify, use_agent
from policy import PolicyHost, crafted, edit_start, edits_map, policy_lines, policy_of, send, show, sign_edit

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
    with tempfile.TemporaryDirectory(prefix='peerspan-policy-sync-') as temporary:
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
                # `access sync --status` adds `edits` (coordination contract, Concurrent edits).
                assert set(view) == {'person_id', 'version', 'sha256', 'deliveries', 'edits'}, view
                assert [d['target'] for d in view['deliveries']] == sorted(['coordinator', sibling]), view
                assert all(d['state'] == 'delivered' and d['version'] == 4 for d in view['deliveries']), view
                assert status(host, net) == view
            quinn_view = status(carol, net)
            assert quinn_view == {'person_id': quinn_id, 'version': None, 'sha256': None, 'deliveries': [],
                                  'edits': []}, quinn_view
            assert alice.call('GET', '/v1/networks/net_missing/policy/sync')[0] == 404
            kinds = set(events(alice)) | set(events(bob))
            for kind, subject in (('network.policy_delivered', f'{pat_id}/{b}'),
                                  ('network.policy_delivered', f'{pat_id}/coordinator'),
                                  ('network.policy_delivered', f'{pat_id}/{a}'),
                                  ('network.policy_updated', pat_id)):
                assert (kind, subject) in kinds, (kind, subject)

            # Migration from version 11 (to the current version), and refusal of the next.
            for host in (alice, bob):
                assert user_version(host) == SCHEMA_VERSION
                host.stop()
                with sqlite3.connect(host.state / 'host.db') as db:
                    db.execute('DROP TABLE policy_deliveries')
                    db.execute('DROP TABLE directory_sends')
                    for table in (*AGENT_CALL_TABLES, *CAPABILITY_TABLES, *POLICY_EDIT_TABLES):
                        db.execute('DROP TABLE ' + table)
                    db.execute('PRAGMA user_version = 11')
                host.start()
                assert user_version(host) == SCHEMA_VERSION
                assert stored(host, net, pat_id) == winner
                assert status(host, net)['deliveries'] == []
                host.stop()
                with sqlite3.connect(host.state / 'host.db') as db:
                    db.execute(f'PRAGMA user_version = {SCHEMA_VERSION + 1}')
                try:
                    host.start()
                    opened = True
                except AssertionError as error:
                    assert 'exited at startup' in str(error), error
                    opened = False
                assert not opened, f'version {SCHEMA_VERSION + 1} opened'
                with sqlite3.connect(host.state / 'host.db') as db:
                    db.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')
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
          'refusals; access sync and status; v11 to v17 migration, v18 refused', flush=True)


EDIT_FIELDS = {'seq', 'state', 'signed_version', 'dropped'}
FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'mcp' / 'server.py'


class SignHook:
    """An ssh-agent proxy on its own socket. Before forwarding the first sign request
    (SSH2_AGENTC_SIGN_REQUEST, 13) it runs `hook`, so that something happens between the CLI's edit route call and
    its submission. Counts sign requests."""

    def __init__(self, directory, upstream, hook):
        self.path = str(directory / 'hook.sock')
        self.upstream, self.hook, self.signs = upstream, hook, 0
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.server.listen(8)
        threading.Thread(target=self.accept, daemon=True).start()

    @staticmethod
    def message(sock):
        def exactly(n):
            data = b''
            while len(data) < n:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    raise EOFError
                data += chunk
            return data
        head = exactly(4)
        return head + exactly(struct.unpack('>I', head)[0])

    def accept(self):
        while True:
            try:
                client, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    def serve(self, client):
        agent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        agent.connect(self.upstream)
        try:
            while True:
                request = self.message(client)
                if request[4] == 13:
                    self.signs += 1
                    if self.signs == 1:
                        self.hook()
                agent.sendall(request)
                client.sendall(self.message(agent))
        except (EOFError, OSError):
            pass
        finally:
            client.close()
            agent.close()

    def close(self):
        self.server.close()


def edits_status(host, net):
    view = status(host, net)
    assert 'edits' in view, view
    for e in view['edits']:
        assert set(e) == EDIT_FIELDS and e['state'] in ('settled', 'unsettled', 'closed'), e
    seqs = [e['seq'] for e in view['edits']]
    assert seqs == sorted(seqs), view['edits']
    return {e['seq']: e for e in view['edits']}


def attention(host, kind):
    code, value = host.call('GET', '/v1/status')
    assert code == 200, value
    return [i for i in value.get('attention', []) if i.get('kind') == kind]


def check_edits(coord_binary, first_binary, second_binary, sender_binary, label):
    """Concurrent edits (coordination contract, Concurrent edits, with PR #15's owner scope and retired entries)."""
    with tempfile.TemporaryDirectory(prefix='peerspan-policy-edits-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        alice = PolicyHost(first_binary, root / 'alice')
        bob = PolicyHost(second_binary, root / 'bob')
        carol = PolicyHost(sender_binary, root / 'carol')
        dave = PolicyHost(second_binary, root / 'dave')
        eve = PolicyHost(first_binary, root / 'eve')
        fred = PolicyHost(second_binary, root / 'fred')
        gus = PolicyHost(first_binary, root / 'gus')
        hal = PolicyHost(second_binary, root / 'hal')
        hosts = (alice, bob, carol, dave, eve, fred, gus, hal)
        (root / 'keys').mkdir()
        keys = {name: ssh_key(root / 'keys', name) for name in ('pat', 'quinn')}
        agents = {}
        hook = None
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        try:
            for name in keys:
                (root / f'agent-{name}').mkdir()
                agents[name] = Agent(root / f'agent-{name}')
                agents[name].add(keys[name][0])
            pat_key, pat_id = keys['pat'][2], person_id(keys['pat'][2])
            quinn_id = person_id(keys['quinn'][2])
            coordinator = coord.start()
            ids = {host: host.start()['id'] for host in (alice, bob, carol)}
            a, b, c = ids[alice], ids[bob], ids[carol]

            def keyed(host, on):
                """Restart a daemon with (or without) a renewal key: the pat agent as its SSH_AUTH_SOCK, the default
                of `run --person-agent`."""
                host.stop()
                host.agent_socket = agents['pat'].socket if on else None
                host.start()

            def mine(host):
                return stored(host, net, pat_id)

            def mine_in(host, network):
                return stored(host, network, pat_id)

            def sync(*names):
                for h in names:
                    h.cli('access', 'sync', '--network', net)

            def lower_than(current, rival, version):
                """A renewal of `current` at `version` (same content, `edits` copied), signed here, whose statement
                hash is lower than `rival`'s, so that it wins the tie-break. Stands in for a sibling's renewal; the
                hash is chosen by varying issued_at."""
                now = datetime.now(timezone.utc).replace(microsecond=0)
                for k in range(1, 400):
                    r = crafted(current, version, now - timedelta(seconds=k), now - timedelta(seconds=k) + timedelta(days=7),
                                keys['pat'][0], root)
                    if policy_hash(r) < policy_hash(rival):
                        return r
                raise AssertionError('no lower-hash renewal found')

            def call(version, text='x', full=False):
                body = {'call_id': 'call_' + os.urandom(16).hex(), 'capability': 'notes-a', 'operation': 'echo',
                        'input': {'text': text}, 'deadline': timestamp(300),
                        'policy': {'person_id': pat_id, 'network_id': net, 'version': version}}
                status, value = wire(alice, fixture_context(carol), 'POST', '/peer/v1/calls', body)
                return (status, value) if full else status

            use_agent(agents['pat'])
            net = alice.cli('network', 'create', '--name', 'edits', '--member', 'pat', '--coordinator', coord.address,
                            '--coordinator-key', coordinator['public_key'])['id']
            for host, name in ((bob, 'pat'), (carol, 'quinn')):
                invite = alice.cli('network', 'invite', '--network', net, '--member', name, '--expires-at', timestamp())
                use_agent(agents[name])
                assert host.cli('network', 'join', '--token', invite['token'])['person']['bound']
            for host in (alice, bob, carol):
                host.cli('network', 'sync', net)
            use_agent(agents['pat'])

            # --- The edit route, edit numbers, serialized reservations, lapsed and unknown numbers.
            code, start0 = edit_start(alice, net)
            assert code == 200 and set(start0) == {'policy', 'version', 'seq'}, (code, start0)
            if start0['policy'] is not None:   # a trust signing at create would have made one
                assert start0['version'] == start0['policy']['version'], start0
            else:
                assert start0['version'] == 0, start0
            assert isinstance(start0['seq'], int) and start0['seq'] >= 1, start0
            assert edit_start(alice, 'net_missing')[0] == 404
            code, carol_start = edit_start(carol, net)
            assert code == 200 and carol_start['policy'] is None and carol_start['version'] == 0, carol_start
            code, start1 = edit_start(alice, net)
            assert code == 200 and start1['seq'] > start0['seq'], (start0, start1)

            def add_rule(agent, principals):
                def change(p):
                    p['rules'] = [r for r in p['rules'] if r['agent'] != agent] + [
                        {'agent': agent, 'principals': principals, 'actions': ['message.append'],
                         'max_message_bytes': 65536, 'allow_disconnected': False}]
                return change

            def submit(host, policy):
                return host.call('POST', f'/v1/networks/{net}/policy', {'policy': policy})

            older = sign_edit(start0, net, pat_key, a, keys['pat'][0], root, add_rule('r0', ['network']))
            code, body = submit(alice, older)
            assert code == 409 and isinstance(body, dict) and body.get('code') == 'edit_conflict', (code, body)
            newer = sign_edit(start1, net, pat_key, a, keys['pat'][0], root, add_rule('r0', ['network']))
            code, body = submit(alice, newer)
            assert code == 201 and policy_of(body) == newer, (code, body)
            assert edits_map(newer)[a] == start1['seq']
            # A policy citing an unknown number for this host.
            code, start2 = edit_start(alice, net)
            unknown = sign_edit(start2, net, pat_key, a, keys['pat'][0], root, add_rule('r1', ['network']),
                                seq=start2['seq'] + 1000)
            assert submit(alice, unknown)[0] == 400, 'a policy citing an unknown seq for this host is refused'
            # A lapsed reservation. Ten real minutes are not waited: the reservation's persisted reserved_at is moved
            # back 11 minutes while the daemon is stopped. Database version 17 specifies the record as {seq, state,
            # start, signed, signed_version, dropped, reserved_at, signed_at} (coordination contract, Direct
            # propagation: Storage); reserved_at is written as RFC3339, as the contract's other timestamps are. No
            # API exposes a reservation's age, so this is the only way short of waiting. If an implementation keeps
            # reservations only in memory, the restart forgets it, and the number is unknown: 400 either way.
            code, start3 = edit_start(alice, net)
            alice.stop()
            with sqlite3.connect(alice.state / 'host.db') as db:
                rows = db.execute('SELECT rowid, record FROM policy_edits WHERE network_id = ? AND seq = ?',
                                  (net, start3['seq'])).fetchall()
                for rowid, record in rows:
                    value = json.loads(record)
                    value['reserved_at'] = (datetime.now(timezone.utc) - timedelta(minutes=11)).strftime(
                        '%Y-%m-%dT%H:%M:%SZ')
                    db.execute('UPDATE policy_edits SET record = ? WHERE rowid = ?', (json.dumps(value), rowid))
            alice.start()
            lapsed = sign_edit(start3, net, pat_key, a, keys['pat'][0], root, add_rule('r1', ['network']))
            assert submit(alice, lapsed)[0] == 400, 'a lapsed reservation is refused with 400'
            assert mine(alice) == newer
            # A CLI edit: its number is in `edits`, and access sync --status lists it.
            v = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn')
            assert v['version'] == newer['version'] + 1 and edits_map(v)[a] > start3['seq'], v
            listed = edits_status(alice, net)
            last = listed[max(listed)]
            assert max(listed) == edits_map(v)[a] and last['state'] == 'settled' and \
                last['signed_version'] == v['version'] and last['dropped'] == [], listed
            assert listed[start1['seq']]['state'] == 'settled', listed
            # Two reservations through the CLI: another reservation is taken between the CLI's edit route call and
            # its submission (at its first signature), so the submission is refused as edit_conflict and the CLI
            # starts again from the edit route.
            hook = SignHook(root, agents['pat'].socket, lambda: edit_start(alice, net))
            os.environ['SSH_AUTH_SOCK'] = hook.path
            before = mine(alice)['version']
            v = alice.cli('access', 'allow', '--network', net, '--agent', 'retried', '--principal', 'network')
            use_agent(agents['pat'])
            assert hook.signs >= 2 and v['version'] == before + 1 and mine(alice) == policy_of(v), (hook.signs, v)
            assert any(r['agent'] == 'retried' for r in v['rules']), v
            # Renewals copy `edits`: access renew, then the daemon's renewal of a policy near its end.
            current = mine(alice)
            renewed = alice.cli('access', 'renew', '--network', net)
            assert renewed['version'] == current['version'] + 1 and renewed['edits'] == current['edits'] and \
                renewed['rules'] == current['rules'], (current, renewed)
            now = datetime.now(timezone.utc)
            ending = crafted(policy_of(renewed), renewed['version'] + 1, now - timedelta(hours=20),
                             now + timedelta(hours=4), keys['pat'][0], root)
            assert submit(alice, ending)[0] == 201
            keyed(alice, True)
            wait_for(lambda: (mine(alice) or {}).get('version', 0) > ending['version'], timeout=30,
                     message='daemon renewal')
            assert mine(alice)['edits'] == ending['edits'] and mine(alice)['rules'] == ending['rules'], mine(alice)
            keyed(alice, False)

            # Capabilities for the share scenarios: notes-a on alice, notes-b on bob, each from a fixture source.
            for host, agent, cap in ((alice, 'na', 'notes-a'), (bob, 'nb', 'notes-b')):
                made = host.cli('agent', 'register', '--name', agent, '--owner', 'pat')
                (root / f'{agent}.log').touch()
                server = {'name': 'fx', 'transport': 'stdio', 'command': sys.executable,
                          'args': ['-I', str(FIXTURE), f'log={root / (agent + ".log")}', f'control={root / (agent + ".json")}'],
                          'env': {}, 'url': None, 'source': 'claude-code:user'}
                code, body = host.call('PUT', f"/v1/agents/{made['id']}/tool-servers",
                                       {'workspace': str(root), 'servers': [server], 'values': {}})
                assert code == 200, body
                sync(alice, bob)
                host.cli('capability', 'create', cap, '--from', f'{agent}/fx', '--operations', 'echo')
            sync(alice, bob, alice)
            wait_for(lambda: mine(alice) == mine(bob) and {r['capability'] for r in mine(alice)['capability_rules']}
                     == {'notes-a', 'notes-b'}, timeout=20, message='both claims everywhere')

            # --- Both shares present after re-applying. Each sibling shares from the same version while the other
            # and the coordinator are stopped; both daemons hold the renewal key.
            keyed(alice, True)
            keyed(bob, True)
            base = mine(alice)
            coord.stop()
            bob.stop()
            x = alice.cli('share', 'notes-a', '--with', 'quinn', '--yes', '--network', net)['policy']
            alice.stop()
            bob.start()
            y = bob.cli('share', 'notes-b', '--with', 'quinn', '--yes', '--network', net)['policy']
            assert x['version'] == y['version'] == base['version'] + 1, (x['version'], y['version'])
            alice.start()

            def both_shared():
                sync(alice, bob)
                pa, pb = mine(alice), mine(bob)
                if pa != pb:
                    return None
                rules = {r['capability']: r['principals'] for r in pa['capability_rules']}
                return pa if rules.get('notes-a') == ['person:' + quinn_id] == rules.get('notes-b') else None
            merged = wait_for(both_shared, timeout=40, message='both shares after re-applying')
            assert merged['version'] == base['version'] + 2, merged['version']
            assert edits_map(merged)[a] >= edits_map(x)[a] and edits_map(merged)[b] >= edits_map(y)[b], merged['edits']
            for host in (alice, bob):
                assert all(e['state'] in ('settled', 'closed') for e in edits_status(host, net).values()), host
            coord.start()
            sync(alice, bob)
            carol.cli('network', 'sync', net)
            # The share's rule has allow_disconnected false, so while alice reconnects after the coordinator's
            # restart a call may get the recoverable 503 (capabilities contract, Authorization: Bounds); it is
            # retried. Any other refusal fails at once.
            def accepted():
                status, value = call(mine(alice)['version'], full=True)
                assert status in (200, 503), ('quinn calls the shared capability', status, value)
                if status == 503:
                    print(f'NOTE {label}: 503 while alice reconnects, retried: {value}', flush=True)
                return status == 200
            wait_for(accepted, timeout=30, message='quinn calls the shared capability (200 once alice is connected)')

            # --- Concurrent edits of different rules of one agent (PR #20: rules keyed by agent and settings). Agent
            # `multi` has two rules with different settings; alice adds quinn to one and bob to the other, each from
            # the same version while the other and the coordinator are stopped. Both daemons hold the key; after
            # re-applying, each rule keeps its own addition. The edits are signed here from each host's edit route,
            # as the CLI would (which of several rules `access allow` edits is not said).
            def multi_rule(actions, size, principals):
                return {'agent': 'multi', 'principals': principals, 'actions': actions, 'max_message_bytes': size,
                        'allow_disconnected': False}

            def edit_on(host, host_id, change):
                code, start = edit_start(host, net)
                assert code == 200, (code, start)
                signed = sign_edit(start, net, pat_key, host_id, keys['pat'][0], root, change)
                code, body = submit(host, signed)
                assert code == 201, (code, body)
                return signed
            edit_on(alice, a, lambda p: p['rules'].extend([multi_rule(['message.append'], 4096, ['network']),
                                                           multi_rule(['task.submit'], 65536, ['network'])]))
            wait_for(lambda: sync(alice, bob) or mine(bob) == mine(alice), timeout=30, message='multi rules on bob')
            base = mine(alice)
            assert len([r for r in base['rules'] if r['agent'] == 'multi']) == 2, base['rules']

            def add_quinn(actions):
                def change(p):
                    for r in p['rules']:
                        if r['agent'] == 'multi' and r['actions'] == actions:
                            r['principals'] = r['principals'] + ['person:' + quinn_id]
                return change
            coord.stop()
            bob.stop()
            mx = edit_on(alice, a, add_quinn(['message.append']))
            alice.stop()
            bob.start()
            my = edit_on(bob, b, add_quinn(['task.submit']))
            assert mx['version'] == my['version'] == base['version'] + 1
            alice.start()

            def both_rules():
                sync(alice, bob)
                pa = mine(alice)
                if pa != mine(bob):
                    return None
                multi = {tuple(r['actions']): r['principals'] for r in pa['rules'] if r['agent'] == 'multi'}
                want = ['network', 'person:' + quinn_id]
                return pa if multi.get(('message.append',)) == want and multi.get(('task.submit',)) == want else None
            try:
                merged_multi = wait_for(both_rules, timeout=40, message='both rules of multi')
            except AssertionError:
                raise AssertionError(('both rules of multi keep their own addition after re-applying',
                                      'alice', [r for r in mine(alice)['rules'] if r['agent'] == 'multi'],
                                      mine(alice)['version'], 'bob', [r for r in mine(bob)['rules'] if r['agent'] == 'multi'],
                                      mine(bob)['version'], 'base', base['version']))
            assert merged_multi['version'] == base['version'] + 2, merged_multi['version']
            coord.start()
            sync(alice, bob)

            # --- An unshare racing a sibling's renewal: refused on the withdrawing host at once, settled after.
            keyed(alice, False)
            base = mine(alice)
            coord.stop()
            bob.stop()
            u = alice.cli('unshare', 'notes-a', '--with', 'quinn', '--network', net)['policy']
            useq = edits_map(u)[a]
            renewal = lower_than(base, u, base['version'] + 1)
            alice.stop()
            bob.start()
            assert submit(bob, renewal)[0] == 201
            alice.start()
            wait_for(lambda: sync(alice) or mine(alice) == renewal, timeout=30, message='the renewal wins on alice')
            assert any(r['capability'] == 'notes-a' and r['principals'] for r in mine(alice)['capability_rules'])
            assert edits_status(alice, net)[useq]['state'] == 'unsettled'
            assert call(renewal['version'], 'withdrawn') == 403, 'the unsettled withdrawal applies on alice at once'
            keyed(alice, True)

            def settled():
                sync(alice, bob)
                pa = mine(alice)
                if pa != mine(bob) or pa['version'] != renewal['version'] + 1:
                    return None
                return pa if edits_status(alice, net)[useq]['state'] == 'settled' else None
            after = wait_for(settled, timeout=40, message='the unshare re-applied and settled')
            rule = next(r for r in after['capability_rules'] if r['capability'] == 'notes-a')
            assert rule['principals'] == [] and rule['host'] == a, rule   # kept as a claim
            assert call(after['version'], 'after') == 403
            coord.start()

            # --- An addition racing a removal of its rule: dropped, item 17, the edit closed and never re-applied.
            # Alice (with the key) adds `network` to reviewer through the CLI; bob's removal of the rule is signed
            # here as bob's CLI would, from bob's edit route, with issued_at chosen so that it wins the tie-break.
            base = mine(alice)
            coord.stop()
            bob.stop()
            added = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal',
                              'person:quinn', '--principal', 'network')
            aseq = edits_map(added)[a]
            alice.stop()
            bob.start()
            code, bstart = edit_start(bob, net)
            assert code == 200 and bstart['version'] == base['version'], bstart
            now = datetime.now(timezone.utc).replace(microsecond=0)
            removal = None
            for k in range(1, 400):
                candidate = sign_edit(bstart, net, pat_key, b, keys['pat'][0], root,
                                      lambda p: p.update(rules=[r for r in p['rules'] if r['agent'] != 'reviewer']),
                                      issued=now - timedelta(seconds=k))
                if policy_hash(candidate) < policy_hash(added):
                    removal = candidate
                    break
            assert removal and submit(bob, removal)[0] == 201
            alice.start()

            def closed():
                sync(alice, bob)
                e = edits_status(alice, net).get(aseq)
                return e if e and e['state'] == 'closed' and mine(alice) == policy_of(removal) else None
            entry = wait_for(closed, timeout=40, message='the dropped addition closed')
            assert entry['dropped'], entry
            assert not any(r['agent'] == 'reviewer' for r in mine(alice)['rules'])
            items = wait_for(lambda: attention(alice, 'policy_edit_dropped'), timeout=20, message='item 17')
            item = next((i for i in items if i['subject'] == f'{net}/{aseq}'), None)
            assert item and item['command'] == f'peerspan access show --network {net}' and 'network' in item['detail'], items
            assert ('network.policy_edit_dropped', f'{pat_id}/{aseq}') in events(alice), events(alice)
            # A closed edit is never re-applied, although no stored policy reflects it: another policy stored on
            # alice (a renewal from bob, copying edits) leaves it alone.
            again = crafted(policy_of(removal), removal['version'] + 1, now, now + timedelta(days=7), keys['pat'][0], root)
            assert edits_map(again).get(a, 0) < aseq
            assert submit(bob, again)[0] == 201
            wait_for(lambda: sync(alice) or mine(alice) == again, timeout=20, message='renewal on alice')
            time.sleep(5)
            sync(alice)
            assert mine(alice) == again and edits_status(alice, net)[aseq]['state'] == 'closed'
            coord.start()

            # --- Without a renewal key, item 16 until the next CLI edit settles it.
            keyed(alice, False)
            base = mine(alice)
            coord.stop()
            bob.stop()
            late = alice.cli('access', 'allow', '--network', net, '--agent', 'late', '--principal', 'network')
            lseq = edits_map(late)[a]
            displacing = lower_than(base, late, base['version'] + 1)
            alice.stop()
            bob.start()
            assert submit(bob, displacing)[0] == 201
            alice.start()
            wait_for(lambda: sync(alice) or mine(alice) == displacing, timeout=30, message='displaced on alice')
            assert edits_status(alice, net)[lseq]['state'] == 'unsettled'
            code, folded = edit_start(alice, net)
            assert code == 200 and folded['version'] == displacing['version'] and \
                any(r['agent'] == 'late' for r in folded['policy']['rules']), folded
            items = wait_for(lambda: attention(alice, 'policy_edit_unsettled'), timeout=100, message='item 16')
            assert items[0]['subject'] == net and items[0]['command'] == f'peerspan access renew --network {net}', items
            nxt = alice.cli('access', 'allow', '--network', net, '--agent', 'later', '--principal', 'network')
            assert {'late', 'later'} <= {r['agent'] for r in nxt['rules']} and nxt['version'] == displacing['version'] + 1
            assert edits_status(alice, net)[lseq]['state'] == 'settled'
            assert not attention(alice, 'policy_edit_unsettled')
            coord.start()
            sync(alice, bob)

            def bob_unsettled(rule):
                """Bob (keyless) signs `rule` while alice and the coordinator are stopped; alice then stores a renewal
                with a lower hash, which displaces it on bob. Returns the edit's number."""
                base = mine(alice)
                coord.stop()
                alice.stop()
                signed = bob.cli('access', 'allow', '--network', net, '--agent', rule, '--principal', 'network')
                seq = edits_map(signed)[b]
                bob.stop()
                alice.start()
                assert submit(alice, lower_than(base, signed, base['version'] + 1))[0] == 201
                bob.start()
                wait_for(lambda: sync(bob) or mine(bob) == mine(alice), timeout=30, message='displaced on bob')
                assert edits_status(bob, net)[seq]['state'] == 'unsettled'
                coord.start()
                return seq

            def bob_records(seq):
                """The state of bob's edit record for pat, read from the database. While bob is not bound to pat,
                `access sync --status` answers 404 (and once bob is bound to quinn it lists quinn's edits), so no API
                shows a suspended edit; the record's shape {seq, state, ...} is specified by database version 17
                (coordination contract, Direct propagation: Storage). Where bob is bound to pat, the suite reads
                `access sync --status` instead."""
                with sqlite3.connect(bob.state / 'host.db') as db:
                    return [json.loads(r[0])['state'] for r in db.execute(
                        'SELECT record FROM policy_edits WHERE network_id = ? AND person_id = ? AND seq = ?',
                        (net, pat_id, seq))]

            def has_rule(policy, agent):
                return any(r['agent'] == agent for r in (policy or {}).get('rules', []))

            def bob_cli(*args):
                return subprocess.run([str(bob.binary), '--state', str(bob.state), *args], capture_output=True,
                                      timeout=20, env=bob.isolated(dict(os.environ)))

            def join_pat(extra, rule):
                """A new machine of pat joins, syncs, and signs an edit that alice stores."""
                ids[extra] = extra.start()['id']
                invite = alice.cli('network', 'invite', '--network', net, '--member', 'pat', '--expires-at', timestamp())
                assert extra.cli('network', 'join', '--token', invite['token'])['person']['bound']
                for h in (alice, extra):
                    h.cli('network', 'sync', net)
                wait_for(lambda: sync(extra) or mine(extra) == mine(alice), timeout=30, message='the new sibling syncs')
                signed = extra.cli('access', 'allow', '--network', net, '--agent', rule, '--principal', 'network')
                assert ids[extra] in edits_map(signed)
                wait_for(lambda: sync(alice) or mine(alice) == policy_of(signed), timeout=30,
                         message='alice stores the new sibling\'s edit')
                return ids[extra]

            def members():
                alice.cli('network', 'sync', net)
                return {m['host_id'] for m in alice.cli('network', 'members', net)}

            def invite_of(host_id):
                """The invite a member joined through: its membership's invite_public_key in alice's view."""
                alice.cli('network', 'sync', net)
                entry = next(m for m in alice.cli('network', 'members', net) if m['host_id'] == host_id)
                key = (entry.get('membership') or {}).get('invite_public_key')
                assert key, ('setup: the member joined through an invite', entry)
                return key

            # quinn becomes an administrator (delegated by the root, alice); quinn's statements are signed on carol,
            # which holds no root seed. A revoked host never syncs again (the coordinator refuses it), so it does not
            # learn of its own revocation; the removal a host can observe is its person's removal.
            alice.cli('network', 'delegate-admin', '--network', net, '--person', 'quinn')
            carol.cli('network', 'sync', net)

            # --- Entries of a host revoked by an administrator are kept (PR #15): dave, pat's third machine, signs
            # an edit and is revoked by quinn; alice's next edit keeps dave's entry.
            d = join_pat(dave, 'daverule')

            def carol_knows(host_id):
                carol.cli('network', 'sync', net)
                return host_id in {m['host_id'] for m in carol.cli('network', 'members', net)}
            # carol (where quinn signs) must have dave in its own member view before revoking it.
            wait_for(lambda: carol_knows(d), timeout=30, message='carol sees dave as a member')
            use_agent(agents['quinn'])
            carol.cli('network', 'revoke', '--network', net, '--host', d)
            use_agent(agents['pat'])
            wait_for(lambda: d not in members(), timeout=30, message='dave revoked by the administrator')
            # The same for an invite revoked by an administrator: gus joins through its own invite and signs an
            # edit; quinn revokes that invite, which drops gus (Invite revocation drops members who joined through
            # it), and the entry is kept as well, since an administrator's revocation can be undone.
            g = join_pat(gus, 'gusrule')
            g_invite = invite_of(g)
            wait_for(lambda: carol_knows(g), timeout=30, message='carol sees gus as a member')
            use_agent(agents['quinn'])
            carol.cli('network', 'revoke-invite', '--network', net, '--invite', g_invite)
            use_agent(agents['pat'])
            wait_for(lambda: g not in members(), timeout=30, message='gus dropped with its invite revoked by the '
                     'administrator')
            kept = alice.cli('access', 'allow', '--network', net, '--agent', 'keepdave', '--principal', 'network')
            assert d in edits_map(kept), ('the entry of a host revoked by an administrator is kept', kept['edits'])
            assert g in edits_map(kept), ('the entry of a host whose invite an administrator revoked is kept',
                                          kept['edits'])

            # --- A change of owner (PR #15) through a removal signed by an administrator: quinn removes pat. Bob's
            # unsettled edit for pat is suspended: kept as it is and not re-applied, although bob holds pat's key.
            # Removing quinn with --revoke-admitted undoes the removal; pat's binding on bob is current again, and
            # the edit resumes and is re-applied. (The Verification item names both a binding to another person and
            # this undo; an undone removal cannot follow a binding to another person, since unbinding is permanent
            # and a bound host cannot bind again, so the suite checks them as two cases.)
            keyed(bob, False)
            sync(alice, bob)
            first = bob_unsettled('bobrule')
            # pat is an administrator by default (network create); the Go implementation refuses to remove a
            # current administrator as a person, so the root first removes pat's administrator role (alice keeps the
            # root seed, so nothing else changes).
            alice.cli('network', 'remove-admin', '--network', net, '--person', 'pat')
            carol.cli('network', 'sync', net)
            use_agent(agents['quinn'])
            carol.cli('network', 'remove-person', '--network', net, '--person', pat_id)
            use_agent(agents['pat'])

            def bob_knows():
                bob_cli('network', 'sync', net)
                return edit_start(bob, net)[0] == 404
            wait_for(bob_knows, timeout=30, message='bob no longer bound to pat (its edit route 404)')
            assert bob_records(first) == ['unsettled'], ('suspended, keeping its state', bob_records(first))
            keyed(bob, True)
            time.sleep(6)
            assert edit_start(bob, net)[0] == 404, 'the edit route of a host not bound in the network is 404'
            assert not has_rule(mine(alice), 'bobrule'), 'a suspended edit is not re-applied'
            assert bob_records(first) == ['unsettled'], ('suspended, keeping its state', bob_records(first))
            alice.cli('network', 'remove-admin', '--network', net, '--person', 'quinn', '--revoke-admitted')

            def resumed():
                for h in (alice, carol):
                    h.cli('network', 'sync', net)
                bob_cli('network', 'sync', net)
                bob_cli('access', 'sync', '--network', net)
                subprocess.run([str(alice.binary), '--state', str(alice.state), 'access', 'sync', '--network', net],
                               capture_output=True, timeout=20, env=alice.isolated(dict(os.environ)))
                return has_rule(mine(alice), 'bobrule') and has_rule(mine(alice), 'keepdave')
            try:
                wait_for(resumed, timeout=90, message='the suspended edit resumed and re-applied')
            except AssertionError:
                raise AssertionError(('the suspended edit resumed and re-applied once the removal is undone',
                                      'bob edit route', edit_start(bob, net)[0], 'bob record', bob_records(first),
                                      'bob policy has bobrule', has_rule(mine(bob), 'bobrule'),
                                      'alice members', alice.cli('network', 'members', net),
                                      'alice policy', mine(alice)))
            wait_for(lambda: edits_status(bob, net).get(first, {}).get('state') == 'settled', timeout=20,
                     message='the resumed edit settled (access sync --status)')

            # --- A binding to another person: bob's new unsettled edit for pat is suspended when pat unbinds bob,
            # and never signed, into pat's policy or into quinn's after bob binds to quinn, although bob's daemon
            # then holds both keys.
            keyed(bob, False)
            sync(alice, bob)
            second = bob_unsettled('bob2rule')
            alice.cli('network', 'unbind', '--network', net, '--host', b)

            def unbound():
                for h in (alice, bob):
                    h.cli('network', 'sync', net)
                return edit_start(bob, net)[0] == 404
            wait_for(unbound, timeout=30, message='bob unbound (its edit route 404)')
            assert bob_records(second) == ['unsettled'], ('suspended, keeping its state', bob_records(second))
            use_agent(agents['quinn'])
            bob.cli('network', 'bind', '--network', net)
            (root / 'agent-both').mkdir()
            agents['both'] = Agent(root / 'agent-both')
            agents['both'].add(keys['pat'][0])
            agents['both'].add(keys['quinn'][0])
            bob.stop()
            bob.agent_socket = agents['both'].socket
            bob.start()
            time.sleep(6)
            q = bob.cli('access', 'allow', '--network', net, '--agent', 'qrule', '--principal', 'network')
            use_agent(agents['pat'])
            assert q['person_public_key'] == keys['quinn'][2] and [r['agent'] for r in q['rules']] == ['qrule'], q
            assert list(edits_map(q)) == [b], q['edits']
            time.sleep(3)
            sync(alice)
            assert not has_rule(mine(alice), 'bob2rule'), mine(alice)
            assert not has_rule(stored(alice, net, quinn_id), 'bob2rule')
            assert bob_records(second) == ['unsettled'], bob_records(second)
            bob.stop()
            bob.agent_socket = None
            bob.start()

            # --- Retired entries (PR #15): fred and eve, pat's fourth and fifth machines, each sign an edit; the
            # root (alice) revokes fred, and eve leaves. Alice's next edit drops both entries, and keeps bob's (no
            # longer bound to pat) and dave's (its administrator-signed revocation undone), neither removed for good.
            # (Dave is not revoked again by the root: whether repeating a revocation of a host whose earlier,
            # now invalid, revocation is stored signs a new statement is not said.)
            wait_for(lambda: d in members(), timeout=30, message='dave back once its revocation is undone')
            f = join_pat(fred, 'fredrule')
            e = join_pat(eve, 'everule')
            h = join_pat(hal, 'halrule')
            alice.cli('network', 'revoke', '--network', net, '--host', f)
            wait_for(lambda: f not in members(), timeout=30, message='fred revoked by the root')
            # hal joined through its own invite, which the root (alice) revokes: hal is dropped, and its membership
            # has ended for good ("hosts whose key or invite was revoked by a root signature").
            alice.cli('network', 'revoke-invite', '--network', net, '--invite', invite_of(h))
            wait_for(lambda: h not in members(), timeout=30, message='hal dropped with its invite revoked by the root')
            eve.cli('network', 'leave', net)
            wait_for(lambda: e not in members(), timeout=30, message='eve gone after leaving')
            before = edits_map(mine(alice))
            assert {b, d, e, f, h} <= set(before), before
            after = alice.cli('access', 'allow', '--network', net, '--agent', 'afterrevoke', '--principal', 'network')
            entries = edits_map(after)
            assert f not in entries and e not in entries and a in entries, ('entries of a host revoked by the root '
                                                                             'and of a host that left are dropped',
                                                                             after['edits'])
            assert h not in entries, ('the entry of a host whose invite the root revoked is dropped', after['edits'])
            assert b in entries and d in entries, ('entries of hosts not removed for good stay', after['edits'])
            assert has_rule(after, 'fredrule') and has_rule(after, 'everule') and has_rule(after, 'halrule'), \
                'content is untouched'

            # --- Rules keyed by agent and settings (coordination contract, Policy statement, PR #20), in a network of
            # its own (v1dup, alice only, no edits): several rules for one agent with different settings are
            # accepted in v2; two with the same agent and settings are refused with 400; a v1 policy may hold such
            # duplicates, and renewing it as v2 (by the CLI and by the daemon) combines them into the first, with
            # their principals united (in no stated order, so compared as sets).
            dupnet = alice.cli('network', 'create', '--name', 'v1dup', '--member', 'pat', '--coordinator',
                               coord.address, '--coordinator-key', coordinator['public_key'])['id']

            def rule(agent, principal, size=4096):
                return {'agent': agent, 'principals': [principal], 'actions': ['message.append'],
                        'max_message_bytes': size, 'allow_disconnected': False}
            first_dup, second_dup, other = rule('dup', 'network'), rule('dup', 'person:' + quinn_id), rule('solo', 'network')

            def signed_policy(version, rules, v2, issued, until):
                p = {'network_id': dupnet, 'person_public_key': pat_key, 'version': version,
                     'issued_at': issued.strftime('%Y-%m-%dT%H:%M:%SZ'), 'valid_until': until.strftime('%Y-%m-%dT%H:%M:%SZ'),
                     'rules': rules}
                if v2:
                    p = {'format': 2, **p, 'capability_rules': [], 'trusted_hosts': [], 'edits': []}
                p['signature'] = ssh_sign(policy_lines(p), keys['pat'][0], root)
                return p

            def plain(rules):
                return [{k: v for k, v in r.items() if not (k == 'max_artifact_bytes' and not v)} for r in rules]

            def combined(policy):
                """The policy's rules hold `dup` once, with network and quinn united, then `solo`."""
                rules = plain(policy['rules'])
                return policy.get('format') == 2 and len(rules) == 2 and rules[1] == other and \
                    {k: v for k, v in rules[0].items() if k != 'principals'} == \
                    {k: v for k, v in first_dup.items() if k != 'principals'} and \
                    sorted(rules[0]['principals']) == sorted(['network', 'person:' + quinn_id])
            now = datetime.now(timezone.utc).replace(microsecond=0)
            current = (mine_in(alice, dupnet) or {}).get('version', 0)
            same = signed_policy(current + 1, [first_dup, second_dup], True, now - timedelta(minutes=1),
                                 now + timedelta(days=7))
            code, body = alice.call('POST', f'/v1/networks/{dupnet}/policy', {'policy': same})
            assert code == 400, ('a v2 policy with two rules of the same agent and settings is refused with 400', code,
                                 body)
            varied = signed_policy(current + 1, [first_dup, rule('dup', 'person:' + quinn_id, 1024)], True,
                                   now - timedelta(minutes=1), now + timedelta(days=7))
            code, body = alice.call('POST', f'/v1/networks/{dupnet}/policy', {'policy': varied})
            assert code == 201, ('several rules for one agent with different settings are accepted in v2', code, body)
            v1dup = signed_policy(current + 2, [first_dup, second_dup, other], False, now - timedelta(minutes=1),
                                  now + timedelta(days=7))
            code, body = alice.call('POST', f'/v1/networks/{dupnet}/policy', {'policy': v1dup})
            assert code == 201, ('a v1 policy may hold several rules with one agent and settings', code, body)
            renewed = alice.cli('access', 'renew', '--network', dupnet)
            assert combined(renewed), ('renewed as v2, the duplicates are combined with their principals united',
                                       renewed)
            ending = signed_policy(renewed['version'] + 1, [first_dup, second_dup, other], False,
                                   now - timedelta(hours=20), now + timedelta(hours=4))
            code, body = alice.call('POST', f'/v1/networks/{dupnet}/policy', {'policy': ending})
            assert code == 201, ('setup: a v1 policy near its end with duplicate rules', code, body)
            keyed(alice, True)
            wait_for(lambda: (mine_in(alice, dupnet) or {}).get('version', 0) > ending['version'], timeout=30,
                     message='daemon renewal of the v1 policy')
            assert combined(mine_in(alice, dupnet)), mine_in(alice, dupnet)
            keyed(alice, False)

            # --- Migration from version 16 to the current version (through 17), and refusal of the next.
            kept = mine(alice)
            alice.stop()
            with sqlite3.connect(alice.state / 'host.db') as db:
                for table in (*AGENT_CALL_TABLES, *POLICY_EDIT_TABLES):
                    db.execute('DROP TABLE ' + table)
                db.execute('PRAGMA user_version = 16')
            alice.start()
            assert user_version(alice) == SCHEMA_VERSION and mine(alice) == kept
            with sqlite3.connect(alice.state / 'host.db') as db:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
                columns = [r[1] for r in db.execute('PRAGMA table_info(policy_edits)')]
            assert 'policy_edits' in tables and columns == ['network_id', 'person_id', 'seq', 'record'], columns
            assert edits_status(alice, net) == {}
            alice.stop()
            with sqlite3.connect(alice.state / 'host.db') as db:
                db.execute(f'PRAGMA user_version = {SCHEMA_VERSION + 1}')
            try:
                alice.start()
                opened = True
            except AssertionError as error:
                assert 'exited at startup' in str(error), error
                opened = False
            assert not opened, f'version {SCHEMA_VERSION + 1} opened'
        finally:
            if hook:
                hook.close()
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            stop_all(hosts)
            coord.stop()
            coord.logs.close()
            for agent in agents.values():
                agent.stop()
    print(f'PASS {label}: edit route, edit numbers, edit_conflict and CLI retry, lapsed and unknown numbers, '
          'renewals copying edits; both shares after re-applying; unshare racing a renewal refused at once and '
          'settled; dropped addition with item 17, closed and never re-applied; item 16 until the next CLI edit; '
          'edits suspended on a change of owner and resumed when an administrator\'s removal is undone; entries '
          'of root-revoked and departed hosts dropped, of an administrator-revoked host kept; v16 to v17 migration, '
          'v18 refused',
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--pairing', action='append',
                        help="the owner's two hosts, such as Go/Rust; default all. The sender runs the "
                             "other language from the first host")
    parser.add_argument('--skip-edits', action='store_true', help='skip the concurrent edits checks')
    parser.add_argument('--edits-only', action='store_true', help='only the concurrent edits checks')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for first in binaries:
        for second in binaries:
            if args.pairing and f'{first}/{second}' not in args.pairing:
                continue
            sender = 'Rust' if first == 'Go' else 'Go'
            label = f"{first}/{second} owner hosts, {sender} sender"
            if not args.edits_only:
                check(args.coord.resolve(), binaries[first], binaries[second], binaries[sender], label)
            if not args.skip_edits:
                check_edits(args.coord.resolve(), binaries[first], binaries[second], binaries[sender], label)


if __name__ == '__main__':
    main()
