#!/usr/bin/env python3
"""Exercise owner access policy (milestone 2b slice 3) with real hosts.

Runs one Go coordinator with Go and Rust hosts in every owner/sender pairing,
with real ssh-agents. The owner allows a person, a group, and `network`;
senders send without grant IDs; denial applies at handoff; a stale policy
injected into the coordinator database is ignored; a receiver behind the
cited version answers 503 until it syncs; the block list overrides grants and
policies without coordination; the daemon renews through its ssh-agent and
access lapses without one; bounds hold with the coordinator stopped.

Policies keep the 1-day minimum validity. Renewal and lapse use policies
signed here with `ssh-keygen -Y sign` and backdated issue times, so less than
a quarter of their validity, or only seconds, remain; no test hook is needed.
Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen).
"""
import argparse
import hashlib
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time

from agent_adapter import adapter_call, credential
from coordination import Coordinator, wait_for
from host_service import UnixHTTPConnection, stop_all
from peer_messaging import fixture_context, request_id, set_probe, timestamp, wire
from persons import Agent, PersonHost, coord_db, person_id, ssh_key, ssh_sign, ssh_verify, use_agent


class PolicyHost(PersonHost):
    """A host whose daemon sees only the agent socket the suite chooses."""

    def __init__(self, binary, state, interval=1):
        super().__init__(binary, state)
        self.daemon_args = (*self.daemon_args[:-2], '--coordination-interval', str(interval))
        self.agent_socket = None

    def daemon_env(self):
        env = self.isolated(dict(os.environ))
        env.pop('SSH_AUTH_SOCK', None)
        if self.agent_socket:
            env['SSH_AUTH_SOCK'] = self.agent_socket
        return env

    def restart(self, interval, agent_socket=None, flag_socket=None):
        self.stop()
        self.daemon_args = (*self.daemon_args[:2], '--coordination-interval', str(interval))
        if flag_socket:
            self.daemon_args = (*self.daemon_args, '--person-agent', flag_socket)
        self.agent_socket = agent_socket
        self.logs.close()
        self.logs = tempfile.TemporaryFile()
        return self.start()


def rfc3339(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


def is_v2(p):
    """A version 2 statement (capabilities contract): `format` 2, or its v2 keys present."""
    return p.get('format') == 2 or 'capability_rules' in p or 'trusted_hosts' in p or 'edits' in p


def policy_lines_v1(p):
    lines = ['peerspan-policy-v1', p['network_id'], p['person_public_key'], str(p['version']), p['issued_at'],
             p['valid_until']]
    for r in p['rules']:
        bounds = f"{r['max_message_bytes']} {'true' if r['allow_disconnected'] else 'false'}"
        if r.get('max_artifact_bytes'):
            bounds += f" {r['max_artifact_bytes']}"
        lines += ['rule', r['agent'], ' '.join(r['principals']), ' '.join(r['actions']), bounds]
    return lines


def policy_lines_v2(p):
    """The v2 statement (capabilities contract, "Policy statement, version 2"): the v1 header fields under the
    header `peerspan-policy-v2`, the v1 rules unchanged, six lines per capability rule in JSON order (the principals
    line is empty for a claim), the `trusted` line with the host IDs sorted (the bare word `trusted` with none), and
    the final `edits` line of `HOST_ID:SEQ` entries sorted in byte order (the bare word `edits` with none).

    The amended v2 text (2026-10-18) always has the `edits` line, and its JSON always has the `edits` key. The line
    is emitted here whenever the key is present; suites assert the key's presence separately, so a policy of the
    earlier v2 text (no key) still verifies in sections that do not concern the amendment."""
    lines = policy_lines_v1(p)
    lines[0] = 'peerspan-policy-v2'
    for c in p.get('capability_rules') or []:
        lines += ['capability_rule', c['host'], c['capability'], ' '.join(c['principals']),
                  f"{c['max_input_bytes']} {'true' if c['allow_disconnected'] else 'false'} {c['max_calls_per_hour']}",
                  'end']
    lines.append(' '.join(['trusted', *sorted(p.get('trusted_hosts') or [])]))
    if 'edits' in p:
        lines.append(' '.join(['edits', *sorted(f"{e['host']}:{e['seq']}" for e in p['edits'] or [])]))
    return lines


def policy_lines(p):
    """The signed lines of a policy: v2 for a v2 policy (which the CLI and daemon renewal always sign since
    database version 16), v1 otherwise."""
    return policy_lines_v2(p) if is_v2(p) else policy_lines_v1(p)


def statement_hash(p):
    """The lowercase hex SHA-256 of a policy's signed statement."""
    return hashlib.sha256('\n'.join(policy_lines(p)).encode()).hexdigest()


def crafted(current, version, issued, until, key, directory):
    """A policy signed here with OpenSSH, with chosen times, in the same statement version as `current`."""
    p = {'network_id': current['network_id'], 'person_public_key': current['person_public_key'], 'version': version,
         'issued_at': rfc3339(issued), 'valid_until': rfc3339(until), 'rules': current['rules']}
    if is_v2(current):
        p = {'format': 2, **p, 'capability_rules': current.get('capability_rules') or [],
             'trusted_hosts': sorted(current.get('trusted_hosts') or [])}
        if 'edits' in current:
            # Not an edit: like a renewal, it copies `edits` (coordination contract, Concurrent edits), so that no
            # host's edits stop being reflected and get re-applied.
            p['edits'] = edits_list(edits_map(current))
    p['signature'] = ssh_sign(policy_lines(p), key, directory)
    return p


def edits_map(p):
    """{host_id: seq} from a policy's `edits` (empty for a v1 policy or a policy without the key)."""
    return {e['host']: e['seq'] for e in (p or {}).get('edits') or []}


def edits_list(mapping):
    """The JSON `edits`: [{host, seq}], sorted by host."""
    return [{'host': h, 'seq': mapping[h]} for h in sorted(mapping)]


def edit_start(host, network):
    """GET /v1/networks/{id}/policy/edit (coordination contract, Concurrent edits): (status, {policy, version, seq}).
    A body that is not JSON (such as a router's plain 404) comes back as text."""
    connection = UnixHTTPConnection(host.state / 'admin.sock')
    try:
        connection.request('GET', f'/v1/networks/{network}/policy/edit')
        response = connection.getresponse()
        text = response.read().decode(errors='replace')
        try:
            return response.status, json.loads(text)
        except ValueError:
            return response.status, text
    finally:
        connection.close()


def sign_edit(start, network_id, person_public_key, host_id, key, directory, change=None, keep=None,
              issued=None, duration=None, seq=None):
    """Sign an edit as the CLI does (coordination contract, Concurrent edits: Signing an edit): apply `change`
    (a function mutating the policy in place) to the edit route's `policy`, or to an empty policy when it is null;
    set the version to `version` + 1 and this host's `edits` entry to `seq`; keep the other entries, or only those of
    hosts in `keep` when given (retired entries are dropped, PR #15); sign over this suite's v2 lines. The duration
    is the starting policy's (7 days without one), `issued_at` now unless given."""
    base = start.get('policy')
    if base is None:
        base = {'format': 2, 'network_id': network_id, 'person_public_key': person_public_key, 'version': 0,
                'issued_at': rfc3339(datetime.now(timezone.utc)), 'valid_until': '', 'rules': [],
                'capability_rules': [], 'trusted_hosts': [], 'edits': []}
        length = timedelta(days=7)
    else:
        length = (datetime.fromisoformat(base['valid_until'].replace('Z', '+00:00')) -
                  datetime.fromisoformat(base['issued_at'].replace('Z', '+00:00')))
    issued = issued or datetime.now(timezone.utc).replace(microsecond=0)
    p = json.loads(json.dumps({'format': 2, 'network_id': base['network_id'],
                               'person_public_key': base['person_public_key'], 'version': start['version'] + 1,
                               'issued_at': rfc3339(issued), 'valid_until': rfc3339(issued + (duration or length)),
                               'rules': base.get('rules') or [],
                               'capability_rules': base.get('capability_rules') or [],
                               'trusted_hosts': sorted(base.get('trusted_hosts') or [])}))
    if change:
        change(p)
    entries = edits_map(base)
    if keep is not None:
        entries = {h: s for h, s in entries.items() if h in keep or h == host_id}
    entries[host_id] = start['seq'] if seq is None else seq
    p['edits'] = edits_list(entries)
    p['signature'] = ssh_sign(policy_lines_v2(p), key, directory)
    return p


def show(host, network, person=None):
    args = ['access', 'show', '--network', network]
    if person:
        args += ['--person', person]
    return host.cli(*args)


def policy_of(value):
    return {k: v for k, v in value.items() if k != 'expires_soon'}


def send(sender, receiver_id, agent, content='hello', deadline=None, grant=None):
    args = ['message', 'send', '--peer', receiver_id, '--agent', agent['id'], '--deadline', deadline or timestamp(),
            '--content', content]
    if grant:
        args += ['--grant', grant['id']]
    return sender.cli(*args)


def expect(sender, receiver_id, agent, state, **kwargs):
    out = send(sender, receiver_id, agent, **kwargs)
    assert out['state'] == state, (sender.binary, state, out)
    return out


def check_agent_principal(alice, bob, carol, ids, net, pat_id, quinn_id, agents):
    """agent:<host_id>/<agent_id> and grants with requester_agent_id match only that asserted agent."""
    a = ids[alice]['id']
    author = bob.cli('agent', 'register', '--name', 'author', '--owner', 'quinn')
    writer = bob.cli('agent', 'register', '--name', 'writer', '--owner', 'quinn')
    session = bob.cli('session', 'attach', '--agent', author['id'], '--integration', 'test')
    scribe = alice.cli('agent', 'register', '--name', 'scribe', '--owner', 'pat')
    principal = f"agent:{ids[bob]['id']}/{author['id']}"
    use_agent(agents['pat'])
    for bad in (f"agent:{ids[bob]['id']}", 'agent:host_x/agent_y', f"agent:{author['id']}/{ids[bob]['id']}"):
        alice.cli('access', 'allow', '--network', net, '--agent', 'scribe', '--principal', bad, success=False)
    allowed = alice.cli('access', 'allow', '--network', net, '--agent', 'scribe', '--principal', principal,
                        '--max-message-bytes', '100')
    assert [r['principals'] for r in allowed['rules'] if r['agent'] == 'scribe'] == [[principal]], allowed
    for host in (bob, carol):
        host.cli('network', 'sync', net)

    def from_agent(*extra, grant=None):
        args = ['message', 'send', '--peer', a, '--agent', scribe['id'], '--deadline', timestamp(),
                '--content', 'as an agent', *extra]
        if grant:
            args += ['--grant', grant['id']]
        return bob.cli(*args)
    sent = from_agent('--from-agent', author['id'], '--from-session', session['id'])
    assert sent['state'] == 'accepted' and sent['request']['origin'] == {'agent_id': author['id'], 'session_id': session['id']}, sent
    assert from_agent('--from-agent', author['id'])['state'] == 'accepted'
    assert from_agent()['state'] == 'rejected'
    assert from_agent('--from-agent', writer['id'])['state'] == 'rejected'
    # Another member host asserting the same agent ID does not match.
    body = {'request_id': request_id(), 'target_agent_id': scribe['id'], 'deadline': timestamp(), 'content': 'spoof',
            'policy': {'person_id': pat_id, 'version': allowed['version']}, 'origin': {'agent_id': author['id']}}
    assert wire(alice, fixture_context(carol), 'POST', '/peer/v1/messages', body)[0] == 403
    assert wire(alice, fixture_context(bob), 'POST', '/peer/v1/messages', body)[0] == 200

    # Handoff names the origin and the sender's person.
    receiving = alice.cli('session', 'attach', '--agent', scribe['id'], '--integration', 'test')
    token = credential(alice, receiving)['token']
    status, handoff = adapter_call(alice, token, 'POST', '/adapter/v1/next', {})
    assert status == 200 and handoff['request']['origin'] == sent['request']['origin'], handoff
    assert handoff['sender_person_id'] == quinn_id and handoff['sender_person'] == 'quinn', handoff

    # A grant with requester_agent_id authorizes only that asserted agent.
    grant = alice.cli('grant', 'create', '--peer', ids[bob]['id'], '--agent', scribe['id'], '--expires-at',
                      timestamp(1200), '--allow-disconnected', '--from-agent', writer['id'])
    assert grant['requester_agent_id'] == writer['id'], grant
    assert from_agent('--from-agent', writer['id'], grant=grant)['state'] == 'accepted'
    assert from_agent('--from-agent', author['id'], grant=grant)['state'] == 'rejected'
    assert from_agent(grant=grant)['state'] == 'rejected'


def check(coord_binary, owner_binary, sender_binary, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-policy-') as temporary:
        root = Path(temporary)
        coord = Coordinator(coord_binary, root / 'coord')
        # The owner's host syncs only when asked, so it can lag a sender.
        alice = PolicyHost(owner_binary, root / 'alice', interval=3600)
        bob, carol, dave = (PolicyHost(sender_binary, root / name) for name in ('bob', 'carol', 'dave'))
        hosts = (alice, bob, carol, dave)
        (root / 'keys').mkdir()
        keys = {name: ssh_key(root / 'keys', name) for name in ('pat', 'quinn', 'rhea')}
        agents = {}
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        try:
            for name in keys:
                (root / f'agent-{name}').mkdir()
                agents[name] = Agent(root / f'agent-{name}')
                agents[name].add(keys[name][0])
            pat_key, pat_id = keys['pat'][2], person_id(keys['pat'][2])
            quinn_id, rhea_id = person_id(keys['quinn'][2]), person_id(keys['rhea'][2])
            coordinator = coord.start()
            ids = {host: host.start() for host in hosts}
            a = ids[alice]['id']

            # Pat owns alice; quinn and rhea bind bob and carol; dave is unbound.
            use_agent(agents['pat'])
            net = alice.cli('network', 'create', '--name', 'team', '--member', 'pat', '--coordinator', coord.address,
                            '--coordinator-key', coordinator['public_key'])['id']
            for host, name in ((bob, 'quinn'), (carol, 'rhea')):
                invite = alice.cli('network', 'invite', '--network', net, '--member', name, '--expires-at', timestamp())
                use_agent(agents[name])
                assert host.cli('network', 'join', '--token', invite['token'])['person']['bound']
            invite = alice.cli('network', 'invite', '--network', net, '--member', 'dave', '--expires-at', timestamp(),
                               '--host-only')
            dave.cli('network', 'join', '--token', invite['token'], '--no-person')
            for host in hosts:
                host.cli('network', 'sync', net)
            reviewer = alice.cli('agent', 'register', '--name', 'reviewer', '--owner', 'pat')
            triage = alice.cli('agent', 'register', '--name', 'triage', '--owner', 'pat')
            session = alice.cli('session', 'attach', '--agent', reviewer['id'], '--integration', 'test')
            token = credential(alice, session)['token']

            # No grant and no policy: refused locally with an explanation.
            use_agent(agents['pat'])
            refused = bob.cli('message', 'send', '--peer', a, '--agent', reviewer['id'], '--deadline', timestamp(),
                              '--content', 'early', success=False)
            assert 'policy' in refused and 'grant' in refused, refused
            assert alice.call('GET', f'/v1/networks/{net}/policy')[0] == 404

            # A person principal, signed by pat through the agent.
            v1 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn',
                           '--max-message-bytes', '100')
            assert v1['version'] == 1 and v1['rules'][0]['principals'] == ['person:' + quinn_id], v1
            ssh_verify(policy_lines(v1), v1['signature'], keys['pat'][1], root)
            # An identical resubmission is accepted again; another version 1 is
            # not, unless its statement hash is lower (the sibling tie-break).
            assert alice.call('POST', f'/v1/networks/{net}/policy', {'policy': v1}) == (201, v1)
            # Search unsigned candidates for a higher hash, then sign only that
            # one; a lower one would win the tie-break and be stored.
            issued = datetime.now(timezone.utc)
            higher = next((issued - timedelta(minutes=m), issued + timedelta(days=d))
                          for d in range(2, 90) for m in range(60)
                          if statement_hash({**v1, 'issued_at': rfc3339(issued - timedelta(minutes=m)),
                                             'valid_until': rfc3339(issued + timedelta(days=d))})
                          > statement_hash(v1))
            other = crafted(v1, 1, *higher, keys['pat'][0], root)
            assert statement_hash(other) > statement_hash(v1)
            assert alice.call('POST', f'/v1/networks/{net}/policy', {'policy': other})[0] == 409
            shown = show(alice, net)
            assert policy_of(shown) == v1 and shown['expires_soon'] is False, shown
            for host in (bob, carol, dave):
                host.cli('network', 'sync', net)
            assert policy_of(show(bob, net, 'pat')) == v1
            out = expect(bob, a, reviewer, 'accepted')
            # The outbound record shows the missing grant as null; the wire omits it.
            assert out['request']['policy'] == {'person_id': pat_id, 'version': 1} and out['request']['grant_id'] is None, out
            received = alice.cli('message', 'list')[-1]['request']
            assert received['policy'] == {'person_id': pat_id, 'version': 1} and 'grant_id' not in received, received
            # Exactly one authorization field, locally and on the wire.
            body = {'peer_host_id': a, 'target_agent_id': reviewer['id'], 'deadline': timestamp(), 'content': 'null grant'}
            status, sent = bob.call('POST', '/v1/outbound', {**body, 'grant_id': None})
            assert status == 200 and sent['state'] == 'accepted' and sent['request']['grant_id'] is None, sent
            assert bob.call('POST', '/v1/outbound', {**body, 'grant_id': ''})[0] == 400
            context = fixture_context(bob)
            wire_body = {'request_id': request_id(), 'target_agent_id': reviewer['id'], 'deadline': timestamp(),
                         'content': 'wire', 'policy': {'person_id': pat_id, 'version': 1}}
            for extra in ({'grant_id': ''}, {'grant_id': 'grant_' + '0' * 32}, {'grant_id': None}):
                assert wire(alice, context, 'POST', '/peer/v1/messages', {**wire_body, **extra})[0] == 400, extra
            assert wire(alice, context, 'POST', '/peer/v1/messages', wire_body)[0] == 200
            for host in (carol, dave):
                rejected = expect(host, a, reviewer, 'rejected')
                assert 'HTTP 403' in rejected['error'], rejected
            # Bounds: size and a deadline past valid_until.
            expect(bob, a, reviewer, 'rejected', content='x' * 101)
            expect(bob, a, reviewer, 'rejected', deadline=timestamp(8 * 86400))
            expect(bob, a, triage, 'rejected')

            # A group, then the network principal.
            alice.cli('network', 'group', 'set', '--network', net, '--group', 'backend', '--person', 'rhea')
            v2 = alice.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn',
                           '--principal', 'group:backend', '--max-message-bytes', '100')
            assert v2['version'] == 2
            carol.cli('network', 'sync', net)
            expect(carol, a, reviewer, 'accepted')
            v3 = alice.cli('access', 'allow', '--network', net, '--agent', 'triage', '--principal', 'network',
                           '--max-message-bytes', '50', '--allow-disconnected')
            assert v3['version'] == 3 and len(v3['rules']) == 2
            dave.cli('network', 'sync', net)
            expect(dave, a, triage, 'accepted')
            expect(dave, a, triage, 'rejected', content='x' * 51)
            expect(dave, a, reviewer, 'rejected')

            # Deny applies to new requests and at handoff.
            pending = expect(bob, a, reviewer, 'accepted', content='pending')
            v4 = alice.cli('access', 'deny', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn')
            assert v4['version'] == 4 and v4['rules'][0]['principals'] == ['group:backend'], v4
            bob.cli('network', 'sync', net)
            expect(bob, a, reviewer, 'rejected')
            while adapter_call(alice, token, 'POST', '/adapter/v1/next', {})[1] is not None:
                pass
            states = {(d['delivery']['sender_host_id'], d['delivery']['request_id']): d['delivery']['state']
                      for d in alice.cli('delivery', 'list')}
            assert states[(ids[bob]['id'], pending['request']['request_id'])] == 'blocked', states
            assert {s for (sender, _), s in states.items() if sender == ids[carol]['id']} == {'unknown'}, states
            assert all(s == 'blocked' for (sender, _), s in states.items() if sender == ids[bob]['id']), states

            # A stale version injected into the coordinator database is ignored.
            for host in hosts:
                host.cli('network', 'sync', net)
            with coord_db(coord) as db:
                db.execute("UPDATE statements SET statement = ? WHERE network_id = ? AND kind = 'policy' AND subject = ?",
                           (json.dumps(v1), net, pat_key))
            for host in hosts:
                host.cli('network', 'sync', net)
                assert show(host, net, pat_id)['version'] == 4, host.binary
            expect(bob, a, reviewer, 'rejected')
            with coord_db(coord) as db:
                db.execute("UPDATE statements SET statement = ? WHERE network_id = ? AND kind = 'policy' AND subject = ?",
                           (json.dumps(v4), net, pat_key))

            # Pat re-allows quinn from bob's host. The coordinator notifies
            # alice, but until its sync completes alice is behind the cited
            # version and answers 503; a retry is accepted once it syncs.
            use_agent(agents['pat'])
            v5 = bob.cli('access', 'allow', '--network', net, '--agent', 'reviewer', '--principal', 'person:quinn',
                         '--principal', 'group:backend', '--max-message-bytes', '100')
            assert v5['version'] == 5
            ahead = send(bob, a, reviewer, content='ahead')
            assert ahead['request']['policy']['version'] == 5, ahead
            if ahead['state'] != 'accepted':
                assert ahead['state'] == 'unknown' and 'HTTP 503' in ahead['error'], ahead
                alice.cli('network', 'sync', net)
                rid = ahead['request']['request_id']
                wait_for(lambda: bob.cli('message', 'retry', '--peer', a, rid)['state'] == 'accepted',
                         message='cited retry')
            assert show(alice, net)['version'] == 5

            # The block list overrides a grant and the policy, without coordination.
            grant = alice.cli('grant', 'create', '--peer', ids[bob]['id'], '--agent', triage['id'], '--expires-at',
                              timestamp(1200), '--max-message-bytes', '50', '--allow-disconnected')
            expect(bob, a, triage, 'accepted', grant=grant)
            coord.stop()
            for block in (('--person', 'quinn'), ('--host', ids[bob]['id'])):
                made = alice.cli('access', 'block', *block)
                assert made['kind'] == block[0][2:] and alice.cli('access', 'block', *block) == made, made
                assert alice.cli('access', 'blocks') == [made]
                expect(bob, a, triage, 'rejected', grant=grant)
                expect(bob, a, triage, 'rejected')
                assert alice.cli('access', 'unblock', *block) == made
                assert 'not' in alice.cli('access', 'unblock', *block, success=False)
                expect(bob, a, triage, 'accepted', grant=grant)
            assert alice.cli('access', 'blocks') == []
            assert made['subject'] == ids[bob]['id']
            coord.start()

            # Renewal through the agent: the daemon's SSH_AUTH_SOCK by default.
            # A backdated 1-day policy has an hour left, under a quarter.
            now = datetime.now(timezone.utc)
            soon = crafted(v5, 6, now - timedelta(hours=23), now + timedelta(hours=1), keys['pat'][0], root)
            status, accepted = bob.call('POST', f'/v1/networks/{net}/policy', {'policy': soon})
            assert status == 201, accepted
            assert show(bob, net, 'pat')['expires_soon'] is True
            alice.restart(1, agent_socket=agents['pat'].socket)

            def renewed():
                p = show(alice, net)
                return p if p['version'] >= 7 else None
            v7 = wait_for(renewed, timeout=15, message='renewal')
            issued = datetime.fromisoformat(v7['issued_at'].replace('Z', '+00:00'))
            until = datetime.fromisoformat(v7['valid_until'].replace('Z', '+00:00'))
            assert v7['version'] == 7 and v7['expires_soon'] is False and until - issued == timedelta(days=1), v7
            assert v7['rules'] == soon['rules'] and abs((issued - datetime.now(timezone.utc)).total_seconds()) < 60, v7
            ssh_verify(policy_lines(v7), v7['signature'], keys['pat'][1], root)
            # Alice stores the renewal before the coordinator accepts it, so
            # poll until it reaches the map.
            def synced():
                for host in (bob, carol, dave):
                    host.cli('network', 'sync', net)
                return show(bob, net, 'pat')['version'] == 7
            wait_for(synced, timeout=30, message='renewal reaches the map')

            # allow_disconnected with the coordinator stopped: the connected-only
            # rule is retryable (503); the triage rule keeps working.
            coord.stop()
            time.sleep(4)
            unknown = expect(bob, a, reviewer, 'unknown', content='disconnected')
            assert 'HTTP 503' in unknown['error'], unknown
            expect(dave, a, triage, 'accepted', content='disconnected')
            coord.start()
            alice.cli('network', 'sync', net)
            rid = unknown['request']['request_id']
            wait_for(lambda: bob.cli('message', 'retry', '--peer', a, rid)['state'] == 'accepted', message='reconnected')

            # Lapse without an agent (--person-agent given explicitly elsewhere):
            # a policy with seconds left stops authorizing once it expires.
            alice.restart(1)
            now = datetime.now(timezone.utc)
            until = now + timedelta(seconds=12)
            short = crafted(v7, 8, until - timedelta(days=1), until, keys['pat'][0], root)
            status, accepted = alice.call('POST', f'/v1/networks/{net}/policy', {'policy': short})
            assert status == 201, accepted
            dave.cli('network', 'sync', net)
            expect(dave, a, triage, 'accepted', content='before lapse', deadline=timestamp(5))
            time.sleep(max(0.0, (until - datetime.now(timezone.utc)).total_seconds()) + 1)
            expect(dave, a, triage, 'rejected', content='after lapse', deadline=timestamp(5))
            lapsed = show(alice, net)
            assert lapsed['version'] == 8 and lapsed['expires_soon'] is True, lapsed

            # --person-agent names the socket explicitly; renewal of a lapsed
            # policy does not happen, and a fresh one is signed by the CLI.
            alice.restart(1, flag_socket=agents['pat'].socket)
            time.sleep(2)
            assert show(alice, net)['version'] == 8
            renewed_cli = alice.cli('access', 'renew', '--network', net)
            assert renewed_cli['version'] == 9 and renewed_cli['rules'] == v7['rules'], renewed_cli
            expect(dave, a, triage, 'accepted', content='renewed by the CLI')

            check_agent_principal(alice, bob, carol, ids, net, pat_id, quinn_id, agents)
            # Activity records policy updates and blocks.
            kinds = {e['kind'] for e in alice.cli('activity', '--limit', '1000')}
            assert {'network.policy_updated', 'access.blocked', 'access.unblocked'} <= kinds, kinds
            with sqlite3.connect(alice.state / 'host.db') as db:
                assert db.execute('PRAGMA user_version').fetchone()[0] == 16
        finally:
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            stop_all(hosts)
            for host in hosts:
                host.logs.close()
            coord.stop()
            coord.logs.close()
            for agent in agents.values():
                agent.stop()
    print(f'PASS {label}: person, group, and network principals without grant IDs; deny at handoff; stale '
          'policy ignored; cited-version 503 then success; blocks over grants and policy offline; agent renewal; '
          'lapse; size, deadline, and allow_disconnected bounds; agent principals and requester-agent grants', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--pairing', action='append', help='owner/senders, such as Go/Rust; default all')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve()}
    for owner in binaries:
        for sender in binaries:
            if args.pairing and f'{owner}/{sender}' not in args.pairing:
                continue
            check(args.coord.resolve(), binaries[owner], binaries[sender], f'{owner} owner, {sender} senders')


if __name__ == '__main__':
    main()
