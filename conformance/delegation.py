#!/usr/bin/env python3
"""Exercise multi-hop delegation chains (milestone 6 slice 4) with real hosts.

Runs four hosts in one network under the Go coordinator, in Go/Rust mixes
that put each implementation in every chain position: alice (pat) originates,
bob (quinn) and carol (rhea) pass work on, and dave is unbound. With
deterministic adapter consumers and no model calls, it covers two- and
three-hop chains authorized for the originator at the final receiver (by
policy and by grant), refusal when only the sender is allowed, refused
forwards (no task.delegate, no chain, depth 0, outside the principals, a
later deadline, past 3 links), chains forged with capsule-peer-probe
(widened principals, depth, or deadline; spliced or reordered links; wrong
previous, signature, task ID, or audience; replay under another task or to
another host; expired links; malformed chains), blocks of a middle hop or the
originator's person and a revoked originator at submission and at handoff,
cancellation propagated two hops down with each hop's own outcome, MCP
delegate_task with parent_task_id and the originator fields in meta, the
shared link test vector, and v10→v11 migration.
Needs the Go coordinator, capsule-peer-probe, and OpenSSH; Node for MCP.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from agent_adapter import Channel, adapter_call, credential, sql
from coordination import Coordinator, wait_for
from host_service import DELEGATION_TABLES, Host, stop_all
import peer_messaging
from peer_messaging import set_probe, timestamp
from persons import Agent, person_id, ssh_key, use_agent
from policy import PolicyHost
from tasks import HANDOFF_KEYS, LAPSED, POLL, act, channel_event, claim, inspect, task_id, tool, until_state

LINK_KEYS = ['network_id', 'index', 'previous', 'issuer_host_id', 'audience_host_id', 'task_id',
             'originator_agent_id', 'principals', 'deadline', 'depth', 'signature']
# The shared link test vector (docs/delegation-chain-contract.md; Go and Rust unit tests).
VECTOR_SEED = bytes(range(32)).hex()
VECTOR = {'network_id': 'net_' + '0123456789abcdef' * 4, 'index': 0, 'previous': 'none',
          'issuer_host_id': 'host_56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c',
          'audience_host_id': 'host_24f6ed6acbfe1009c030d7ca567c33ca4830911498236b5561a6c82abec5de28',
          'task_id': 'task_00112233445566778899aabbccddeeff', 'originator_agent_id': 'agent_' + '0f' * 16,
          'principals': ['network'], 'deadline': '2026-10-10T00:00:00Z', 'depth': 2,
          'signature': '/0HegHFCfUgKX6UpzfgGus1zCT+yenfwMXilPs5/XmW1OOWJM8QzNHS1XTchodJnQ5ceCXm2a+fHE1TSGssbDA=='}
VECTOR_HASH = '008fbde97103a352b90839c243a0400d5b96427c3cc41aa56950fe559d7e8dae'


def statement(link):
    return '\n'.join(['capsule-delegation-v1', link['network_id'], str(link['index']), link['previous'],
                      link['issuer_host_id'], link['audience_host_id'], link['task_id'], link['originator_agent_id'],
                      ' '.join(link['principals']), link['deadline'], str(link['depth'])])


def link_hash(link):
    return hashlib.sha256((statement(link) + '\n' + link['signature']).encode()).hexdigest()


def probe(*args, stdin=None):
    result = subprocess.run([peer_messaging.PROBE, *args], input=stdin, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def sign(signer, network, index, previous, issuer, audience, tid, agent, principals, deadline, depth):
    """A link signed with a host's key, exactly as given."""
    args = ['sign-link', '--state', str(signer.state), '--network-id', network, '--index', str(index), '--previous',
            previous, '--issuer', issuer, '--audience', audience, '--task-id', tid, '--originator-agent', agent,
            '--deadline', deadline, '--depth', str(depth)]
    for principal in principals:
        args += ['--principal', principal]
    return probe(*args)


def resign(signer, link, **changes):
    fields = {**link, **changes}
    return sign(signer, fields['network_id'], fields['index'], fields['previous'], fields['issuer_host_id'],
                fields['audience_host_id'], fields['task_id'], fields['originator_agent_id'], fields['principals'],
                fields['deadline'], fields['depth'])


def submit_raw(sender, receiver, request, chain):
    """POST /peer/v1/tasks from the sender's host key with a given chain."""
    value = probe('submit-task', '--state', str(sender.state), '--address', receiver.address,
                  '--request', json.dumps(request), '--chain', json.dumps(chain))
    return value['status'], value['body']


def grant(host, requester, agent, action='task.delegate'):
    g = host.cli('grant', 'create', '--peer', requester, '--agent', agent['id'], '--expires-at', timestamp(7200),
                 '--allow-disconnected', '--action', action)
    assert g['action'] == action, g
    return g


def root(alice, peer, agent, origin, g, depth=2, principals=(), deadline=None):
    """An owner submission from the originating agent that creates link 0."""
    args = ['task', 'submit', '--peer', peer, '--agent', agent['id'], '--input', 'whole job', '--grant', g['id'],
            '--from-agent', origin['id'], '--delegation-depth', str(depth)]
    for principal in principals:
        args += ['--delegate-to', principal]
    if deadline:
        args += ['--deadline', deadline]
    out = alice.cli(*args)
    assert out['submit_state'] == 'accepted', out
    return out


def forward(host, parent_sender, parent, peer, agent, g=None, deadline=None, expect=200):
    """POST /v1/tasks with parent; returns the local record or the error."""
    body = {'peer_host_id': peer, 'target_agent_id': agent['id'], 'input': 'part',
            'parent': {'sender_host_id': parent_sender, 'task_id': parent}}
    if g:
        body['grant_id'] = g['id']
    if deadline:
        body['deadline'] = deadline
    status, value = host.call('POST', '/v1/tasks', body)
    assert status == expect, (status, value)
    return value


def take(host, token, tid):
    """Claim the expected task and accept it."""
    handoff = claim(host, token)
    assert handoff and handoff['task']['task_id'] == tid, (tid, handoff)
    assert set(handoff) == HANDOFF_KEYS, handoff
    act(host, token, tid, 'accept')
    return handoff


def cancel_claim(host, token, tid):
    status, notice = adapter_call(host, token, 'POST', '/adapter/v1/tasks/cancels/next', {})
    assert status == 200 and notice and notice['delivery']['task_id'] == tid, notice
    return notice


def activity(host, kind):
    return [e['subject_id'] for e in host.cli('activity', '--limit', '1000') if e['kind'] == kind]


def check_vector():
    signed = probe('sign-link', '--seed-hex', VECTOR_SEED, *sum((['--' + flag, str(VECTOR[key])] for flag, key in (
        ('network-id', 'network_id'), ('index', 'index'), ('previous', 'previous'), ('issuer', 'issuer_host_id'),
        ('audience', 'audience_host_id'), ('task-id', 'task_id'), ('originator-agent', 'originator_agent_id'),
        ('deadline', 'deadline'), ('depth', 'depth'))), []), '--principal', 'network')
    assert list(signed) == LINK_KEYS and signed == VECTOR, signed
    assert link_hash(signed) == VECTOR_HASH
    hashed = subprocess.run([peer_messaging.PROBE, 'link-hash'], input=json.dumps(signed), capture_output=True,
                            text=True, timeout=10)
    assert hashed.stdout.strip() == VECTOR_HASH, hashed
    print('PASS link test vector: statement, signature, and previous hash', flush=True)


def check(binaries, coord_binary, node, script, label):
    with tempfile.TemporaryDirectory(prefix='capsule-delegation-') as temporary:
        directory = Path(temporary)
        coord = Coordinator(coord_binary, directory / 'coord')
        alice, bob, carol, dave = (PolicyHost(binary, directory / name)
                                   for binary, name in zip(binaries, ('alice', 'bob', 'carol', 'dave')))
        hosts = (alice, bob, carol, dave)
        (directory / 'keys').mkdir()
        keys = {name: ssh_key(directory / 'keys', name) for name in ('pat', 'quinn', 'rhea')}
        agents = {}
        channels = []
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        try:
            for name in keys:
                (directory / f'agent-{name}').mkdir()
                agents[name] = Agent(directory / f'agent-{name}')
                agents[name].add(keys[name][0])
            pat_id = person_id(keys['pat'][2])
            coordinator = coord.start()
            A, B, C, D = (host.start()['id'] for host in hosts)
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
            for host in hosts:
                wait_for(lambda: len(host.cli('network', 'members', net)) == 4, timeout=20, message='four members')
            origin = alice.cli('agent', 'register', '--name', 'origin', '--owner', 'pat')
            worker = bob.cli('agent', 'register', '--name', 'worker', '--owner', 'quinn')
            helper = carol.cli('agent', 'register', '--name', 'helper', '--owner', 'rhea')
            extra = dave.cli('agent', 'register', '--name', 'extra', '--owner', 'dave')
            tokens = {}
            for host, agent in ((bob, worker), (carol, helper), (dave, extra)):
                session = host.cli('session', 'attach', '--agent', agent['id'], '--integration', 'test')
                tokens[host] = credential(host, session)['token']

            # Two hops, authorized at carol by her owner's policy for the originator.
            gB = grant(bob, A, worker)
            use_agent(agents['rhea'])
            carol.cli('access', 'allow', '--network', net, '--agent', 'helper', '--principal', 'person:pat',
                      '--action', 'task.submit', '--allow-disconnected')
            bob.cli('network', 'sync', net)
            t0 = root(alice, B, worker, origin, gB)
            l0 = t0['delegation'][0]
            assert t0['parent'] is None and t0['request']['delegation'] == t0['delegation'], t0
            assert set(l0) == set(LINK_KEYS), l0
            assert l0 == {**l0, 'network_id': net, 'index': 0, 'previous': 'none', 'issuer_host_id': A,
                          'audience_host_id': B, 'task_id': t0['request']['task_id'], 'originator_agent_id':
                          origin['id'], 'principals': ['network'], 'deadline': t0['request']['deadline'],
                          'depth': 2}, l0
            assert l0['deadline'].endswith('Z')
            h0 = take(bob, tokens[bob], t0['request']['task_id'])
            assert h0['delegable'] is True and h0['originator_person_id'] == pat_id, h0
            assert h0['task']['delegation'] == t0['delegation'] and h0['task']['origin'] == {'agent_id': origin['id']}
            t1 = forward(bob, A, t0['request']['task_id'], C, helper)
            assert t1['submit_state'] == 'accepted' and t1['request']['policy'] and t1['request']['grant_id'] is None
            assert t1['parent'] == {'sender_host_id': A, 'task_id': t0['request']['task_id']}, t1
            assert t1['delegation'] == t1['request']['delegation'] and len(t1['delegation']) == 2, t1
            l1 = t1['delegation'][1]
            assert t1['delegation'][0] == l0 and l1['previous'] == link_hash(l0), t1
            assert l1 == {**l1, 'index': 1, 'issuer_host_id': B, 'audience_host_id': C, 'task_id':
                          t1['request']['task_id'], 'originator_agent_id': origin['id'], 'principals': ['network'],
                          'deadline': t1['request']['deadline'], 'depth': 1}, l1
            assert t1['request']['origin']['agent_id'] == worker['id'], t1
            assert f"{C}/{t1['request']['task_id']}" in activity(bob, 'task.delegated')
            h1 = take(carol, tokens[carol], t1['request']['task_id'])
            assert h1['task']['delegation'] == t1['delegation'] and h1['delegable'] is False, h1
            assert h1['originator_person_id'] == pat_id and h1['delivery']['sender_host_id'] == B, h1
            # Refused when only the sender is allowed.
            carol.cli('access', 'allow', '--network', net, '--agent', 'helper', '--principal', 'person:quinn',
                      '--action', 'task.submit', '--allow-disconnected')
            bob.cli('network', 'sync', net)
            sender_only = forward(bob, A, t0['request']['task_id'], C, helper)
            assert sender_only['submit_state'] == 'rejected' and 'HTTP 403' in sender_only['error'], sender_only

            # Three hops, by grants for the originator; refused under one for the sender.
            gC = grant(carol, A, helper)
            gD = grant(dave, A, extra, 'task.submit')
            t0 = root(alice, B, worker, origin, gB)['request']['task_id']
            take(bob, tokens[bob], t0)
            t1 = forward(bob, A, t0, C, helper, gC)['request']['task_id']
            assert take(carol, tokens[carol], t1)['delegable'] is True
            t2 = forward(carol, B, t1, D, extra, gD)
            assert t2['submit_state'] == 'accepted' and len(t2['delegation']) == 3, t2
            assert t2['delegation'][2]['depth'] == 0 and t2['delegation'][2]['previous'] == link_hash(t2['delegation'][1])
            h2 = take(dave, tokens[dave], t2['request']['task_id'])
            assert [link['issuer_host_id'] for link in h2['task']['delegation']] == [A, B, C], h2
            assert h2['delegable'] is False and h2['originator_person_id'] == pat_id, h2
            assert forward(carol, B, t1, D, extra, grant(dave, C, extra, 'task.submit'))['submit_state'] == 'rejected'
            # Past 3 links: depth is spent at dave.
            forward(dave, C, t2['request']['task_id'], A, origin, gD, expect=403)

            # Refused forwards.
            plain = root(alice, B, worker, origin, grant(bob, A, worker, 'task.submit'))['request']['task_id']
            assert take(bob, tokens[bob], plain)['delegable'] is False
            forward(bob, A, plain, C, helper, gC, expect=403)
            chainless = alice.cli('task', 'submit', '--peer', B, '--agent', worker['id'], '--input', 'x', '--grant',
                                  gB['id'], '--from-agent', origin['id'])
            assert chainless['delegation'] is None and 'delegation' not in chainless['request'], chainless
            handoff = take(bob, tokens[bob], chainless['request']['task_id'])
            assert handoff['delegable'] is False and 'delegation' not in handoff['task'], handoff
            forward(bob, A, chainless['request']['task_id'], C, helper, gC, expect=403)
            shallow = root(alice, B, worker, origin, gB, depth=1)['request']['task_id']
            take(bob, tokens[bob], shallow)
            last = forward(bob, A, shallow, C, helper, gC)['request']['task_id']
            spent = take(carol, tokens[carol], last)
            assert spent['delegable'] is False and spent['task']['delegation'][1]['depth'] == 0, spent
            forward(carol, B, last, D, extra, gD, expect=403)
            narrow = root(alice, B, worker, origin, gB, principals=('host:' + C,))
            assert narrow['delegation'][0]['principals'] == ['host:' + C], narrow
            take(bob, tokens[bob], narrow['request']['task_id'])
            forward(bob, A, narrow['request']['task_id'], D, extra, gD, expect=403)
            forward(bob, A, narrow['request']['task_id'], C, helper, gC, deadline=timestamp(7200), expect=403)
            # The CLI forwards with --parent-sender and --parent-task.
            cli_forward = bob.cli('task', 'submit', '--peer', C, '--agent', helper['id'], '--input', 'by cli', '--grant',
                                  gC['id'], '--parent-sender', A, '--parent-task', narrow['request']['task_id'])
            assert cli_forward['submit_state'] == 'accepted' and len(cli_forward['delegation']) == 2, cli_forward
            take(carol, tokens[carol], cli_forward['request']['task_id'])
            for bad in ({'delegation_depth': 3}, {'delegation_depth': 1, 'delegation_principals': ['group:x']},
                        {'delegation_principals': ['network']}, {'delegation_depth': 1, 'origin': None}):
                body = {'peer_host_id': B, 'target_agent_id': worker['id'], 'input': 'x', 'grant_id': gB['id'],
                        'origin': {'agent_id': origin['id']}, **bad}
                body = {k: v for k, v in body.items() if v is not None}
                assert alice.call('POST', '/v1/tasks', body)[0] == 400, bad

            # Forged chains, sent by bob's key to carol with carol's grant for alice.
            def base(d1=None, d0=None):
                d1 = d1 or timestamp(1200)
                first = sign(alice, net, 0, 'none', A, B, task_id(), origin['id'], ['network'], d0 or timestamp(1800), 2)
                second = sign(bob, net, 1, link_hash(first), B, C, task_id(), origin['id'], ['network'], d1, 1)
                return [first, second]

            def request(chain, **changes):
                return {'task_id': chain[-1]['task_id'], 'grant_id': gC['id'], 'target_agent_id': helper['id'],
                        'deadline': chain[-1]['deadline'], 'input': 'forged', 'origin': {'agent_id': worker['id']},
                        **changes}

            control = base()
            status, accepted = submit_raw(bob, carol, request(control), control)
            assert status == 200 and accepted['state'] == 'queued', accepted
            assert submit_raw(bob, carol, request(control), control) == (200, accepted)
            forged = claim(carol, tokens[carol])
            assert forged['task']['delegation'] == control and forged['originator_person_id'] == pat_id, forged
            act(carol, tokens[carol], control[-1]['task_id'], 'reject', {'reason': 'forged'})
            refusals = {}
            chain = base()
            wide = resign(alice, chain[0], principals=['host:' + C])
            refusals['widened principals'] = [wide, resign(bob, chain[1], previous=link_hash(wide))]
            chain = base()
            refusals['widened depth'] = [chain[0], resign(bob, chain[1], depth=2)]
            chain = base(d1=timestamp(2400))
            refusals['widened deadline'] = chain
            chain, other = base(), base()
            refusals['spliced'] = [other[0], chain[1]]
            chain = base()
            refusals['reordered'] = [chain[1], chain[0]]
            refusals['wrong previous'] = [chain[0], resign(bob, chain[1], previous='0' * 64)]
            chain = base()
            refusals['bad signature'] = [chain[0], {**chain[1], 'signature': chain[0]['signature']}]
            chain = base()
            refusals['wrong audience'] = [chain[0], resign(bob, chain[1], audience_host_id=D)]
            chain = base()
            mismatch = resign(bob, chain[1], task_id=task_id())
            assert submit_raw(bob, carol, request([chain[0], mismatch], task_id=chain[1]['task_id']),
                              [chain[0], mismatch])[0] == 403, 'mismatched task ID'
            chain = base(d1=timestamp(-30), d0=timestamp(-20))
            refusals['expired link'] = chain
            chain = base()
            refusals['link 0 depth 3'] = [resign(alice, chain[0], depth=3)]
            refusals['link 0 depth 3'].append(resign(bob, chain[1], previous=link_hash(refusals['link 0 depth 3'][0]),
                                                     depth=2))
            for name, chain in refusals.items():
                assert submit_raw(bob, carol, request(chain), chain)[0] == 403, name
            # Replay under another task, and to another host.
            assert submit_raw(bob, carol, request(control, task_id=task_id()), control)[0] == 403
            to_dave = request(control, grant_id=gD['id'], target_agent_id=extra['id'])
            assert submit_raw(bob, dave, to_dave, control)[0] == 403
            # A chain from another sender than its last issuer.
            chain = base()
            assert submit_raw(dave, carol, request(chain), chain)[0] == 403
            # Malformed chains.
            chain = base()
            for name, bad in {'empty': [], 'four links': chain + chain, 'not a list': chain[0],
                              'unsorted': [chain[0], {**chain[1], 'principals': ['network', 'host:' + D]}],
                              'extra key': [chain[0], {**chain[1], 'extra': 1}],
                              'null field': [chain[0], {**chain[1], 'depth': None}],
                              'offset deadline': [chain[0], {**chain[1], 'deadline': '2099-01-01T00:00:00+00:00'}]}.items():
                assert submit_raw(bob, carol, request(chain), bad)[0] == 400, name

            # Blocks: a middle hop and the originator's person, at submission and at handoff.
            for subject in (('--host', B), ('--person', 'pat')):
                parent = root(alice, B, worker, origin, gB)['request']['task_id']
                take(bob, tokens[bob], parent)
                queued = forward(bob, A, parent, C, helper, gC)['request']['task_id']
                carol.cli('access', 'block', *subject)
                refused = forward(bob, A, parent, C, helper, gC)
                assert refused['submit_state'] == 'rejected' and 'HTTP 403' in refused['error'], (subject, refused)
                assert claim(carol, tokens[carol]) is None
                lapsed = until_state(bob, {'id': C}, queued, 'rejected')
                assert bob.cli('task', 'events', '--peer', C, queued)[-1]['message'] == LAPSED, lapsed
                carol.cli('access', 'unblock', *subject)

            # Cancellation propagates two hops down; each hop reports its own outcome.
            t0 = root(alice, B, worker, origin, gB)['request']['task_id']
            take(bob, tokens[bob], t0)
            t1 = forward(bob, A, t0, C, helper, gC)['request']['task_id']
            take(carol, tokens[carol], t1)
            t2 = forward(carol, B, t1, D, extra, gD)['request']['task_id']
            take(dave, tokens[dave], t2)
            assert alice.cli('task', 'cancel', '--peer', B, t0)['cancel_state'] == 'sent'
            wait_for(lambda: inspect(bob, {'id': C}, t1)['status']['cancel_requested'], timeout=POLL,
                     message='cancellation at carol')
            wait_for(lambda: inspect(carol, {'id': D}, t2)['status']['cancel_requested'], timeout=POLL,
                     message='cancellation at dave')
            forward(bob, A, t0, C, helper, gC, expect=409)
            cancel_claim(dave, tokens[dave], t2)
            act(dave, tokens[dave], t2, 'cancelled')
            cancel_claim(carol, tokens[carol], t1)
            act(carol, tokens[carol], t1, 'complete', {'status': 'succeeded', 'output': 'finished anyway'})
            cancel_claim(bob, tokens[bob], t0)
            act(bob, tokens[bob], t0, 'cancelled')
            until_state(carol, {'id': D}, t2, 'cancelled')
            finished = until_state(bob, {'id': C}, t1, 'succeeded')
            assert finished['status']['cancel_requested'] is True and finished['cancel_state'] == 'sent', finished
            until_state(alice, {'id': B}, t0, 'cancelled')

            # MCP: delegate_task with parent_task_id, and the originator fields in meta.
            if node:
                planner = alice.cli('agent', 'register', '--name', 'planner', '--owner', 'pat')
                coder = bob.cli('agent', 'register', '--name', 'coder', '--owner', 'quinn')
                tester = carol.cli('agent', 'register', '--name', 'tester', '--owner', 'rhea')
                secrets_by_name = {}
                for host, agent in ((alice, planner), (bob, coder), (carol, tester)):
                    session = host.cli('session', 'attach', '--agent', agent['id'], '--integration', 'claude-channel')
                    secrets_by_name[agent['name']] = (session, credential(host, session))
                to_coder = grant(bob, A, coder)
                to_tester = grant(carol, A, tester, 'task.submit')
                route = alice.cli('adapter', 'route', 'add', '--adapter', secrets_by_name['planner'][1]['adapter']['id'],
                                  '--name', 'coder', '--peer', B, '--agent', coder['id'], '--grant', to_coder['id'],
                                  '--action', 'task.submit', '--delegation-depth', '2', '--expires-at', timestamp(900))
                assert route['delegation_depth'] == 2, route
                bob.cli('adapter', 'route', 'add', '--adapter', secrets_by_name['coder'][1]['adapter']['id'], '--name',
                        'tester', '--peer', C, '--agent', tester['id'], '--grant', to_tester['id'], '--action',
                        'task.submit', '--expires-at', timestamp(900))
                alice.cli('adapter', 'route', 'add', '--adapter', secrets_by_name['planner'][1]['adapter']['id'],
                          '--name', 'bad', '--peer', B, '--agent', coder['id'], '--delegation-depth', '1',
                          '--expires-at', timestamp(900), success=False)
                channel = {}
                for host, name in ((alice, 'planner'), (bob, 'coder'), (carol, 'tester')):
                    channel[name] = Channel(node, script, host, secrets_by_name[name][1], directory / f'{name}-channel')
                    channels.append(channel[name])
                failed, submitted = tool(channel['planner'], 'delegate_task', {'destination': 'coder', 'input': 'build'})
                assert not failed and submitted['submit_state'] == 'accepted', submitted
                event = channel_event(channel['coder'], 'task')
                meta = event['meta']
                assert meta['task_id'] == submitted['task_id'] and meta['delegable'] is True, meta
                assert meta['originator_host_id'] == A and meta['originator_agent_id'] == planner['id'], meta
                assert meta['originator_person_id'] == pat_id and meta['chain_hosts'] == [A], meta
                failed, early = tool(channel['coder'], 'delegate_task', {'destination': 'tester', 'input': 'test it',
                                                                      'parent_task_id': meta['task_id']})
                assert failed, early
                assert not tool(channel['coder'], 'task_accept', {'task_id': meta['task_id']})[0]
                failed, passed = tool(channel['coder'], 'delegate_task', {'destination': 'tester', 'input': 'test it',
                                                                       'parent_task_id': meta['task_id']})
                assert not failed and passed['submit_state'] == 'accepted', passed
                assert passed['parent_task_id'] == meta['task_id'], passed
                record = tool(channel['coder'], 'task_status', {'task_id': passed['task_id']})[1]
                assert record['parent'] == {'sender_host_id': A, 'task_id': meta['task_id']}, record
                assert len(record['delegation']) == 2, record
                event = channel_event(channel['tester'], 'task')
                meta = event['meta']
                assert meta['task_id'] == passed['task_id'] and meta['delegable'] is False, meta
                assert meta['originator_host_id'] == A and meta['originator_agent_id'] == planner['id'], meta
                assert meta['originator_person_id'] == pat_id and meta['chain_hosts'] == [A, B], meta
                assert meta['origin_agent_id'] == coder['id'] and meta['sender_host_id'] == B, meta

            # A revoked originator: refused at submission and rejected at handoff.
            gBD, gCD = grant(bob, D, worker), grant(carol, D, helper, 'task.submit')
            parents = []
            for _ in range(2):
                out = root(dave, B, worker, extra, gBD)
                parents.append(out['request']['task_id'])
                take(bob, tokens[bob], parents[-1])
            queued = forward(bob, D, parents[0], C, helper, gCD)['request']['task_id']
            alice.cli('network', 'revoke', '--network', net, '--host', D)
            for host in (bob, carol):
                wait_for(lambda: D not in {m['host_id'] for m in host.cli('network', 'members', net)}, timeout=20,
                         message='revocation sync')
            assert claim(carol, tokens[carol]) is None
            until_state(bob, {'id': C}, queued, 'rejected')
            assert bob.cli('task', 'events', '--peer', C, queued)[-1]['message'] == LAPSED
            refused = forward(bob, D, parents[1], C, helper, gCD)
            assert refused['submit_state'] == 'rejected' and 'HTTP 403' in refused['error'], refused
        finally:
            failure = None
            for channel in channels:
                try:
                    channel.close()
                except Exception as error:
                    failure = failure or error
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            stop_all(hosts)
            coord.stop()
            coord.logs.close()
            for agent in agents.values():
                agent.stop()
            if failure:
                raise failure
    print(f'PASS {label}: two- and three-hop chains authorized for the originator, refused forwards, forged '
          'chains, blocks and revocation at submission and handoff, two-hop cancellation'
          + (', MCP parent_task_id and meta' if node else ''), flush=True)


def migration_check(original, replacement, label):
    with tempfile.TemporaryDirectory(prefix='capsule-delegation-migration-') as directory:
        host = Host(original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            host.stop()
            for table in DELEGATION_TABLES:
                sql(host, 'DROP TABLE ' + table)
            sql(host, 'PRAGMA user_version = 10')
            host.binary = str(replacement)
            assert host.start()['id'] == identity['id']
            assert sql(host, 'PRAGMA user_version')[0][0] == 11
            assert {row[0] for row in sql(host, "SELECT name FROM sqlite_master WHERE type = 'table'")} >= set(DELEGATION_TABLES)
            assert host.cli('agent', 'inspect', agent['id']) == agent
            assert host.cli('task', 'list') == []
            host.stop()
            sql(host, 'PRAGMA user_version = 12')
            for binary in (original, replacement):
                result = subprocess.run([str(binary), '--state', str(host.state), 'run'], capture_output=True, timeout=5)
                assert result.returncode != 0 and sql(host, 'PRAGMA user_version')[0][0] == 12
        finally:
            stop_all((host,))
    print(f'PASS {label}: v10→v11 migration; version 12 refused', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    parser.add_argument('--node', type=Path, help='Node.js for the MCP cases; skipped without it')
    parser.add_argument('--mix', action='append',
                        help='implementations of alice, bob, carol, and dave, such as GRGR; default GGGG, RRRR, '
                             'GRGR, and RGRG, which put each implementation in every position')
    args = parser.parse_args()
    set_probe(args.probe.resolve(strict=True))
    script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'
    node = args.node.resolve() if args.node else None
    binaries = {'G': args.go.resolve(), 'R': args.rust.resolve()}
    check_vector()
    migration_check(binaries['G'], binaries['R'], 'Go→Rust')
    migration_check(binaries['R'], binaries['G'], 'Rust→Go')
    for mix in args.mix or ['GGGG', 'RRRR', 'GRGR', 'RGRG']:
        assert len(mix) == 4 and set(mix) <= set(binaries), mix
        names = {'G': 'Go', 'R': 'Rust'}
        check([binaries[c] for c in mix], args.coord.resolve(), node, script,
              'alice, bob, carol, dave = ' + ', '.join(names[c] for c in mix))


if __name__ == '__main__':
    main()
