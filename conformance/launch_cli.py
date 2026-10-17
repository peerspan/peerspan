#!/usr/bin/env python3
"""Exercise the launch CLI shape (milestone 7 slice 1) across CLI/daemon pairings.

Runs every Go/Rust CLI and daemon pairing, with one Go coordinator and real
ssh-agents for the network cases. It covers:

- the name: one binary as `peerspan` and `peerspan-host`, through symbolic links;
- help: the root help's command set and order, `help advanced` and
  `--help-advanced` listing every command, and hidden commands' own help;
- network defaulting with zero, one, and two networks, and the explicit-only
  commands;
- `--expires-in` everywhere, each expiry default (session setup and its
  routes file included, through an interrupted setup's recovery), and mutual
  exclusion with `--expires-at`;
- renewable credentials: expiry advancing after a lease renewal more than 60
  seconds later, a following route moving with it, `adapter.renewed` recorded
  once, an explicit expiry never moving, and `follows_credential` refused on
  a fixed credential;
- `GET /v1/status` and `peerspan status`: the shape, each deterministic
  attention kind (coordination_error with the coordinator stopped,
  policy_expiring with a crafted policy and no ssh-agent for the daemon,
  policy_delivery_failing with a sibling down, credential_expiring,
  tasks_failed, artifact_quota with a small --artifact-quota), and exit codes
  0, 1, and 2.

The bundle's `bin/peerspan` link is covered by installed_bundle.py. Renewal is
checked at the end of each pairing, once more than 60 seconds have passed
since the credential was issued. Needs OpenSSH (ssh-agent, ssh-add,
ssh-keygen).
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from agent_adapter import adapter_call, instance_for
from artifacts import upload
from coordination import Coordinator, wait_for
from harness_setup import catalog
from host_service import stop_all
from peer_messaging import set_probe
from persons import Agent, person_id, ssh_key, use_agent
from policy import PolicyHost, crafted

ROOT_COMMANDS = [
    'status', 'install', 'run',
    'network create', 'join', 'invite',
    'attach', 'agents', 'send', 'task',
    'allow', 'deny', 'block', 'unblock',
    'network list', 'network members', 'access show',
    'session start', 'session doctor',
]
# Every command help advanced must list, beyond the root help's.
HIDDEN_COMMANDS = [
    'info', 'agent register', 'agent list', 'agent inspect',
    'session attach', 'session list', 'session inspect', 'session detach',
    'peer add', 'peer list', 'peer path',
    'grant create', 'grant list', 'grant revoke',
    'message list', 'message inspect', 'message retry', 'message refresh', 'message reply', 'message origin',
    'task list', 'task inspect', 'task cancel', 'task events', 'task artifact',
    'artifact list', 'artifact prune',
    'network sync', 'network revoke', 'network revoke-invite', 'network leave', 'network rotate-root',
    'network admit', 'network invite-person', 'network redeem-person', 'network bind', 'network unbind',
    'network remove-person', 'network persons', 'network delegate-admin', 'network remove-admin',
    'network group set', 'network groups',
    'access renew', 'access sync', 'access block', 'access unblock', 'access blocks',
    'person show',
    'adapter create', 'adapter list', 'adapter inspect', 'adapter revoke', 'adapter rotate', 'adapter connection',
    'adapter route add', 'adapter route list', 'adapter route revoke',
    'delivery list', 'delivery inspect', 'activity', 'uninstall',
    'session setup', 'message send', 'task submit',
    'network join', 'network invite', 'access allow', 'access deny',
]
# `capabilities` added by the capabilities contract (Status).
STATUS_KEYS = {'host_id', 'version', 'networks', 'blocks', 'agents', 'artifacts', 'capabilities', 'attention'}
CAPABILITY_COUNTS = {'sources', 'capabilities', 'shared', 'calls_running'}
NETWORK_KEYS = {'id', 'name', 'coordinator', 'last_sync_at', 'last_sync_error', 'members', 'person', 'policy',
                'policy_deliveries_pending'}
SESSION_KEYS = {'id', 'integration', 'adapter_id', 'connection', 'expires_at', 'renewable'}
ATTENTION_ORDER = ['coordination_error', 'policy_expired', 'policy_expiring', 'policy_delivery_failing',
                   'credential_expiring', 'tasks_failed', 'artifact_quota',
                   # Slice 2's service and coordinator items; launch_service.py checks them.
                   'service_not_installed', 'linger_disabled', 'person_agent_unreachable', 'coordinator_limit',
                   # Items 12 and 13 (launch and live delivery contracts), 14 and 15 (capabilities contract).
                   'agent_name_conflict', 'channel_unverified', 'capability_failing', 'capability_name_conflict']
QUOTA = 1000
DAY = 24 * 3600

# An installed, active, lingering user service as recording-free stubs, so the
# CLI's service checks (slice 2) add no attention to the cases here.
SERVICE_HOME = Path(tempfile.mkdtemp(prefix='launch-cli-service-'))
(SERVICE_HOME / 'config/systemd/user').mkdir(parents=True)
(SERVICE_HOME / 'config/systemd/user/peerspan.service').write_text('[Service]\n')
(SERVICE_HOME / 'bin').mkdir()
for tool, script in {'systemctl': 'echo active', 'loginctl': 'echo Linger=yes'}.items():
    stub = SERVICE_HOME / 'bin' / tool
    stub.write_text(f'#!/bin/sh\n{script}\n')
    stub.chmod(0o755)


def parse_time(value):
    """An RFC3339 time with any fractional precision."""
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)', value)
    assert match, value
    fraction = (match.group(2) or '.0')[:7]
    zone = '+00:00' if match.group(3) == 'Z' else match.group(3)
    return datetime.fromisoformat(match.group(1) + fraction + zone)


def near(value, seconds, tolerance=120):
    """Assert an RFC3339 time is about `seconds` from now."""
    offset = (parse_time(value) - datetime.now(timezone.utc)).total_seconds()
    assert abs(offset - seconds) <= tolerance, (value, offset, seconds)


def rfc3339(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


class LaunchHost(PolicyHost):
    """A daemon of one implementation driven by the other's CLI, without an ssh-agent for the daemon."""

    def __init__(self, daemon_binary, cli_binary, state, quota=None):
        super().__init__(daemon_binary, state)
        self.cli_binary = str(cli_binary)
        if quota is not None:
            self.daemon_args = (*self.daemon_args, '--artifact-quota', str(quota))

    def run(self, *args, program=None):
        """Run the CLI, returning the completed process."""
        env = dict(os.environ)
        if not self.keep_agent:
            env.pop('SSH_AUTH_SOCK', None)
        env['PATH'] = f"{SERVICE_HOME / 'bin'}:{env.get('PATH', '')}"
        env['XDG_CONFIG_HOME'] = str(SERVICE_HOME / 'config')
        return subprocess.run([program or self.cli_binary, '--state', str(self.state), *args],
                              capture_output=True, text=True, timeout=20, env=env)

    def cli(self, *args, success=True):
        result = self.run(*args)
        assert (result.returncode == 0) == success, (self.cli_binary, args, result.stdout, result.stderr)
        return json.loads(result.stdout) if success else result.stderr

    def refuse(self, *args, contains=()):
        result = self.run(*args)
        assert result.returncode != 0, (args, result.stdout)
        for text in contains:
            assert text in result.stderr, (args, text, result.stderr)
        return result.stderr

    def status(self, program=None):
        result = self.run('status', '--json', program=program)
        assert result.returncode in (0, 1), (result.returncode, result.stdout, result.stderr)
        value = json.loads(result.stdout)
        assert result.returncode == (1 if value['attention'] else 0), (result.returncode, value['attention'])
        return value


def commands(text):
    """The command paths of a help text's Commands section."""
    lines = text.splitlines()
    assert 'Commands:' in lines, text
    paths = []
    for line in lines[lines.index('Commands:') + 1:]:
        if not line.strip():
            break
        assert line.startswith('  '), line
        paths.append(re.split(r' {2,}', line.strip())[0])
    return paths


def help_of(program, *args):
    result = subprocess.run([str(program), *args], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


def check_name_and_help(cli_binary, links):
    """peerspan and peerspan-host behave alike; the root help lists the main commands only."""
    for name in ('peerspan', 'peerspan-host'):
        link = links / name
        if not link.exists():
            link.symlink_to(cli_binary)
    short, long = links / 'peerspan', links / 'peerspan-host'
    for program in (short, long):
        root = help_of(program)
        assert help_of(program, '--help') == root and help_of(program, 'help') == root
        assert commands(root) == ROOT_COMMANDS, commands(root)
        last = [line for line in root.splitlines() if line.strip()][-1]
        assert 'help advanced' in last, last
        advanced = commands(help_of(program, 'help', 'advanced'))
        assert len(advanced) == len(set(advanced)), advanced
        assert set(ROOT_COMMANDS + HIDDEN_COMMANDS) <= set(advanced), set(ROOT_COMMANDS + HIDDEN_COMMANDS) - set(advanced)
        assert set(commands(help_of(program, '--help-advanced'))) == set(advanced)
        # Hidden commands keep their own help.
        for path in ('grant create', 'adapter route add', 'network revoke', 'activity', 'access renew'):
            assert '--' in help_of(program, *path.split(), '--help'), path
    assert 'peerspan-host' not in help_of(short), help_of(short)
    assert 'peerspan-host' in help_of(long)
    assert commands(help_of(short)) == commands(help_of(long))
    return short, long


def check_not_running(host, program):
    """Exit code 2 and the not-running object when the daemon is unreachable."""
    result = host.run('status', '--json', program=program)
    assert result.returncode == 2, (result.returncode, result.stdout, result.stderr)
    value = json.loads(result.stdout)
    value.pop('service', None)  # added by the CLI in slice 2
    assert value == {'daemon': 'not running', 'state': str(Path(host.state).resolve())}, value
    assert host.run('status', program=program).returncode == 2


def check_shape(value):
    assert set(value) - {'service'} == STATUS_KEYS, value  # the CLI adds service in slice 2
    assert isinstance(value['host_id'], str) and value['host_id'].startswith('host_'), value
    assert isinstance(value['version'], str) and value['version'], value
    assert isinstance(value['blocks'], int)
    assert set(value['artifacts']) == {'quota', 'stored_bytes', 'pending_bytes'}, value['artifacts']
    check_capability_counts(value)
    assert [n['id'] for n in value['networks']] == sorted(n['id'] for n in value['networks'])
    for n in value['networks']:
        assert set(n) == NETWORK_KEYS, n
        assert n['person'] is None or set(n['person']) == {'id', 'label'}, n
        assert n['policy'] is None or set(n['policy']) == {'version', 'valid_until'}, n
    names = [a['name'] for a in value['agents']]
    assert names == sorted(names), names
    for a in value['agents']:
        assert set(a) == {'id', 'name', 'sessions'}, a
        for s in a['sessions']:
            assert set(s) == SESSION_KEYS, s
    for item in value['attention']:
        assert set(item) == {'kind', 'subject', 'detail', 'command'}, item
        assert item['kind'] in ATTENTION_ORDER, item
    keys = [(ATTENTION_ORDER.index(i['kind']), i['subject']) for i in value['attention']]
    assert keys == sorted(keys), keys


def check_capability_counts(value):
    """`capabilities: {sources, capabilities, shared, calls_running, open_to}`: the object also contains the
    open-list count (capabilities contract, Status)."""
    counts = value['capabilities']
    assert set(counts) == CAPABILITY_COUNTS | {'open_to'}, counts
    for key in counts:
        assert isinstance(counts[key], int) and counts[key] >= 0, counts


def capability_counts(value):
    return dict(value['capabilities'])


def attention(value, kind=None):
    items = value['attention']
    return [i for i in items if i['kind'] == kind] if kind else items


def session_of(value, session_id):
    for a in value['agents']:
        for s in a['sessions']:
            if s['id'] == session_id:
                return s
    return None


def connect(host, secret):
    return adapter_call(host, secret['token'], 'POST', '/adapter/v1/connect',
                        {'instance_id': instance_for(host, secret['token'])['instance']})


def renewed(host, adapter_id):
    events = host.cli('activity', '--limit', '1000')
    return [e for e in events if e['kind'] == 'adapter.renewed' and e['subject_id'] == adapter_id]


def check(coord_binary, cli_binary, daemon_binary, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-launch-cli-') as temporary:
        root = Path(temporary)
        (root / 'links').mkdir()
        short, long = check_name_and_help(cli_binary, root / 'links')

        coord = Coordinator(coord_binary, root / 'coord')
        alice = LaunchHost(daemon_binary, cli_binary, root / 'alice', quota=QUOTA)
        bob = LaunchHost(daemon_binary, cli_binary, root / 'bob')
        hosts = (alice, bob)
        check_not_running(alice, short)
        check_not_running(alice, long)

        (root / 'keys').mkdir()
        pat_key = ssh_key(root / 'keys', 'pat')
        (root / 'agent').mkdir()
        agent = Agent(root / 'agent')
        agent.add(pat_key[0])
        saved_sock = os.environ.get('SSH_AUTH_SOCK')
        use_agent(None)
        try:
            coordinator = coord.start()
            ai, bi = alice.start(), bob.start()
            a, b = ai['id'], bi['id']

            # A fresh host needs no attention: exit 0, through either name.
            fresh = alice.status(short)
            check_shape(fresh)
            assert fresh['host_id'] == a and fresh['networks'] == [] and fresh['attention'] == [], fresh
            assert fresh['artifacts'] == {'quota': QUOTA, 'stored_bytes': 0, 'pending_bytes': 0}, fresh
            assert capability_counts(fresh) == {'sources': 0, 'capabilities': 0, 'shared': 0, 'calls_running': 0,
                                                'open_to': 0}, fresh
            assert alice.run('status').returncode == 0
            same = alice.status(long)
            assert {k: v for k, v in same.items()} == fresh, (same, fresh)

            # Network defaulting without any network.
            for args in (('network', 'members'), ('network', 'sync'), ('network', 'persons'), ('network', 'groups'),
                         ('access', 'show'), ('network', 'invite', '--member', 'x')):
                alice.refuse(*args, contains=('not a member of any network',))

            # Peers, agents, and sessions for the expiry and credential cases.
            alice.cli('peer', 'add', '--id', b, '--public-key', bi['public_key'], '--address', bob.address)
            bob.cli('peer', 'add', '--id', a, '--public-key', ai['public_key'], '--address', alice.address)
            reviewer = bob.cli('agent', 'register', '--name', 'reviewer', '--owner', 'pat')
            sessions = {}
            for name in ('renewing', 'fixed', 'later', 'spare'):
                registered = alice.cli('agent', 'register', '--name', name, '--owner', 'pat')
                sessions[name] = alice.cli('session', 'attach', '--agent', registered['id'], '--integration', 'test')

            # Expiries: mutual exclusion and the --expires-in syntax everywhere.
            both = ('--expires-at', rfc3339(3600), '--expires-in', '1h')
            for args in (('grant', 'create', '--peer', a, '--agent', reviewer['id']),
                         ('network', 'invite', '--network', 'net_x', '--member', 'x'),
                         ('network', 'invite-person', '--network', 'net_x', '--member', 'x'),
                         ('adapter', 'create', '--session', sessions['spare']['id']),
                         ('adapter', 'route', 'add', '--adapter', 'adapter_' + '0' * 32, '--name', 'x', '--peer', b,
                          '--agent', reviewer['id']),
                         ('session', 'setup', '--directory', str(root / 'setup'), '--harness', 'claude-code',
                          '--agent', reviewer['id'])):
                host = bob if args[0] == 'grant' else alice
                host.refuse(*args, *both, contains=('mutually exclusive',))
                host.refuse(*args, '--expires-in', '0m', contains=('whole-minute or whole-hour',))
                host.refuse(*args, '--expires-in', '721h', contains=('whole-minute or whole-hour',))

            # Credentials: renewable by default, fixed with --expires-in.
            issued = time.monotonic()
            renewing = alice.cli('adapter', 'create', '--session', sessions['renewing']['id'])
            assert renewing['adapter']['renewable'] is True, renewing
            near(renewing['adapter']['expires_at'], DAY)
            fixed = alice.cli('adapter', 'create', '--session', sessions['fixed']['id'], '--expires-in', '2h')
            assert fixed['adapter']['renewable'] is False, fixed
            near(fixed['adapter']['expires_at'], 7200, tolerance=30)
            later = alice.cli('adapter', 'create', '--session', sessions['later']['id'], '--expires-at', rfc3339(2 * DAY))
            assert later['adapter']['renewable'] is False
            listed = {x['id']: x for x in alice.cli('adapter', 'list')}
            assert listed[renewing['adapter']['id']]['renewable'] is True
            assert listed[fixed['adapter']['id']]['renewable'] is False

            # Routes follow a renewable credential by default; an explicit
            # expiry stays fixed; a fixed credential refuses to be followed.
            follower = alice.cli('adapter', 'route', 'add', '--adapter', renewing['adapter']['id'], '--name', 'follow',
                                 '--peer', b, '--agent', reviewer['id'])
            assert follower['follows_credential'] is True, follower
            assert follower['expires_at'] == renewing['adapter']['expires_at'], follower
            pinned = alice.cli('adapter', 'route', 'add', '--adapter', renewing['adapter']['id'], '--name', 'pinned',
                               '--peer', b, '--agent', reviewer['id'], '--expires-in', '3h')
            assert pinned['follows_credential'] is False, pinned
            near(pinned['expires_at'], 3 * 3600, tolerance=30)
            alice.refuse('adapter', 'route', 'add', '--adapter', fixed['adapter']['id'], '--name', 'follow',
                         '--peer', b, '--agent', reviewer['id'])
            code, body = alice.call('POST', '/v1/adapter-routes', {
                'adapter_id': fixed['adapter']['id'], 'name': 'follow', 'peer_host_id': b,
                'target_agent_id': reviewer['id'], 'max_message_bytes': 100, 'max_messages': 1})
            assert code == 400 and body['code'] == 'invalid', (code, body)
            listed = alice.cli('adapter', 'route', 'list', '--adapter', fixed['adapter']['id'])
            assert listed == [], listed
            routes = {r['name']: r for r in alice.cli('adapter', 'route', 'list', '--adapter', renewing['adapter']['id'])}
            assert routes['follow']['follows_credential'] is True and routes['pinned']['follows_credential'] is False

            # The first connection, within a minute of issue, does not renew.
            assert connect(alice, renewing)[0] == 200
            assert connect(alice, fixed)[0] == 200
            initial = alice.cli('adapter', 'inspect', renewing['adapter']['id'])
            assert initial['expires_at'] == renewing['adapter']['expires_at'], initial
            assert renewed(alice, renewing['adapter']['id']) == []

            # Grants default to 30 days; invites to 7 days; message deadlines to 1 hour.
            grant = bob.cli('grant', 'create', '--peer', a, '--agent', reviewer['id'], '--allow-disconnected')
            near(grant['expires_at'], 30 * DAY)
            short_grant = bob.cli('grant', 'create', '--peer', a, '--agent', reviewer['id'], '--expires-in', '90m')
            near(short_grant['expires_at'], 5400, tolerance=30)
            sent = alice.cli('message', 'send', '--peer', b, '--agent', reviewer['id'], '--grant', grant['id'],
                             '--content', 'hello')
            near(sent['request']['deadline'], 3600, tolerance=60)

            # A task refused by the receiver (its grant allows only messages).
            refused = alice.cli('task', 'submit', '--peer', b, '--agent', reviewer['id'], '--grant', grant['id'],
                                '--input', 'refused')
            task = refused['request']['task_id']
            wait_for(lambda: alice.cli('task', 'inspect', '--peer', b, task)['submit_state'] == 'rejected',
                     message='task rejection')

            # Artifacts above 90% of the quota.
            upload(alice, 'large', b'x' * (QUOTA * 9 // 10 + 1))

            # Attention without networks: exit 1 with these items, in order.
            value = alice.status()
            check_shape(value)
            assert alice.run('status').returncode == 1
            items = [(i['kind'], i['subject']) for i in attention(value)]
            assert items == [('credential_expiring', fixed['adapter']['id']), ('tasks_failed', '1'),
                             ('artifact_quota', 'artifacts')], items
            assert attention(value, 'credential_expiring')[0]['command'].startswith('peerspan session setup')
            assert attention(value, 'tasks_failed')[0]['command'] == 'peerspan task list'
            assert attention(value, 'artifact_quota')[0]['command'] == 'peerspan artifact prune'
            assert value['artifacts']['stored_bytes'] == QUOTA * 9 // 10 + 1, value['artifacts']
            names = {x['name']: x for x in value['agents']}
            assert set(names) == {'renewing', 'fixed', 'later', 'spare'}, names
            view = session_of(value, sessions['renewing']['id'])
            assert view == {'id': sessions['renewing']['id'], 'integration': 'test',
                            'adapter_id': renewing['adapter']['id'], 'connection': 'ready',
                            'expires_at': renewing['adapter']['expires_at'], 'renewable': True}, view
            assert session_of(value, sessions['later']['id'])['connection'] == 'registered'
            spare = session_of(value, sessions['spare']['id'])
            assert spare['adapter_id'] is None and spare['connection'] is None and spare['expires_at'] is None, spare
            assert spare['renewable'] is False

            # Session setup without an expiry is renewable, and routes without
            # one follow it, through recovery too; with an explicit expiry,
            # routes default to that fixed expiry.
            bundles = catalog(root / 'integrations')
            routes_file = root / 'routes.json'
            routes_file.write_text(json.dumps([
                {'name': 'follow', 'peer_host_id': b, 'target_agent_id': reviewer['id']},
                {'name': 'pinned', 'peer_host_id': b, 'target_agent_id': reviewer['id'], 'expires_at': rfc3339(7200)}]))
            for name, expiry in (('setup-renewable', ()), ('setup-fixed', ('--expires-in', '48h'))):
                registered = alice.cli('agent', 'register', '--name', name, '--owner', 'pat')
                directory = root / name
                configured = alice.cli('session', 'setup', '--directory', str(directory), '--harness', 'file-fixture',
                                       '--integrations', str(bundles), '--agent', registered['id'],
                                       '--routes', str(routes_file), *expiry)
                credential = alice.cli('adapter', 'inspect', configured['adapter_id'])
                assert credential['renewable'] is (not expiry), credential
                assert configured['expires_at'] == credential['expires_at'], (configured, credential)
                near(credential['expires_at'], DAY if not expiry else 2 * DAY)
                listed = {r['name']: r for r in alice.cli('adapter', 'route', 'list', '--adapter', credential['id'])}
                assert listed['follow']['follows_credential'] is (not expiry), listed
                assert listed['follow']['expires_at'] == credential['expires_at'], listed
                assert listed['pinned']['follows_credential'] is False, listed
                profile = json.loads((directory / 'profile.json').read_text())
                if not expiry:
                    assert 'expires_at' not in profile['request'], profile['request']
                    assert 'expires_at' not in profile['request']['routes'][0], profile['request']
                # An interrupted setup recovers its renewable credential and routes.
                profile['phase'] = 'preparing'
                (directory / 'profile.json').write_text(json.dumps(profile))
                (directory / 'credential.json').unlink()
                resumed = alice.cli('session', 'setup', '--directory', str(directory))
                assert resumed['adapter_id'] == credential['id'], resumed
                assert json.loads((directory / 'profile.json').read_text())['phase'] == 'configured'

            # One network: pat creates it on alice, and bob joins as pat's
            # second host. Commands default to that network.
            use_agent(agent)
            for host in hosts:
                host.keep_agent = True
            one = alice.cli('network', 'create', '--name', 'one', '--member', 'pat', '--coordinator', coord.address,
                            '--coordinator-key', coordinator['public_key'])['id']
            invite = alice.cli('network', 'invite', '--member', 'pat')
            assert invite['network_id'] == one
            near(invite['invite_expires_at'], 7 * DAY)
            assert bob.cli('network', 'join', '--token', invite['token'])['person']['bound']
            near(alice.cli('network', 'invite', '--member', 'pat', '--expires-in', '2h')['invite_expires_at'], 7200,
                 tolerance=30)
            near(alice.cli('network', 'invite-person', '--member', 'quinn')['invite_expires_at'], 7 * DAY)
            near(alice.cli('network', 'invite-person', '--member', 'quinn', '--expires-in', '30m')['invite_expires_at'],
                 1800, tolerance=30)
            for host in hosts:
                host.cli('network', 'sync')
            members = {m['host_id'] for m in alice.cli('network', 'members')}
            assert members == {a, b}, members
            # Host IDs only: a background sync may change updated_at between the two reads.
            assert {m['host_id'] for m in alice.cli('network', 'members', one)} == members
            pat = person_id(pat_key[2])
            assert {p['person_id'] for p in alice.cli('network', 'persons')} == {pat}
            assert isinstance(alice.cli('network', 'groups'), list)
            v1 = alice.cli('access', 'allow', '--agent', 'reviewer', '--principal', 'network')
            assert v1['network_id'] == one and v1['version'] == 1, v1
            assert alice.cli('access', 'show')['version'] == 1
            assert alice.cli('access', 'sync', '--status')['person_id'] == pat
            wait_for(lambda: bob.call('GET', f'/v1/networks/{one}/policy?person={pat}')[1].get('version') == 1,
                     message='policy push to bob')
            # Explicit-only commands still need their network.
            alice.refuse('network', 'leave')
            alice.refuse('network', 'rotate-root')
            alice.refuse('network', 'revoke', '--host', b)

            value = alice.status()
            check_shape(value)
            [network] = value['networks']
            assert network['id'] == one and network['name'] == 'one' and network['coordinator'] == coord.address
            assert network['members'] == 2 and network['person'] == {'id': pat, 'label': 'pat'}, network
            assert network['policy'] == {'version': 1, 'valid_until': v1['valid_until']}, network
            assert network['last_sync_at'] and network['last_sync_error'] is None, network

            # A sibling down: the delivery to bob fails until it returns.
            bob.stop()
            alice.cli('access', 'allow', '--agent', 'writer', '--principal', 'network')
            subject = f'{one}/{b}'

            def failing():
                v = alice.status()
                found = [i for i in attention(v, 'policy_delivery_failing') if i['subject'] == subject]
                return (v, found[0]) if found else None
            value, item = wait_for(failing, timeout=30, message='policy_delivery_failing')
            check_shape(value)
            assert item['command'] == f'peerspan access sync --network {one}', item
            assert value['networks'][0]['policy_deliveries_pending'] >= 1, value['networks']
            bob.start()
            alice.cli('access', 'sync')
            wait_for(lambda: not attention(alice.status(), 'policy_delivery_failing'), timeout=30,
                     message='delivery to the returned sibling')
            assert alice.status()['networks'][0]['policy_deliveries_pending'] == 0

            # A policy near its end, which the daemon cannot renew without an ssh-agent.
            current = alice.cli('access', 'show')
            now = datetime.now(timezone.utc)
            ending = crafted(current, current['version'] + 1, now - timedelta(hours=20), now + timedelta(hours=4),
                             pat_key[0], root)
            code, body = alice.call('POST', f'/v1/networks/{one}/policy', {'policy': ending})
            assert code == 201, (code, body)
            value = alice.status()
            check_shape(value)
            [item] = attention(value, 'policy_expiring')
            assert item['subject'] == one and item['command'] == f'peerspan access renew --network {one}', item
            assert value['networks'][0]['policy'] == {'version': ending['version'], 'valid_until': ending['valid_until']}
            assert not attention(value, 'policy_expired')

            # A second network: nothing is guessed.
            two = alice.cli('network', 'create', '--name', 'two', '--member', 'pat', '--no-person', '--coordinator',
                            coord.address, '--coordinator-key', coordinator['public_key'])['id']
            for args in (('network', 'members'), ('network', 'sync'), ('access', 'show'),
                         ('network', 'invite', '--member', 'x')):
                alice.refuse(*args, contains=(one, two, 'one', 'two'))
            assert {m['host_id'] for m in alice.cli('network', 'members', two)} == {a}
            value = alice.status()
            assert [n['id'] for n in value['networks']] == sorted([one, two])
            unbound = next(n for n in value['networks'] if n['id'] == two)
            assert unbound['person'] is None and unbound['policy'] is None and unbound['members'] == 1, unbound

            # The coordinator stopped: both networks report a coordination error.
            coord.stop()

            def errors():
                v = alice.status()
                found = attention(v, 'coordination_error')
                return (v, found) if len(found) == 2 else None
            value, found = wait_for(errors, timeout=30, message='coordination errors')
            check_shape(value)
            assert [i['subject'] for i in found] == sorted([one, two]), found
            for i in found:
                assert i['command'] == f"peerspan network sync {i['subject']}", i
            assert alice.run('status').returncode == 1

            # Renewal, once more than 60 seconds have passed since issue.
            remaining = 62 - (time.monotonic() - issued)
            if remaining > 0:
                time.sleep(remaining)
            assert connect(alice, renewing)[0] == 200
            assert connect(alice, fixed)[0] == 200
            moved = alice.cli('adapter', 'inspect', renewing['adapter']['id'])
            gained = (parse_time(moved['expires_at']) - parse_time(initial['expires_at'])).total_seconds()
            assert gained >= 60, (initial, moved)
            near(moved['expires_at'], DAY, tolerance=30)
            assert moved['renewable'] is True
            routes = {r['name']: r for r in alice.cli('adapter', 'route', 'list', '--adapter', renewing['adapter']['id'])}
            assert routes['follow']['expires_at'] == moved['expires_at'], routes
            assert routes['pinned']['expires_at'] == pinned['expires_at'], routes
            assert alice.cli('adapter', 'inspect', fixed['adapter']['id'])['expires_at'] == fixed['adapter']['expires_at']
            assert len(renewed(alice, renewing['adapter']['id'])) == 1
            assert connect(alice, renewing)[0] == 200
            assert len(renewed(alice, renewing['adapter']['id'])) == 1
            assert renewed(alice, fixed['adapter']['id']) == []
            assert session_of(alice.status(), sessions['renewing']['id'])['expires_at'] == moved['expires_at']
        finally:
            if saved_sock is None:
                os.environ.pop('SSH_AUTH_SOCK', None)
            else:
                os.environ['SSH_AUTH_SOCK'] = saved_sock
            try:
                stop_all(hosts)
            finally:
                coord.stop()
                coord.logs.close()
                agent.stop()
    print(f'PASS {label}: name and help, network defaulting, expiry defaults and --expires-in, renewable '
          'credentials and following routes, status shape, attention kinds, and exit codes', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, help='required unless every --pairing is Go/Go')
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--pairing', action='append',
                        help='CLI/daemon implementations, such as Go/Rust; repeatable; default all four')
    args = parser.parse_args()
    set_probe(args.probe)
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve() if args.rust else None}
    pairings = args.pairing or [f'{c}/{d}' for c in binaries for d in binaries]
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        if cli not in binaries or daemon not in binaries:
            parser.error(f'unknown pairing {pairing}')
        if binaries[cli] is None or binaries[daemon] is None:
            parser.error(f'pairing {pairing} needs --rust')
        check(args.coord.resolve(), binaries[cli], binaries[daemon], f'{cli} CLI, {daemon} daemon')


if __name__ == '__main__':
    main()
