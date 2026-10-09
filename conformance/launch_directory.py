#!/usr/bin/env python3
"""Exercise the agent directory and addressing (milestone 7 slice 4) across CLI/daemon pairings.

Written from docs/launch-contract.md ("Slice 4: directory and addressing") and the
contracts it builds on, independently of both implementations. Runs every Go/Rust
CLI and daemon pairing (all hosts of a pairing run that pairing's daemon and are
driven by its CLI), with one Go coordinator per pairing, real ssh-agents, the
peer probe for the peer route, and the real Node MCP adapter. Each pairing
reports these sections separately:

- root help: the new command set, and the moved commands listed in `help advanced`
  (that they still run is checked where they are used);
- peer route: listings through self access, a person rule, a `*` rule, a group
  rule, `everyone`, an `agent:` principal (`from_agent`), and grants; agents with
  no authorization unlisted, and `[]`; blocks hiding policy and grant entries but
  not self; `connected` before and after an adapter connects; 403 for a host that
  is not a member, 404 for an unknown network;
- discovery: the `GET /v1/directory` shape and refresh, a new agent appearing
  after `agents --refresh`, a policy change reflected within 10 seconds without a
  refresh, and a stopped host keeping its agents with `state: error`;
- addresses: both forms, case-folded labels, `unknown`, `ambiguous` (a duplicate
  injected with `agent register` on two hosts of one person), `local`, and a host
  without a person addressed by host ID;
- sending: `send` and `task` by address under self, policy, and grant with the
  authorization each cites, `--grant` overriding the choice, `from_agent` rules,
  `not_authorized` persisting nothing, and the moved `message send`/`task submit`;
- agents and status: `agents --json` fields, and status item 12 for the injected
  duplicate;
- attach: default naming and each suffix rule across two hosts of one person,
  `--name` taken refused with no registration, an unprofiled agent reused by
  `--name`, re-attach with `reused: true` and after revocation, `unchecked_hosts`
  with a sibling stopped, and `session start`/`doctor` without `--directory`;
- directory sessions: MCP `list_agents`, `send` and `delegate_task` by `to`
  through the real adapter, `send_status` reporting `to`; `no_directory` for
  sessions from `session setup` and `adapter create`; the rate cap with retries and
  route sends not counted; the adapter deadlines; setup validation;
- attach after expiry: a new credential for the same agent;
- retry after a label change: an uncertain send by address whose target host is
  then unbound from its person, retried automatically to the stored target.

Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen), capsule-peer-probe, and Node for
the MCP cases. Exits non-zero listing every failed section. Each host has its own
HOME and XDG_CONFIG_HOME, so nothing touches the real ~/.config/capsule.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback

from agent_adapter import Channel, adapter_call, sql
from coordination import Coordinator, wait_for
from host_service import UnixHTTPConnection, stop_all
from launch_onboarding import DEFAULT, Failure, OnboardHost, near, need, parse_time
from peer_messaging import fixture_context, request_id, set_probe, timestamp, wire
from persons import Agent, person_id, ssh_key
from tasks import task_id, tool

ROOT_COMMANDS = [
    'status', 'install', 'run',
    'network create', 'join', 'invite',
    'attach', 'agents', 'send', 'task',
    'allow', 'deny', 'block', 'unblock',
    'network list', 'network members',
    'access show',
    'session start', 'session doctor',
]
MOVED_COMMANDS = ['session setup', 'message send', 'task submit']
SELF_ACTIONS = {'message.append', 'task.submit', 'task.delegate'}
DEFAULT_ACTIONS = ['message.append', 'task.submit']
GIB = 1073741824
SELF_KEYS = {'kind', 'actions', 'max_message_bytes', 'max_artifact_bytes'}
POLICY_KEYS = {'kind', 'actions', 'max_message_bytes', 'max_artifact_bytes', 'from_agent'}
GRANT_KEYS = {'kind', 'grant_id', 'actions', 'max_message_bytes', 'max_artifact_bytes', 'expires_at', 'from_agent'}
LISTING_KEYS = {'name', 'agent_id', 'connected', 'authorizations'}
DIRECTORY_KEYS = {'network_id', 'refreshed_at', 'hosts', 'agents'}
DIRECTORY_HOST_KEYS = {'host_id', 'person_id', 'person_label', 'state', 'refreshed_at', 'error'}
DIRECTORY_AGENT_KEYS = {'address', 'host_id', 'person_id', 'person_label', 'name', 'agent_id', 'connected',
                        'authorizations'}
AGENTS_KEYS = {'network_id', 'refreshed_at', 'reachable', 'mine', 'inbound', 'hosts'}
REACHABLE_KEYS = {'address', 'host_id', 'agent_id', 'connected', 'host_state', 'actions'}
MINE_KEYS = {'address', 'host_id', 'agent_id', 'connected'}
INBOUND_KEYS = {'agent', 'principals', 'actions', 'max_artifact_bytes'}
ADAPTER_AGENT_KEYS = {'address', 'network_id', 'connected', 'actions', 'max_message_bytes', 'max_artifact_bytes'}
ATTACH_KEYS = {'agent', 'session_id', 'adapter_id', 'profile', 'workspace', 'reused', 'unchecked_hosts', 'next'}
ADDRESSABLE = re.compile(r'[a-z0-9][a-z0-9._-]{0,63}')
SHORT_HOST = re.sub(r'[^a-z0-9._-]', '-', socket.gethostname().split('.')[0].lower())
NOT_ADDRESSABLE = 'Not Addressable'


def sanitized(text):
    """A suffix as the contract makes it: lowercased, other characters as `-`."""
    return re.sub(r'[^a-z0-9._-]', '-', text.lower())


def by_name(listing):
    return {entry['name']: entry for entry in listing}


def kinds(entry):
    """Entry kinds in served order: self, then policy entries in rule order, then grants by grant ID."""
    return [a['kind'] for a in entry['authorizations']]


def canonical(authorizations):
    return sorted(json.dumps(a, sort_keys=True) for a in authorizations)


def directory_order(a):
    """Directory agent order: by address, then host ID; null addresses last, by host ID, then agent ID."""
    if a['address'] is None:
        return (1, '', a['host_id'], a['agent_id'])
    return (0, a['address'], a['host_id'], '')


def mentions(value, text):
    return text in json.dumps(value)


class DirectoryHost(OnboardHost):
    """An onboarding host whose CLI may run in a chosen directory with a longer timeout."""

    def run(self, *args, sock=DEFAULT, env=None, argv=None, cwd=None, timeout=90):
        e = dict(os.environ)
        e.pop('SSH_AUTH_SOCK', None)
        chosen = self.sock if sock is DEFAULT else sock
        if chosen:
            e['SSH_AUTH_SOCK'] = chosen
        e['USER'] = e['LOGNAME'] = 'not-the-login-name'
        e.update(self.private_env())
        e.update(env or {})
        command = argv or [self.cli_binary, '--state', str(self.state), *args]
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=e, cwd=cwd)

    def cli(self, *args, success=True, sock=DEFAULT, cwd=None):
        result = self.run(*args, sock=sock, cwd=cwd)
        assert (result.returncode == 0) == success, (self.cli_binary, args, result.returncode, result.stdout[-800:],
                                                     result.stderr[-800:])
        return json.loads(result.stdout) if success else result.stderr

    def call(self, method, path, body=None, raw=None):
        """As Host.call, but a body that is not JSON (such as a router's plain 404) comes back as text."""
        connection = UnixHTTPConnection(self.state / 'admin.sock', timeout=30)
        try:
            payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
            if isinstance(payload, str):
                payload = payload.encode()
            connection.request(method, path, payload, {'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = response.read()
            try:
                return response.status, json.loads(data)
            except json.JSONDecodeError:
                return response.status, data.decode(errors='replace')
        finally:
            connection.close()

    def directory(self, network=None, refresh=False):
        query = f'?network={network}' if network else ''
        if refresh:
            return self.call('POST', '/v1/directory/refresh' + query, {})
        return self.call('GET', '/v1/directory' + query)


class Pairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, node, root):
        self.label, self.cli_binary, self.daemon, self.node, self.root = label, cli_binary, daemon_binary, node, root
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results = []
        self.hosts = {}
        self.agents = {}
        self.keys = {}
        self.channels = []
        self.script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'

    # --- infrastructure -----------------------------------------------------------------------------------

    def host(self, name):
        h = DirectoryHost(self.daemon, self.cli_binary, self.root / name, self.root / f'user-{name}')
        self.hosts[name] = h
        return h

    def section(self, name, function):
        started = time.monotonic()
        self.soft = []
        try:
            notes = function() or ''
            need(not self.soft, 'shapes', *sorted(set(self.soft)))
        except Exception as error:  # report and continue with the next section
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=4)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}',
              flush=True)
        return True

    def coordinator_flags(self):
        return ('--coordinator', self.coord.address, '--coordinator-key', self.coord_key)

    def listing(self, receiver, caller, network=None):
        status, body = wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'GET',
                            f'/peer/v1/networks/{network or self.net}/agents')
        return status, body

    def listed(self, receiver, caller, rule):
        status, body = self.listing(receiver, caller)
        need(status == 200 and isinstance(body, list), f'{rule}: 200 with an array', status, body)
        for entry in body:
            need(LISTING_KEYS <= set(entry), 'Peer route: entries are {name, agent_id, connected, authorizations}',
                 entry)
            if set(entry) != LISTING_KEYS:
                self.soft.append(f'Peer route: entry keys {sorted(entry)}')
            for a in entry['authorizations']:
                expected = {'self': SELF_KEYS, 'policy': POLICY_KEYS, 'grant': GRANT_KEYS}.get(a.get('kind'))
                need(expected is not None and expected <= set(a), 'Peer route: authorization shapes', a)
                # Extra fields are reported at the end of the section, so the remaining cases still run.
                if set(a) != expected:
                    self.soft.append(f"Peer route: shapes are exact: {a['kind']} entry is {sorted(expected)}, "
                                     f"got {sorted(a)}")
            order = [{'self': 0, 'policy': 1, 'grant': 2}.get(a['kind'], 3) for a in entry['authorizations']]
            grants = [a['grant_id'] for a in entry['authorizations'] if a['kind'] == 'grant']
            need(order == sorted(order) and grants == sorted(grants),
                 'Peer route: entries are ordered self, then policy entries, then grants by grant ID', entry)
        need([(e['name'], e['agent_id']) for e in body] == sorted((e['name'], e['agent_id']) for e in body),
             'Peer route: sorted by name, then ID', [e['name'] for e in body])
        need(all(e['authorizations'] for e in body), 'Peer route: an agent with no authorizations is never listed',
             body)
        return by_name(body)

    def policy_version(self, host, person=None):
        status, body = host.call('GET', f'/v1/networks/{self.net}/policy?person={person or self.pat}')
        return body['version'] if status == 200 else 0

    def synced(self, version, *hosts, person=None):
        for h in hosts:
            wait_for(lambda: self.policy_version(h, person) >= version, timeout=40,
                     message=f'policy version {version} on {h.state.name}')

    def allow(self, *args):
        out = self.p1.cli('allow', *args, '--network', self.net)
        return out['policy']['version']

    def refresh(self, host, network=None):
        status, body = host.directory(network or self.net, refresh=True)
        need(status == 200, 'POST /v1/directory/refresh returns 200 with the directory', status, body)
        return body

    def outbound(self, host, peer, rid):
        status, body = host.call('GET', f'/v1/outbound/{peer}/{rid}')
        return body if status == 200 else None

    def settle_message(self, host, peer, record, timeout=40):
        if record.get('state') != 'unknown':
            return record
        rid = record['request']['request_id']

        def done():
            r = self.outbound(host, peer, rid)
            return r if r and r['state'] != 'unknown' else None
        return wait_for(done, timeout=timeout, message='message outcome')

    def settle_task(self, host, record, timeout=40):
        if record.get('submit_state') != 'unknown':
            return record
        peer, tid = record['peer_host_id'], record['request']['task_id']

        def done():
            status, r = host.call('GET', f'/v1/tasks/{peer}/{tid}')
            return r if status == 200 and r['submit_state'] != 'unknown' else None
        return wait_for(done, timeout=timeout, message='task outcome')

    def received(self, host, rid):
        """Whether a host has received the message with this request ID."""
        return any(m['request']['request_id'] == rid for m in host.cli('message', 'list', '--limit', '1000'))

    def send(self, host, target, text, *extra, peer):
        out = host.cli('send', target, text, *extra)
        need(isinstance(out, dict) and 'request' in out, 'send prints the outbound record', out)
        out = self.settle_message(host, peer, out)
        return out

    def task(self, host, target, text, *extra):
        out = host.cli('task', target, text, *extra)
        need(isinstance(out, dict) and 'request' in out and 'submit_state' in out,
             'task prints the local task record', out)
        return self.settle_task(host, out)

    def counts(self, host):
        return (sql(host, 'SELECT COUNT(*) FROM outbound_messages')[0][0],
                sql(host, 'SELECT COUNT(*) FROM outbound_tasks')[0][0])

    def attach(self, host, *args, success=True, cwd=None):
        return host.cli('attach', *args, '--integrations', str(self.catalog), success=success, cwd=cwd)

    def profile_secret(self, out):
        path = Path(out['profile']) / 'credential.json'
        need(path.exists(), 'attach writes the profile with its credential', path)
        return json.loads(path.read_text())

    # --- sections ------------------------------------------------------------------------------------------

    def check_help(self):
        def help_of(*args):
            r = subprocess.run([self.cli_binary, *args], capture_output=True, text=True, timeout=10)
            need(r.returncode == 0, 'help exits 0', args, r.stderr)
            return r.stdout

        def commands(text):
            lines = text.splitlines()
            need('Commands:' in lines, 'help has a Commands: header (slice 1)', text)
            paths = []
            for line in lines[lines.index('Commands:') + 1:]:
                if not line.strip():
                    break
                paths.append(re.split(r' {2,}', line.strip())[0])
            return paths
        root = commands(help_of('--help'))
        need(root == ROOT_COMMANDS, 'Root help now lists, in order: status, install, run, network create, join, '
             'invite, attach, agents, send, task, allow, deny, block, unblock, network list, network members, '
             'access show, session start, session doctor', root)
        advanced = commands(help_of('help', 'advanced'))
        missing = [c for c in ROOT_COMMANDS + MOVED_COMMANDS if c not in advanced]
        need(not missing, 'session setup, message send, and task submit move to help advanced, unchanged', missing)
        for path in MOVED_COMMANDS + ['attach', 'agents', 'send', 'task']:
            need('--' in help_of(*path.split(), '--help'), 'each command keeps its own --help', path)

    def check_peer_route(self):
        rule = 'Peer route'
        ids, agent = self.ids, self.agent
        # Captured during setup, before any policy or grant existed.
        need(self.before == {'c1': (200, []), 'b1': (200, [])},
             f'{rule}: a caller with no authorizations receives []', self.before)

        def policy_entry(entry, actions=DEFAULT_ACTIONS, from_agent=None):
            need(kinds(entry) == ['policy'], f'{rule}: exactly one policy entry for {entry["name"]}', entry)
            [a] = entry['authorizations']
            need(sorted(a['actions']) == sorted(actions) and a['max_message_bytes'] == 65536
                 and a['max_artifact_bytes'] == 0 and a['from_agent'] == from_agent,
                 f'{rule}: the policy entry carries the rule\'s settings ({entry["name"]})', a, actions, from_agent)

        # Carol: a person rule, a group rule, everyone, an agent: principal, and grants.
        carol = self.listed('p1', 'c1', rule)
        expected = ['alpha', 'beta', 'delta', 'eps', 'gamma', 'notask']
        need(sorted(carol) == expected, f'{rule}: carol sees exactly the agents she is authorized for; '
             'agents with no authorization are unlisted', sorted(carol))
        for name in ('alpha', 'beta', 'gamma'):
            policy_entry(carol[name])
            need(carol[name]['agent_id'] == agent[name]['id'], f'{rule}: agent_id', carol[name])
        policy_entry(carol['notask'], ['message.append'])
        policy_entry(carol['delta'], from_agent=agent['corig']['id'])
        eps = carol['eps']
        need(kinds(eps) == ['grant'] * 3, f'{rule}: each unexpired, unrevoked grant to the caller host is listed', eps)
        for a in eps['authorizations']:
            g = self.grants[a['grant_id']]
            need(a['actions'] == [g['action']] and a['max_message_bytes'] == g['max_message_bytes']
                 and a['max_artifact_bytes'] == g.get('max_artifact_bytes', 0)
                 and parse_time(a['expires_at']) == parse_time(g['expires_at']) and a['from_agent'] is None,
                 f'{rule}: a grant entry carries the grant\'s action, bounds, expiry, and from_agent (its requester '
                 'agent, here none)', a, g)
        need(not any(e['connected'] for e in carol.values()), f'{rule}: connected false without a session', carol)

        # Bob: a `*` rule reaches only agents without named rules (gamma's named rule is everyone's, so bob, a
        # member, has it too); names as registered.
        bob = self.listed('p1', 'b1', rule)
        need(sorted(bob) == sorted([NOT_ADDRESSABLE, 'eps', 'gamma', 'omega']),
             f'{rule}: a * rule applies to agents without named rules', sorted(bob))
        for entry in bob.values():
            policy_entry(entry)

        # n1, without a person: everyone, and a grant.
        nobody = self.listed('p1', 'n1', rule)
        need(sorted(nobody) == ['gamma', 'omega'] and kinds(nobody['gamma']) == ['policy']
             and kinds(nobody['omega']) == ['grant'], f'{rule}: everyone and a grant for a host without a person',
             nobody)

        # p2: self access on every agent, with the self bounds.
        sibling = self.listed('p1', 'p2', rule)
        need(sorted(sibling) == sorted(self.p1_agents), f'{rule}: self access lists every agent', sorted(sibling))
        for entry in sibling.values():
            selfs = [a for a in entry['authorizations'] if a['kind'] == 'self']
            need(len(selfs) == 1 and set(selfs[0]['actions']) == SELF_ACTIONS
                 and selfs[0]['max_message_bytes'] == 65536 and selfs[0]['max_artifact_bytes'] == GIB,
                 f'{rule}: the self entry allows every action with its bounds', entry)
        need(kinds(sibling['gamma']) == ['self', 'policy'], f'{rule}: everyone also covers a sibling host',
             sibling['gamma'])

        # Blocks hide policy and grant entries, not self.
        for target, caller in ((ids['c1'], 'c1'), ('carol', 'c1'), (ids['n1'], 'n1')):
            self.p1.cli('block', target)
            try:
                status, body = self.listing('p1', caller)
                need((status, body) == (200, []), f'{rule}: blocks hide policy and grant entries (block {target})',
                     status, body)
            finally:
                self.p1.cli('unblock', target)
        self.p1.cli('block', ids['p2'])
        try:
            blocked = self.listed('p1', 'p2', rule)
            need(sorted(blocked) == sorted(self.p1_agents) and all(kinds(e) == ['self'] for e in blocked.values()),
                 f'{rule}: blocks apply to policies, not to self access', blocked)
        finally:
            self.p1.cli('unblock', ids['p2'])
        need(sorted(self.listed('p1', 'c1', rule)) == expected, f'{rule}: unblocking restores the listing')

        # connected: before and after an adapter connects.
        session = self.p1.cli('session', 'attach', '--agent', agent['omega']['id'], '--integration', 'test')
        secret = self.p1.cli('adapter', 'create', '--session', session['id'], '--expires-at', timestamp(1800))
        need(self.listed('p1', 'p2', rule)['omega']['connected'] is False,
             f'{rule}: connected false before the adapter connects')
        status, _ = adapter_call(self.p1, secret['token'], 'GET', '/adapter/v1/session')
        need(status == 200, 'adapter connects', status)
        need(self.listed('p1', 'p2', rule)['omega']['connected'] is True,
             f'{rule}: connected true when an attached session\'s adapter holds a valid lease')

        # 403 for a caller that is not a member of the network; 404 for an unknown network.
        status, body = self.listing('p1', 'x')
        need(status == 403, f'{rule}: a caller that is not a current member of that network gets 403', status, body)
        status, body = self.listing('p1', 'x', self.other)
        need((status, body) == (200, []), f'{rule}: the same caller is served in its own network', status, body)
        status, body = self.listing('p1', 'c1', 'net_' + secrets.token_hex(16))
        need(status == 404, f'{rule}: a network the receiver does not belong to returns 404', status, body)

    def check_discovery(self):
        c1, p2 = self.hosts['c1'], self.hosts['p2']
        ids = self.ids
        directory = self.refresh(c1)
        need(set(directory) == DIRECTORY_KEYS and directory['network_id'] == self.net
             and directory['refreshed_at'], 'Discovery: {network_id, refreshed_at, hosts, agents}', directory)
        hosts = directory['hosts']
        need(all(set(h) == DIRECTORY_HOST_KEYS for h in hosts), 'Discovery: host entries', hosts)
        need([h['host_id'] for h in hosts] == sorted(h['host_id'] for h in hosts), 'hosts are sorted by host ID', hosts)
        others = sorted(ids[n] for n in self.members if n != 'c1')
        need(sorted(h['host_id'] for h in hosts) == others,
             'Hosts queried: every current, unrevoked member other than itself', hosts, others)
        need(all(h['state'] == 'ok' and h['refreshed_at'] and h['error'] is None for h in hosts),
             'Discovery: every running host answered (state ok)', hosts)
        host = {h['host_id']: h for h in hosts}
        need(host[ids['p1']]['person_id'] == self.pat and host[ids['p1']]['person_label'] == 'pat'
             and host[ids['n1']]['person_id'] is None and host[ids['n1']]['person_label'] is None,
             'Discovery: hosts show their bound person, or null', host)
        agents = directory['agents']
        need(all(set(a) == DIRECTORY_AGENT_KEYS for a in agents), 'Discovery: agent entries', agents)
        need(agents == sorted(agents, key=directory_order),
             'agents are sorted by address, then host ID, with null addresses last', agents)
        entries = {a['address']: a for a in agents}
        alpha = entries.get('pat/alpha')
        need(alpha and alpha['host_id'] == ids['p1'] and alpha['person_id'] == self.pat
             and alpha['person_label'] == 'pat' and alpha['name'] == 'alpha'
             and alpha['agent_id'] == self.agent['alpha']['id'], 'Discovery: address PERSON/AGENT', entries)
        served = self.listed('p1', 'c1', 'Peer route')
        for name in served:
            entry = entries.get(f'pat/{name}')
            need(entry and entry['authorizations'] == served[name]['authorizations'],
                 'Discovery: authorizations as served by the peer', name, entry, served[name])
        nag = entries.get(f"{ids['n1']}/nagent")
        need(nag and nag['person_id'] is None and nag['person_label'] is None,
             'address is HOST_ID/AGENT when the host has no bound person', entries)
        need(not any(a['host_id'] == ids['c1'] for a in agents), 'the directory holds other hosts only', agents)

        # The bound person's own view: names that are not addressable have a null address.
        status, mirror = self.hosts['b1'].directory(self.net, refresh=True)
        odd = [a for a in mirror.get('agents', []) if a['name'] == NOT_ADDRESSABLE]
        need(status == 200 and len(odd) == 1 and odd[0]['address'] is None,
             'address is null for names that are not addressable (as registered in the peer response)', mirror)
        need(mirror['agents'] == sorted(mirror['agents'], key=directory_order) and mirror['agents'][-1] is odd[0],
             'null addresses sort last', [a['address'] for a in mirror['agents']])

        # Network defaulting on the API: c1 has one network; p1 has two.
        status, single = c1.directory()
        need(status == 200 and single.get('network_id') == self.net,
             'GET /v1/directory defaults to the only network', status, single)
        status, several = self.p1.directory()
        need(status == 400 and mentions(several, self.net) and mentions(several, self.other),
             'GET /v1/directory without network on a host in several networks is 400, listing them', status, several)
        status, unknown = c1.directory('net_' + secrets.token_hex(32))
        need(status == 404, 'GET /v1/directory for an unknown network is 404', status, unknown)

        self.agent['fresh'] = self.p1.cli('agent', 'register', '--name', 'fresh', '--owner', 'pat')
        # A policy change is reflected within 10 seconds, without a refresh.
        version = self.allow('carol', '--agent', 'fresh')
        started = time.monotonic()
        stored = seen = None
        while time.monotonic() - started < 60 and seen is None:
            if stored is None and self.policy_version(c1) >= version:
                stored = time.monotonic()
            status, view = c1.directory(self.net)
            if status == 200 and any(a['address'] == 'pat/fresh' and a['authorizations'] for a in view['agents']):
                seen = time.monotonic()
            time.sleep(0.2)
        need(seen is not None, 'Discovery: a policy change is reflected without a refresh')
        stored = stored or seen
        need(seen - stored <= 12, 'Discovery: within 10 seconds of a change to any stored policy',
             f'stored after {stored - started:.1f}s, reflected after {seen - started:.1f}s')
        notes = f'policy reflected {seen - stored:.1f}s after it was stored'

        # A stopped host keeps its previous agents, with state error.
        before = {h['host_id']: h for h in self.refresh(c1)['hosts']}[ids['n1']]
        need(before['state'] == 'ok', 'n1 answered before it stopped', before)
        n1 = self.hosts['n1']
        n1.stop()
        stopped_at = time.time()
        try:
            after = self.refresh(c1)
            entry = {h['host_id']: h for h in after['hosts']}[ids['n1']]
            need(entry['state'] == 'error' and isinstance(entry['error'], str) and entry['error'],
                 'Failures: a host that fails is marked with the error (state error)', entry)
            need(entry['refreshed_at'] and parse_time(entry['refreshed_at']).timestamp() <= stopped_at + 1
                 and parse_time(entry['refreshed_at']) >= parse_time(before['refreshed_at']),
                 'Failures: marked with the time of the last success', entry, before)
            need(any(a['address'] == f"{ids['n1']}/nagent" for a in after['agents']),
                 'Failures: a host that fails keeps its previous agents', after['agents'])
        finally:
            n1.start()

        # A new agent appears after `agents --refresh`.
        self.agent['later'] = self.p1.cli('agent', 'register', '--name', 'later', '--owner', 'pat')
        out = p2.cli('agents', '--refresh', '--json', '--network', self.net)
        mine = {m['address']: m for m in out.get('mine', [])}
        reach = {r['address']: r for r in out.get('reachable', [])}
        need('pat/later' in mine and mine['pat/later']['agent_id'] == self.agent['later']['id']
             and mine['pat/later']['host_id'] == ids['p1'], 'Discovery: a new agent appears after --refresh (mine)',
             out.get('mine'))
        need('pat/later' in reach and SELF_ACTIONS <= set(reach['pat/later']['actions']),
             'Discovery: a new agent appears after --refresh (reachable, through self access)', out.get('reachable'))

        return notes

    def check_addresses(self):
        c1, p1, ids = self.hosts['c1'], self.p1, self.ids
        before = self.counts(c1)

        def refused(host, to, status, code, **extra):
            body = {'to': to, 'content': 'refused', 'deadline': timestamp(600), 'request_id': request_id(), **extra}
            got, value = host.call('POST', '/v1/outbound', body)
            need(got == status and isinstance(value, dict) and value.get('code') == code
                 and {'code', 'error', 'matches'} <= set(value),
                 f'Resolution failures return {status} ({code}) with {{code, error, matches}}', to, got, value)
            return value

        # On the owner API first. unknown:
        for to in ('pat/nosuch', 'nobody/alpha', f"host_{'0' * 64}/alpha"):
            value = refused(c1, to, 404, 'unknown')
            need(value['matches'] == [], 'matches is empty unless ambiguous', value)
        got, value = c1.call('POST', '/v1/tasks', {'to': 'pat/nosuch', 'input': 'x'})
        need(got == 404 and isinstance(value, dict) and value.get('code') == 'unknown',
             'POST /v1/tasks accepts to, and resolves it', got, value)

        # ambiguous: a duplicate injected with agent register on two hosts of pat.
        directory = self.refresh(c1)
        dups = {a['host_id']: a['address'] for a in directory['agents'] if a['name'] == 'dup'}
        need(dups == {ids['p1']: f"{ids['p1']}/dup", ids['p2']: f"{ids['p2']}/dup"},
             'address is HOST_ID/AGENT when the name is duplicated within that person', dups)
        value = refused(c1, 'pat/dup', 409, 'ambiguous')
        want = sorted([{'address': f"{ids[h]}/dup", 'network_id': self.net} for h in ('p1', 'p2')],
                      key=lambda m: (m['network_id'], m['address']))
        need(value['matches'] == want, 'ambiguous: matches lists {address, network_id} objects, sorted by network ID, '
             'then address', value, want)

        # local
        for to in ('pat/alpha', f"{ids['p1']}/alpha"):
            refused(p1, to, 400, 'local', network=self.net)

        # Both forms at once.
        got, value = c1.call('POST', '/v1/outbound', {'to': 'pat/alpha', 'peer_host_id': ids['p1'],
                                                      'target_agent_id': self.agent['alpha']['id'],
                                                      'content': 'both', 'deadline': timestamp(600)})
        need(got == 400, 'POST /v1/outbound: giving both forms is 400', got, value)
        got, value = c1.call('POST', '/v1/tasks', {'to': 'pat/alpha', 'peer_host_id': ids['p1'],
                                                   'target_agent_id': self.agent['alpha']['id'], 'input': 'both'})
        need(got == 400, 'POST /v1/tasks: giving both forms is 400', got, value)
        need(self.counts(c1) == before, 'The daemon resolves the address before persisting anything',
             before, self.counts(c1))

        # An accepted send on the API, with network.
        rid = request_id()
        got, out = c1.call('POST', '/v1/outbound', {'to': 'pat/alpha', 'network': self.net, 'content': 'api',
                                                    'deadline': timestamp(600), 'request_id': rid})
        need(got == 200, 'POST /v1/outbound accepts to with optional network', got, out)
        out = self.settle_message(c1, ids['p1'], out)
        need(out['state'] == 'accepted' and out['request']['target_agent_id'] == self.agent['alpha']['id']
             and self.received(p1, rid), 'Addresses: PERSON/AGENT reaches that agent (API)', out)
        need(out.get('to') == 'pat/alpha', 'Persistence: the record shows to as given', out)

        # The CLI: both forms, and a case-folded label.
        out = self.send(c1, 'pat/alpha', 'by label', peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request']['target_agent_id'] == self.agent['alpha']['id']
             and self.received(p1, out['request']['request_id']), 'Addresses: PERSON/AGENT (send)', out)
        need(out.get('to') == 'pat/alpha', 'Persistence: the record shows to as given (send)', out)
        out = self.send(c1, f"{ids['p1']}/alpha", 'by host', peer=ids['p1'])
        need(out['state'] == 'accepted' and self.received(p1, out['request']['request_id'])
             and out['request']['target_agent_id'] == self.agent['alpha']['id'], 'Addresses: HOST_ID/AGENT', out)
        for label in ('PAT', 'Pat'):
            out = self.send(c1, f'{label}/alpha', 'folded', peer=ids['p1'])
            need(out['state'] == 'accepted' and self.received(p1, out['request']['request_id'])
                 and out.get('to') == f'{label}/alpha',
                 'Addresses: person labels compared with ASCII case folded; to shown as given', out)
        result = c1.run('send', 'pat/nosuch', 'nothing')
        need(result.returncode != 0, 'send to an unknown address fails', result.stdout)
        result = c1.run('send', 'pat/dup', 'which one')
        need(result.returncode != 0 and all(f"{ids[h]}/dup" in result.stderr for h in ('p1', 'p2'))
             and self.net in result.stderr, 'ambiguous: the error lists each match as HOST_ID/AGENT with its network',
             result.stderr)
        out = self.send(c1, f"{ids['p1']}/dup", 'picked', peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request']['target_agent_id'] == self.agent['dup1']['id'],
             'HOST_ID/AGENT picks one agent of a duplicate pair', out)
        need(p1.run('send', 'pat/alpha', 'to myself', '--network', self.net).returncode != 0,
             'send to a local agent fails')

        # A host without a person, by host ID; with --network.
        out = self.send(c1, f"{ids['n1']}/nagent", 'no person', '--network', self.net, peer=ids['n1'])
        need(out['state'] == 'accepted' and out['request'].get('grant_id') == self.n1_grant['id']
             and self.received(self.hosts['n1'], out['request']['request_id']),
             'Addresses: a host without a bound person, addressed by host ID', out)
        # Refused sends persisted nothing: the seven accepted sends were all that was stored.
        after = self.counts(c1)
        need(after == (before[0] + 7, before[1]), 'The daemon resolves the address before persisting anything',
             before, after)

    def check_sending(self):
        c1, p1, p2, ids = self.hosts['c1'], self.p1, self.hosts['p2'], self.ids
        cite = {'person_id': self.pat}

        # not_authorized, persisting nothing.
        before = self.counts(c1)
        status, value = c1.call('POST', '/v1/tasks', {'to': 'pat/notask', 'input': 'not allowed'})
        need(status == 403 and isinstance(value, dict) and value.get('code') == 'not_authorized',
             'When none allows the action: 403 not_authorized (task to a message-only rule)', status, value)
        status, value = c1.call('POST', '/v1/outbound', {'to': 'pat/delta', 'content': 'not from corig',
                                                         'deadline': timestamp(600), 'request_id': request_id()})
        need(status == 403 and isinstance(value, dict) and value.get('code') == 'not_authorized',
             'When none allows the action: 403 (a from_agent entry for another agent)', status, value)
        need(self.counts(c1) == before, 'not_authorized persists nothing', before, self.counts(c1))

        # Self.
        out = self.send(p2, 'pat/alpha', 'from a sibling', '--network', self.net, peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request'].get('self') == cite
             and out['request'].get('grant_id') is None and out['request'].get('policy') is None,
             'Choosing an authorization: self access first, cited as self (send)', out)
        path = self.root / 'input.txt'
        path.write_bytes(b'directory input ' * 32)
        t = self.task(p2, 'pat/alpha', 'self task', '--network', self.net, '--file', str(path))
        need(t['submit_state'] == 'accepted' and t['request'].get('self') == cite and t['peer_host_id'] == ids['p1']
             and t['request']['target_agent_id'] == self.agent['alpha']['id'],
             'Choosing an authorization: self (task)', t)
        need(len(t['request'].get('artifacts') or []) == 1, 'task --file is --artifact', t['request'])
        need(t.get('to') == 'pat/alpha', 'Persistence: the task record shows to as given', t)

        # Policy.
        out = self.send(c1, 'pat/alpha', 'by policy', peer=ids['p1'])
        need(out['state'] == 'accepted' and (out['request'].get('policy') or {}).get('person_id') == self.pat
             and out['request'].get('grant_id') is None and out['request'].get('self') is None,
             'Choosing an authorization: a policy entry, cited as the target owner\'s policy (send)', out)
        t = self.task(c1, 'pat/alpha', 'policy task')
        need(t['submit_state'] == 'accepted' and (t['request'].get('policy') or {}).get('person_id') == self.pat
             and t['request'].get('grant_id') is None, 'Choosing an authorization: policy (task)', t)
        # A from_agent entry applies only to requests from that agent.
        out = self.send(c1, 'pat/delta', 'from corig', '--from-agent', self.agent['corig']['id'], peer=ids['p1'])
        need(out['state'] == 'accepted' and (out['request'].get('policy') or {}).get('person_id') == self.pat,
             'a policy entry whose from_agent is the origin agent', out)

        # Grant: the one with the latest expires_at.
        out = self.send(c1, 'pat/eps', 'by grant', peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request'].get('grant_id') == self.eps_late['id'],
             'Choosing an authorization: the grant with the latest expires_at, cited by its ID (send)',
             out, self.eps_late['id'])
        t = self.task(c1, 'pat/eps', 'grant task')
        need(t['submit_state'] == 'accepted' and t['request'].get('grant_id') == self.eps_task['id'],
             'Choosing an authorization: a grant that allows task.submit (task)', t)

        # --grant overrides the choice.
        g = p1.cli('grant', 'create', '--peer', ids['c1'], '--agent', self.agent['alpha']['id'], '--expires-in', '2h',
                   '--allow-disconnected')
        out = self.send(c1, 'pat/alpha', 'explicit grant', '--grant', g['id'], peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request'].get('grant_id') == g['id']
             and out['request'].get('policy') is None, 'An explicit grant_id (owner --grant) overrides the choice', out)

        before = self.counts(c1)
        need(c1.run('task', 'pat/notask', 'not allowed').returncode != 0, 'task refused by not_authorized fails')
        need(self.counts(c1) == before, 'not_authorized persists nothing (CLI)', before, self.counts(c1))

        # The moved commands still run.
        out = c1.cli('message', 'send', '--peer', ids['p1'], '--agent', self.agent['alpha']['id'], '--content',
                     'moved command')
        out = self.settle_message(c1, ids['p1'], out)
        need(out['state'] == 'accepted', 'message send still runs', out)
        need('to' not in out, 'Records not sent by address have no to key (outbound)', {'to': out.get('to')})
        t = c1.cli('task', 'submit', '--peer', ids['p1'], '--agent', self.agent['alpha']['id'], '--input', 'moved')
        t = self.settle_task(c1, t)
        need(t['submit_state'] == 'accepted', 'task submit still runs', t)
        need('to' not in t, 'Records not sent by address have no to key (task)', {'to': t.get('to')})

    def check_agents_and_status(self):
        c1, p1, p2, ids = self.hosts['c1'], self.p1, self.hosts['p2'], self.ids
        for h in (c1, p1, p2):
            self.refresh(h)
        # Item 12, for the duplicate injected on p1 and p2.
        for h in (p1, p2):
            def conflict():
                self.refresh(h, self.net)
                status, value = h.call('GET', '/v1/status')
                items = [i for i in value.get('attention', []) if i['kind'] == 'agent_name_conflict']
                return items or None
            try:
                items = wait_for(conflict, timeout=20, message='agent_name_conflict')
            except AssertionError:
                raise Failure(f'Status item 12: agent_name_conflict on {h.state.name} for a duplicate name of this '
                              'host\'s person')
            need([i['subject'] for i in items] == [f'{self.net}/dup'], 'item 12: subject NETWORK/NAME', items)
            need('attach' in items[0]['command'] and '--name' in items[0]['command'],
                 'item 12: command capsule attach HARNESS --name NEW', items)
        status, value = c1.call('GET', '/v1/status')
        need(not [i for i in value.get('attention', []) if i['kind'] == 'agent_name_conflict'],
             'item 12 only on a host that has one of them', value.get('attention'))

        out = c1.cli('agents', '--json')
        need(set(out) == AGENTS_KEYS and out['network_id'] == self.net, 'agents --json prints {network_id, '
             'refreshed_at, reachable, mine, inbound, hosts}', out)
        need(all(set(r) == REACHABLE_KEYS for r in out['reachable']), 'reachable uses {address, host_id, agent_id, '
             'connected, host_state, actions}', out['reachable'])
        need(all(r['address'] and ADDRESSABLE.fullmatch(r['address'].split('/')[-1]) for r in out['reachable']),
             'reachable lists addressable agents', out['reachable'])
        reach = {r['address']: r for r in out['reachable']}
        alpha = reach.get('pat/alpha')
        need(alpha and alpha['host_id'] == ids['p1'] and alpha['agent_id'] == self.agent['alpha']['id']
             and alpha['host_state'] == 'ok' and set(DEFAULT_ACTIONS) <= set(alpha['actions']),
             'reachable: address, actions, connection, and whether its host answered', alpha)
        directory = c1.directory(self.net)[1]
        need([(h['host_id'], h['state']) for h in out['hosts']] == [(h['host_id'], h['state'])
                                                                     for h in directory['hosts']]
             and all(set(h) == DIRECTORY_HOST_KEYS for h in out['hosts']),
             'hosts is the directory\'s hosts', out['hosts'], directory['hosts'])
        need(all(set(m) == MINE_KEYS for m in out['mine']), 'mine uses {address, host_id, agent_id, connected}',
             out['mine'])
        need({m['agent_id'] for m in out['mine']} >= {self.agent['corig']['id']}, 'mine: this host\'s agents',
             out['mine'])
        readable = c1.run('agents')
        need(readable.returncode == 0 and 'pat/alpha' in readable.stdout, 'agents prints the reachable addresses',
             readable.stdout)

        # The person's own hosts: mine spans this host and the directory; inbound mirrors the policy.
        mine = p2.cli('agents', '--json', '--network', self.net)
        addresses = {m['address'] for m in mine['mine']}
        need({'pat/alpha', 'pat/gamma'} <= addresses and f"{ids['p2']}/dup" in addresses,
             'mine: this person\'s agents on this host and in the directory', sorted(a for a in addresses if a))
        inbound = p1.cli('agents', '--json', '--network', self.net)['inbound']
        need(all(set(i) == INBOUND_KEYS for i in inbound), 'inbound uses {agent, principals, actions, '
             'max_artifact_bytes}', inbound)
        status, policy = p1.call('GET', f'/v1/networks/{self.net}/policy?person={self.pat}')
        expected = sorted(json.dumps([r['agent'], sorted(r['principals']), sorted(r['actions']),
                                      r.get('max_artifact_bytes', 0)]) for r in policy['rules'])
        got = sorted(json.dumps([i['agent'], sorted(i['principals']), sorted(i['actions']), i['max_artifact_bytes']])
                     for i in inbound)
        need(got == expected, 'inbound: one entry per rule of the stored policy, principals in policy form',
             got, expected)

    def check_attach(self):
        a1, a2, ids = self.hosts['a1'], self.hosts['a2'], self.ids
        ws = self.root / 'ws'

        def project(*parts):
            path = ws.joinpath(*parts)
            path.mkdir(parents=True, exist_ok=True)
            return path

        def attached(out, name, host, workspace, rule):
            need(set(out) == ATTACH_KEYS, 'attach prints {agent, session_id, adapter_id, profile, workspace, reused, '
                 'unchecked_hosts, next}', out)
            need(out['agent']['name'] == name, f'{rule}: agent name {name}', out['agent'])
            need(out['agent']['address'] == f'ana/{name}', 'agent.address is PERSON/NAME', out['agent'])
            need(Path(out['workspace']) == workspace.resolve(), 'the profile records the project\'s real path',
                 out['workspace'], workspace)
            want = host.config / 'capsule' / 'sessions' / ids[host.state.name] / name
            need(Path(out['profile']).resolve() == want.resolve(),
                 'Profiles live in $XDG_CONFIG_HOME/capsule/sessions/HOST_ID/AGENT_NAME/', out['profile'], want)
            return out

        # The expiring attach first, so that its minute passes during the rest.
        expiring = project('expiring')
        out = self.attach(a1, 'file-fixture', '--name', 'expiring', '--directory', str(expiring), '--expires-in', '1m')
        self.expiring = (expiring, out)

        # 1. The base name, for `claude` meaning claude-code.
        w1 = project('app')
        out = attached(self.attach(a1, 'claude', '--directory', str(w1)), 'claude', a1, w1,
                       'Naming: the base name (claude for claude-code)')
        need(out['reused'] is False and out['unchecked_hosts'] == [], 'a fresh attach', out)
        need(mentions(out['next'], 'session start'), 'next is capsule session start for launch-capable integrations',
             out)
        registered = a1.cli('agent', 'inspect', out['agent']['id'])
        need(registered['owner'] == 'ana', 'Registering: owner is this host\'s bound person\'s label', registered)
        record = a1.cli('adapter', 'inspect', out['adapter_id'])
        need(record.get('directory') is True and record.get('max_sends_per_hour') == 100
             and record.get('renewable') is True, 'Setup: directory access, max_sends_per_hour 100, a renewable '
             'credential', record)
        session = a1.cli('session', 'inspect', out['session_id'])
        need(session['integration'] == 'claude-code' and session['agent_id'] == out['agent']['id'],
             'HARNESS claude means claude-code', session)
        self.w1 = (w1, out)

        # 2. BASE-PROJECT when the base name is used on this host, and -2 after it.
        w2 = project('proj-two')
        attached(self.attach(a1, 'claude', '--directory', str(w2)), 'claude-proj-two', a1, w2, 'Naming: BASE-PROJECT')
        w2b = project('other', 'proj-two')
        # -N goes on the last candidate that applied (settled with the owner).
        attached(self.attach(a1, 'claude', '--directory', str(w2b)), 'claude-proj-two-2', a1, w2b,
                 'Naming: then -2 appended')
        odd = project('My Proj!')
        attached(self.attach(a1, 'claude', '--directory', str(odd)), 'claude-' + sanitized('My Proj!'), a1, odd,
                 'Naming: suffixes lowercased, other characters become -')
        long = project('p' * 80)
        out = self.attach(a1, 'claude', '--directory', str(long))
        need(out['agent']['name'] == ('claude-' + 'p' * 80)[:64], 'Naming: cut so that the name fits in 64 characters',
             out['agent'])
        again = self.attach(a1, 'claude', '--directory', str(project('again', 'p' * 80)))
        need(again['agent']['name'] == ('claude-' + 'p' * 80)[:62] + '-2',
             'Naming: the suffix is cut so that the whole name, including -N, fits in 64 characters', again['agent'])

        # 3. BASE-HOSTNAME when the base is used only on another host of the person, then -2.
        w5 = project('second-machine')
        attached(self.attach(a2, 'claude', '--directory', str(w5)), f'claude-{SHORT_HOST}', a2, w5,
                 'Naming: BASE-HOSTNAME when the base is used only on another host')
        w6 = project('second-again')
        attached(self.attach(a2, 'claude', '--directory', str(w6)), f'claude-{SHORT_HOST}-2', a2, w6,
                 'Naming: BASE-HOSTNAME, then -2')
        wf = project('fixture')
        attached(self.attach(a2, 'file-fixture', '--directory', str(wf)), 'file-fixture', a2, wf,
                 'Naming: the base name is otherwise the integration ID')

        # --name taken: refused with 409 before any registration, naming the host that has it.
        agents = a2.cli('agent', 'list')
        taken = project('taken')
        error = self.attach(a2, 'claude', '--name', 'claude', '--directory', str(taken), success=False)
        need(ids['a1'] in error, 'a taken --name is refused, and the error names the host that has it', error)
        need(a2.cli('agent', 'list') == agents, 'a taken --name is refused before any registration')
        need(not (a2.config / 'capsule' / 'sessions' / ids['a2'] / 'claude').exists(), 'a refused attach leaves no '
             'profile')
        error = self.attach(a1, 'claude', '--name', 'claude-proj-two', '--directory', str(taken), success=False)
        need(error, 'a --name used on this host by an attach profile is refused')

        # A --name naming an agent on this host that no attach profile records is reused.
        legacy = a1.cli('agent', 'register', '--name', 'legacy', '--owner', 'ana')
        wl = project('legacy')
        out = attached(self.attach(a1, 'file-fixture', '--name', 'legacy', '--directory', str(wl)), 'legacy', a1, wl,
                       '--name naming an unprofiled agent')
        need(out['agent']['id'] == legacy['id'], 'A --name naming an agent on this host that no attach profile '
             'records is reused', out, legacy)

        # Re-attaching: unchanged while the credential is valid; a new setup after revocation.
        w1, first = self.w1
        adapters = a1.cli('adapter', 'list')
        again = self.attach(a1, 'claude', '--directory', str(w1))
        need(again['reused'] is True and again['agent']['id'] == first['agent']['id']
             and again['adapter_id'] == first['adapter_id'] and again['session_id'] == first['session_id'],
             'Re-attaching with a valid credential changes nothing and reports reused: true', again, first)
        need(a1.cli('adapter', 'list') == adapters, 'reused: no new credential')
        a1.cli('adapter', 'revoke', first['adapter_id'])
        renewed = self.attach(a1, 'claude', '--directory', str(w1))
        need(renewed['reused'] is False and renewed['agent']['id'] == first['agent']['id']
             and renewed['adapter_id'] != first['adapter_id'],
             'Re-attaching after revocation performs a new setup for the same agent', renewed)
        secret = self.profile_secret(renewed)
        need(secret['adapter']['id'] == renewed['adapter_id'], 'the old profile is replaced once the setup succeeds',
             secret['adapter'])
        self.w1 = (w1, renewed)

        # session start / doctor without --directory, from the recorded workspace.
        report = a1.run('session', 'doctor', cwd=w1)
        need(report.stdout.strip(), 'session doctor without --directory reports', report.stderr)
        value = json.loads(report.stdout)
        need(value.get('harness') == 'claude-code', 'session doctor uses the attach profile of the current directory',
             value)
        launched = a1.cli('session', 'start', '--', '--example', 'x', cwd=w1)
        need(launched.get('arguments') == ['--example', 'x'] and Path(launched.get('cwd')).resolve() == w1.resolve(),
             'session start uses the attach profile of the current directory', launched)
        nowhere = project('no-profile')
        need(a1.run('session', 'doctor', cwd=nowhere).returncode != 0,
             'session doctor without --directory and without a profile for the current directory fails')
        need(a1.run('session', 'start', cwd=nowhere).returncode != 0,
             'session start without --directory and without a profile for the current directory fails')

        # unchecked_hosts with the sibling stopped.
        a2.stop()
        try:
            wu = project('unchecked')
            out = self.attach(a1, 'file-fixture', '--directory', str(wu))
            need(out['unchecked_hosts'] == [ids['a2']], 'a host of the person that could not be reached is '
                 'reported in unchecked_hosts, and does not block the attach', out)
        finally:
            a2.start()

    def check_expired_attach(self):
        a1 = self.hosts['a1']
        if not getattr(self, 'expiring', None):
            raise Failure('attach: the expiring attach was not created')
        workspace, first = self.expiring
        record = a1.cli('adapter', 'inspect', first['adapter_id'])
        expires = parse_time(record['expires_at']).timestamp()
        need(record.get('renewable') is False and expires - time.time() < 70, 'attach --expires-in 1m is fixed', record)
        while time.time() < expires + 2:
            time.sleep(min(1, max(0.05, expires + 2 - time.time())))
        out = self.attach(a1, 'file-fixture', '--directory', str(workspace))
        need(out['reused'] is False and out['agent']['id'] == first['agent']['id']
             and out['adapter_id'] != first['adapter_id'],
             'Re-attaching after expiry performs a new setup for the same agent', out, first)

    def check_directory_sessions(self):
        c1, p1, a1, ids = self.hosts['c1'], self.p1, self.hosts['a1'], self.ids
        notes = []

        # Setup validation on the owner API.
        sample = self.agent['csetup']
        for extra in ({'max_sends_per_hour': 5}, {'directory': True, 'max_sends_per_hour': 0},
                      {'directory': True, 'max_sends_per_hour': 10001}):
            status, body = c1.call('POST', '/v1/adapters/setup', {
                'agent_id': sample['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
                'expires_at': timestamp(900), **extra})
            need(status == 400, 'max_sends_per_hour is 1 to 10,000 and requires directory', extra, status, body)

        # no_directory: a session from session setup, and one from adapter create.
        profile = self.root / 'setup-profile'
        configured = c1.cli('session', 'setup', '--harness', 'file-fixture', '--directory', str(profile), '--agent',
                            sample['id'], '--integrations', str(self.catalog))
        need(configured.get('session_id'), 'session setup still runs', configured)
        plain = json.loads((profile / 'credential.json').read_text())
        session = c1.cli('session', 'attach', '--agent', self.agent['corig']['id'], '--integration', 'test')
        created = c1.cli('adapter', 'create', '--session', session['id'], '--expires-in', '30m')
        for secret, what in ((plain, 'session setup'), (created, 'adapter create')):
            token = secret['token']
            for method, path, body in (
                    ('POST', '/adapter/v1/send', {'to': 'pat/alpha', 'request_id': request_id(), 'content': 'x'}),
                    ('POST', '/adapter/v1/delegations', {'to': 'pat/alpha', 'task_id': task_id(), 'input': 'x'}),
                    ('GET', '/adapter/v1/agents', None)):
                status, value = adapter_call(c1, token, method, path, body)
                need(status == 403 and isinstance(value, dict) and value.get('code') == 'no_directory',
                     f'Without directory access ({what}), a to request returns 403 no_directory', path, status, value)

        # The rate cap, on a directory session of carol's with a cap of 2.
        (self.root / 'ws-carol').mkdir(exist_ok=True)
        capped = self.attach(c1, 'file-fixture', '--directory', str(self.root / 'ws-carol'), '--max-sends-per-hour', '2')
        record = c1.cli('adapter', 'inspect', capped['adapter_id'])
        need(record.get('directory') is True and record.get('max_sends_per_hour') == 2,
             'The adapter\'s record shows directory and max_sends_per_hour', record)
        token = self.profile_secret(capped)['token']
        status, listing = adapter_call(c1, token, 'GET', '/adapter/v1/agents')
        need(status == 200 and isinstance(listing, list) and all(set(e) == ADAPTER_AGENT_KEYS for e in listing),
             'GET /adapter/v1/agents returns [{address, network_id, connected, actions, max_message_bytes, '
             'max_artifact_bytes}]', status, listing)
        need(all(e['address'] for e in listing), 'GET /adapter/v1/agents lists addressable agents only', listing)
        entry = {e['address']: e for e in listing}
        eps = entry.get('pat/eps')
        need(eps and set(eps['actions']) == set(DEFAULT_ACTIONS) and eps['network_id'] == self.net,
             'actions are the union over the agent\'s authorizations', eps)
        need('pat/delta' not in entry and 'pat/alpha' in entry,
             'an agent left with no actions (only from_agent entries for other agents) is omitted', sorted(entry))

        both = {'to': 'pat/alpha', 'destination': 'x', 'request_id': request_id(), 'content': 'both'}
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send', both)
        need(status == 400, 'POST /adapter/v1/send: giving both to and destination is 400', status, value)
        first = {'to': 'pat/alpha', 'network': self.net, 'request_id': request_id(), 'content': 'one'}
        status, sent = adapter_call(c1, token, 'POST', '/adapter/v1/send', first, timeout=15)
        need(status == 200, 'an adapter send by address', status, sent)
        delegated = {'to': 'pat/alpha', 'task_id': task_id(), 'input': 'two'}
        status, task = adapter_call(c1, token, 'POST', '/adapter/v1/delegations', delegated, timeout=15)
        need(status == 200, 'an adapter delegation by address', status, task)
        need(task.get('to') == 'pat/alpha', 'Persistence: the delegation record shows to as given', task)
        third = {'to': 'pat/alpha', 'request_id': request_id(), 'content': 'three'}
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send', third, timeout=15)
        need(status == 429 and value.get('code') == 'rate_limited' and type(value.get('retry_after')) is int
             and 1 <= value['retry_after'] <= 3600 and 'error' in value,
             'Rate cap: a request over max_sends_per_hour returns 429 {code: rate_limited, error, retry_after}',
             status, value)
        status, value = adapter_call(c1, token, 'GET', '/adapter/v1/sends/' + third['request_id'])
        need(status == 404, 'Rate cap: a refused request persists nothing', status, value)
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/delegations',
                                     {'to': 'pat/alpha', 'task_id': task_id(), 'input': 'four'}, timeout=15)
        need(status == 429, 'Rate cap: delegations count against the same cap', status, value)
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send', first, timeout=15)
        need(status == 200, 'Rate cap: a retry is never counted', status, value)
        c1.cli('adapter', 'route', 'add', '--adapter', capped['adapter_id'], '--name', 'alpha-route', '--peer',
               ids['p1'], '--agent', self.agent['alpha']['id'], '--expires-in', '10m')
        routed = request_id()
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send',
                                     {'destination': 'alpha-route', 'request_id': routed, 'content': 'route'},
                                     timeout=15)
        need(status == 200, 'Rate cap: route sends keep their own budgets and are not counted', status, value)
        for rid, destination, to in ((routed, 'alpha-route', None), (first['request_id'], None, 'pat/alpha')):
            status, value = adapter_call(c1, token, 'GET', '/adapter/v1/sends/' + rid)
            need(status == 200 and 'destination' in value and 'to' in value and value['destination'] == destination
                 and value['to'] == to, 'the adapter send status always has both destination and to, one of them null',
                 status, value)

        # Deadlines: 5 minutes for sends, 1 hour for delegations.
        stored = self.outbound(c1, ids['p1'], first['request_id'])
        need(stored and near(stored['request']['deadline'], 300, 30), 'Adapter sends by address get 5 minutes',
             stored)
        need(stored.get('to') == 'pat/alpha', 'Persistence: the record shows to as given (adapter send)', stored)
        status, local = c1.call('GET', f"/v1/tasks/{ids['p1']}/{delegated['task_id']}")
        need(status == 200 and near(local['request']['deadline'], 3600, 60), 'adapter delegations get 1 hour',
             status, local)

        # MCP, through the real adapter, on ana's attached session.
        if not getattr(self, 'w1', None):
            raise Failure('MCP cases need the attach section\'s session')
        _, attached = self.w1
        secret = self.profile_secret(attached)
        channel = Channel(self.node, self.script, a1, secret, self.root / 'mcp-ana')
        self.channels.append(channel)
        failed, agents = tool(channel, 'list_agents', {})
        need(not failed and isinstance(agents, list), 'MCP list_agents', agents)
        addresses = {e.get('address') for e in agents}
        need('pat/gamma' in addresses and f'ana/claude-{SHORT_HOST}' in addresses,
             'MCP list_agents: addressable agents in the directory', sorted(a for a in addresses if a))
        failed, sent = tool(channel, 'send', {'to': 'pat/gamma', 'network': self.net, 'content': 'from mcp'})
        need(not failed and sent.get('request_id'), 'MCP send by to', sent)
        rid = sent['request_id']

        def delivered():
            failed, status = tool(channel, 'send_status', {'request_id': rid})
            return status if not failed and status.get('state') == 'accepted' else None
        status = wait_for(delivered, timeout=40, message='MCP send accepted')
        need(status.get('to') == 'pat/gamma', 'send_status reports to for these sends', status)
        message = [m for m in p1.cli('message', 'list', '--limit', '1000') if m['request']['request_id'] == rid]
        need(message and message[0]['request']['target_agent_id'] == self.agent['gamma']['id']
             and (message[0]['request'].get('origin') or {}).get('agent_id') == attached['agent']['id'],
             'MCP send by to reaches the agent, with the session\'s agent as origin', message)
        failed, submitted = tool(channel, 'delegate_task', {'to': 'pat/gamma', 'input': 'mcp task'})
        need(not failed and submitted.get('task_id'), 'MCP delegate_task by to', submitted)
        tid = submitted['task_id']

        def accepted():
            failed, record = tool(channel, 'task_status', {'task_id': tid})
            return record if not failed and record.get('submit_state') == 'accepted' else None
        record = wait_for(accepted, timeout=40, message='MCP delegation accepted')
        need(record['request']['target_agent_id'] == self.agent['gamma']['id']
             and (record['request'].get('policy') or {}).get('person_id') == self.pat,
             'MCP delegate_task by to reaches the agent under the target owner\'s policy', record)
        notes.append(f'mcp list_agents {len(agents)} entries')
        return '; '.join(notes)

    def check_label_retry(self):
        """An uncertain send by address keeps its stored target after the address would resolve elsewhere."""
        c1, b1, b2, ids = self.hosts['c1'], self.hosts['b1'], self.hosts['b2'], self.ids
        self.refresh(c1)
        b1.stop()
        try:
            out = c1.cli('send', 'bob/bobby', 'retry me', '--network', self.net)
            need(out['state'] == 'unknown', 'a send to a stopped host is uncertain', out)
            rid = out['request']['request_id']
            need(self.outbound(c1, ids['b1'], rid), 'The resolved host and agent ID are stored with the request', out)
            # The address change made here (settled with the owner) is an unbinding of b1 from bob; bob's
            # other host then registers the same name, so the address would now resolve to b2.
            b2.cli('network', 'unbind', '--network', self.net, '--host', ids['b1'])
            moved = b2.cli('agent', 'register', '--name', 'bobby', '--owner', 'bob')
            b2.cli('grant', 'create', '--peer', ids['c1'], '--agent', moved['id'], '--expires-in', '2h',
                   '--allow-disconnected')
            wait_for(lambda: not any(m['host_id'] == ids['b1'] and m['person_id']
                                     for m in c1.cli('network', 'members', self.net)), timeout=30,
                     message='b1 unbound in c1\'s map')
        finally:
            b1.start()

        def done():
            r = self.outbound(c1, ids['b1'], rid)
            return r if r and r['state'] != 'unknown' else None
        record = wait_for(done, timeout=120, message='the automatic retry')
        need(record['state'] == 'accepted' and record['request']['target_agent_id'] == self.agent['bobby']['id'],
             'Retries use the stored target and never re-resolve', record)
        need(self.received(b1, rid) and not self.received(b2, rid), 'the retry reached the stored host', rid)
        need(record.get('to') == 'bob/bobby', 'the record still shows to as given', record)

    # --- the pairing ---------------------------------------------------------------------------------------

    def setup_catalog(self):
        """The fixture integration as `file-fixture` and as `claude-code` (no Claude needed)."""
        self.catalog = self.root / 'integrations'
        source = Path(__file__).with_name('fixtures') / 'harness'
        for identity in ('file-fixture', 'claude-code'):
            bundle = self.catalog / identity
            bundle.mkdir(parents=True)
            for name in ('provider.py', 'harness.py'):
                shutil.copy2(source / name, bundle / name)
            (bundle / 'integration.json').write_text(json.dumps({
                'version': 1, 'id': identity, 'command': [str(Path(sys.executable).resolve()), './provider.py'],
                'operations': ['prepare', 'check', 'launch']}))

    def join(self, name, label, person=True):
        token = self.p1.cli('network', 'invite', '--network', self.net, '--member', label, '--expires-in', '1h')['token']
        h = self.hosts[name]
        extra = () if person else ('--no-person',)
        out = h.cli('network', 'join', '--token', token, *extra)
        if person:
            assert out['person'] and out['person']['bound'], out
        return out

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        for name in ('pat', 'bob', 'carol', 'ana'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.bob, self.carol, self.ana = (person_id(self.keys[n][2]) for n in ('pat', 'bob', 'carol', 'ana'))
        self.setup_catalog()

        self.section('root help', self.check_help)
        self.coord_key = self.coord.start()['public_key']
        persons = {'p1': 'pat', 'p2': 'pat', 'b1': 'bob', 'b2': 'bob', 'c1': 'carol', 'a1': 'ana', 'a2': 'ana',
                   'n1': None, 'x': None}
        for name, person in persons.items():
            self.host(name).sock = self.agents[person].socket if person else None
        self.p1 = self.hosts['p1']
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids = self.ids

        created = self.p1.cli('network', 'create', '--name', 'team', '--member', 'pat', *self.coordinator_flags())
        self.net = created['id']
        assert created['person']['bound'], created
        for name in ('p2', 'b1', 'b2', 'c1', 'a1', 'a2'):
            self.join(name, persons[name])
        self.join('n1', 'nobody', person=False)
        self.members = ['p1', 'p2', 'b1', 'b2', 'c1', 'a1', 'a2', 'n1']
        expected = {ids[n]: {'pat': self.pat, 'bob': self.bob, 'carol': self.carol, 'ana': self.ana}.get(persons[n])
                    for n in self.members}

        def bound():
            for n in self.members:
                seen = {m['host_id']: m['person_id'] for m in self.hosts[n].cli('network', 'members', self.net)}
                if seen != expected:
                    return None
            return True
        wait_for(bound, timeout=60, message='every member bound as expected on every host')

        # A second network of p1's, so that x is a member of p1's but not of the team network.
        other = self.p1.cli('network', 'create', '--name', 'other', '--member', 'p1x', '--no-person',
                            *self.coordinator_flags(), sock=None)
        self.other = other['id']
        token = self.p1.cli('network', 'invite', '--network', self.other, '--member', 'xhost', '--expires-in', '1h',
                            sock=None)['token']
        self.hosts['x'].cli('network', 'join', '--token', token, '--no-person')
        wait_for(lambda: len(self.p1.cli('network', 'members', self.other)) == 2, timeout=30,
                 message='x in p1\'s map of the other network')

        # Agents.
        self.agent = {}
        self.p1_agents = ['alpha', 'beta', 'gamma', 'delta', 'eps', 'omega', 'notask', NOT_ADDRESSABLE]
        for host, names in (('p1', self.p1_agents), ('c1', ['corig', 'csetup']), ('n1', ['nagent']),
                            ('b1', ['bobby'])):
            for name in names:
                self.agent[name] = self.hosts[host].cli('agent', 'register', '--name', name, '--owner',
                                                        persons[host] or 'nobody')

        # Before any policy or grant: what the peer route serves to carol and bob.
        # The peer route may be missing; the peer route section reports it, and setup goes on.
        def probe(name):
            try:
                return self.listing('p1', name)
            except OSError as error:
                return (None, str(error))
        try:
            wait_for(lambda: probe('c1')[0] == 200, timeout=20, message='peer route reachable')
        except AssertionError:
            pass
        self.before = {name: probe(name) for name in ('c1', 'b1')}

        # pat's policy and the grants.
        self.p1.cli('network', 'group', 'set', '--network', self.net, '--group', 'team-g', '--person', 'carol')
        self.allow('carol', '--agent', 'alpha')
        self.allow('group:team-g', '--agent', 'beta')
        self.allow('everyone', '--agent', 'gamma')
        self.allow(f"agent:{ids['c1']}/{self.agent['corig']['id']}", '--agent', 'delta')
        self.allow('carol', '--agent', 'notask', '--no-tasks')
        version = self.allow('bob')
        self.grants = {}

        def grant(host, peer, agent, hours, *extra):
            g = self.hosts[host].cli('grant', 'create', '--peer', ids[peer], '--agent', self.agent[agent]['id'],
                                     '--expires-in', f'{hours}h', '--allow-disconnected', *extra)
            self.grants[g['id']] = g
            return g
        grant('p1', 'c1', 'eps', 1)
        self.eps_late = grant('p1', 'c1', 'eps', 2)
        self.eps_task = grant('p1', 'c1', 'eps', 2, '--action', 'task.submit')
        grant('p1', 'n1', 'omega', 1)
        self.n1_grant = grant('n1', 'c1', 'nagent', 2)
        grant('b1', 'c1', 'bobby', 2)
        self.synced(version, *(self.hosts[n] for n in self.members))

        self.section('peer route', self.check_peer_route)
        self.section('discovery', self.check_discovery)
        # The injected duplicate: the same name on two hosts of pat, allowed for carol.
        self.agent['dup1'] = self.p1.cli('agent', 'register', '--name', 'dup', '--owner', 'pat')
        self.agent['dup2'] = self.hosts['p2'].cli('agent', 'register', '--name', 'dup', '--owner', 'pat')
        self.synced(self.allow('carol', '--agent', 'dup'), self.hosts['c1'])
        self.section('addresses', self.check_addresses)
        self.section('sending', self.check_sending)
        self.section('agents and status', self.check_agents_and_status)
        self.section('attach', self.check_attach)
        self.section('directory sessions', self.check_directory_sessions)
        self.section('attach after expiry', self.check_expired_attach)
        self.section('retry after a label change', self.check_label_retry)

    def close(self):
        try:
            for channel in self.channels:
                try:
                    channel.close()
                except Exception:
                    if channel.process.poll() is None:
                        channel.process.kill()
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()


def run_pairing(coord_binary, cli_binary, daemon_binary, node, label):
    with tempfile.TemporaryDirectory(prefix='capsule-directory-') as temporary:
        pairing = Pairing(label, cli_binary, daemon_binary, coord_binary, node, Path(temporary))
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [setup]: {detail}', flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        print(f'---- {label}: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} sections passed '
              f'in {time.monotonic() - started:.0f}s', flush=True)
        return pairing.results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--go', type=Path, required=True)
    parser.add_argument('--rust', type=Path, help='required unless every --pairing is Go/Go')
    parser.add_argument('--coord', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True, help='capsule-peer-probe test client')
    parser.add_argument('--node', type=Path, required=True, help='Node for the MCP adapter cases')
    parser.add_argument('--pairing', action='append', help='CLI/DAEMON, such as Go/Rust; repeatable; default all four')
    args = parser.parse_args()
    set_probe(args.probe.resolve())
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve() if args.rust else None}
    pairings = args.pairing or [f'{c}/{d}' for c in binaries for d in binaries]
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        if cli not in binaries or daemon not in binaries:
            parser.error(f'unknown pairing {pairing}')
        if binaries[cli] is None or binaries[daemon] is None:
            parser.error(f'pairing {pairing} needs --rust')
    failures = []
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        label = f'{cli} CLI, {daemon} daemon'
        for name, ok, detail in run_pairing(args.coord.resolve(), binaries[cli], binaries[daemon],
                                            args.node.resolve(), label):
            if not ok:
                failures.append(f'{label} [{name}]: {detail.strip().splitlines()[-1] if detail.strip() else ""}')
    print('==== summary', flush=True)
    for line in failures:
        print('FAIL ' + line[:1200], flush=True)
    if failures:
        raise SystemExit(f'{len(failures)} section(s) failed')
    print('PASS all sections', flush=True)


if __name__ == '__main__':
    main()
