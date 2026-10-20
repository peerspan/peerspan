#!/usr/bin/env python3
"""Agent capability tools (milestone 10 slice 2), run by conformance/capabilities.py.

Written from docs/capabilities-contract.md ("Agent tools (slice 2)" and its Verification list, plus the slice 1
case for a person whose label contains `/`), and the agent adapter, outbound, recovery, live delivery, and launch
contracts it extends, independently of the Go and Rust hosts and of the shared Node adapter, which runs here only
as a black box (`attach claude --runner NODE`, with a fixture `claude` executable; no model runs).

Each CLI/daemon pairing gets its own topology, separate from the slice 1 pairing in capabilities.py:
- pat (label `pat`): p1 serves the capabilities (agent `srv`, source `srv/fx`, the fixture MCP server) and opens
  its sources to p2; p2 is trusted (agent `pa`); p3 is untrusted (agent `pu`); p4 serves a second copy of `dup`.
- quinn: q1, with MCP agents `qa`, `qb`, `qno` (--no-calls), `qlim` (--max-calls-per-hour 2), `qred`, and `qend`,
  plus raw adapter sessions for the routes.
- `ops/sam` (a label containing `/`): s1 serves `sx` (shared with quinn) and opens its sources to s2 (trusted).
Networks: team (all of them) and other (p1 and q1).

Capabilities on p1 (all on the source's own instance, so 4 running calls fill it): `tools` (shared with quinn,
1,000 calls an hour), `limited` (quinn, 1 an hour: the receiver's 429), `agentonly` (agent:q1/qa), `mixed`
(agent:q1/qa in team, quinn in other), `recheck` and `revoke` (quinn), `private` (not shared), and `dup`, which is
also on p4 with neither copy claimed (so `pat/dup` is ambiguous for pat's trusted p2).

Sections, per pairing (contract Verification bullets in brackets):
- opt-in [Opt-in];
- listing [Listing], except `unanswered`, which runs last (it stops p4);
- calls [Calls: within wait with origin and citation, 10 seconds, outlasting wait, no event when answered, the
  claim-while-waiting path, wait 0/60/61, source, ambiguous, not_found, the receiver's 429];
- agent rules and repeats [Calls: agent: rule, repeated call_id through the route and the tool];
- queued window [Calls: call_cancel while queued, expired, rejected at the recheck; rejected at submission];
- running calls [Calls: call_cancel while running, uncertain after the receiver restarts];
- rate limit [Rate limit];
- results [Results];
- call updates and pending work [Call updates and pending work];
- revocation [Revocation];
- slash label [slice 1 CLI: a person whose label contains `/`];
- unanswered [Listing: `unanswered` with a stopped host].
Once per run (from capabilities.py): migration from version 17 to 18 [Migration].

Where the contract is silent, the suite takes the narrowest reading or makes no assertion; such spots are marked
"Q:" and soft results are NOTE lines.
"""
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
import traceback

from coordination import Coordinator, wait_for
from host_service import UnixHTTPConnection, stop_all
from launch_onboarding import Failure, need
import live_delivery
from live_delivery import Consumer, Fixture as ClaudeFixture, flag
from peer_messaging import fixture_context, timestamp, wire
from persons import Agent, person_id, ssh_key

import capabilities as caps
from capabilities import CapHost, DropCallResponse, Fixture, PYTHON, cap_rule, crafted_v2, db_rows, policy_of

# --- the contract's exact texts and shapes ----------------------------------------------------------------------

CALLS_PROMPT = 'Let this agent call capabilities shared with you, and yours on your other trusted machines? [y/N]'
PENDING_NOTE = ('The call has not finished. Its result arrives as a kind=call_update event; call_status reports it at '
                'any time.')
UNCERTAIN_NOTE = ('The call was running when it ended without a result, so it may or may not have taken effect. Do '
                  'not call it again on your own: check whether it took effect, or ask the person.')
NEVER_RAN_NOTE = 'The call never ran, so it had no effect. Calling again makes a new call.'
PARTS_NOTE = 'The result is in parts; call call_status with offset set to next_offset for the next part.'
RECOVERY = 'Nothing was called or recorded.'
TEXTS = {
    'no_calls': 'This session may not call capabilities. The person enables it with peerspan attach --calls.',
    'rate_limited': 'This session reached its hourly limit of capability calls.',
    'source': 'Sources can be called only from the peerspan CLI.',
    'ambiguous': 'The address names a capability on more than one host; use one of candidates.',
    'not_found': ('No capability at this address is available to this session now. It may have been unshared, or its '
                  'host may not have answered (see unanswered). Check list_capabilities.'),
}
NOT_RECORDED_NOTE = 'The host has no record of this call for this agent; it never ran.'
HOOK_LEAD = ('Peerspan work this session still owes, listed after /clear, compaction, or resume. Finish each task '
             'with the task_* tools, answer each delivery with reply, and check each call with call_status; call '
             'pending_work for the current list. ')
LAPSED = 'authorization lapsed before start'
VIEW_KEYS = {'call_id', 'address', 'peer_host_id', 'operation', 'submit_state', 'state', 'error', 'created_at',
             'deadline', 'result', 'result_part', 'truncated', 'result_bytes', 'offset', 'next_offset', 'note'}
ENTRY_KEYS = {'address', 'host_id', 'capability', 'operations', 'resources', 'state', 'unavailable'}
LISTING_KEYS = {'capabilities', 'unanswered'}
META_KEYS = {'call_id', 'notification_id', 'address', 'operation', 'state', 'error', 'result_bytes', 'truncated',
             'session_id', 'redelivered'}
PENDING_CALL_KEYS = {'call_id', 'address', 'operation', 'state', 'error', 'result_bytes', 'created_at', 'deadline',
                     'session_id', 'redelivered'}
NOTIFICATION_KEYS = {'id', 'peer_host_id', 'call_id', 'adapter_id', 'session_id', 'state', 'created_at',
                     'updated_at'}
REFUSAL_KEYS = {'call_id', 'address', 'code', 'error', 'recovery'}
REFUSAL_EXTRAS = {'retry_after', 'candidates', 'unanswered'}
TOOLS = ('list_capabilities', 'call_capability', 'call_status', 'call_cancel')
FINAL = {'succeeded', 'failed', 'rejected', 'expired', 'cancelled', 'uncertain'}
PENDING_STATES = {'submitting', 'queued', 'running'}
CALL_ID = re.compile(r'call_[0-9a-f]{32}')
NOTIFICATION_ID = re.compile(r'notification_[0-9a-f]{32}')
INLINE = 65536
NEW_TABLES = ('adapter_calls', 'call_update_notifications')
VERSION = 18
# The integrations directory whose shared adapter `attach --runner NODE` runs (capabilities.py --integrations).
INTEGRATIONS = live_delivery.INTEGRATIONS


def cid():
    return 'call_' + secrets.token_hex(16)


def marker(prefix):
    return f'{prefix}-{secrets.token_hex(4)}'


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False)


def note_for(state, truncated):
    if state in PENDING_STATES:
        return PENDING_NOTE
    if state == 'uncertain':
        return UNCERTAIN_NOTE
    if state in ('rejected', 'expired', 'cancelled'):
        return NEVER_RAN_NOTE
    if state in ('succeeded', 'failed') and truncated:
        return PARTS_NOTE
    return None


def check_view(view, rule='a call view'):
    """The call view's shape and its internal rules (The call view)."""
    need(isinstance(view, dict) and set(view) == VIEW_KEYS, f'{rule}: the call view has exactly the contract\'s '
         'fields', sorted(set(view) ^ VIEW_KEYS) if isinstance(view, dict) else view)
    need(CALL_ID.fullmatch(view['call_id'] or ''), f'{rule}: call_id is call_ and 32 hex digits', view['call_id'])
    need(view['note'] == note_for(view['state'], view['truncated']), f'{rule}: note is the exact text for its state',
         view['state'], view['truncated'], view['note'])
    if view['result_bytes'] is None:
        need(view['result'] is None and view['result_part'] is None and view['truncated'] is False and
             view['next_offset'] is None, f'{rule}: before there is a result, result and result_part are null, '
             'truncated false, next_offset null', view)
    elif not view['truncated']:
        need(view['result'] is not None and view['result_part'] is None and view['next_offset'] is None and
             view['offset'] == 0 and view['result_bytes'] <= INLINE,
             f'{rule}: an inline result (at most 65,536 bytes, offset 0): result set, result_part null', view)
    else:
        need(view['result'] is None and isinstance(view['result_part'], str),
             f'{rule}: a result in parts: result null, result_part text', str(view)[:400])
    if view['state'] == 'submitting':
        need(view['submit_state'] == 'unknown', f'{rule}: state submitting while submit_state is unknown', view)
    return view


# The fixture's canon text (fixtures/mcp/server.py).
CANON_TEXT = 'q"b\\s/\x01\b\t\n\x0c\r\x1f\x7f é€😀 '


def canonical(value):
    """The contract's result text encoding: no whitespace, keys sorted by UTF-8 bytes (code point order), raw
    UTF-8, escaping only \" and \\, \b \t \n \f \r, and other characters below U+0020 as \\u00xx (lowercase).
    The fixture's numbers are integers and 1.5, which Python renders as sent."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode())
        return '{' + ','.join(canonical(k) + ':' + canonical(v) for k, v in items) + '}'
    if isinstance(value, list):
        return '[' + ','.join(canonical(v) for v in value) + ']'
    if isinstance(value, str):
        out = []
        for ch in value:
            if ch in '"\\':
                out.append('\\' + ch)
            elif ch in '\b\t\n\f\r':
                out.append({'\b': '\\b', '\t': '\\t', '\n': '\\n', '\f': '\\f', '\r': '\\r'}[ch])
            elif ord(ch) < 0x20:
                out.append('\\u%04x' % ord(ch))
            else:
                out.append(ch)
        return '"' + ''.join(out) + '"'
    return json.dumps(value)


def first_difference(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i, a[max(0, i - 20):i + 20], b[max(0, i - 20):i + 20]
    return min(len(a), len(b)), a[-40:], b[-40:]


def meta_equal(got, want):
    """Channel meta values may arrive as strings (Claude Code meta is string-valued)."""
    if got == want:
        return True
    if want is None:
        return got in (None, '', 'null')
    if isinstance(want, bool):
        return flag({'v': got}, 'v') is want
    return str(got) == str(want)


class Raw:
    """A raw adapter client (bearer token and one instance), connecting before each request, with a timeout long
    enough for POST /adapter/v1/calls (it may take 25 seconds)."""

    def __init__(self, host, credential):
        self.host, self.token, self.adapter = host, credential['token'], credential['adapter']
        self.instance = 'instance_' + secrets.token_hex(32)

    def request(self, method, path, body=None, timeout=40):
        connection = UnixHTTPConnection(self.host.state / 'adapter.sock', timeout=timeout)
        try:
            payload = json.dumps(body).encode() if body is not None else None
            connection.request(method, path, payload, {'Authorization': 'Bearer ' + self.token,
                                                       'Content-Type': 'application/json',
                                                       'X-Peerspan-Instance': self.instance})
            response = connection.getresponse()
            data = response.read()
            try:
                return response.status, json.loads(data)
            except ValueError:
                return response.status, data.decode(errors='replace')
        finally:
            connection.close()

    def connect(self):
        return self.request('POST', '/adapter/v1/connect', {
            'adapter_id': self.adapter['id'], 'session_id': self.adapter['session_id'], 'instance_id': self.instance,
            'protocol_version': '2025-11-25'})

    def call(self, method, path, body=None, timeout=40):
        status, value = self.connect()
        need(status == 200, 'raw adapter connects', status, value)
        return self.request(method, path, body, timeout)

    def ready(self):
        status, value = self.call('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, 'POST /adapter/v1/ready', status, value)


class AgentPairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, node, root, only=None):
        self.label, self.cli_binary, self.daemon, self.node, self.root = label, cli_binary, daemon_binary, node, root
        self.only = only
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results, self.notes, self.setup_notes = [], [], []
        self.hosts, self.ids, self.keys, self.agents = {}, {}, {}, {}
        self.sessions = {}      # name -> {host, agent_id, session_id, adapter_id, profile, workspace, out, consumer}
        self.consumers = []
        self.aid = {}

    # --- infrastructure ----------------------------------------------------------------------------------------

    def host(self, name, person):
        h = CapHost(self.daemon, self.cli_binary, self.root / name, self.root / f'user-{name}')
        h.sock = self.agents[person].socket if person else None
        self.hosts[name] = h
        return h

    def section(self, name, function):
        if self.only and name not in self.only:
            return None
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:  # report and continue with the next section
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=5)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [agent tools: {name}] ({time.monotonic() - started:.0f}s): {detail}',
                  flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [agent tools: {name}] ({time.monotonic() - started:.0f}s)'
              f'{": " + notes if notes else ""}', flush=True)
        return True

    def soft(self, condition, rule, *detail):
        if not condition:
            self.notes.append(f'{rule}: ' + ' | '.join(repr(d)[:300] for d in detail))
            print(f'NOTE {self.label} (not counted): {rule}', flush=True)

    def note(self, text):
        self.notes.append(text)
        print(f'NOTE {self.label}: {text}', flush=True)

    def env(self, host):
        e = self.hosts[host].environment()
        e['PATH'] = str(Path(self.node).parent) + os.pathsep + e.get('PATH', '')
        return e

    def coordinator_flags(self):
        return ('--coordinator', self.coord.address, '--coordinator-key', self.coord_key)

    def invite(self, label, net):
        return self.hosts['p1'].cli('network', 'invite', '--network', net, '--member', label,
                                    '--expires-in', '1h')['token']

    def policy(self, host='p1', net=None, person=None):
        path = f'/v1/networks/{net or self.team}/policy?person={person or self.pat}'
        status, body = self.hosts[host].call('GET', path)
        return policy_of(body) if status == 200 else None

    def version(self, host='p1', net=None, person=None):
        p = self.policy(host, net, person)
        return p['version'] if p else 0

    def synced(self, version, *names, net=None, person=None, timeout=40):
        net = net or self.team
        for name in names:
            h = self.hosts[name]

            def caught_up():
                h.run('network', 'sync', net)
                return self.version(name, net, person) >= version
            wait_for(caught_up, timeout=timeout, message=f'policy version {version} on {name}')

    def sync_pat(self):
        """Every member stores pat's newest policy in team (and q1 in other)."""
        self.synced(self.version('p1'), 'p2', 'p3', 'p4', 'q1', 's1', 's2')
        self.synced(self.version('p1', self.other), 'q1', net=self.other)

    def register(self, host, name, owner):
        agent = self.hosts[host].cli('agent', 'register', '--name', name, '--owner', owner)
        self.aid[name] = agent['id']
        return agent

    def put_servers(self, host, agent, servers):
        definitions = [{'name': name, 'transport': 'stdio', 'command': PYTHON, 'args': args, 'env': {}, 'url': None,
                        'source': 'claude-code:user'} for name, args in servers.items()]
        status, body = self.hosts[host].call('PUT', f'/v1/agents/{self.aid[agent]}/tool-servers',
                                             {'workspace': str(self.root), 'servers': definitions, 'values': {}})
        need(status == 200, 'setup: PUT /v1/agents/{agent_id}/tool-servers', host, agent, status, body)

    def create(self, host, name, source, operations):
        code, out, stdout, stderr = self.hosts[host].outcome('capability', 'create', name, '--from', source,
                                                             '--operations', ','.join(operations))
        need(code == 0, f'setup: capability create {name} on {host}', code, stderr[-400:])

    def share(self, host, name, principal, net=None, per_hour=None):
        args = ['share', name, '--with', principal, '--yes', '--network', net or self.team]
        if per_hour:
            args += ['--calls-per-hour', str(per_hour)]
        code, out, stdout, stderr = self.hosts[host].outcome(*args)
        need(code == 0, f'setup: share {name} --with {principal}', code, stderr[-400:])

    def unshare(self, host, name, principal, net=None):
        code, out, stdout, stderr = self.hosts[host].outcome('unshare', name, '--with', principal, '--network',
                                                             net or self.team)
        need(code == 0, f'unshare {name} --with {principal}', code, stderr[-400:])
        return out

    def adapter_record(self, host, adapter_id):
        status, body = self.hosts[host].call('GET', f'/v1/adapters/{adapter_id}')
        need(status == 200 and isinstance(body, dict), 'GET /v1/adapters/{id}', status, body)
        return body

    def count(self, host, table, where='', args=()):
        return db_rows(self.hosts[host], f'SELECT COUNT(*) FROM {table} {where}', args)[0][0]

    def notification(self, host, call_id):
        """(seen_at, redeliveries, record) of the call-update notification for call_id, or None."""
        rows = db_rows(self.hosts[host], 'SELECT seen_at, redeliveries, record FROM call_update_notifications '
                       'WHERE call_id = ?', (call_id,))
        if not rows:
            return None
        seen_at, redeliveries, record = rows[0]
        try:
            record = json.loads(record)
        except ValueError:
            pass
        return seen_at, redeliveries, record

    def executions(self, key, text):
        return self.fixture.calls(key, marker=text)

    # --- attach and consumers ------------------------------------------------------------------------------

    def workspace(self, host, name):
        w = self.root / 'projects' / host / name
        w.mkdir(parents=True, exist_ok=True)
        return w

    def attach_argv(self, name, workspace, flags):
        return ['attach', 'claude', '--name', name, '--directory', str(workspace), '--integrations',
                str(INTEGRATIONS), '--runner', str(self.node), '--option', f'executable={self.claude.path}',
                '--no-start', *flags]

    def attach(self, host, name, *flags, workspace=None, terminal=None):
        """(exit code, output or None, stderr or terminal text, whether the calls prompt was seen)."""
        workspace = workspace or self.workspace(host, name)
        argv = self.attach_argv(name, workspace, flags)
        h = self.hosts[host]
        if terminal is not None:
            code, out, tty, stdout, seen = h.converse(*argv, answers=[terminal], prompt=CALLS_PROMPT, timeout=120)
            return code, out, tty, seen
        code, out, stdout, stderr = h.outcome(*argv, cwd=str(self.root), timeout=150)
        return code, out, stderr, caps.squash(CALLS_PROMPT) in caps.squash(stderr)

    def consumer(self, host, profile, label):
        c = Consumer(Path(profile), self.env(host), self.root / 'consumers' / f'{label}-{len(self.consumers)}')
        self.consumers.append(c)
        return c

    def verified(self, host, profile, label):
        c = self.consumer(host, profile, label)
        _, hello = c.wait_event('hello', timeout=30)
        failed, value = c.tool('peerspan_ready', {'nonce': hello['meta']['nonce']})
        need(not failed and value == {'ready': True}, 'peerspan_ready', failed, value)
        return c

    def session(self, host, name, *flags):
        """An attached MCP session, verified; recorded in self.sessions (setup failures become setup notes)."""
        try:
            workspace = self.workspace(host, name)
            code, out, stderr, _ = self.attach(host, name, *flags, workspace=workspace)
            need(code == 0 and isinstance(out, dict), f'attach claude --name {name} {" ".join(flags)}', code,
                 stderr[-500:])
            s = {'host': host, 'agent_id': out['agent']['id'], 'session_id': out['session_id'],
                 'adapter_id': out['adapter_id'], 'profile': out['profile'], 'workspace': workspace, 'out': out}
            s['consumer'] = self.verified(host, out['profile'], name)
            self.aid[name] = s['agent_id']
            self.sessions[name] = s
            return s
        except Exception as error:
            self.setup_notes.append(f'session {name}: {str(error)[:400]}')
            return None

    def s(self, name):
        s = self.sessions.get(name)
        need(s is not None, f'setup: the MCP session {name} (attach --calls and the adapter) is available',
             *[n for n in self.setup_notes if name in n])
        return s

    def replace(self, name, terminal=None, flags=('--calls',)):
        """Close the session's consumer and attach the same workspace again: a new authorization of the same agent
        (launch contract, Re-attaching), verified. A replacement does not carry the calls setting over, so --calls is
        given again."""
        s = self.s(name)
        s['consumer'].close()
        code, out, text, seen = self.attach(s['host'], name, *flags, workspace=s['workspace'], terminal=terminal)
        need(code == 0 and isinstance(out, dict) and out['agent']['id'] == s['agent_id'] and
             out['session_id'] != s['session_id'], f'attach again replaces {name}\'s session', code, text[-500:])
        previous = dict(s)
        s.update({'session_id': out['session_id'], 'adapter_id': out['adapter_id'], 'profile': out['profile'],
                  'out': out})
        s['consumer'] = self.verified(s['host'], out['profile'], name)
        return previous, out, seen

    @staticmethod
    def tool(c, name, arguments, seconds=120):
        """(is_error, parsed text) of an MCP tool call; a JSON-RPC error counts as an error."""
        result = c.call('tools/call', {'name': name, 'arguments': arguments}, seconds=seconds)
        if 'jsonrpc_error' in result:
            return True, result['jsonrpc_error']
        text = ''.join(x.get('text', '') for x in result.get('content', []) if x.get('type') == 'text')
        try:
            return bool(result.get('isError')), json.loads(text)
        except ValueError:
            return bool(result.get('isError')), text

    def cc(self, name, address, operation, input=None, wait=None, call_id=None):
        """call_capability from session NAME: (is_error, value, seconds taken)."""
        arguments = {'address': address, 'operation': operation, 'input': input if input is not None else {}}
        if wait is not None:
            arguments['wait'] = wait
        if call_id is not None:
            arguments['call_id'] = call_id
        started = time.monotonic()
        failed, value = self.tool(self.s(name)['consumer'], 'call_capability', arguments, seconds=150)
        return failed, value, time.monotonic() - started

    def ok_call(self, name, address, operation, input=None, wait=None, call_id=None, rule='call_capability'):
        failed, value, elapsed = self.cc(name, address, operation, input, wait, call_id)
        need(not failed, f'{rule}: not a tool error', value)
        check_view(value, rule)
        return value, elapsed

    def status(self, name, call_id, offset=None):
        arguments = {'call_id': call_id}
        if offset is not None:
            arguments['offset'] = offset
        return self.tool(self.s(name)['consumer'], 'call_status', arguments)

    def final_view(self, name, call_id, timeout=90):
        def done():
            failed, view = self.status(name, call_id)
            need(not failed, 'call_status: not a tool error', view)
            return view if view.get('state') in FINAL else None
        view = wait_for(done, timeout=timeout, message=f'call {call_id} final through call_status')
        return check_view(view, 'call_status')

    def listing(self, name):
        failed, value = self.tool(self.s(name)['consumer'], 'list_capabilities', {})
        need(not failed and isinstance(value, dict) and set(value) == LISTING_KEYS,
             'list_capabilities returns {capabilities, unanswered}', failed, str(value)[:400])
        for e in value['capabilities']:
            need(set(e) == ENTRY_KEYS, 'each entry is {address, host_id, capability, operations, resources, state, '
                 'unavailable}', e)
        keys = [(e['address'], e['host_id']) for e in value['capabilities']]
        need(keys == sorted(keys), 'entries sorted by address, then host ID', keys)
        for u in value['unanswered']:
            need(set(u) == {'host_id', 'error'}, 'unanswered entries are {host_id, error}', u)
        return value

    def events_for(self, name, call_id, since=0.0):
        c = self.s(name)['consumer']
        return [p for _, p in c.channel(since) if (p.get('meta') or {}).get('kind') == 'call_update' and
                (p.get('meta') or {}).get('call_id') == call_id]

    def wait_update(self, name, call_id, since=0.0, timeout=60):
        _, params = self.s(name)['consumer'].wait_event(
            'call_update', since=since, timeout=timeout,
            where=lambda p: (p.get('meta') or {}).get('call_id') == call_id)
        return params

    def check_event(self, name, params, view_rule='the call_update event'):
        """meta {call_id, notification_id, address, operation, state, error, result_bytes, truncated, session_id,
        redelivered}; content the call view at offset 0 as JSON text."""
        meta = {k: v for k, v in (params.get('meta') or {}).items() if k != 'kind'}
        need(set(meta) <= META_KEYS, f'{view_rule}: meta has only the contract\'s keys (besides kind)',
             sorted(set(meta) - META_KEYS))
        need(NOTIFICATION_ID.fullmatch(str(meta['notification_id'])), f'{view_rule}: notification_id is '
             'notification_ and 32 hex digits', meta)
        try:
            view = json.loads(params.get('content') or '')
        except ValueError:
            raise Failure(f'{view_rule}: content is the call view as JSON text: {str(params.get("content"))[:300]}')
        check_view(view, view_rule)
        need(view['offset'] == 0, f'{view_rule}: the view at offset 0', view)
        # The Claude channel omits null meta fields (agent adapter contract: meta values are strings).
        absent = META_KEYS - set(meta)
        need(not absent - {'error', 'result_bytes'} and all(view[k] is None for k in absent),
             f'{view_rule}: meta has every field, null ones omitted', sorted(absent))
        for key in ('call_id', 'address', 'operation', 'state', 'error', 'result_bytes', 'truncated'):
            need(meta_equal(meta.get(key), view[key]), f'{view_rule}: meta {key} matches the call view',
                 meta.get(key), view[key])
        return meta, view

    def pending(self, name):
        failed, value = self.tool(self.s(name)['consumer'], 'pending_work', {})
        need(not failed and isinstance(value, dict) and set(value) == {'deliveries', 'replies', 'tasks', 'calls'},
             'pending_work returns {deliveries, replies, tasks, calls}', failed, str(value)[:300])
        for item in value['calls']:
            need(set(item) == PENDING_CALL_KEYS, 'each pending call is {call_id, address, operation, state, error, '
                 'result_bytes, created_at, deadline, session_id, redelivered}', item)
        created = [caps.parse_time(i['created_at']) for i in value['calls']]
        need(created == sorted(created), 'pending calls oldest first by created_at', value['calls'])
        return value

    def refusal(self, value, code, rule):
        """A tool refusal that persisted nothing: {call_id, address, code, error, recovery} (+ extras)."""
        need(isinstance(value, dict) and REFUSAL_KEYS <= set(value) <= REFUSAL_KEYS | REFUSAL_EXTRAS,
             f'{rule}: the refusal is {{call_id, address, code, error, recovery}} plus retry_after, candidates, or '
             'unanswered', value)
        need(value['code'] == code and value['recovery'] == RECOVERY, f'{rule}: code {code} and recovery '
             f'"{RECOVERY}"', value)
        if code in TEXTS:
            need(value['error'] == TEXTS[code], f'{rule}: the exact {code} text', value['error'])
        return value

    def raw_setup(self, host, agent_id, calls=True, expires_in=7200, extra=None):
        body = {'agent_id': agent_id, 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
                'expires_at': timestamp(expires_in), 'calls': calls}
        body.update(extra or {})
        status, value = self.hosts[host].call('POST', '/v1/adapters/setup', body)
        need(status == 201, 'POST /v1/adapters/setup', body, status, value)
        return Raw(self.hosts[host], value['credential']), value

    def qraw_session(self):
        """A raw adapter session of quinn's agent `qraw` on q1, with calls, verified."""
        if getattr(self, 'qraw', None) is None:
            agent = self.register('q1', 'qraw', 'quinn')
            self.qraw, _ = self.raw_setup('q1', agent['id'])
            self.qraw.ready()
        return self.qraw

    def received(self, host, call_id):
        after = 0
        while True:
            page = self.hosts[host].cli('calls', 'received', '--after', str(after), '--limit', '1000')
            for item in page:
                if (item.get('request') or {}).get('call_id') == call_id:
                    return item
            if len(page) < 1000:
                return None
            after = page[-1]['sequence']

    def inspect(self, host, peer, call_id):
        return self.hosts[host].cli('calls', 'inspect', '--peer', self.ids[peer], call_id)

    def fill_slots(self, seconds, count=4):
        """Occupy p1's source instance (srv/fx, shared by every capability here) with self calls from p2 on `tools`,
        returning once the fixture runs them all."""
        before = len(self.fixture.calls('fx', name='sleep'))
        for _ in range(count):
            b = {'call_id': cid(), 'capability': 'tools', 'operation': 'sleep',
                 'input': {'seconds': seconds, 'text': marker('slot')}, 'deadline': timestamp(300),
                 'self': {'person_id': self.pat, 'network_id': self.team}}
            status, record = wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'POST', '/peer/v1/calls', b)
            need(status == 200, 'setup: a self call from p2 fills a slot', status, record)
        wait_for(lambda: len(self.fixture.calls('fx', name='sleep')) >= before + count, timeout=30,
                 message='4 running calls')
        return time.monotonic()

    def restart(self, name):
        h = self.hosts[name]
        h.stop()
        h.logs.close()
        h.logs = tempfile.TemporaryFile()
        return h.start()

    # --- setup -----------------------------------------------------------------------------------------------

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        for name in ('pat', 'quinn', 'sam'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.quinn, self.sam = (person_id(self.keys[n][2]) for n in ('pat', 'quinn', 'sam'))
        self.fixture = Fixture(root / 'fixture')
        self.claude = ClaudeFixture(root / 'claude')
        self.coord_key = self.coord.start()['public_key']
        persons = {'p1': 'pat', 'p2': 'pat', 'p3': 'pat', 'p4': 'pat', 'q1': 'quinn', 's1': 'sam', 's2': 'sam'}
        for name, person in persons.items():
            self.host(name, person)
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids, h = self.ids, self.hosts

        self.team = h['p1'].cli('network', 'create', 'team', '--as', 'pat', '--trusted',
                                *self.coordinator_flags())['id']
        for name, label, flags in (('p2', 'pat', ('--trusted',)), ('p3', 'pat', ('--untrusted',)),
                                   ('p4', 'pat', ('--untrusted',)), ('q1', 'quinn', ('--untrusted',)),
                                   ('s1', 'ops/sam', ('--trusted',)), ('s2', 'ops/sam', ('--trusted',))):
            h[name].cli('join', self.invite(label, self.team), *flags)
        self.other = h['p1'].cli('network', 'create', 'other', '--as', 'pat', '--untrusted',
                                 *self.coordinator_flags())['id']
        h['q1'].cli('join', self.invite('quinn', self.other), '--untrusted')
        expected = {ids[n]: {'pat': self.pat, 'quinn': self.quinn, 'sam': self.sam}[p] for n, p in persons.items()}

        def bound():
            for n in persons:
                h[n].run('network', 'sync', self.team)
            seen = {m['host_id']: m['person_id'] for m in h['p1'].cli('network', 'members', self.team)}
            return seen == expected
        wait_for(bound, timeout=90, message='every member of team bound as expected')
        for n in ('p1', 'q1'):
            h[n].run('network', 'sync', self.other)

        # Sources: srv/fx on p1 (open to p2), srv4/fx on p4, sagent/fx on s1 (open to s2).
        self.register('p1', 'srv', 'pat')
        self.put_servers('p1', 'srv', {'fx': self.fixture.args('fx')})
        self.register('p4', 'srv4', 'pat')
        self.put_servers('p4', 'srv4', {'fx': self.fixture.args('fx4')})
        self.register('s1', 'sagent', 'ops/sam')
        self.put_servers('s1', 'sagent', {'fx': self.fixture.args('sfx')})
        for host, target in (('p1', 'p2'), ('s1', 's2')):
            status, body = h[host].call('POST', '/v1/sources/open-to', {'host_id': ids[target]})
            need(status in (200, 201), 'setup: sources open-to', host, target, status, body)

        for name, operations in (('tools', ['echo', 'sleep', 'big', 'fail', 'tool_error', 'write_note']),
                                 ('limited', ['echo']), ('agentonly', ['echo']), ('mixed', ['echo']),
                                 ('recheck', ['echo', 'sleep']), ('revoke', ['echo', 'sleep']),
                                 ('private', ['echo']), ('dup', ['echo'])):
            self.create('p1', name, 'srv/fx', operations)
        self.create('s1', 'sx', 'sagent/fx', ['echo'])
        self.unclaim_dup()

        # Sessions (the adapter). Failures become setup notes; the sections that need them fail on their own.
        for host, name, flags in (('p2', 'pa', ('--calls',)), ('p3', 'pu', ('--calls',)), ('q1', 'qa', ('--calls',)),
                                  ('q1', 'qb', ('--calls',)), ('q1', 'qno', ('--no-calls',)),
                                  ('q1', 'qlim', ('--calls', '--max-calls-per-hour', '2', '--max-sends-per-hour',
                                                  '2')),
                                  ('q1', 'qred', ('--calls',)), ('q1', 'qend', ('--calls',))):
            self.session(host, name, *flags)

        self.share('p1', 'tools', 'quinn', per_hour=1000)
        self.share('p1', 'limited', 'quinn', per_hour=1)
        self.share('p1', 'recheck', 'quinn')
        self.share('p1', 'revoke', 'quinn')
        self.share('p1', 'mixed', 'quinn', net=self.other)
        if 'qa' in self.sessions:
            principal = f"agent:{ids['q1']}/{self.aid['qa']}"
            self.share('p1', 'agentonly', principal)
            self.share('p1', 'mixed', principal)
        self.share('s1', 'sx', 'quinn')
        h['p1'].cli('allow', 'quinn', '--network', self.team)
        self.sync_pat()
        self.synced(self.version('s1', person=self.sam), 'q1', 's2', 'p1', person=self.sam)

        self.section('opt-in', self.check_opt_in)
        self.section('listing', self.check_listing)
        self.section('calls', self.check_calls)
        self.section('agent rules and repeats', self.check_agent_rules)
        self.section('queued window', self.check_queued)
        self.section('running calls', self.check_running)
        self.section('rate limit', self.check_rate_limit)
        self.section('results', self.check_results)
        self.section('call updates and pending work', self.check_updates)
        self.section('revocation', self.check_revocation)
        self.section('slash label (slice 1)', self.check_slash_label)
        self.section('unanswered', self.check_unanswered)
        if self.setup_notes:
            print(f'NOTE {self.label} agent tools setup: ' + ' | '.join(self.setup_notes), flush=True)

    def unclaim_dup(self):
        """`dup` on p1 and on p4 with neither copy claimed, so no policy binds the name and pat has it on two hosts
        (owner decision 12). Creation always claims, so each claim is withdrawn by a policy signed here with pat's key
        (as an owner could sign by hand; not an edit, copying `edits`), as the slice 1 suite does."""
        h = self.hosts
        for net in (self.team, self.other):
            self.drop_rule('dup', net)
        self.synced(self.version('p1'), 'p4')
        self.create('p4', 'dup', 'srv4/fx', ['echo'])
        self.synced(self.version('p4'), 'p1')
        self.drop_rule('dup', self.team)
        need(not any(r['capability'] == 'dup' for r in (self.policy('p1') or {}).get('capability_rules') or []),
             'setup: no policy of pat binds dup')
        h['p4'].run('network', 'sync', self.team)

    def drop_rule(self, name, net):
        current = self.policy('p1', net)
        rules = [r for r in current.get('capability_rules') or [] if r['capability'] != name]
        if len(rules) == len(current.get('capability_rules') or []):
            return
        signed = crafted_v2(current, current['version'] + 1, self.keys['pat'][0], self.root, capability_rules=rules)
        status, body = self.hosts['p1'].call('POST', f'/v1/networks/{net}/policy', {'policy': signed})
        need(status == 201, f'setup: pat\'s policy in {net} without a rule for {name}', status, body)

    # --- opt-in --------------------------------------------------------------------------------------------

    def check_opt_in(self):
        q1, ids = self.hosts['q1'], self.ids
        notes = []

        def counts():
            return (self.count('q1', 'adapter_credentials'), self.count('q1', 'agents'))

        # Refusals, before anything changes.
        for flags in (('--calls', '--no-calls'), ('--no-calls', '--max-calls-per-hour', '5'),
                      ('--calls', '--max-calls-per-hour', '0'), ('--calls', '--max-calls-per-hour', '10001')):
            before = counts()
            name = 'refused' + secrets.token_hex(2)
            workspace = self.workspace('q1', name)
            code, out, stderr, _ = self.attach('q1', name, *flags, workspace=workspace)
            need(code == 1 and counts() == before and not any(workspace.iterdir()),
                 'attach refuses --calls with --no-calls, --max-calls-per-hour with --no-calls, and a value outside 1 '
                 'to 10,000 with exit 1 before anything changes', flags, code, counts(), before, stderr[-300:])
            need(not any(a['name'] == name for a in q1.cli('agent', 'list')), 'a refused attach registers nothing',
                 name)

        # Flags, output, and the adapter record.
        cases = ((('--calls',), True, 100), (('--calls', '--max-calls-per-hour', '7'), True, 7),
                 (('--no-calls',), False, None), ((), False, None),
                 # Without a terminal and without --calls the answer is no, and --max-calls-per-hour is not used.
                 (('--max-calls-per-hour', '9'), False, None))
        for flags, calls, limit in cases:
            name = 'opt' + secrets.token_hex(2)
            code, out, stderr, seen = self.attach('q1', name, *flags)
            need(code == 0 and isinstance(out, dict), f'attach {" ".join(flags)}', code, stderr[-400:])
            need(out.get('calls') is calls and out.get('max_calls_per_hour') == limit and 'max_calls_per_hour' in out,
                 'attach output gains calls and max_calls_per_hour (null when calls is false)', flags, out)
            record = self.adapter_record('q1', out['adapter_id'])
            need(record.get('calls') is calls and 'max_calls_per_hour' in record and
                 record['max_calls_per_hour'] == limit, 'the adapter record gains calls and max_calls_per_hour',
                 flags, record)
            if '--calls' not in flags and '--no-calls' not in flags:
                need(not seen, 'without a terminal, attach asks nothing and the answer is no', flags, stderr[-400:])

        # The prompt at a terminal.
        name = 'tty' + secrets.token_hex(2)
        code, out, tty, seen = self.attach('q1', name, terminal='y')
        need(code == 0 and seen and isinstance(out, dict) and out['calls'] is True and out['max_calls_per_hour'] == 100,
             f'at a terminal, attach asks "{CALLS_PROMPT}" and y enables calls (100 an hour)', code, seen,
             tty[-500:], out)
        name = 'tty' + secrets.token_hex(2)
        code, out, tty, seen = self.attach('q1', name, '--max-calls-per-hour', '9', terminal='n')
        need(code == 0 and seen and isinstance(out, dict) and out['calls'] is False and
             out['max_calls_per_hour'] is None,
             'declining the prompt: calls false, and --max-calls-per-hour is not used', code, seen, tty[-500:], out)
        name = 'tty' + secrets.token_hex(2)
        code, out, tty, seen = self.attach('q1', name, '--calls', terminal='y')
        need(code == 0 and not seen and out['calls'] is True, 'with --calls, no prompt at a terminal', code, seen,
             tty[-300:])

        # POST /v1/adapters/setup.
        agent = self.register('q1', 'setupcheck', 'quinn')
        for extra in ({'max_calls_per_hour': 5}, {'calls': False, 'max_calls_per_hour': 5},
                      {'calls': True, 'max_calls_per_hour': 0}, {'calls': True, 'max_calls_per_hour': 10001}):
            body = {'agent_id': agent['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
                    'expires_at': timestamp(900), **extra}
            status, value = q1.call('POST', '/v1/adapters/setup', body)
            need(status == 400, 'POST /v1/adapters/setup refuses max_calls_per_hour without calls, and outside 1 to '
                 '10,000', extra, status, value)
        raw, value = self.raw_setup('q1', agent['id'], calls=True)
        adapter = (value.get('credential') or {}).get('adapter') or {}
        need(adapter.get('calls') is True and adapter.get('max_calls_per_hour') == 100,
             'the setup response\'s adapter record: calls true, max_calls_per_hour 100 by default', adapter)
        q1.cli('adapter', 'revoke', adapter['id'])
        profile = self.root / 'setup-profile'
        configured = q1.cli('session', 'setup', '--harness', 'claude-code', '--directory', str(profile), '--agent',
                            agent['id'], '--integrations', str(INTEGRATIONS), '--runner', str(self.node), '--option',
                            f'executable={self.claude.path}')
        secret = json.loads((profile / 'credential.json').read_text())
        record = self.adapter_record('q1', secret['adapter']['id'])
        need(record.get('calls') is False and 'max_calls_per_hour' in record and record['max_calls_per_hour'] is None,
             'a credential from session setup has calls false (max_calls_per_hour null)', configured, record)

        # Re-attaching onto a never-connected credential.
        name = 'reuse' + secrets.token_hex(2)
        workspace = self.workspace('q1', name)
        code, first, stderr, _ = self.attach('q1', name, '--calls', '--max-calls-per-hour', '5', workspace=workspace)
        need(code == 0, 'setup: attach --calls --max-calls-per-hour 5', code, stderr[-300:])
        for flags in (('--no-calls',), ('--calls', '--max-calls-per-hour', '6'), ('--max-calls-per-hour', '6')):
            before = counts()
            code, out, stderr, _ = self.attach('q1', name, *flags, workspace=workspace)
            need(code == 1 and counts() == before, 'reusing a never-connected credential: a differing --calls, '
                 '--no-calls, or --max-calls-per-hour is refused with exit 1 before anything changes', flags, code,
                 stderr[-300:])
            need(re.search(r'\b5\b', stderr) and 'calls' in stderr, 'the refusal names the stored calls and '
                 'max_calls_per_hour', flags, stderr[-300:])
        for flags in (('--calls', '--max-calls-per-hour', '5'), ('--calls',), ()):
            code, out, stderr, _ = self.attach('q1', name, *flags, workspace=workspace)
            need(code == 0 and out['reused'] is True and out['adapter_id'] == first['adapter_id'] and
                 out['calls'] is True and out['max_calls_per_hour'] == 5,
                 'a matching flag (or none) is accepted, and the stored setting stands', flags, code, out,
                 stderr[-300:])
        code, out, tty, seen = self.attach('q1', name, workspace=workspace, terminal='n')
        need(code == 0 and not seen and isinstance(out, dict) and out['reused'] is True and out['calls'] is True and
             out['max_calls_per_hour'] == 5, 're-attaching with none of the three flags asks nothing, even at a '
             'terminal, and keeps the stored setting', code, seen, tty[-400:], out)

        # After replacement, the flags or the prompt decide again.
        name = 'rep' + secrets.token_hex(2)
        workspace = self.workspace('q1', name)
        code, first, stderr, _ = self.attach('q1', name, '--calls', '--max-calls-per-hour', '5', workspace=workspace)
        need(code == 0, 'setup: attach --calls', code, stderr[-300:])
        c = self.verified('q1', first['profile'], name)
        c.close()
        code, out, tty, seen = self.attach('q1', name, workspace=workspace, terminal='n')
        need(code == 0 and seen and out['reused'] is False and out['adapter_id'] != first['adapter_id'] and
             out['calls'] is False and out['max_calls_per_hour'] is None,
             'after replacement the old setting is not carried over: the prompt is asked again', code, seen,
             tty[-400:], out)

        # Without opt-in: each adapter call route answers 403 no_calls, and the tools return the no_calls text.
        noc = self.register('q1', 'nocalls', 'quinn')
        raw, _ = self.raw_setup('q1', noc['id'], calls=False)
        raw.ready()
        some = cid()
        for method, path, body in (('GET', '/adapter/v1/capabilities', None),
                                   ('POST', '/adapter/v1/calls', {'call_id': some, 'address': 'pat/tools',
                                                                  'operation': 'echo', 'input': {}}),
                                   ('GET', f'/adapter/v1/calls/{some}', None),
                                   ('POST', f'/adapter/v1/calls/{some}/cancel', {}),
                                   ('POST', '/adapter/v1/call-updates/next', {}),
                                   ('POST', f'/adapter/v1/call-updates/notification_{secrets.token_hex(16)}/forwarded',
                                    {})):
            status, value = raw.call(method, path, body)
            need(status == 403 and isinstance(value, dict) and value.get('code') == 'no_calls' and
                 isinstance(value.get('error'), str), 'without calls on the credential, each adapter call route '
                 'answers 403 {code: "no_calls", error}', path, status, value)
        c = self.s('qno')['consumer']
        listed = c.call('tools/list', {})
        names = {t['name'] for t in listed.get('tools', [])}
        need(set(TOOLS) <= names, 'the four tools are listed without opt-in', sorted(names))
        before = self.count('q1', 'outbound_calls')
        failed, value, _ = self.cc('qno', 'pat/tools', 'echo', {'text': 'x'})
        need(failed, 'call_capability without opt-in is a tool error', value)
        self.refusal(value, 'no_calls', 'call_capability without opt-in')
        need(self.count('q1', 'outbound_calls') == before, 'a no_calls refusal persists nothing')
        for name, arguments, keys in (('list_capabilities', {}, {'code', 'error', 'recovery'}),
                                      ('call_status', {'call_id': some}, {'call_id', 'code', 'error', 'recovery'}),
                                      ('call_cancel', {'call_id': some}, {'call_id', 'code', 'error', 'recovery'})):
            failed, value = self.tool(c, name, arguments)
            need(failed and isinstance(value, dict) and set(value) == keys and value['code'] == 'no_calls' and
                 value['error'] == TEXTS['no_calls'] and value['recovery'] == RECOVERY and
                 value.get('call_id', some) == some,
                 f'{name} without opt-in returns the refusal shape without address'
                 + (' or call_id' if 'call_id' not in keys else ''), failed, value)
        return '; '.join(notes)

    # --- listing -------------------------------------------------------------------------------------------

    def check_listing(self):
        ids = self.ids
        qa = self.listing('qa')
        found = {e['address']: e for e in qa['capabilities']}
        for name in ('tools', 'limited', 'agentonly', 'mixed', 'recheck', 'revoke'):
            need(f'pat/{name}' in found and found[f'pat/{name}']['host_id'] == ids['p1'],
                 'list_capabilities through policy', name, sorted(found))
        need('pat/private' not in found and not any(e['capability'] == 'dup' for e in qa['capabilities']),
             'an unshared capability is never listed through policy', sorted(found))
        need(found['pat/tools']['capability'] == 'tools' and
             {o['name'] for o in found['pat/tools']['operations']} >= {'echo', 'sleep', 'big'},
             'entries as in discover: operations with name, description, input_schema, read_only',
             found['pat/tools'])
        qb = {e['address'] for e in self.listing('qb')['capabilities']}
        need('pat/agentonly' not in qb and 'pat/mixed' in qb and 'pat/tools' in qb,
             'an agent: rule is listed for that agent and not for another agent of the same host', sorted(qb))

        pa = self.listing('pa')['capabilities']
        addresses = {e['address'] for e in pa}
        need({'pat/tools', 'pat/private'} <= addresses, 'list_capabilities through self from a trusted host',
             sorted(addresses))
        need({f"{ids['p1']}/dup", f"{ids['p4']}/dup"} <= addresses, 'an unsettled name on two hosts is listed by '
             'HOST_ID/CAPABILITY', sorted(addresses))
        need(not any(e['address'].count('/') > 1 or '/' in e['capability'] for e in pa),
             'sources opened to the host are never listed', sorted(addresses))
        pu = self.listing('pu')['capabilities']
        need(not any(e['host_id'] in (ids['p1'], ids['p4']) for e in pu),
             'nothing from an untrusted host of the same person', [e['address'] for e in pu])

        # from_agent in GET /peer/v1/capabilities.
        status, listing = wire(self.hosts['p1'], fixture_context(self.hosts['q1']), 'GET', '/peer/v1/capabilities')
        need(status == 200, 'GET /peer/v1/capabilities from q1', status, listing)
        by = {e['capability']: e for e in listing}
        qa_id = self.aid['qa']
        need([(v.get('kind'), v.get('network_id'), v.get('from_agent')) for v in by['agentonly']['via']] ==
             [('policy', self.team, qa_id)], 'a rule whose only matching principal is an agent: principal appears '
             'with from_agent set to that agent', by['agentonly']['via'])
        need(all('from_agent' in v and v['from_agent'] is None for v in by['tools']['via']),
             'a rule with another matching principal appears with from_agent null', by['tools']['via'])
        mixed = [(v['network_id'], v.get('from_agent')) for v in by['mixed']['via']]
        need(sorted(mixed) == sorted([(self.team, qa_id), (self.other, None)]) and
             [m[0] for m in mixed] == sorted(m[0] for m in mixed),
             'policy entries for each network, by network ID', mixed)
        status, listing = wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'GET', '/peer/v1/capabilities')
        selfs = [v for e in listing for v in e['via'] if v.get('kind') == 'self']
        need(status == 200 and selfs and all('from_agent' not in v for v in selfs),
             'self entries have no from_agent', status, selfs[:3])

        # discover and the owner's call ignore agent: entries.
        status, body = self.hosts['q1'].call('GET', f'/v1/discover?person=pat')
        need(status == 200, 'GET /v1/discover', status, body)
        names = {e['capability']: e for e in body['capabilities']}
        need('agentonly' not in names and 'mixed' in names and 'tools' in names,
             'discover omits capabilities left with no via entry whose from_agent is null', sorted(names))
        need(all(v.get('from_agent') is None for e in body['capabilities'] for v in e['via']),
             'discover ignores via entries whose from_agent is not null', names.get('mixed'))
        need(all('from_agent' in v for e in body['capabilities'] for v in e['via'] if v.get('kind') == 'policy'),
             'the remaining policy entries keep from_agent: null in discover JSON', names.get('mixed'))
        before = self.count('q1', 'outbound_calls')
        code, out, stdout, stderr = self.hosts['q1'].outcome('call', 'pat/agentonly', 'echo', '--input',
                                                             '{"text": "owner"}', '--wait', '5s')
        need(code != 0 and self.count('q1', 'outbound_calls') == before,
             'the owner CLI cannot call a capability shared only with an agent', code, stderr[-300:])
        return f"{len(qa['capabilities'])} entries for qa, {len(pa)} for pa (self), {len(pu)} for pu"

    # --- calls ---------------------------------------------------------------------------------------------

    def check_calls(self):
        ids, notes = self.ids, []
        f = self.fixture

        # 1. Within wait: origin on both hosts, the citation, no event, the notification seen.
        text = marker('basic')
        view, elapsed = self.ok_call('qa', 'pat/tools', 'echo', {'text': text})
        need(view['state'] == 'succeeded' and view['submit_state'] == 'accepted' and view['address'] == 'pat/tools'
             and view['peer_host_id'] == ids['p1'] and view['operation'] == 'echo' and view['error'] is None,
             'a call finishing within wait returns the final view', view)
        need(isinstance(view['result'], dict) and caps.first_text(view['result']) == text,
             'the result is the server\'s result object', view['result'])
        need(view['result_bytes'] == len(compact(view['result']).encode()), 'result_bytes is the length of the '
             'result\'s compact JSON encoding', view['result_bytes'], len(compact(view['result']).encode()))
        call = view['call_id']
        s = self.s('qa')
        record = self.inspect('q1', 'p1', call)
        origin = {'agent_id': s['agent_id'], 'session_id': s['session_id']}
        need(record.get('adapter_id') == s['adapter_id'], 'the outbound record gains adapter_id', record)
        need(record['request'].get('origin') == origin, 'origin {agent_id, session_id} stored in the outbound '
             'record\'s request', record['request'])
        need(record['request'].get('policy') == {'person_id': self.pat, 'network_id': self.team,
                                                 'version': self.version('p1')} and 'self' not in record['request'],
             'the citation is the first via entry that applies: pat\'s team policy', record['request'])
        got = self.received('p1', call)
        need(got and got['request'].get('origin') == origin, 'the receiver stores origin with the request, shown '
             'by calls received', got)
        need(len(self.executions('fx', text)) == 1, 'executed once')
        listed = self.hosts['q1'].cli('calls', 'list', '--limit', '1000')
        need(any((x.get('call') or {}).get('request', {}).get('call_id') == call for x in listed),
             'calls list shows agent calls with the owner\'s', listed[-2:])
        time.sleep(4)
        need(not self.events_for('qa', call), 'no call_update event for a call call_capability returned final')
        n = self.notification('q1', call)
        need(n and n[0], 'its call-update notification is seen', n)
        notes.append(f"first call's notification {n[2].get('state') if isinstance(n[2], dict) else n[2]}")
        if isinstance(n[2], dict):
            # The stored record may hold more; the route's `delivery` object is checked exactly (queued window).
            need(NOTIFICATION_KEYS <= set(n[2]), 'the stored notification record has the notification\'s fields',
                 n[2])
            # Q: the claim-while-waiting path (forwarded) and the GET-first path (unknown) are not distinguishable by
            # the caller; both are allowed here, and which ran is noted.

        # 2. A call taking 10 seconds, default wait.
        text = marker('ten')
        view, elapsed = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 10, 'text': text})
        need(view['state'] == 'succeeded' and 10 <= elapsed < 30, 'a 10-second call is returned final with the '
             'default wait', view['state'], elapsed)
        self.soft(elapsed < 14, 'fast status checks: a 10-second call returned within about 2 seconds of finishing',
                  elapsed)
        notes.append(f'10-second call returned in {elapsed:.1f}s')
        time.sleep(3)
        need(not self.events_for('qa', view['call_id']), 'no call_update event for the 10-second call')
        n = self.notification('q1', view['call_id'])
        need(n and n[0], 'the notification of a call returned final while waiting is seen', n)
        notes.append(f"10-second call's notification {n[2].get('state') if isinstance(n[2], dict) else n[2]}")

        # 3. Outlasting wait: pending note, one event, call_status with the result.
        text = marker('outlast')
        started = time.monotonic()
        view, elapsed = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 8, 'text': text}, wait=2)
        need(view['state'] in ('queued', 'running') and view['note'] == PENDING_NOTE and view['result'] is None and
             2 <= elapsed < 8, 'a call outlasting wait returns queued or running with the pending note', view,
             elapsed)
        call = view['call_id']
        params = self.wait_update('qa', call, timeout=40)
        meta, content = self.check_event('qa', params)
        need(meta_equal(meta['state'], 'succeeded') and meta_equal(meta['session_id'], self.s('qa')['session_id'])
             and meta_equal(meta['redelivered'], False) and meta_equal(meta['address'], 'pat/tools') and
             caps.first_text(content['result']) == 'slept ' + text,
             'the call_update event: meta and the call view with the result', meta, content)
        pend = self.pending('qa')
        held = [c for c in pend['calls'] if c['call_id'] == call]
        need(len(held) == 1 and held[0]['state'] == 'succeeded' and held[0]['session_id'] == self.s('qa')['session_id']
             and held[0]['redelivered'] is False, 'pending_work lists a call whose notification the session holds '
             'unseen', pend['calls'])
        time.sleep(3)
        need(len(self.events_for('qa', call)) == 1, 'exactly one call_update event', len(self.events_for('qa', call)))
        failed, final = self.status('qa', call)
        need(not failed and check_view(final, 'call_status')['state'] == 'succeeded' and
             caps.first_text(final['result']) == 'slept ' + text, 'call_status returns the result', final)
        n = self.notification('q1', call)
        need(n and n[0], 'call_status marks the notification seen', n)
        need(not [c for c in self.pending('qa')['calls'] if c['call_id'] == call],
             'a seen call is no longer pending')

        # 4. wait 0, 60, and 61.
        text = marker('w0')
        view, elapsed = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 3, 'text': text}, wait=0)
        need(view['state'] in PENDING_STATES and elapsed < 3, 'wait 0 returns at once', view['state'], elapsed)
        text = marker('w60')
        view, elapsed = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 3, 'text': text}, wait=60)
        need(view['state'] == 'succeeded' and elapsed < 20, 'wait 60 returns once final', view['state'], elapsed)
        text = marker('w61')
        before = self.count('q1', 'outbound_calls')
        failed, value, _ = self.cc('qa', 'pat/tools', 'echo', {'text': text}, wait=61)
        need(failed and 'call_capability' in json.dumps(value), 'wait 61 is invalid: a tool error naming the tool',
             failed, value)
        need(self.count('q1', 'outbound_calls') == before and not self.executions('fx', text),
             'invalid arguments call nothing')

        # 5. A source address.
        before = self.count('p2', 'outbound_calls')
        failed, value, _ = self.cc('pa', 'pat/srv/fx', 'echo', {'text': 'source'})
        need(failed and self.count('p2', 'outbound_calls') == before,
             'call_capability with a source address is a tool error that calls nothing', value)
        # The address schema admits a second /, so the daemon's source refusal and its text reach the agent.
        self.refusal(value, 'source', 'a source address through call_capability')
        agent = self.register('p2', 'praw', 'pat')
        raw, _ = self.raw_setup('p2', agent['id'])
        raw.ready()
        for address in ('pat/srv/fx', f"{ids['p1']}/srv/fx"):
            status, value = raw.call('POST', '/adapter/v1/calls', {'call_id': cid(), 'address': address,
                                                                   'operation': 'echo', 'input': {'text': 's'}})
            need(status == 400 and isinstance(value, dict) and value.get('code') == 'source' and
                 self.count('p2', 'outbound_calls') == before,
                 'POST /adapter/v1/calls: an address with two / is 400 {code: "source", error}, persisting nothing',
                 address, status, value)

        # 6. ambiguous and not_found.
        failed, value, _ = self.cc('pa', 'pat/dup', 'echo', {'text': 'dup'})
        need(failed, 'an ambiguous address is a tool error', value)
        self.refusal(value, 'ambiguous', 'ambiguous')
        need(value.get('candidates') == sorted([f"{ids['p1']}/dup", f"{ids['p4']}/dup"]),
             'ambiguous gives the sorted HOST_ID/CAPABILITY candidates', value)
        need(self.count('p2', 'outbound_calls') == before, 'ambiguous persists nothing')
        status, value = raw.call('POST', '/adapter/v1/calls', {'call_id': cid(), 'address': 'pat/dup',
                                                               'operation': 'echo', 'input': {}})
        need(status == 409 and value.get('code') == 'ambiguous' and value.get('candidates') ==
             sorted([f"{ids['p1']}/dup", f"{ids['p4']}/dup"]), 'the route: 409 {code: "ambiguous", error, '
             'candidates}', status, value)
        failed, value, _ = self.cc('pa', f"{ids['p4']}/dup", 'echo', {'text': marker('dup4')})
        need(not failed and value.get('state') == 'succeeded' and value.get('peer_host_id') == ids['p4'],
             'a candidate address resolves to its host (self citation)', value)
        dup4 = value['call_id']
        before = self.count('q1', 'outbound_calls')
        failed, value, _ = self.cc('qa', 'pat/nothing', 'echo', {})
        need(failed, 'not_found is a tool error', value)
        self.refusal(value, 'not_found', 'not_found')
        need(isinstance(value.get('unanswered'), list), 'not_found gives unanswered', value)
        need(self.count('q1', 'outbound_calls') == before, 'not_found persists nothing')
        record = self.inspect('p2', 'p4', dup4)
        need('self' in record['request'] and record['request']['self'] == {'person_id': self.pat,
                                                                        'network_id': self.team},
             'a self-authorized call cites self', record['request'])

        # 7. The receiver's 429 limit: refused at the first attempt, returned final, no event.
        first, _ = self.ok_call('qa', 'pat/limited', 'echo', {'text': marker('lim1')})
        need(first['state'] == 'succeeded', 'the first call within the receiver\'s limit of 1 an hour', first)
        text = marker('lim2')
        view, elapsed = self.ok_call('qa', 'pat/limited', 'echo', {'text': text})
        need(view['state'] == 'rejected' and view['submit_state'] == 'rejected' and isinstance(view['error'], str)
             and view['note'] == NEVER_RAN_NOTE and elapsed < 20,
             'the receiver\'s 429 limit makes the call rejected, returned final with the never-ran note', view,
             elapsed)
        need(not self.executions('fx', text), 'a rejected call never ran')
        time.sleep(4)
        need(not self.events_for('qa', view['call_id']), 'no call_update event for a call refused at its first '
             'attempt')
        return '; '.join(notes)

    # --- agent rules and repeats ---------------------------------------------------------------------------

    def check_agent_rules(self):
        ids = self.ids
        view, _ = self.ok_call('qa', 'pat/agentonly', 'echo', {'text': marker('ao')})
        need(view['state'] == 'succeeded', 'an agent: rule authorizes its agent', view)
        failed, value, _ = self.cc('qb', 'pat/agentonly', 'echo', {'text': marker('ao-b')})
        need(failed, 'an agent: rule refuses another agent of the same host', value)
        self.refusal(value, 'not_found', 'agent: rule for another agent')

        # Citations: qb only through `other`; qa the first entry in listed order.
        view, _ = self.ok_call('qb', 'pat/mixed', 'echo', {'text': marker('mx-b')})
        record = self.inspect('q1', 'p1', view['call_id'])
        need(view['state'] == 'succeeded' and record['request'].get('policy', {}).get('network_id') == self.other,
             'the citation is the first via entry that applies to this agent (qb: other)', record['request'])
        view, _ = self.ok_call('qa', 'pat/mixed', 'echo', {'text': marker('mx-a')})
        record = self.inspect('q1', 'p1', view['call_id'])
        need(record['request'].get('policy', {}).get('network_id') == min(self.team, self.other),
             'qa cites the first policy entry in listed order (by network ID)', record['request'])

        # The peer route: only that host and agent.
        s_a, s_b = self.s('qa'), self.s('qb')
        for origin, allowed in (({'agent_id': s_a['agent_id'], 'session_id': s_a['session_id']}, True),
                                ({'agent_id': s_b['agent_id'], 'session_id': s_b['session_id']}, False),
                                (None, False)):
            body = {'call_id': cid(), 'capability': 'agentonly', 'operation': 'echo',
                    'input': {'text': marker('peer')}, 'deadline': timestamp(300),
                    'policy': {'person_id': self.pat, 'network_id': self.team, 'version': self.version('p1')}}
            if origin:
                body['origin'] = origin
            status, record = wire(self.hosts['p1'], fixture_context(self.hosts['q1']), 'POST', '/peer/v1/calls', body)
            if allowed:
                need(status == 200, 'agent:HOST/AGENT matches a call from that host with that origin agent', status,
                     record)
            else:
                need(status in (403, 404) and not self.executions('fx', body['input']['text']),
                     'agent:HOST/AGENT matches no other origin, and no call without one', origin, status, record)

        # Repeats through the route.
        raw = self.qraw_session()
        text = marker('rep')
        body = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'echo', 'input': {'text': text}}
        status, first = raw.call('POST', '/adapter/v1/calls', body)
        need(status == 200, 'POST /adapter/v1/calls returns 200 with the call view', status, first)
        check_view(first, 'POST /adapter/v1/calls')
        status, again = raw.call('POST', '/adapter/v1/calls', body)
        need(status == 200 and again['call_id'] == body['call_id'] and again['created_at'] == first['created_at'],
             'an identical repeat returns the existing call view', status, again)
        status, changed = raw.call('POST', '/adapter/v1/calls', {**body, 'input': {'text': text + 'x'}})
        need(status == 409 and changed.get('code') == 'conflict', 'a changed repeat is 409 {code: "conflict"}',
             status, changed)
        rows = self.count('q1', 'adapter_calls', 'WHERE adapter_id = ?', (raw.adapter['id'],))
        need(rows == 1, 'repeats are not counted (one adapter_calls row)', rows)
        wait_for(lambda: raw.call('GET', f"/adapter/v1/calls/{body['call_id']}")[1].get('state') == 'succeeded',
                 timeout=30, message='the route call succeeds')
        need(len(self.executions('fx', text)) == 1, 'a repeated call_id executes once')

        # Repeats through call_capability with call_id given.
        text = marker('toolrep')
        given = cid()
        view, _ = self.ok_call('qa', 'pat/tools', 'echo', {'text': text}, call_id=given)
        need(view['call_id'] == given, 'call_capability uses the given call_id', view)
        again, _ = self.ok_call('qa', 'pat/tools', 'echo', {'text': text}, call_id=given)
        need(again['call_id'] == given and again['created_at'] == view['created_at'] and
             again['state'] == 'succeeded', 'call_capability with the same call_id returns the existing call', again)
        failed, value, _ = self.cc('qa', 'pat/tools', 'echo', {'text': text + 'x'}, call_id=given)
        need(failed, 'a changed repeat through call_capability is a tool error', value)
        self.refusal(value, 'conflict', 'a changed repeat')
        need(len(self.executions('fx', text)) == 1, 'executed once')
        return ''

    # --- the queued window ---------------------------------------------------------------------------------

    def check_queued(self):
        f = self.fixture
        exp_agent = self.register('q1', 'qexp', 'quinn')
        expiring, _ = self.raw_setup('q1', exp_agent['id'], expires_in=45)
        expiring.ready()
        # A rejection at submission: the receiver's 413 for an input over the rule's max_input_bytes (65,536).
        text = marker('sub413')
        view, _ = self.ok_call('qa', 'pat/tools', 'echo', {'text': text + 'x' * 70000})
        need(view['state'] == 'rejected' and view['submit_state'] == 'rejected' and view['note'] == NEVER_RAN_NOTE and
             isinstance(view['error'], str) and view['error'], 'rejected at submission (the receiver\'s 413), with '
             'the never-ran note', view)
        # The operation is not checked against the entry's operations: the receiver refuses it, and the call is
        # rejected.
        text = marker('sub404')
        before = self.count('q1', 'outbound_calls')
        view, _ = self.ok_call('qa', 'pat/tools', 'purge', {'text': text})
        need(view['state'] == 'rejected' and view['submit_state'] == 'rejected' and view['note'] == NEVER_RAN_NOTE
             and self.count('q1', 'outbound_calls') == before + 1 and not self.executions('fx', text),
             'an operation the capability does not list is submitted and rejected by the receiver', view)

        started = self.fill_slots(60)
        texts = {k: marker(k) for k in ('cq', 'rc', 'ex')}
        queued, _ = self.ok_call('qa', 'pat/tools', 'echo', {'text': texts['cq']}, wait=0)
        need(queued['state'] == 'queued' and queued['note'] == PENDING_NOTE, 'queued behind 4 running calls',
             queued)
        failed, cancelled = self.tool(self.s('qa')['consumer'], 'call_cancel', {'call_id': queued['call_id']})
        need(not failed, 'call_cancel returns the call view, not a tool error', cancelled)
        check_view(cancelled, 'call_cancel')
        view = self.final_view('qa', queued['call_id'], timeout=30)
        need(view['state'] == 'cancelled' and view['note'] == NEVER_RAN_NOTE,
             'call_cancel while queued: cancelled, with the never-ran note', view)

        rechecked, _ = self.ok_call('qa', 'pat/recheck', 'echo', {'text': texts['rc']}, wait=0)
        need(rechecked['state'] == 'queued', 'queued behind 4 running calls', rechecked)
        body = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'echo', 'input': {'text': texts['ex']}}
        status, expiring_view = expiring.call('POST', '/adapter/v1/calls', body)
        need(status == 200 and expiring_view.get('state') == 'queued', 'a call queued until its deadline (capped by '
             'the credential\'s expiry, 45 seconds)', status, expiring_view)
        texts['ex2'] = marker('ex2')
        body2 = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'echo', 'input': {'text': texts['ex2']}}
        status, second_view = expiring.call('POST', '/adapter/v1/calls', body2)
        need(status == 200 and second_view.get('state') == 'queued', 'a second call queued until its deadline',
             status, second_view)
        deadline = caps.parse_time(expiring_view['deadline'])
        need(deadline.timestamp() <= time.time() + 50, 'the deadline is capped by the credential\'s expires_at',
             expiring_view['deadline'])
        self.unshare('p1', 'recheck', 'quinn')

        view = self.final_view('qa', rechecked['call_id'], timeout=120)
        need(view['state'] == 'rejected' and view['error'] == LAPSED and view['note'] == NEVER_RAN_NOTE,
             'rejected at the recheck before start, with the never-ran note', view)
        # The expired call, through another credential of the same agent after the first expired.
        wait_for(lambda: time.time() > deadline.timestamp() + 2, timeout=90, message='the credential expired')
        later, _ = self.raw_setup('q1', exp_agent['id'])
        later.ready()

        # Both notifications are created after their session's authorization ended (the credential expired). The
        # second is seen by the next session's GET of a final view (bound to it and seen at once, so never claimed);
        # the first goes to that session through call-updates/next, redelivered false.
        def second_final():
            status, v = later.call('GET', f"/adapter/v1/calls/{body2['call_id']}")
            return v if status == 200 and v.get('state') in FINAL else None
        view = check_view(wait_for(second_final, timeout=60, message='the second expiring call final'))
        need(view['state'] == 'expired', 'the second call expired', view)
        n = self.notification('q1', body2['call_id'])
        need(n and n[0], 'a late notification no session holds is seen by the next session\'s final call view', n)
        rows = db_rows(self.hosts['q1'], 'SELECT session_id FROM call_update_notifications WHERE call_id = ?',
                       (body2['call_id'],))
        need(rows and rows[0][0] == later.adapter['session_id'], 'it is bound to that session', rows,
             later.adapter['session_id'])

        def claim():
            status, value = later.call('POST', '/adapter/v1/call-updates/next', {})
            need(status == 200, 'call-updates/next answers 200 for a verified session', status, value)
            return value
        claimed = wait_for(claim, timeout=60, message='the late call update claimed by the next session')
        need(isinstance(claimed, dict) and set(claimed) == {'delivery', 'call', 'redelivered'},
             'call-updates/next returns {delivery, call, redelivered}', claimed)
        delivery = claimed['delivery']
        need(isinstance(delivery, dict) and set(delivery) == NOTIFICATION_KEYS and
             NOTIFICATION_ID.fullmatch(delivery['id']) and delivery['call_id'] == body['call_id'] and
             delivery['peer_host_id'] == self.ids['p1'] and delivery['state'] == 'unknown',
             'the notification record {id, peer_host_id, call_id, adapter_id, session_id, state, created_at, '
             'updated_at}, claimed while unknown', delivery)
        view = check_view(claimed['call'], 'call-updates/next')
        need(claimed['redelivered'] is False and view['offset'] == 0 and view['state'] == 'expired' and
             view['note'] == NEVER_RAN_NOTE, 'a late arrival: redelivered false; the call view at offset 0, expired '
             'with the never-ran note', claimed)
        status, view = later.call('GET', f"/adapter/v1/calls/{body['call_id']}")
        need(status == 200 and check_view(view)['state'] == 'expired',
             'GET answers for calls made through any credential of the agent', status, view)
        status, value = later.call('POST', f"/adapter/v1/call-updates/{delivery['id']}/forwarded", {})
        need(status == 200, 'POST /adapter/v1/call-updates/{id}/forwarded', status, value)
        status, again = later.call('POST', f"/adapter/v1/call-updates/{delivery['id']}/forwarded", {})
        need(status == 200, 'forwarded is idempotent', status, again)
        status, value = self.qraw_session().call('POST', f"/adapter/v1/call-updates/{delivery['id']}/forwarded", {})
        need(status == 404, 'forwarded answers 404 for another credential', status, value)
        n = self.notification('q1', body['call_id'])
        need(n and isinstance(n[2], dict) and n[2].get('state') == 'forwarded', 'the notification is forwarded', n)
        time.sleep(2)
        status, value = later.call('POST', '/adapter/v1/call-updates/next', {})
        need(status == 200 and value is None, 'the notification seen by call_status is never claimed afterwards',
             status, value)
        for key, text in texts.items():
            need(not f.calls('fx', marker=text), 'a call that never ran is never executed', key)
        self.share('p1', 'recheck', 'quinn')
        return ''

    # --- running calls -------------------------------------------------------------------------------------

    def check_running(self):
        f = self.fixture
        text = marker('cr')
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 30, 'text': text}, wait=2)
        need(view['state'] == 'running', 'a running call', view)
        failed, cancelled = self.tool(self.s('qa')['consumer'], 'call_cancel', {'call_id': view['call_id']})
        need(not failed, 'call_cancel returns the call view', cancelled)
        check_view(cancelled, 'call_cancel')
        final = self.final_view('qa', view['call_id'], timeout=60)
        need(final['state'] == 'uncertain' and final['error'] == 'cancel_requested' and
             final['note'] == UNCERTAIN_NOTE, 'call_cancel while running: uncertain with the uncertain note', final)
        need(len(f.calls('fx', marker=text)) == 1, 'executed exactly once')

        text = marker('rs')
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 20, 'text': text}, wait=2)
        need(view['state'] == 'running', 'a running call', view)
        self.restart('p1')
        final = self.final_view('qa', view['call_id'], timeout=90)
        need(final['state'] == 'uncertain' and final['error'] == 'daemon_restarted' and
             final['note'] == UNCERTAIN_NOTE, 'uncertain after the receiver restarts mid-call', final)
        time.sleep(8)
        need(len(f.calls('fx', marker=text)) == 1, 'exactly one execution recorded by the fixture',
             f.calls('fx', marker=text))
        return ''

    # --- rate limit ----------------------------------------------------------------------------------------

    def check_rate_limit(self):
        q1, ids = self.hosts['q1'], self.ids
        s = self.s('qlim')
        c = s['consumer']
        wait_for(lambda: q1.call('POST', f'/v1/directory/refresh?network={self.team}', {})[0] == 200 and
                 any(x.get('address') == 'pat/srv' for x in q1.directory(self.team)[1].get('agents', [])),
                 timeout=40, message='pat/srv in q1\'s directory')
        failed, sent = self.tool(c, 'send', {'to': 'pat/srv', 'network': self.team, 'content': 'one'})
        need(not failed, 'a send by address', sent)

        # Call A: its first submit response is lost, so the daemon retries it.
        text_a = marker('ra')
        relay = DropCallResponse(self.hosts['p1'])
        identity = self.hosts['p1'].call('GET', '/v1/host')[1]
        q1.configure(self.hosts['p1'], identity, relay.address)
        try:
            view_a, _ = self.ok_call('qlim', 'pat/tools', 'echo', {'text': text_a}, wait=0)
            relay.close()
        finally:
            q1.configure(self.hosts['p1'], identity)
        need(view_a['submit_state'] == 'unknown' and view_a['state'] == 'submitting',
             'a lost submit response: submitting', view_a)
        view = self.final_view('qlim', view_a['call_id'], timeout=90)
        need(view['state'] == 'succeeded' and len(self.executions('fx', text_a)) == 1,
             'recovered by the daemon\'s retry, executed once', view)
        rows = self.count('q1', 'adapter_calls', 'WHERE adapter_id = ?', (s['adapter_id'],))
        need(rows == 1, 'daemon retries are not counted', rows)

        text_b = marker('rb')
        view_b, _ = self.ok_call('qlim', 'pat/tools', 'echo', {'text': text_b})
        need(view_b['state'] == 'succeeded', 'the second call (sends and retries not counted)', view_b)
        failed, again, _ = self.cc('qlim', 'pat/tools', 'echo', {'text': text_b}, call_id=view_b['call_id'])
        need(not failed and again.get('call_id') == view_b['call_id'], 'a repeat at the limit returns the existing '
             'call (repeats are not counted)', again)
        before = (self.count('q1', 'outbound_calls'), self.count('q1', 'adapter_calls'))
        text_c = marker('rc')
        failed, value, _ = self.cc('qlim', 'pat/tools', 'echo', {'text': text_c})
        need(failed, 'the third call is a tool error', value)
        self.refusal(value, 'rate_limited', 'the third call')
        need(type(value.get('retry_after')) is int and 1 <= value['retry_after'] <= 3600,
             'retry_after is a whole number of seconds, at least 1', value)
        need((self.count('q1', 'outbound_calls'), self.count('q1', 'adapter_calls')) == before and
             not self.executions('fx', text_c), 'rate_limited persists nothing')
        failed, sent = self.tool(c, 'send', {'to': 'pat/srv', 'network': self.team, 'content': 'two'})
        need(not failed, 'calls do not count against max_sends_per_hour', sent)
        failed, sent = self.tool(c, 'send', {'to': 'pat/srv', 'network': self.team, 'content': 'three'})
        need(failed and 'rate_limited' in json.dumps(sent), 'sends keep their own limit', sent)
        return ''

    # --- results -------------------------------------------------------------------------------------------

    def check_results(self):
        notes = []
        probe, _ = self.ok_call('qa', 'pat/tools', 'big', {'bytes': 1000})
        overhead = probe['result_bytes'] - 1000
        exact, _ = self.ok_call('qa', 'pat/tools', 'big', {'bytes': INLINE - overhead})
        need(exact['result_bytes'] == INLINE and exact['truncated'] is False and isinstance(exact['result'], dict),
             'a result text of exactly 65,536 bytes is inline', {k: exact[k] for k in ('result_bytes', 'truncated')})
        more, _ = self.ok_call('qa', 'pat/tools', 'big', {'bytes': INLINE - overhead + 1})
        need(more['result_bytes'] == INLINE + 1 and more['truncated'] is True and more['offset'] == 0 and
             more['note'] == PARTS_NOTE, 'one byte more is in parts', {k: more[k] for k in ('result_bytes',
                                                                                             'truncated', 'note')})
        text = self.page('qa', more)
        need(len(text.encode()) == INLINE + 1 and caps.first_text(json.loads(text)) == 'b' * (INLINE - overhead + 1),
             'the parts concatenate to the result text')

        # A multi-byte character at a part boundary: with 2-byte characters, one of pad 0 or 1 puts byte 65,536
        # inside a character.
        inside, inside_pad = None, None
        for pad in (0, 1):
            view, _ = self.ok_call('qa', 'pat/tools', 'big', {'bytes': 40000, 'unit': 'é', 'pad': pad})
            data = self.page('qa', view).encode()
            need(len(data) == view['result_bytes'], 'result_bytes is the result text\'s length in bytes',
                 len(data), view['result_bytes'])
            need(caps.first_text(json.loads(data)) == 'a' * pad + 'é' * 40000, 'the parts concatenate to the result '
                 'text, multi-byte characters intact')
            if (data[INLINE] & 0xC0) == 0x80:
                inside, inside_pad = view, pad
                break
        need(inside is not None, 'a multi-byte character can reach a part boundary: the result text keeps é as '
             'UTF-8 (it is not ASCII-escaped)', 'result text is ASCII' if data.isascii() else 'not ASCII',
             data[INLINE - 8:INLINE + 8])
        need(len(inside['result_part'].encode()) == INLINE - 1 and inside['next_offset'] == INLINE - 1,
             'a part ends on a UTF-8 character boundary, the longest such piece', len(inside['result_part'].encode()),
             inside['next_offset'])
        for offset in (INLINE, inside['result_bytes'] + 1):
            failed, value = self.status('qa', inside['call_id'], offset)
            need(failed, 'call_status with an offset inside a character or beyond result_bytes is a tool error',
                 offset, value)

        # Route-level offsets (400).
        raw = self.qraw_session()
        body = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'big',
                'input': {'bytes': 40000, 'unit': 'é', 'pad': inside_pad}}
        status, view = raw.call('POST', '/adapter/v1/calls', body)
        need(status == 200, 'POST /adapter/v1/calls', status, view)
        final = wait_for(lambda: (r := raw.call('GET', f"/adapter/v1/calls/{body['call_id']}"))[1].get('state') in
                         FINAL and r[1], timeout=30, message='the route call final')
        for offset in (INLINE, final['result_bytes'] + 1):
            status, value = raw.call('GET', f"/adapter/v1/calls/{body['call_id']}?offset={offset}")
            need(status == 400, 'GET /adapter/v1/calls/{id}?offset= inside a UTF-8 character or beyond result_bytes '
                 'is 400', offset, status, value)
        status, value = raw.call('GET', f"/adapter/v1/calls/{body['call_id']}?offset={INLINE - 1}")
        need(status == 200 and value['offset'] == INLINE - 1 and value['truncated'] is True,
             'a part from a valid offset', status, str(value)[:300])

        # The canonical result text: sorted keys, raw UTF-8, the specified escapes; the same result_bytes and parts
        # from Go and Rust daemons, so it is compared with this suite's own encoding of the parsed result.
        for repeat in (1, 3000):
            view, _ = self.ok_call('qa', 'pat/tools', 'canon', {'repeat': repeat})
            need(view['state'] == 'succeeded', 'the canon call succeeds', {k: view[k] for k in ('state', 'error')})
            if view['truncated']:
                text = self.page('qa', view)
                expected = canonical(json.loads(text))
            else:
                expected = text = canonical(view['result'])
            need(text == expected and view['result_bytes'] == len(expected.encode()),
                 'the result text is the canonical encoding (sorted keys, raw UTF-8, only the specified escapes)',
                 repeat, view['result_bytes'], len(expected.encode()), first_difference(text, expected))
            need(json.loads(text)['content'][0]['text'] == CANON_TEXT * repeat, 'the result is the server\'s')
        notes.append('canonical result text matches')

        # A non-zero offset before there is a result is 400.
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 4, 'text': marker('pre')}, wait=0)
        need(view['result_bytes'] is None, 'no result yet', view)
        failed, value = self.status('qa', view['call_id'], 1)
        need(failed, 'call_status with a non-zero offset before there is a result is a tool error', value)
        failed, value = self.status('qa', view['call_id'], 0)
        need(not failed and check_view(value)['offset'] == 0, 'offset 0 before there is a result', value)
        body = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'sleep',
                'input': {'seconds': 4, 'text': marker('pre2')}}
        status, value = raw.call('POST', '/adapter/v1/calls', body)
        need(status == 200 and value.get('result_bytes') is None, 'a call without a result yet', status, value)
        status, value = raw.call('GET', f"/adapter/v1/calls/{body['call_id']}?offset=1")
        need(status == 400, 'GET with a non-zero offset before there is a result is 400', status, value)

        # result_too_large.
        view, _ = self.ok_call('qa', 'pat/tools', 'big', {'bytes': 1100000})
        need(view['state'] == 'failed' and view['error'] == 'result_too_large' and view['result'] is None and
             view['note'] is None, 'result_too_large is failed', {k: view[k] for k in ('state', 'error', 'note')})
        return '; '.join(notes)

    def page(self, name, view):
        """Concatenate the parts of a result from offset 0 with call_status until next_offset is null."""
        if not view['truncated']:
            return compact(view['result'])
        parts, current = [], view
        while True:
            part = current['result_part']
            need(len(part.encode()) <= INLINE, 'a part is at most 65,536 bytes', len(part.encode()))
            parts.append(part)
            if current['next_offset'] is None:
                break
            need(current['next_offset'] == current['offset'] + len(part.encode()), 'next_offset is the offset after '
                 'the part', current['offset'], current['next_offset'])
            failed, current = self.status(name, view['call_id'], current['next_offset'])
            need(not failed, 'call_status with offset', current)
            check_view(current, 'call_status with offset')
            need(current['truncated'] is True and current['result'] is None, 'a later part is in parts', current)
        return ''.join(parts)

    # --- call updates and pending work ---------------------------------------------------------------------

    def check_updates(self):
        q1 = self.hosts['q1']
        notes = []
        # 409 before verification; the other call routes work.
        agent = self.register('q1', 'unverified', 'quinn')
        raw, _ = self.raw_setup('q1', agent['id'])
        status, value = raw.call('POST', '/adapter/v1/call-updates/next', {})
        need(status == 409 and value == {'code': 'conflict', 'error': 'channel not verified'},
             'call-updates/next answers 409 before verification', status, value)
        status, value = raw.call('GET', '/adapter/v1/capabilities')
        need(status == 200 and isinstance(value, dict) and set(value) == LISTING_KEYS,
             'GET /adapter/v1/capabilities works before verification', status, str(value)[:300])
        status, value = raw.call('POST', '/adapter/v1/calls', {'call_id': cid(), 'address': 'pat/tools',
                                                               'operation': 'echo', 'input': {'text': 'nv'}})
        need(status == 200, 'POST /adapter/v1/calls works before verification', status, value)

        # mark_seen.
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 3, 'text': marker('ms')}, wait=0)
        self.wait_update('qa', view['call_id'], timeout=40)
        c = self.s('qa')['consumer']
        failed, value = self.tool(c, 'mark_seen', {'ids': [view['call_id']]})
        need(not failed and value == {'seen': [view['call_id']]}, 'mark_seen accepts call IDs', failed, value)
        need(self.notification('q1', view['call_id'])[0], 'mark_seen marks the notification seen')
        need(not [x for x in self.pending('qa')['calls'] if x['call_id'] == view['call_id']],
             'a seen call is not pending')
        failed, value = self.tool(c, 'mark_seen', {'ids': [view['call_id']]})
        need(not failed and value == {'seen': []}, 'mark_seen ignores IDs already seen', value)

        # Redelivery to the next attachment after replacement, at most 3 times.
        view, _ = self.ok_call('qred', 'pat/tools', 'sleep', {'seconds': 3, 'text': marker('rd')}, wait=0)
        call = view['call_id']
        params = self.wait_update('qred', call, timeout=40)
        meta, _ = self.check_event('qred', params)
        need(meta_equal(meta['redelivered'], False), 'the first event: redelivered false', meta)
        notification = meta['notification_id']
        for attempt in (1, 2, 3):
            self.replace('qred')
            params = self.wait_update('qred', call, timeout=40)
            meta, content = self.check_event('qred', params, f'redelivery {attempt}')
            need(meta_equal(meta['redelivered'], True) and meta_equal(meta['notification_id'], notification) and
                 content['state'] == 'succeeded' and meta_equal(meta['session_id'], self.s('qred')['session_id']),
                 'redelivered to the next attachment with redelivered true and the same notification', attempt, meta)
            pend = [x for x in self.pending('qred')['calls'] if x['call_id'] == call]
            need(len(pend) == 1 and pend[0]['redelivered'] is True, 'pending_work: redelivered true', pend)
        self.replace('qred')
        time.sleep(8)
        need(not self.events_for('qred', call), 'redelivered at most 3 times')
        need(not [x for x in self.pending('qred')['calls'] if x['call_id'] == call],
             'past the limit, the notification is no longer offered')
        n = self.notification('q1', call)
        need(n and n[1] == 3 and not n[0], 'redeliveries 3, unseen', n)

        # A call made by a session that has ended: pending_work, session pending, call_status, the late event.
        s = self.s('qend')
        old = dict(s)
        view, _ = self.ok_call('qend', 'pat/tools', 'sleep', {'seconds': 40, 'text': marker('end')}, wait=2)
        need(view['state'] in PENDING_STATES, 'a call still running', view)
        call = view['call_id']
        s['consumer'].close()
        q1.cli('adapter', 'revoke', old['adapter_id'])
        self.replace_after_revoke('qend')
        pend = self.pending('qend')
        mine = [x for x in pend['calls'] if x['call_id'] == call]
        need(len(mine) == 1 and mine[0]['session_id'] == old['session_id'] and mine[0]['state'] in PENDING_STATES and
             mine[0]['redelivered'] is False and mine[0]['address'] == 'pat/tools' and mine[0]['operation'] == 'sleep',
             'pending_work lists an unfinished call made by the agent\'s ended session, with its session_id', pend)
        failed, current = self.status('qend', call)
        need(not failed and check_view(current)['call_id'] == call and current['state'] in PENDING_STATES,
             'call_status from the new session answers for the earlier session\'s call', current)
        need(caps.parse_time(mine[0]['created_at']) == caps.parse_time(current['created_at']) and
             caps.parse_time(mine[0]['deadline']) == caps.parse_time(current['deadline']),
             'pending calls carry the view\'s created_at and deadline', mine[0], current)
        workspace = self.s('qend')['workspace']
        result = q1.run('session', 'pending', '--json', cwd=str(workspace))
        need(result.returncode == 0 and json.loads(result.stdout or 'null') == pend,
             'session pending --json includes calls', result.returncode, result.stdout[-500:], result.stderr[-300:])
        result = q1.run('session', 'pending', '--hook', cwd=str(workspace))
        problem = self.hook_problem(result.stdout, pend)
        need(result.returncode == 0 and problem is None, 'session pending --hook with the calls text', problem,
             result.stdout[-600:])
        params = self.wait_update('qend', call, timeout=90)
        meta, content = self.check_event('qend', params, 'a late call update')
        need(meta_equal(meta['redelivered'], False) and content['state'] == 'succeeded',
             'a call finishing after its session ended reaches the next verified session, redelivered false', meta)
        need(meta_equal(meta['session_id'], self.s('qend')['session_id']),
             'meta.session_id is the session that holds the notification, not the one that made the call', meta,
             old['session_id'])
        failed, final = self.status('qend', call)
        need(not failed and final['state'] == 'succeeded', 'call_status answers with the result', final)
        need(not [x for x in self.pending('qend')['calls'] if x['call_id'] == call], 'then nothing is pending')
        return '; '.join(notes)

    def replace_after_revoke(self, name):
        s = self.s(name)
        code, out, text, _ = self.attach(s['host'], name, '--calls', workspace=s['workspace'])
        need(code == 0 and out['agent']['id'] == s['agent_id'] and out['session_id'] != s['session_id'],
             'attach after revocation sets up a new session for the same agent', code, text[-400:])
        s.update({'session_id': out['session_id'], 'adapter_id': out['adapter_id'], 'profile': out['profile'],
                  'out': out})
        s['consumer'] = self.verified(s['host'], out['profile'], name)

    @staticmethod
    def hook_problem(stdout, pending):
        try:
            value = json.loads(stdout)
        except ValueError:
            return 'stdout is not one JSON object'
        output = value.get('hookSpecificOutput') if isinstance(value, dict) else None
        if not (isinstance(output, dict) and output.get('hookEventName') == 'SessionStart' and
                isinstance(output.get('additionalContext'), str)):
            return 'not {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": TEXT}}'
        text = output['additionalContext']
        if not text.startswith(HOOK_LEAD):
            return 'additionalContext does not start with the slice 2 lead sentence'
        rest = text[len(HOOK_LEAD):]
        try:
            if json.loads(rest) != pending:
                return 'the object after the lead differs from pending_work'
        except ValueError:
            return 'the text after the lead is not JSON'
        if rest != compact(json.loads(rest)) and rest != json.dumps(json.loads(rest), separators=(',', ':')):
            return 'the object is not compact JSON'
        return None

    # --- revocation ----------------------------------------------------------------------------------------

    def check_revocation(self):
        text = marker('rv')
        view, _ = self.ok_call('qa', 'pat/revoke', 'sleep', {'seconds': 8, 'text': text}, wait=2)
        need(view['state'] == 'running', 'a running call', view)
        self.unshare('p1', 'revoke', 'quinn')
        failed, value, _ = self.cc('qa', 'pat/revoke', 'echo', {'text': marker('rv2')})
        need(failed, 'after unshare, call_capability is a tool error', value)
        self.refusal(value, 'not_found', 'after unshare')
        final = self.final_view('qa', view['call_id'], timeout=60)
        need(final['state'] == 'succeeded' and len(self.executions('fx', text)) == 1,
             'a running call finishes after unshare', final)
        return ''

    # --- slice 1: a person whose label contains / --------------------------------------------------------------

    def check_slash_label(self):
        ids, q1, s2 = self.ids, self.hosts['q1'], self.hosts['s2']
        sx, source = f"{ids['s1']}/sx", f"{ids['s1']}/sagent/fx"
        status, body = q1.call('GET', f'/v1/discover?network={self.team}')
        need(status == 200, 'GET /v1/discover', status, body)
        mine = [e for e in body['capabilities'] if e['host_id'] == ids['s1']]
        need([e['address'] for e in mine] == [sx], 'discover addresses the capabilities of a person whose label '
             'contains / by host ID', [e['address'] for e in mine])
        need(not any(e['address'].startswith('ops/') for e in body['capabilities']), 'never by the label',
             [e['address'] for e in body['capabilities']])
        text = marker('slash')
        code, out, stdout, stderr = q1.outcome('call', sx, 'echo', '--input', json.dumps({'text': text}), '--wait',
                                               '30s')
        need(code == 0 and caps.dig(out, 'status', 'state') == 'succeeded', 'callable by HOST_ID/CAPABILITY', code,
             stderr[-300:], out)
        status, body = s2.call('GET', f'/v1/discover?network={self.team}')
        need(status == 200, 'GET /v1/discover on s2', status, body)
        addresses = {(e['kind'], e['address']) for e in body['capabilities'] if e['host_id'] == ids['s1']}
        need(addresses == {('capability', sx), ('source', source)}, 'the person\'s own trusted machine sees the '
             'capability and the source by host ID', sorted(addresses))
        for target in (sx, source):
            text = marker('slash2')
            code, out, stdout, stderr = s2.outcome('call', target, 'echo', '--input', json.dumps({'text': text}),
                                                   '--wait', '30s')
            need(code == 0 and caps.dig(out, 'status', 'state') == 'succeeded' and
                 len(self.fixture.calls('sfx', marker=text)) == 1, 'callable by its host-ID address', target,
                 code, stderr[-300:])
        before = self.count('q1', 'outbound_calls')
        code, out, stdout, stderr = q1.outcome('call', 'ops/sam/sx', 'echo', '--input', '{"text": "no"}', '--wait', '5s')
        need(code != 0 and self.count('q1', 'outbound_calls') == before, 'the label is never used as PERSON',
             code, stderr[-300:])
        if 'qa' in self.sessions:
            entries = {e['address'] for e in self.listing('qa')['capabilities']}
            need(sx in entries, 'list_capabilities addresses it by host ID too', sorted(entries))
            view, _ = self.ok_call('qa', sx, 'echo', {'text': marker('slash3')})
            need(view['state'] == 'succeeded', 'call_capability by host ID', view)
        return ''

    # --- unanswered ----------------------------------------------------------------------------------------

    def check_unanswered(self):
        self.hosts['p4'].stop()
        value = self.listing('qa')
        need(any(u['host_id'] == self.ids['p4'] and isinstance(u['error'], str) for u in value['unanswered']),
             'unanswered lists a stopped host', value['unanswered'])
        return ''

    def close(self):
        try:
            for c in self.consumers:
                try:
                    c.close()
                except Exception:
                    pass
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()


def run_pairing(coord_binary, cli_binary, daemon_binary, node, label, integrations=None, only=None):
    global INTEGRATIONS
    if integrations:
        INTEGRATIONS = Path(integrations)
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-agents-') as temporary:
        pairing = AgentPairing(label, cli_binary, daemon_binary, coord_binary, node, Path(temporary), only)
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [agent tools: setup]: {detail}', flush=True)
            if pairing.setup_notes:
                print(f'NOTE {label} agent tools setup: ' + ' | '.join(pairing.setup_notes), flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        print(f'---- {label} agent tools: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} sections '
              f'passed in {time.monotonic() - started:.0f}s', flush=True)
        return [(f'agent tools: {name}', ok, detail) for name, ok, detail in pairing.results]


# --- migration from version 17 to 18 ------------------------------------------------------------------------

def strip_call_fields(path):
    """Remove calls and max_calls_per_hour from every credential record's JSON, as a version 17 record has none."""
    connection = sqlite3.connect(path)
    try:
        columns = [r[1] for r in connection.execute('PRAGMA table_info(adapter_credentials)')]
        for column in columns:
            for rowid, value in connection.execute(f'SELECT rowid, {column} FROM adapter_credentials').fetchall():
                if not isinstance(value, str) or not value.startswith('{'):
                    continue
                try:
                    record = json.loads(value)
                except ValueError:
                    continue
                if isinstance(record, dict) and ('calls' in record or 'max_calls_per_hour' in record):
                    record.pop('calls', None)
                    record.pop('max_calls_per_hour', None)
                    connection.execute(f'UPDATE adapter_credentials SET {column} = ? WHERE rowid = ?',
                                       (json.dumps(record), rowid))
        connection.commit()
    finally:
        connection.close()


def check_migration(original, replacement, label, baseline=None):
    """Version 17 to 18, with existing credentials reading calls false; the next version refused.

    With `baseline` (a version 17 peerspan-host), the version 17 state is made by it. Otherwise it is made by
    `original` and taken back to version 17: the two version 18 tables and the index dropped, credential records
    without the new fields, and user_version 17."""
    from host_service import Host
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-agents-migration-') as directory:
        host = Host(baseline or original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'quinn')
            status, body = host.call('POST', '/v1/adapters/setup', {
                'agent_id': agent['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
                'expires_at': timestamp(3600)})
            need(status == 201, 'setup: a credential', status, body)
            adapter_id = body['credential']['adapter']['id']
            host.stop()
            if baseline:
                need(db_rows(host, 'PRAGMA user_version')[0][0] == VERSION - 1, 'the baseline is version 17')
            else:
                need(db_rows(host, 'PRAGMA user_version')[0][0] == VERSION, 'Database version 18', label)
                connection = sqlite3.connect(host.state / 'host.db')
                try:
                    connection.execute('DROP INDEX IF EXISTS adapter_calls_rate')
                    for table in NEW_TABLES:
                        connection.execute(f'DROP TABLE {table}')
                    connection.execute(f'PRAGMA user_version = {VERSION - 1}')
                    connection.commit()
                finally:
                    connection.close()
                strip_call_fields(host.state / 'host.db')
            host.binary = str(replacement)
            need(host.start()['id'] == identity['id'], 'the identity survives migration')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == VERSION, 'migrated to version 18')
            tables = {r[0] for r in db_rows(host, "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')")}
            need(set(NEW_TABLES) | {'adapter_calls_rate'} <= tables, 'migration creates the two tables and the index',
                 sorted(tables))
            status, record = host.call('GET', f'/v1/adapters/{adapter_id}')
            need(status == 200 and record.get('calls') is False and 'max_calls_per_hour' in record and
                 record['max_calls_per_hour'] is None, 'an existing credential reads calls false', status, record)
            host.stop()
            connection = sqlite3.connect(host.state / 'host.db')
            connection.execute(f'PRAGMA user_version = {VERSION + 1}')
            connection.commit()
            connection.close()
            for binary in {str(original), str(replacement)}:
                result = subprocess.run([binary, '--state', str(host.state), 'run'], capture_output=True, timeout=10)
                need(result.returncode != 0, 'version 18 binaries reject version 19', binary)
        finally:
            stop_all((host,))
    return label
