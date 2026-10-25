#!/usr/bin/env python3
"""Agent capability tools (milestone 10 slice 2), run by conformance/capabilities.py.

Written from docs/capabilities-contract.md ("Agent tools (slice 2)" and its Verification list, plus the slice 1
case for a person whose label contains `/`), and the agent adapter, outbound, recovery, live delivery, and launch
contracts it extends, independently of the Go and Rust hosts and of the shared Node adapter, which runs here only
as a black box (`attach claude --runner NODE`, with a fixture `claude` executable; no model runs).

Each CLI/daemon pairing gets its own topology, separate from the slice 1 pairing in capabilities.py:
- pat (label `pat`): p1 serves the capabilities (agent `srv`, source `srv/fx`, the fixture MCP server) and opens
  its sources to p2; p2 is trusted (agent `pa`); p3 is untrusted (agent `pu`); p4 serves a second copy of `dup`;
  x1 runs the other implementation and serves `xtools`; o1 runs a version 17 host (--baseline17, which predates
  `wait`) and serves `oldtools` (both shared with quinn).
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
- calls [Calls: within wait with origin and citation, 10 seconds, outlasting wait, no event while held (the
  notification seen, never claimed), wait 0, source (route and tool), unlisted operation, ambiguous, not_found,
  the receiver's 429];
- call timing [Calls: a 2-second tool returned final within 3 seconds, to this pairing's daemon and to the other
  implementation; a wait above the limit answering at 15 seconds; the peer route's wait (11 refused, 0 at once,
  held, answered within 1 second of finishing, at the receiver through the probe); the caller daemon's held status
  requests; a version 17 receiver asked again no sooner than 1 second after each answer];
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

Slice 3, item C (sharing with one agent), is in SharePairing below, written from the contract's "Sharing with one
agent (slice 3)" section and its Verification list, in a topology of its own per pairing (see its docstring), with
sections: lookup route [Lookup route]; forms [Forms]; authorization [Authorization]; resolution [Resolution, with
`--old` for a host that predates the route]; review and output [Review and output]; recipient views [Recipient
views]; call --from-agent [`call --from-agent`]; states [`shares`]; unshare [`unshare`]. The listing section above
carries the replaced slice 2 case for `discover`.

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
import urllib.parse

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


class RawNumber(str):
    """A number token, emitted exactly as spelled."""


# The spellings the fixture's canon tool sends (contract: numbers exactly as the receiver sent them).
CANON_NUMBERS = ['-0', '1.50', '1e+00', '1E2', '100000000000000000000000']


def canon_expected(repeat):
    """The canon tool's result (fixtures/mcp/server.py, canon_result), with its number tokens as sent."""
    n = RawNumber
    return {'structuredContent': {'zeta': n('1'), 'numbers': [n(x) for x in CANON_NUMBERS], 'Émile': n('1.5'),
                                  'alpha': {'b': n('-2'), 'a': [n('3'), CANON_TEXT, None, True]},
                                  'Zed': 'Z', 'beta': '\u2028\u2029'},
            'content': [{'text': CANON_TEXT * repeat, 'type': 'text'}]}


def canonical(value):
    """The contract's result text encoding: no whitespace, keys sorted by UTF-8 bytes (code point order), raw
    UTF-8, escaping only \" and \\, \b \t \n \f \r, and other characters below U+0020 as \\u00xx (lowercase).
    The fixture's numbers are integers and 1.5, which Python renders as sent."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode())
        return '{' + ','.join(canonical(k) + ':' + canonical(v) for k, v in items) + '}'
    if isinstance(value, list):
        return '[' + ','.join(canonical(v) for v in value) + ']'
    if isinstance(value, RawNumber):
        return str(value)
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
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, node, root, only=None, other=None,
                 baseline17=None):
        self.label, self.cli_binary, self.daemon, self.node, self.root = label, cli_binary, daemon_binary, node, root
        self.only = only
        self.other_daemon = other        # the other implementation's peerspan-host, serving from x1
        self.baseline17 = baseline17     # a version 17 peerspan-host (predates wait), serving from o1
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results, self.notes, self.setup_notes = [], [], []
        self.hosts, self.ids, self.keys, self.agents = {}, {}, {}, {}
        self.sessions = {}      # name -> {host, agent_id, session_id, adapter_id, profile, workspace, out, consumer}
        self.consumers = []
        self.aid = {}

    # --- infrastructure ----------------------------------------------------------------------------------------

    def host(self, name, person, daemon=None, cli=None):
        h = CapHost(daemon or self.daemon, cli or self.cli_binary, self.root / name, self.root / f'user-{name}')
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
        self.synced(self.version('p1'), 'p2', 'p3', 'p4', 'q1', 's1', 's2', *self.extra)
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

    def ok_call(self, name, address, operation, input=None, wait=None, call_id=None, rule='call_capability'):
        """call_capability, calling again with the same call_id after a lost response (the contract's recovery for
        it; the shared machine can stall past the adapter's timeout)."""
        call_id = call_id or cid()
        for attempt in range(3):
            failed, value, elapsed = self.cc(name, address, operation, input, wait, call_id)
            lost = failed and isinstance(value, dict) and 'code' not in value and \
                str(value.get('recovery', '')).startswith('Check call_status')
            if not lost:
                break
        need(not failed, f'{rule}: not a tool error', value)
        check_view(value, rule)
        return value, elapsed

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

    def until_state(self, name, view, state, timeout=20):
        """With wait 0 the view may come before the submission ends (submitting); follow it to `state`."""
        need(view['state'] in ('submitting', state), f'a call {state} (or still submitting)', view)
        if view['state'] == state:
            return view

        def reached():
            failed, current = self.status(name, view['call_id'])
            return current if not failed and current.get('state') == state else None
        view = wait_for(reached, timeout=timeout, message=f'call {state}')
        need(view['note'] == PENDING_NOTE, f'a {state} call has the pending note', view)
        return view

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
        # x1 runs the other implementation (and its CLI), o1 a version 17 host that predates `wait`; both serve
        # capabilities of pat's shared with quinn.
        self.extra = []
        if self.other_daemon:
            self.host('x1', 'pat', self.other_daemon, self.other_daemon)
            self.extra.append('x1')
        if self.baseline17:
            self.host('o1', 'pat', self.baseline17, self.baseline17)
            self.extra.append('o1')
        for name in self.extra:
            persons[name] = 'pat'
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids, h = self.ids, self.hosts

        self.team = h['p1'].cli('network', 'create', 'team', '--as', 'pat', '--trusted',
                                *self.coordinator_flags())['id']
        for name, label, flags in (('p2', 'pat', ('--trusted',)), ('p3', 'pat', ('--untrusted',)),
                                   ('p4', 'pat', ('--untrusted',)), ('q1', 'quinn', ('--untrusted',)),
                                   ('s1', 'ops/sam', ('--trusted',)), ('s2', 'ops/sam', ('--trusted',)),
                                   *[(n, 'pat', ('--untrusted',)) for n in self.extra]):
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
        self.put_servers('p1', 'srv', {'fx': self.fixture.args('fx') + ['canon=1']})
        self.register('p4', 'srv4', 'pat')
        self.put_servers('p4', 'srv4', {'fx': self.fixture.args('fx4')})
        self.register('s1', 'sagent', 'ops/sam')
        self.put_servers('s1', 'sagent', {'fx': self.fixture.args('sfx')})
        for host, target in (('p1', 'p2'), ('s1', 's2')):
            status, body = h[host].call('POST', '/v1/sources/open-to', {'host_id': ids[target]})
            need(status in (200, 201), 'setup: sources open-to', host, target, status, body)

        # The capabilities of x1 and o1, created and shared first; p1 then stores their claims before its own edits.
        for name, agent, capability in (('x1', 'srvx', 'xtools'), ('o1', 'srvo', 'oldtools')):
            if name not in self.hosts:
                continue
            self.synced(self.version('p1'), name)
            self.register(name, agent, 'pat')
            self.put_servers(name, agent, {'fx': self.fixture.args(f'fx-{name}')})
            self.create(name, capability, f'{agent}/fx', ['echo', 'sleep'])
            self.share(name, capability, 'quinn', per_hour=1000)
            self.synced(self.version(name), 'p1')

        for name, operations in (('tools', ['echo', 'sleep', 'big', 'canon', 'fail', 'tool_error', 'write_note']),
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
        self.section('call timing', self.check_timing)
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

        # discover: capabilities the owner can call keep only their from_agent null entries; agent-only ones are
        # listed with for_agents (slice 3 replaced the slice 2 case "discover unchanged by agent: rules").
        status, body = self.hosts['q1'].call('GET', f'/v1/discover?person=pat')
        need(status == 200, 'GET /v1/discover', status, body)
        names = {e['capability']: e for e in body['capabilities']}
        need('agentonly' in names and 'mixed' in names and 'tools' in names,
             'discover lists agent-only capabilities too (slice 3)', sorted(names))
        need(names['agentonly'].get('for_agents') == [{'agent_id': qa_id, 'name': 'qa'}] and
             [v.get('from_agent') for v in names['agentonly']['via']] == [qa_id],
             'an agent-only capability keeps its via entries and gains for_agents', names['agentonly'])
        callable_ = [e for n, e in names.items() if n != 'agentonly']
        need(all(v.get('from_agent') is None for e in callable_ for v in e['via']) and
             all('for_agents' not in e for e in callable_),
             'capabilities the owner can call keep only their from_agent null entries, without for_agents',
             names.get('mixed'))
        need(all('from_agent' in v for e in callable_ for v in e['via'] if v.get('kind') == 'policy'),
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
        if isinstance(n[2], dict):
            # While the POST is held, call-updates/next never claims the call's notification.
            need(n[2].get('state') != 'forwarded', 'a notification of a call answered by the held POST is never '
                 'claimed (not forwarded)', n[2])
            # The stored record may hold more; the route's `delivery` object is checked exactly (queued window).
            need(NOTIFICATION_KEYS <= set(n[2]), 'the stored notification record has the notification\'s fields',
                 n[2])

        # 2. A call taking 10 seconds, default wait.
        text = marker('ten')
        view, elapsed = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 10, 'text': text})
        need(view['state'] == 'succeeded' and 10 <= elapsed < 12.5, 'a 10-second call is returned final with the '
             'default wait (the 15-second wait limit), soon after it finishes', view['state'], elapsed)
        notes.append(f'10-second call returned in {elapsed:.1f}s')
        time.sleep(3)
        need(not self.events_for('qa', view['call_id']), 'no call_update event for the 10-second call')
        n = self.notification('q1', view['call_id'])
        need(n and n[0] and (not isinstance(n[2], dict) or n[2].get('state') != 'forwarded'),
             'while call_capability is held no event is emitted, and the notification ends up seen (never claimed)',
             n)

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

        # 4. wait 0 answers once the call is persisted; a negative wait is invalid. (A wait above the limit is in
        # the call timing section.)
        text = marker('w0')
        before = self.count('q1', 'outbound_calls')
        view, elapsed = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 3, 'text': text}, wait=0)
        need(view['state'] in PENDING_STATES and elapsed < 2 and self.count('q1', 'outbound_calls') == before + 1,
             'wait 0 answers once the call is persisted', view['state'], elapsed)
        text = marker('wneg')
        before = self.count('q1', 'outbound_calls')
        failed, value, _ = self.cc('qa', 'pat/tools', 'echo', {'text': text}, wait=-1)
        need(failed and 'call_capability' in json.dumps(value), 'wait -1 is invalid: a tool error naming the tool',
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

    # --- call timing (decision 15) -------------------------------------------------------------------------

    def done_time(self, key, text):
        """When the fixture finished the execution whose arguments carry `text` (its own clock, this machine's)."""
        calls = self.fixture.calls(key, marker=text)
        need(len(calls) == 1, 'executed once', key, text, calls)
        start = calls[0]
        for e in self.fixture.entries(key):
            if e['event'] == 'done' and e.get('id') == start['id'] and e['pid'] == start['pid'] and \
                    e['time'] >= start['time']:
                return e['time']
        return None

    def outbound(self, host, call_id):
        rows = db_rows(self.hosts[host], 'SELECT record FROM outbound_calls WHERE call_id = ?', (call_id,))
        return json.loads(rows[0][0]) if rows else None

    def watch_final(self, host, call_id, timeout=60):
        """Read the caller's outbound record every 50 ms until its status is final; (record, time.time() then)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.outbound(host, call_id)
            if record and (record.get('status') or {}).get('state') in FINAL:
                return record, time.time()
            time.sleep(0.05)
        raise Failure(f'outbound call {call_id} final on {host}: {self.outbound(host, call_id)}')

    def watch_state(self, host, call_id, states, timeout=30):
        """Read the caller's outbound record every 50 ms until its status state is in `states`; (record, time)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            record = self.outbound(host, call_id)
            if record and (record.get('status') or {}).get('state') in states:
                return record, time.time()
            time.sleep(0.05)
        raise Failure(f'outbound call {call_id} in {sorted(states)} on {host}: {self.outbound(host, call_id)}')

    def check_timing(self):
        notes = []
        q1, p1 = self.hosts['q1'], self.hosts['p1']

        # A tool taking 2 seconds is returned final within 3 seconds of the tool call: to a host of this pairing's
        # daemon (p1), and to one of the other implementation (x1).
        need('x1' in self.hosts, 'setup: a serving host of the other implementation (capabilities.py --rust and --go)')
        for address, key in (('pat/tools', 'fx'), ('pat/xtools', 'fx-x1')):
            text = marker('two')
            view, elapsed = self.ok_call('qa', address, 'sleep', {'seconds': 2, 'text': text})
            need(view['state'] == 'succeeded' and elapsed <= 3.0, 'a call whose tool takes 2 seconds is returned '
                 'final by call_capability within 3 seconds of the tool call', address, view['state'], elapsed)
            notes.append(f'{address} 2-second call in {elapsed:.2f}s')

        # A wait above the limit answers no later than the wait limit (15 seconds), not before it.
        text = w60_text = marker('w60')
        view, elapsed = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 25, 'text': text}, wait=60)
        need(view['state'] in PENDING_STATES and view['note'] == PENDING_NOTE and 14.5 <= elapsed <= 16.5,
             'a wait above the limit answers at the 15-second wait limit, unfinished', view['state'], elapsed)
        notes.append(f'wait 60 answered after {elapsed:.1f}s')

        # The peer route, at the receiver through the probe (as q1): wait 11 refused, wait 0 at once, wait 10
        # held for its full time when the call does not finish, and answered within 1 second of the call finishing.
        context = fixture_context(q1)
        cite = {'policy': {'person_id': self.pat, 'network_id': self.team, 'version': self.version('p1')}}

        def submit(seconds, text):
            body = {'call_id': cid(), 'capability': 'tools', 'operation': 'sleep',
                    'input': {'seconds': seconds, 'text': text}, 'deadline': timestamp(300), **cite}
            status, record = wire(p1, context, 'POST', '/peer/v1/calls', body)
            need(status == 200, 'a call through the peer route', status, record)
            return body['call_id']

        long_text = marker('held')
        long_call = submit(14, long_text)
        for query in ('wait=11', 'wait=-1', 'wait=5&state=bogus', 'wait=5&state=RUNNING'):
            status, value = wire(p1, context, 'GET', f'/peer/v1/calls/{long_call}?{query}')
            need(status == 400, 'GET /peer/v1/calls/{id} with a wait outside 0 to 10, or a state that is not a call '
                 'state, is 400', query, status, value)
        wait_for(lambda: self.fixture.calls('fx', marker=long_text), timeout=10, message='the long call running')
        started = time.monotonic()
        status, record = wire(p1, context, 'GET', f'/peer/v1/calls/{long_call}?wait=10&state=queued')
        need(status == 200 and record['state'] == 'running' and time.monotonic() - started < 1.5,
             'a state that already differs answers at once', status, record.get('state'),
             time.monotonic() - started)
        started = time.monotonic()
        status, record = wire(p1, context, 'GET', f'/peer/v1/calls/{long_call}?wait=0')
        need(status == 200 and record['state'] not in FINAL and time.monotonic() - started < 1.5,
             'wait 0 answers at once', status, record.get('state'), time.monotonic() - started)
        started = time.monotonic()
        status, record = wire(p1, context, 'GET', f'/peer/v1/calls/{long_call}?wait=2')
        held = time.monotonic() - started
        need(status == 200 and record['state'] not in FINAL and 1.8 <= held <= 3.5,
             'a held GET answers after its wait when the call has not finished', status, record.get('state'), held)
        text = marker('short')
        short_call = submit(3, text)
        wait_for(lambda: self.fixture.calls('fx', marker=text), timeout=10, message='the short call running')
        status, record = wire(p1, context, 'GET', f'/peer/v1/calls/{short_call}?wait=10&state=running')
        answered = time.time()
        done = self.done_time('fx', text)
        need(status == 200 and record['state'] == 'succeeded' and record.get('result') is not None and done and
             answered - done <= 1.3, 'a held GET (state running) answers within 1 second of the call finishing, with '
             'the result', status, record.get('state'), answered - (done or 0))

        # The instance's earlier sleeps (wait 60 and the long peer call) finish first, so the slots can be filled.
        wait_for(lambda: self.done_time('fx', w60_text) and self.done_time('fx', long_text), timeout=40,
                 message='the earlier sleeps finished')
        # queued to running: with the instance's 4 slots busy for 4 seconds, a queued call's held GET (state queued)
        # answers within 1 second of the call starting to run, at the receiver and at the caller daemon.
        self.fill_slots(4)
        text = marker('startsoon')
        queued_call = submit(2, text)
        status, record = wire(p1, context, 'GET', f'/peer/v1/calls/{queued_call}?wait=10&state=queued')
        answered = time.time()
        calls = self.fixture.calls('fx', marker=text)
        need(status == 200 and record['state'] in ('running', 'succeeded') and calls and
             answered - calls[0]['time'] <= 1.3, 'a held GET (state queued) answers within 1 second of the call '
             'starting to run', status, record.get('state'), answered - (calls[0]['time'] if calls else 0))
        self.fill_slots(4)
        text = marker('callerstart')
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 3, 'text': text}, wait=0)
        record, seen = self.watch_state('q1', view['call_id'], {'running'} | FINAL)
        calls = self.fixture.calls('fx', marker=text)
        need(record['status']['state'] == 'running' and calls and seen - calls[0]['time'] <= 1.3,
             'the caller daemon stores running within 1 second of the call starting to run', record['status'],
             seen - (calls[0]['time'] if calls else 0))
        notes.append(f"running seen {seen - calls[0]['time']:.2f}s after start")
        self.watch_final('q1', view['call_id'])

        # The caller daemon's held status requests: a 12-second call from qa is seen final within 1 second of
        # finishing, with few status requests (one held request at a time, each up to 10 seconds).
        # Q: requests are counted with the outbound record's status_queries, on the caller: the QUIC stream is
        # encrypted, so the receiver side is seen only through the probe checks above.
        text = marker('callerheld')
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 12, 'text': text}, wait=0)
        record, seen = self.watch_final('q1', view['call_id'])
        done = self.done_time('fx', text)
        need(done and seen - done <= 1.3, 'the caller daemon has the result within 1 second of the call finishing',
             seen - (done or 0))
        # Q: whether held requests count in status_queries is not said; 0 means they are not counted, and then the
        # number of requests cannot be observed here.
        need(isinstance(record.get('status_queries'), int) and record['status_queries'] <= 4,
             'one held status request at a time (a 12-second call takes at most a few)', record.get('status_queries'))
        notes.append(f"held: final {seen - done:.2f}s after finishing, {record['status_queries']} status requests "
                     'counted')

        # A receiver that predates wait (version 17) answers at once: asked again no sooner than 1 second after each
        # answer, and the call still returns final.
        if 'o1' not in self.hosts:
            print(f'SKIP {self.label} [agent tools: call timing]: the version 17 receiver case needs --baseline17',
                  flush=True)
            notes.append('SKIPPED the version 17 receiver case (no --baseline17)')
            return '; '.join(notes)
        text = marker('old')
        started = time.time()
        view, _ = self.ok_call('qa', 'pat/oldtools', 'sleep', {'seconds': 6, 'text': text}, wait=0)
        record, seen = self.watch_final('q1', view['call_id'])
        span = seen - started
        need(record['status']['state'] == 'succeeded', 'a call to a host that predates wait still becomes final',
             record['status'])
        need(isinstance(record.get('status_queries'), int) and record['status_queries'] <= span + 2,
             'asked again no sooner than 1 second after each answer', record.get('status_queries'), span)
        self.soft(record['status_queries'] > 0, 'status requests to a version 17 receiver are counted in '
                  'status_queries (otherwise the 1-second spacing cannot be observed)', record['status_queries'])
        done = self.done_time('fx-o1', text)
        need(done and seen - done <= 2.3, 'seen final within about a second of finishing', seen - (done or 0))
        final = self.final_view('qa', view['call_id'])
        need(final['state'] == 'succeeded', 'call_status returns it final', final)
        notes.append(f"version 17 receiver: {record['status_queries']} status requests over {span:.1f}s")
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
        queued = self.until_state('qa', queued, 'queued')
        failed, cancelled = self.tool(self.s('qa')['consumer'], 'call_cancel', {'call_id': queued['call_id']})
        need(not failed, 'call_cancel returns the call view, not a tool error', cancelled)
        check_view(cancelled, 'call_cancel')
        view = self.final_view('qa', queued['call_id'], timeout=30)
        need(view['state'] == 'cancelled' and view['note'] == NEVER_RAN_NOTE,
             'call_cancel while queued: cancelled, with the never-ran note', view)
        cancelled_id, cancelled_at = queued['call_id'], time.monotonic()

        rechecked, _ = self.ok_call('qa', 'pat/recheck', 'echo', {'text': texts['rc']}, wait=0)
        rechecked = self.until_state('qa', rechecked, 'queued')
        body = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'echo', 'input': {'text': texts['ex']},
                'wait': 0}
        status, expiring_view = expiring.call('POST', '/adapter/v1/calls', body)
        need(status == 200 and expiring_view.get('state') in ('submitting', 'queued'), 'a call queued until its '
             'deadline (capped by the credential\'s expiry, 45 seconds)', status, expiring_view)
        texts['ex2'] = marker('ex2')
        body2 = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'echo', 'input': {'text': texts['ex2']},
                 'wait': 0}
        status, second_view = expiring.call('POST', '/adapter/v1/calls', body2)
        need(status == 200 and second_view.get('state') in ('submitting', 'queued'), 'a second call queued until '
             'its deadline', status, second_view)
        for b in (body, body2):
            wait_for(lambda b=b: expiring.call('GET', f"/adapter/v1/calls/{b['call_id']}")[1].get('state') ==
                     'queued', timeout=20, message='the expiring call queued')
        deadline = caps.parse_time(expiring_view['deadline'])
        need(deadline.timestamp() <= time.time() + 50, 'the deadline is capped by the credential\'s expires_at',
             expiring_view['deadline'])
        self.unshare('p1', 'recheck', 'quinn')

        # The queued call's held status request (state queued) was in flight when it was cancelled; it stays
        # cancelled (checked now, more than 10 seconds later).
        time.sleep(max(0.0, 11 - (time.monotonic() - cancelled_at)))
        view = self.final_view('qa', cancelled_id)
        need(view['state'] == 'cancelled', 'a held answer never moves a stored state backwards', view)
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

    def running_at_receiver(self, view, text, key='fx'):
        """A call the fixture is executing. The caller's view may still say queued: with held status requests, it
        learns of `running` only when a held request answers (decision 15)."""
        need(view['state'] in PENDING_STATES and view['note'] == PENDING_NOTE, 'an unfinished call', view)
        wait_for(lambda: self.fixture.calls(key, marker=text), timeout=10, message='the fixture runs the call')

    def check_running(self):
        f = self.fixture
        text = marker('cr')
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 30, 'text': text}, wait=2)
        self.running_at_receiver(view, text)
        failed, cancelled = self.tool(self.s('qa')['consumer'], 'call_cancel', {'call_id': view['call_id']})
        need(not failed, 'call_cancel returns the call view', cancelled)
        check_view(cancelled, 'call_cancel')
        final = self.final_view('qa', view['call_id'], timeout=60)
        need(final['state'] == 'uncertain' and final['error'] == 'cancel_requested' and
             final['note'] == UNCERTAIN_NOTE, 'call_cancel while running: uncertain with the uncertain note', final)
        # A held status request (state running) was in flight when the call was cancelled; its answer never moves
        # the stored state backwards, and a final state is never replaced (held requests last up to 10 seconds).
        time.sleep(11)
        later = self.final_view('qa', view['call_id'])
        need(later['state'] == 'uncertain' and later['error'] == 'cancel_requested',
             'a final state is never replaced by a held answer', later)
        need(len(f.calls('fx', marker=text)) == 1, 'executed exactly once')

        text = marker('rs')
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 20, 'text': text}, wait=2)
        self.running_at_receiver(view, text)
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
        for repeat in (3000, 1):  # in parts first, where the text itself is seen
            view, _ = self.ok_call('qa', 'pat/tools', 'canon', {'repeat': repeat})
            need(view['state'] == 'succeeded', 'the canon call succeeds', {k: view[k] for k in ('state', 'error')})
            expected = canonical(canon_expected(repeat))
            if view['truncated']:
                text = self.page('qa', view)
                numbers = re.search(r'"numbers":\[[^\]]*\]', text)
                need(numbers and numbers.group(0) == '"numbers":[' + ','.join(CANON_NUMBERS) + ']',
                     'each number is spelled exactly as the receiver sent it',
                     numbers.group(0).encode() if numbers else text[:300].encode())
                need(text == expected, 'the result text is the canonical encoding (sorted keys, raw UTF-8, only the '
                     'specified escapes, numbers as sent)', first_difference(text, expected))
            need(view['result_bytes'] == len(expected.encode()), 'result_bytes of the canonical encoding', repeat,
                 view['result_bytes'], len(expected.encode()))
        notes.append('canonical result text matches')

        # A non-zero offset before there is a result is 400.
        view, _ = self.ok_call('qa', 'pat/tools', 'sleep', {'seconds': 4, 'text': marker('pre')}, wait=0)
        need(view['result_bytes'] is None, 'no result yet', view)
        failed, value = self.status('qa', view['call_id'], 1)
        need(failed, 'call_status with a non-zero offset before there is a result is a tool error', value)
        failed, value = self.status('qa', view['call_id'], 0)
        need(not failed and check_view(value)['offset'] == 0, 'offset 0 before there is a result', value)
        body = {'call_id': cid(), 'address': 'pat/tools', 'operation': 'sleep',
                'input': {'seconds': 4, 'text': marker('pre2')}, 'wait': 0}
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
        self.running_at_receiver(view, text)
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



# --- slice 3: sharing with one agent ------------------------------------------------------------------------------

LOOKUP_OK_KEYS = {'principal', 'host_id', 'agent_id', 'person_id', 'address', 'unanswered'}
SHARE3_KEYS = {'policy', 'capability', 'principal', 'recipient', 'created'}
UNSHARE3_KEYS = {'policy', 'capability', 'principal', 'recipient', 'removed'}
RECIPIENT_KEYS = {'address', 'host_id', 'agent_id', 'person_id'}
AGENT_RECIPIENT_KEYS = {'network_id', 'principal', 'label', 'agent_state'}
SHARES_AGENT_KEYS = AGENT_RECIPIENT_KEYS | {'unshare'}
LINE_SAME_MACHINE = ('The share stays with this agent on this machine. If the agent is set up again on another machine, '
                     'share it again.')
LINE_TRUSTED = ('This machine is trusted, so this agent already reaches all your capabilities through self access. '
                'This share matters only if you untrust it.')
LINE_UNBOUND_CLAIM = ('That host makes the claim itself: anyone, and any program, that can run peerspan as that host\'s '
                      'owner can call as this agent. Other machines, other agents, and other people cannot.')
TRY_AGAIN = 'Try again when it is online, or use agent:HOST_ID/AGENT_ID.'
SOURCE_AS_AGENT = 'Agents cannot call sources; call them without --from-agent.'
SHARE_SECTIONS = ('shares: lookup route', 'shares: forms', 'shares: authorization', 'shares: resolution',
                  'shares: review and output', 'shares: recipient views', 'shares: call --from-agent',
                  'shares: states', 'shares: unshare')


def claim_line(host_id, person):
    return (f'That host makes the claim itself: {person}, and any program that can run peerspan as {person} on that '
            f'machine, can call as this agent. {person}\'s other machines and other agents, and other people, cannot.')


def lines_of(text):
    return [line.strip() for line in text.replace('\r', '').split('\n')]


def walk(value):
    """Every dict inside value, depth first."""
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v)


class SharePairing(AgentPairing):
    """Capabilities slice 3, item C (sharing with one agent), in a topology of its own per CLI/daemon pairing.

    - pat (the sharer): p1 (trusted; the source srv/fx and every capability; local agent `plocal`; in team and
      other), p2 (trusted; agent `pown`; in team and other), p3 (untrusted; agent `puntr`).
    - quinn (the recipient): q1 (trusted; MCP sessions `qa` and `qlim` (--max-calls-per-hour 1), raw sessions of
      `qb` and `qx`, registered `qhid` and `QBad` (not addressable)), q2 (a raw session of another `qx`, `qgone`,
      and the source `q2srv/fx`, opened to q1), q3 (`qoff`), q4 (`qrev`, revoked later), q5 (`qunb`, unbound from
      quinn later and bound to rhea), and o1, a host built before this slice (`--old`: agents `oldvis`, which quinn
      lets pat reach, so p1's directory lists it, and `oldhid`, which it does not).
    - `ops/sam` (a label containing `/`): s1 (agent `sagent`). rhea: r1. n2 joins without a person (`nagent`).
      n1 is not a member of team.
    Networks: team (all members but n1), other (p1 only), and side (q3 and n1)."""

    def __init__(self, label, cli_binary, daemon_binary, coord_binary, node, root, only=None, old=None):
        super().__init__(label, cli_binary, daemon_binary, coord_binary, node, root, only)
        self.old = old

    # --- helpers -------------------------------------------------------------------------------------------

    def start_coordinator(self):
        """Start the coordinator, retrying when it is slow to listen (the shared machine stalls for seconds)."""
        for attempt in range(3):
            try:
                return self.coord.start()['public_key']
            except AssertionError:
                if attempt == 2:
                    raise
                if self.coord.process is not None:
                    self.coord.process.kill()
                    self.coord.process.wait()
                time.sleep(5)

    def section(self, name, function):
        if self.only and name not in self.only:
            return None
        return super().section(name, function)

    def ok_call(self, name, address, operation, input=None, wait=None, call_id=None, rule='call_capability'):
        """call_capability, calling again with the same call_id after a lost response (the contract's recovery for
        it; the shared machine can stall past the adapter's timeout)."""
        call_id = call_id or cid()
        for attempt in range(3):
            failed, value, elapsed = self.cc(name, address, operation, input, wait, call_id)
            lost = failed and isinstance(value, dict) and 'code' not in value and \
                str(value.get('recovery', '')).startswith('Check call_status')
            if not lost:
                break
        need(not failed, f'{rule}: not a tool error', value)
        check_view(value, rule)
        return value, elapsed

    def create(self, host, name, source, operations):
        code, out, stdout, stderr = self.hosts[host].outcome('capability', 'create', name, '--from', source,
                                                             '--operations', ','.join(operations), timeout=300)
        need(code == 0, f'setup: capability create {name} on {host}', code, stderr[-400:])

    def lookup(self, address, host='p1', net=None):
        query = urllib.parse.urlencode({'address': address, 'network': net or self.team})
        return self.hosts[host].call('GET', f'/v1/agent-lookup?{query}')

    def peer_lookup(self, target, caller, net=None, raw_query=None, **params):
        query = raw_query if raw_query is not None else urllib.parse.urlencode(params)
        return wire(self.hosts[target], fixture_context(self.hosts[caller]), 'GET',
                    f'/peer/v1/networks/{net or self.team}/agent-lookup?{query}')

    def principal_of(self, host, agent):
        return f'agent:{self.ids[host]}/{self.aid[agent]}'

    def rule_principals(self, name, net=None, host='p1'):
        p = self.policy(host, net)
        for r in (p or {}).get('capability_rules') or []:
            if r['capability'] == name and r['host'] == self.ids[host]:
                return list(r['principals'])
        return None

    def share3(self, name, recipient, host='p1', net=None, expect=True, per_hour=None):
        """`share NAME --with RECIPIENT --yes`: (exit code, output, stderr, whether a version was signed)."""
        before = self.version(host, net)
        args = ['share', name, '--with', recipient, '--yes', '--network', net or self.team]
        if per_hour:
            args += ['--calls-per-hour', str(per_hour)]
        code, out, stdout, stderr = self.hosts[host].outcome(*args)
        after = self.version(host, net)
        if code == 0:
            need(isinstance(out, dict) and set(out) == SHARE3_KEYS, 'share prints {policy, capability, principal, '
                 'recipient, created}', recipient, out)
            need(after in (before, before + 1), 'share signs the next version or nothing', before, after)
        else:
            need(after == before, 'a refused share signs nothing', recipient, before, after, code, stderr[-600:])
        if expect:
            need(code == 0, f'share {name} --with {recipient}', code, stderr[-600:])
        return code, out, stderr, after == before + 1

    def share_tty(self, name, recipient, host='p1', net=None):
        argv = ['share', name, '--with', recipient, '--network', net or self.team]
        code, out, tty, stdout, seen = self.hosts[host].at_terminal(*argv, answer='y', prompt=caps.SHARE_PROMPT,
                                                                    timeout=90)
        need(code == 0 and seen and isinstance(out, dict), f'share {name} --with {recipient} at a terminal, '
             'answering y', code, tty[-800:])
        return out, tty

    def _unshare3(self, name, recipient, host, net):
        code, out, stdout, stderr = self.hosts[host].outcome('unshare', name, '--with', recipient, '--network',
                                                             net or self.team)
        return code, out, stderr

    def refused(self, code, stderr, text, rule):
        need(code != 0 and text in caps.squash(stderr), f'{rule}: exit non-zero with "{text}"', code, stderr[-600:])

    def directory(self, host='p1', net=None):
        status, body = self.hosts[host].call('POST', f'/v1/directory/refresh?network={net or self.team}', {})
        need(status == 200, 'POST /v1/directory/refresh', status, body)
        return body

    def capability_recipients(self, name, host='p1', lookup=False):
        path = f'/v1/capabilities/{name}' + ('?lookup=true' if lookup else '')
        status, body = self.hosts[host].call('GET', path)
        need(status == 200 and isinstance(body, dict), f'GET {path}', status, body)
        return body.get('recipients') or []

    def shares_entry(self, out, name, principal):
        """The agent recipient for `principal` under capability NAME anywhere in `shares --json`."""
        for d in walk(out):
            if d.get('name') == name or d.get('capability') == name:
                for r in walk(d):
                    if r is not d and r.get('principal') == principal and 'agent_state' in r:
                        return r, d
        return None, None

    def members(self, net=None):
        return {m['host_id']: m for m in self.hosts['p1'].cli('network', 'members', net or self.team)}

    def sync_until(self, condition, message, hosts=('p1',), net=None, timeout=90):
        def done():
            for n in hosts:
                self.hosts[n].run('network', 'sync', net or self.team)
            return condition()
        return wait_for(done, timeout=timeout, message=message)

    def delete_agent(self, host, agent_id):
        """The fixture removes an agent's record while its daemon is stopped (no delete command exists)."""
        h = self.hosts[host]
        h.stop()
        connection = sqlite3.connect(h.state / 'host.db')
        try:
            deleted = 0
            tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
            for table in tables:
                columns = {r[1] for r in connection.execute(f'PRAGMA table_info({table})')}
                if {'id', 'name', 'owner'} <= columns:
                    deleted += connection.execute(f'DELETE FROM {table} WHERE id = ?', (agent_id,)).rowcount
            connection.commit()
        finally:
            connection.close()
        need(deleted == 1, 'fixture: the agent record deleted', host, agent_id, deleted)
        h.logs.close()
        h.logs = tempfile.TemporaryFile()
        h.start()

    def call_as(self, host, address, *flags, text=None, wait='30s'):
        """`call ADDRESS echo` with flags: (exit code, output, stderr, marker)."""
        text = text or marker('as')
        code, out, stdout, stderr = self.hosts[host].outcome('call', address, 'echo', '--input',
                                                             json.dumps({'text': text}), '--wait', wait, *flags,
                                                             timeout=120)
        return code, out, stderr, text

    # --- setup -----------------------------------------------------------------------------------------------

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        for name in ('pat', 'quinn', 'sam', 'rhea'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.quinn, self.sam, self.rhea = (person_id(self.keys[n][2]) for n in ('pat', 'quinn', 'sam',
                                                                                          'rhea'))
        self.fixture = Fixture(root / 'fixture')
        self.claude = ClaudeFixture(root / 'claude')
        self.coord_key = self.start_coordinator()
        persons = {'p1': 'pat', 'p2': 'pat', 'p3': 'pat', 'q1': 'quinn', 'q2': 'quinn', 'q3': 'quinn', 'q4': 'quinn',
                   'q5': 'quinn', 's1': 'sam', 'r1': 'rhea', 'n1': None, 'n2': None}
        for name, person in persons.items():
            self.host(name, person)
        if self.old:
            self.host('o1', 'quinn', self.old, self.old)
            persons['o1'] = 'quinn'
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids, h = self.ids, self.hosts

        self.team = h['p1'].cli('network', 'create', 'team', '--as', 'pat', '--trusted',
                                *self.coordinator_flags())['id']
        joins = [('p2', 'pat', ('--trusted',)), ('p3', 'pat', ('--untrusted',)), ('q1', 'quinn', ('--trusted',)),
                 ('q2', 'quinn', ('--untrusted',)), ('q3', 'quinn', ('--untrusted',)),
                 ('q4', 'quinn', ('--untrusted',)), ('q5', 'quinn', ('--untrusted',)),
                 ('s1', 'ops/sam', ('--untrusted',)), ('r1', 'rhea', ('--untrusted',)), ('n2', 'nobody', ('--no-person',))]
        if 'o1' in h:
            joins.append(('o1', 'quinn', ('--untrusted',)))
        for name, label, flags in joins:
            token = self.invite(label, self.team)
            for attempt in range(4):
                # A join is retried with the same invite when the coordinator was too slow to answer (load).
                result = h[name].run('join', token, *flags)
                slow = 'coordination unavailable' in result.stderr or 'deadline exceeded' in result.stderr
                if result.returncode == 0 or not slow or attempt == 3:
                    break
                time.sleep(5)
                if self.team in json.dumps(h[name].call('GET', '/v1/networks')[1]):
                    break
            need(self.team in json.dumps(h[name].call('GET', '/v1/networks')[1]), f'setup: {name} joins team as '
                 f'{label}', result.stderr[-500:])
        self.other = h['p1'].cli('network', 'create', 'other', '--as', 'pat', '--trusted',
                                 *self.coordinator_flags())['id']
        label_of = {'pat': self.pat, 'quinn': self.quinn, 'sam': self.sam, 'rhea': self.rhea, None: None}
        expected = {ids[n]: label_of[p] for n, p in persons.items() if n != 'n1'}

        def bound():
            for n in persons:
                if n != 'n1':
                    h[n].run('network', 'sync', self.team)
            seen = {m['host_id']: m['person_id'] for m in h['p1'].cli('network', 'members', self.team)}
            return seen == expected
        wait_for(bound, timeout=120, message='every member of team bound as expected')
        h['p1'].run('network', 'sync', self.other)
        # side: q3 and n1, so n1 is a known host to q3 but not a member of team.
        self.side = h['q3'].cli('network', 'create', 'side', '--as', 'quinn', '--untrusted',
                                *self.coordinator_flags())['id']
        token = h['q3'].cli('network', 'invite', '--network', self.side, '--member', 'stranger', '--expires-in',
                            '1h')['token']
        h['n1'].cli('join', token, '--no-person')
        for n in ('q3', 'n1'):
            h[n].run('network', 'sync', self.side)

        # Agents.
        for host, name, owner in (('p1', 'srv', 'pat'), ('p1', 'plocal', 'pat'), ('p2', 'pown', 'pat'),
                                  ('p3', 'puntr', 'pat'), ('q1', 'qb', 'quinn'), ('q1', 'qx', 'quinn'),
                                  ('q1', 'qhid', 'quinn'), ('q1', 'QBad', 'quinn'), ('q2', 'qgone', 'quinn'),
                                  ('q2', 'q2srv', 'quinn'), ('q3', 'qoff', 'quinn'), ('q4', 'qrev', 'quinn'),
                                  ('q5', 'qunb', 'quinn'), ('s1', 'sagent', 'ops/sam'), ('n2', 'nagent', 'n2'),
                                  *([('o1', 'oldvis', 'quinn'), ('o1', 'oldhid', 'quinn')] if 'o1' in h else [])):
            self.register(host, name, owner)
        self.put_servers('p1', 'srv', {'fx': self.fixture.args('fx')})
        self.put_servers('q2', 'q2srv', {'fx': self.fixture.args('q2fx')})
        status, body = h['q2'].call('POST', '/v1/sources/open-to', {'host_id': ids['q1']})
        need(status in (200, 201), 'setup: q2 opens its sources to q1', status, body)
        self.raw, self.raw_setups = {}, {}
        self.aid['qx@q2'] = h['q2'].cli('agent', 'register', '--name', 'qx', '--owner', 'quinn')['id']
        for host, name, agent_id in (('q1', 'qb', self.aid['qb']), ('q1', 'qx', self.aid['qx']),
                                     ('q2', 'qx', self.aid['qx@q2'])):
            self.raw[(host, name)], setup = self.raw_setup(host, agent_id)
            self.raw_setups[(host, name)] = setup
            self.raw[(host, name)].session_id = setup['credential']['adapter']['session_id']

        for name in ('forms', 'forms2', 'auth', 'auth2', 'rev', 'ao', 'budget', 'lim', 'both', 'pub', 'st', 'un',
                     'un2'):
            self.create('p1', name, 'srv/fx', ['echo', 'sleep'])

        for host, name, flags in (('q1', 'qa', ('--calls',)),
                                  ('q1', 'qlim', ('--calls', '--max-calls-per-hour', '1'))):
            self.session(host, name, *flags)

        # quinn lets pat reach oldvis on o1 (so p1's directory lists it), and nothing else of quinn's.
        if 'o1' in h:
            h['q1'].cli('allow', 'pat', '--agent', 'oldvis', '--network', self.team)
        self.sync_all_policies()

        self.section('shares: lookup route', self.check_lookup_route)
        self.section('shares: forms', self.check_forms)
        self.section('shares: authorization', self.check_share_authorization)
        self.section('shares: resolution', self.check_resolution)
        self.section('shares: review and output', self.check_review)
        self.section('shares: recipient views', self.check_recipient_views)
        self.section('shares: call --from-agent', self.check_from_agent)
        self.section('shares: states', self.check_states)
        self.section('shares: unshare', self.check_unshare3)
        if self.setup_notes:
            print(f'NOTE {self.label} agent shares setup: ' + ' | '.join(self.setup_notes), flush=True)

    def sync_all_policies(self):
        live = [n for n in self.hosts if n not in ('n1',) and self.hosts[n].process and
                self.hosts[n].process.poll() is None]
        for person, owner_host in ((self.pat, 'p1'), (self.quinn, 'q1')):
            v = self.version(owner_host, person=person)
            if v:
                self.synced(v, *[n for n in live if n != owner_host], person=person)

    # --- the lookup route ------------------------------------------------------------------------------------

    def check_lookup_route(self):
        ids, aid = self.ids, self.aid
        want = {'agent': {'agent_id': aid['qhid'], 'name': 'qhid'}}
        status, body = self.peer_lookup('q1', 'p1', name='qhid')
        need(status == 200 and body == want, 'the lookup route by name: 200 {agent: {agent_id, name}}', status, body)
        status, body = self.peer_lookup('q1', 'p1', agent_id=aid['qhid'])
        need(status == 200 and body == want, 'the lookup route by agent_id', status, body)
        for params, rule in (({'name': 'nosuch'}, 'an unknown name'),
                             ({'agent_id': 'agent_' + secrets.token_hex(16)}, 'an unknown agent ID'),
                             ({'name': 'QBad'}, 'a non-addressable name')):
            status, body = self.peer_lookup('q1', 'p1', **params)
            need(status == 200 and body == {'agent': None}, f'the lookup route: 200 with agent null for {rule}',
                 status, body)
        status, body = self.peer_lookup('q1', 'p1', agent_id=aid['QBad'])
        need(status == 200 and body == {'agent': {'agent_id': aid['QBad'], 'name': None}},
             'the lookup route by agent_id for a non-addressable name returns name null', status, body)
        status, body = self.peer_lookup('q3', 'n1', name='qoff')
        need(status == 403, 'the lookup route: 403 for a caller that is not a member of that network', status, body)
        status, body = self.peer_lookup('q3', 'n1', net=self.side, name='qoff')
        need(status == 200 and body == {'agent': {'agent_id': aid['qoff'], 'name': 'qoff'}},
             'the same caller is answered in a network it is a member of', status, body)
        status, body = self.peer_lookup('q1', 'p1', net=self.other, name='qhid')
        need(status == 404 and isinstance(body, dict) and body.get('code') == 'not_found',
             'the lookup route: 404 {code: "not_found"} for a network the host is not in', status, body)
        for query, rule in (('', 'neither parameter'),
                            (urllib.parse.urlencode({'name': 'qhid', 'agent_id': aid['qhid']}), 'both parameters'),
                            ('name=' + 'a' * 260, 'a query over 256 bytes')):
            status, body = self.peer_lookup('q1', 'p1', raw_query=query)
            need(status == 400 and isinstance(body, dict) and body.get('code') == 'invalid',
                 f'the lookup route: 400 invalid for {rule}', status, body)
        return ''

    # --- forms ------------------------------------------------------------------------------------------------

    def check_forms(self):
        ids, aid = self.ids, self.aid
        qhid = self.principal_of('q1', 'qhid')
        directory = self.directory('p1')
        need(not any(a.get('agent_id') == aid['qhid'] for a in directory['agents']),
             'setup: p1\'s directory does not list qhid (no rule lets p1 reach it)', directory['agents'])
        code, out, _, signed = self.share3('forms', 'quinn/qhid')
        need(signed and out['principal'] == qhid and qhid in self.rule_principals('forms'),
             'share --with PERSON/AGENT stores agent:HOST_ID/AGENT_ID, found through the lookup route although the '
             'directory does not list it', out)
        need(out['recipient'] == {'address': 'quinn/qhid', 'host_id': ids['q1'], 'agent_id': aid['qhid'],
                                  'person_id': self.quinn}, 'recipient {address, host_id, agent_id, person_id}',
             out['recipient'])
        code, out, _, signed = self.share3('forms', f"{ids['q1']}/qhid")
        need(not signed and out['principal'] == qhid and self.rule_principals('forms').count(qhid) == 1,
             'share --with HOST_ID/AGENT stores the same principal; a repeat signs nothing', out)
        need(out['recipient'] == {'address': 'quinn/qhid', 'host_id': ids['q1'], 'agent_id': aid['qhid'],
                                  'person_id': self.quinn}, 'a repeat still prints recipient, the address resolved to '
             'PERSON/AGENT', out['recipient'])
        code, out, _, signed = self.share3('forms', f'{self.quinn}/qhid')
        need(not signed and out['principal'] == qhid, 'PERSON may be a person ID', out)
        qb = self.principal_of('q1', 'qb')
        code, out, _, signed = self.share3('forms', qb)
        need(signed and out['principal'] == qb and out['recipient'] is None and qb in self.rule_principals('forms'),
             'agent:HOST_ID/AGENT_ID stored as given, with recipient null', out)
        code, out, _, signed = self.share3('forms', 'quinn')
        need(out['recipient'] is None, 'recipient is null for other forms', out)
        before = self.version('p1')
        code, out, stderr, _ = self.share3('forms', 'quinn/a/b', expect=False)
        self.refused(code, stderr, 'invalid recipient "quinn/a/b": use PERSON/AGENT, HOST_ID/AGENT, or person:LABEL '
                     'for a label that contains /', 'two / refused')
        code, out, stderr, _ = self.share3('forms', 'quinn/Bad_Name', expect=False)
        self.refused(code, stderr, 'invalid agent name "Bad_Name"', 'a non-addressable agent name refused')
        need(self.version('p1') == before, 'the refusals sign nothing')
        # A person whose label contains /: person:LABEL, and that person's agent through HOST_ID/AGENT.
        code, out, _, signed = self.share3('forms2', 'person:ops/sam')
        need(out['principal'] == 'person:' + self.sam and out['recipient'] is None,
             'person:LABEL reaches a person whose label contains /', out)
        code, out, _, signed = self.share3('forms2', f"{ids['s1']}/sagent")
        need(out['principal'] == self.principal_of('s1', 'sagent') and out['recipient'] == {
            'address': f"{ids['s1']}/sagent", 'host_id': ids['s1'], 'agent_id': self.aid['sagent'],
            'person_id': self.sam}, 'HOST_ID/AGENT reaches that person\'s agent, addressed HOST_ID/AGENT', out)
        code, out, stderr, _ = self.share3('forms2', 'ops/sam', expect=False)
        need(code != 0, 'a bare value with one / is an agent address, never a person label (ops/sam: no person ops)',
             code, out)
        return ''

    # --- authorization ----------------------------------------------------------------------------------------

    def check_share_authorization(self):
        ids = self.ids
        self.share3('auth', 'quinn/qa')
        self.share3('auth2', self.principal_of('q1', 'qx'))
        self.sync_all_policies()
        view, _ = self.ok_call('qa', 'pat/auth', 'echo', {'text': marker('auth')})
        need(view['state'] == 'succeeded', 'the shared agent\'s adapter calls are accepted', view)
        status, value = self.raw[('q1', 'qb')].call('POST', '/adapter/v1/calls', {
            'call_id': cid(), 'address': 'pat/auth', 'operation': 'echo', 'input': {'text': marker('authb')}})
        need(status == 404 and value.get('code') == 'not_found', 'another agent on the same host is refused',
             status, value)
        status, value = self.raw[('q1', 'qx')].call('POST', '/adapter/v1/calls', {
            'call_id': cid(), 'address': 'pat/auth2', 'operation': 'echo', 'input': {'text': marker('authx')},
            'wait': 15})
        need(status == 200 and value.get('state') == 'succeeded', 'qx on q1 calls auth2', status, value)
        # The same name on quinn's other host.
        agent = {'id': self.aid['qx@q2']}
        raw2, setup = self.raw[('q2', 'qx')], self.raw_setups[('q2', 'qx')]
        text = marker('authx2')
        status, value = raw2.call('POST', '/adapter/v1/calls', {
            'call_id': cid(), 'address': 'pat/auth2', 'operation': 'echo', 'input': {'text': text}})
        need(status == 404 and value.get('code') == 'not_found' and not self.executions('fx', text),
             'an agent with the same name on another host of the same person is refused', status, value)
        # And through the peer route with that origin, from q2.
        body = {'call_id': cid(), 'capability': 'auth2', 'operation': 'echo', 'input': {'text': text},
                'deadline': timestamp(300), 'origin': {'agent_id': agent['id'], 'session_id': setup['credential'][
                    'adapter']['session_id']},
                'policy': {'person_id': self.pat, 'network_id': self.team, 'version': self.version('p1')}}
        status, record = wire(self.hosts['p1'], fixture_context(self.hosts['q2']), 'POST', '/peer/v1/calls', body)
        need(status in (403, 404) and not self.executions('fx', text), 'the receiver refuses q2\'s qx', status, record)
        return ''

    # --- resolution -------------------------------------------------------------------------------------------

    def check_resolution(self):
        ids, aid = self.ids, self.aid
        notes = []
        # One match, the JSON shape.
        status, body = self.lookup('quinn/qhid')
        need(status == 200 and set(body) == LOOKUP_OK_KEYS, 'GET /v1/agent-lookup: 200 {principal, host_id, agent_id, '
             'person_id, address, unanswered}', status, body)
        need(body['principal'] == self.principal_of('q1', 'qhid') and body['host_id'] == ids['q1'] and
             body['agent_id'] == aid['qhid'] and body['person_id'] == self.quinn and body['address'] == 'quinn/qhid',
             'the lookup\'s fields', body)
        need(all(set(u) == {'host_id', 'error'} for u in body['unanswered']), 'unanswered entries {host_id, error}',
             body['unanswered'])
        # ambiguous: qx on q1 and q2.
        status, body = self.lookup('quinn/qx')
        want = sorted([f"{ids['q1']}/qx", f"{ids['q2']}/qx"])
        need(status == 409 and isinstance(body, dict) and set(body) == {'code', 'error', 'matches'} and
             body['code'] == 'ambiguous' and [m['address'] for m in body['matches']] == want and
             all(set(m) == {'address', 'network_id'} and m['network_id'] == self.team for m in body['matches']),
             '409 {code: "ambiguous", error, matches: [{address, network_id}]}, HOST_ID/AGENT sorted', status, body)
        code, out, stderr, _ = self.share3('rev', 'quinn/qx', expect=False)
        need(code != 0, 'share refuses an ambiguous address, signing nothing', code)
        # local, through PERSON/AGENT and HOST_ID/AGENT.
        for address in ('pat/plocal', f"{ids['p1']}/plocal"):
            status, body = self.lookup(address)
            text = (f'{address} is on this host, and a host never calls itself. Share with an agent on another '
                    'machine.')
            need(status == 400 and isinstance(body, dict) and set(body) == {'code', 'error'} and
                 body['code'] == 'local' and body['error'] == text, f'400 local for {address}, with its text',
                 status, body)
            code, out, stderr, _ = self.share3('rev', address, expect=False)
            self.refused(code, stderr, text, f'share --with {address} refused as local')
        # unknown_host, unknown_person, invalid.
        stranger = ids['n1']
        status, body = self.lookup(f'{stranger}/qa')
        need(status == 404 and isinstance(body, dict) and set(body) == {'code', 'error'} and
             body['code'] == 'unknown_host' and body['error'] == f'unknown host {stranger} in network {self.team}',
             '404 unknown_host for a host ID that is not a member', status, body)
        code, out, stderr, _ = self.share3('rev', f'{stranger}/qa', expect=False)
        self.refused(code, stderr, f'unknown host {stranger} in network {self.team}', 'share: unknown_host')
        status, body = self.lookup('nobody/qa')
        need(status == 404 and isinstance(body, dict) and body.get('code') == 'unknown_person',
             '404 unknown_person for a label matching no person', status, body)
        for bad in ('quinn/a/b', 'quinn', 'quinn/Bad_Name'):
            status, body = self.lookup(bad)
            need(status == 400 and isinstance(body, dict) and body.get('code') == 'invalid',
                 f'400 invalid for {bad!r}, not an agent address', status, body)
        status, body = self.hosts['p1'].call('GET', f'/v1/agent-lookup?network={self.team}')
        need(status == 400 and isinstance(body, dict) and body.get('code') == 'invalid', '400 invalid without address',
             status, body)

        # A host predating the route (o1): the directory cache answers for it.
        if 'o1' in self.hosts:
            directory = self.directory('p1')
            need(any(a.get('agent_id') == aid['oldvis'] for a in directory['agents']),
                 'setup: p1\'s directory lists oldvis', directory['agents'])
            status, body = self.lookup('quinn/oldvis')
            need(status == 200 and body.get('principal') == self.principal_of('o1', 'oldvis') and
                 not any(u['host_id'] == ids['o1'] for u in body['unanswered']),
                 'a host that answers 404 without code: its directory entry counts as its answer', status, body)
            status, body = self.lookup(f"{ids['o1']}/oldhid")
            need(status == 404 and isinstance(body, dict) and body.get('code') == 'unknown' and
                 body.get('unanswered') == [{'host_id': ids['o1'], 'error': 'unsupported'}],
                 'without a directory entry: unknown, listing the old host as unsupported', status, body)
            want = (f"{ids['o1']} has no agent named oldhid. Not answered: {ids['o1']} (unsupported). " + TRY_AGAIN)
            need(body.get('error') == want, 'the HOST_ID/AGENT unknown text with the not-answered part', body, want)
        else:
            notes.append('no --old host: the older-host cases skipped')

        # A stopped host of the person.
        q3 = self.hosts['q3']
        q3.stop()
        try:
            status, body = self.lookup('quinn/nosuch')
            need(status == 404 and isinstance(body, dict) and set(body) == {'code', 'error', 'unanswered'} and
                 body['code'] == 'unknown', '404 {code: "unknown", error, unanswered}', status, body)
            un = body['unanswered']
            need([u['host_id'] for u in un] == sorted(u['host_id'] for u in un) and
                 any(u['host_id'] == ids['q3'] for u in un), 'unanswered names the stopped host, sorted by host ID',
                 un)
            want = ('quinn has no agent named nosuch on the hosts that answered. Not answered: ' +
                    ', '.join(f"{u['host_id']} ({u['error']})" for u in un) + '. ' + TRY_AGAIN)
            need(body['error'] == want, 'the unknown text, with the not-answered part', body['error'], want)
            code, out, stderr, _ = self.share3('rev', 'quinn/nosuch', expect=False)
            self.refused(code, stderr, 'quinn has no agent named nosuch on the hosts that answered.',
                         'share: unknown, with nothing signed')
            need(f"Not answered: {ids['q3']}" in caps.squash(stderr) or f"{ids['q3']} (" in caps.squash(stderr),
                 'share prints the not-answered text', stderr[-600:])
            # One match with the stopped host unanswered: the share goes ahead and the review lists it.
            status, body = self.lookup('quinn/qhid')
            need(status == 200 and any(u['host_id'] == ids['q3'] for u in body['unanswered']),
                 'one match while a host is stopped: 200, unanswered lists it', status, body)
            out, tty = self.share_tty('rev', 'quinn/qhid')
            checked = [line for line in lines_of(tty) if line.startswith('Not checked: ')]
            need(len(checked) == 1 and f"{ids['q3']} (" in checked[0], 'the review has the Not checked: line naming '
                 'the stopped host', checked, tty[-1200:])
            need(out['principal'] == self.principal_of('q1', 'qhid'), 'the share goes ahead', out)
        finally:
            q3.start()
        return '; '.join(notes)

    # --- review and output --------------------------------------------------------------------------------

    def review_has(self, tty, recipient, host, agent, person, trusted, unchecked=()):
        lines = lines_of(tty)
        hid = self.ids[host]
        bound = (f'agent {self.aid[agent]} on host {hid}, bound to {person}' if person else
                 f'agent {self.aid[agent]} on host {hid}, not bound to a person')
        need(bound in lines, 'the review\'s agent … on host … line', bound, tty[-1500:])
        at = lines.index(bound)
        previous = [line for line in lines[:at] if line][-1]
        need(previous.endswith(recipient), 'the recipient line names the resolved address, followed by the agent line',
             previous, recipient)
        reach = (f'{recipient} can use these operations with the credentials they run with on this host. Anything '
                 f'those credentials can reach through them, {recipient} can too.')
        need(reach in caps.squash(tty), 'the reach sentence uses the address', reach, tty[-1500:])
        paragraph = [f'Only calls that {hid} says come from this agent are allowed.',
                     claim_line(hid, person) if person else LINE_UNBOUND_CLAIM, LINE_SAME_MACHINE]
        for line in paragraph:
            need(line in lines, 'the agent paragraph line', line, tty[-1500:])
        need(lines.index(paragraph[0]) < lines.index(paragraph[1]) < lines.index(paragraph[2]),
             'the agent paragraph in order', tty[-1500:])
        need((LINE_TRUSTED in lines) == trusted, 'the trusted-own-agent line ' + ('present' if trusted else 'absent'),
             tty[-1500:])
        checked = [line for line in lines if line.startswith('Not checked:')]
        if unchecked:
            need(len(checked) == 1 and all(f'{u} (' in checked[0] for u in unchecked),
                 'the Not checked: line lists the hosts that did not answer', unchecked, checked)
        else:
            need(not checked, 'no Not checked: line when every host answered', checked)

    def check_review(self):
        ids, aid = self.ids, self.aid
        # o1 predates the lookup route and its directory entries lack qb, so it is not checked (unsupported).
        old = [ids['o1']] if 'o1' in ids else []
        out, tty = self.share_tty('rev', 'quinn/qb')
        self.review_has(tty, 'quinn/qb', 'q1', 'qb', 'quinn', False, old)
        if old:
            need(f"Not checked: {ids['o1']} (unsupported)" in lines_of(tty), 'an old host is not checked: unsupported',
                 tty[-1200:])
        need(out['recipient'] == {'address': 'quinn/qb', 'host_id': ids['q1'], 'agent_id': aid['qb'],
                                  'person_id': self.quinn}, 'recipient in share JSON', out)
        out, tty = self.share_tty('rev', 'pat/pown')
        self.review_has(tty, 'pat/pown', 'p2', 'pown', 'pat', True)
        need(out['recipient']['person_id'] == self.pat, 'an agent on another host of the signer may be shared with',
             out)
        out, tty = self.share_tty('rev', 'pat/puntr')
        self.review_has(tty, 'pat/puntr', 'p3', 'puntr', 'pat', False)
        out, tty = self.share_tty('rev', f"{ids['n2']}/nagent")
        self.review_has(tty, f"{ids['n2']}/nagent", 'n2', 'nagent', None, False)
        need(out['recipient'] == {'address': f"{ids['n2']}/nagent", 'host_id': ids['n2'], 'agent_id': aid['nagent'],
                                  'person_id': None}, 'recipient for a host without a person: HOST_ID/AGENT, '
             'person_id null', out)
        # The agent: form: the paragraph too.
        principal = self.principal_of('q1', 'qhid')
        out, tty = self.share_tty('forms2', principal)
        lines = lines_of(tty)
        for line in (f"Only calls that {ids['q1']} says come from this agent are allowed.",
                     claim_line(ids['q1'], 'quinn'), LINE_SAME_MACHINE):
            need(line in lines, 'the agent paragraph for the agent: form', line, tty[-1500:])
        need(out['recipient'] is None, 'recipient null for the agent: form', out)
        # A repeat signs nothing and still prints recipient.
        code, out, _, signed = self.share3('rev', 'quinn/qb')
        need(not signed and out['recipient']['agent_id'] == aid['qb'], 'a repeat signs nothing, with recipient', out)
        return ''

    # --- recipient views ------------------------------------------------------------------------------------

    def check_recipient_views(self):
        aid, q1 = self.aid, self.hosts['q1']
        self.share3('ao', 'quinn/qa')
        self.share3('both', 'quinn/qa')
        self.share3('both', 'quinn')
        self.share3('pub', 'quinn')
        self.sync_all_policies()
        status, body = q1.call('GET', '/v1/discover')
        need(status == 200, 'GET /v1/discover', status, body)
        by = {e['address']: e for e in body['capabilities']}
        need('pat/ao' in by and by['pat/ao'].get('for_agents') == [{'agent_id': aid['qa'], 'name': 'qa'}],
             'default discover lists an agent-only capability with for_agents [{agent_id, name}]', by.get('pat/ao'))
        need(all(v.get('from_agent') == aid['qa'] for v in by['pat/ao']['via']) and by['pat/ao']['via'],
             'an agent-only entry keeps its via entries', by['pat/ao']['via'])
        for name in ('pat/both', 'pat/pub'):
            need(name in by and 'for_agents' not in by[name] and
                 all(v.get('from_agent') is None for v in by[name]['via']),
                 'capabilities the owner can call: only from_agent null entries, and no for_agents', by.get(name))
        code, out, stdout, stderr = q1.outcome('discover')
        need(code == 0 and 'only for your agent qa' in stdout, 'the readable line says only for your agent NAME',
             code, stdout[-800:])
        # call without --from-agent.
        text = 'pat/ao is shared only with your agent qa. Add --from-agent qa to call as that agent.'
        before = self.count('q1', 'outbound_calls')
        code, out, stderr, _ = self.call_as('q1', 'pat/ao')
        self.refused(code, stderr, text, 'call on an agent-only capability without --from-agent')
        status, value = q1.call('POST', '/v1/calls', {'target': 'pat/ao', 'operation': 'echo',
                                                      'input': {'text': 'x'}})
        need(status == 403 and isinstance(value, dict) and value.get('code') == 'agent_only' and
             value.get('error') == text and value.get('for_agents') == [{'agent_id': aid['qa'], 'name': 'qa'}],
             '403 {code: "agent_only", error, for_agents}', status, value)
        need(self.count('q1', 'outbound_calls') == before, 'agent_only persists nothing')
        # discover --from-agent equals list_capabilities.
        source_seen = wait_for(lambda: any(e.get('kind') == 'source' for e in
                                           (q1.call('GET', '/v1/discover')[1] or {}).get('capabilities', [])),
                               timeout=90, message='q1\'s discover lists q2\'s source (self access)')
        need(source_seen, 'setup: a source in the owner\'s discover')
        listing = self.listing('qa')
        status, mine = q1.call('GET', f"/v1/discover?from_agent={aid['qa']}")
        need(status == 200 and isinstance(mine, dict) and set(mine) == {'capabilities', 'unanswered'},
             'GET /v1/discover?from_agent=: {capabilities, unanswered}, without agents', status, mine)
        need(mine['capabilities'] == listing['capabilities'],
             'discover --from-agent equals the agent\'s list_capabilities', mine, listing)
        need(any(e['address'] == 'pat/ao' for e in mine['capabilities']) and
             not any(e['address'].count('/') > 1 for e in mine['capabilities']),
             'including the agent-only capability, excluding sources', [e['address'] for e in mine['capabilities']])
        for given in (aid['qa'], 'qa'):
            code, out, stdout, stderr = q1.outcome('discover', '--from-agent', given, '--json')
            need(code == 0 and isinstance(out, dict) and out.get('capabilities') == listing['capabilities'],
                 f'discover --from-agent {given} --json equals list_capabilities', code, stderr[-300:], out)
        status, value = q1.call('GET', '/v1/discover?from_agent=agent_' + secrets.token_hex(16))
        need(status == 404, 'discover?from_agent= with an unknown agent ID: 404', status, value)
        return ''

    # --- call --from-agent ----------------------------------------------------------------------------------

    def check_from_agent(self):
        ids, aid, q1 = self.ids, self.aid, self.hosts['q1']
        qa = self.s('qa')
        notes = []
        code, out, stderr, text = self.call_as('q1', 'pat/ao', '--from-agent', aid['qa'])
        need(code == 0 and caps.dig(out, 'status', 'state') == 'succeeded', 'call --from-agent AGENT_ID', code,
             stderr[-400:], out)
        by_id = out
        code, out, stderr, text = self.call_as('q1', 'pat/ao', '--from-agent', 'qa', '--from-session',
                                               qa['session_id'])
        need(code == 0 and caps.dig(out, 'status', 'state') == 'succeeded', 'call --from-agent NAME --from-session',
             code, stderr[-400:], out)
        with_session = out
        code, out, stderr, _ = self.call_as('q1', 'pat/ao', '--from-agent', 'qa')
        need(code == 0 and caps.dig(out, 'status', 'state') == 'succeeded', 'call --from-agent NAME', code,
             stderr[-400:])
        # Records.
        for record, session in ((by_id, None), (with_session, qa['session_id'])):
            call_id = record['request']['call_id']
            local = self.inspect('q1', 'p1', call_id)
            origin = local['request'].get('origin') or {}
            need(origin.get('agent_id') == aid['qa'] and origin.get('session_id') == session and
                 'adapter_id' in local and local['adapter_id'] is None,
                 'the outbound record stores origin in request, with adapter_id null', local)
            received = self.received('p1', call_id)
            need(received is not None and (received['request'].get('origin') or {}).get('agent_id') == aid['qa'] and
                 (received['request'].get('origin') or {}).get('session_id') == session,
                 'the receiver stores origin', received)
        # Refusals before persisting.
        before = self.count('q1', 'outbound_calls')
        for flags, text, rule in ((('--from-agent', 'nosuch'), 'no agent nosuch on this host', 'an unknown agent'),
                                  (('--from-session', qa['session_id']), '--from-session needs --from-agent',
                                   '--from-session without --from-agent')):
            code, out, stderr, _ = self.call_as('q1', 'pat/ao', *flags)
            self.refused(code, stderr, text, rule)
        for session, rule in (('session_' + secrets.token_hex(16), 'an unknown session'),
                              (self.raw[('q1', 'qb')].session_id, 'another agent\'s session')):
            code, out, stderr, _ = self.call_as('q1', 'pat/ao', '--from-agent', 'qa', '--from-session', session)
            need(code != 0, f'{rule} refused', code, stderr[-300:])
            status, value = q1.call('POST', '/v1/calls', {'target': 'pat/ao', 'operation': 'echo', 'input': {},
                                                          'origin': {'agent_id': aid['qa'], 'session_id': session}})
            need(status == 404, f'POST /v1/calls with {rule}: 404', status, value)
        status, value = q1.call('POST', '/v1/calls', {'target': 'pat/ao', 'operation': 'echo', 'input': {},
                                                      'origin': {'agent_id': 'agent_' + secrets.token_hex(16)}})
        need(status == 404, 'POST /v1/calls with an unknown origin agent: 404', status, value)
        # A source.
        source = f"{ids['q2']}/q2srv/fx"
        code, out, stderr, _ = self.call_as('q1', source, '--from-agent', 'qa')
        self.refused(code, stderr, SOURCE_AS_AGENT, 'a source address with --from-agent')
        status, value = q1.call('POST', '/v1/calls', {'target': source, 'operation': 'echo', 'input': {},
                                                      'origin': {'agent_id': aid['qa']}})
        need(status == 400 and isinstance(value, dict) and value.get('code') == 'source' and
             value.get('error') == SOURCE_AS_AGENT, 'POST /v1/calls with origin and a source: 400 source', status,
             value)
        need(self.count('q1', 'outbound_calls') == before, 'every refusal persists nothing')

        # Not counted against the agent's limit; counted in the receiver's rule budget.
        self.share3('lim', 'quinn/qlim')
        self.share3('budget', 'quinn/qa', per_hour=2)
        self.sync_all_policies()
        for i in range(2):
            code, out, stderr, _ = self.call_as('q1', 'pat/lim', '--from-agent', 'qlim')
            need(code == 0, 'an owner call as qlim', code, stderr[-300:])
        adapter = self.s('qlim')['adapter_id']
        need(self.count('q1', 'adapter_calls', 'WHERE adapter_id = ?', (adapter,)) == 0,
             'no adapter_calls row for owner calls as the agent')
        view, _ = self.ok_call('qlim', 'pat/lim', 'echo', {'text': marker('lim')})
        need(view['state'] == 'succeeded', 'owner calls as the agent do not block its own call (limit 1)', view)
        for i in range(2):
            code, out, stderr, _ = self.call_as('q1', 'pat/budget', '--from-agent', 'qa')
            need(code == 0, f'budget call {i + 1} of 2', code, stderr[-300:])
        code, out, stderr, text = self.call_as('q1', 'pat/budget', '--from-agent', 'qa')
        need(code == 1 and isinstance(out, dict) and out.get('submit_state') == 'rejected' and
             not self.executions('fx', text),
             'the receiver counts owner calls as the agent in the rule budget: the third is refused (429 limit)',
             code, out)
        self.soft('429' in str(out.get('error')), 'the refused call\'s error is the receiver\'s 429', out)

        # Invisible to the agent.
        since = time.time()
        code, out, stderr, text = self.call_as('q1', 'pat/ao', '--from-agent', 'qa', '--from-session',
                                               qa['session_id'])
        call_id = out['request']['call_id']
        need(code == 0, 'a call as qa with its session', code, stderr[-300:])
        failed, value = self.status('qa', call_id)
        need(not failed and value.get('state') == 'not_recorded', 'call_status answers not_recorded', value)
        failed, value = self.tool(qa['consumer'], 'call_cancel', {'call_id': call_id})
        need(not failed and value.get('state') == 'not_recorded', 'call_cancel answers not_recorded', value)
        pending = self.pending('qa')
        need(not any(c['call_id'] == call_id for c in pending['calls']), 'pending_work does not list it', pending)
        time.sleep(5)
        need(not self.events_for('qa', call_id, since), 'no call_update event arrives')
        need(not db_rows(self.hosts['q1'], 'SELECT 1 FROM call_update_notifications WHERE call_id = ?', (call_id,)),
             'no call-update notification is created')
        return '; '.join(notes)

    # --- shares states ----------------------------------------------------------------------------------------

    def agent_recipient(self, name, principal, lookup=False):
        for r in self.capability_recipients(name, lookup=lookup):
            if r.get('principal') == principal:
                return r
        raise Failure(f'GET /v1/capabilities/{name}: no recipient {principal}')

    def expect_state(self, out, name, principal, state, label):
        entry, _ = self.shares_entry(out, name, principal)
        need(entry is not None and set(entry) == SHARES_AGENT_KEYS, 'shares --json: each agent recipient is '
             '{network_id, principal, label, agent_state, unshare}', name, principal, entry)
        need(entry['agent_state'] == state and entry['label'] == label and entry['network_id'] == self.team,
             f'shares: agent_state {state} with label {label}', entry)
        host_id = principal[len('agent:'):].split('/')[0]
        by = f"{host_id}/{label.rsplit('/', 1)[1]}" if state == 'found' and label else principal
        want = f'peerspan unshare {name} --with {by} --network {self.team}'
        need(entry['unshare'] == want, f'shares: the unshare command for {state}', entry['unshare'], want)
        return entry

    def shares_json(self):
        code, out, stdout, stderr = self.hosts['p1'].outcome('shares', '--json', '--network', self.team, timeout=120)
        need(code == 0 and out is not None, 'shares --json', code, stderr[-400:])
        return out

    def check_states(self):
        ids, aid, h = self.ids, self.aid, self.hosts
        targets = {'qa': 'q1', 'qoff': 'q3', 'qgone': 'q2', 'qrev': 'q4', 'qunb': 'q5'}
        for agent in targets:
            self.share3('st', f'quinn/{agent}')
        principal = {a: f'agent:{ids[host]}/{aid[a]}' for a, host in targets.items()}
        # qx is on q1 and on q2: shared by principal, its removal command names q1's address.
        principal['qx'] = self.principal_of('q1', 'qx')
        self.share3('st', principal['qx'])
        out = self.shares_json()
        for agent in targets:
            self.expect_state(out, 'st', principal[agent], 'found', f'quinn/{agent}')
        entry = self.expect_state(out, 'st', principal['qx'], 'found', 'quinn/qx')
        need(f"--with {ids['q1']}/qx " in entry['unshare'], 'the unshare command names HOST_ID/AGENT_NAME even when '
             'the person has an agent of that name on another host', entry)
        r = self.agent_recipient('st', principal['qa'])
        need(set(r) == AGENT_RECIPIENT_KEYS and r['agent_state'] == 'found' and r['label'] == 'quinn/qa',
             'GET /v1/capabilities/{name}: {network_id, principal, label, agent_state} from the cache', r)
        plain = [x for x in self.capability_recipients('st') if not x['principal'].startswith('agent:')]
        need(all(set(x) == {'network_id', 'principal', 'label'} for x in plain), 'other recipients unchanged', plain)

        # unanswered, not_found, host_gone, unbound.
        h['q3'].stop()
        self.delete_agent('q2', aid['qgone'])
        h['p1'].cli('network', 'revoke', '--network', self.team, '--host', ids['q4'])
        h['q1'].cli('network', 'unbind', '--network', self.team, '--host', ids['q5'])
        self.sync_until(lambda: ids['q4'] not in self.members() and
                        self.members().get(ids['q5'], {}).get('person_id') is None,
                        'q4 revoked and q5 unbound, in p1\'s map', hosts=('p1', 'q1', 'q5'))
        out = self.shares_json()
        self.expect_state(out, 'st', principal['qoff'], 'unanswered', 'quinn/qoff')
        self.expect_state(out, 'st', principal['qgone'], 'not_found', 'quinn/qgone')
        entry, _ = self.shares_entry(out, 'st', principal['qrev'])
        need(entry and entry['agent_state'] == 'host_gone' and entry['unshare'] ==
             f"peerspan unshare st --with {principal['qrev']} --network {self.team}",
             'shares: host_gone after revocation, unshare by principal', entry)
        self.expect_state(out, 'st', principal['qunb'], 'unbound', f"{ids['q5']}/qunb")
        self.expect_state(out, 'st', principal['qa'], 'found', 'quinn/qa')

        # Without lookup: no peer traffic (a stopped host answers at once) and the cached states.
        started = time.monotonic()
        r = self.agent_recipient('st', principal['qoff'])
        elapsed = time.monotonic() - started
        need(elapsed < 3 and r['agent_state'] == 'unanswered', 'GET /v1/capabilities without lookup answers at once '
             'with the cached state', elapsed, r)
        need(self.agent_recipient('st', principal['qgone'])['agent_state'] == 'not_found' and
             self.agent_recipient('st', principal['qa'])['agent_state'] == 'found', 'cached states reported')

        # The label uses the host's current person: q5 bound to rhea.
        h['q5'].cli('network', 'bind', '--network', self.team, sock=self.agents['rhea'].socket)
        self.sync_until(lambda: self.members().get(ids['q5'], {}).get('person_id') == self.rhea,
                        'q5 bound to rhea in p1\'s map', hosts=('p1', 'q5'))
        out = self.shares_json()
        self.expect_state(out, 'st', principal['qunb'], 'found', 'rhea/qunb')
        return ''

    # --- unshare ---------------------------------------------------------------------------------------------

    def check_unshare3(self):
        ids, aid = self.ids, self.aid
        # By PERSON/AGENT, with recipient.
        self.share3('un', 'quinn/qa')
        before = self.version('p1')
        code, out, stderr = self._unshare3('un', 'quinn/qa', 'p1', None)
        need(code == 0 and isinstance(out, dict) and set(out) == UNSHARE3_KEYS and out['removed'] == 1 and
             out['principal'] == self.principal_of('q1', 'qa') and self.version('p1') == before + 1,
             'unshare --with PERSON/AGENT: {policy, capability, principal, recipient, removed}', code, out,
             stderr[-300:])
        need(out['recipient'] == {'address': 'quinn/qa', 'host_id': ids['q1'], 'agent_id': aid['qa'],
                                  'person_id': self.quinn}, 'unshare prints recipient', out)
        # removed: 0 for an agent address.
        code, out, stderr = self._unshare3('un', 'quinn/qa', 'p1', None)
        principal = self.principal_of('q1', 'qa')
        need(code == 0 and out['removed'] == 0 and out.get('note') ==
             f'the rule for un on this host does not name {principal}. Access through person:quinn, a group, or '
             'everyone is unaffected.' and self.version('p1') == before + 1,
             'removed: 0 for an agent address: the note, nothing signed', out)
        code, out, stderr = self._unshare3('un', f"{ids['n2']}/nagent", 'p1', None)
        need(code == 0 and out['removed'] == 0 and out.get('note') ==
             f"the rule for un on this host does not name {self.principal_of('n2', 'nagent')}. Access through a group "
             'or everyone is unaffected.', 'the removed: 0 note for a host without a person', out)

        # The fallback listing: a stopped host (q3 is still stopped) and a revoked one (q4).
        problems = []
        for address, agent, host in (('quinn/qoff', 'qoff', 'q3'), ('quinn/qrev', 'qrev', 'q4'),
                                     (f"{ids['q4']}/qrev", 'qrev', 'q4')):
            before = self.version('p1')
            code, out, stderr = self._unshare3('st', address, 'p1', None)
            command = f"peerspan unshare st --with agent:{ids[host]}/{aid[agent]} --network {self.team}"
            listed = sorted(set(re.findall(r'peerspan unshare st --with (agent:\S+)', stderr)))
            if not (code != 0 and self.version('p1') == before and command in stderr):
                problems.append((address, code, f'expected agent:{ids[host]}/{aid[agent]}', 'listed', listed,
                                 stderr[:300]))
        for agent, host in (('qoff', 'q3'), ('qrev', 'q4')):
            code, out, stderr = self._unshare3('st', f'agent:{ids[host]}/{aid[agent]}', 'p1', None)
            need(code == 0 and out['removed'] == 1, 'the listed command removes the gone agent', code, out)

        # The note after unshare --with PERSON.
        for recipient in ('quinn', 'quinn/qb', 'quinn/qhid'):
            self.share3('un2', recipient)
        rule = self.rule_principals('un2')
        agents = [p for p in rule if p.startswith('agent:')]
        labels = {self.principal_of('q1', 'qb'): ('quinn/qb', f"{ids['q1']}/qb"),
                  self.principal_of('q1', 'qhid'): ('quinn/qhid', f"{ids['q1']}/qhid")}
        want = ' '.join(f'{labels[p][0]} still has its own share. Run peerspan unshare un2 --with {labels[p][1]} '
                        f'--network {self.team} to remove it.' for p in agents)
        code, out, stderr = self._unshare3('un2', 'quinn', 'p1', None)
        need(code == 0 and set(out) == UNSHARE3_KEYS | {'note'} and out['recipient'] is None,
             'unshare --with PERSON: {policy, capability, principal, recipient, removed, note}, recipient null', out)
        need(code == 0 and out['removed'] == 1 and out.get('note') == want,
             'unshare --with PERSON: the note naming the agent shares that remain, in rule order', out, want)
        need(not problems, 'unshare --with an address that fails to resolve (host stopped, host revoked): exit 1, '
             'nothing signed, and the agent: command for the address\'s hosts listed (for PERSON/AGENT, the hosts '
             'bound to the person, current members or not)', *problems)
        return ''


def run_share_pairing(coord_binary, cli_binary, daemon_binary, node, label, only=None, old=None):
    if only and not any(name in SHARE_SECTIONS for name in only):
        return []
    with tempfile.TemporaryDirectory(prefix='peerspan-agent-shares-') as temporary:
        pairing = SharePairing(label, cli_binary, daemon_binary, coord_binary, node, Path(temporary), only, old)
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('shares: setup', False, detail))
            print(f'FAIL {label} [agent tools: shares: setup]: {detail}', flush=True)
            if pairing.setup_notes:
                print(f'NOTE {label} agent shares setup: ' + ' | '.join(pairing.setup_notes), flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shares: shutdown', False, repr(error)))
        print(f'---- {label} agent shares: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} sections '
              f'passed in {time.monotonic() - started:.0f}s', flush=True)
        return [(f'agent tools: {name}', ok, detail) for name, ok, detail in pairing.results]


def run_pairing(coord_binary, cli_binary, daemon_binary, node, label, integrations=None, only=None, other=None,
                baseline17=None):
    global INTEGRATIONS
    if integrations:
        INTEGRATIONS = Path(integrations)
    if only and all(name in SHARE_SECTIONS for name in only):
        return []
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-agents-') as temporary:
        pairing = AgentPairing(label, cli_binary, daemon_binary, coord_binary, node, Path(temporary), only, other,
                               baseline17)
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
