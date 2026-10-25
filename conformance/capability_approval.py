#!/usr/bin/env python3
"""Per-call approval (capabilities slice 3, item B), run by conformance/capabilities.py.

Written from docs/capabilities-contract.md ("Per-call approval (slice 3)" and its Verification list), with the
accepted proposal docs/capabilities-slice3-approval-proposal.md for intent, independently of the Go and Rust hosts
and of the shared Node adapter, which runs here only as a black box (`attach claude --runner NODE`, with a fixture
`claude` executable; no model runs).

Each CLI/daemon pairing gets its own topology:
- pat: p1 serves the capabilities. Its agent `srv` is the source agent, attached with --no-calls so that its
  verified session receives approval notices; its source is `srv/fx`, the fixture MCP server. p1 also has a
  second attached agent, `srv2`, and `srv3` (source `srv3/fx3`, capability `quiet`), whose adapter the notices
  section pauses; and the registered (never attached) agents `srvraw` (source `srvraw/fxr`,
  capability `rawcap`) and `nobody`, for raw requests to the notice claim route. p2 is pat's trusted host (agent `pa`, --calls) and serves `late` (source
  `srvp2/fx`) for the agent timeout case. o2 runs a version 18 host (--baseline18) serving `oldcap`.
- quinn: q1 (agents `qa` and `qb`, --calls), and o1, a version 18 host (--baseline18) calling from its own CLI.
- rhea: r1, whose person label carries a C1 control character (U+009B, CSI), as another caller.
Network: team.

Capabilities on p1, on srv/fx's own instance unless noted: `chg` (changing; echo, write_note, purge, and resources),
`every` (all; echo and resources), `named` (the list [echo]; echo and write_note), `plain` (none), `mine`
(changing; for self access), `pend` (all; the pending limit), `both` (all, 20 calls an hour: the budget before the
pending limit), `rev` (all; approve after unshare), and, each with its own instance (`--arg`), `iso` (no instance
for a pending call) and `rst` (restart).

Sections, per pairing (contract Verification bullets in brackets): configuration, acceptance, decisions, CLI,
caller, notices, status, older peers, and last the agent timeout case [Caller: one call_update after timeout],
whose 15-minute call is started during setup. Once per run (from capabilities.py): migration from versions 18 and
19 to 20, and version 21 refused [Migration].

Where the contract is silent, the suite takes the narrowest reading or makes no assertion; such spots are marked
"Q:" and soft results are NOTE lines.
"""
import json
from pathlib import Path
import re
import secrets
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
import traceback

from coordination import wait_for
from host_service import APPROVAL_TABLES, BUILTIN_TABLES, LINKING_TABLES, SCHEMA_VERSION, Host, UnixHTTPConnection, stop_all
from launch_onboarding import Failure, need, parse_time as parse_datetime
from live_delivery import Fixture as ClaudeFixture
from peer_messaging import fixture_context, timestamp, wire
from persons import Agent, person_id, ssh_key

import capabilities as caps
import capability_agents as agents
from capabilities import CapHost, PYTHON
from capability_agents import AgentPairing, NEVER_RAN_NOTE, FINAL, CALL_ID, LAPSED, cid, marker, meta_equal

# --- the contract's exact texts and shapes ----------------------------------------------------------------------

NONE = {'operations': 'none', 'agent_self': True}
APPROVAL_KEYS = {'state', 'requested_at', 'expires_at', 'decided_at', 'reason'}
RECORD_KEYS = {'sender_host_id', 'call_id', 'state', 'capability', 'operation', 'changes_things', 'caller', 'origin',
               'input_sha256', 'requested_at', 'expires_at', 'decided_at', 'reason'}
CALLER_KEYS = {'person_id', 'person_label', 'host_id', 'via'}
LISTED_KEYS = RECORD_KEYS | {'input_preview', 'input_bytes'}
SHOWN_KEYS = LISTED_KEYS | {'input'}
NOTICE_KEYS = {'id', 'sender_host_id', 'call_id', 'agent_id', 'session_id', 'state', 'created_at'}
NOTICE_META = {'notice_id', 'call_id', 'sender_host_id', 'caller', 'origin_agent_id', 'capability', 'operation',
               'changes_things', 'expires_at'}
NOTICE_ID = re.compile(r'notice_[0-9a-f]{32}')
STATES = ('pending', 'approved', 'denied', 'expired', 'cancelled')
AWAITING_NOTE = ('The capability\'s owner must approve this call before it runs; it has not run. Its result arrives '
                 'as a kind=call_update event; call_status reports it at any time. Do not call it again: a new call '
                 'needs a new approval.')
NOTICE_TEXT = ('A call to your capability {capability} ({operation}) from {caller} is waiting for the person\'s '
               'approval, until {expires}. You cannot approve or deny it. Tell the person, and ask them to run '
               'peerspan approvals in a terminal on this machine.')
NEEDS_TERMINAL = 'peerspan approve needs a terminal: approval must come from the person.'
APPROVE_PROMPT = 'Approve this call? It runs once, with the credentials it runs with on this machine. [y/N]'
GUIDED_PROMPT = 'Require your approval for each call to tools that can change things? [Y/n]'
SHARE_PROMPT = caps.SHARE_PROMPT
REVIEW_EVERY = 'Every call waits for your approval at this machine (peerspan approvals).'
REVIEW_SOME = 'Calls to {ops} wait for your approval at this machine (peerspan approvals).'
REVIEW_NONE = 'No call waits for your approval. To require it: peerspan capability approval {name} changing'
REVIEW_HINT = 'Tools are marked by the server itself; a tool it wrongly marks read-only runs without approval.'
EMPTY = 'No calls are waiting for your approval.'
NO_LONGER = 'the call is no longer waiting for approval'
TOO_MANY = 'too many calls are waiting for approval'
DESCRIPTION = ('Some operations wait for their owner\'s approval, shown by approval in list_capabilities; such a call '
               'returns awaiting_approval, and its result follows as a kind=call_update event.')
WAITING = 'Waiting for {owner} to approve this call (until {expires}). Check it later with peerspan calls inspect ' \
          '--peer {host} {id}.'
VIEW_KEYS = agents.VIEW_KEYS | {'approval'}
DOCS = ['fixture://docs/guide', 'fixture://docs/readme']
VERSION = 20
NEW_TABLES = ('approval_notices', 'call_approvals')
NEW_INDEX = 'call_approvals_state'
RHEA_LABEL = 'rhea\u009b31m'   # a C1 control (CSI); labels exclude only U+0000 to U+001F and U+007F
INTEGRATIONS = agents.INTEGRATIONS
# How long after a deadline a pending approval may still be pending: the daemon checks at least every 5 seconds.
SWEEP = 5 + 2


def api(host, method, path, body=None, timeout=60):
    """A local API request with a timeout suited to a loaded machine (host_service's default is 3 seconds)."""
    connection = UnixHTTPConnection(host.state / 'admin.sock', timeout=timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        connection.request(method, path, payload, {'Content-Type': 'application/json'})
        response = connection.getresponse()
        data = response.read()
        try:
            return response.status, json.loads(data)
        except ValueError:
            return response.status, data.decode(errors='replace')
    finally:
        connection.close()


def db_rows(host, statement, args=()):
    """Rows from the host's database, waiting out the daemon's write locks (up to 30 seconds)."""
    connection = sqlite3.connect(host.state / 'host.db', timeout=30)
    try:
        return connection.execute(statement, args).fetchall()
    finally:
        connection.close()


def input_text(value):
    """The input encoded as the call view encodes a result (agents.canonical: the slice 2 result text)."""
    return agents.canonical(value)


def preview_of(value):
    """input_preview: the longest prefix of at most 512 bytes ending on a character boundary, then U+007F and
    U+0080 to U+009F written as \\u and four lowercase hex digits."""
    data = input_text(value).encode()
    cut = min(512, len(data))
    while cut < len(data) and cut > 0 and (data[cut] & 0xC0) == 0x80:
        cut -= 1
    prefix = data[:cut].decode()
    return ''.join('\\u%04x' % ord(ch) if 0x7f <= ord(ch) <= 0x9f else ch for ch in prefix)


def raw_controls(text):
    """Characters a terminal could act on, other than newline and tab (and carriage return)."""
    return sorted({hex(ord(ch)) for ch in text if (ord(ch) < 0x20 and ch not in '\n\t\r') or 0x7f <= ord(ch) <= 0x9f})


def note_for(state, truncated):
    if state == 'awaiting_approval':
        return AWAITING_NOTE
    return agents.note_for(state, truncated)


def check_view(view, rule='a call view'):
    """The slice 2 call view, plus `approval` and the derived state `awaiting_approval`."""
    need(isinstance(view, dict) and set(view) == VIEW_KEYS, f'{rule}: the call view has exactly the slice 2 fields '
         'plus approval', sorted(set(view) ^ VIEW_KEYS) if isinstance(view, dict) else view)
    need(CALL_ID.fullmatch(view['call_id'] or ''), f'{rule}: call_id', view['call_id'])
    need(view['note'] == note_for(view['state'], view['truncated']), f'{rule}: note is the exact text for its state',
         view['state'], view['note'])
    a = view['approval']
    need(a is None or (isinstance(a, dict) and set(a) == APPROVAL_KEYS),
         f'{rule}: approval is null or {{state, requested_at, expires_at, decided_at, reason}}', a)
    if view['state'] == 'awaiting_approval':
        need(a and a['state'] == 'pending', f'{rule}: awaiting_approval only with a pending approval', view)
    elif a and a['state'] == 'pending':
        need(view['state'] in ('submitting', 'awaiting_approval'), f'{rule}: a queued call whose approval is pending '
             'shows awaiting_approval', view)
    return view


def status_approval(record, rule):
    """The peer status record's `approval`: null, or {state, requested_at, expires_at, decided_at, reason}."""
    need(isinstance(record, dict) and 'approval' in record, f'{rule}: the status record has approval',
         str(record)[:400])
    a = record['approval']
    need(a is None or (isinstance(a, dict) and set(a) == APPROVAL_KEYS), f'{rule}: approval is null or {{state, '
         'requested_at, expires_at, decided_at, reason}}', a)
    return a


def parse_time(value):
    """An RFC3339 time as seconds since the epoch."""
    return parse_datetime(value).timestamp()


def same_time(a, b, slack=1.0):
    return a is not None and b is not None and abs(parse_time(a) - parse_time(b)) <= slack


class PatientHost(CapHost):
    """A CapHost whose local API requests wait up to 60 seconds, for a loaded machine."""

    def call(self, method, path, body=None, raw=None):
        return api(self, method, path, raw if raw is not None else body)


class ApprovalPairing(AgentPairing):
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, node, root, only=None, baseline18=None):
        super().__init__(label, cli_binary, daemon_binary, coord_binary, node, root, only)
        self.baseline18 = baseline18
        self.extra = []
        self.labels = {}

    # --- infrastructure ----------------------------------------------------------------------------------------

    def host(self, name, person, daemon=None, cli=None):
        h = PatientHost(daemon or self.daemon, cli or self.cli_binary, self.root / name, self.root / f'user-{name}')
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
            print(f'FAIL {self.label} [approval: {name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [approval: {name}] ({time.monotonic() - started:.0f}s)'
              f'{": " + notes if notes else ""}', flush=True)
        return True

    def sync_pat(self):
        self.synced(self.version('p1'), 'p2', 'q1', 'r1', *self.extra)

    def create_cli(self, host, name, source, operations, *flags, resources=None, expect=0):
        argv = ['capability', 'create', name, '--from', source]
        if operations:
            argv += ['--operations', ','.join(operations)]
        if resources:
            argv += ['--resources', ','.join(resources) if isinstance(resources, list) else resources]
        code, out, stdout, stderr = self.hosts[host].outcome(*argv, *flags)
        if expect is not None:
            need(code == expect, f'capability create {name} {" ".join(flags)}', expect, code, stderr[-400:])
        return code, out, stderr

    def record(self, name, host='p1'):
        status, body = api(self.hosts[host], 'GET', f'/v1/capabilities/{name}')
        need(status == 200 and isinstance(body, dict), f'GET /v1/capabilities/{name}', status, body)
        return body

    def set_approval(self, name, *args, host='p1'):
        code, out, stdout, stderr = self.hosts[host].outcome('capability', 'approval', name, *args)
        need(code == 0, f'capability approval {name} {" ".join(args)}', code, stderr[-400:])
        return out

    def versions(self):
        """pat's stored policy version in team on p1."""
        return self.version('p1')

    def cite(self):
        return {'policy': {'person_id': self.pat, 'network_id': self.team, 'version': self.version('p1')}}

    def self_cite(self):
        return {'self': {'person_id': self.pat, 'network_id': self.team}}

    def origin(self, name):
        s = self.s(name)
        return {'agent_id': s['agent_id'], 'session_id': s['session_id']}

    def submit(self, caller, capability, operation, input=None, call=None, deadline=None, cite=None, origin=None,
               receiver='p1', expect=200, rule=None):
        """POST /peer/v1/calls through the probe as `caller`: (body, status, record)."""
        body = {'call_id': call or cid(), 'capability': capability, 'operation': operation,
                'input': input if input is not None else {}, 'deadline': deadline or timestamp(600)}
        if origin:
            body['origin'] = origin
        body.update(cite or (self.self_cite() if caller == 'p2' else self.cite()))
        status, record = wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'POST', '/peer/v1/calls',
                              body)
        retry_until = time.monotonic() + 45
        while status == 503 and expect != 503 and time.monotonic() < retry_until:
            # Recoverable (contract: 503 while coordination is disconnected, as for messages); a loaded machine
            # sometimes drops the receiver's coordinator connection briefly. Nothing was persisted.
            time.sleep(2)
            status, record = wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'POST',
                                  '/peer/v1/calls', body)
        if expect is not None:
            need(status == expect, rule or f'POST /peer/v1/calls {capability} {operation} from {caller}', expect,
                 status, record)
        return body, status, record

    def peer_status(self, caller, call_id, query='', receiver='p1'):
        status, record = wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'GET',
                              f'/peer/v1/calls/{call_id}{query}')
        need(status == 200, 'GET /peer/v1/calls/{id}', status, record)
        return record

    def peer_final(self, caller, call_id, timeout=60):
        def done():
            r = self.peer_status(caller, call_id)
            return r if r.get('state') in FINAL else None
        return wait_for(done, timeout=timeout, message=f'call {call_id} final at the receiver')

    def held(self, rule, record):
        """A just-accepted call that needs approval."""
        a = status_approval(record, rule)
        need(record['state'] == 'queued' and a and a['state'] == 'pending' and a['decided_at'] is None and
             a['reason'] is None, f'{rule}: queued, with approval pending', record)
        return a

    def runs(self, rule, caller, record):
        """A call that needs no approval: approval null, and it runs at once."""
        a = status_approval(record, rule)
        need(a is None, f'{rule}: approval is null (no approval needed)', record)
        final = self.peer_final(caller, record['call_id'])
        need(final['state'] == 'succeeded' and final.get('approval') is None, f'{rule}: it runs at once', final)
        return final

    def approvals(self, state=None):
        path = '/v1/approvals' + (f'?state={state}' if state else '')
        status, body = api(self.hosts['p1'], 'GET', path)
        need(status == 200 and isinstance(body, dict) and set(body) == {'approvals'} and
             isinstance(body['approvals'], list), f'GET {path} returns {{approvals: [...]}}', status,
             str(body)[:300])
        for a in body['approvals']:
            self.check_record(a, LISTED_KEYS)
        return body['approvals']

    def check_record(self, a, keys=RECORD_KEYS):
        need(isinstance(a, dict) and set(a) == keys, 'an approval record has exactly the contract\'s fields',
             sorted(set(a) ^ keys) if isinstance(a, dict) else a)
        need(a['state'] in STATES, 'approval state', a['state'])
        need(isinstance(a['caller'], dict) and set(a['caller']) == CALLER_KEYS and
             a['caller']['via'] in ('policy', 'self'), 'caller is {person_id, person_label, host_id, via}',
             a['caller'])
        need(isinstance(a['changes_things'], bool), 'changes_things is a boolean', a)
        need(isinstance(a['input_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', a['input_sha256']),
             'input_sha256 is lowercase hex SHA-256', a['input_sha256'])
        need((a['decided_at'] is None) == (a['state'] == 'pending'), 'decided_at is null exactly while pending', a)
        return a

    def shown(self, sender, call_id, expect=200):
        status, body = api(self.hosts['p1'], 'GET', f'/v1/approvals/{self.ids[sender]}/{call_id}')
        if expect is not None:
            need(status == expect, 'GET /v1/approvals/{sender}/{call_id}', expect, status, body)
        if status == 200:
            self.check_record(body, SHOWN_KEYS)
        return body

    def decide(self, sender, call_id, verb, body=None):
        sender_id = self.ids.get(sender, sender)
        return api(self.hosts['p1'], 'POST', f'/v1/approvals/{sender_id}/{call_id}/{verb}', body or {})

    def approve_api(self, sender, call_id):
        status, body = self.decide(sender, call_id, 'approve')
        need(status == 200, 'POST /v1/approvals/{sender}/{call_id}/approve', status, body)
        self.check_record(body)
        need(body['state'] == 'approved', 'approve returns the approved record', body)
        return body

    def deny_api(self, sender, call_id, reason=None):
        status, body = self.decide(sender, call_id, 'deny', {'reason': reason})
        need(status == 200, 'POST /v1/approvals/{sender}/{call_id}/deny', status, body)
        self.check_record(body)
        need(body['state'] == 'denied', 'deny returns the denied record', body)
        return body

    def deny_all(self):
        for a in self.approvals('pending'):
            self.decide(a['sender_host_id'], a['call_id'], 'deny', {'reason': None})

    def activity(self, subject, host='p1'):
        events, after = [], 0
        while True:
            page = self.hosts[host].cli('activity', '--after', str(after), '--limit', '1000')
            events += page
            if len(page) < 1000:
                break
            after = page[-1]['sequence']
        return [e for e in events if e.get('subject_id') == subject]

    def kinds(self, sender, call_id):
        return [e.get('kind') for e in self.activity(f'{self.ids[sender]}/{call_id}')]

    def has_kinds(self, sender, call_id, wanted, rule):
        def present():
            kinds = self.kinds(sender, call_id)
            return kinds if all(k in kinds for k in wanted) else None
        try:
            return wait_for(present, timeout=10, message='activity')
        except Exception:
            raise Failure(f'{rule}: activities {wanted} for {sender}/{call_id}; got {self.kinds(sender, call_id)}')

    def executed(self, key, text):
        return self.fixture.calls(key, marker=text)

    def starts(self, key):
        return [e for e in self.fixture.entries(key) if e['event'] == 'start']

    def notices(self, name, call_id=None, since=0.0):
        c = self.s(name)['consumer']
        return [p for _, p in c.channel(since) if (p.get('meta') or {}).get('kind') == 'approval_request' and
                (call_id is None or (p.get('meta') or {}).get('call_id') == call_id)]

    def ok_call(self, name, address, operation, input=None, wait=None, call_id=None, rule='call_capability'):
        failed, value, elapsed = self.cc(name, address, operation, input, wait, call_id)
        need(not failed, f'{rule}: not a tool error', value)
        check_view(value, rule)
        return value, elapsed

    def view(self, name, call_id):
        failed, value = self.status(name, call_id)
        need(not failed, 'call_status: not a tool error', value)
        return check_view(value, 'call_status')

    def until_view(self, name, call_id, states, timeout=30):
        def reached():
            v = self.view(name, call_id)
            return v if v['state'] in states else None
        return wait_for(reached, timeout=timeout, message=f'call {call_id} in {sorted(states)} through call_status')

    def update_events(self, name, call_id):
        return self.events_for(name, call_id)

    def check_update(self, name, params, rule):
        meta = {k: v for k, v in (params.get('meta') or {}).items() if k != 'kind'}
        try:
            view = json.loads(params.get('content') or '')
        except ValueError:
            raise Failure(f'{rule}: content is the call view as JSON text: {str(params.get("content"))[:300]}')
        check_view(view, rule)
        for key in ('call_id', 'state', 'error'):
            need(meta_equal(meta.get(key), view[key]), f'{rule}: meta {key} matches the call view', meta.get(key),
                 view[key])
        return meta, view

    def pending_work(self, name):
        failed, value = self.tool(self.s(name)['consumer'], 'pending_work', {})
        need(not failed and isinstance(value, dict) and isinstance(value.get('calls'), list),
             'pending_work returns calls', failed, str(value)[:300])
        return value

    def count(self, host, table, where='', args=()):
        return db_rows(self.hosts[host], f'SELECT COUNT(*) FROM {table} {where}', args)[0][0]

    def outbound_record(self, host, call_id):
        rows = db_rows(self.hosts[host], 'SELECT record FROM outbound_calls WHERE call_id = ?', (call_id,))
        return json.loads(rows[0][0]) if rows else None

    def wait_outbound(self, host, call_id, predicate, timeout=60, step=0.05):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self.outbound_record(host, call_id)
            if r and predicate(r):
                return r, time.time()
            time.sleep(step)
        raise Failure(f'outbound call {call_id} on {host}: {str(self.outbound_record(host, call_id))[:600]}')

    def held_get(self, context, path, decided, key):
        """A held GET through the probe; a probe failure is reported with when the decision was made."""
        started = time.time()
        try:
            return wire(self.hosts['p1'], context, 'GET', path)
        except OSError as error:
            raise Failure(f'held GET {path}: {error} after {time.time() - started:.1f}s; the {key} returned '
                          f'{decided[key] - started:.1f}s in' if key in decided else
                          f'held GET {path}: {error} after {time.time() - started:.1f}s; the {key} had not returned')

    def peer_listing(self, caller, receiver='p1'):
        status, body = wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'GET', '/peer/v1/capabilities')
        need(status == 200 and isinstance(body, list), 'GET /peer/v1/capabilities', status, str(body)[:300])
        return {e['capability']: e for e in body}

    @staticmethod
    def op_flags(entry):
        return {o['name']: o.get('approval', 'absent') for o in entry['operations']}

    def log_tail(self, name, size=2500):
        """The end of a daemon's log (its stdout and stderr), for failure reports."""
        h = self.hosts[name]
        try:
            h.logs.flush()
            h.logs.seek(0)
            return h.logs.read().decode(errors='replace')[-size:]
        except Exception as error:
            return f'(no log: {error})'

    def close(self):
        failures = []
        try:
            for c in self.consumers:
                try:
                    c.close()
                except Exception:
                    pass
            for name, h in self.hosts.items():
                try:
                    h.stop()
                except Exception as error:
                    failures.append(f'{name}: {error!r}')
                    print(f'NOTE {self.label} approval: {name} did not stop cleanly ({error!r}); its log ends: '
                          f'{self.log_tail(name)!r}', flush=True)
                finally:
                    try:
                        h.logs.close()
                    except Exception:
                        pass
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()
        if failures:
            raise AssertionError('; '.join(failures))

    def restart_p1(self):
        """Restart p1; its attached adapters reconnect by themselves. The srv consumer's channel is kept."""
        self.restart('p1')
        time.sleep(3)

    # --- setup -------------------------------------------------------------------------------------------------

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        for name in ('pat', 'quinn', 'rhea'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.quinn, self.rhea = (person_id(self.keys[n][2]) for n in ('pat', 'quinn', 'rhea'))
        self.fixture = caps.Fixture(root / 'fixture')
        self.claude = ClaudeFixture(root / 'claude')
        self.coord_key = self.coord.start()['public_key']
        persons = {'p1': 'pat', 'p2': 'pat', 'q1': 'quinn', 'r1': 'rhea'}
        for name, person in persons.items():
            self.host(name, person)
        if self.baseline18:
            self.host('o1', 'quinn', self.baseline18, self.baseline18)
            self.host('o2', 'pat', self.baseline18, self.baseline18)
            persons.update({'o1': 'quinn', 'o2': 'pat'})
            self.extra = ['o1', 'o2']
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids, h = self.ids, self.hosts

        self.team = h['p1'].cli('network', 'create', 'team', '--as', 'pat', '--trusted',
                                *self.coordinator_flags())['id']
        self.labels = {'pat': 'pat', 'quinn': 'quinn', 'rhea': RHEA_LABEL}
        for name, flags in (('p2', ('--trusted',)), ('q1', ('--untrusted',)), ('r1', ('--untrusted',)),
                            *[(n, ('--untrusted',)) for n in self.extra]):
            label = self.labels[persons[name]]
            code, out, stdout, stderr = h[name].outcome('join', self.invite(label, self.team), *flags)
            if code != 0 and name == 'r1':
                self.setup_notes.append(f'join with the label {label!r} failed ({stderr[-200:]}); using rhea')
                self.labels['rhea'] = 'rhea'
                h[name].cli('join', self.invite('rhea', self.team), *flags)
            else:
                need(code == 0, f'setup: join {name}', code, stderr[-300:])
        expected = {ids[n]: {'pat': self.pat, 'quinn': self.quinn, 'rhea': self.rhea}[p] for n, p in persons.items()}

        def bound():
            for n in persons:
                h[n].run('network', 'sync', self.team)
            seen = {m['host_id']: m['person_id'] for m in h['p1'].cli('network', 'members', self.team)}
            return seen == expected
        wait_for(bound, timeout=90, message='every member of team bound as expected')

        # Sessions. srv is the source agent of p1's capabilities: attached without calls, verified, with the fixture
        # put in place as its tool server.
        for host, name, flags in (('p1', 'srv', ('--no-calls',)), ('p1', 'srv2', ('--no-calls',)),
                                  ('p2', 'pa', ('--calls',)), ('q1', 'qa', ('--calls',)), ('q1', 'qb', ('--calls',))):
            self.session(host, name, *flags)
        need('srv' in self.sessions, 'setup: the source agent srv attached and verified', self.setup_notes)
        self.put_servers('p1', 'srv', {'fx': self.fixture.args('fx')})
        # srv3: the source agent of `quiet`, whose adapter the notices section pauses (notices decided before a claim).
        self.session('p1', 'srv3', '--no-calls')
        need('srv3' in self.sessions, 'setup: srv3 attached and verified', self.setup_notes)
        self.put_servers('p1', 'srv3', {'fx3': self.fixture.args('fx3')})
        # srvraw: a registered agent (never attached), the source of `rawcap`, for raw claim-route requests; nobody: a
        # registered agent with no capability.
        self.register('p1', 'srvraw', 'pat')
        self.put_servers('p1', 'srvraw', {'fxr': self.fixture.args('fxr')})
        self.register('p1', 'nobody', 'pat')
        status, body = api(h['p1'], 'POST', '/v1/sources/open-to', {'host_id': ids['p2']})
        need(status in (200, 201), 'setup: p1 opens its sources to p2', status, body)

        # p2 serves `late` (the agent timeout case), so p1's approvals stay this suite's to count.
        self.synced(self.version('p1'), 'p2')
        self.register('p2', 'srvp2', 'pat')
        self.put_servers('p2', 'srvp2', {'fx': self.fixture.args('fx-p2')})
        self.create_cli('p2', 'late', 'srvp2/fx', ['echo'], '--approval', 'all')
        self.share('p2', 'late', 'quinn', per_hour=1000)
        self.synced(self.version('p2'), 'p1')

        if 'o2' in h:
            self.synced(self.version('p1'), 'o2')
            self.register('o2', 'srvo', 'pat')
            self.put_servers('o2', 'srvo', {'fx': self.fixture.args('fx-o2')})
            self.create('o2', 'oldcap', 'srvo/fx', ['echo', 'write_note'])
            self.share('o2', 'oldcap', 'quinn', per_hour=1000)
            self.synced(self.version('o2'), 'p1')

        f = self.fixture
        for name, operations, flags, resources in (
                ('chg', ['echo', 'write_note', 'purge'], ('--approval', 'changing'), DOCS),
                ('every', ['echo'], ('--approval', 'all'), DOCS),
                ('named', ['echo', 'write_note'], ('--approval', 'echo'), None),
                ('plain', ['echo', 'write_note'], (), None),
                ('mine', ['echo', 'write_note'], ('--approval', 'changing'), None),
                ('pend', ['echo'], ('--approval', 'all'), None),
                ('both', ['echo'], ('--approval', 'all'), None),
                ('rev', ['echo'], ('--approval', 'all'), None),
                ('iso', ['echo', 'sleep'], ('--approval', 'all', *self.args_flags(f.args('iso', isolated=False))),
                 None),
                ('rst', ['echo', 'sleep'], ('--approval', 'all', *self.args_flags(f.args('rst', isolated=False))),
                 None)):
            self.create_cli('p1', name, 'srv/fx', operations, *flags, resources=resources)
        self.create_cli('p1', 'quiet', 'srv3/fx3', ['echo'], '--approval', 'all')
        self.create_cli('p1', 'rawcap', 'srvraw/fxr', ['echo'], '--approval', 'all')
        for name in ('chg', 'every', 'named', 'plain', 'mine', 'pend', 'iso', 'rst', 'quiet', 'rawcap'):
            self.share('p1', name, 'quinn', per_hour=1000)
        self.share('p1', 'pend', 'person:' + self.rhea)
        self.share('p1', 'chg', 'person:' + self.rhea)
        self.share('p1', 'both', 'quinn', per_hour=20)
        self.share('p1', 'rev', 'quinn')
        self.sync_pat()

        # The agent timeout case: an agent call's deadline is 15 minutes, so it starts now and is checked last.
        self.timeout_call = None
        try:
            text = marker('agent-timeout')
            view, _ = self.ok_call('qb', 'pat/late', 'echo', {'text': text}, wait=0)
            self.timeout_call = (view['call_id'], text)
        except Exception as error:
            self.setup_notes.append(f'the agent timeout call: {str(error)[:300]}')

        self.section('configuration', self.check_configuration)
        self.section('acceptance', self.check_acceptance)
        self.section('decisions', self.check_decisions)
        self.section('CLI', self.check_cli)
        self.section('caller', self.check_caller)
        self.section('notices', self.check_notices)
        self.section('status', self.check_status)
        self.section('older peers', self.check_older)
        self.section('caller: timeout', self.check_agent_timeout)
        if self.setup_notes:
            print(f'NOTE {self.label} approval setup: ' + ' | '.join(self.setup_notes), flush=True)

    @staticmethod
    def args_flags(args):
        out = []
        for a in args:
            out += ['--arg', a]
        return out

    # --- configuration -------------------------------------------------------------------------------------

    def check_configuration(self):
        p1 = self.hosts['p1']
        # Each mode at create; absent means none; the list stored sorted by byte order and deduplicated.
        for name, flags, want in (
                ('cfg-none', (), NONE),
                ('cfg-chg', ('--approval', 'changing'), {'operations': 'changing', 'agent_self': True}),
                ('cfg-all', ('--approval', 'all'), {'operations': 'all', 'agent_self': True}),
                ('cfg-list', ('--approval', 'write_note,echo,write_note'),
                 {'operations': ['echo', 'write_note'], 'agent_self': True}),
                ('cfg-noself', ('--approval', 'changing', '--no-agent-self-approval'),
                 {'operations': 'changing', 'agent_self': False}),
                ('cfg-noself2', ('--no-agent-self-approval',), {'operations': 'none', 'agent_self': False}),
                ('cfg-explicit', ('--approval', 'none'), NONE)):
            self.create_cli('p1', name, 'srv/fx', ['echo', 'write_note'], *flags)
            got = self.record(name).get('approval')
            need(got == want, f'capability create {" ".join(flags) or "(no --approval)"} stores approval', want, got)
        self.create_cli('p1', 'cfg-read', 'srv/fx', ['echo'], '--approval', 'read', resources=DOCS)
        need(self.record('cfg-read')['approval'] == {'operations': ['read'], 'agent_self': True},
             'read in the list of a capability with resources', self.record('cfg-read')['approval'])

        # Through the API: an absent agent_self reads as true.
        status, body = api(p1, 'POST', '/v1/capabilities', self.api_body('cfg-api', {'operations': 'all'}))
        need(status == 201 and body.get('approval') == {'operations': 'all', 'agent_self': True},
             'POST /v1/capabilities: an absent agent_self means true', status, body)

        # Refusals: a list name that is not an operation, read without resources, an empty list, an invalid value.
        before = self.versions()
        for name, ops, value in (('cfg-bad1', ['echo'], 'purge'), ('cfg-bad2', ['echo'], 'read'),
                                 ('cfg-bad3', ['echo'], 'sometimes')):
            code, out, stderr = self.create_cli('p1', name, 'srv/fx', ops, '--approval', value, expect=None)
            need(code == 1 and self.capability_missing(name), 'capability create with an invalid --approval exits 1, '
                 'creating nothing', value, code, stderr[-300:])
        for name, approval in (('cfg-bad4', {'operations': ['purge'], 'agent_self': True}),
                               ('cfg-bad5', {'operations': ['read'], 'agent_self': True}),
                               ('cfg-bad6', {'operations': [], 'agent_self': True}),
                               ('cfg-bad7', {'operations': 'sometimes', 'agent_self': True}),
                               ('cfg-bad8', {'operations': 'all', 'agent_self': 'yes'}),
                               ('cfg-bad9', 'all')):
            status, body = api(p1, 'POST', '/v1/capabilities', self.api_body(name, approval))
            need(status == 400 and self.capability_missing(name), 'POST /v1/capabilities with an invalid approval is '
                 '400', approval, status, body)
            status, body = api(p1, 'PUT', '/v1/capabilities/cfg-none/approval', approval)
            need(status == 400 and self.record('cfg-none')['approval'] == NONE,
                 'PUT /v1/capabilities/{name}/approval with an invalid value is 400, the record unchanged', approval,
                 status, body)
        status, body = api(p1, 'PUT', '/v1/capabilities/cfg-none/approval', {'agent_self': False})
        need(status == 400, 'PUT approval without operations is 400', status, body)
        need(self.versions() == before, 'refusals sign nothing', before, self.versions())

        # Repeat and conflict, including approval, compared after reading defaults.
        before = self.versions()
        self.create_cli('p1', 'cfg-chg', 'srv/fx', ['echo', 'write_note'], '--approval', 'changing')
        self.create_cli('p1', 'cfg-none', 'srv/fx', ['echo', 'write_note'], '--approval', 'none')
        self.create_cli('p1', 'cfg-list', 'srv/fx', ['echo', 'write_note'], '--approval', 'echo,write_note')
        need(self.versions() == before, 'identical repeats (approval included, after defaults) sign nothing', before)
        status, body = api(p1, 'POST', '/v1/capabilities', self.api_body('cfg-api', {'operations': 'all',
                                                                                     'agent_self': True}))
        need(status == 200, 'an identical repeat through the API returns 200', status, body)
        for flags in (('--approval', 'all'), ('--approval', 'changing', '--no-agent-self-approval')):
            code, out, stderr = self.create_cli('p1', 'cfg-chg', 'srv/fx', ['echo', 'write_note'], *flags,
                                                expect=None)
            need(code != 0 and self.record('cfg-chg')['approval'] == {'operations': 'changing', 'agent_self': True},
                 'a repeat differing only in approval is refused, the record unchanged', flags, code)
        status, body = api(p1, 'POST', '/v1/capabilities', self.api_body('cfg-api', {'operations': 'changing'}))
        need(status == 409, 'a repeat differing in approval through the API is 409', status, body)

        # `capability approval`: modes, agent_self kept when neither flag is given, no signing, the activity, 404.
        before = self.versions()
        count = len([e for e in self.activity('cfg-none') if e.get('kind') == 'capability.approval_changed'])
        for args, want in ((('all',), {'operations': 'all', 'agent_self': True}),
                           (('changing', '--no-agent-self'), {'operations': 'changing', 'agent_self': False}),
                           (('echo',), {'operations': ['echo'], 'agent_self': False}),
                           (('write_note,echo', '--agent-self'), {'operations': ['echo', 'write_note'],
                                                                  'agent_self': True}),
                           (('none',), NONE),
                           (('none',), NONE)):
            out = self.set_approval('cfg-none', *args)
            got = self.record('cfg-none')['approval']
            need(got == want, f'capability approval cfg-none {" ".join(args)}', want, got)
            need(isinstance(out, dict) and out.get('name') == 'cfg-none' and out.get('approval') == want,
                 'capability approval prints the record', str(out)[:300])
        need(self.versions() == before, 'capability approval signs no policy (the stored versions unchanged)', before,
             self.versions())
        changed = [e for e in self.activity('cfg-none') if e.get('kind') == 'capability.approval_changed']
        need(len(changed) == count + 6, 'each change, also one that changes nothing, records '
             'capability.approval_changed with the name as subject', count, len(changed))
        status, body = api(p1, 'PUT', '/v1/capabilities/cfg-none/approval', {'operations': 'all'})
        need(status == 200 and isinstance(body, dict) and body.get('approval') == {'operations': 'all',
                                                                                    'agent_self': True} and
             body.get('name') == 'cfg-none', 'PUT approval without agent_self keeps it, returning the record',
             status, body)
        status, body = api(p1, 'PUT', '/v1/capabilities/nosuch/approval', {'operations': 'all'})
        need(status == 404, 'PUT approval for an unknown capability is 404', status, body)
        code, out, stdout, stderr = p1.outcome('capability', 'approval', 'nosuch', 'all')
        need(code != 0, 'capability approval for an unknown capability fails', code)
        code, out, stdout, stderr = p1.outcome('capability', 'approval', 'cfg-none', 'all', '--agent-self',
                                               '--no-agent-self')
        need(code == 1, '--agent-self and --no-agent-self together exit 1', code, stderr[-300:])
        code, out, stdout, stderr = p1.outcome('capability', 'approval', 'cfg-none', 'purge')
        need(code != 0 and self.record('cfg-none')['approval']['operations'] == 'all',
             'capability approval naming a non-operation is refused', code)

        # Records without approval read as none: the record with the field removed from storage, as one written
        # before this slice.
        self.strip_approval('cfg-noself2')
        need(self.record('cfg-noself2')['approval'] == NONE, 'a stored record without approval reads as none with '
             'agent_self true', self.record('cfg-noself2'))

        # Show, list, and shares.
        code, out, stdout, stderr = p1.outcome('capability', 'show', 'cfg-noself')
        need(code == 0 and isinstance(out, dict) and out.get('approval') == {'operations': 'changing',
                                                                             'agent_self': False},
             'capability show shows approval', code, stdout[-400:])
        code, out, stdout, stderr = p1.outcome('capability', 'list', '--json')
        listed = out if isinstance(out, list) else (out or {}).get('capabilities') if isinstance(out, dict) else None
        need(code == 0 and isinstance(listed, list) and all('approval' in c for c in listed) and any(
             c.get('name') == 'chg' and c.get('approval') == {'operations': 'changing', 'agent_self': True}
             for c in listed), 'capability list --json shows approval in every record', code, stdout[-400:])
        status, body = api(p1, 'GET', '/v1/capabilities')
        need(status == 200 and all('approval' in c for c in body['capabilities']), 'GET /v1/capabilities shows '
             'approval in every record', status)
        code, out, stdout, stderr = p1.outcome('shares', '--json')
        need(code == 0 and self.has_approval(out, 'chg', {'operations': 'changing', 'agent_self': True}),
             'shares --json shows approval', code, stdout[-600:])
        code, out, stdout, stderr = p1.outcome('capability', 'list')
        line = next((x for x in stdout.splitlines() if 'cfg-noself' in x and 'cfg-noself2' not in x), '')
        self.soft('approval: changing' in line and '-agent_self' in line, 'the readable capability list line has '
                  'approval: MODE with -agent_self', line)

        self.check_review()
        self.check_guided()
        return ''

    def api_body(self, name, approval):
        return {'name': name, 'source': {'agent': 'srv', 'server': 'fx'}, 'operations': ['echo', 'write_note'],
                'resources': None, 'env_file': None, 'policies': self.claims('p1', name), 'approval': approval}

    def claims(self, host, name):
        """The claim policies the CLI would send (as capabilities.py signs them), for pat's team policy."""
        from policy import sign_edit
        status, start = api(self.hosts[host], 'GET', f'/v1/networks/{self.team}/policy/edit')
        need(status == 200, 'setup: the edit route', status, start)

        def change(p):
            if not any(r['capability'] == name for r in p['capability_rules']):
                p['capability_rules'].append(caps.cap_rule(self.ids[host], name, []))
        return [sign_edit(start, self.team, self.keys['pat'][2], self.ids[host], self.keys['pat'][0], self.root,
                          change)]

    def capability_missing(self, name):
        return api(self.hosts['p1'], 'GET', f'/v1/capabilities/{name}')[0] == 404

    def strip_approval(self, name):
        """Remove `approval` from the stored record (the daemon stopped), as a record written before this slice."""
        h = self.hosts['p1']
        h.stop()
        try:
            connection = sqlite3.connect(h.state / 'host.db', timeout=30)
            try:
                (value,) = connection.execute('SELECT record FROM capabilities WHERE name = ?', (name,)).fetchone()
                record = json.loads(value)
                record.pop('approval', None)
                connection.execute('UPDATE capabilities SET record = ? WHERE name = ?', (json.dumps(record), name))
                connection.commit()
            finally:
                connection.close()
        finally:
            h.logs.close()
            h.logs = tempfile.TemporaryFile()
            h.start()
        time.sleep(3)

    @staticmethod
    def has_approval(value, name, want):
        found = []

        def walk(v):
            if isinstance(v, dict):
                if (v.get('name') == name or v.get('capability') == name) and 'approval' in v:
                    found.append(v['approval'])
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
        walk(value)
        return want in found

    def review_of(self, name):
        """share NAME --with rhea (by person ID) --yes: the review on stderr."""
        code, out, stdout, stderr = self.hosts['p1'].outcome('share', name, '--with', 'person:' + self.rhea, '--yes',
                                                             '--network', self.team)
        need(code == 0, f'share {name} --yes', code, stderr[-400:])
        return stderr

    def check_review(self):
        rows = (('rv-all', ['echo', 'write_note'], ('--approval', 'all'), DOCS),
                ('rv-chg', ['echo', 'write_note', 'purge'], ('--approval', 'changing'), DOCS),
                ('rv-list', ['echo', 'write_note'], ('--approval', 'read,echo'), DOCS),
                ('rv-none', ['echo', 'write_note'], (), None),
                ('rv-ro', ['echo'], (), None))
        for name, ops, flags, resources in rows:
            self.create_cli('p1', name, 'srv/fx', ops, *flags, resources=resources)
        approval_lines = ('wait for your approval', 'waits for your approval', 'No call waits')

        def lines(text):
            return [caps.squash(x) for x in text.splitlines() if caps.squash(x)]
        text = lines(self.review_of('rv-all'))
        need(REVIEW_EVERY in text and REVIEW_HINT not in text, 'the review under all: the every-call line, no hint',
             text)
        text = lines(self.review_of('rv-chg'))
        some = REVIEW_SOME.format(ops='write_note, purge')
        need(some in text and REVIEW_HINT in text and text.index(REVIEW_HINT) == text.index(some) + 1,
             'the review under changing names the tools with read_only false in the record\'s order, then the hint',
             text)
        text = lines(self.review_of('rv-list'))
        need(REVIEW_SOME.format(ops='echo, read') in text and REVIEW_HINT not in text,
             'the review under a list: its names in the record\'s order, read last', text)
        text = lines(self.review_of('rv-none'))
        need(REVIEW_NONE.format(name='rv-none') in text, 'the review under none with a write tool', text)
        text = lines(self.review_of('rv-ro'))
        need(not any(m in x for x in text for m in approval_lines), 'no approval line under none with only read-only '
             'tools', text)
        # Position: after the operation and resource lines and before the credential line; checked here as before
        # the reach statement, which follows the credential and recipient lines.
        joined = caps.squash(self.review_of('rv-all'))
        need(-1 < joined.find(REVIEW_EVERY) < joined.find(caps.REACH), 'the approval line comes before the reach '
             'statement', joined[-800:])
        # share NAME never changes the requirement, and refuses --approval and --no-agent-self-approval.
        before = self.versions()
        for flags in (('--approval', 'all'), ('--no-agent-self-approval',)):
            code, out, stdout, stderr = self.hosts['p1'].outcome('share', 'rv-none', '--with', 'quinn', *flags,
                                                                 '--yes', '--network', self.team)
            need(code == 1 and self.versions() == before, 'share NAME with an approval flag exits 1 before signing',
                 flags, code, stderr[-300:])
        need(self.record('rv-none')['approval'] == NONE and
             self.record('rv-chg')['approval']['operations'] == 'changing', 'share NAME never changes approval')
        for name, *_ in rows:
            self.unshare('p1', name, 'person:' + self.rhea)

    def check_guided(self):
        p1 = self.hosts['p1']
        # Every selection is given as a flag (resources included), so the only questions are approval's, the resource
        # bound's (item D: asked when --bound is not given; answered with an empty line, no bound), and the
        # confirmation.
        flags = ['--from', 'srv/fx', '--operations', 'echo,write_note', '--resources', DOCS[1], '--network',
                 self.team]
        rhea = 'person:' + self.rhea
        code, out, tty, stdout, seen = p1.converse('share', '--with', rhea, *flags, '--name', 'gd-yes',
                                                   answers=['', '', 'y'], prompt=SHARE_PROMPT, timeout=120)
        need(code == 0 and caps.squash(GUIDED_PROMPT) in caps.squash(tty), 'the guided share asks about approval at a '
             'terminal when a selected tool can change things', code, tty[-800:])
        need(self.record('gd-yes')['approval'] == {'operations': 'changing', 'agent_self': True},
             'an empty line (the default) stores changing', self.record('gd-yes')['approval'])
        code, out, tty, stdout, seen = p1.converse('share', '--with', rhea, *flags, '--name', 'gd-no',
                                                   answers=['n', '', 'y'], prompt=SHARE_PROMPT, timeout=120)
        need(code == 0 and self.record('gd-no')['approval'] == NONE, 'answering n stores none', code, tty[-600:])
        code, out, tty, stdout, seen = p1.converse('share', '--with', rhea, *flags, '--name', 'gd-yes2',
                                                   '--no-agent-self-approval', answers=['YES', '', 'y'],
                                                   prompt=SHARE_PROMPT, timeout=120)
        need(code == 0 and self.record('gd-yes2')['approval'] == {'operations': 'changing', 'agent_self': False},
             'YES (any case) means changing; --no-agent-self-approval sets agent_self false', code, tty[-600:])
        code, out, tty, stdout, seen = p1.converse('share', '--with', rhea, '--from', 'srv/fx', '--operations', 'echo',
                                                   '--resources', DOCS[1], '--network', self.team, '--name', 'gd-ro',
                                                   answers=['', 'y'],
                                                   prompt=SHARE_PROMPT, timeout=120)
        need(code == 0 and caps.squash(GUIDED_PROMPT) not in caps.squash(tty) and
             self.record('gd-ro')['approval'] == NONE, 'no approval question when no selected tool can change things',
             code, tty[-600:])
        code, out, tty, stdout, seen = p1.converse('share', '--with', rhea, *flags, '--name', 'gd-given',
                                                   '--approval', 'all', answers=['', 'y'], prompt=SHARE_PROMPT,
                                                   timeout=120)
        need(code == 0 and caps.squash(GUIDED_PROMPT) not in caps.squash(tty) and
             self.record('gd-given')['approval'] == {'operations': 'all', 'agent_self': True},
             'with --approval at a terminal nothing is asked and --approval decides', code, tty[-600:])
        code, out, stdout, stderr = p1.outcome('share', '--with', rhea, *flags, '--name', 'gd-flag', '--approval',
                                               'all', '--yes')
        need(code == 0 and self.record('gd-flag')['approval'] == {'operations': 'all', 'agent_self': True},
             'the guided share without a terminal takes --approval', code, stderr[-400:])
        code, out, stdout, stderr = p1.outcome('share', '--with', rhea, *flags, '--name', 'gd-absent', '--yes')
        need(code == 0 and self.record('gd-absent')['approval'] == NONE and
             caps.squash(GUIDED_PROMPT) not in caps.squash(stderr), 'without a terminal or --approval: none, nothing '
             'asked', code, stderr[-400:])
        for name in ('gd-yes', 'gd-no', 'gd-yes2', 'gd-ro', 'gd-given', 'gd-flag', 'gd-absent'):
            self.unshare('p1', name, rhea)
        self.sync_pat()

    # --- acceptance ------------------------------------------------------------------------------------------

    def check_acceptance(self):
        # changing: a write tool held (and not run), a read-only tool and read at once.
        text = marker('chg-w')
        body, _, record = self.submit('q1', 'chg', 'write_note', {'text': text})
        a = self.held('changing, write_note', record)
        need(same_time(a['expires_at'], body['deadline']), 'expires_at is the call\'s deadline', a, body['deadline'])
        _, _, record2 = self.submit('q1', 'chg', 'purge', {'text': marker('chg-p')})
        self.held('changing, purge (no annotations: read_only false)', record2)
        _, _, r = self.submit('q1', 'chg', 'echo', {'text': marker('chg-e')})
        self.runs('changing, echo (read-only)', 'q1', r)
        _, _, r = self.submit('q1', 'chg', 'read', {'uri': DOCS[0]})
        self.runs('changing, read', 'q1', r)
        need(not self.executed('fx', text), 'a held call does not run')
        shown = self.shown('q1', body['call_id'])
        need(shown['changes_things'] is True and shown['operation'] == 'write_note' and shown['capability'] == 'chg'
             and shown['caller'] == {'person_id': self.quinn, 'person_label': 'quinn', 'host_id': self.ids['q1'],
                                     'via': 'policy'} and shown['origin'] is None and
             shown['sender_host_id'] == self.ids['q1'] and shown['call_id'] == body['call_id'] and
             same_time(shown['expires_at'], body['deadline']),
             'the approval record: capability, operation, changes_things, caller, origin, expires_at', shown)
        self.has_kinds('q1', body['call_id'], ['call.received', 'call.approval_requested'],
                       'acceptance records call.received and call.approval_requested')
        # all holds read; a list holds only its names.
        _, _, r = self.submit('q1', 'every', 'read', {'uri': DOCS[0]})
        self.held('all, read', r)
        need(self.shown('q1', r['call_id'])['changes_things'] is False, 'changes_things is false for read')
        _, _, r = self.submit('q1', 'every', 'echo', {'text': marker('ev')})
        self.held('all, echo', r)
        _, _, r = self.submit('q1', 'named', 'echo', {'text': marker('nm-e')})
        self.held('a list, a named operation', r)
        need(self.shown('q1', r['call_id'])['changes_things'] is False, 'changes_things false for a read-only tool')
        _, _, r = self.submit('q1', 'named', 'write_note', {'text': marker('nm-w')})
        self.runs('a list, an operation not named', 'q1', r)
        _, _, r = self.submit('q1', 'plain', 'write_note', {'text': marker('pl')})
        self.runs('none', 'q1', r)

        # Self access: without origin exempt, with origin held; with origin exempt under agent_self false; a policy
        # call with origin held whatever agent_self.
        _, _, r = self.submit('p2', 'mine', 'write_note', {'text': marker('self')})
        self.runs('self without origin', 'p2', r)
        sbody, _, r = self.submit('p2', 'mine', 'write_note', {'text': marker('self-o')}, origin=self.origin('pa'))
        self.held('self with origin, agent_self true', r)
        shown = self.shown('p2', sbody['call_id'])
        need(shown['caller'] == {'person_id': self.pat, 'person_label': 'pat', 'host_id': self.ids['p2'],
                                 'via': 'self'} and shown['origin'] == self.origin('pa'),
             'a self call\'s approval: via self, its origin', shown)
        self.set_approval('mine', 'changing', '--no-agent-self')
        _, _, r = self.submit('p2', 'mine', 'write_note', {'text': marker('self-n')}, origin=self.origin('pa'))
        self.runs('self with origin, agent_self false', 'p2', r)
        _, _, r = self.submit('q1', 'mine', 'write_note', {'text': marker('pol-o')}, origin=self.origin('qa'))
        self.held('a policy call with origin, agent_self false', r)
        _, _, r = self.submit('q1', 'mine', 'write_note', {'text': marker('pol')})
        self.held('a policy call without origin', r)
        self.set_approval('mine', 'changing', '--agent-self')
        # Sources: never held.
        for origin in (None, self.origin('pa')):
            _, _, r = self.submit('p2', 'srv/fx', 'write_note', {'text': marker('src')}, origin=origin)
            self.runs('a source call', 'p2', r)

        # A requirement changed after acceptance changes nothing for the accepted call.
        self.set_approval('chg', 'none')
        time.sleep(3)
        r = self.peer_status('q1', record['call_id'])
        need(r['state'] == 'queued' and r['approval']['state'] == 'pending' and not self.executed('fx', text),
             'turning approval off leaves an accepted call pending, not run', r)
        self.set_approval('chg', 'changing')
        self.deny_all()

        # The pending limit: 20 from quinn under pend, the 21st refused (nothing persisted); rhea still accepted;
        # pat's self calls have their own key.
        ids = []
        for i in range(20):
            _, _, r = self.submit('q1', 'pend', 'echo', {'text': f'pend-{i}'})
            self.held(f'pending call {i + 1}', r)
            ids.append(r['call_id'])
        before = caps.received_count(self.hosts['p1'])
        body, status, r = self.submit('q1', 'pend', 'echo', {'text': 'pend-21'}, expect=None)
        need(status == 429 and r == {'code': 'limit', 'error': TOO_MANY, 'limit': 'max_pending_approvals'},
             'the 21st pending call from one caller under one rule is 429 max_pending_approvals', status, r)
        self.shown('q1', body['call_id'], expect=404)
        need(caps.received_count(self.hosts['p1']) == before, 'the refused call persists nothing', before,
             caps.received_count(self.hosts['p1']))
        _, _, r = self.submit('r1', 'pend', 'echo', {'text': 'pend-rhea'})
        self.held('another caller under the same rule is still accepted', r)
        _, _, r = self.submit('p2', 'pend', 'echo', {'text': 'pend-self'}, origin=self.origin('pa'))
        self.held('a self call has its own pending key', r)
        self.deny_api('q1', ids[0])
        _, _, r = self.submit('q1', 'pend', 'echo', {'text': 'pend-after'})
        self.held('after one decision, the caller is accepted again', r)
        self.deny_all()

        # The budget counted at acceptance, refused before the pending limit: `both` allows 20 calls an hour.
        for i in range(20):
            _, _, r = self.submit('q1', 'both', 'echo', {'text': f'both-{i}'})
            self.held(f'budgeted call {i + 1}', r)
        _, status, r = self.submit('q1', 'both', 'echo', {'text': 'both-21'}, expect=None)
        need(status == 429 and isinstance(r, dict) and r.get('code') == 'limit' and
             r.get('limit') == 'max_calls_per_hour', 'over both limits: the max_calls_per_hour refusal', status, r)
        self.deny_all()
        _, status, r = self.submit('q1', 'both', 'echo', {'text': 'both-22'}, expect=None)
        need(status == 429 and isinstance(r, dict) and r.get('limit') == 'max_calls_per_hour',
             'denied calls still count against the budget (counted at acceptance)', status, r)
        return ''

    # --- decisions -------------------------------------------------------------------------------------------

    def check_decisions(self):
        # Approve, then exactly one execution.
        text = marker('approve')
        body, _, r = self.submit('q1', 'chg', 'write_note', {'text': text})
        self.held('setup', r)
        out = self.approve_api('q1', body['call_id'])
        need(out['decided_at'] is not None, 'decided_at set on approval', out)
        final = self.peer_final('q1', body['call_id'])
        need(final['state'] == 'succeeded' and final['approval']['state'] == 'approved' and
             final['approval']['decided_at'], 'an approved call runs, its approval approved', final)
        time.sleep(2)
        need(len(self.executed('fx', text)) == 1, 'exactly one execution', self.executed('fx', text))
        self.has_kinds('q1', body['call_id'], ['call.approval_requested', 'call.approved', 'call.started',
                                               'call.finished'], 'approve: call.approved then call.started')

        # Deny with a reason; never executed; the reason only in the approval; over 1,024 bytes refused.
        text = marker('deny')
        body, _, r = self.submit('q1', 'chg', 'write_note', {'text': text})
        status, out = self.decide('q1', body['call_id'], 'deny', {'reason': 'x' * 1025})
        need(status == 400 and self.shown('q1', body['call_id'])['state'] == 'pending',
             'a reason over 1,024 bytes is 400, nothing changed', status, out)
        status, out = self.decide('q1', body['call_id'], 'deny', {'reason': 'é' * 513})
        need(status == 400, 'the 1,024-byte limit is in UTF-8 bytes (513 é are 1,026 bytes)', status, out)
        code, out, stdout, stderr = self.hosts['p1'].outcome('deny', body['call_id'], '--reason', 'y' * 1025)
        need(code == 1 and self.shown('q1', body['call_id'])['state'] == 'pending', 'deny --reason over 1,024 bytes '
             'exits 1', code, stderr[-300:])
        reason = 'not now ' + secrets.token_hex(4)
        out = self.deny_api('q1', body['call_id'], reason)
        need(out['reason'] == reason, 'the denied record carries the reason', out)
        final = self.peer_status('q1', body['call_id'])
        need(final['state'] == 'rejected' and final['error'] == 'approval_denied' and
             final['approval']['state'] == 'denied' and final['approval']['reason'] == reason,
             'deny: rejected with approval_denied, the reason in the approval', final)
        need(not self.executed('fx', text), 'a denied call never runs')
        self.has_kinds('q1', body['call_id'], ['call.denied', 'call.finished'], 'deny activities')
        events = self.activity(f"{self.ids['q1']}/{body['call_id']}")
        need(reason not in json.dumps(events) and text not in json.dumps(events),
             'activity never holds the input or the reason', events)
        denied_id = body['call_id']
        body2, _, _ = self.submit('q1', 'chg', 'write_note', {'text': marker('empty-reason')})
        out = self.deny_api('q1', body2['call_id'], '')
        need(out['reason'] is None, 'an empty reason reads as null', out)

        # Twice: 409 conflict with the record.
        for verb in ('approve', 'deny'):
            status, out = self.decide('q1', denied_id, verb)
            need(status == 409 and isinstance(out, dict) and out.get('code') == 'conflict' and
                 out.get('error') == NO_LONGER and isinstance(out.get('approval'), dict) and
                 out['approval'].get('state') == 'denied', f'{verb} of an approval no longer pending: 409 conflict '
                 'with the record', status, out)
        body3, _, _ = self.submit('q1', 'chg', 'write_note', {'text': marker('twice')})
        self.approve_api('q1', body3['call_id'])
        status, out = self.decide('q1', body3['call_id'], 'approve')
        need(status == 409 and isinstance(out, dict) and out.get('code') == 'conflict' and
             (out.get('approval') or {}).get('state') == 'approved', 'approving twice: 409 conflict with the record',
             status, out)
        status, out = self.decide('q1', cid(), 'approve')
        need(status == 404, 'approving an unknown approval is 404', status, out)

        # A pending approval reaching its deadline, with no request reaching the receiver.
        text = marker('timeout')
        body, _, r = self.submit('q1', 'chg', 'write_note', {'text': text}, deadline=timestamp(12))
        self.held('setup', r)
        deadline = parse_time(body['deadline'])
        wait_for(lambda: self.shown('q1', body['call_id'])['state'] != 'pending', timeout=12 + SWEEP + 5,
                 message='the approval leaves pending')
        shown = self.shown('q1', body['call_id'])
        need(shown['state'] == 'expired' and deadline - 1 <= parse_time(shown['decided_at']) <= deadline + SWEEP,
             'a pending approval expires at its deadline (checked at least every 5 seconds), with no request reaching '
             'the receiver', shown, body['deadline'])
        final = self.peer_status('q1', body['call_id'])
        need(final['state'] == 'expired' and final['error'] == 'approval_timeout' and
             final['approval']['state'] == 'expired', 'expired with approval_timeout, the approval expired', final)
        need(not self.executed('fx', text), 'never executed')
        self.has_kinds('q1', body['call_id'], ['call.approval_expired', 'call.finished'], 'expiry activities')

        # Cancel while pending.
        body, _, r = self.submit('q1', 'chg', 'write_note', {'text': marker('cancel')})
        status, out = wire(self.hosts['p1'], fixture_context(self.hosts['q1']), 'POST',
                           f"/peer/v1/calls/{body['call_id']}/cancel", {})
        need(status == 200 and out.get('state') == 'cancelled' and
             (status_approval(out, 'cancel') or {}).get('state') == 'cancelled',
             'cancel while pending: the call cancelled, its approval cancelled', status, out)
        need(self.shown('q1', body['call_id'])['state'] == 'cancelled', 'the approval record cancelled')
        self.has_kinds('q1', body['call_id'], ['call.cancel_requested', 'call.finished'], 'cancel activities')

        # Approve after unshare: rejected at the recheck.
        text = marker('rev')
        body, _, r = self.submit('q1', 'rev', 'echo', {'text': text})
        self.held('setup', r)
        self.unshare('p1', 'rev', 'quinn')
        self.approve_api('q1', body['call_id'])
        final = self.peer_final('q1', body['call_id'])
        need(final['state'] == 'rejected' and final['error'] == LAPSED and final['approval']['state'] == 'approved',
             'approve after unshare: rejected at the recheck with authorization lapsed before start', final)
        need(not self.executed('fx', text), 'never executed')
        self.share('p1', 'rev', 'quinn')
        self.sync_pat()

        # A repeated call_id: the same record and approval, no second approval or notice; a new call_id with the
        # same input needs its own approval.
        text = marker('repeat')
        body, _, first = self.submit('q1', 'chg', 'write_note', {'text': text})
        approvals_before = self.count('p1', 'call_approvals')
        notices_before = self.count('p1', 'approval_notices')
        _, status, again = self.submit('q1', 'chg', 'write_note', {'text': text}, call=body['call_id'],
                                       deadline=body['deadline'], cite={'policy': body['policy']})
        need(again.get('call_id') == first['call_id'] and again.get('approval') == first['approval'] and
             again.get('state') == 'queued', 'an identical repeat returns the existing record with its approval',
             first, again)
        need(self.count('p1', 'call_approvals') == approvals_before and
             self.count('p1', 'approval_notices') == notices_before, 'a repeat creates no second approval or notice')
        _, status, changed = self.submit('q1', 'chg', 'write_note', {'text': text + '-changed'}, call=body['call_id'],
                                         deadline=body['deadline'], cite={'policy': body['policy']}, expect=None)
        need(status == 409, 'a changed repeat is 409', status, changed)
        body2, _, r = self.submit('q1', 'chg', 'write_note', {'text': text})
        self.held('a new call_id with the same input needs its own approval', r)
        self.approve_api('q1', body['call_id'])
        r = self.peer_status('q1', body2['call_id'])
        need(r['approval']['state'] == 'pending', 'approving one call never approves another with the same input', r)
        self.deny_api('q1', body2['call_id'])

        # No server instance while every queued call is pending; started once approved.
        text = marker('iso')
        starts = len(self.starts('iso'))
        body, _, r = self.submit('q1', 'iso', 'echo', {'text': text})
        self.held('setup', r)
        time.sleep(6)
        need(len(self.starts('iso')) == starts, 'no server instance is started for a pending call', starts,
             self.starts('iso'))
        self.approve_api('q1', body['call_id'])
        final = self.peer_final('q1', body['call_id'])
        need(final['state'] == 'succeeded' and len(self.executed('iso', text)) == 1,
             'approved, it runs once', final)
        self.check_restart()
        return ''

    def check_restart(self):
        """Pending and approved calls surviving a receiver restart: rst's own instance is filled with 4 approved
        sleeps, so a fifth approved call stays queued; a sixth stays pending."""
        texts = [marker(f'rst{i}') for i in range(4)]
        for text in texts:
            body, _, _ = self.submit('q1', 'rst', 'sleep', {'seconds': 40, 'text': text})
            self.approve_api('q1', body['call_id'])
        wait_for(lambda: all(self.executed('rst', t) for t in texts), timeout=40, message='4 running sleeps')
        approved_text, pending_text = marker('rst-approved'), marker('rst-pending')
        approved, _, _ = self.submit('q1', 'rst', 'echo', {'text': approved_text})
        self.approve_api('q1', approved['call_id'])
        pending, _, _ = self.submit('q1', 'rst', 'echo', {'text': pending_text})
        time.sleep(1)
        r = self.peer_status('q1', approved['call_id'])
        need(r['state'] == 'queued' and r['approval']['state'] == 'approved', 'setup: an approved call queued '
             'behind 4 running calls', r)
        self.restart_p1()
        final = self.peer_final('q1', approved['call_id'], timeout=60)
        need(final['state'] == 'succeeded' and final['approval']['state'] == 'approved' and
             len(self.executed('rst', approved_text)) == 1, 'an approved call survives a restart and starts normally',
             final)
        r = self.peer_status('q1', pending['call_id'])
        need(r['state'] == 'queued' and r['approval']['state'] == 'pending' and
             not self.executed('rst', pending_text), 'a pending call survives a restart, still pending', r)
        self.approve_api('q1', pending['call_id'])
        final = self.peer_final('q1', pending['call_id'])
        need(final['state'] == 'succeeded' and len(self.executed('rst', pending_text)) == 1,
             'then approved, it runs once', final)

    # --- CLI -------------------------------------------------------------------------------------------------

    def check_cli(self):
        p1 = self.hosts['p1']
        self.deny_all()
        code, out, stdout, stderr = p1.outcome('approvals')
        need(code == 0 and EMPTY in stdout + stderr, 'approvals with nothing pending prints the empty message', code,
             stdout[-300:], stderr[-300:])
        code, out, stdout, stderr = p1.outcome('approvals', '--json')
        need(code == 0 and out == {'approvals': []}, 'approvals --json with nothing pending', code, stdout[-300:])
        status, body = api(p1, 'GET', '/v1/approvals?state=bogus')
        need(status == 400, 'GET /v1/approvals with another state is 400', status, body)

        # Three pending approvals in order: from q1 (an input with an escape sequence, BEL, DEL, and C1 characters),
        # r1 (a label with a C1 control), and p2 (self with origin, a long input); and one decided.
        evil = {'text': 'a\x1b[31mred\x07\x7fb\u0085c\u009b2Jd'}
        b1, _, _ = self.submit('q1', 'chg', 'write_note', evil)
        time.sleep(1.1)
        b2, _, _ = self.submit('r1', 'chg', 'write_note', {'text': 'from rhea'})
        time.sleep(1.1)
        long_input = {'text': 'é' * 400}
        b3, _, _ = self.submit('p2', 'mine', 'write_note', long_input, origin=self.origin('pa'))
        decided, _, _ = self.submit('q1', 'chg', 'write_note', {'text': marker('decided')})
        self.deny_api('q1', decided['call_id'], 'no')
        listed = self.approvals()
        self.soft(self.approvals('pending') == listed, 'Q: GET /v1/approvals without state equals state=pending')
        keys = [(a['sender_host_id'], a['call_id']) for a in listed]
        want = [(self.ids['q1'], b1['call_id']), (self.ids['r1'], b2['call_id']), (self.ids['p2'], b3['call_id'])]
        need(keys == want, 'pending approvals oldest first by requested_at', want, keys)
        everything = self.approvals('all')
        need((self.ids['q1'], decided['call_id']) in [(a['sender_host_id'], a['call_id']) for a in everything] and
             all(a['state'] == 'pending' for a in listed), 'state=all includes decided approvals; pending does not',
             [a['state'] for a in everything])
        order = [(parse_time(a['requested_at']), a['sender_host_id'], a['call_id']) for a in everything]
        need(order == sorted(order), 'state=all sorted by requested_at, sender_host_id, call_id', order)
        code, out, stdout, stderr = p1.outcome('approvals', '--all', '--json')
        need(code == 0 and isinstance(out, dict) and [(a['sender_host_id'], a['call_id']) for a in out['approvals']] ==
             [(a['sender_host_id'], a['call_id']) for a in everything], 'approvals --all --json', code)
        code, out, stdout, stderr = p1.outcome('approvals', '--json')
        need(code == 0 and isinstance(out, dict) and [(a['sender_host_id'], a['call_id']) for a in out['approvals']] ==
             want, 'approvals --json prints the pending list', code, stdout[-300:])
        r2 = next(a for a in listed if a['call_id'] == b2['call_id'])
        need(r2['caller']['person_label'] == self.labels['rhea'] and r2['caller']['person_id'] == self.rhea,
             'the caller\'s person label as bound in the network map', r2['caller'])

        # The input preview: canonical text, 512 bytes on a character boundary, U+007F and C1 escaped.
        by_id = {a['call_id']: a for a in listed}
        for body, value in ((b1, evil), (b3, long_input)):
            item = by_id[body['call_id']]
            need(item['input_bytes'] == len(input_text(value).encode()) and item['input_preview'] == preview_of(value),
                 'input_bytes is the canonical input text\'s length, input_preview its escaped prefix of at most 512 '
                 'bytes on a character boundary', value, item['input_bytes'], item['input_preview'],
                 preview_of(value))
        need(len(preview_of(long_input).encode()) == 511, 'self-check: the long preview ends on a character boundary')

        # Readable output: each line holds SENDER/CALL_ID; no raw control characters from the caller's text.
        code, out, stdout, stderr = p1.outcome('approvals')
        for sender, call in want:
            need(f'{sender}/{call}' in stdout, 'each readable line contains SENDER_HOST_ID/CALL_ID', sender, call,
                 stdout[-600:])
        need(not raw_controls(stdout + stderr), 'readable approvals output shows no raw control or escape character '
             '(from the input and the person label)', raw_controls(stdout + stderr))
        need(self.labels['rhea'] == 'rhea' or '\\u009b' in stdout, 'the label\'s C1 control is written as \\u009b',
             stdout[-600:])
        code, out, stdout, stderr = p1.outcome('approvals', '--all')
        need(code == 0 and f"{self.ids['q1']}/{decided['call_id']}" in stdout, 'approvals --all lists decided ones',
             stdout[-600:])

        # approvals show: bare ID and full form, --json with the whole input; readable output escaped.
        code, out, stdout, stderr = p1.outcome('approvals', 'show', b1['call_id'], '--json')
        need(code == 0 and isinstance(out, dict) and set(out) == SHOWN_KEYS and out['input'] == evil and
             out['call_id'] == b1['call_id'], 'approvals show ID --json: the record, preview, bytes, and input', code,
             stdout[-500:])
        status, body = api(p1, 'GET', f"/v1/approvals/{b1['call_id']}")
        need(status == 200 and isinstance(body, dict) and body.get('input') == evil,
             'GET /v1/approvals/{call_id} resolves a bare ID', status, body)
        code, out, stdout, stderr = p1.outcome('approvals', 'show', f"{self.ids['q1']}/{b1['call_id']}")
        need(code == 0 and not raw_controls(stdout + stderr) and '\\u001b' in stdout,
             'readable approvals show escapes control characters in the pretty-printed input',
             raw_controls(stdout + stderr), stdout[-600:])
        self.shown('q1', decided['call_id'])   # any state

        # approve without a terminal: refused before any request, nothing changed.
        code, out, stdout, stderr = p1.outcome('approve', b1['call_id'])
        need(code == 1 and NEEDS_TERMINAL in stderr and self.shown('q1', b1['call_id'])['state'] == 'pending',
             'approve without a terminal exits 1 with its text, nothing changed', code, stderr[-300:])
        # At a pseudo-terminal: n declines; y approves, printing the record on stdout.
        code, out, tty, stdout, seen = p1.converse('approve', b2['call_id'], answers=['n'], prompt=APPROVE_PROMPT)
        need(code == 1 and seen and self.shown('r1', b2['call_id'])['state'] == 'pending',
             'approve answered n exits 1, nothing changed', code, tty[-500:])
        code, out, tty, stdout, seen = p1.converse('approve', f"{self.ids['r1']}/{b2['call_id']}", answers=['y'],
                                                   prompt=APPROVE_PROMPT)
        need(code == 0 and seen and isinstance(out, dict) and out.get('state') == 'approved' and
             out.get('call_id') == b2['call_id'], 'approve at a pseudo-terminal answered y approves, printing the '
             'record on stdout', code, stdout[-300:], tty[-500:])
        need('from rhea' in tty and tty.find('from rhea') < tty.find('Approve this call?'),
             'approve prints what approvals show prints before asking', tty[-600:])
        code, out, tty, stdout, seen = p1.converse('approve', b2['call_id'], answers=['y'], prompt=APPROVE_PROMPT)
        need(code == 1, 'approve of an approval no longer pending exits 1', code, tty[-300:])
        # deny without a terminal.
        code, out, stdout, stderr = p1.outcome('deny', b1['call_id'], '--reason', 'cli')
        need(code == 0 and isinstance(out, dict) and out.get('state') == 'denied' and out.get('reason') == 'cli',
             'deny without a terminal denies, printing the record', code, stdout[-300:], stderr[-300:])

        # Ambiguous bare IDs: q1 and p2 use one call ID.
        shared = cid()
        self.submit('q1', 'chg', 'write_note', {'text': 'amb-q'}, call=shared)
        self.submit('p2', 'mine', 'write_note', {'text': 'amb-p'}, call=shared, origin=self.origin('pa'))
        status, body = api(p1, 'GET', f'/v1/approvals/{shared}')
        candidates = sorted([f"{self.ids['q1']}/{shared}", f"{self.ids['p2']}/{shared}"])
        need(status == 409 and isinstance(body, dict) and body.get('code') == 'ambiguous' and
             body.get('candidates') == candidates, 'a bare ID two senders used: 409 ambiguous with sorted candidates',
             status, body)
        code, out, stdout, stderr = p1.outcome('deny', shared)
        need(code == 1 and self.shown('q1', shared)['state'] == 'pending' and self.shown('p2', shared)['state'] ==
             'pending', 'deny with an ambiguous bare ID exits 1, nothing changed', code, stderr[-300:])
        code, out, stdout, stderr = p1.outcome('deny', f"{self.ids['p2']}/{shared}")
        need(code == 0 and self.shown('p2', shared)['state'] == 'denied' and
             self.shown('q1', shared)['state'] == 'pending', 'the full form then works', code, stderr[-300:])
        # Unknown and malformed IDs.
        unknown = cid()
        status, body = api(p1, 'GET', f'/v1/approvals/{unknown}')
        need(status == 404, 'GET /v1/approvals/{call_id} for an unknown ID is 404', status, body)
        status, body = api(p1, 'GET', f"/v1/approvals/{self.ids['q1']}/{unknown}")
        need(status == 404, 'GET /v1/approvals/{sender}/{call_id} unknown is 404', status, body)
        for argv in (('approvals', 'show', unknown), ('deny', unknown), ('approvals', 'show', 'call_XYZ'),
                     ('approvals', 'show', 'nonsense')):
            code, out, stdout, stderr = p1.outcome(*argv)
            need(code == 1, f'{" ".join(argv)} exits 1', code, stderr[-300:])
        # deny beside the access deny: --reason with an argument that is not an ID, and --agent or --network with an
        # ID, are refused before any request (nothing signed, nothing denied).
        before = self.versions()
        pending_q = cid()
        self.submit('q1', 'chg', 'write_note', {'text': 'deny-flags'}, call=pending_q)
        for argv in (('deny', 'call_XYZ', '--reason', 'x'), ('deny', 'quinn', '--reason', 'x'),
                     ('deny', pending_q, '--network', self.team), ('deny', pending_q, '--agent', 'srv')):
            code, out, stdout, stderr = p1.outcome(*argv)
            need(code == 1 and self.versions() == before and self.shown('q1', pending_q)['state'] == 'pending',
                 f'{" ".join(argv)} exits 1 before any request', code, stderr[-300:])

        # input null once deleted (Q: the retention trigger is not specified; see the PR question): the decided
        # call's timestamps moved 8 days back, the receiver restarted.
        self.check_deleted_input(decided['call_id'])
        self.deny_all()
        return ''

    def check_deleted_input(self, call_id):
        h = self.hosts['p1']
        h.stop()
        try:
            connection = sqlite3.connect(h.state / 'host.db', timeout=30)
            try:
                (value,) = connection.execute('SELECT record FROM received_calls WHERE call_id = ? AND sender = ?',
                                              (call_id, self.ids['q1'])).fetchone()
                record = json.loads(value)
                old = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 8 * 86400))
                for key in ('finished_at', 'created_at'):
                    if record.get(key):
                        record[key] = old
                connection.execute('UPDATE received_calls SET record = ? WHERE call_id = ? AND sender = ?',
                                   (json.dumps(record), call_id, self.ids['q1']))
                connection.commit()
            finally:
                connection.close()
        finally:
            h.logs.close()
            h.logs = tempfile.TemporaryFile()
            h.start()
        time.sleep(3)
        try:
            shown = wait_for(lambda: (lambda s: s if s['input'] is None else None)(self.shown('q1', call_id)),
                             timeout=60, message='input deleted')
        except Exception:
            rows = db_rows(h, 'SELECT record FROM received_calls WHERE call_id = ?', (call_id,))
            raise Failure('approvals show: input null once deleted (inputs go 7 days after final; the suite moved '
                          f'finished_at 8 days back and restarted the receiver): {self.shown("q1", call_id)}; the '
                          f'stored status record: {rows}')
        need(shown['input_preview'] is None and shown['input_bytes'] is None, 'input_preview and input_bytes null once '
             'the input is deleted', shown)

    # --- caller ----------------------------------------------------------------------------------------------

    def check_caller(self):
        q1, p1 = self.hosts['q1'], self.hosts['p1']
        notes = []
        # `call` from the owner CLI: exit 3 and the stderr line; approval in calls list, inspect, and received.
        text = marker('cli')
        code, out, stdout, stderr = q1.outcome('call', 'pat/chg', 'write_note', '--input', json.dumps({'text': text}),
                                               '--wait', '3s')
        need(code == 3 and isinstance(out, dict), 'call of a held operation exits 3', code, stdout[-300:],
             stderr[-300:])
        call_id = out['request']['call_id']
        accepted = time.time()
        stored = (out.get('status') or {}).get('approval')
        need(isinstance(stored, dict) and stored.get('state') == 'pending', 'the outbound record\'s status has the '
             'receiver\'s approval', out.get('status'))
        line = WAITING.format(owner='pat', expires=stored['expires_at'], host=self.ids['p1'], id=call_id)
        need(caps.squash(line) in caps.squash(stderr), 'call prints the waiting line on stderr', line, stderr[-500:])
        record = self.inspect('q1', 'p1', call_id)
        need(((record.get('status') or {}).get('approval') or {}).get('state') == 'pending',
             'calls inspect shows approval inside status', record.get('status'))
        listed = [x for x in q1.cli('calls', 'list') if ((x.get('call') or {}).get('request') or {}).get('call_id') ==
                  call_id]
        need(listed and ((listed[0]['call'].get('status') or {}).get('approval') or {}).get('state') == 'pending',
             'calls list shows approval inside status', listed)
        item = self.received('p1', call_id)
        need(item and (status_approval(item['status'], 'calls received') or {}).get('state') == 'pending',
             'calls received shows approval in the status record', item)

        # The peer route: an invalid approval value is 400; with approval but without wait it answers at once; a
        # held request answers within 1 second of a decision.
        context = fixture_context(q1)
        body, _, r = self.submit('q1', 'chg', 'write_note', {'text': marker('held')})
        for query in ('approval=bogus', 'wait=2&approval=PENDING', 'wait=2&state=queued&approval=maybe'):
            status, value = wire(p1, context, 'GET', f"/peer/v1/calls/{body['call_id']}?{query}")
            need(status == 400, 'an approval value outside the five states and none is 400', query, status, value)
        started = time.monotonic()
        status, value = wire(p1, context, 'GET', f"/peer/v1/calls/{body['call_id']}?approval=pending")
        need(status == 200 and time.monotonic() - started < 5, 'approval without wait answers at once (not held)', status,
             time.monotonic() - started)
        started = time.monotonic()
        status, value = wire(p1, context, 'GET',
                             f"/peer/v1/calls/{body['call_id']}?wait=10&state=queued&approval=none")
        need(status == 200 and time.monotonic() - started < 5, 'an approval state that already differs answers at '
             'once (not held)', status, time.monotonic() - started)
        decided = {}

        def later(verb, key):
            time.sleep(2.5)
            (self.approve_api if verb == 'approve' else self.deny_api)('q1', body['call_id'])
            decided[key] = time.time()
        # wait=8 keeps the held request inside the probe's own deadline; the decision comes 2.5 seconds in.
        threading.Thread(target=later, args=('approve', 'approve'), daemon=True).start()
        status, value = self.held_get(context, f"/peer/v1/calls/{body['call_id']}?wait=8&state=queued&approval=pending",
                                      decided, 'approve')
        answered = time.time()
        need(status == 200 and decided.get('approve') and answered - decided['approve'] <= 1.0 and
             value['approval']['state'] == 'approved', 'a held request (approval=pending) answers within 1 second of '
             'approve', status, value.get('approval'), answered - decided.get('approve', answered))
        self.peer_final('q1', body['call_id'])
        body, _, r = self.submit('q1', 'chg', 'write_note', {'text': marker('held-deny')})
        threading.Thread(target=later, args=('deny', 'deny'), daemon=True).start()
        status, value = self.held_get(context, f"/peer/v1/calls/{body['call_id']}?wait=8&approval=pending", decided,
                                      'deny')
        answered = time.time()
        need(status == 200 and decided.get('deny') and answered - decided['deny'] <= 1.0 and
             value['state'] == 'rejected', 'a held request answers within 1 second of deny', status,
             value.get('state'), answered - decided.get('deny', answered))

        # The listing: approval per operation (the peer route, discover --json, list_capabilities), (needs approval).
        listing = self.peer_listing('q1')
        want = {'chg': {'echo': False, 'write_note': True, 'purge': True, 'read': False},
                'every': {'echo': True, 'read': True}, 'named': {'echo': True, 'write_note': False},
                'plain': {'echo': False, 'write_note': False}}
        for name, flags in want.items():
            need(name in listing and self.op_flags(listing[name]) == flags, 'GET /peer/v1/capabilities: approval per '
                 'operation (policy via)', name, flags, listing.get(name) and self.op_flags(listing[name]))
        own = self.peer_listing('p2')
        need(self.op_flags(own['mine']) == {'echo': False, 'write_note': True},
             'self via with agent_self true: covered operations true', self.op_flags(own['mine']))
        sources = [e for e in own.values() if e.get('kind') == 'source']
        need(sources and all(o.get('approval') is False for e in sources for o in e['operations']),
             'operations of source entries have approval false', sources[:1])
        self.set_approval('mine', 'changing', '--no-agent-self')
        need(self.op_flags(self.peer_listing('p2')['mine']) == {'echo': False, 'write_note': False},
             'self via with agent_self false: false', self.op_flags(self.peer_listing('p2')['mine']))
        need(self.op_flags(self.peer_listing('q1')['mine']) == {'echo': False, 'write_note': True},
             'policy via: covered operations true whatever agent_self', self.op_flags(self.peer_listing('q1')['mine']))
        self.set_approval('mine', 'changing', '--agent-self')
        code, out, stdout, stderr = q1.outcome('discover', 'pat', '--json')
        entries = {e['capability']: e for e in (out or {}).get('capabilities', [])}
        for name, flags in want.items():
            need(name in entries and self.op_flags(entries[name]) == flags, 'discover --json carries approval', name,
                 entries.get(name) and self.op_flags(entries[name]))
        code, out, stdout, stderr = q1.outcome('discover', 'pat')
        need(code == 0 and 'write_note (needs approval)' in stdout and 'echo (needs approval)' in stdout and
             'purge (needs approval)' in stdout, 'readable discover prints (needs approval) after such operations',
             code, stdout[-1200:])
        failed, value = self.tool(self.s('qa')['consumer'], 'list_capabilities', {})
        entries = {e['capability']: e for e in (value or {}).get('capabilities', [])} if not failed else {}
        for name, flags in want.items():
            need(name in entries and self.op_flags(entries[name]) == flags, 'list_capabilities carries approval', name,
                 entries.get(name) and self.op_flags(entries[name]))
        tools = self.s('qa')['consumer'].call('tools/list', {})
        description = next((t.get('description') or '' for t in tools.get('tools', []) if t['name'] ==
                            'call_capability'), '')
        need(caps.squash(DESCRIPTION) in caps.squash(description), 'call_capability\'s description gains the approval '
             'sentence', description)

        # call_capability: awaiting_approval within the wait limit, with its note and approval; call_status; pending
        # work; then exactly one call_update after approval and success, none on approval itself.
        text = marker('agent-ok')
        view, elapsed = self.ok_call('qa', 'pat/chg', 'write_note', {'text': text})
        need(view['state'] == 'awaiting_approval' and view['note'] == AWAITING_NOTE and
             view['approval']['state'] == 'pending' and elapsed <= 17, 'call_capability returns awaiting_approval with '
             'its note and approval within the wait limit', view, elapsed)
        agent_call = view['call_id']
        view = self.view('qa', agent_call)
        need(view['state'] == 'awaiting_approval', 'call_status reports awaiting_approval', view)
        pend = self.pending_work('qa')
        mine = [x for x in pend['calls'] if x['call_id'] == agent_call]
        need(len(mine) == 1 and mine[0]['state'] == 'awaiting_approval', 'pending_work lists the call as '
             'awaiting_approval', pend['calls'])
        result = q1.run('session', 'pending', '--json', cwd=str(self.s('qa')['workspace']))
        try:
            listed = json.loads(result.stdout or 'null')
        except ValueError:
            listed = None
        need(result.returncode == 0 and isinstance(listed, dict) and
             any(x.get('call_id') == agent_call and x.get('state') == 'awaiting_approval' for x in listed['calls']),
             'session pending --json lists awaiting_approval', result.returncode, result.stdout[-400:])
        # Held requests past 60 seconds while pending: approve 75 seconds after acceptance.
        remaining = accepted + 75 - time.time()
        if remaining > 0:
            time.sleep(remaining)
        need(not self.update_events('qa', agent_call), 'no call_update while awaiting approval')
        self.approve_api('q1', call_id)
        approved_at = time.time()
        record, seen = self.wait_outbound('q1', call_id, lambda r: (r.get('status') or {}).get('state') in FINAL,
                                          timeout=70)
        need(seen - approved_at <= 2.0 and record['status']['state'] == 'succeeded', 'an approval more than 60 seconds '
             'after acceptance reaches the caller (held requests continuing), result stored within 2 seconds',
             seen - approved_at, record['status'])
        notes.append(f'result stored {seen - approved_at:.2f}s after approve, {approved_at - accepted:.0f}s after '
                     'acceptance')
        self.approve_api('q1', agent_call)
        approved_at = time.time()
        params = self.wait_update('qa', agent_call, timeout=30)
        meta, content = self.check_update('qa', params, 'call_update after approval')
        need(content['state'] == 'succeeded' and content['approval']['state'] == 'approved' and
             time.time() - approved_at <= 5, 'one call_update after approval and success', content)
        time.sleep(4)
        need(len(self.update_events('qa', agent_call)) == 1, 'exactly one call_update (none for the approval itself)',
             len(self.update_events('qa', agent_call)))

        # Denial: one call_update, rejected with approval_denied, the never-ran note, the reason in approval.
        view, _ = self.ok_call('qa', 'pat/chg', 'write_note', {'text': marker('agent-deny')}, wait=0)
        view = self.until_view('qa', view['call_id'], {'awaiting_approval'})
        self.deny_api('q1', view['call_id'], 'no thanks')
        params = self.wait_update('qa', view['call_id'], timeout=30)
        meta, content = self.check_update('qa', params, 'call_update after denial')
        need(content['state'] == 'rejected' and content['error'] == 'approval_denied' and
             content['note'] == NEVER_RAN_NOTE and content['approval']['reason'] == 'no thanks',
             'denial: rejected, approval_denied, the never-ran note, the reason in approval', content)
        time.sleep(3)
        need(len(self.update_events('qa', view['call_id'])) == 1, 'exactly one call_update after denial')
        return '; '.join(notes)

    def check_agent_timeout(self):
        need(self.timeout_call, 'setup: the agent timeout call', self.setup_notes)
        call_id, text = self.timeout_call
        view = self.view('qb', call_id)
        need(view['state'] in ('awaiting_approval', 'expired'), 'the timeout call awaits approval until its deadline',
             view)
        deadline = parse_time(view['deadline'])
        remaining = deadline + SWEEP + 3 - time.time()
        if remaining > 0:
            time.sleep(remaining)
        try:
            params = self.wait_update('qb', call_id, timeout=60)
        except AssertionError:
            receiver = wire(self.hosts['p2'], fixture_context(self.hosts['q1']), 'GET', f'/peer/v1/calls/{call_id}')
            raise Failure(f'one call_update after timeout: none within 60 seconds of the deadline plus {SWEEP + 3}s; '
                          f'call_status {self.status("qb", call_id)}; the caller\'s outbound record '
                          f'{str(self.outbound_record("q1", call_id))[:900]}; the receiver\'s status {receiver}; '
                          f'q1 log: {self.log_tail("q1")!r}; p2 log: {self.log_tail("p2")!r}')
        meta, content = self.check_update('qb', params, 'call_update after timeout')
        need(content['state'] == 'expired' and content['error'] == 'approval_timeout' and
             content['note'] == NEVER_RAN_NOTE and content['approval']['state'] == 'expired',
             'timeout: expired, approval_timeout, the never-ran note', content)
        time.sleep(3)
        need(len(self.update_events('qb', call_id)) == 1, 'exactly one call_update after timeout')
        need(not self.executed('fx-p2', text), 'never executed')
        return ''

    # --- notices ---------------------------------------------------------------------------------------------

    def check_notices(self):
        p1 = self.hosts['p1']
        # p1 restarted in earlier sections; srv's adapter recovers its attachment, and verification is kept.
        # One event in the source agent's verified session: exact content and meta, without the input; with an
        # origin (qa's), then without.
        since = time.monotonic()
        secret = marker('input-secret')
        body, _, r = self.submit('q1', 'chg', 'write_note', {'text': secret}, origin=self.origin('qa'))
        shown = self.shown('q1', body['call_id'])
        _, params = self.s('srv')['consumer'].wait_event(
            'approval_request', since=since, timeout=30,
            where=lambda p: (p.get('meta') or {}).get('call_id') == body['call_id'])
        meta = {k: v for k, v in (params.get('meta') or {}).items() if k != 'kind'}
        need(set(meta) == NOTICE_META, 'the event meta has exactly the contract\'s keys',
             sorted(set(meta) ^ NOTICE_META))
        want = {'call_id': body['call_id'], 'sender_host_id': self.ids['q1'], 'caller': 'quinn',
                'origin_agent_id': self.origin('qa')['agent_id'], 'capability': 'chg', 'operation': 'write_note',
                'changes_things': True, 'expires_at': shown['expires_at']}
        for key, value in want.items():
            need(meta_equal(meta.get(key), value), f'meta {key}', value, meta.get(key))
        need(NOTICE_ID.fullmatch(str(meta['notice_id'])), 'notice_id is notice_ and 32 hex digits', meta)
        content = params.get('content')
        need(content == NOTICE_TEXT.format(capability='chg', operation='write_note', caller='quinn',
                                           expires=shown['expires_at']), 'the exact notice content', content)
        need(secret not in json.dumps(params), 'neither the content nor meta includes the input')
        time.sleep(3)
        need(len(self.notices('srv', body['call_id'])) == 1, 'one event per approval')
        rows = db_rows(p1, 'SELECT record FROM approval_notices WHERE call_id = ?', (body['call_id'],))
        notice = json.loads(rows[0][0]) if rows else None
        need(notice and notice.get('state') == 'forwarded' and notice.get('session_id') == self.s('srv')['session_id'],
             'acknowledged through forwarded; bound to the claiming session', notice)
        need(not self.notices('srv2', body['call_id']), 'no event in a session of another agent')
        since = time.monotonic()
        body2, _, _ = self.submit('r1', 'chg', 'write_note', {'text': marker('n-r')})
        _, params = self.s('srv')['consumer'].wait_event(
            'approval_request', since=since, timeout=30,
            where=lambda p: (p.get('meta') or {}).get('call_id') == body2['call_id'])
        meta = params.get('meta') or {}
        need(meta.get('origin_agent_id') in (None, '', 'null'), 'origin_agent_id null without an origin', meta)
        need(meta_equal(meta.get('caller'), self.labels['rhea']), 'caller is the person label', meta)
        self.deny_all()

        # A notice decided before it is claimed: srv3's adapter paused (SIGSTOP), two held calls to `quiet` (srv3's),
        # one denied before any claim; then the adapter resumed.
        consumer = self.s('srv3')['consumer']
        consumer.signal(signal.SIGSTOP)
        try:
            kept, _, _ = self.submit('q1', 'quiet', 'echo', {'text': marker('kept')})
            voided, _, _ = self.submit('q1', 'quiet', 'echo', {'text': marker('void')})
            self.deny_api('q1', voided['call_id'])
            rows = db_rows(p1, 'SELECT record FROM approval_notices WHERE call_id = ?', (voided['call_id'],))
            unclaimed = db_rows(p1, 'SELECT session_id FROM approval_notices WHERE call_id = ?', (kept['call_id'],))
        finally:
            consumer.signal(signal.SIGCONT)
        need(unclaimed and unclaimed[0][0] is None, 'setup: the notices were not claimed while srv3\'s adapter was '
             'paused', unclaimed)
        need(rows and json.loads(rows[0][0]).get('state') == 'void', 'a notice decided before its claim is void', rows)
        consumer.wait_event('approval_request', timeout=60,
                            where=lambda p: (p.get('meta') or {}).get('call_id') == kept['call_id'])
        time.sleep(4)
        need(not self.notices('srv3', voided['call_id']), 'no event for a notice decided before its claim')
        need(len(self.notices('srv3', kept['call_id'])) == 1, 'the pending one arrives once')

        # The claim route, through raw credentials of `srvraw` (a registered agent, the source of `rawcap`).
        raw_kept, _, _ = self.submit('q1', 'rawcap', 'echo', {'text': marker('raw-kept')})
        raw_void, _, _ = self.submit('q1', 'rawcap', 'echo', {'text': marker('raw-void')})
        self.deny_api('q1', raw_void['call_id'])
        raw, _ = self.raw_setup('p1', self.aid['srvraw'], calls=False)
        status, value = raw.call('POST', '/adapter/v1/approval-notices/next', {})
        need(status == 409 and value == {'code': 'conflict', 'error': 'channel not verified'},
             'the claim route answers 409 before verification', status, value)
        raw.ready()
        status, value = raw.call('POST', '/adapter/v1/approval-notices/next', {})
        need(status == 200 and isinstance(value, dict) and set(value) == {'notice', 'approval'} and
             set(value['notice']) == NOTICE_KEYS and value['notice']['call_id'] == raw_kept['call_id'] and
             value['approval']['state'] == 'pending' and value['notice']['session_id'] and
             value['notice']['agent_id'] == self.aid['srvraw'] and NOTICE_ID.fullmatch(value['notice']['id']),
             'the claim returns {notice, approval}, without calls on the credential, skipping the voided notice',
             status, value)
        self.check_record(value['approval'])
        need(value['approval']['call_id'] == raw_kept['call_id'], 'the approval record of the claimed notice')
        notice_id = value['notice']['id']
        status, value = raw.call('POST', '/adapter/v1/approval-notices/next', {})
        need(status == 200 and value is None, 'null when there is nothing to claim', status, value)
        for _ in range(2):
            status, value = raw.call('POST', f'/adapter/v1/approval-notices/{notice_id}/forwarded', {})
            need(status == 200 and isinstance(value, dict) and value.get('state') == 'forwarded' and
                 value.get('id') == notice_id, 'forwarded sets forwarded and returns the notice, idempotently', status,
                 value)
        other, _ = self.raw_setup('p1', self.aid['nobody'], calls=False)
        other.ready()
        status, value = other.call('POST', f'/adapter/v1/approval-notices/{notice_id}/forwarded', {})
        need(status == 404, 'forwarded for a notice claimed by another credential is 404', status, value)
        status, value = raw.call('POST', f'/adapter/v1/approval-notices/notice_{secrets.token_hex(16)}/forwarded', {})
        need(status == 404, 'forwarded for an unknown notice is 404', status, value)
        status, value = other.call('POST', '/adapter/v1/approval-notices/next', {})
        need(status == 200 and value is None, 'another agent claims nothing of srvraw\'s', status, value)

        failed, value = self.tool(consumer, 'mark_seen', {'ids': [notice_id]})
        self.soft(failed or value == {'seen': []}, 'Q: mark_seen does not accept a notice ID (refused or ignored)',
                  failed, value)
        failed, value = self.tool(consumer, 'pending_work', {})
        need(not failed and kept['call_id'] not in json.dumps(value) and 'notice_' not in json.dumps(value),
             'notices are not listed in pending_work', value)
        self.deny_all()
        return ''

    # --- status ----------------------------------------------------------------------------------------------

    def check_status(self):
        self.deny_all()
        status = self.full_status()
        need(status['capabilities'].get('approvals_pending') == 0 and not self.approval_items(status),
             'nothing pending: approvals_pending 0 and no item 18', status['capabilities'],
             self.approval_items(status))
        first, _, _ = self.submit('q1', 'chg', 'write_note', {'text': marker('st1')})
        time.sleep(1.1)
        self.submit('r1', 'chg', 'write_note', {'text': marker('st2')})
        status = self.full_status()
        items = self.approval_items(status)
        need(status['capabilities'].get('approvals_pending') == 2, 'approvals_pending counts pending approvals',
             status['capabilities'])
        need(len(items) == 1 and items[0].get('subject') == '2' and items[0].get('command') == 'peerspan approvals' and
             isinstance(items[0].get('detail'), str) and 'chg' in items[0]['detail'] and
             'write_note' in items[0]['detail'], 'one item 18 call_approval_pending: the count, the oldest call in the '
             'detail, peerspan approvals', items)
        self.deny_api('q1', first['call_id'])
        status = self.full_status()
        need(status['capabilities'].get('approvals_pending') == 1 and
             (self.approval_items(status) or [{}])[0].get('subject') == '1', 'the count follows decisions',
             status['capabilities'], self.approval_items(status))
        self.deny_all()
        status = self.full_status()
        need(status['capabilities'].get('approvals_pending') == 0 and not self.approval_items(status),
             'item 18 gone once every approval is decided', self.approval_items(status))
        return ''

    def full_status(self):
        status, value = api(self.hosts['p1'], 'GET', '/v1/status')
        need(status == 200 and isinstance(value.get('capabilities'), dict), 'GET /v1/status', status)
        return value

    @staticmethod
    def approval_items(status):
        return [i for i in status.get('attention', []) if i.get('kind') == 'call_approval_pending']

    # --- older peers -----------------------------------------------------------------------------------------

    def check_older(self):
        need('o1' in self.hosts, 'setup: version 18 hosts (--baseline18)')
        o1 = self.hosts['o1']
        # A version 18 caller: queued, then the result after approval; rejected with approval_denied after denial.
        text = marker('old-ok')
        code, out, stdout, stderr = o1.outcome('call', 'pat/chg', 'write_note', '--input',
                                               json.dumps({'text': text}), '--wait', '3s')
        need(code == 3 and isinstance(out, dict) and (out.get('status') or {}).get('state') == 'queued',
             'a version 18 caller sees queued', code, stdout[-400:], stderr[-300:])
        call_ok = out['request']['call_id']
        text2 = marker('old-deny')
        code, out, stdout, stderr = o1.outcome('call', 'pat/chg', 'write_note', '--input',
                                               json.dumps({'text': text2}), '--wait', '1s')
        need(code == 3 and isinstance(out, dict), 'a second version 18 call, queued', code, stdout[-300:])
        call_deny = out['request']['call_id']
        self.approve_api('o1', call_ok)
        self.deny_api('o1', call_deny, 'old')
        record, seen = self.wait_outbound('o1', call_ok, lambda r: (r.get('status') or {}).get('state') in FINAL,
                                          timeout=150, step=0.5)
        need(record['status']['state'] == 'succeeded' and len(self.executed('fx', text)) == 1,
             'the version 18 caller gets the result after approval', record['status'])
        record, _ = self.wait_outbound('o1', call_deny, lambda r: (r.get('status') or {}).get('state') in FINAL,
                                       timeout=150, step=0.5)
        need(record['status']['state'] == 'rejected' and record['status']['error'] == 'approval_denied',
             'the version 18 caller sees rejected with approval_denied', record['status'])
        # This slice's caller against a version 18 receiver: unchanged; listings read approval false.
        listing = self.peer_listing('q1', receiver='o2')
        need('oldcap' in listing and all('approval' not in o for o in listing['oldcap']['operations']),
             'self-check: the version 18 receiver lists no approval', listing.get('oldcap'))
        code, out, stdout, stderr = self.hosts['q1'].outcome('discover', 'pat', '--json')
        entry = next((e for e in (out or {}).get('capabilities', []) if e['capability'] == 'oldcap'), None)
        need(entry and self.op_flags(entry) == {'echo': False, 'write_note': False}, 'discover shows approval false '
             'for a version 18 receiver', entry)
        failed, value = self.tool(self.s('qa')['consumer'], 'list_capabilities', {})
        entry = next((e for e in (value or {}).get('capabilities', []) if e['capability'] == 'oldcap'), None)
        need(not failed and entry and self.op_flags(entry) == {'echo': False, 'write_note': False},
             'list_capabilities shows approval false for a version 18 receiver', entry)
        view, _ = self.ok_call('qa', 'pat/oldcap', 'write_note', {'text': marker('to-old')})
        need(view['state'] == 'succeeded' and view['approval'] is None, 'an agent call to a version 18 receiver runs, '
             'approval null', view)
        code, out, stdout, stderr = self.hosts['q1'].outcome('call', 'pat/oldcap', 'write_note', '--input',
                                                             json.dumps({'text': marker('to-old-cli')}))
        need(code == 0 and isinstance(out, dict) and (out.get('status') or {}).get('approval') is None,
             'an owner call to a version 18 receiver: succeeded, approval null', code, stdout[-300:])
        return ''


def run_pairing(coord_binary, cli_binary, daemon_binary, node, label, integrations=None, only=None, baseline18=None):
    global INTEGRATIONS
    if integrations:
        INTEGRATIONS = Path(integrations)
        agents.INTEGRATIONS = INTEGRATIONS
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-approval-') as temporary:
        pairing = ApprovalPairing(label, cli_binary, daemon_binary, coord_binary, node, Path(temporary), only,
                                  baseline18)
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [approval: setup]: {detail}', flush=True)
            if pairing.setup_notes:
                print(f'NOTE {label} approval setup: ' + ' | '.join(pairing.setup_notes), flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        for note in pairing.notes:
            print(f'NOTE {label} approval (not counted): {note}', flush=True)
        print(f'---- {label} approval: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} sections '
              f'passed in {time.monotonic() - started:.0f}s', flush=True)
        return [(f'approval: {name}', ok, detail) for name, ok, detail in pairing.results]


# --- migration to version 20 ----------------------------------------------------------------------------------

def check_migration(original, replacement, label, baseline=None, start=18):
    """Version 18 or 19 to 20, with existing capability records reading approval none; version 21 refused.

    With `baseline` (a version 18 peerspan-host), the version 18 state is made by it. Otherwise it is made by
    `original` and taken back to version `start`, as the other suites model older state: the version 20 tables
    (APPROVAL_TABLES, with their index) dropped, `approval` removed from capability records, for 18 also the version
    19 machine-linking tables (LINKING_TABLES) dropped, and user_version set. A database below 19 gets the version 19
    tables first, so migrating from 18 also creates them."""
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-approval-migration-') as directory:
        root = Path(directory)
        host = Host(baseline or original, root / 'host')
        fixture = caps.Fixture(root / 'fixture')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            status, body = api(host, 'PUT', f"/v1/agents/{agent['id']}/tool-servers", {
                'workspace': str(root), 'values': {},
                'servers': [{'name': 'fx', 'transport': 'stdio', 'command': PYTHON, 'args': fixture.args('fx'),
                             'env': {}, 'url': None, 'source': 'claude-code:user'}]})
            need(status == 200, 'setup: the fixture source', status, body)
            host.cli('capability', 'create', 'keptcap', '--from', 'kept/fx', '--operations', 'echo,write_note')
            host.stop()
            if baseline:
                need(start == 18 and db_rows(host, 'PRAGMA user_version')[0][0] == 18, 'the baseline is version 18')
            else:
                need(db_rows(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION, 'the current database version', label)
                connection = sqlite3.connect(host.state / 'host.db')
                try:
                    connection.execute(f'DROP INDEX IF EXISTS {NEW_INDEX}')
                    for table in (*BUILTIN_TABLES, *APPROVAL_TABLES, *(LINKING_TABLES if start < 19 else ())):
                        connection.execute(f'DROP TABLE {table}')
                    for name, value in connection.execute('SELECT name, record FROM capabilities').fetchall():
                        record = json.loads(value)
                        record.pop('approval', None)
                        connection.execute('UPDATE capabilities SET record = ? WHERE name = ?',
                                           (json.dumps(record), name))
                    connection.execute(f'PRAGMA user_version = {start}')
                    connection.commit()
                finally:
                    connection.close()
            host.binary = str(replacement)
            need(host.start()['id'] == identity['id'], 'the identity survives migration')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION, 'migrated to the current version')
            objects = {r[0] for r in db_rows(host, "SELECT name FROM sqlite_master WHERE type IN ('table', 'index')")}
            need(set(NEW_TABLES) | {NEW_INDEX} <= objects, 'migration creates the two tables and the index',
                 sorted(objects))
            need(set(LINKING_TABLES) <= objects, f'after migrating from {start}, the version 19 tables exist',
                 sorted(set(LINKING_TABLES) - objects))
            status, record = api(host, 'GET', '/v1/capabilities/keptcap')
            need(status == 200 and record.get('approval') == NONE, 'an existing capability reads approval none',
                 status, record)
            host.stop()
            version = SCHEMA_VERSION + 1
            connection = sqlite3.connect(host.state / 'host.db')
            connection.execute(f'PRAGMA user_version = {version}')
            connection.commit()
            connection.close()
            for binary in {str(original), str(replacement)}:
                result = subprocess.run([binary, '--state', str(host.state), 'run'], capture_output=True,
                                        timeout=10)
                need(result.returncode != 0, f'current binaries refuse version {version}', binary)
            need(db_rows(host, 'PRAGMA user_version')[0][0] == version, 'refused without changes', version)
        finally:
            stop_all((host,))
    return label
