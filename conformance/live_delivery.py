#!/usr/bin/env python3
"""Exercise live-session readiness and diagnostics (milestone 9, slice 1) across CLI/daemon pairings.

Written from docs/live-delivery-contract.md ("Slice 1: readiness and diagnostics" and its
Verification list), with context from the live delivery proposal and the contracts it extends
(agent adapter, outbound, recovery, task, harness integration, launch), independently of the Go and
Rust hosts and of the Node adapter, which runs here only as a black box.

Each pairing runs one Go coordinator and two hosts, alice's (A) and bob's (B), both running the
pairing's daemon and driven by its CLI. Every host has its own HOME and XDG_CONFIG_HOME, so persons
use generated keys and nothing touches the real ~/.config/capsule. Sessions are prepared with the
Claude integration (`session setup --harness claude-code`) against a fixture `claude` executable
that reports a chosen `--version` and `auth status` JSON and, when launched, prints its arguments,
cwd, and MCP_PROTOCOL_NEGOTIATION. No model runs: the MCP consumer here is deterministic. It starts
the adapter exactly as the profile's mcp.json describes, initializes MCP, records every channel
event with its arrival time, and calls `capsule_ready` only when a check says so. Raw adapter
clients (bearer token and instance, as the recovery contract allows) cover the routes directly.

The 60-second hello re-send and the 120-second status item 13 need real time. A silent session is
started first, and its timers run while the other sections do; a status watcher samples
`GET /v1/status` in the background. Sections, per pairing:

- hello event: the first channel event is `hello` with a fresh 128-bit hex nonce, its content
  naming `capsule_ready` and the nonce; nothing else (no queued message) follows; the tool list has
  `capsule_ready` taking `{nonce}`;
- work routes before verification: the five work routes answer 409 `{code: "conflict", error:
  "channel not verified"}` and claim nothing, the connection object shows `channel`,
  `channel_verified_at` (keeping the first time), and `protocol_version`, while outbound and `GET /adapter/v1/session` work;
  `POST /adapter/v1/ready` needs the credential and a lease, and is idempotent; afterwards the
  queued message and task are claimed;
- wrong nonce and capsule_ready: a wrong nonce is a tool error and changes nothing; the right one
  returns `{ready: true}`, the queued message and task arrive, new work flows, and a repeat call
  returns `{ready: true}`;
- connected: `connected` and `channel` in `GET /v1/directory` on bob's host before and after
  verification, for an unverified lease, and with no lease (null); session objects from the session
  routes (`/v1/sessions`, `/v1/sessions/{id}`, attach, detach, setup, `/adapter/v1/session`, here
  through `session list`/`inspect`/`attach`/`detach` and the API) and the connection object
  report `channel`;
- doctor: `claude_version` below, at, and above 2.1.187 (and unparseable), `claude_account`
  warnings (passing checks whose detail starts with `Warning: `) for a present non-first-party
  provider and team/enterprise subscriptions, none without `apiProvider`, `channel`
  (verified, unverified with the item 13 message, not running passing), integration checks with
  the `harness/` prefix, and `adapter_ready` requiring a verified channel;
- protocol: the negotiated revision recorded as `protocol_version`, and doctor failing
  `mcp_protocol` for a fixture adapter reporting `2026-07-28`;
- launch: `session start` launching Claude with `MCP_PROTOCOL_NEGOTIATION=legacy`, and the MCP
  instructions at most 2,048 characters;
- fatal stop: a replaced instance emits one `disconnected` event naming `capsule attach claude`
  (or `claude-code`), writes a reason to stderr, and exits 1; the replacement starts unverified;
- deadlines: adapter sends by address and through routes default to 1 hour, bounded by the
  credential's expiry and, for routes, the route's expiry;
- migration: a schema 13 state (made by a pre-milestone-9 host, `--baseline`) opening at 14 with
  its authorization unverified;
- hello re-sent once: exactly one more hello, with the same nonce, about 60 seconds after the first,
  and none after; the lease kept;
- item 13: `channel_unverified` absent before 120 seconds of unverified lease and present after,
  with subject, command, and message; `status` exiting 1; doctor's channel check carrying the
  message; then `capsule_ready` clears it and delivers the held message;
- daemon restart: a verified authorization stays verified across a restart of its daemon (work
  flows without another `capsule_ready`). (A new attachment of a previously verified agent
  starting unverified is checked in the fatal stop section, on the replacement attachment.)

Ambiguities are listed in the suite questions file and marked "Q:" below; checks take the most
literal reading. Needs Python 3, capsule-peer-probe, Node, and the Go coordinator.
Exits non-zero listing every failed section.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from coordination import Coordinator, wait_for
from host_service import UnixHTTPConnection, stop_all
from launch_directory import DirectoryHost
from launch_onboarding import Failure, near, need
from peer_messaging import request_id, set_probe, timestamp
from tasks import task_id

REPO = Path(__file__).resolve().parents[1]
INTEGRATIONS = REPO / 'integrations'
MINIMUM = '2.1.187'
NOT_VERIFIED = 'channel not verified'
WORK_ROUTES = ('/adapter/v1/next', '/adapter/v1/tasks/next', '/adapter/v1/tasks/cancels/next',
               '/adapter/v1/task-updates/next', '/adapter/v1/replies/next')
RESEND = 60
ITEM13 = 120
CLIENT_PROTOCOL = '2025-11-25'
LATE_PROTOCOL = '2026-07-28'
NONCE = re.compile(r'[0-9a-fA-F]{32}')
TASK_TOOLS_PREFIX = 'task_'

# The fixture `claude`: answers `--version` and `auth status` (exactly those arguments) from files beside it, so a check can change them; any other invocation is a launch, printing its arguments,
# cwd, and the MCP_PROTOCOL_NEGOTIATION environment variable as one JSON line. Every call is logged.
FIXTURE_CLAUDE = r'''#!/usr/bin/env python3
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
with open(os.path.join(here, "calls.log"), "a") as log:
    log.write(json.dumps(args) + "\n")
if args == ["--version"]:
    with open(os.path.join(here, "version.txt")) as f:
        sys.stdout.write(f.read())
elif args == ["auth", "status"]:
    with open(os.path.join(here, "auth.json")) as f:
        sys.stdout.write(f.read())
elif "--version" in args:
    # As Claude Code does, --version with other arguments (such as the channel launch flags) still prints it.
    with open(os.path.join(here, "version.txt")) as f:
        sys.stdout.write(f.read())
else:
    print(json.dumps({"arguments": args, "cwd": os.getcwd(), "pid": os.getpid(),
                      "MCP_PROTOCOL_NEGOTIATION": os.environ.get("MCP_PROTOCOL_NEGOTIATION")}))
'''
GOOD_VERSION = '2.1.291 (Claude Code)\n'
FIRST_PARTY = {'loggedIn': True, 'authMethod': 'claude.ai', 'apiProvider': 'firstParty', 'subscriptionType': 'max'}


class Fixture:
    """One fixture claude executable in its own directory, with switchable version and account."""

    def __init__(self, directory):
        directory.mkdir(parents=True)
        self.directory = directory
        self.path = directory / 'claude'
        self.path.write_text(FIXTURE_CLAUDE)
        self.path.chmod(0o700)
        self.version(GOOD_VERSION)
        self.account(FIRST_PARTY)

    def version(self, text):
        (self.directory / 'version.txt').write_text(text)

    def account(self, value):
        (self.directory / 'auth.json').write_text(json.dumps(value) + '\n')


def not_verified(status, value):
    """The work routes' answer before verification: 409 {code: "conflict", error: "channel not verified"}."""
    return status == 409 and isinstance(value, dict) and value.get('code') == 'conflict' \
        and value.get('error') == NOT_VERIFIED


def session_in(value, session_id):
    """The session object with this ID inside a response (the response itself, or nested in it), or None."""
    if isinstance(value, dict):
        if value.get('id') == session_id:
            return value
        values = value.values()
    elif isinstance(value, list):
        values = value
    else:
        return None
    for item in values:
        found = session_in(item, session_id)
        if found is not None:
            return found
    return None


def session_channel(value, session_id, route):
    """channel on the session object a session route returns."""
    found = session_in(value, session_id)
    need(found is not None, f'{route} returns the session object', value)
    need('channel' in found, f'session objects from {route} gain channel', found)
    return found['channel']


def check_named(report, name):
    """A doctor check by name. claude_version and claude_account come from the Claude integration, so they
    carry the CLI's harness/ prefix. Q: the contract does not say whether channel and mcp_protocol are native
    or integration checks; either name is accepted for those."""
    names = ('harness/' + name,) if name in ('claude_version', 'claude_account') else (name, 'harness/' + name)
    found = [c for c in report.get('checks', []) if c.get('name') in names]
    need(len(found) == 1, f'doctor reports exactly one {names[0]} check',
         [c.get('name') for c in report.get('checks', [])])
    return found[0]


class Consumer:
    """A deterministic MCP client in place of Claude Code: it runs the adapter as mcp.json describes."""

    def __init__(self, profile, env, directory):
        directory.mkdir(parents=True, exist_ok=True)
        config = json.loads((profile / 'mcp.json').read_text())
        servers = config['mcpServers']
        need(len(servers) == 1, 'mcp.json describes one server', servers)
        [(self.name, server)] = servers.items()
        environment = dict(env)
        environment.update(server.get('env') or {})
        self.stderr_path = directory / 'stderr.log'
        self.stderr = open(self.stderr_path, 'wb')
        self.process = subprocess.Popen([server['command'], *server.get('args', [])], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr, env=environment,
                                        cwd=str(directory), start_new_session=True)
        self.lock = threading.Lock()
        self.responses = {}
        self.events = []  # (monotonic time, params) of notifications/claude/channel
        self.other = []
        self.closed_at = None
        self.count = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.started = time.monotonic()
        self.initialized = self.call('initialize', {
            'protocolVersion': CLIENT_PROTOCOL, 'capabilities': {},
            'clientInfo': {'name': 'capsule-live-delivery-conformance', 'version': '1'}})
        self.negotiated = self.initialized.get('protocolVersion')
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def _read(self):
        for line in self.process.stdout:
            now = time.monotonic()
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            with self.lock:
                if 'id' in message and ('result' in message or 'error' in message):
                    self.responses[message['id']] = message
                elif message.get('method') == 'notifications/claude/channel':
                    self.events.append((now, message.get('params') or {}))
                else:
                    self.other.append((now, message))
        self.closed_at = time.monotonic()

    def send(self, value):
        self.process.stdin.write((json.dumps(value) + '\n').encode())
        self.process.stdin.flush()

    def call(self, method, params, seconds=20):
        self.count += 1
        rid = self.count
        self.send({'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params})
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            with self.lock:
                if rid in self.responses:
                    response = self.responses.pop(rid)
                    break
            if self.closed_at is not None:
                raise Failure(f'MCP adapter exited during {method}: {self.stderr_text()[-600:]}')
            time.sleep(0.02)
        else:
            raise Failure(f'MCP {method} timed out')
        if 'error' in response:
            return {'jsonrpc_error': response['error']}
        return response['result']

    def tool(self, name, arguments):
        """(is_error, parsed text) for a tool call; a JSON-RPC error counts as an error too."""
        result = self.call('tools/call', {'name': name, 'arguments': arguments})
        if 'jsonrpc_error' in result:
            return True, result['jsonrpc_error']
        text = ''.join(c.get('text', '') for c in result.get('content', []) if c.get('type') == 'text')
        try:
            return bool(result.get('isError')), json.loads(text)
        except json.JSONDecodeError:
            return bool(result.get('isError')), text

    def channel(self, since=0.0):
        with self.lock:
            return [(t, p) for t, p in self.events if t >= since]

    def kinds(self, since=0.0):
        return [(p.get('meta') or {}).get('kind') for _, p in self.channel(since)]

    def wait_event(self, kind, since=0.0, timeout=20, where=None):
        def found():
            for t, p in self.channel(since):
                meta = p.get('meta') or {}
                if meta.get('kind') == kind and (where is None or where(p)):
                    return t, p
            return None
        return wait_for(found, timeout=timeout, message=f'a {kind} channel event')

    def hellos(self):
        return [(t, p) for t, p in self.channel() if (p.get('meta') or {}).get('kind') == 'hello']

    def stderr_text(self):
        try:
            return self.stderr_path.read_text(errors='replace')
        except OSError:
            return ''

    def signal(self, number):
        os.killpg(self.process.pid, number)

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except OSError:
                    pass
                self.process.wait()
        self.stderr.close()


class RawAdapter:
    """A raw adapter client: bearer token and one instance; every call first connects (renews the lease).

    The connect body carries protocol_version (Q: the contract adds it to POST /adapter/v1/connect without
    saying whether renewals repeat it; this client always sends it, except for a schema 13 host)."""

    def __init__(self, host, secret, protocol=CLIENT_PROTOCOL):
        self.host, self.token, self.adapter = host, secret['token'], secret['adapter']
        self.instance = 'instance_' + secrets.token_hex(32)
        self.protocol = protocol

    def request(self, method, path, body=None, token=None, instance=None):
        connection = UnixHTTPConnection(self.host.state / 'adapter.sock', timeout=15)
        try:
            payload = json.dumps(body).encode() if body is not None else None
            headers = {'Authorization': 'Bearer ' + (token or self.token), 'Content-Type': 'application/json',
                       'X-Capsule-Instance': instance or self.instance}
            connection.request(method, path, payload, headers)
            response = connection.getresponse()
            data = response.read()
            try:
                return response.status, json.loads(data)
            except json.JSONDecodeError:
                return response.status, data.decode(errors='replace')
        finally:
            connection.close()

    def connect(self):
        body = {'adapter_id': self.adapter['id'], 'session_id': self.adapter['session_id'],
                'instance_id': self.instance}
        if self.protocol is not None:
            body['protocol_version'] = self.protocol
        return self.request('POST', '/adapter/v1/connect', body)

    def call(self, method, path, body=None):
        status, value = self.connect()
        need(status == 200, 'raw adapter connects', status, value)
        return self.request(method, path, body)


def user_version(host):
    with sqlite3.connect(host.state / 'host.db', timeout=10) as connection:
        return connection.execute('PRAGMA user_version').fetchone()[0]


class StatusWatcher:
    """Samples GET /v1/status every 2 seconds: (monotonic time, channel_unverified items)."""

    def __init__(self, host):
        self.host = host
        self.samples = []
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self.stopping.is_set():
            started = time.monotonic()
            try:
                status, body = self.host.call('GET', '/v1/status')
                if status == 200:
                    items = [i for i in body.get('attention', []) if i.get('kind') == 'channel_unverified']
                    self.samples.append((started, items))
            except Exception:
                pass
            self.stopping.wait(2)

    def stop(self):
        self.stopping.set()
        self.thread.join(timeout=10)


class Pairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, node, baseline, root):
        self.label, self.cli_binary, self.daemon, self.node, self.root = label, cli_binary, daemon_binary, node, root
        self.baseline = baseline
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results = []
        self.hosts = {}
        self.consumers = []
        self.watcher = None
        self.observed = {}

    # --- infrastructure -----------------------------------------------------------------------------------

    def host(self, name, daemon=None, cli=None):
        h = DirectoryHost(daemon or self.daemon, cli or self.cli_binary, self.root / name, self.root / f'user-{name}')
        self.hosts[name] = h
        return h

    def section(self, name, function):
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:  # report and continue with the next section
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=5)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}',
              flush=True)
        return True

    def env(self, host):
        e = dict(os.environ)
        e.update(host.private_env())
        e['PATH'] = str(Path(self.node).parent) + os.pathsep + e.get('PATH', '')
        return e

    def register(self, host, name, owner):
        return host.cli('agent', 'register', '--name', name, '--owner', owner)

    def profile(self, name, agent, fixture):
        """A Claude integration profile for agent, with the fixture claude."""
        directory = self.root / 'profiles' / name
        directory.parent.mkdir(exist_ok=True)
        out = self.a.cli('session', 'setup', '--harness', 'claude-code', '--directory', str(directory), '--agent',
                         agent['id'], '--integrations', str(INTEGRATIONS), '--runner', str(self.node), '--option',
                         f'executable={fixture.path}', '--expires-in', '2h')
        need(out.get('session_id') and (directory / 'mcp.json').exists(), f'session setup for {name}', out)
        return directory, out

    def secret(self, directory):
        return json.loads((directory / 'credential.json').read_text())

    def consumer(self, directory, name):
        c = Consumer(directory, self.env(self.a), self.root / 'consumers' / name)
        self.consumers.append(c)
        return c

    def doctor(self, directory, host=None):
        result = (host or self.a).run('session', 'doctor', '--directory', str(directory))
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise Failure(f'session doctor prints its JSON report: {result.stdout[-500:]} {result.stderr[-500:]}')
        return result.returncode, report

    def directory_of(self, name, refresh=True):
        """bob's view of alice's agent `name`, from GET /v1/directory (after a refresh)."""
        if refresh:
            status, body = self.b.call('POST', f'/v1/directory/refresh?network={self.net}', {})
            need(status == 200, 'POST /v1/directory/refresh', status, body)
        status, body = self.b.call('GET', f'/v1/directory?network={self.net}')
        need(status == 200, 'GET /v1/directory', status, body)
        entries = [a for a in body['agents'] if a.get('address') == f'alice/{name}']
        need(len(entries) == 1, f'alice/{name} in bob\'s directory', [a.get('address') for a in body['agents']])
        return entries[0]

    def directory_state(self, name):
        entry = self.directory_of(name)
        need('channel' in entry, 'Directory entries gain channel', entry)
        return entry['connected'], entry['channel']

    def sessions_of(self, agent):
        listing = self.a.cli('session', 'list', '--agent', agent['id'])
        need(isinstance(listing, list), 'session list prints a list', listing)
        return {s['id']: s for s in listing}

    def deliveries_mention(self, rid):
        return rid in json.dumps(self.a.cli('delivery', 'list'))

    def send_from_bob(self, name, text):
        out = self.b.cli('send', f'alice/{name}', text, '--network', self.net)
        rid = out['request']['request_id']

        def accepted():
            status, record = self.b.call('GET', f"/v1/outbound/{self.ids['a']}/{rid}")
            return record if status == 200 and record.get('state') == 'accepted' else None
        wait_for(accepted, timeout=40, message=f'bob\'s send to alice/{name} accepted')
        return rid

    def task_from_bob(self, name, text):
        out = self.b.cli('task', f'alice/{name}', text, '--network', self.net)
        tid = out['request']['task_id']

        def accepted():
            status, record = self.b.call('GET', f"/v1/tasks/{self.ids['a']}/{tid}")
            return record if status == 200 and record.get('submit_state') == 'accepted' else None
        wait_for(accepted, timeout=40, message=f'bob\'s task to alice/{name} accepted')
        return tid

    def connection(self, adapter_id):
        return self.a.cli('adapter', 'connection', adapter_id)['state']

    def connection_object(self, adapter_id, host=None):
        """GET /v1/adapters/{id}/connection, which gains channel, channel_verified_at, and protocol_version."""
        status, body = (host or self.a).call('GET', f'/v1/adapters/{adapter_id}/connection')
        need(status == 200 and isinstance(body, dict), 'GET /v1/adapters/{id}/connection', status, body)
        for key in ('channel', 'channel_verified_at', 'protocol_version'):
            need(key in body, f'the connection object gains {key}', body)
        return body

    def session_channels(self, agent, session_id):
        """channel on this session's objects from session list and session inspect."""
        listed = self.sessions_of(agent).get(session_id)
        need(listed is not None and 'channel' in listed, 'session list objects gain channel', listed)
        inspected = self.a.cli('session', 'inspect', session_id)
        need('channel' in inspected, 'session inspect objects gain channel', inspected)
        need(listed['channel'] == inspected['channel'], 'session list and inspect report the same channel', listed,
             inspected)
        return listed['channel']

    # --- sections ------------------------------------------------------------------------------------------

    def check_hello(self):
        s1 = self.s1
        _, first = s1.wait_event('hello', timeout=20)
        events = s1.channel()
        need(events and (events[0][1].get('meta') or {}).get('kind') == 'hello',
             'Hello event: the adapter emits hello before anything else', [p.get('meta') for _, p in events])
        meta = first.get('meta') or {}
        need(all(isinstance(v, str) for v in meta.values()), 'channel meta values are strings', meta)
        nonce = meta.get('nonce')
        need(isinstance(nonce, str) and NONCE.fullmatch(nonce), 'Hello event: meta.nonce is a 128-bit hex value',
             meta)
        content = first.get('content') or ''
        need('capsule_ready' in content and nonce in content,
             'Hello event: its content asks the model to call capsule_ready with that nonce', content)
        self.s1_nonce, self.s1_hello = nonce, self.s1.hellos()[0][0]
        # The message bob queued before this session started stays unclaimed.
        time.sleep(3)
        need(s1.kinds() == ['hello'], 'Before capsule_ready, no work is forwarded (only the hello event)',
             s1.kinds())
        need(not self.deliveries_mention(self.queued_quiet), 'Before capsule_ready, the adapter claims no work',
             self.queued_quiet)
        tools = {t['name']: t for t in s1.call('tools/list', {})['tools']}
        ready = tools.get('capsule_ready')
        need(ready and 'nonce' in (ready.get('inputSchema') or {}).get('properties', {}),
             'capsule_ready takes {nonce}', ready)
        self.tools = tools
        return f'nonce {nonce[:8]}…'

    def check_routes(self):
        a, b = self.a, self.b
        agent = self.agent['rawq']
        status, body = a.call('POST', '/v1/adapters/setup', {
            'agent_id': agent['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
            'expires_at': timestamp(7200), 'directory': True})
        need(status == 201, 'POST /v1/adapters/setup with directory', status, body)
        raw = RawAdapter(a, body['credential'])
        self.raw_rawq = raw
        session_id = raw.adapter['session_id']
        # Q: the setup response's session object is found by its ID wherever it is nested.
        need(session_channel(body, session_id, 'POST /v1/adapters/setup') is None,
             'a new setup\'s session has channel null (no lease)', body)
        rid = self.send_from_bob('rawq', 'held for rawq')
        tid = self.task_from_bob('rawq', 'task held for rawq')
        status, value = raw.connect()
        need(status == 200, 'POST /adapter/v1/connect with protocol_version', status, value)
        before = self.connection_object(raw.adapter['id'])
        need(before['channel'] == 'unverified' and before['channel_verified_at'] is None,
             'the connection object: channel unverified with a lease, channel_verified_at null', before)
        for path in WORK_ROUTES:
            status, value = raw.call('POST', path, {})
            need(not_verified(status, value),
                 f'Work routes: until verified, {path} answers 409 {{code: "conflict", error: "channel not verified"}}', status, value)
        need(not self.deliveries_mention(rid), 'Work routes: a 409 claims nothing', rid)
        status, value = raw.call('GET', '/adapter/v1/session')
        need(status == 200, 'GET /adapter/v1/session works before verification', status, value)
        need(session_channel(value, session_id, 'GET /adapter/v1/session') == 'unverified',
             'GET /adapter/v1/session: channel unverified before verification', value)
        status, value = a.call('GET', f'/v1/sessions/{session_id}')
        need(status == 200 and session_channel(value, session_id, 'GET /v1/sessions/{id}') == 'unverified',
             'GET /v1/sessions/{id}: channel unverified', status, value)
        status, value = raw.call('POST', '/adapter/v1/send', {'to': 'bob/target', 'network': self.net,
                                                              'request_id': request_id(), 'content': 'early'})
        need(status == 200, 'Outbound tools work before verification (a send by address)', status, value)
        nonce = secrets.token_hex(16)
        # The ready route requires the credential and a lease.
        status, value = raw.request('POST', '/adapter/v1/ready', {'nonce': nonce}, token='token_' + 'a' * 64)
        need(not 200 <= status < 300, 'POST /adapter/v1/ready requires the adapter\'s credential', status, value)
        status, value = raw.request('POST', '/adapter/v1/ready', {'nonce': nonce},
                                    instance='instance_' + secrets.token_hex(32))
        need(not 200 <= status < 300, 'POST /adapter/v1/ready requires the adapter\'s lease (bound instance)',
             status, value)
        status, value = raw.call('POST', '/adapter/v1/next', {})
        need(status == 409, 'a refused ready verifies nothing', status, value)
        status, value = raw.call('POST', '/adapter/v1/ready', {'nonce': nonce})
        need(200 <= status < 300, 'POST /adapter/v1/ready with {nonce}', status, value)
        first = self.connection_object(raw.adapter['id'])
        need(first['channel'] == 'verified' and first['channel_verified_at'],
             'The daemon stores channel_verified_at; the connection object shows channel verified', first)
        time.sleep(1.5)
        status, value = raw.call('POST', '/adapter/v1/ready', {'nonce': nonce})
        need(200 <= status < 300, 'POST /adapter/v1/ready is idempotent', status, value)
        status, value = raw.call('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, 'POST /adapter/v1/ready again after verification', status, value)
        status, value = raw.call('GET', '/adapter/v1/session')
        need(status == 200 and session_channel(value, session_id, 'GET /adapter/v1/session') == 'verified',
             'GET /adapter/v1/session: channel verified after verification', status, value)
        status, value = a.call('GET', '/v1/sessions')
        need(status == 200 and session_channel(value, session_id, 'GET /v1/sessions') == 'verified',
             'GET /v1/sessions: channel verified', status, value)
        again = self.connection_object(raw.adapter['id'])
        need(again['channel_verified_at'] == first['channel_verified_at'],
             'channel_verified_at keeps the first time', first, again)
        need(again['protocol_version'] == CLIENT_PROTOCOL, 'the connection object shows the reported protocol_version',
             again)
        status, value = raw.call('POST', '/adapter/v1/next', {})
        need(status == 200 and isinstance(value, dict) and value.get('request', {}).get('request_id') == rid,
             'After verification, /adapter/v1/next claims the held message', status, value)
        status, value = raw.call('POST', '/adapter/v1/tasks/next', {})
        need(status == 200 and isinstance(value, dict) and tid in json.dumps(value),
             'After verification, /adapter/v1/tasks/next claims the held task', status, value)
        for path in ('/adapter/v1/tasks/cancels/next', '/adapter/v1/task-updates/next', '/adapter/v1/replies/next'):
            status, value = raw.call('POST', path, {})
            need(status == 200, f'After verification, {path} answers 200', status, value)
        return 'five routes 409 before, claims after'

    def check_capsule_ready(self):
        s2 = self.s2
        _, hello = s2.wait_event('hello', timeout=20)
        nonce = hello['meta']['nonce']
        need(nonce != getattr(self, 's1_nonce', None), 'each adapter\'s nonce is fresh', nonce)
        self.observed['eager_before'] = self.directory_state('eager')
        wrong = secrets.token_hex(16)
        failed, value = s2.tool('capsule_ready', {'nonce': wrong})
        need(failed, 'capsule_ready: a wrong nonce returns a tool error', value)
        time.sleep(2)
        need(s2.kinds() == ['hello'], 'A wrong nonce changes nothing: no work arrives', s2.kinds())
        self.observed['eager_wrong'] = self.directory_state('eager')
        need(not self.deliveries_mention(self.queued_eager), 'A wrong nonce changes nothing: nothing claimed')
        marked = time.monotonic()
        failed, value = s2.tool('capsule_ready', {'nonce': nonce})
        need(not failed and value == {'ready': True}, 'capsule_ready with the matching nonce returns {ready: true}',
             failed, value)
        _, message = s2.wait_event('message', since=marked, timeout=20,
                                   where=lambda p: p['meta'].get('request_id') == self.queued_eager
                                   or self.queued_eager in json.dumps(p))
        _, task = s2.wait_event('task', since=marked, timeout=20, where=lambda p: self.queued_eager_task in json.dumps(p))
        rid = self.send_from_bob('eager', 'after ready')
        s2.wait_event('message', since=marked, timeout=20, where=lambda p: rid in json.dumps(p))
        failed, value = s2.tool('capsule_ready', {'nonce': nonce})
        need(not failed and value == {'ready': True}, 'A repeated capsule_ready after readiness returns {ready: true}',
             failed, value)
        self.observed['eager_after'] = self.directory_state('eager')
        self.s2_nonce = nonce
        return 'held message and task delivered after capsule_ready'

    def check_connected(self):
        need('eager_after' in self.observed, 'needs the capsule_ready section')
        need(self.observed['eager_before'] == (False, 'unverified'),
             'Directory: a lease without verification is connected false, channel unverified',
             self.observed['eager_before'])
        need(self.observed['eager_wrong'] == (False, 'unverified'), 'Directory: still unverified after a wrong nonce',
             self.observed['eager_wrong'])
        need(self.observed['eager_after'] == (True, 'verified'),
             'Directory: after capsule_ready, connected true and channel verified', self.observed['eager_after'])
        state = self.directory_state('quiet')
        need(state == (False, 'unverified'), 'Directory: the silent session\'s agent is unverified', state)
        state = self.directory_state('idle')
        need(state == (False, None), 'Directory: an agent without a lease has channel null', state)
        # session list reports channel the same way.
        for name, expected in (('eager', 'verified'), ('quiet', 'unverified'), ('launchy', None)):
            value = self.session_channels(self.agent[name], self.session_ids[name])
            need(value == expected, f'session objects report channel {expected} ({name})', value)
            adapter_id = self.secret(self.profiles[name])['adapter']['id']
            value = self.connection_object(adapter_id)['channel']
            need(value == expected, f'the connection object reports channel {expected} ({name})', value)
        return 'unverified, verified, null'

    def check_doctor(self):
        directory, fixture = self.profiles['eager'], self.fixtures['eager']
        notes = []
        code, report = self.doctor(directory)
        need(code == 0 and report.get('adapter_ready') is True,
             'doctor: a verified session with a current Claude is ready', code, report.get('checks'))
        need(check_named(report, 'claude_version')['status'] == 'ok', 'claude_version ok for 2.1.291', report)
        need(check_named(report, 'claude_account')['status'] == 'ok', 'claude_account ok for a firstParty max account',
             report)
        need(check_named(report, 'channel')['status'] == 'ok', 'channel ok when verified', report)
        need(check_named(report, 'mcp_protocol')['status'] == 'ok', 'mcp_protocol ok for the negotiated revision',
             report)
        # Q: "session doctor and session list report channel the same way" read as a top-level channel field.
        need(report.get('channel') == 'verified', 'session doctor reports channel verified', report.get('channel'))
        try:
            for text, ok in (('2.1.186 (Claude Code)\n', False), ('2.0.999 (Claude Code)\n', False),
                             ('1.9.300\n', False), ('Claude Code\n', False), (f'{MINIMUM} (Claude Code)\n', True),
                             (f'{MINIMUM}\n', True), ('2.2.0 (Claude Code)\n', True), ('3.0.0\n', True)):
                fixture.version(text)
                code, report = self.doctor(directory)
                check = check_named(report, 'claude_version')
                if ok:
                    need(check['status'] == 'ok' and code == 0 and report.get('adapter_ready') is True,
                         f'claude_version: {text.strip()!r} is at least {MINIMUM}', code, check)
                else:
                    need(check['status'] == 'error' and MINIMUM in check.get('detail', ''),
                         f'claude_version: {text.strip()!r} fails, naming the minimum', check)
                    need(code != 0 and report.get('adapter_ready') is False,
                         'a failing claude_version makes doctor fail', code, report.get('adapter_ready'))
            notes.append('versions')
        finally:
            fixture.version(GOOD_VERSION)
        calls = [json.loads(line) for line in (fixture.directory / 'calls.log').read_text().splitlines()]
        need(['--version'] in calls, 'claude_version runs the executable with --version and no other arguments',
             calls[-10:])
        provider = 'channels are not available on this provider'
        owner = 'an organization owner must enable channels'
        no_provider = {k: v for k, v in FIRST_PARTY.items() if k != 'apiProvider'}
        try:
            for account, expected in (({**FIRST_PARTY, 'apiProvider': 'bedrock'}, provider),
                                      ({**FIRST_PARTY, 'apiProvider': 'vertex'}, provider),
                                      ({**FIRST_PARTY, 'apiProvider': 'foundry'}, provider),
                                      ({**FIRST_PARTY, 'subscriptionType': 'team'}, owner),
                                      ({**FIRST_PARTY, 'subscriptionType': 'enterprise'}, owner),
                                      ({**FIRST_PARTY, 'subscriptionType': 'pro'}, None),
                                      (no_provider, None),
                                      ({**no_provider, 'subscriptionType': 'team'}, owner),
                                      (FIRST_PARTY, None)):
                fixture.account(account)
                code, report = self.doctor(directory)
                check = check_named(report, 'claude_account')
                if expected is None:
                    need(check['status'] == 'ok' and not check.get('detail', '').startswith('Warning: '),
                         'claude_account ok without a warning (the provider warning needs apiProvider present)',
                         account, check)
                    continue
                need(check['status'] == 'ok' and check.get('detail', '').startswith('Warning: '),
                     'claude_account: a warning is a passing check whose detail starts with "Warning: "', account,
                     check)
                need(expected in check.get('detail', '').lower(), f'claude_account warning says "{expected}"',
                     account, check)
                need(code == 0 and report.get('adapter_ready') is True,
                     'claude_account warnings do not fail doctor or adapter_ready', code, report.get('checks'))
            notes.append('accounts')
        finally:
            fixture.account(FIRST_PARTY)

        # Unverified: the silent session (a lease, no capsule_ready).
        code, report = self.doctor(self.profiles['quiet'])
        check = check_named(report, 'channel')
        need(check['status'] == 'error' and 'channelsEnabled' in check.get('detail', ''),
             'channel: unverified fails with the item 13 message (naming channelsEnabled)', check)
        need(report.get('adapter_ready') is False and code != 0, 'adapter_ready requires channel verified', code,
             report.get('adapter_ready'))
        need(report.get('channel') == 'unverified', 'session doctor reports channel unverified', report.get('channel'))
        # Not running: a profile never connected.
        code, report = self.doctor(self.profiles['launchy'])
        check = check_named(report, 'channel')
        need('not running' in check.get('detail', '').lower(), 'channel: not running without a lease', check)
        need(check['status'] == 'ok', 'channel: not running passes', check)
        need(report.get('channel') is None, 'session doctor reports channel null without a lease',
             report.get('channel'))
        return ', '.join(notes)

    def check_protocol(self):
        s2 = self.s2
        need(s2.negotiated, 'MCP initialize negotiated a revision', s2.initialized)
        fields = self.connection_object(self.secret(self.profiles['eager'])['adapter']['id'])
        need(fields['protocol_version'] == s2.negotiated,
             'protocol_version: the daemon stores the revision the adapter negotiated', s2.negotiated, fields)
        # A fixture adapter reporting 2026-07-28, verified so only the protocol differs.
        directory = self.profiles['oldproto']
        raw = RawAdapter(self.a, self.secret(directory), protocol=LATE_PROTOCOL)
        status, value = raw.connect()
        need(status == 200, 'a fixture adapter connects reporting protocol_version 2026-07-28', status, value)
        status, value = raw.call('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, 'the fixture adapter verifies its channel', status, value)
        fields = self.connection_object(raw.adapter['id'])
        need(fields['protocol_version'] == LATE_PROTOCOL, 'protocol_version recorded as reported', fields)
        raw.connect()
        code, report = self.doctor(directory)
        check = check_named(report, 'mcp_protocol')
        need(check['status'] == 'error', 'mcp_protocol: doctor fails at 2026-07-28 or later', check)
        need(code != 0 and report.get('adapter_ready') is False, 'doctor fails for a late MCP revision', code,
             report.get('adapter_ready'))
        need(check_named(report, 'channel')['status'] == 'ok', 'the fixture adapter\'s channel is verified', report)
        return f'negotiated {s2.negotiated}'

    def check_launch(self):
        directory = self.profiles['launchy']
        workspace = self.root / 'workspace'
        workspace.mkdir(exist_ok=True)
        result = self.a.run('session', 'start', '--directory', str(directory), '--workspace', str(workspace), '--',
                            '--name', 'live')
        need(result.returncode == 0, 'session start launches the fixture claude', result.returncode,
             result.stdout[-500:], result.stderr[-500:])
        line = [x for x in result.stdout.splitlines() if x.startswith('{')]
        need(line, 'the fixture printed its launch line', result.stdout)
        launched = json.loads(line[-1])
        need(launched.get('MCP_PROTOCOL_NEGOTIATION') == 'legacy',
             'Launch: Claude Code runs with MCP_PROTOCOL_NEGOTIATION=legacy in its environment', launched)
        need(launched['arguments'][-2:] == ['--name', 'live'] and launched['cwd'] == str(workspace),
             'the existing arguments and workspace are kept', launched)
        instructions = self.s1.initialized.get('instructions')
        need(isinstance(instructions, str) and instructions,
             'the adapter sends MCP server instructions', self.s1.initialized.keys())
        need(len(instructions) <= 2048, 'Instructions: at most 2,048 characters', len(instructions))
        tools = getattr(self, 'tools', None) or {t['name']: t for t in self.s1.call('tools/list', {})['tools']}
        concerned = [n for n in tools if n in ('delegate_task', 'artifact_save') or n.startswith(TASK_TOOLS_PREFIX)]
        need('delegate_task' in concerned and 'artifact_save' in concerned,
             'the tools that receive moved guidance exist', sorted(tools))
        need(all(tools[n].get('description') for n in concerned), 'those tools carry descriptions', concerned)
        detached = self.a.cli('session', 'detach', self.session_ids['launchy'])
        need(session_channel(detached, self.session_ids['launchy'], 'session detach') is None,
             'session detach: the session object has channel null', detached)
        return f'instructions {len(instructions)} characters'

    def check_fatal(self):
        directory = self.profiles['doomed']
        s3 = self.consumer(directory, 'doomed')
        _, hello = s3.wait_event('hello', timeout=20)
        failed, value = s3.tool('capsule_ready', {'nonce': hello['meta']['nonce']})
        need(not failed, 'capsule_ready', value)
        adapter_id = self.secret(directory)['adapter']['id']
        wait_for(lambda: self.connection(adapter_id) == 'ready', timeout=10, message='doomed ready')
        s3.signal(signal.SIGSTOP)
        try:
            wait_for(lambda: self.connection(adapter_id) == 'offline', timeout=30, message='the lease lapsing')
            session = self.a.cli('session', 'attach', '--agent', self.agent['doomed']['id'], '--integration', 'test')
            need(session_channel(session, session['id'], 'session attach') is None,
                 'session attach: a new session has channel null', session)
            fresh = self.a.cli('adapter', 'create', '--session', session['id'], '--expires-in', '2h')
            need(adapter_id in (fresh.get('replaced_adapter_ids') or []), 'a fresh attachment replaces the instance',
                 fresh)
            self.replacement = fresh
            before = len(s3.stderr_text())
            resumed = time.monotonic()
        finally:
            s3.signal(signal.SIGCONT)
        try:
            s3.process.wait(timeout=40)
        except subprocess.TimeoutExpired:
            need(False, 'Fatal stops: the replaced adapter did not exit within 40 seconds of resuming',
                          [p.get('meta') for _, p in s3.channel(resumed)], s3.stderr_text()[-800:])
        time.sleep(0.3)
        disconnected = [p for t, p in s3.channel(resumed) if (p.get('meta') or {}).get('kind') == 'disconnected']
        need(len(disconnected) == 1, 'Fatal stops: one channel event with meta.kind disconnected',
             [p.get('meta') for _, p in s3.channel(resumed)])
        content = disconnected[0].get('content') or ''
        # HARNESS for this profile: claude-code, or claude, which attach reads as claude-code (launch contract).
        need(re.search(r'capsule attach claude(-code)?\b', content),
             'the disconnected event says how to reattach (capsule attach HARNESS in the project)', content)
        need(len(s3.stderr_text()) > before, 'Fatal stops: the reason is written to stderr', s3.stderr_text()[-300:])
        need(s3.process.returncode == 1, 'Fatal stops: the adapter exits with status 1', s3.process.returncode)
        # The new attachment of this agent, whose earlier authorization was verified, starts unverified.
        raw = RawAdapter(self.a, fresh)
        status, value = raw.call('POST', '/adapter/v1/next', {})
        need(not_verified(status, value),
             'Recovery: a new authorization starts unverified', status, value)
        need(self.directory_state('doomed') == (False, 'unverified'), 'and its agent shows unverified',
             self.directory_of('doomed', refresh=False))
        return 'disconnected, stderr, exit 1; the new attachment unverified'

    def check_deadlines(self):
        """Default deadlines: 1 hour, bounded by the credential's expiry and, for routes, the route's expiry."""
        a = self.a
        notes = []
        # (credential lifetime in seconds, expected by address, [(route expiry, expected through the route)])
        cases = ((3 * 3600, 3600, [('2h', 3600), ('30m', 1800)]),
                 (1500, 1500, [('24m', 1440)]))
        for lifetime, by_address, routes in cases:
            agent = self.register(a, f'sender{lifetime}', 'alice')
            status, body = a.call('POST', '/v1/adapters/setup', {
                'agent_id': agent['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
                'expires_at': timestamp(lifetime), 'directory': True})
            need(status == 201, 'POST /v1/adapters/setup', status, body)
            raw = RawAdapter(a, body['credential'])
            rid = request_id()
            status, value = raw.call('POST', '/adapter/v1/send', {'to': 'bob/target', 'network': self.net,
                                                                  'request_id': rid, 'content': 'deadline'})
            need(status == 200, 'an adapter send by address', status, value)
            status, record = a.call('GET', f"/v1/outbound/{self.ids['b']}/{rid}")
            need(status == 200 and near(record['request']['deadline'], by_address, 30),
                 f'Deadlines: an adapter send by address gets {by_address // 60} minutes '
                 '(1 hour, bounded by the credential\'s expiry)', by_address, status, record)
            notes.append(f'to {by_address // 60}m')
            for index, (expiry, expected) in enumerate(routes):
                name = f'tobob{index}'
                a.cli('adapter', 'route', 'add', '--adapter', raw.adapter['id'], '--name', name, '--peer',
                      self.ids['b'], '--agent', self.agent['target']['id'], '--expires-in', expiry)
                rid = request_id()
                status, value = raw.call('POST', '/adapter/v1/send', {'destination': name, 'request_id': rid,
                                                                      'content': 'deadline by route'})
                need(status == 200, 'an adapter send through a route', status, value)
                status, record = a.call('GET', f"/v1/outbound/{self.ids['b']}/{rid}")
                need(status == 200 and near(record['request']['deadline'], expected, 30),
                     f'Deadlines: a route send gets the earliest of 1 hour, the route\'s expiry ({expiry}), and the '
                     f'credential\'s expiry ({lifetime // 60}m)', expected, status, record)
                notes.append(f'route {expected // 60}m')
        return ', '.join(notes)

    def check_migration(self):
        if self.baseline is None:
            raise Failure('migration needs --baseline (a capsule-host at schema 13)')
        h = DirectoryHost(self.baseline, self.baseline, self.root / 'migration', self.root / 'user-migration')
        self.hosts['migration'] = h
        h.start()
        need(user_version(h) == 13, 'the baseline host writes schema 13', user_version(h))
        agent = h.cli('agent', 'register', '--name', 'legacy', '--owner', 'me')
        session = h.cli('session', 'attach', '--agent', agent['id'], '--integration', 'test')
        secret = h.cli('adapter', 'create', '--session', session['id'], '--expires-at', timestamp(7200))
        raw = RawAdapter(h, secret, protocol=None)
        status, value = raw.connect()
        need(status == 200, 'the baseline adapter connects', status, value)
        agents = h.cli('agent', 'list')
        h.stop()
        h.binary, h.cli_binary = str(self.daemon), str(self.cli_binary)
        h.start()
        need(user_version(h) == 14, 'Shared state: the schema moves to version 14', user_version(h))
        need(h.cli('agent', 'list') == agents, 'existing state is preserved', agents)
        fields = self.connection_object(secret['adapter']['id'], host=h)
        need(fields['channel_verified_at'] is None, 'Existing authorizations migrate as unverified', fields)
        raw.protocol = CLIENT_PROTOCOL
        status, value = raw.connect()
        need(status == 200, 'the original instance recovers after the upgrade', status, value)
        fields = self.connection_object(secret['adapter']['id'], host=h)
        need(fields['channel'] == 'unverified' and fields['protocol_version'] == CLIENT_PROTOCOL,
             'the recovered migrated authorization: channel unverified, protocol_version recorded', fields)
        status, value = raw.request('POST', '/adapter/v1/next', {})
        need(not_verified(status, value),
             'a migrated authorization is unverified: work routes answer 409', status, value)
        status, value = raw.call('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, 'and can then be verified', status, value)
        status, value = raw.call('POST', '/adapter/v1/next', {})
        need(status == 200, 'work routes answer after verification', status, value)
        h.stop()
        return '13 to 14'

    def check_resend(self):
        need(getattr(self, 's1_hello', None), 'needs the hello section')
        remaining = self.s1_hello + ITEM13 + 15 - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        hellos = self.s1.hellos()
        need(len(hellos) == 2, 'Re-sending hello: exactly once more, then never again',
             [round(t - self.s1_hello, 1) for t, _ in hellos])
        gap = hellos[1][0] - hellos[0][0]
        # Q: "within 60 seconds" gives no tolerance; the suite allows 58 to 70 seconds.
        need(58 <= gap <= 70, 'Re-sending hello: after 60 seconds without capsule_ready', round(gap, 1))
        need(hellos[1][1].get('meta', {}).get('nonce') == self.s1_nonce, 'the re-sent hello has the same nonce',
             hellos[1][1].get('meta'))
        need(self.s1.kinds() == ['hello', 'hello'], 'nothing else arrives while unverified', self.s1.kinds())
        need(self.s1.process.poll() is None, 'the adapter keeps waiting', self.s1.process.returncode)
        state = self.connection_object(self.secret(self.profiles['quiet'])['adapter']['id'])
        need(state.get('state') == 'ready', 'the adapter keeps its lease', state, self.s1.stderr_text()[-500:])
        return f'second hello after {gap:.1f}s'

    def check_item13(self):
        need(getattr(self, 's1_hello', None), 'needs the hello section')
        remaining = self.s1_hello + ITEM13 + 15 - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        samples = list(self.watcher.samples)

        def quiet_items(items):
            return [i for i in items if i.get('subject') == 'quiet']
        early = [t - self.s1_hello for t, items in samples if t - self.s1_hello < ITEM13 - 5 and quiet_items(items)]
        need(not early, 'Status item 13: not added before 120 seconds of unverified lease',
             [round(x, 1) for x in early])
        need(any(t - self.s1_hello < ITEM13 - 5 for t, _ in samples), 'the watcher sampled status before 120 seconds',
             len(samples))
        status, body = self.a.call('GET', '/v1/status')
        need(status == 200, 'GET /v1/status', status)
        items = quiet_items([i for i in body['attention'] if i.get('kind') == 'channel_unverified'])
        need(len(items) == 1, 'Status item 13: channel_unverified for the authorization unverified over 120 seconds',
             [(i['kind'], i['subject']) for i in body['attention']],
             'sampled (seconds after hello, item present; most recent first): '
             + ' '.join(f'{t - self.s1_hello:.0f}:{int(bool(quiet_items(x)))}' for t, x in reversed(samples)),
             self.connection_object(self.secret(self.profiles['quiet'])['adapter']['id']))
        item = items[0]
        need(item['command'] == 'capsule session doctor', 'item 13 command: capsule session doctor', item)
        detail = item.get('detail', '')
        need('channelsEnabled' in detail, 'item 13 message names channelsEnabled', detail)
        # Q: the other three causes have no fixed wording; the suite looks for their key words.
        for word in ('provider', 'version', 'flag'):
            need(word in detail.lower(), f'item 13 message names the likely causes ({word})', detail)
        need(not [i for i in body['attention'] if i.get('kind') == 'channel_unverified'
                  and i.get('subject') in ('eager', 'rawq', 'oldproto')], 'verified authorizations get no item 13',
             body['attention'])
        kinds = [i['kind'] for i in body['attention']]
        if 'agent_name_conflict' in kinds:
            need(kinds.index('agent_name_conflict') < kinds.index('channel_unverified'), 'item 13 follows item 12',
                 kinds)
        result = self.a.run('status', '--json')
        need(result.returncode == 1 and 'channel_unverified' in result.stdout, 'status shows item 13 and exits 1',
             result.returncode)
        code, report = self.doctor(self.profiles['quiet'])
        need(detail in check_named(report, 'channel').get('detail', ''),
             'doctor\'s channel check fails with the item 13 message', check_named(report, 'channel'), detail)
        # Now the model calls capsule_ready: the held message arrives and the item goes.
        marked = time.monotonic()
        failed, value = self.s1.tool('capsule_ready', {'nonce': self.s1_nonce})
        need(not failed and value == {'ready': True}, 'capsule_ready after the re-send', failed, value)
        self.s1.wait_event('message', since=marked, timeout=20, where=lambda p: self.queued_quiet in json.dumps(p))
        status, body = self.a.call('GET', '/v1/status')
        need(not quiet_items([i for i in body['attention'] if i.get('kind') == 'channel_unverified']),
             'item 13 goes once verified', body['attention'])
        need(self.directory_state('quiet') == (True, 'verified'), 'the agent is connected once verified')
        first = min((t for t, items in samples if quiet_items(items)), default=None)
        return f'item first sampled {first - self.s1_hello:.0f}s after hello' if first else 'item present'

    def check_restart(self):
        a = self.a
        if self.watcher:
            self.watcher.stop()
        eager_id = self.secret(self.profiles['eager'])['adapter']['id']
        need(self.directory_state('eager') == (True, 'verified'), 'eager verified before the restart')
        a.stop()
        a.start()
        wait_for(lambda: self.connection(eager_id) == 'ready', timeout=30, message='the adapter recovering')
        marked = time.monotonic()
        rid = self.send_from_bob('eager', 'after restart')
        self.s2.wait_event('message', since=marked, timeout=30, where=lambda p: rid in json.dumps(p))
        failed_ready = [p for _, p in self.s2.channel(marked) if p.get('meta', {}).get('kind') == 'disconnected']
        need(not failed_ready, 'the recovering adapter keeps running', failed_ready)
        need(self.directory_state('eager') == (True, 'verified'),
             'Recovery: verification belongs to the authorization and survives a daemon restart')
        need(getattr(self, 'raw_rawq', None), 'needs the work routes section\'s adapter')
        status, value = self.raw_rawq.call('POST', '/adapter/v1/next', {})
        need(status == 200, 'a verified raw authorization claims work after the restart without ready', status, value)
        sessions = self.sessions_of(self.agent['eager'])
        need((sessions.get(self.session_ids['eager']) or {}).get('channel') == 'verified',
             'session list still reports channel verified after the restart', sessions)
        return 'verified across restart'

    # --- the pairing ---------------------------------------------------------------------------------------

    def run(self):
        self.coord_key = self.coord.start()['public_key']
        self.a, self.b = self.host('a'), self.host('b')
        self.ids = {'a': self.a.start()['id'], 'b': self.b.start()['id']}
        created = self.a.cli('network', 'create', 'team', '--as', 'alice', '--coordinator', self.coord.address,
                             '--coordinator-key', self.coord_key)
        self.net = created['id']
        token = self.a.cli('invite', 'bob', '--network', self.net)['token']
        self.b.cli('join', token)
        for h in (self.a, self.b):
            wait_for(lambda h=h: len(h.cli('network', 'members', self.net)) == 2, timeout=40,
                     message='both members known')
        self.agent = {n: self.register(self.a, n, 'alice')
                      for n in ('quiet', 'eager', 'rawq', 'idle', 'launchy', 'oldproto', 'doomed')}
        self.agent['target'] = self.register(self.b, 'target', 'bob')
        self.a.cli('allow', 'bob', '--network', self.net)
        self.b.cli('allow', 'alice', '--network', self.net)
        wait_for(lambda: self.b.call('POST', f'/v1/directory/refresh?network={self.net}', {})[0] == 200
                 and any(x.get('address') == 'alice/quiet' for x in self.b.directory(self.net)[1].get('agents', [])),
                 timeout=40, message='alice\'s agents in bob\'s directory')
        wait_for(lambda: self.a.call('POST', f'/v1/directory/refresh?network={self.net}', {})[0] == 200
                 and any(x.get('address') == 'bob/target' for x in self.a.directory(self.net)[1].get('agents', [])),
                 timeout=40, message='bob\'s agent in alice\'s directory')

        self.fixtures, self.profiles, self.session_ids = {}, {}, {}
        for name in ('quiet', 'eager', 'launchy', 'oldproto', 'doomed'):
            self.fixtures[name] = Fixture(self.root / 'fixtures' / name)
            self.profiles[name], out = self.profile(name, self.agent[name], self.fixtures[name])
            self.session_ids[name] = out['session_id']

        # Work waiting before the sessions start.
        self.queued_quiet = self.send_from_bob('quiet', 'held for quiet')
        self.queued_eager = self.send_from_bob('eager', 'held for eager')
        self.queued_eager_task = self.task_from_bob('eager', 'task held for eager')

        # The silent session's timers start now and run while the other sections do.
        self.watcher = StatusWatcher(self.a)
        self.s1 = self.consumer(self.profiles['quiet'], 'quiet')
        self.s2 = self.consumer(self.profiles['eager'], 'eager')

        self.section('hello event', self.check_hello)
        self.section('work routes before verification', self.check_routes)
        self.section('wrong nonce and capsule_ready', self.check_capsule_ready)
        self.section('connected', self.check_connected)
        self.section('doctor', self.check_doctor)
        self.section('protocol', self.check_protocol)
        self.section('launch', self.check_launch)
        self.section('fatal stop', self.check_fatal)
        self.section('deadlines', self.check_deadlines)
        self.section('migration', self.check_migration)
        self.section('hello re-sent once', self.check_resend)
        self.section('item 13', self.check_item13)
        self.section('daemon restart', self.check_restart)

    def save_logs(self, directory):
        target = directory / re.sub(r'[^A-Za-z0-9]+', '-', self.label)
        target.mkdir(parents=True, exist_ok=True)
        for name, h in [*self.hosts.items(), ('coord', self.coord)]:
            try:
                h.logs.seek(0)
                (target / f'{name}.log').write_bytes(h.logs.read())
            except (OSError, ValueError):
                pass
        for index, c in enumerate(self.consumers):
            try:
                shutil.copy2(c.stderr_path, target / f'adapter-{index}.stderr')
            except OSError:
                pass

    def close(self):
        try:
            if self.watcher:
                self.watcher.stop()
            for c in self.consumers:
                try:
                    c.close()
                except Exception:
                    pass
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()


def run_pairing(coord_binary, cli_binary, daemon_binary, node, baseline, label, logs=None):
    with tempfile.TemporaryDirectory(prefix='capsule-live-delivery-') as temporary:
        pairing = Pairing(label, cli_binary, daemon_binary, coord_binary, node, baseline, Path(temporary))
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [setup]: {detail}', flush=True)
        finally:
            if logs and not all(ok for _, ok, _ in pairing.results):
                pairing.save_logs(logs)
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
    parser.add_argument('--node', type=Path, required=True, help='Node 22 or newer, for the MCP adapter')
    parser.add_argument('--baseline', type=Path,
                        help='a capsule-host from before milestone 9 (schema 13), for the migration section')
    parser.add_argument('--pairing', action='append', help='CLI/DAEMON, such as Go/Rust; repeatable; default all four')
    parser.add_argument('--parallel', action='store_true', help='run the pairings at the same time')
    parser.add_argument('--logs', type=Path, help='save daemon, coordinator, and adapter logs of failing pairings here')
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
    baseline = args.baseline.resolve() if args.baseline else None
    outcomes = {}

    def one(pairing):
        cli, _, daemon = pairing.partition('/')
        label = f'{cli} CLI, {daemon} daemon'
        outcomes[label] = run_pairing(args.coord.resolve(), binaries[cli], binaries[daemon], args.node.resolve(),
                                      baseline, label, args.logs)
    if args.parallel:
        threads = [threading.Thread(target=one, args=(p,)) for p in pairings]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    else:
        for p in pairings:
            one(p)
    failures = [f'{label} [{name}]: {detail.strip().splitlines()[-1] if detail.strip() else ""}'
                for label, results in outcomes.items() for name, ok, detail in results if not ok]
    print('==== summary', flush=True)
    for line in failures:
        print('FAIL ' + line[:1200], flush=True)
    if failures:
        raise SystemExit(f'{len(failures)} section(s) failed')
    print('PASS all sections', flush=True)


if __name__ == '__main__':
    main()
