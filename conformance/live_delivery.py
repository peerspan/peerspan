#!/usr/bin/env python3
"""Exercise live-session delivery (milestone 9, slices 1 and 2) across CLI/daemon pairings.

Written from docs/live-delivery-contract.md ("Slice 1: readiness and diagnostics", "Slice 2: seen,
redelivery, adoption, and pending work", and their Verification lists), with context from the live delivery proposal and the contracts it extends
(agent adapter, outbound, recovery, task, harness integration, launch), independently of the Go and
Rust hosts and of the Node adapter, which runs here only as a black box.

Each pairing runs two hosts, alice's (A) and bob's (B), in one coordinator-free network built by
conformance/dec_network.py (A creates it; bob joins with his own original key), both running the
pairing's daemon and driven by its CLI. Every host has its own HOME and XDG_CONFIG_HOME, where each
person's fixture key is the configured owner key, so nothing touches the real ~/.config/peerspan. Sessions are prepared with the
Claude integration (`session setup --harness claude-code`) against a fixture `claude` executable
that reports a chosen `--version` and `auth status` JSON and, when launched, prints its arguments,
cwd, and MCP_PROTOCOL_NEGOTIATION. No model runs: the MCP consumer here is deterministic. It starts
the adapter exactly as the profile's mcp.json describes, initializes MCP, records every channel
event with its arrival time, and calls `peerspan_ready` only when a check says so. Raw adapter
clients (bearer token and instance, as the recovery contract allows) cover the routes directly.

The 60-second hello re-send and the 120-second status item 13 need real time. A silent session is
started first, and its timers run while the other sections do; a status watcher samples
`GET /v1/status` in the background. Sections, per pairing:

- hello event: the first channel event is `hello` with a fresh 128-bit hex nonce, its content
  naming `peerspan_ready` and the nonce; nothing else (no queued message) follows; the tool list has
  `peerspan_ready` taking `{nonce}`;
- work routes before verification: the five work routes answer 409 `{code: "conflict", error:
  "channel not verified"}` and claim nothing, the connection object shows `channel`,
  `channel_verified_at` (keeping the first time), and `protocol_version`, while outbound and `GET /adapter/v1/session` work;
  `POST /adapter/v1/ready` needs the credential and a lease, and is idempotent; afterwards the
  queued message and task are claimed;
- wrong nonce and peerspan_ready: a wrong nonce is a tool error and changes nothing; the right one
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
- protocol: the negotiated revision recorded as `protocol_version`; doctor failing `mcp_protocol` for a
  fixture adapter of a `claude-code` session reporting `2026-07-28`, and passing (naming the value) for a
  fixture adapter of another harness (the Python/file fixture integration) reporting it; a missing value
  not failing; a fixture adapter that connects without `protocol_version` and later learns one having it
  stored before `POST /adapter/v1/ready`, and keeping it across a later connect without the field;
- launch: `session start` launching Claude with `MCP_PROTOCOL_NEGOTIATION=legacy`, and the MCP
  instructions at most 2,048 characters;
- fatal stop: a replaced instance emits one `disconnected` event naming `peerspan attach claude`
  (or `claude-code`), writes a reason to stderr, and exits 1; the replacement starts unverified;
- deadlines: adapter sends by address and through routes default to 1 hour, bounded by the
  credential's expiry and, for routes, the route's expiry;
- migration: a schema 13 state (made by a pre-milestone-9 host, `--baseline`) opening at 14 with
  its authorization unverified;
- hello re-sent once: exactly one more hello, with the same nonce, about 60 seconds after the first,
  and none after; the lease kept;
- item 13: `channel_unverified` absent before 120 seconds of unverified lease and present after,
  with subject, command, and message; `status` exiting 1; doctor's channel check carrying the
  message; then `peerspan_ready` clears it and delivers the held message;
- daemon restart: a verified authorization stays verified across a restart of its daemon (work
  flows without another `peerspan_ready`). (A new attachment of a previously verified agent
  starting unverified is checked in the fatal stop section, on the replacement attachment.)

Slice 2 sections run after slice 1's migration section, while the silent session's timers run. MCP
consumers there use `attach claude --no-start` profiles (directory sessions, so `send` and
`delegate_task` work by address); a session is replaced by closing its consumer and attaching the
same project again. Raw adapters end authorizations by revocation. bob's `target` agent answers
alice's sends and accepts her delegations through a raw adapter. The version 15 columns are read
from host.db, since the contract lists them as shared state.

- seen: `reply`, `mark_seen` (delivery, request, and task IDs; repeats ignored; 0, 101, and
  unknown IDs refused), `send_status`, `task_accept`, `task_reject`, `task_progress` after a
  forwarded cancellation request, and `task_status` after a forwarded update, observed in
  `pending_work` and in `seen_at`, `cancel_seen_at`, and `reply_seen_at`; owner delivery records
  without the new fields;
- redelivery after replacement: an unseen message, reply, and offered task reach the next
  attachment with `redelivered` true, keeping their IDs and rows; a late reply arrives with
  `redelivered` false; seen and rejected items are not redelivered; `pending_work` on the new
  session; `redeliveries`, `returned_at`, `adopted_at`; the sender's record unchanged and one
  reply and one set of task events reaching the sender;
- adoption: running and cancel-requested tasks adopted with `adopted`, `state`, and `progress`
  (omitted when none), the old authorization and another agent refused, the adopting session
  finishing them; raw task handoffs with `adopted`, `progress`, and `redelivered`, and a later
  cancellation request reaching the adopting session;
- delegation chain after replacement: a third host (carol); bob -> alice/mid -> carol/end, with
  alice's middle session replaced while carol works; the child's later update reaches the adopting
  session and the chain completes;
- pending work: `pending_work`'s exact fields and order, previews of 200 characters, the
  administration route, `session pending --json` and its lines, `--hook` output (the lead sentence
  and compact pending_work JSON, nothing when no work is pending), nothing and exit 0 without an
  attachment, and the raw `GET /adapter/v1/pending` and `POST /adapter/v1/seen`;
- launch settings: `--settings` naming `claude-settings.json` in the profile, mode 0600, its exact
  content with matcher `clear|compact|resume` and the single-quoted absolute CLI path (also one
  containing a quote), the hook command's output, no global or project settings, and `--settings`
  refused among the user's arguments;
- limits: a message blocked and a task failed (`session never saw the task`) after 3
  redeliveries, a reply no longer offered after 3, deadlines passing while queued, and revocation
  (`deny`) blocking a returned message;
- migration to 15: a schema 14 host (`--baseline14`, milestone 9 slice 1) with handed-off items,
  upgraded: the columns added, existing items marked seen and not redelivered.

Ambiguities are listed in the suite questions file and marked "Q:" below; checks take the most
literal reading. Needs Python 3, peerspan-peer-probe, Node, and OpenSSH (ssh-keygen). The migration to 15
section is not portable (a schema 14 host cannot join a coordinator-free network) and fails with that reason.
`--slice1-only` skips the slice 2 sections.
Exits non-zero listing every failed section.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from support import wait_for
from dec_network import DecNetwork
from host_service import SCHEMA_VERSION, UnixHTTPConnection, stop_all
from launch_directory import DirectoryHost
from launch_onboarding import Failure, near, need, parse_time
from peer_messaging import request_id, set_probe, timestamp
from tasks import task_id
from harness_setup import catalog as fixture_catalog

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
LEARNED_PROTOCOL = '2025-06-18'
OTHER_HARNESS = 'file-fixture'
NONCE = re.compile(r'[0-9a-fA-F]{32}')
TASK_TOOLS_PREFIX = 'task_'
# Slice 2.
LIMIT = 3
PREVIEW = 200
NEVER_SAW = 'session never saw the task'
SETTINGS_FILE = 'claude-settings.json'
MATCHER = 'clear|compact|resume'
# `session pending --hook`: additionalContext is this lead followed by the object as compact JSON.
HOOK_LEAD = ('Peerspan work this session still owes, listed after /clear, compaction, or resume. Finish each task '
             'with the task_* tools and answer each delivery with reply; call pending_work for the current list. ')
# Database version 18 (capabilities contract, Agent tools: Pending work) adds `calls` to pending work and replaces
# the hook's lead sentence; hosts at version 18 or later are held to that.
CALLS_VERSION = 18
HOOK_LEAD_CALLS = ('Peerspan work this session still owes, listed after /clear, compaction, or resume. Finish each '
                   'task with the task_* tools, answer each delivery with reply, and check each call with call_status; '
                   'call pending_work for the current list. ')
DELIVERY_KEYS = {'delivery_id', 'request_id', 'sender_host_id', 'origin_agent_id', 'preview', 'seen', 'deadline',
                 'redelivered'}
REPLY_KEYS = {'notification_id', 'request_id', 'peer_host_id', 'preview'}
TASK_KEYS = {'task_id', 'delivery_id', 'sender_host_id', 'state', 'preview', 'deadline', 'adopted'}
SEEN_COLUMNS = {'seen_at', 'redeliveries', 'returned_at'}
MIGRATED_COLUMNS = {'deliveries': SEEN_COLUMNS, 'task_update_notifications': SEEN_COLUMNS,
                    'task_deliveries': SEEN_COLUMNS | {'cancel_seen_at', 'adopted_at'},
                    'adapter_outbound': {'reply_seen_at', 'reply_redeliveries', 'reply_returned_at'}}

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
            'clientInfo': {'name': 'peerspan-live-delivery-conformance', 'version': '1'}})
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
                       'X-Peerspan-Instance': instance or self.instance}
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


def flag(meta, key):
    """A boolean in channel meta: Claude Code meta values are strings, so true and false arrive as JSON text.
    True, False, or None (absent or anything else)."""
    value = meta.get(key)
    if value in (True, 'true'):
        return True
    if value in (False, 'false'):
        return False
    return None


def same_time(a, b):
    if a is None or b is None:
        return a is None and b is None
    return parse_time(a) == parse_time(b)


def shell_quoted(path):
    return "'" + path.replace("'", "'\\''") + "'"


def expected_settings(peerspan):
    """The --settings file's content (Pending work)."""
    return {'hooks': {'SessionStart': [{'matcher': MATCHER, 'hooks': [
        {'type': 'command', 'command': f'{shell_quoted(peerspan)} session pending --hook'}]}]}}


def hook_output(stdout, pending, lead=None):
    """`session pending --hook` output for a nonempty pending object: the SessionStart hookSpecificOutput whose
    additionalContext is HOOK_LEAD followed by the object as compact JSON (compared parsed). Returns a failure
    description, or None."""
    try:
        value = json.loads(stdout)
    except ValueError:
        return 'stdout is not one JSON object'
    if not (isinstance(value, dict) and set(value) == {'hookSpecificOutput'}
            and isinstance(value['hookSpecificOutput'], dict)
            and set(value['hookSpecificOutput']) == {'hookEventName', 'additionalContext'}
            and value['hookSpecificOutput']['hookEventName'] == 'SessionStart'
            and isinstance(value['hookSpecificOutput']['additionalContext'], str)):
        return 'not {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": TEXT}}'
    text = value['hookSpecificOutput']['additionalContext']
    lead = lead or (HOOK_LEAD_CALLS if 'calls' in pending else HOOK_LEAD)
    if not text.startswith(lead):
        return 'additionalContext does not start with the lead sentence'
    rest = text[len(lead):]
    if '\n' in rest or rest != rest.strip():
        return 'the object after the lead is not compact JSON'
    try:
        if json.loads(rest) != pending:
            return 'the object after the lead differs from pending_work'
    except ValueError:
        return 'the text after the lead is not a JSON object'
    return None


def rows(host, query, args=()):
    """Rows of the host's database as dicts (the version 15 columns are shared state)."""
    connection = sqlite3.connect(host.state / 'host.db', timeout=10)
    try:
        connection.row_factory = sqlite3.Row
        return [dict(r) for r in connection.execute(query, args)]
    finally:
        connection.close()


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
    def __init__(self, label, cli_binary, daemon_binary, node, baseline, root, baseline14=None, slices=(1, 2)):
        self.label, self.cli_binary, self.daemon, self.node, self.root = label, cli_binary, daemon_binary, node, root
        self.baseline = baseline
        self.baseline14 = baseline14
        self.slices = slices
        # Coordinator-free network (decentralized-spec.md 6 and 8; conformance/dec_network.py).
        self.dec = DecNetwork(root / 'dec')
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
        need('peerspan_ready' in content and nonce in content,
             'Hello event: its content asks the model to call peerspan_ready with that nonce', content)
        self.s1_nonce, self.s1_hello = nonce, self.s1.hellos()[0][0]
        # The message bob queued before this session started stays unclaimed.
        time.sleep(3)
        need(s1.kinds() == ['hello'], 'Before peerspan_ready, no work is forwarded (only the hello event)',
             s1.kinds())
        need(not self.deliveries_mention(self.queued_quiet), 'Before peerspan_ready, the adapter claims no work',
             self.queued_quiet)
        tools = {t['name']: t for t in s1.call('tools/list', {})['tools']}
        ready = tools.get('peerspan_ready')
        need(ready and 'nonce' in (ready.get('inputSchema') or {}).get('properties', {}),
             'peerspan_ready takes {nonce}', ready)
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

    def check_peerspan_ready(self):
        s2 = self.s2
        _, hello = s2.wait_event('hello', timeout=20)
        nonce = hello['meta']['nonce']
        need(nonce != getattr(self, 's1_nonce', None), 'each adapter\'s nonce is fresh', nonce)
        self.observed['eager_before'] = self.directory_state('eager')
        wrong = secrets.token_hex(16)
        failed, value = s2.tool('peerspan_ready', {'nonce': wrong})
        need(failed, 'peerspan_ready: a wrong nonce returns a tool error', value)
        time.sleep(2)
        need(s2.kinds() == ['hello'], 'A wrong nonce changes nothing: no work arrives', s2.kinds())
        self.observed['eager_wrong'] = self.directory_state('eager')
        need(not self.deliveries_mention(self.queued_eager), 'A wrong nonce changes nothing: nothing claimed')
        marked = time.monotonic()
        failed, value = s2.tool('peerspan_ready', {'nonce': nonce})
        need(not failed and value == {'ready': True}, 'peerspan_ready with the matching nonce returns {ready: true}',
             failed, value)
        _, message = s2.wait_event('message', since=marked, timeout=20,
                                   where=lambda p: p['meta'].get('request_id') == self.queued_eager
                                   or self.queued_eager in json.dumps(p))
        _, task = s2.wait_event('task', since=marked, timeout=20, where=lambda p: self.queued_eager_task in json.dumps(p))
        rid = self.send_from_bob('eager', 'after ready')
        s2.wait_event('message', since=marked, timeout=20, where=lambda p: rid in json.dumps(p))
        failed, value = s2.tool('peerspan_ready', {'nonce': nonce})
        need(not failed and value == {'ready': True}, 'A repeated peerspan_ready after readiness returns {ready: true}',
             failed, value)
        self.observed['eager_after'] = self.directory_state('eager')
        self.s2_nonce = nonce
        return 'held message and task delivered after peerspan_ready'

    def check_connected(self):
        need('eager_after' in self.observed, 'needs the peerspan_ready section')
        need(self.observed['eager_before'] == (False, 'unverified'),
             'Directory: a lease without verification is connected false, channel unverified',
             self.observed['eager_before'])
        need(self.observed['eager_wrong'] == (False, 'unverified'), 'Directory: still unverified after a wrong nonce',
             self.observed['eager_wrong'])
        need(self.observed['eager_after'] == (True, 'verified'),
             'Directory: after peerspan_ready, connected true and channel verified', self.observed['eager_after'])
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

        # Unverified: the silent session (a lease, no peerspan_ready).
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
        # Doctor's 2026-07-28 failure applies to the claude-code harness only: a fixture adapter of another
        # harness (the Python/file fixture integration) reporting it passes, and doctor names the value.
        directory = self.profiles['otherproto']
        raw = RawAdapter(self.a, self.secret(directory), protocol=LATE_PROTOCOL)
        status, value = raw.connect()
        need(status == 200, f'a {OTHER_HARNESS} fixture adapter connects reporting protocol_version 2026-07-28',
             status, value)
        status, value = raw.request('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, f'the {OTHER_HARNESS} fixture adapter verifies its channel', status, value)
        fields = self.connection_object(raw.adapter['id'])
        need(fields['protocol_version'] == LATE_PROTOCOL, f'protocol_version recorded for the {OTHER_HARNESS} adapter',
             fields)
        raw.connect()
        code, report = self.doctor(directory)
        need(report.get('harness') == OTHER_HARNESS, 'doctor reports the other harness', report.get('harness'))
        check = check_named(report, 'mcp_protocol')
        need(check['status'] == 'ok', 'mcp_protocol: for a harness other than claude-code, 2026-07-28 passes', check)
        need(LATE_PROTOCOL in check.get('detail', ''), 'mcp_protocol: doctor\'s detail names the stored value', check)
        need(code == 0 and report.get('adapter_ready') is True,
             f'doctor passes for a {OTHER_HARNESS} adapter reporting 2026-07-28', code, report.get('checks'))

        # A missing value is not a failure (a claude-code session whose adapter never reported one).
        directory = self.profiles['noproto']
        raw = RawAdapter(self.a, self.secret(directory), protocol=None)
        status, value = raw.connect()
        need(status == 200, 'a fixture adapter connects without protocol_version', status, value)
        status, value = raw.request('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, 'the fixture adapter without protocol_version verifies its channel', status, value)
        fields = self.connection_object(raw.adapter['id'])
        need(fields['protocol_version'] is None, 'protocol_version null when none was reported', fields)
        raw.connect()
        code, report = self.doctor(directory)
        check = check_named(report, 'mcp_protocol')
        need(check['status'] == 'ok', 'mcp_protocol: a missing value is not a failure', check)
        need(code == 0 and report.get('adapter_ready') is True, 'doctor passes when no protocol_version was reported',
             code, report.get('checks'))

        # A fixture adapter that connects without protocol_version and later learns one (as the Codex sidecar does
        # from the first tool call) connects again with it, so it is stored before POST /adapter/v1/ready; a later
        # connect without the field leaves it unchanged.
        directory = self.profiles['learner']
        raw = RawAdapter(self.a, self.secret(directory), protocol=None)
        status, value = raw.connect()
        need(status == 200, 'the learning fixture adapter connects without protocol_version', status, value)
        fields = self.connection_object(raw.adapter['id'])
        need(fields['protocol_version'] is None, 'protocol_version null before the adapter learns one', fields)
        raw.protocol = LEARNED_PROTOCOL
        status, value = raw.connect()
        need(status == 200, 'the fixture adapter connects again with the protocol_version it learned', status, value)
        fields = self.connection_object(raw.adapter['id'])
        need(fields['protocol_version'] == LEARNED_PROTOCOL and fields['channel'] == 'unverified',
             'the learned protocol_version is stored before POST /adapter/v1/ready', fields)
        status, value = raw.request('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, 'the learning fixture adapter verifies its channel', status, value)
        raw.protocol = None
        status, value = raw.connect()
        need(status == 200, 'the fixture adapter connects again without protocol_version', status, value)
        fields = self.connection_object(raw.adapter['id'])
        need(fields['protocol_version'] == LEARNED_PROTOCOL and fields['channel'] == 'verified',
             'a connect without protocol_version leaves the stored value unchanged', fields)
        code, report = self.doctor(directory)
        check = check_named(report, 'mcp_protocol')
        need(check['status'] == 'ok' and LEARNED_PROTOCOL in check.get('detail', ''),
             'mcp_protocol passes and names the stored value', check)
        return f'negotiated {s2.negotiated}; {OTHER_HARNESS} passes at {LATE_PROTOCOL}; learned {LEARNED_PROTOCOL} kept'

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
        failed, value = s3.tool('peerspan_ready', {'nonce': hello['meta']['nonce']})
        need(not failed, 'peerspan_ready', value)
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
        need(re.search(r'peerspan attach claude(-code)?\b', content),
             'the disconnected event says how to reattach (peerspan attach HARNESS in the project)', content)
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
            raise Failure('migration needs --baseline (a peerspan-host at schema 13)')
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
        # A slice 2 host continues to version 15 (checked in the migration to 15 section).
        need(user_version(h) >= 14, 'Shared state: the schema moves to version 14', user_version(h))
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
        need(58 <= gap <= 70, 'Re-sending hello: after 60 seconds without peerspan_ready', round(gap, 1))
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
        need(item['command'] == 'peerspan session doctor', 'item 13 command: peerspan session doctor', item)
        detail = item.get('detail', '')
        need('channelsEnabled' in detail, 'item 13 message names channelsEnabled', detail)
        # Q: the other three causes have no fixed wording; the suite looks for their key words.
        for word in ('provider', 'version', 'flag'):
            need(word in detail.lower(), f'item 13 message names the likely causes ({word})', detail)
        need(not [i for i in body['attention'] if i.get('kind') == 'channel_unverified'
                  and i.get('subject') in ('eager', 'rawq', 'oldproto', 'noproto', 'learner', 'otherproto')], 'verified authorizations get no item 13',
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
        # Now the model calls peerspan_ready: the held message arrives and the item goes.
        marked = time.monotonic()
        failed, value = self.s1.tool('peerspan_ready', {'nonce': self.s1_nonce})
        need(not failed and value == {'ready': True}, 'peerspan_ready after the re-send', failed, value)
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

    # --- slice 2: helpers --------------------------------------------------------------------------------

    def slice2_fixture(self):
        if not getattr(self, '_slice2_fixture', None):
            self._slice2_fixture = Fixture(self.root / 'fixtures' / 'slice2')
        return self._slice2_fixture

    def attach_profile(self, workspace, name=None):
        """`attach claude --no-start` in workspace: a directory session (it may send and delegate by address) whose
        profile records the workspace. Run again for the same workspace once the adapter has exited, it sets up a new
        authorization for the same agent, replacing the old one (launch contract, Re-attaching)."""
        workspace.mkdir(parents=True, exist_ok=True)
        args = ['attach', 'claude', '--directory', str(workspace), '--integrations', str(INTEGRATIONS),
                '--runner', str(self.node), '--option', f'executable={self.slice2_fixture().path}',
                '--expires-in', '2h', '--no-start']
        if name:
            args[2:2] = ['--name', name]
        result = self.a.run(*args, cwd=str(self.root), timeout=90)
        need(result.returncode == 0, 'attach claude --no-start', args, result.stdout[-500:], result.stderr[-500:])
        out = json.loads(result.stdout)
        need((Path(out['profile']) / 'mcp.json').exists(), 'attach writes an MCP profile', out)
        return out

    def verified(self, profile, name):
        """A consumer on profile that answers the hello event with peerspan_ready."""
        c = self.consumer(Path(profile), name)
        _, hello = c.wait_event('hello', timeout=20)
        failed, value = c.tool('peerspan_ready', {'nonce': hello['meta']['nonce']})
        need(not failed and value == {'ready': True}, 'peerspan_ready', failed, value)
        return c

    def raw_for(self, host, agent, directory=False):
        """A raw adapter on a new session of agent, connected and verified."""
        status, body = host.call('POST', '/v1/adapters/setup', {
            'agent_id': agent['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
            'expires_at': timestamp(7200), 'directory': directory})
        need(status == 201, 'POST /v1/adapters/setup', agent.get('name'), status, body)
        raw = RawAdapter(host, body['credential'])
        status, value = raw.call('POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(200 <= status < 300, 'POST /adapter/v1/ready', status, value)
        return raw

    def end(self, raw, host=None):
        """End an authorization by revoking it (one of the three ways the Redelivery section names)."""
        (host or self.a).cli('adapter', 'revoke', raw.adapter['id'])

    @staticmethod
    def claim(raw, path, match, timeout=30):
        """Poll a claim route until a handoff matching match arrives; the handoff, or None at the timeout."""
        # Claiming consumes: a handoff that does not match is kept on the raw adapter for later claims.
        kept = raw.__dict__.setdefault('kept', {}).setdefault(path, [])
        for index, value in enumerate(kept):
            if match(value):
                return kept.pop(index)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, value = raw.call('POST', path, {})
            need(status == 200, f'{path} answers 200', status, value)
            if value and match(value):
                return value
            if value:
                kept.append(value)
            else:
                time.sleep(0.3)
        return None

    def claims_nothing(self, raw, path, match, rule, seconds=5):
        found = self.claim(raw, path, match, timeout=seconds)
        need(found is None, rule, found)

    def bob_target(self):
        """bob's raw target adapter, verified: it answers alice's sends and accepts her delegations."""
        if not getattr(self, '_bob_target', None):
            self._bob_target = self.raw_for(self.b, self.agent['target'])
            self._bob_tasks = set()
        return self._bob_target

    def bob_answer(self, rid, content):
        raw = self.bob_target()
        handoff = self.claim(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid, timeout=40)
        need(handoff, 'bob\'s target receives alice\'s send', rid)
        status, value = raw.call('POST', f"/adapter/v1/deliveries/{handoff['delivery']['id']}/reply",
                                 {'content': content})
        need(status == 200, 'bob replies', status, value)

    def bob_accept(self, tid):
        raw = self.bob_target()
        handoff = self.claim(raw, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == tid, timeout=40)
        need(handoff, 'bob\'s target receives alice\'s delegation', tid)
        status, value = raw.call('POST', f'/adapter/v1/tasks/{tid}/accept', {})
        need(status == 200, 'bob accepts the delegation', status, value)

    def bob_task(self, tid):
        status, record = self.b.call('GET', f"/v1/tasks/{self.ids['a']}/{tid}")
        need(status == 200, 'bob\'s task record', tid, status, record)
        return record

    def bob_events(self, tid):
        status, events = self.b.call('GET', f"/v1/tasks/{self.ids['a']}/{tid}/events")
        need(status == 200 and isinstance(events, list), 'bob\'s task events', status, events)
        return events

    def bob_state(self, tid, state, timeout=60):
        return wait_for(lambda: (r := self.bob_task(tid))['status'] and r['status']['state'] == state and r,
                        timeout=timeout, message=f'bob sees {tid} {state}')

    def bob_outbound(self, rid):
        status, record = self.b.call('GET', f"/v1/outbound/{self.ids['a']}/{rid}")
        need(status == 200, 'bob\'s outbound record', rid, status, record)
        return record

    def deliveries_for(self, rid, host=None):
        return [d['delivery'] for d in (host or self.a).cli('delivery', 'list')
                if d['delivery'].get('request_id') == rid]

    def event(self, c, kind, key, value, since=0.0, timeout=30, where=None):
        """The first channel event of kind whose meta[key] is value."""
        _, params = c.wait_event(kind, since=since, timeout=timeout,
                                 where=lambda p: (p.get('meta') or {}).get(key) == value
                                 and (where is None or where(p)))
        return params

    def events_named(self, c, key, value, since=0.0, kinds=None):
        return [p for _, p in c.channel(since) if (p.get('meta') or {}).get(key) == value
                and (kinds is None or (p.get('meta') or {}).get('kind') in kinds)]

    def pending(self, c):
        failed, value = c.tool('pending_work', {})
        need(not failed and isinstance(value, dict), 'pending_work returns an object', failed, value)
        keys = {'deliveries', 'replies', 'tasks'} | ({'calls'} if user_version(self.a) >= CALLS_VERSION else set())
        need(set(value) == keys, 'pending_work returns {deliveries, replies, tasks} (and calls from version 18)',
             value)
        for name, keys in (('deliveries', DELIVERY_KEYS), ('replies', REPLY_KEYS), ('tasks', TASK_KEYS)):
            need(isinstance(value[name], list), f'pending_work {name} is a list', value[name])
            for item in value[name]:
                need(set(item) == keys, f'Pending work: each {name} item is exactly {sorted(keys)}', item)
        return value

    def mark_seen(self, c, ids, expected, rule):
        failed, value = c.tool('mark_seen', {'ids': ids})
        need(not failed and value == {'seen': expected}, rule, ids, failed, value)

    # --- slice 2: sections -------------------------------------------------------------------------------

    def check_seen(self):
        """Seen by reply, mark_seen, send_status, and the task_* tools, observed in pending_work and the v15 columns."""
        a, net = self.a, self.net
        out = self.attach_profile(self.root / 'projects' / 'seer', 'seer')
        self.seer = {'first': out, 'agent_id': out['agent']['id'], 'workspace': self.root / 'projects' / 'seer'}
        c1 = self.verified(out['profile'], 'seer-1')
        self.seer_c1 = c1
        self.seer_old_secret = self.secret(Path(out['profile']))
        m, r, t, d = {}, {}, {}, {}

        # Inbound messages: m1 answered with reply, m2 marked seen, m3 left unseen.
        for key in ('m1', 'm2', 'm3'):
            rid = self.send_from_bob('seer', f'seer message {key}')
            meta = self.event(c1, 'message', 'request_id', rid)['meta']
            need(flag(meta, 'redelivered') is False, 'Events: a first delivery carries meta.redelivered false', meta)
            m[key] = (rid, meta['delivery_id'])
        failed, value = c1.tool('reply', {'delivery_id': m['m1'][1], 'content': 'answered m1'})
        need(not failed, 'reply to m1', value)
        self.mark_seen(c1, [m['m2'][1]], [m['m2'][1]], 'mark_seen with a delivery ID returns {seen: [ids]}')
        self.mark_seen(c1, [m['m2'][1]], [], 'mark_seen ignores IDs already seen')
        self.mark_seen(c1, [m['m1'][1]], [], 'reply set seen: mark_seen then ignores that delivery')
        failed, value = c1.tool('mark_seen', {'ids': []})
        need(failed, 'mark_seen takes 1 to 100 IDs: none is an error', value)
        failed, value = c1.tool('mark_seen', {'ids': ['delivery_' + secrets.token_hex(16) for _ in range(101)]})
        need(failed, 'mark_seen takes 1 to 100 IDs: 101 is an error', value)
        # Q: an ID this session does not hold is read literally (it takes IDs this session holds) as an error.
        failed, value = c1.tool('mark_seen', {'ids': ['delivery_' + secrets.token_hex(16)]})
        need(failed, 'mark_seen takes IDs this session holds: an unknown ID is an error', value)

        # Replies to the session's own sends: r1 by send_status, r2 by mark_seen with its request_id, r3 unseen.
        for key in ('r1', 'r2', 'r3'):
            failed, sent = c1.tool('send', {'to': 'bob/target', 'network': net, 'content': f'seer asks {key}'})
            need(not failed and sent.get('request_id'), 'MCP send by to', sent)
            rid = sent['request_id']
            self.bob_answer(rid, f'bob answers {key}')
            meta = self.event(c1, 'reply', 'request_id', rid, timeout=60)['meta']
            need(flag(meta, 'redelivered') is False, 'Events: a first reply event carries meta.redelivered false',
                 meta)
            r[key] = (rid, meta.get('notification_id'))
        failed, value = c1.tool('send_status', {'request_id': r['r1'][0]})
        need(not failed, 'send_status naming r1', value)
        self.mark_seen(c1, [r['r2'][0]], [r['r2'][0]], 'mark_seen with a request ID (a reply to this session\'s send)')

        # Tasks: t1 accepted with progress, t2 rejected, t3 and t4 cancel requested and seen (mark_seen; a task_*
        # call), t5 offered and unseen, t6 accepted with an unseen cancellation request.
        for key in ('t1', 't2', 't3', 't4', 't5', 't6'):
            tid = self.task_from_bob('seer', f'seer task {key}')
            meta = self.event(c1, 'task', 'task_id', tid)['meta']
            need(flag(meta, 'redelivered') is False and flag(meta, 'adopted') is False,
                 'Events: a first task event carries redelivered false and adopted false', meta)
            t[key] = (tid, meta.get('delivery_id'))
        for key in ('t1', 't3', 't4', 't6'):
            failed, value = c1.tool('task_accept', {'task_id': t[key][0]})
            need(not failed, f'task_accept {key}', value)
        failed, value = c1.tool('task_progress', {'task_id': t['t1'][0], 'message': 'step one'})
        need(not failed, 'task_progress t1', value)
        failed, value = c1.tool('task_reject', {'task_id': t['t2'][0], 'reason': 'not mine'})
        need(not failed, 'task_reject t2', value)
        for key in ('t3', 't4', 't6'):
            self.b.cli('task', 'cancel', '--peer', self.ids['a'], t[key][0])
            self.event(c1, 'task_cancel_requested', 'task_id', t[key][0], timeout=40)
        self.mark_seen(c1, [t['t3'][0]], [t['t3'][0]], 'mark_seen with a task ID (a cancellation request)')
        failed, value = c1.tool('task_progress', {'task_id': t['t4'][0], 'message': 'stopping soon'})
        need(not failed, 'task_progress t4 after its cancellation request was forwarded', value)

        # Task updates of this session's delegations: d1 by mark_seen, d2 by task_status, d3 unseen. Q: the Verification
        # list names redelivery of messages, replies, and tasks only, so task update redelivery is not checked.
        for key in ('d1', 'd2', 'd3'):
            failed, record = c1.tool('delegate_task', {'to': 'bob/target', 'network': net,
                                                      'input': f'seer delegates {key}'})
            need(not failed and record.get('task_id'), 'MCP delegate_task by to', record)
            tid = record['task_id']
            self.bob_accept(tid)
            self.event(c1, 'task_update', 'task_id', tid, timeout=60,
                       where=lambda p: p['meta'].get('event_kind') == 'accepted')
            d[key] = tid
        updates = {key: [row['id'] for row in rows(a, 'SELECT id FROM task_update_notifications WHERE task_id=?',
                                                   (tid,))] for key, tid in d.items()}
        self.mark_seen(c1, [d['d1']], [d['d1']], 'mark_seen with a task ID (task updates)')
        failed, value = c1.tool('task_status', {'task_id': d['d2']})
        need(not failed, 'task_status d2', value)
        self.seer.update(m=m, r=r, t=t, d=d)

        # The model's view: pending_work.
        value = self.pending(c1)
        need([x['delivery_id'] for x in value['deliveries']] == [m['m2'][1], m['m3'][1]],
             'pending_work deliveries: unanswered deliveries oldest first (m1 answered by reply is gone)',
             value['deliveries'])
        need([x['seen'] for x in value['deliveries']] == [True, False],
             'pending_work: seen true after mark_seen, false otherwise', value['deliveries'])
        need([x['request_id'] for x in value['replies']] == [r['r3'][0]],
             'pending_work replies: only unseen replies (send_status and mark_seen set seen)', value['replies'])
        need([(x['task_id'], x['state']) for x in value['tasks']]
             == [(t['t1'][0], 'running'), (t['t3'][0], 'cancel_requested'), (t['t4'][0], 'cancel_requested'),
                 (t['t5'][0], 'queued'), (t['t6'][0], 'cancel_requested')],
             'pending_work tasks: queued, running, and cancel_requested tasks oldest first (rejected t2 is gone)',
             value['tasks'])

        # The daemon's record: the version 15 columns.
        def column(table, key, value_, name):
            found = rows(a, f'SELECT * FROM {table} WHERE {key}=?', (value_,))
            need(len(found) == 1 and name in found[0], f'Shared state: {table}.{name} for {value_}', found)
            return found[0][name]
        for key, seen in (('m1', True), ('m2', True), ('m3', False)):
            got = column('deliveries', 'id', m[key][1], 'seen_at')
            need(bool(got) == seen, f'Seen: deliveries.seen_at for {key} ({"reply" if key == "m1" else "mark_seen"})'
                 if seen else 'Seen: an unseen delivery has seen_at null', key, got)
        for key, seen in (('r1', True), ('r2', True), ('r3', False)):
            got = column('adapter_outbound', 'request_id', r[key][0], 'reply_seen_at')
            need(bool(got) == seen, 'Seen: adapter_outbound.reply_seen_at set by send_status and mark_seen, null '
                 'otherwise', key, got)
        for key, seen, cancel in (('t1', True, None), ('t2', True, None), ('t3', True, True), ('t4', True, True),
                                  ('t5', False, None), ('t6', True, False)):
            got = column('task_deliveries', 'task_id', t[key][0], 'seen_at')
            need(bool(got) == seen, 'Seen: task_deliveries.seen_at set by task_accept and task_reject, null '
                 'for an offered task', key, got)
            if cancel is not None:
                got = column('task_deliveries', 'task_id', t[key][0], 'cancel_seen_at')
                need(bool(got) == cancel, 'Seen: cancel_seen_at set by mark_seen (task ID) or a task_* call after '
                     'the cancellation request was forwarded', key, got)
        for key, seen in (('d1', True), ('d2', True), ('d3', False)):
            for nid in updates[key]:
                got = column('task_update_notifications', 'id', nid, 'seen_at')
                need(bool(got) == seen, 'Seen: task_update_notifications.seen_at set by mark_seen (task ID) or a '
                     'task_* call (task_status) after the update was forwarded', key, nid, got)
        # Owner output and records are unchanged: no seen fields in delivery records.
        record = self.deliveries_for(m['m2'][0])
        need(len(record) == 1 and not {'seen_at', 'redeliveries', 'returned_at'} & set(record[0]),
             'Owner output (delivery list) is unchanged: the additions are columns, not record fields', record)
        return 'reply, mark_seen, send_status, task_accept/reject, task_progress, task_status'

    def check_redelivery(self):
        need(getattr(self, 'seer', None) and 't' in self.seer, 'needs the seen section')
        a, b, net, s = self.a, self.b, self.net, self.seer
        m, r, t = s['m'], s['r'], s['t']
        c1 = self.seer_c1
        before_m3 = self.bob_outbound(m['m3'][0])
        need(before_m3['state'] == 'accepted', 'm3 accepted before the replacement', before_m3)
        # A late arrival: a send whose reply comes after the authorization ended.
        failed, sent = c1.tool('send', {'to': 'bob/target', 'network': net, 'content': 'seer asks r4'})
        need(not failed and sent.get('request_id'), 'MCP send by to', sent)
        r4 = sent['request_id']
        c1.close()
        second = self.attach_profile(s['workspace'])
        need(second['agent']['id'] == s['agent_id'] and second['session_id'] != s['first']['session_id'],
             'attach again: a new attachment of the same agent', second, s['first'])
        old = self.seer_old_secret['adapter']['id']
        need(self.connection(old) in ('revoked', 'detached', 'expired'),
             'the old authorization ended (replaced)', self.connection(old))
        self.bob_answer(r4, 'bob answers r4 late')
        marked = time.monotonic()
        c2 = self.verified(second['profile'], 'seer-2')
        self.seer_c2, self.seer_second = c2, second

        meta = self.event(c2, 'message', 'request_id', m['m3'][0], since=marked)['meta']
        need(flag(meta, 'redelivered') is True, 'Redelivery: an unseen message reaches the next session with '
             'meta.redelivered true', meta)
        need(meta.get('delivery_id') == m['m3'][1], 'A claim of a returned item keeps its delivery_id', meta,
             m['m3'][1])
        meta = self.event(c2, 'reply', 'request_id', r['r3'][0], since=marked, timeout=60)['meta']
        need(flag(meta, 'redelivered') is True, 'Redelivery: an unseen reply reaches the next session with '
             'meta.redelivered true', meta)
        need(meta.get('notification_id') == r['r3'][1], 'A claim of a returned reply keeps its notification_id',
             meta, r['r3'][1])
        meta = self.event(c2, 'task', 'task_id', t['t5'][0], since=marked)['meta']
        need(flag(meta, 'redelivered') is True and flag(meta, 'adopted') is False,
             'Redelivery: an unseen offered task reaches the next session with redelivered true, adopted false', meta)
        if t['t5'][1]:
            need(meta.get('delivery_id') == t['t5'][1], 'the returned task keeps its delivery_id', meta)
        meta = self.event(c2, 'reply', 'request_id', r4, since=marked, timeout=60)['meta']
        need(flag(meta, 'redelivered') is False, 'Late arrivals: a reply arriving after its authorization ended goes '
             'to the next verified session with redelivered false', meta)
        time.sleep(4)
        for key in ('m1', 'm2'):
            need(not self.events_named(c2, 'request_id', m[key][0], marked),
                 f'Items that were seen are never redelivered ({key})', key)
        for key in ('r1', 'r2'):
            need(not self.events_named(c2, 'request_id', r[key][0], marked, kinds=('reply',)),
                 f'Seen replies are never redelivered ({key})', key)
        need(not self.events_named(c2, 'task_id', t['t2'][0], marked), 'a rejected task is not redelivered')
        for key in ('m3',):
            need(len(self.events_named(c2, 'request_id', m[key][0], marked)) == 1, 'redelivered once to the session')

        # pending_work on the new session: the returned items, and not the seen item the old session held.
        value = self.pending(c2)
        need([(x['delivery_id'], x['redelivered'], x['seen']) for x in value['deliveries']]
             == [(m['m3'][1], True, False)],
             'pending_work: the redelivered delivery (redelivered true); m2, seen by the ended session, is not held '
             'by this one', value['deliveries'])
        need([x['request_id'] for x in value['replies']] == [r['r3'][0], r4],
             'pending_work: the returned reply and the late reply, oldest first', value['replies'])
        # Q: where adopted tasks fall in "oldest first" is not said; the tasks are compared as a set here.
        need({x['task_id']: x['adopted'] for x in value['tasks']}
             == {t['t1'][0]: True, t['t3'][0]: True, t['t4'][0]: True, t['t5'][0]: False, t['t6'][0]: True},
             'pending_work: adopted tasks adopted true, the redelivered offer adopted false', value['tasks'])

        # The daemon's record.
        def one(table, key, value_):
            found = rows(a, f'SELECT * FROM {table} WHERE {key}=?', (value_,))
            need(len(found) == 1, f'one {table} row for {value_} (a claim of a returned item keeps its row)', found)
            return found[0]
        row = one('deliveries', 'id', m['m3'][1])
        need(row.get('redeliveries') == 1 and row.get('returned_at') is None and not row.get('seen_at'),
             'deliveries: redeliveries 1 after one return and claim; a claim clears returned_at', row)
        row = one('task_deliveries', 'task_id', t['t5'][0])
        need(row.get('redeliveries') == 1 and row.get('adopted_at') is None,
             'task_deliveries: a redelivered offer counts 1 and is not adopted', row)
        row = one('task_deliveries', 'task_id', t['t1'][0])
        need(row.get('redeliveries') == 0 and row.get('adopted_at'),
             'task_deliveries: adoption sets adopted_at and does not count as a redelivery', row)
        row = one('adapter_outbound', 'request_id', r['r3'][0])
        need(row.get('reply_redeliveries') == 1, 'adapter_outbound.reply_redeliveries 1', row)
        row = one('adapter_outbound', 'request_id', r4)
        need(row.get('reply_redeliveries') == 0, 'a late reply was never forwarded: reply_redeliveries 0', row)

        # The sender's view is unchanged, and nothing reaches the sender twice.
        after = self.bob_outbound(m['m3'][0])
        need(after['state'] == 'accepted' and after.get('attempts') == before_m3.get('attempts'),
             'A sender\'s view of a returned message is unchanged: it stays accepted', before_m3, after)
        need(len(self.deliveries_for(m['m3'][0])) == 1, 'the receiver keeps one delivery for the returned message')
        need([e['kind'] for e in self.bob_events(t['t5'][0])] == ['queued'],
             'the sender of a returned task sees no new event', self.bob_events(t['t5'][0]))
        failed, value = c2.tool('reply', {'delivery_id': m['m3'][1], 'content': 'answered after redelivery'})
        need(not failed, 'the new session replies to the redelivered message', value)

        def replied():
            out = b.cli('message', 'reply', '--peer', self.ids['a'], m['m3'][0])
            return out if out.get('state') == 'replied' else None
        out = wait_for(replied, timeout=40, message='bob fetches the reply')
        need('answered after redelivery' in json.dumps(out), 'the sender gets the new session\'s reply', out)
        failed, value = c2.tool('reply', {'delivery_id': m['m3'][1], 'content': 'answered after redelivery'})
        need(not failed, 'an identical repeat returns the saved reply', value)
        failed, value = c2.tool('task_accept', {'task_id': t['t5'][0]})
        need(not failed, 'the new session accepts the redelivered task', value)
        failed, value = c2.tool('task_complete', {'task_id': t['t5'][0], 'status': 'succeeded', 'output': 't5 done'})
        need(not failed, 'and completes it', value)
        self.bob_state(t['t5'][0], 'succeeded')
        kinds = [e['kind'] for e in self.bob_events(t['t5'][0])]
        need(kinds == ['queued', 'accepted', 'succeeded'], 'the sender sees the redelivered task once', kinds)
        self.mark_seen(c2, [r['r3'][0], r4], [r['r3'][0], r4], 'mark_seen the returned and late replies')
        return 'message, reply, task redelivered; late reply; seen items kept back'

    def check_adoption(self):
        need(getattr(self, 'seer_c2', None), 'needs the redelivery section')
        a, t, c2 = self.a, self.seer['t'], self.seer_c2
        expected = {'t1': ('running', 'step one'), 't3': ('cancel_requested', None),
                    't4': ('cancel_requested', 'stopping soon'), 't6': ('cancel_requested', None)}
        for key, (state, progress) in expected.items():
            found = self.events_named(c2, 'task_id', t[key][0], kinds=('task',))
            need(len(found) == 1, f'Adoption: one task event for the adopted task {key}', found)
            meta = found[0]['meta']
            need(flag(meta, 'adopted') is True and meta.get('state') == state,
                 f'Adoption: meta.adopted true and meta.state {state} ({key})', meta)
            need(flag(meta, 'redelivered') is False, 'an adoption is not a redelivery', meta)
            if progress is None:
                need('progress' not in meta, 'meta.progress is omitted when there is none', meta)
            else:
                need(meta.get('progress') == progress, 'meta.progress is the latest progress message', meta)
        # The old authorization cannot change them.
        old = RawAdapter(a, self.seer_old_secret)
        status, value = old.connect()
        need(status != 200, 'the old (replaced) authorization cannot connect', status, value)
        for path, body in ((f"/adapter/v1/tasks/{t['t1'][0]}/progress", {'message': 'from the old session'}),
                           (f"/adapter/v1/tasks/{t['t3'][0]}/cancelled", {})):
            status, value = old.request('POST', path, body)
            need(not 200 <= status < 300, 'Adoption: the old authorization is unable to change an adopted task',
                 path, status, value)
        need('from the old session' not in json.dumps(self.bob_events(t['t1'][0])), 'nothing changed')
        # Another agent's session gets none of them, and cannot change them.
        stranger = self.register(a, 'stranger', 'alice')
        raw = self.raw_for(a, stranger)
        ours = {t[k][0] for k in t}
        self.claims_nothing(raw, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] in ours,
                            'Adoption never moves a task between agents')
        status, value = raw.call('POST', f"/adapter/v1/tasks/{t['t1'][0]}/progress", {'message': 'stranger'})
        need(status in (403, 404), 'another agent\'s session cannot change an adopted task', status, value)
        # Only the adopting session changes them.
        for call, args in (('task_progress', {'task_id': t['t1'][0], 'message': 'after adoption'}),
                           ('task_complete', {'task_id': t['t1'][0], 'status': 'succeeded', 'output': 't1 done'}),
                           ('task_cancelled', {'task_id': t['t3'][0]}),
                           ('task_complete', {'task_id': t['t4'][0], 'status': 'succeeded', 'output': 't4 done'}),
                           ('task_cancelled', {'task_id': t['t6'][0]})):
            failed, value = c2.tool(call, args)
            need(not failed, f'the adopting session may change the task ({call})', args, value)
        self.bob_state(t['t1'][0], 'succeeded')
        self.bob_state(t['t3'][0], 'cancelled')
        self.bob_state(t['t4'][0], 'succeeded')
        self.bob_state(t['t6'][0], 'cancelled')
        need('after adoption' in json.dumps(self.bob_events(t['t1'][0])), 'the adopted progress reaches the sender')

        # Raw handoffs: adopted, progress, and redelivered at the top level; a later cancellation request goes to the
        # adopting session.
        agent = self.register(a, 'rawadopt', 'alice')
        r1 = self.raw_for(a, agent)
        ta, tb = self.task_from_bob('rawadopt', 'raw adopt a'), self.task_from_bob('rawadopt', 'raw adopt b')
        for tid in (ta, tb):
            h = self.claim(r1, '/adapter/v1/tasks/next', lambda v, tid=tid: v['task']['task_id'] == tid)
            need(h and h.get('redelivered') is False and h.get('adopted') is False and 'progress' in h
                 and h['progress'] is None, 'Events: a task handoff gains redelivered false, adopted false, and '
                 'progress null', h)
            status, value = r1.call('POST', f'/adapter/v1/tasks/{tid}/accept', {})
            need(status == 200, 'accept', status, value)
        status, value = r1.call('POST', f'/adapter/v1/tasks/{ta}/progress', {'message': 'halfway'})
        need(status == 200, 'progress', status, value)
        self.end(r1)
        r2 = self.raw_for(a, agent)
        for tid, progress in ((ta, 'halfway'), (tb, None)):
            h = self.claim(r2, '/adapter/v1/tasks/next', lambda v, tid=tid: v['task']['task_id'] == tid)
            need(h and h.get('adopted') is True and h.get('progress') == progress and h.get('redelivered') is False
                 and h['status']['state'] == 'running',
                 'Adoption happens at the claim through /adapter/v1/tasks/next: adopted true, the latest progress, '
                 'redelivered false', h)
        self.b.cli('task', 'cancel', '--peer', self.ids['a'], tb)
        h = self.claim(r2, '/adapter/v1/tasks/cancels/next', lambda v: tb in json.dumps(v), timeout=40)
        need(h, 'An adopted task\'s later cancellation request goes to the adopting session')
        for path, body in ((f'/adapter/v1/tasks/{ta}/complete', {'status': 'succeeded', 'output': 'a'}),
                           (f'/adapter/v1/tasks/{tb}/cancelled', {})):
            status, value = r2.call('POST', path, body)
            need(status == 200, 'the adopting raw session finishes the task', path, status, value)
        return 'running and cancel_requested adopted; old and other sessions refused'

    def check_chain(self):
        """bob/origin -> alice/mid -> carol/end; alice's middle session is replaced while carol works."""
        a, b, net = self.a, self.b, self.net
        c = self.host('c')
        self.dec.install_key(c, 'carol')
        self.ids['c'] = c.start()['id']
        self.dec.join(a, c, 'carol')
        self.dec.wait_members((a, b, c), 3)
        c.cli('allow', 'everyone', '--network', net)
        a.cli('allow', 'bob', '--delegate', '--network', net)
        for h in (a, b, c):
            try:
                h.cli('network', 'sync', net)
            except AssertionError:
                pass
        origin = self.register(b, 'origin', 'bob')
        end = self.register(c, 'end', 'carol')
        rorigin = self.raw_for(b, origin, directory=True)
        rend = self.raw_for(c, end)
        workspace = self.root / 'projects' / 'mid'
        first = self.attach_profile(workspace, 'mid')
        m1 = self.verified(first['profile'], 'mid-1')

        def listed(h, address):
            h.call('POST', f'/v1/directory/refresh?network={net}', {})
            return any(x.get('address') == address for x in h.directory(net)[1].get('agents', []))
        wait_for(lambda: listed(b, 'alice/mid'), timeout=40, message='alice/mid in bob\'s directory')
        wait_for(lambda: listed(a, 'carol/end'), timeout=40, message='carol/end in alice\'s directory')
        parent = task_id()
        status, record = rorigin.call('POST', '/adapter/v1/delegations', {
            'to': 'alice/mid', 'network': net, 'task_id': parent, 'input': 'review, pass part on',
            'delegation_depth': 1})
        need(status == 200, 'bob\'s origin delegates to alice/mid with delegation_depth 1', status, record)
        meta = self.event(m1, 'task', 'task_id', parent, timeout=60)['meta']
        need(flag(meta, 'delegable') is True, 'the middle task is delegable', meta)
        failed, value = m1.tool('task_accept', {'task_id': parent})
        need(not failed, 'mid accepts', value)
        failed, forward = m1.tool('delegate_task', {'to': 'carol/end', 'network': net, 'input': 'your part',
                                                   'parent_task_id': parent})
        need(not failed and forward.get('task_id'), 'mid forwards to carol/end with parent_task_id', forward)
        child = forward['task_id']
        h = self.claim(rend, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == child, timeout=60)
        need(h and len(h['task'].get('delegation') or []) == 2, 'carol receives the two-link chain', h)
        status, value = rend.call('POST', f'/adapter/v1/tasks/{child}/accept', {})
        need(status == 200, 'carol accepts', status, value)
        self.event(m1, 'task_update', 'task_id', child, timeout=60,
                   where=lambda p: p['meta'].get('event_kind') == 'accepted')

        # Replace the middle session.
        m1.close()
        second = self.attach_profile(workspace)
        need(second['agent']['id'] == first['agent']['id'], 'the same agent', second)
        marked = time.monotonic()
        m2 = self.verified(second['profile'], 'mid-2')
        meta = self.event(m2, 'task', 'task_id', parent, since=marked)['meta']
        need(flag(meta, 'adopted') is True and meta.get('state') == 'running',
             'Adoption: the middle link\'s task is adopted, running', meta)
        status, value = rend.call('POST', f'/adapter/v1/tasks/{child}/complete',
                                  {'status': 'succeeded', 'output': 'carol result'})
        need(status == 200, 'carol completes', status, value)
        update = self.event(m2, 'task_update', 'task_id', child, since=marked, timeout=60,
                            where=lambda p: p['meta'].get('event_kind') == 'succeeded')
        need('carol result' in json.dumps(update), 'Late arrivals: the child\'s updates go to the adopting session',
             update)
        failed, value = m2.tool('task_complete', {'task_id': parent, 'status': 'succeeded',
                                                 'output': 'combined: carol result'})
        need(not failed, 'the adopting session completes the middle task', value)

        def done():
            status, record = rorigin.call('GET', f'/adapter/v1/delegations/{parent}')
            return record if status == 200 and (record.get('status') or {}).get('state') == 'succeeded' else None
        record = wait_for(done, timeout=60, message='the chain completes at bob\'s origin')
        need('combined: carol result' in json.dumps(record) or 'combined' in json.dumps(self.b.call(
            'GET', f"/v1/tasks/{self.ids['a']}/{parent}/events")[1]),
             'the originator gets the middle agent\'s output', record)
        status, local = a.call('GET', f"/v1/tasks/{self.ids['c']}/{child}")
        need(status == 200 and local['status']['state'] == 'succeeded' and len(local.get('delegation') or []) == 2,
             'A delegation chain whose link was adopted continues unchanged', status, local)
        self.mid = m2
        return 'two-link chain completed after the middle session was replaced'

    def check_pending(self):
        a, b, net = self.a, self.b, self.net
        workspace = self.root / 'projects' / 'pender'
        out = self.attach_profile(workspace, 'pender')
        session_id = out['session_id']
        p = self.verified(out['profile'], 'pender')
        self.pender = (workspace, p)
        long = 'é' * 150 + 'x' * 150  # 300 characters, 450 UTF-8 bytes
        sent = {}
        for key, text in (('pm1', long), ('pm2', 'short two'), ('pm3', 'answer me')):
            rid = self.send_from_bob('pender', text)
            sent[key] = (rid, self.event(p, 'message', 'request_id', rid)['meta'])
        failed, value = p.tool('reply', {'delivery_id': sent['pm3'][1]['delivery_id'], 'content': 'done'})
        need(not failed, 'reply pm3', value)
        self.mark_seen(p, [sent['pm2'][1]['delivery_id']], [sent['pm2'][1]['delivery_id']], 'mark_seen pm2')
        tasks = {}
        for key, text in (('pt1', long), ('pt2', 'run me'), ('pt3', 'cancel me'), ('pt4', 'finish me'),
                          ('pt5', 'reject me')):
            tid = self.task_from_bob('pender', text)
            tasks[key] = (tid, self.event(p, 'task', 'task_id', tid)['meta'])
        for key in ('pt2', 'pt3', 'pt4'):
            need(not p.tool('task_accept', {'task_id': tasks[key][0]})[0], f'task_accept {key}')
        need(not p.tool('task_complete', {'task_id': tasks['pt4'][0], 'status': 'succeeded', 'output': 'x'})[0],
             'task_complete pt4')
        need(not p.tool('task_reject', {'task_id': tasks['pt5'][0], 'reason': 'no'})[0], 'task_reject pt5')
        b.cli('task', 'cancel', '--peer', self.ids['a'], tasks['pt3'][0])
        self.event(p, 'task_cancel_requested', 'task_id', tasks['pt3'][0], timeout=40)
        replies = {}
        for key, answer in (('pr1', long[::-1]), ('pr2', 'seen answer')):
            failed, value = p.tool('send', {'to': 'bob/target', 'network': net, 'content': f'pender asks {key}'})
            need(not failed, 'MCP send', value)
            self.bob_answer(value['request_id'], answer)
            replies[key] = (value['request_id'], self.event(p, 'reply', 'request_id', value['request_id'],
                                                            timeout=60)['meta'], answer)
        self.mark_seen(p, [replies['pr2'][0]], [replies['pr2'][0]], 'mark_seen pr2')

        value = self.pending(p)
        expected = []
        for key, text, seen in (('pm1', long, False), ('pm2', 'short two', True)):
            rid, meta = sent[key]
            expected.append({'delivery_id': meta['delivery_id'], 'request_id': rid, 'sender_host_id': self.ids['b'],
                             'origin_agent_id': meta.get('origin_agent_id'), 'preview': text[:PREVIEW], 'seen': seen,
                             'deadline': self.bob_outbound(rid)['request']['deadline'], 'redelivered': False})
        got = value['deliveries']
        need([x['delivery_id'] for x in got] == [x['delivery_id'] for x in expected],
             'pending_work deliveries: unanswered deliveries held by this session, oldest first', got, expected)
        for item, want in zip(got, expected):
            need(same_time(item['deadline'], want['deadline']), 'a delivery\'s deadline', item, want)
            need({k: v for k, v in item.items() if k != 'deadline'} == {k: v for k, v in want.items() if k != 'deadline'},
                 'pending_work delivery fields match the event meta; preview is the first 200 characters', item, want)
        rid, meta, answer = replies['pr1']
        want = [{'notification_id': meta.get('notification_id'), 'request_id': rid, 'peer_host_id': self.ids['b'],
                 'preview': answer[:PREVIEW]}]
        need(value['replies'] == want, 'pending_work replies: unseen replies {notification_id, request_id, '
             'peer_host_id, preview}', value['replies'], want)
        got = value['tasks']
        order = [('pt1', 'queued', long), ('pt2', 'running', 'run me'), ('pt3', 'cancel_requested', 'cancel me')]
        need([(x['task_id'], x['state']) for x in got] == [(tasks[k][0], s) for k, s, _ in order],
             'pending_work tasks: queued, running, and cancel_requested held by this session, oldest first', got)
        for item, (key, state, text) in zip(got, order):
            tid, meta = tasks[key]
            need(item['sender_host_id'] == self.ids['b'] and item['preview'] == text[:PREVIEW]
                 and item['adopted'] is False and same_time(item['deadline'], self.bob_task(tid)['request']['deadline'])
                 and isinstance(item['delivery_id'], str) and item['delivery_id'].startswith('delivery_')
                 and item['delivery_id'] == meta.get('delivery_id', item['delivery_id']),
                 'pending_work task fields', item, meta)

        status, admin = a.call('GET', f'/v1/sessions/{session_id}/pending')
        need(status == 200 and admin == value, 'GET /v1/sessions/{id}/pending returns the same object', status, admin)
        result = a.run('session', 'pending', '--json', cwd=str(workspace))
        need(result.returncode == 0, 'session pending --json exits 0', result.returncode, result.stderr[-300:])
        need(json.loads(result.stdout) == value, 'session pending --json prints the same object as pending_work for '
             'the current directory\'s attachment', result.stdout[-800:])
        # The hook passes no --state: the attach profile is found under whichever state directory made it.
        result = a.run(argv=[a.cli_binary, 'session', 'pending', '--json'], cwd=str(workspace))
        need(result.returncode == 0 and json.loads(result.stdout or 'null') == value,
             'session pending --json without --state finds the attach profile whose workspace is the current '
             'directory', result.returncode, result.stdout[-500:], result.stderr[-300:])
        result = a.run('session', 'pending', cwd=str(workspace))
        lines = [x for x in result.stdout.splitlines() if x.strip()]
        need(result.returncode == 0 and len(lines) == 6, 'session pending without --json prints one line per item',
             result.returncode, result.stdout)
        for argv in (None, [a.cli_binary, 'session', 'pending', '--hook']):
            result = a.run('session', 'pending', '--hook', argv=argv, cwd=str(workspace))
            need(result.returncode == 0 and hook_output(result.stdout, value) is None,
                 'session pending --hook prints {"hookSpecificOutput": {"hookEventName": "SessionStart", '
                 '"additionalContext": LEAD + compact pending_work JSON}}', argv is None,
                 hook_output(result.stdout, value), result.returncode, result.stdout[-800:], result.stderr[-300:])
        # An attachment with all three lists empty: --hook prints nothing.
        idle_ws = self.root / 'projects' / 'idle'
        idle = self.attach_profile(idle_ws, 'idle')
        status, listed = a.call('GET', f"/v1/sessions/{idle['session_id']}/pending")
        empty = {'deliveries': [], 'replies': [], 'tasks': []}
        if user_version(a) >= CALLS_VERSION:
            empty['calls'] = []
        need(status == 200 and listed == empty,
             'an idle attachment has no pending work', status, listed)
        result = a.run('session', 'pending', '--hook', cwd=str(idle_ws))
        need(result.returncode == 0 and result.stdout == '',
             'session pending --hook prints nothing when all three lists are empty', result.returncode,
             result.stdout, result.stderr[-300:])
        empty = self.root / 'projects' / 'none'
        empty.mkdir(parents=True, exist_ok=True)
        for flags in (('--json',), ('--hook',), ()):
            result = a.run('session', 'pending', *flags, cwd=str(empty))
            need(result.returncode == 0 and result.stdout == '',
                 'With no attachment for the directory, session pending prints nothing and exits 0', flags,
                 result.returncode, result.stdout, result.stderr[-300:])

        # The adapter route, with a raw adapter.
        agent = self.register(a, 'rawpend', 'alice')
        raw = self.raw_for(a, agent)
        rid = self.send_from_bob('rawpend', 'for the raw route')
        h = self.claim(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid, timeout=40)
        need(h and h.get('redelivered') is False, 'Events: a message handoff gains redelivered false', h)
        need(not {'seen_at', 'redeliveries'} & set(h['delivery']), 'handoff objects keep their fields', h)
        did = h['delivery']['id']
        status, listed = raw.call('GET', '/adapter/v1/pending')
        need(status == 200 and [x['delivery_id'] for x in listed.get('deliveries', [])] == [did]
             and listed['deliveries'][0]['seen'] is False and listed['replies'] == [] and listed['tasks'] == [],
             'GET /adapter/v1/pending', status, listed)
        status, admin = a.call('GET', f"/v1/sessions/{raw.adapter['session_id']}/pending")
        need(status == 200 and admin == listed, 'the adapter route and the administration route agree', admin, listed)
        status, value = raw.call('POST', '/adapter/v1/seen', {'ids': [did]})
        need(status == 200 and value == {'seen': [did]}, 'POST /adapter/v1/seen with {ids}', status, value)
        status, value = raw.call('POST', '/adapter/v1/seen', {'ids': [did]})
        need(status == 200 and value == {'seen': []}, 'POST /adapter/v1/seen ignores IDs already seen', status, value)
        for ids in ([], ['delivery_' + secrets.token_hex(16) for _ in range(101)]):
            status, value = raw.call('POST', '/adapter/v1/seen', {'ids': ids})
            need(status == 400, 'POST /adapter/v1/seen takes 1 to 100 IDs', len(ids), status, value)
        status, listed = raw.call('GET', '/adapter/v1/pending')
        need(status == 200 and listed['deliveries'][0]['seen'] is True, 'pending: seen true after the route', listed)
        return '2 deliveries, 1 reply, 3 tasks; session pending and both routes agree'

    def check_settings(self):
        a = self.a
        agent = self.register(a, 'settled', 'alice')
        directory, _ = self.profile('settled', agent, self.slice2_fixture())
        workspace = self.root / 'workspace-settled'
        workspace.mkdir(exist_ok=True)
        cli = str(Path(self.cli_binary).resolve())

        def launch(argv=None, extra=('--name', 'hooked')):
            args = ['session', 'start', '--directory', str(directory), '--workspace', str(workspace), '--', *extra]
            result = a.run(*args, argv=[argv, '--state', str(a.state), *args] if argv else None)
            lines = [x for x in result.stdout.splitlines() if x.startswith('{')]
            return result, (json.loads(lines[-1]) if lines else None)

        result, launched = launch()
        need(result.returncode == 0 and launched, 'session start launches the fixture claude', result.returncode,
             result.stdout[-400:], result.stderr[-400:])
        args = launched['arguments']
        need(args.count('--settings') == 1, 'Launch adds --settings PATH once', args)
        path = Path(args[args.index('--settings') + 1])
        need(path.is_absolute() and path.resolve() == (directory / SETTINGS_FILE).resolve(),
             'PATH is claude-settings.json in the session profile directory', path, directory)
        need(args[-2:] == ['--name', 'hooked'], 'the user\'s arguments are kept', args)
        need(stat.S_IMODE(path.stat().st_mode) == 0o600, 'the settings file is written with mode 0600',
             oct(path.stat().st_mode))
        settings = json.loads(path.read_text())
        need(settings == expected_settings(cli), 'the settings file holds exactly the SessionStart hook for '
             f'"{MATCHER}" running \'PEERSPAN\' session pending --hook', settings, expected_settings(cli))
        need(settings['hooks']['SessionStart'][0]['matcher'] == MATCHER, 'the hook matchers: clear|compact|resume')
        home = Path(self.a.private_env()['HOME'])
        need(not (workspace / '.claude').exists() and not (home / '.claude' / 'settings.json').exists(),
             'It changes no global or project Claude Code settings')
        command = settings['hooks']['SessionStart'][0]['hooks'][0]['command']
        result = subprocess.run(['sh', '-c', command], cwd=str(workspace), env=a.environment(), capture_output=True,
                                text=True, timeout=60)
        need(result.returncode == 0 and result.stdout == '', 'the hook command, run in a workspace with no attachment, '
             'prints nothing and exits 0', result.returncode, result.stdout, result.stderr[-300:])
        if getattr(self, 'pender', None):
            ws, consumer = self.pender
            result = subprocess.run(['sh', '-c', command], cwd=str(ws), env=a.environment(), capture_output=True,
                                    text=True, timeout=60)
            pending = self.pending(consumer)
            need(result.returncode == 0 and hook_output(result.stdout, pending) is None,
                 'the hook command, run in an attached project, prints the --hook form of the pending_work object',
                 hook_output(result.stdout, pending), result.returncode, result.stdout[-500:], result.stderr[-300:])
        # --settings among the user's arguments is refused, as --mcp-config is.
        result, launched = launch(extra=('--settings', str(workspace / 'mine.json')))
        need(result.returncode != 0 and launched is None, '--settings among the user\'s extra arguments is refused',
             result.returncode, result.stdout[-300:])
        # A peerspan path containing a quote: '\'' inside single quotes.
        quoted = self.root / "it's here"
        quoted.mkdir(exist_ok=True)
        copy = quoted / Path(cli).name
        shutil.copy2(cli, copy)
        result, launched = launch(argv=str(copy))
        need(result.returncode == 0 and launched, 'session start from a copied CLI', result.returncode,
             result.stderr[-400:])
        settings = json.loads(path.read_text())
        need(settings == expected_settings(str(copy.resolve())),
             'the command single-quotes the absolute path of the peerspan executable that launched the session '
             '(a \' in it becomes \'\\\'\')', settings, str(copy))
        result = subprocess.run(['sh', '-c', settings['hooks']['SessionStart'][0]['hooks'][0]['command']],
                                cwd=str(workspace), env=a.environment(), capture_output=True, text=True, timeout=60)
        need(result.returncode == 0, 'the quoted command runs in the shell', result.returncode, result.stderr[-300:])
        return f'{SETTINGS_FILE} 0600, matcher {MATCHER}'

    def check_limits(self):
        a, b, net = self.a, self.b, self.net
        notes = []
        # The redelivery limit of 3: a message and a task forwarded to four sessions in turn, never seen.
        agent = self.register(a, 'bouncer', 'alice')
        rid = self.send_from_bob('bouncer', 'bounce me')
        tid = self.task_from_bob('bouncer', 'bounce task')
        flags, task_flags, delivery_ids = [], [], set()
        for index in range(LIMIT + 1):
            raw = self.raw_for(a, agent)
            h = self.claim(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid)
            need(h, f'session {index + 1} receives the unseen message ({LIMIT} redeliveries)', index)
            flags.append(h.get('redelivered'))
            delivery_ids.add(h['delivery']['id'])
            if index % 2 == 0:
                # Forwarded means claimed: an unconfirmed delivery returns too.
                raw.call('POST', f"/adapter/v1/deliveries/{h['delivery']['id']}/forwarded", {})
            h = self.claim(raw, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == tid)
            need(h, f'session {index + 1} is offered the unseen task', index)
            task_flags.append((h.get('redelivered'), h.get('adopted')))
            self.end(raw)
        # Q: "redelivered at most 3 times" is read as four handoffs in all (the first, then 3 redeliveries), the item
        # failing when the fourth holder ends; this matches redeliveries counting claims after a return, up to 3.
        need(flags == [False, True, True, True], 'Events: handoffs carry redelivered false, then true for each '
             'redelivery', flags)
        need(task_flags == [(False, False)] + [(True, False)] * LIMIT, 'task handoffs: redelivered, not adopted',
             task_flags)
        need(len(delivery_ids) == 1, 'a returned message keeps its delivery ID', delivery_ids)
        raw = self.raw_for(a, agent)
        self.claims_nothing(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid,
                            'An item is redelivered at most 3 times (message)')
        self.claims_nothing(raw, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == tid,
                            'An item is redelivered at most 3 times (task)')
        wait_for(lambda: [d['state'] for d in self.deliveries_for(rid)] == ['blocked'], timeout=20,
                 message='the message blocked after 3 redeliveries')
        need(self.bob_outbound(rid)['state'] == 'accepted', 'the sender\'s view of the message stays accepted')
        record = self.bob_state(tid, 'failed')
        events = self.bob_events(tid)
        need(events[-1]['kind'] == 'failed' and NEVER_SAW in json.dumps(events[-1]),
             'A task past the limit moves from queued to failed with "session never saw the task", emitting the '
             'usual failed event to its sender', events, record)
        need([e['kind'] for e in events] == ['queued', 'failed'], 'no other events for the never-accepted task',
             events)
        row = rows(a, 'SELECT * FROM deliveries WHERE id=?', (delivery_ids.pop(),))
        need(row and row[0].get('redeliveries') == LIMIT, 'deliveries.redeliveries is 3', row)
        notes.append('message blocked, task failed after 3')

        # Replies have no deadline; past the limit they are no longer offered and stay unseen.
        asker = self.register(a, 'asker', 'alice')
        raw = self.raw_for(a, asker, directory=True)
        rq = request_id()
        status, value = raw.call('POST', '/adapter/v1/send', {'to': 'bob/target', 'network': net, 'request_id': rq,
                                                              'content': 'ask'})
        need(status == 200, 'asker sends by address', status, value)
        self.bob_answer(rq, 'answer to asker')
        reply_flags = []
        for index in range(LIMIT + 1):
            if index:
                raw = self.raw_for(a, asker, directory=True)
            h = self.claim(raw, '/adapter/v1/replies/next', lambda v: rq in json.dumps(v), timeout=60)
            need(h, f'session {index + 1} receives the unseen reply', index)
            reply_flags.append(h.get('redelivered'))
            self.end(raw)
        need(reply_flags == [False, True, True, True], 'reply handoffs: redelivered after each return', reply_flags)
        raw = self.raw_for(a, asker, directory=True)
        self.claims_nothing(raw, '/adapter/v1/replies/next', lambda v: rq in json.dumps(v),
                            'Replies past the limit of 3 are no longer offered')
        row = rows(a, 'SELECT * FROM adapter_outbound WHERE request_id=?', (rq,))
        need(row and row[0].get('reply_redeliveries') == LIMIT and row[0].get('reply_seen_at') is None,
             'and stay unseen (reply_redeliveries 3, reply_seen_at null)', row)
        notes.append('reply not offered after 3')

        # Deadlines passing while queued.
        lapser = self.register(a, 'lapser', 'alice')
        deadline = timestamp(40)
        out = b.cli('send', 'alice/lapser', 'short-lived', '--network', net, '--deadline', deadline)
        rid = out['request']['request_id']
        out = b.cli('task', 'alice/lapser', 'short-lived task', '--network', net, '--deadline', deadline)
        tid = out['request']['task_id']
        raw = self.raw_for(a, lapser)
        need(self.claim(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid, timeout=30),
             'the short-lived message is claimed')
        need(self.claim(raw, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == tid, timeout=30),
             'the short-lived task is claimed')
        self.end(raw)
        remaining = (parse_time(deadline) - datetime.now(timezone.utc)).total_seconds() + 3
        need(remaining > 3, 'the authorization ended before the deadline', remaining)
        time.sleep(remaining)
        raw = self.raw_for(a, lapser)
        self.claims_nothing(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid,
                            'a returned message whose deadline passed while queued is not redelivered')
        self.claims_nothing(raw, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == tid,
                            'a returned task whose deadline passed while queued is not redelivered')
        # Q: the contract does not say how a returned message whose deadline passed is recorded; only that it is not
        # redelivered and the sender's view is unchanged is checked.
        self.bob_state(tid, 'expired')
        need(self.bob_outbound(rid)['state'] == 'accepted', 'the sender\'s view of the message stays accepted')
        notes.append('deadline')

        # Revocation of the sender's access blocks a returned message.
        shut = self.register(a, 'shut', 'alice')
        rid = self.send_from_bob('shut', 'returned then blocked')
        raw = self.raw_for(a, shut)
        need(self.claim(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid), 'claimed')
        self.end(raw)
        a.cli('deny', 'bob', '--network', net)
        try:
            raw = self.raw_for(a, shut)
            self.claims_nothing(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid,
                                'Revocation of the sender\'s access blocks a returned message')
            wait_for(lambda: [d['state'] for d in self.deliveries_for(rid)] == ['blocked'], timeout=20,
                     message='the returned message recorded blocked')
        finally:
            a.cli('allow', 'bob', '--network', net)
            try:
                b.cli('network', 'sync', net)
            except AssertionError:
                pass
        notes.append('revocation')
        return ', '.join(notes)

    def check_migration15(self):
        if self.baseline14 is None:
            raise Failure('migration to 15 needs --baseline14 (a peerspan-host at schema 14, milestone 9 slice 1)')
        a, b, net = self.a, self.b, self.net
        h = DirectoryHost(self.baseline14, self.baseline14, self.root / 'migration15', self.root / 'user-migration15')
        self.hosts['migration15'] = h
        self.ids['m'] = h.start()['id']
        need(user_version(h) == 14, 'the baseline host writes schema 14', user_version(h))
        # Not portable: this section had a schema-14 host (a build from before the coordinator-free
        # design) join the network with a coordinator token, then upgraded it in place. A coordinator-free
        # network admits only hosts that run the join request (decentralized-spec.md section 8), which a
        # schema-14 build cannot, and coordinator tokens are refused (DEC-OWN2).
        h.stop()
        raise Failure('not portable to a coordinator-free network: a schema 14 baseline host cannot join it '
                      '(decentralized-spec.md 8); the rest of this section needs that membership')
        h.cli('allow', 'bob', '--network', net)
        try:
            b.cli('network', 'sync', net)
        except AssertionError:
            pass
        keeper = h.cli('agent', 'register', '--name', 'keeper', '--owner', 'mia')
        raw = self.raw_for(h, keeper)
        rid = b.cli('send', 'mia/keeper', 'before the upgrade', '--network', net)['request']['request_id']
        t1 = b.cli('task', 'mia/keeper', 'offered before the upgrade', '--network', net)['request']['task_id']
        t2 = b.cli('task', 'mia/keeper', 'running before the upgrade', '--network', net)['request']['task_id']
        handoff = self.claim(raw, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid, timeout=60)
        need(handoff, 'the baseline host hands off the message')
        raw.call('POST', f"/adapter/v1/deliveries/{handoff['delivery']['id']}/forwarded", {})
        for tid in (t1, t2):
            need(self.claim(raw, '/adapter/v1/tasks/next', lambda v, tid=tid: v['task']['task_id'] == tid,
                            timeout=60), 'the baseline host hands off the task', tid)
        status, value = raw.call('POST', f'/adapter/v1/tasks/{t2}/accept', {})
        need(status == 200, 'accept before the upgrade', status, value)
        agents = h.cli('agent', 'list')
        h.stop()
        h.binary, h.cli_binary = str(self.daemon), str(self.cli_binary)
        h.start()
        need(user_version(h) == SCHEMA_VERSION, 'Shared state: the schema moves to the current version (19 since '
             'approved machine linking, transaction contract)', user_version(h))
        need(h.cli('agent', 'list') == agents, 'existing state is preserved')
        for table, columns in MIGRATED_COLUMNS.items():
            present = {r['name'] for r in rows(h, f'SELECT name FROM pragma_table_info(\'{table}\')')}
            need(columns <= present, f'Shared state: {table} gains {sorted(columns)}', sorted(present))
        row = rows(h, 'SELECT * FROM deliveries WHERE id=?', (handoff['delivery']['id'],))
        need(row and row[0]['seen_at'] and row[0]['redeliveries'] == 0 and row[0]['returned_at'] is None,
             'Upgrades: migration marks existing deliveries seen, with 0 redeliveries and null returned_at', row)
        for tid in (t1, t2):
            row = rows(h, 'SELECT * FROM task_deliveries WHERE task_id=?', (tid,))
            need(row and row[0]['seen_at'] and row[0]['cancel_seen_at'] and row[0]['redeliveries'] == 0
                 and row[0]['returned_at'] is None and row[0]['adopted_at'] is None,
                 'Upgrades: existing task deliveries seen (seen_at and cancel_seen_at), 0 redeliveries, null '
                 'returned_at and adopted_at', row)
        self.end(raw, host=h)
        fresh = self.raw_for(h, keeper)
        self.claims_nothing(fresh, '/adapter/v1/next', lambda v: v['request']['request_id'] == rid,
                            'nothing from before the upgrade is redelivered (message)')
        self.claims_nothing(fresh, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == t1,
                            'nothing from before the upgrade is redelivered (offered task)')
        # Q: adoption does not depend on seen, so a task running before the upgrade is read as adopted.
        adopted = self.claim(fresh, '/adapter/v1/tasks/next', lambda v: v['task']['task_id'] == t2, timeout=10)
        need(adopted and adopted.get('adopted') is True, 'a task running before the upgrade is adopted by the next '
             'verified session', adopted)
        h.stop()
        return '14 to 15'

    # --- the pairing ---------------------------------------------------------------------------------------

    def run(self):
        self.a, self.b = self.host('a'), self.host('b')
        # Each person's original key is that host's configured owner key, as `network create`/`join`
        # used to generate it there (decentralized-spec.md 6 step 3), so `allow`/`deny` find it.
        self.dec.install_key(self.a, 'alice')
        self.dec.install_key(self.b, 'bob')
        self.ids = {'a': self.a.start()['id'], 'b': self.b.start()['id']}
        created = self.dec.create(self.a, 'alice')
        self.net = created['id']
        self.dec.join(self.a, self.b, 'bob')
        self.dec.wait_members((self.a, self.b), 2)
        self.agent = {n: self.register(self.a, n, 'alice')
                      for n in ('quiet', 'eager', 'rawq', 'idle', 'launchy', 'oldproto', 'doomed', 'noproto',
                                'learner', 'otherproto')}
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
        for name in ('quiet', 'eager', 'launchy', 'oldproto', 'doomed', 'noproto', 'learner'):
            self.fixtures[name] = Fixture(self.root / 'fixtures' / name)
            self.profiles[name], out = self.profile(name, self.agent[name], self.fixtures[name])
            self.session_ids[name] = out['session_id']
        # A session of another harness: the Python/file fixture integration.
        bundles = fixture_catalog(self.root / 'other-integrations', identity=OTHER_HARNESS)
        directory = self.root / 'profiles' / 'otherproto'
        out = self.a.cli('session', 'setup', '--harness', OTHER_HARNESS, '--directory', str(directory), '--agent',
                         self.agent['otherproto']['id'], '--integrations', str(bundles), '--expires-in', '2h')
        need(out.get('session_id') and out.get('harness') == OTHER_HARNESS, 'session setup for otherproto', out)
        self.profiles['otherproto'], self.session_ids['otherproto'] = directory, out['session_id']

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
        self.section('wrong nonce and peerspan_ready', self.check_peerspan_ready)
        self.section('connected', self.check_connected)
        self.section('doctor', self.check_doctor)
        self.section('protocol', self.check_protocol)
        self.section('launch', self.check_launch)
        self.section('fatal stop', self.check_fatal)
        self.section('deadlines', self.check_deadlines)
        self.section('migration', self.check_migration)
        # Slice 2 (skipped with --slice1-only). These run while the silent session's timers do.
        if 2 in self.slices:
            for name, check in (('seen', self.check_seen),
                                ('redelivery after replacement', self.check_redelivery),
                                ('adoption', self.check_adoption),
                                ('delegation chain after replacement', self.check_chain),
                                ('pending work', self.check_pending),
                                ('launch settings', self.check_settings),
                                ('limits', self.check_limits),
                                ('migration to 15', self.check_migration15)):
                self.section(name, check)
        self.section('hello re-sent once', self.check_resend)
        self.section('item 13', self.check_item13)
        self.section('daemon restart', self.check_restart)

    def save_logs(self, directory):
        target = directory / re.sub(r'[^A-Za-z0-9]+', '-', self.label)
        target.mkdir(parents=True, exist_ok=True)
        for name, h in self.hosts.items():
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
            pass


def run_pairing(cli_binary, daemon_binary, node, baseline, label, logs=None, baseline14=None,
                slices=(1, 2)):
    with tempfile.TemporaryDirectory(prefix='peerspan-live-delivery-') as temporary:
        pairing = Pairing(label, cli_binary, daemon_binary, node, baseline, Path(temporary),
                          baseline14, slices)
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
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--node', type=Path, required=True, help='Node 22 or newer, for the MCP adapter')
    parser.add_argument('--baseline', type=Path,
                        help='a peerspan-host from before milestone 9 (schema 13), for the migration section')
    parser.add_argument('--baseline14', type=Path,
                        help='a peerspan-host from milestone 9 slice 1 (schema 14), for the migration to 15 section')
    parser.add_argument('--slice1-only', action='store_true',
                        help='skip the slice 2 sections (slice 1 sections always run: slice 2 runs inside their setup)')
    parser.add_argument('--pairing', action='append', help='CLI/DAEMON, such as Go/Rust; repeatable; default all four')
    parser.add_argument('--parallel', action='store_true', help='run the pairings at the same time')
    parser.add_argument('--logs', type=Path, help='save daemon and adapter logs of failing pairings here')
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
    baseline14 = args.baseline14.resolve() if args.baseline14 else None
    outcomes = {}

    def one(pairing):
        cli, _, daemon = pairing.partition('/')
        label = f'{cli} CLI, {daemon} daemon'
        outcomes[label] = run_pairing(binaries[cli], binaries[daemon], args.node.resolve(),
                                      baseline, label, args.logs, baseline14,
                                      (1,) if args.slice1_only else (1, 2))
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
