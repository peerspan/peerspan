#!/usr/bin/env python3
"""Live launch run (milestone 7 slice 5): three Claude Code sessions on the documented path.

Written from docs/launch-contract.md ("Slice 5: acceptance", Live run).

Three persons on one host as the invoking user: alice (Go), bob (Rust), and
carol (Go) by default (--mix). Preparation, not part of the path: the harness
builds capsule-coord and runs it on loopback (or, with --coordinator and
--coordinator-key, uses a deployed one), packages the bundles with it as
the default coordinator (as launch_acceptance.py does), and extracts them.
Each person has their own XDG_CONFIG_HOME, XDG_STATE_HOME, and daemon, run in
the foreground with `capsule run` from the installed bundle; HOME is shared,
so every Claude Code session uses the operator's existing login. No ssh-agent
is passed, so each person's key is generated.

Setup follows the team path with `allow everyone --delegate` in place of
`allow everyone`: alice creates the network and invites bob and carol, every
person allows everyone with delegation, and each runs `capsule attach claude`
in a project directory of their own, in a terminal the harness drives, with
Claude Code's built-in tools disabled (arguments after `--`). Before the flow,
the harness waits, without running any command of the path, until every host
has synced with coordination after the last `allow` and lists the others'
agents, so the run measures the models rather than coordination latency.

Flow: the harness prompts only alice's session. Alice's Claude calls
list_agents, then delegate_task to bob/claude by `to` with delegation_depth 1, asking for a short
review with a part to be passed on to carol; bob's Claude accepts and calls
delegate_task to carol/claude with parent_task_id; carol's completes; bob's
completes the parent with carol's result; alice's receives the final update,
then sends one message to carol/claude by `to` and gets a reply.

Mid-task /clear (docs/live-delivery-contract.md, Slice 2, Verification; live
mode, unless --no-clear): once bob's session has accepted alice's task and
passed a part on (bob's task `running` and his task to carol submitted, in host
state), the harness pauses carol's daemon (SIGSTOP) so carol's result cannot
finish bob's task first. Once bob's transcript has been quiet for a few
seconds, the harness records what the SessionStart hook's command (`capsule
session pending --hook` in bob's project) prints and types `/clear` into bob's
terminal. bob's session starts with empty context, and carol's daemon resumes
(SIGCONT); the Claude launch's SessionStart hook (matcher
`clear|compact|resume`) adds the pending work to it, and the model has the
`pending_work` tool. The run then checks from host state that bob's task still
succeeds, and from bob's post-/clear transcript that the model completed it and
either received the hook's context or called pending_work. bob's session runs
without `--disable-slash-commands` so `/clear` is the built-in command. In
--fixture mode nothing is cleared: bob's consumer calls pending_work and the
harness runs the hook's command at the same point, and the flow continues.

Verification, from host state: every task and message was submitted by an
adapter with directory access and has a `to`, and no route exists; carol's
task carries a two-link chain originating at alice; each task ended
completed (succeeded); the message has a reply.

Results go to docs/results/launch-live.json (live mode) with the commands, the
tool calls observed, task states, and model and version strings.

--fixture replaces the models with deterministic MCP consumers: the `claude`
that attach launches is a fixture that runs the configured MCP adapter and
hands its stdio to the harness over a private socket, and the harness makes
the same tool calls. It checks the harness, not model behavior; it writes
results only with --output.

Needs Python 3.12, Node 22, Go, Cargo, and npm; live mode also a logged-in
Claude Code allowed to use development channels.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import pty
import queue
import re
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_adapter import Channel  # noqa: E402
from claude_session import ClaudeSession, session_environment  # noqa: E402
from claude_session import wait_for as wait_live  # noqa: E402
from launch_acceptance import (REPO, external_coordinator, first_json, package_bundles,  # noqa: E402
                               start_coordinator, tail)
from tasks import channel_event, tool  # noqa: E402

PERSONS = ('alice', 'bob', 'carol')
NAMES = {'G': 'go', 'R': 'rust'}
TOOLS = ['capsule_ready', 'list_agents', 'send', 'send_status', 'reply', 'delegate_task', 'task_accept', 'task_reject',
         'task_progress', 'task_complete', 'task_status', 'pending_work', 'mark_seen']
CLEARED = 'bob'  # the person whose session gets /clear mid-task
FLOW_SECONDS = 600
READY_SECONDS = 120

# The fixture `claude` for --fixture: runs the MCP server from the generated
# configuration and relays its stdio to the harness over a private Unix socket.
FIXTURE = r'''#!/usr/bin/env python3
"""Fixture claude for live_launch_agents.py --fixture: relays the MCP adapter, no model."""
import json, os, socket, subprocess, sys, threading, time

args = sys.argv[1:]
if "--version" in args:
    print("2.1.291 (fixture)")
    sys.exit(0)
if args[:2] == ["auth", "status"]:
    print(json.dumps({"loggedIn": True, "authMethod": "claude.ai"}))
    sys.exit(0)
value = args[args.index("--mcp-config") + 1]
config = json.loads(value) if value.lstrip().startswith("{") else json.load(open(value))
server = config["mcpServers"]["capsule"]
with open(os.environ["CAPSULE_LIVE_FIXTURE_LOG"], "a") as f:
    f.write(json.dumps({"time": time.time(), "pid": os.getpid(), "arguments": args, "cwd": os.getcwd()}) + "\n")
errors = open(os.environ["CAPSULE_LIVE_FIXTURE_LOG"] + ".server", "ab")
child = subprocess.Popen([server["command"], *server.get("args", [])], env={**os.environ, **server.get("env", {})},
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
path = os.environ["CAPSULE_LIVE_FIXTURE_SOCKET"]
listener = socket.socket(socket.AF_UNIX)
listener.bind(path)
os.chmod(path, 0o600)
listener.listen(1)
connection, _ = listener.accept()


def upstream():
    for line in connection.makefile("rb"):
        child.stdin.write(line)
        child.stdin.flush()
    child.stdin.close()


threading.Thread(target=upstream, daemon=True).start()
for line in child.stdout:
    connection.sendall(line)
sys.exit(child.wait() or 1)
'''


class RelayedChannel(Channel):
    """agent_adapter.Channel's MCP client, over the fixture claude's socket."""

    def __init__(self, path, seconds=60):
        deadline = time.monotonic() + seconds
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.connect(str(path))
                break
            except OSError:
                self.sock.close()
                if time.monotonic() > deadline:
                    raise AssertionError(f'the fixture claude never opened {path}')
                time.sleep(0.2)

        class Pipe:
            pass
        self.process = Pipe()
        self.process.stdin = self.sock.makefile('w')
        self.process.stdout = self.sock.makefile('r')
        self.events = queue.Queue()
        self.notifications = []
        self.count = 0
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        result = self.call('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                         'clientInfo': {'name': 'capsule-live-fixture', 'version': '1'}})
        assert result['capabilities']['experimental'] == {'claude/channel': {}}, result
        self.protocol = result['protocolVersion']
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        self.handshake()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class Person:
    def __init__(self, name, impl, root, bundle, claude_dir, node):
        self.name, self.impl = name, impl
        self.root = root / name
        self.config = self.root / 'config'
        self.statehome = self.root / 'state'
        self.project = self.root / 'project'
        for path in [self.root, self.config, self.statehome, self.project]:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.bin = bundle / 'bin'
        env = {key: value for key, value in session_environment().items()
               if key not in ('SSH_AUTH_SOCK', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME')}
        env.update(XDG_CONFIG_HOME=str(self.config), XDG_STATE_HOME=str(self.statehome),
                   PATH=f'{self.bin}:{claude_dir}:{node.parent}:{env.get("PATH", "/usr/bin:/bin")}',
                   CAPSULE_LIVE_FIXTURE_SOCKET=str(self.root / 'claude.sock'),
                   CAPSULE_LIVE_FIXTURE_LOG=str(self.root / 'claude-fixture.jsonl'))
        self.env = env
        self.daemon = None
        self.attach_process = None

    def start(self, commands):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        self.log = open(self.root / 'daemon.log', 'wb')
        argv = ['capsule', 'run', '--peer-listen', f'127.0.0.1:{port}']
        self.daemon = subprocess.Popen(argv, env=self.env, cwd=self.root, stdout=self.log, stderr=self.log,
                                       start_new_session=True)
        commands.append({'person': self.name, 'command': ' '.join(argv), 'kind': 'daemon (foreground)'})
        deadline = time.monotonic() + 20
        while True:
            result = self.run('status', '--json')
            if result.returncode in (0, 1) and first_json(result.stdout) and 'host_id' in first_json(result.stdout):
                self.state = self.statehome / 'capsule' / 'host'
                self.host_id = first_json(result.stdout)['host_id']
                return
            if self.daemon.poll() is not None or time.monotonic() > deadline:
                raise AssertionError(f'{self.name}\'s daemon did not start: {tail((self.root / "daemon.log").read_text())}')
            time.sleep(0.2)

    def run(self, *args, timeout=120):
        return subprocess.run(['capsule', *args], env=self.env, cwd=self.root, capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL)

    def step(self, commands, command, shown=None):
        argv = command.split() if isinstance(command, str) else command
        result = self.run(*argv[1:])
        commands.append({'person': self.name, 'implementation': self.impl, 'command': shown or ' '.join(argv),
                         'kind': 'capsule', 'exit': result.returncode})
        print(f'  {self.name}$ {shown or " ".join(argv)} -> exit {result.returncode}', flush=True)
        if result.returncode != 0:
            raise AssertionError(f'{self.name}: `{shown or " ".join(argv)}` exited {result.returncode}\n'
                                 f'{tail(result.stdout)}\n{tail(result.stderr)}')
        return result

    def json(self, *args):
        result = self.run(*args)
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return json.loads(result.stdout)

    def sql(self, statement, args=()):
        with sqlite3.connect(f'file:{self.state / "host.db"}?mode=ro', uri=True, timeout=10) as conn:
            return conn.execute(statement, args).fetchall()

    def stop(self):
        for process in [self.attach_process, self.daemon]:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass


class AttachedSession(ClaudeSession):
    """A real Claude Code session started by `capsule attach claude` in a terminal the harness drives.

    Capsule's launch supplies the MCP configuration and channel; the arguments
    after `--` restrict the experiment as live_delegation.py's sessions do."""

    def __init__(self, person, allowed_tools, slash_commands=False):
        self.directory = person.project
        self.cleared_at = None
        self.sid = str(uuid.uuid4())
        self.console = bytearray()
        self.debug_path = person.root / 'claude-debug.log'
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 120, 0, 0))

        def terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        # No `--settings` here: Capsule's launch passes its own (the SessionStart
        # hook) and refuses another. `--setting-sources ''` still keeps the
        # operator's user, project, and local settings (and their hooks) out.
        self.arguments = [
            '--session-id', self.sid, '--strict-mcp-config',
            '--setting-sources', '', '--tools', '', '--allowedTools',
            ','.join('mcp__capsule__' + name for name in allowed_tools), '--permission-mode', 'dontAsk',
            *([] if slash_commands else ['--disable-slash-commands']), '--debug-file', str(self.debug_path)]
        self.command = ['capsule', 'attach', 'claude', '--', *self.arguments]
        self.process = subprocess.Popen(self.command, cwd=person.project, stdin=slave, stdout=slave, stderr=slave,
                                        env=person.env, preexec_fn=terminal)
        os.close(slave)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def transcript_paths(self):
        """The --session-id transcript, then, after /clear, the transcripts of the sessions it started.

        /clear starts a new session (a new ID and transcript) in the same terminal;
        each person's project directory, and so its transcript directory, is its own."""
        own = super().transcript_paths()
        return own + self.later_paths(own)

    def later_paths(self, own=None):
        own = super().transcript_paths() if own is None else own
        if self.cleared_at is None or not own:
            return []
        later = [p for p in own[0].parent.glob('*.jsonl')
                 if p.stem != self.sid and p.stat().st_mtime >= self.cleared_at - 2]
        return sorted(later, key=lambda p: p.stat().st_mtime)


def transcript_entries(session, paths=None):
    entries = []
    for path in session.transcript_paths() if paths is None else paths:
        for line in path.read_text().splitlines():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def assistant_text(session):
    return '\n'.join(block.get('text', '') for entry in transcript_entries(session) if entry.get('type') == 'assistant'
                     for block in entry.get('message', {}).get('content', [])
                     if isinstance(block, dict) and block.get('type') == 'text')


def models(session):
    return sorted({entry['message']['model'] for entry in transcript_entries(session)
                   if entry.get('type') == 'assistant' and isinstance(entry.get('message'), dict)
                   and entry['message'].get('model')})


# Setup: the team path with `allow everyone --delegate`.

def setup(people, commands, attach):
    """Returns the time of the last `allow`."""
    alice, bob, carol = people
    alice.step(commands, 'capsule network create acme')
    tokens = {}
    for person in (bob, carol):
        result = alice.step(commands, f'capsule invite {person.name}')
        match = re.search(r'capsule join ([^\s"\']+)', result.stdout)
        assert match, f'invite printed no join line: {result.stdout}'
        tokens[person.name] = match.group(1)
    alice.step(commands, 'capsule allow everyone --delegate')
    attach(alice)
    last_allow = None
    for person in (bob, carol):
        token = tokens[person.name]
        person.step(commands, ['capsule', 'join', token], shown='capsule join TOKEN')
        person.step(commands, 'capsule allow everyone --delegate')
        last_allow = datetime.now(timezone.utc)
        attach(person)
    return last_allow


def parse_time(text):
    """RFC 3339 with up to nanoseconds."""
    match = re.match(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$', text or '')
    if not match:
        return None
    zone = '+00:00' if match.group(3) == 'Z' else match.group(3)
    return datetime.fromisoformat(match.group(1) + '.' + (match.group(2) or '0')[:6].ljust(6, '0') + zone)


def wait_ready(people, after):
    """Not a path step: every host synced after the last allow, and lists the others' agents."""
    def synced():
        for person in people:
            status = first_json(person.run('status', '--json').stdout) or {}
            networks = status.get('networks') or []
            if not networks or any((parse_time(n.get('last_sync_at')) or after) <= after for n in networks):
                return False
        return True
    wait_live(synced, READY_SECONDS)

    def listed():
        for person in people:
            value = first_json(person.run('agents', '--json', '--refresh').stdout) or {}
            reachable = {e.get('address'): e for e in value.get('reachable', [])}
            for other in people:
                if other is person:
                    continue
                entry = reachable.get(other.address)
                if not entry or not entry.get('connected') or 'task.delegate' not in (entry.get('actions') or []):
                    return False
        return True
    wait_live(listed, READY_SECONDS)


def attach_fixture(person, commands, root):
    out = open(person.root / 'attach.out', 'w+')
    err = open(person.root / 'attach.err', 'w+')
    person.attach_process = subprocess.Popen(['capsule', 'attach', 'claude'], cwd=person.project, env=person.env,
                                             stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                             start_new_session=True)
    commands.append({'person': person.name, 'implementation': person.impl, 'command': 'capsule attach claude',
                     'kind': 'capsule', 'background': True, 'cwd': 'project'})
    print(f'  {person.name}$ capsule attach claude (background)', flush=True)
    try:
        channel = RelayedChannel(person.root / 'claude.sock')
    except AssertionError:
        err.seek(0)
        out.seek(0)
        raise AssertionError(f'{person.name}: attach did not launch the fixture claude (exit '
                             f'{person.attach_process.poll()}): {tail(out.read())} {tail(err.read())}')
    err.seek(0)
    output = first_json(err.read())
    assert output and output['agent']['address'], f'{person.name}: attach printed no output object on stderr'
    person.address = output['agent']['address']
    person.agent_id = output['agent']['id']
    person.attached = output
    return channel


def attach_live(person, commands, slash_commands=False):
    session = AttachedSession(person, TOOLS, slash_commands)
    commands.append({'person': person.name, 'implementation': person.impl,
                     'command': 'capsule attach claude -- ' + ' '.join(
                         repr(a) if a == '' or ' ' in a or '"' in a else a for a in session.arguments),
                     'kind': 'capsule', 'background': True, 'cwd': 'project', 'terminal': True})
    print(f'  {person.name}$ capsule attach claude -- … (terminal)', flush=True)
    return session


def attached_output(person, session):
    """attach prints its output object on stderr (the terminal) before launching."""
    def found():
        text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', session.console.decode(errors='replace'))
        match = re.search(r'"address"\s*:\s*"([^"]+)"', text)
        agent = re.search(r'"id"\s*:\s*"(agent_[0-9a-f]+)"', text)
        return (match.group(1), agent.group(1)) if match and agent else None
    person.address, person.agent_id = wait_live(found, 60)


# Flows.

def review_input(nonce):
    return (f'Review request {nonce} from alice. Review this Python function in one or two sentences: '
            '`def mean(xs): return sum(xs) / len(xs) - 1`. Pass one part on: call delegate_task with to '
            '"carol/claude", parent_task_id set to this task\'s task_id, and input "Suggest a corrected one-line '
            'version of: def mean(xs): return sum(xs) / len(xs) - 1". When carol\'s kind=task_update event with '
            'state succeeded arrives, complete this task with task_complete, status succeeded, and output your '
            'review followed by "CAROL SAYS: " and carol\'s output verbatim.')


def fixture_flow(people, channels, nonce):
    alice, bob, carol = people
    a, b, c = (channels[p.name] for p in people)
    observed = {p.name: [] for p in people}

    def call(person, channel, name, arguments):
        failed, out = tool(channel, name, arguments)
        observed[person.name].append({'tool': name, 'input': arguments, 'error': failed})
        assert not failed, (person.name, name, out)
        return out

    listing = call(alice, a, 'list_agents', {})
    addresses = {entry['address'] for entry in (listing if isinstance(listing, list) else listing.get('agents', []))}
    assert {bob.address, carol.address} <= addresses, listing
    parent_out = call(alice, a, 'delegate_task', {'to': bob.address, 'delegation_depth': 1,
                                                  'input': review_input(nonce)})
    assert parent_out['submit_state'] == 'accepted', parent_out
    parent = channel_event(b, 'task')
    parent_id = parent['meta']['task_id']
    assert parent['meta'].get('delegable') is True, ('bob\'s task is not delegable', parent['meta'])
    call(bob, b, 'task_accept', {'task_id': parent_id})
    arguments = {'to': carol.address, 'parent_task_id': parent_id,
                 'input': 'Suggest a corrected one-line version of: def mean(xs): return sum(xs) / len(xs) - 1'}
    failed, sub_out = tool(b, 'delegate_task', arguments)
    observed['bob'].append({'tool': 'delegate_task', 'input': arguments, 'error': failed})
    assert not failed, ('bob could not pass the task on with parent_task_id', sub_out,
                        {k: parent['meta'].get(k) for k in ('delegable', 'chain_hosts', 'originator_host_id')})
    assert sub_out['submit_state'] == 'accepted', sub_out
    # Where the live run clears bob's session: bob's task running, his part
    # passed on. No /clear here; bob's consumer asks for pending work and the
    # harness runs the SessionStart hook's command, then the flow continues.
    pending = call(bob, b, 'pending_work', {})
    midtask = {'parent_task_id': parent_id, 'pending_work': pending, 'hook_command': hook_pending(bob)}
    child = channel_event(c, 'task')
    child_id = child['meta']['task_id']
    call(carol, c, 'task_accept', {'task_id': child_id})
    carol_output = f'CAROL_RESULT_{nonce}: def mean(xs): return sum(xs) / len(xs)'
    call(carol, c, 'task_complete', {'task_id': child_id, 'status': 'succeeded', 'output': carol_output})
    while True:
        update = channel_event(b, 'task_update')
        if update['meta']['state'] == 'succeeded':
            break
    call(bob, b, 'task_complete', {'task_id': parent_id, 'status': 'succeeded',
                                   'output': 'The function subtracts 1 from the mean. CAROL SAYS: ' + update['content']})
    while True:
        final = channel_event(a, 'task_update')
        if final['meta']['state'] == 'succeeded':
            break
    sent = call(alice, a, 'send', {'to': carol.address, 'content': f'Thanks for the fix ({nonce}); one sentence back?'})
    message = channel_event(c, 'message')
    result = c.reply(message['meta']['delivery_id'], f'CAROL_REPLY_{nonce}: glad to help.')
    observed['carol'].append({'tool': 'reply', 'input': {'delivery_id': message['meta']['delivery_id']},
                              'error': result.get('isError', False)})
    reply = channel_event(a, 'reply')
    return {'tool_calls': observed, 'alice_final_update': final['content'], 'alice_reply_event': reply['content'],
            'send': sent, 'carol_task_meta': child['meta'], 'midtask': midtask}


def live_prompt(nonce):
    return ('This is a Capsule integration experiment. Use only Capsule tools. (1) Call list_agents. '
            '(2) Call delegate_task with to "bob/claude", delegation_depth 1, and this input, verbatim: "' + review_input(nonce).replace('"', "'")
            + '" (3) The delegate_task result is not the result: kind=task_update events for that task will arrive; '
            'ignore them until one has state succeeded, then respond in your terminal with exactly two lines: '
            'ALICE_RESULT_OBSERVED, then that event\'s content verbatim. (4) Then call send with to "carol/claude" '
            'and content "Thanks for the fix; please reply with one sentence." (5) When the kind=reply event arrives, '
            'respond in your terminal with ALICE_REPLY_OBSERVED followed by the reply content. Do nothing else.')


def received_task(person):
    """The one task this person's host received: (task_id, state), or (None, None)."""
    rows = person.sql('SELECT task_id, record FROM received_tasks ORDER BY rowid')
    return (rows[0][0], json.loads(rows[0][1]).get('state')) if rows else (None, None)


def hook_pending(person):
    """What the SessionStart hook's command prints now: `capsule session pending --hook` in the
    person's project directory, with no --state, as the hook runs it. `output` is the pending
    work object carried in its additionalContext, after the fixed lead sentence."""
    result = subprocess.run(['capsule', 'session', 'pending', '--hook'], env=person.env, cwd=person.project,
                            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    hook = first_json(result.stdout) or {}
    context = (hook.get('hookSpecificOutput') or {}).get('additionalContext') or ''
    return {'exit': result.returncode, 'context_lead': context[:context.find('{')].strip(),
            'output': first_json(context[context.find('{'):]) if '{' in context else None,
            'stderr': tail(result.stderr)}


def lists_running(pending, task_id):
    tasks = (pending or {}).get('tasks') if isinstance(pending, dict) else None
    return bool(task_id) and any(t.get('task_id') == task_id and t.get('state') == 'running' for t in tasks or [])


def adapter_count(person):
    return len(person.sql('SELECT c.id FROM adapter_credentials c JOIN sessions s ON s.id = c.session_id '
                          'WHERE s.agent_id = ?', (person.agent_id,)))


def clear_mid_task(people, session):
    """Types /clear into bob's terminal while his task is running; returns what was recorded then."""
    _alice, bob, carol = people

    def passed_on():
        _tid, state = received_task(bob)
        if state is not None and state not in ('queued', 'running'):
            return 'too_late'
        if state == 'running' and bob.sql('SELECT 1 FROM outbound_tasks'):
            # Pause carol's daemon so her result cannot reach bob, and finish
            # his task, before /clear. It resumes once /clear has taken.
            carol.daemon.send_signal(signal.SIGSTOP)
            return 'ready'
        return None
    try:
        return clear_paused(people, session, wait_live(passed_on, FLOW_SECONDS))
    finally:
        carol.daemon.send_signal(signal.SIGCONT)


def clear_paused(people, session, stage):
    _alice, bob, _carol = people
    # Let bob's turn end (the transcript quiet for 5 s, at most 90 s), so /clear
    # is not typed into a running turn.
    def size():
        return sum(p.stat().st_size for p in session.transcript_paths() if p.exists())
    last, since, start = size(), time.monotonic(), time.monotonic()
    while time.monotonic() - start < 90:
        time.sleep(0.5)
        now = size()
        if now != last:
            last, since = now, time.monotonic()
        elif time.monotonic() - since >= 5:
            break
    parent_id, parent_state = received_task(bob)
    record = {
        'person': CLEARED, 'stage_before_clear': stage, 'waited_for_quiet_seconds': round(time.monotonic() - start, 1),
        'parent_task_id': parent_id, 'bob_parent_state_at_clear': parent_state,
        'carol_daemon_paused_at_clear': True,
        'hook_command_at_clear': hook_pending(bob), 'bob_adapters_at_clear': adapter_count(bob),
        'session_id_before_clear': session.sid,
    }
    record['debug_offset'] = len(session.debug())
    session.cleared_at = time.time()
    record['cleared_at'] = datetime.now(timezone.utc).isoformat()
    print(f'Typing /clear into {CLEARED}\'s session (task {parent_state}).', flush=True)
    os.write(session.master, b'/clear')
    time.sleep(1)
    os.write(session.master, b'\r')

    def took():
        return bool(session.later_paths()) or 'SessionStart' in session.debug()[record['debug_offset']:]
    enters = 1
    try:
        wait_live(took, 20)
    except AssertionError:
        # The command menu may take the first Enter to complete `/clear`; a
        # second Enter runs it, and on an empty prompt does nothing.
        os.write(session.master, b'\r')
        enters = 2
        try:
            wait_live(took, 20)
        except AssertionError:
            pass
    record['enters_sent'] = enters
    return record


def clear_evidence(session, record):
    """After the flow: what bob's session shows after /clear, from its transcripts and debug log."""
    later = session.later_paths()
    parent_id = record['parent_task_id']
    hook_entries = []
    for path in later:
        for line in path.read_text().splitlines():
            if 'hook_additional_context' in line and 'SessionStart' in line:
                hook_entries.append({'transcript': path.stem, 'mentions_parent_task': bool(parent_id) and parent_id in line,
                                     'excerpt': line[:1500]})
    after = {t: session.tool_exchanges('mcp__capsule__' + t, later) for t in TOOLS}
    debug = session.debug()[record['debug_offset']:]
    return {
        'session_ids_after_clear': [p.stem for p in later],
        'session_start_hook_context_entries': hook_entries,
        'debug_session_start_lines': [line[:300] for line in debug.splitlines() if 'SessionStart' in line][:20],
        'tool_calls_after_clear': {t: calls for t, calls in after.items() if calls},
        'pending_work_called_after_clear': bool(after['pending_work']),
        'completed_parent_after_clear': any(
            (c['input'] or {}).get('task_id') == parent_id and (c['input'] or {}).get('status') == 'succeeded'
            for c in after['task_complete']),
        'bob_adapters_after_flow': None,
    }


def live_flow(people, sessions, nonce, clear):
    alice = sessions['alice']
    print('Three interactive Claude sessions registered their Capsule channels; prompting alice only.', flush=True)
    pids = {name: s.process.pid for name, s in sessions.items()}
    alice.prompt(live_prompt(nonce))
    cleared = clear_mid_task(people, sessions[CLEARED]) if clear else None
    wait_live(lambda: alice.assistant_said('ALICE_RESULT_OBSERVED'), FLOW_SECONDS)
    print('Alice reported the final update.', flush=True)
    wait_live(lambda: alice.assistant_said('ALICE_REPLY_OBSERVED')
              or 'ALICE_REPLY_OBSERVED' in assistant_text(alice), FLOW_SECONDS)
    print('Alice reported the reply.', flush=True)
    assert {name: s.process.pid for name, s in sessions.items()} == pids
    if cleared is not None:
        cleared.update(clear_evidence(sessions[CLEARED], cleared))
        cleared['bob_adapters_after_flow'] = adapter_count(people[1])
    return {
        'clear': cleared,
        'tool_calls': {name: {t: s.tool_exchanges('mcp__capsule__' + t) for t in TOOLS if s.tool_exchanges('mcp__capsule__' + t)}
                       for name, s in sessions.items()},
        'alice_text': assistant_text(alice),
        'models': {name: models(s) for name, s in sessions.items()},
        'protocols': [m.group(1) if (m := re.search(r'"negotiatedProtocolVersion"\s*:\s*"([^"]+)"',
                                                    s.debug().replace('\\"', '"'))) else None
                      for s in sessions.values()],
    }


# Verification from host state.

def records(person, statement, args=()):
    return [json.loads(row[0]) for row in person.sql(statement, args)]


def verify(people):
    """The contract's checks, from each host's database (the shared schema) and owner CLI records."""
    alice, bob, carol = people
    r = {}
    adapters = {}
    for person in people:
        adapters[person.name] = {
            rec['id']: rec for rec in records(
                person, 'SELECT c.record FROM adapter_credentials c JOIN sessions s ON s.id = c.session_id '
                        'WHERE s.agent_id = ?', (person.agent_id,))}
    r['every_attached_adapter_has_directory_access'] = all(
        recs and all(rec.get('directory') is True for rec in recs.values()) for recs in adapters.values())
    r['no_route_exists'] = all(not person.sql('SELECT 1 FROM adapter_routes') for person in people)
    # Each session called capsule_ready (live delivery contract, slice 1), so its
    # channel is verified and status shows no channel_unverified item.
    r['every_attached_channel_verified'] = all(
        recs and all(person.sql('SELECT channel_verified_at FROM adapter_connections WHERE adapter_id = ? '
                                'AND channel_verified_at IS NOT NULL', (adapter_id,)) for adapter_id in recs)
        for person, recs in ((p, adapters[p.name]) for p in people))
    r['no_channel_unverified_item'] = all(
        not [i for i in (first_json(person.run('status', '--json').stdout) or {}).get('attention', [])
             if i.get('kind') == 'channel_unverified'] for person in people)

    tasks = {person.name: records(person, 'SELECT record FROM outbound_tasks') for person in people}
    r['one_task_each_from_alice_and_bob_none_from_carol'] = (
        len(tasks['alice']) == 1 and len(tasks['bob']) == 1 and tasks['carol'] == [])
    t0, t1 = (tasks['alice'] or [{}])[0], (tasks['bob'] or [{}])[0]
    t0_id, t1_id = t0.get('request', {}).get('task_id'), t1.get('request', {}).get('task_id')
    r['tasks_submitted_by_directory_adapters_with_to'] = (
        t0.get('adapter_id') in adapters['alice'] and t1.get('adapter_id') in adapters['bob']
        and t0.get('to') == bob.address and t1.get('to') == carol.address
        and not t0.get('route_id') and not t1.get('route_id'))
    r['bob_task_passed_on_with_parent'] = (t1.get('parent') or {}).get('task_id') == t0_id and t0_id is not None

    received = carol.sql('SELECT request, record FROM received_tasks WHERE task_id = ?', (t1_id,))
    request = json.loads(received[0][0]) if received else {}
    chain = request.get('delegation') or []
    r['carol_task_two_link_chain_from_alice'] = (
        len(chain) == 2
        and [link.get('issuer_host_id') for link in chain] == [alice.host_id, bob.host_id]
        and [link.get('audience_host_id') for link in chain] == [bob.host_id, carol.host_id]
        and all(link.get('originator_agent_id') == alice.agent_id for link in chain)
        and chain[0].get('task_id') == t0_id and chain[1].get('task_id') == t1_id
        and [link.get('depth') for link in chain] == [1, 0])

    def states():
        found = {
            'alice_view_of_bob_task': alice.json('task', 'inspect', '--peer', bob.host_id, t0_id)['status']['state']
            if t0_id else None,
            'bob_view_of_carol_task': bob.json('task', 'inspect', '--peer', carol.host_id, t1_id)['status']['state']
            if t1_id else None,
        }
        for person, sender, tid, key in [(bob, alice, t0_id, 'bob_received'), (carol, bob, t1_id, 'carol_received')]:
            rows = person.sql('SELECT record FROM received_tasks WHERE sender = ? AND task_id = ?', (sender.host_id, tid))
            found[key] = json.loads(rows[0][0]).get('state') if rows else None
        return found
    deadline = time.monotonic() + 60
    while True:
        task_states = states()
        if set(task_states.values()) == {'succeeded'} or time.monotonic() > deadline:
            break
        time.sleep(1)
    r['each_task_completed'] = set(task_states.values()) == {'succeeded'}

    sends = alice.sql('SELECT peer, request_id, adapter_id, route_id FROM adapter_outbound')
    messages = []
    for peer, request_id, adapter_id, route_id in sends:
        rows = alice.sql('SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?', (peer, request_id))
        record = json.loads(rows[0][0]) if rows else {}
        replies = alice.sql('SELECT record FROM outbound_replies WHERE peer = ? AND request_id = ?', (peer, request_id))
        messages.append({'peer': peer, 'request_id': request_id, 'adapter_id': adapter_id, 'route_id': route_id,
                         'to': record.get('to'), 'state': record.get('state'), 'reply': bool(replies)})
    r['one_message_by_alice_directory_adapter_with_to'] = (
        len(messages) == 1 and messages[0]['adapter_id'] in adapters['alice'] and not messages[0]['route_id']
        and messages[0]['to'] == carol.address and messages[0]['peer'] == carol.host_id)
    r['message_has_reply'] = len(messages) == 1 and messages[0]['reply']
    others = [person.name for person in (bob, carol) if person.sql('SELECT 1 FROM adapter_outbound')]
    r['only_alice_sent_messages'] = not others
    return r, task_states, {'parent': t0_id, 'subtask': t1_id, 'chain': chain, 'messages': messages}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--node', type=Path, default=Path('node'), help='Node 22 executable')
    parser.add_argument('--claude', type=Path, help='Claude Code executable; required unless --fixture')
    parser.add_argument('--mix', default='GRG', help='implementations of alice, bob, and carol (default GRG)')
    parser.add_argument('--fixture', action='store_true', help='deterministic MCP consumers instead of models')
    parser.add_argument('--repo', type=Path, default=REPO, help='checkout to package from')
    parser.add_argument('--output', type=Path, help='results file (default docs/results/launch-live.json when live)')
    parser.add_argument('--keep', action='store_true', help='keep the work directory')
    parser.add_argument('--coordinator', metavar='HOST:PORT',
                        help='use this deployed coordinator instead of one on loopback; needs --coordinator-key '
                             'and, when live, --output')
    parser.add_argument('--coordinator-key', metavar='KEY', help="the deployed coordinator's public key")
    parser.add_argument('--no-clear', action='store_true', help='live mode: skip the mid-task /clear in bob\'s session')
    args = parser.parse_args()
    if not args.fixture and not args.claude:
        parser.error('--claude is required unless --fixture')
    if bool(args.coordinator) != bool(args.coordinator_key):
        parser.error('--coordinator and --coordinator-key go together')
    if args.coordinator and not args.fixture and not args.output:
        parser.error('--output is required with --coordinator')
    if len(args.mix) != 3 or set(args.mix) - set(NAMES):
        parser.error('--mix is three of G and R')
    output = args.output or (None if args.fixture else REPO / 'docs/results/launch-live.json')
    node = Path(shutil.which(str(args.node)) or args.node).resolve()
    impls = [NAMES[c] for c in args.mix]

    def interrupted(number, _frame):
        raise KeyboardInterrupt(f'signal {number}')
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)

    work = Path(tempfile.mkdtemp(prefix='capsule-live-', dir='/var/tmp'))
    coord = None
    people = []
    channels = {}
    sessions = {}
    commands = []
    try:
        (work / 'bin').mkdir()
        if args.coordinator:
            coord, address, key = external_coordinator(args.coordinator, args.coordinator_key)
        else:
            coord, address, key = start_coordinator(args.repo.resolve(), work)
        archives, release = package_bundles(args.repo.resolve(), node, work, address, key, sorted(set(impls)))
        bundles = {}
        for impl, (archive, _checksum, root) in archives.items():
            subprocess.run(['tar', '-xzf', str(archive), '-C', str(work)], check=True)
            bundles[impl] = work / root
        claude_dir = work / 'claude-bin'
        claude_dir.mkdir()
        if args.fixture:
            (claude_dir / 'claude').write_text(FIXTURE)
            (claude_dir / 'claude').chmod(0o755)
        else:
            (claude_dir / 'claude').symlink_to(args.claude.resolve())
        people = [Person(name, impl, work, bundles[impl], claude_dir, node) for name, impl in zip(PERSONS, impls)]
        for person in people:
            person.start(commands)
        nonce = os.urandom(3).hex()

        def attach(person):
            if args.fixture:
                channels[person.name] = attach_fixture(person, commands, work)
            else:
                sessions[person.name] = attach_live(person, commands,
                                                    slash_commands=person.name == CLEARED and not args.no_clear)
                attached_output(person, sessions[person.name])
                # Accept the workspace and development-channel confirmations, as the person would.
                sessions[person.name].ready()
        last_allow = setup(people, commands, attach)
        wait_ready(people, last_allow)
        print('Every host synced and lists the others; starting the flow.', flush=True)
        if args.fixture:
            observed = fixture_flow(people, channels, nonce)
        else:
            observed = live_flow(people, sessions, nonce, not args.no_clear)
        verified, states, ids = verify(people)
        if not args.fixture:
            verified['every_session_called_capsule_ready'] = all(
                'capsule_ready' in calls for calls in observed['tool_calls'].values()) and len(observed['tool_calls']) == 3
        if args.fixture:
            midtask = observed['midtask']
            verified['bob_pending_work_listed_running_task_midtask'] = lists_running(
                midtask['pending_work'], midtask['parent_task_id'])
            verified['hook_command_listed_running_task_midtask'] = (
                midtask['hook_command']['exit'] == 0
                and lists_running(midtask['hook_command']['output'], midtask['parent_task_id']))
        elif observed['clear'] is not None:
            cleared = observed['clear']
            verified['hook_command_listed_running_task_midtask'] = (
                cleared['hook_command_at_clear']['exit'] == 0
                and lists_running(cleared['hook_command_at_clear']['output'], cleared['parent_task_id']))
            verified['bob_task_running_when_cleared'] = cleared['bob_parent_state_at_clear'] == 'running'
            verified['bob_session_restarted_by_clear'] = bool(cleared['session_ids_after_clear'])
            verified['bob_given_pending_work_after_clear'] = (
                any(e['mentions_parent_task'] for e in cleared['session_start_hook_context_entries'])
                or cleared['pending_work_called_after_clear'])
            verified['bob_completed_task_after_clear'] = (
                cleared['completed_parent_after_clear'] and states.get('bob_received') == 'succeeded')
        print('Verified from host state:', json.dumps(verified, indent=2), flush=True)
        failed = [k for k, v in verified.items() if not v]
        report = {
            'checked_at': datetime.now(timezone.utc).isoformat(),
            'mode': 'fixture' if args.fixture else 'live',
            'contract': 'docs/launch-contract.md, Slice 5: acceptance (live run); docs/live-delivery-contract.md, '
                        'Slice 2: Verification (mid-task /clear)',
            'coordinator': ({'address': args.coordinator, 'public_key': args.coordinator_key,
                             'description': 'deployed coordinator, built into the bundles as the default'}
                            if args.coordinator else
                            'capsule-coord from the checkout on loopback, built into the bundles as the default'),
            'persons': {p.name: {'implementation': p.impl, 'address': p.address, 'host_id': p.host_id} for p in people},
            'release': release,
            'commands': commands,
            'task_states': states,
            'harness_verified': verified,
            'ids': {'parent_task': ids['parent'], 'subtask': ids['subtask'],
                    'chain_issuers': [link.get('issuer_host_id') for link in ids['chain']]},
            'messages': ids['messages'],
            'tool_calls': observed['tool_calls'],
        }
        if args.fixture:
            report['evidence'] = ('harness_verified comes from host databases and owner CLI records read after the '
                                  'flow; tool_calls are the deterministic consumers\' own calls.')
            report['limitations'] = ['Deterministic MCP consumers, no model: this checks the harness and the flow, '
                                     'not model use.',
                                     'No /clear happens in fixture mode; there is no Claude Code session or '
                                     'SessionStart hook. At the point the live run clears bob\'s session, bob\'s '
                                     'consumer calls pending_work and the harness runs the hook\'s command '
                                     '(`capsule session pending --hook` in bob\'s project); the flow then continues.']
            report['clear'] = {'performed': False, 'midtask': observed['midtask']}
        else:
            report['claude_version'] = subprocess.check_output([str(args.claude.resolve()), '--version'],
                                                               text=True).strip()
            report['models'] = observed['models']
            report['mcp_protocols'] = observed['protocols']
            report['alice_terminal_text'] = observed['alice_text'][-4000:]
            report['evidence'] = ('harness_verified comes from host databases and owner CLI records read after the '
                                  'flow; tool_calls come from each session\'s own transcript; alice_terminal_text is '
                                  'the model\'s own report, not host state.')
            report['limitations'] = [
                'Three persons as one OS user on one host, not separate machines; '
                + ('coordination over the internet to the deployed coordinator, peer traffic on this host.'
                   if args.coordinator else 'over loopback.'),
                'Alice\'s prompt names the tools and addresses; bob and carol were not prompted and acted on the '
                'channel events alone, following the instructions alice\'s task carried.',
            ]
            if observed['clear'] is None:
                report['clear'] = {'performed': False, 'note': '--no-clear'}
            else:
                report['clear'] = {'performed': True, **observed['clear']}
                report['evidence'] += (
                    ' clear: bob_task_running_when_cleared and the hook command output are host state read just '
                    'before /clear was typed; bob_session_restarted_by_clear means a new transcript (session ID) '
                    'appeared in bob\'s project transcript directory after /clear; bob_given_pending_work_after_clear '
                    'means a post-/clear transcript holds a SessionStart hook_additional_context entry naming bob\'s '
                    'task, or the model called pending_work after /clear; bob_completed_task_after_clear means the '
                    'post-/clear transcript holds task_complete (succeeded) for that task and host state shows it '
                    'succeeded.')
                report['limitations'] += [
                    'bob\'s session runs without --disable-slash-commands so that /clear is the built-in command.',
                    'The harness types /clear into the terminal once bob\'s transcript is quiet; whether Claude Code ran '
                    'it is inferred from a new transcript or a SessionStart line in the debug log (enters_sent records '
                    'whether a second Enter was needed).',
                    'Hook context is detected by a hook_additional_context/SessionStart transcript entry; if Claude '
                    'Code records it differently, only a pending_work call counts as evidence. Neither shows how the '
                    'model used the context.',
                    'After /clear the model is not prompted; its next turn comes from carol\'s task_update channel '
                    'event. The hook\'s preview of the task input is 200 characters, so the instructions carried in '
                    'alice\'s task may be cut off in it.',
                ]
        if failed:
            report['failed'] = failed
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
            print('wrote', output, flush=True)
        if failed:
            raise SystemExit(f'host-state verification failed: {failed}\n{json.dumps(states)}')
        print('Live launch run passed.' if not args.fixture else 'Fixture launch run passed.', flush=True)
    except Exception:
        for name, session in sessions.items():
            print(f'{name} stage:', getattr(session, 'startup_stage', None), flush=True)
            if session.process.poll() is None:
                print(f'{name} screen tail:', session.screen()[-1500:], flush=True)
        raise
    finally:
        for channel in channels.values():
            channel.close()
        for session in sessions.values():
            session.close()
        for person in people:
            person.stop()
        if coord is not None and coord.poll() is None:
            coord.terminate()
            try:
                coord.wait(timeout=10)
            except subprocess.TimeoutExpired:
                coord.kill()
        if args.keep:
            print('kept', work, flush=True)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
