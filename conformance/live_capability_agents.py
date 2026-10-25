#!/usr/bin/env python3
"""Live acceptance for agent capability tools (milestone 10 slice 2) with real harnesses and models.

Written from docs/capabilities-contract.md ("Agent tools (slice 2)", Verification, the live acceptance paragraph),
separately from deterministic conformance (capabilities.py and capability_agents.py). It records its results in
docs/results/capabilities-live.json (or --output).

Two persons on one machine, each with their own daemon and state, joined through a coordinator this run starts on
loopback (`--coord`):
- Bob (a temporary HOME): his Claude Code configuration (`~/.claude.json`, user scope) has a GitHub MCP server
  named `github` (by default `npx -y @modelcontextprotocol/server-github`, overridable with --github-command and
  --github-arg), whose token is the reference `${GITHUB_PERSONAL_ACCESS_TOKEN}`, captured at `attach` from the
  environment variable named by --token-env (default GITHUB_TOKEN). `attach claude --no-start` discovers it; Bob
  creates `github-issues` from it with `list_issues` selected and shares it with `person:alice`.
  Attach checks that Claude Code is signed in even with --no-start, so Bob's HOME links the operator's Claude
  login (`~/.claude/.credentials.json`, where Claude Code keeps it on Linux); Bob never starts Claude Code.
- Alice (the operator's real HOME, so each harness uses its existing login; a private XDG_CONFIG_HOME for
  Peerspan, with the operator's `opencode` configuration directory linked into it; Bob's GitHub token withheld from
  her environment): for each of Claude Code, Codex, and OpenCode in turn, `attach HARNESS --calls` attaches a session
  in a project of its own, and the session is asked in plain words to list the open issues of the test repository
  (--repo, or PEERSPAN_LIVE_REPO) through Bob's capability. Attach also discovers Alice's own harness MCP servers
  and snapshots them, as it always does. Each harness is driven as its integration expects:
  - Claude Code: `attach claude --calls -- ARGS` launches it in print mode (DEFAULT_ARGS, or --claude-args; only
    Peerspan's call tools allowed, built-in tools off). The second turn runs the same `attach` again in the same
    project after Claude Code exited, which waits out the exited adapter's lease and launches the same agent with a
    fresh session (launch contract, "Attach launches"). Print mode never confirms the channel (peerspan_ready);
    outbound tools work before verification.
  - Codex attaches to an existing, loaded app-server thread: the run starts a private `codex app-server --listen
    unix://SOCKET`, a frontend that holds Alice's client connection open (fixtures/codex/frontend.mjs) starts a
    thread in the project (approval policy `never`, read-only sandbox) and one baseline turn, then `attach codex
    --calls --option thread=ID --option socket=SOCKET -- --json` runs the sidecar, which stays up for both turns.
  - OpenCode attaches to an existing session of a running server with Peerspan's plugin: the run starts a private
    `opencode serve` on loopback with the plugin in OPENCODE_CONFIG_CONTENT, creates a session in the project that
    denies the tools that could reach GitHub otherwise (bash, edit, webfetch, websearch, task, external_directory),
    gives it one baseline turn, then `attach opencode --calls --option server=URL --option session=ID --option
    directory=PROJECT --option bindings=PATH -- --json` runs the sidecar, which stays up for both turns.
  For Codex and OpenCode the run waits for the model to answer the sidecar's hello (records `peerspan_ready`), and
  submits each turn itself (`turn/start`; `prompt_async`).

For each harness the run checks that:
- the model called `list_capabilities` and `call_capability` with `bob/github-issues` and `list_issues`, and its
  answer names issues of the repository (their numbers or titles, from the GitHub API with the same token);
- both hosts recorded the call, with Alice's agent as `origin`;
- after Bob runs `unshare github-issues --with person:alice`, the next turn asks again, naming the address, and the
  call is refused with the `not_found` text, nothing more is executed on Bob's host (no further received call), and
  the model's answer says it can no longer reach the capability (a keyword check, recorded with the answer for
  review);
- each turn completed (Claude Code exited 0; the Codex turn completed; the OpenCode turn has no error).
Before each harness's run Bob shares again. The report records each harness's version, the negotiated MCP revision
(the adapter connection's `protocol_version` on Alice's host, null when the adapter reported none), and the model's
tool calls and answers, as parsed from Claude Code's JSON output, the Codex thread's turns, and the OpenCode
session's messages; nothing about model behavior is inferred from notification acknowledgements. Tool calls are
recognized by name (any name ending in list_capabilities or call_capability) with their arguments.

Needs Python 3, Node 22 (with the integrations' npm dependencies installed), the Go or Rust host binaries, the Go
coordinator, the harnesses on PATH and logged in, a
GitHub token that can read the repository, and network access for the GitHub MCP server. It is never run by the
deterministic suites.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

from coordination import Coordinator, wait_for
from host_service import stop_all
from launch_directory import DEFAULT, DirectoryHost
from live_opencode_agents import Conversation
from peer_messaging import available_port

REPO = Path(__file__).resolve().parents[1]
NOT_FOUND = ('No capability at this address is available to this session now. It may have been unshared, or its host '
             'may not have answered (see unanswered). Check list_capabilities.')
HARNESSES = {'claude': 'claude', 'codex': 'codex', 'opencode': 'opencode'}
DEFAULT_ARGS = {
    # Claude Code: print mode with the stream of tool calls; only the four tools allowed, built-in tools off.
    'claude': ['-p', '{prompt}', '--output-format', 'stream-json', '--verbose', '--setting-sources', '', '--tools', '',
               '--allowedTools', ','.join('mcp__peerspan__' + t for t in ('list_capabilities', 'call_capability',
                                                                          'call_status', 'call_cancel')),
               '--permission-mode', 'dontAsk'],
}
FIRST_PROMPT = ('Please list the open issues of the GitHub repository {repo}. Bob has shared a capability for this '
                'with me through Peerspan; use it. Answer with each issue\'s number and title.')
SECOND_PROMPT = ('Please list the open issues of the GitHub repository {repo} again by calling Bob\'s Peerspan '
                 'capability bob/github-issues directly, even if it is no longer listed. If the call fails or you '
                 'cannot reach it, say so plainly.')
UNREACHABLE = re.compile(r'no longer|not available|unavailable|cannot|can[\'\u2019]t|can not|unable|not_found|not found|'
                         r'unshared|no capability|isn[\'\u2019]t available|is not available|lost access|no access', re.I)


class Person(DirectoryHost):
    """A daemon and CLI of one implementation. With real_home, HOME is the operator's (harness logins); Peerspan's
    configuration stays private in XDG_CONFIG_HOME either way."""

    def __init__(self, binary, root, real_home=False, withheld=()):
        super().__init__(binary, binary, root / 'state', root / 'user')
        self.real_home, self.withheld = real_home, withheld
        if real_home:
            source = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'opencode'
            if source.exists():
                (self.config / 'opencode').symlink_to(source)

    def private_env(self):
        env = {'XDG_CONFIG_HOME': str(self.config)}
        if not self.real_home:
            env['HOME'] = str(self.home)
        return env

    def environment(self, sock=DEFAULT, env=None):
        # Bob's GitHub token is his: Alice's harnesses never see it (OpenCode would also pick it up as a login).
        e = super().environment(sock, env)
        for name in self.withheld:
            if not (env and name in env):
                e.pop(name, None)
        return e


def tool_calls(text):
    """Every tool call in a harness's JSON output: (name, arguments) for names ending in list_capabilities or
    call_capability, found anywhere in the JSON objects of its lines."""
    found = []

    def walk(value):
        if isinstance(value, dict):
            name = value.get('name') or value.get('tool')
            if isinstance(name, str) and re.search(r'(list_capabilities|call_capability|call_status)$', name):
                arguments = value.get('input') or value.get('arguments') or (value.get('state') or {}).get('input')
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except ValueError:
                        pass
                found.append({'name': name, 'arguments': arguments})
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    for line in text.splitlines():
        try:
            walk(json.loads(line))
        except ValueError:
            continue
    return found


def answer_text(text):
    """The model's final answer as best found in the JSON output: Claude Code's result, Codex agent messages, or
    OpenCode text parts; otherwise the raw output's last 2,000 characters."""
    answers = []
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get('type') == 'result' and isinstance(event.get('result'), str):
            answers.append(event['result'])
        item = event.get('item') if isinstance(event.get('item'), dict) else None
        if item and item.get('type') in ('agent_message', 'assistant_message') and isinstance(item.get('text'), str):
            answers.append(item['text'])
        part = event.get('part') if isinstance(event.get('part'), dict) else None
        if part and part.get('type') == 'text' and isinstance(part.get('text'), str):
            answers.append(part['text'])
    return '\n'.join(answers) if answers else text[-2000:]


def open_issues(repo, token):
    request = urllib.request.Request(f'https://api.github.com/repos/{repo}/issues?state=open&per_page=100',
                                     headers={'Authorization': f'Bearer {token}',
                                              'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        issues = json.loads(response.read())
    return [{'number': i['number'], 'title': i['title']} for i in issues if 'pull_request' not in i]


def version_of(command):
    try:
        return subprocess.run([command, '--version'], capture_output=True, text=True, timeout=30).stdout.strip()
    except OSError as error:
        return f'unavailable: {error}'


def wait_until(check, seconds, message):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.5)
    raise AssertionError(f'timed out after {seconds} seconds waiting for {message}')


class Sidecar:
    """`attach HARNESS --calls ... -- --json` for an integration whose launch is a foreground sidecar (Codex,
    OpenCode): attach replaces itself with the sidecar, which prints one JSON event per line on stdout."""

    def __init__(self, run, argv, workspace):
        self.events, self.lines = [], queue.Queue()
        self.logs = tempfile.TemporaryFile()
        self.process = subprocess.Popen([run.alice.cli_binary, '--state', str(run.alice.state), *argv],
                                        cwd=str(workspace), env=run.alice.environment(), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=self.logs, text=True)
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        for line in self.process.stdout:
            try:
                self.lines.put(json.loads(line))
            except ValueError:
                self.lines.put({'type': 'unparsed', 'text': line.rstrip()})
        self.lines.put(None)

    def drain(self):
        while True:
            try:
                event = self.lines.get_nowait()
            except queue.Empty:
                return
            if event is not None:
                self.events.append(event)

    def event(self, event_type, seconds, **keys):
        """The first event of this type and keys seen so far or within seconds; None if none."""
        deadline = time.monotonic() + seconds
        while True:
            self.drain()
            for event in self.events:
                if event.get('type') == event_type and all(event.get(k) == v for k, v in keys.items()):
                    return event
            if self.process.poll() is not None and self.lines.empty():
                return None
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.2)

    def errors(self):
        self.logs.seek(0)
        return self.logs.read().decode(errors='replace')

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.drain()


class ClaudeDriver:
    """Claude Code in print mode. Each turn is `attach claude --calls -- ARGS` in the same project: the first sets up
    the session and launches Claude Code; the second re-attaches after Claude Code exited, which waits out the
    exited adapter's lease and launches the same agent with a fresh session (launch contract, "Attach launches")."""

    def __init__(self, run, workspace):
        self.run, self.workspace = run, workspace
        self.attachment = {}

    def start(self):
        pass

    def turn(self, prompt):
        args = self.run.args
        override = args.claude_args
        extra = [a.replace('{prompt}', prompt) for a in (json.loads(override) if override else DEFAULT_ARGS['claude'])]
        argv = ['attach', 'claude', '--calls', '--directory', str(self.workspace), '--integrations',
                str(args.integrations), '--runner', str(args.node), '--', *extra]
        started = time.monotonic()
        result = subprocess.run([self.run.alice.cli_binary, '--state', str(self.run.alice.state), *argv],
                                cwd=str(self.workspace), env=self.run.alice.environment(), capture_output=True,
                                text=True, timeout=args.timeout, stdin=subprocess.DEVNULL)
        output = result.stdout + '\n' + result.stderr
        return {'completed': result.returncode == 0, 'exit': result.returncode,
                'seconds': round(time.monotonic() - started), 'tool_calls': tool_calls(output),
                'answer': answer_text(output), 'output': output}

    def stop(self):
        pass


class CodexDriver:
    """Codex attaches to an existing, loaded app-server thread (harness integration contract). The run starts a
    private `codex app-server --listen unix://SOCKET` with Alice's environment (the operator's Codex login), creates
    a thread in the project with `thread/start`, and runs `attach codex --calls --option thread=ID --option
    socket=SOCKET -- --json`, whose sidecar stays running. A frontend (fixtures/codex/frontend.mjs) holds Alice's
    client connection open, as the native Codex client would, starts the thread and its turns (`turn/start`, after
    one baseline turn before attaching, so the thread is an existing conversation), and reads tool calls and
    answers back from the thread's turns (`thread/read` with turns)."""

    def __init__(self, run, workspace):
        self.run, self.workspace = run, workspace
        self.server = self.sidecar = None
        self.attachment = {}

    def request(self, method, params):
        self.count += 1
        self.frontend.stdin.write(json.dumps({'id': self.count, 'method': method, 'params': params}) + '\n')
        self.frontend.stdin.flush()
        line = self.frontend.stdout.readline()
        if not line:
            raise AssertionError(f'the Codex frontend exited during {method}')
        answer = json.loads(line)
        assert answer.get('id') == self.count, answer
        if answer.get('error'):
            raise AssertionError(f"Codex app-server {method} failed: {answer['error']}")
        return answer['result']

    def thread(self):
        try:
            return self.request('thread/read', {'threadId': self.thread_id, 'includeTurns': True})['thread']
        except AssertionError:
            # A new thread has no stored turns until its first input, and cannot be read with them.
            return {**self.request('thread/read', {'threadId': self.thread_id, 'includeTurns': False})['thread'],
                    'turns': []}

    def start(self):
        run = self.run
        directory = self.workspace.parent / 'codex-app-server'
        directory.mkdir()
        listen = directory / 'codex.sock'
        self.server_logs = tempfile.TemporaryFile()
        self.server = subprocess.Popen([shutil.which('codex'), 'app-server', '--listen', f'unix://{listen}'],
                                       cwd=str(self.workspace), env=run.alice.environment(), stdout=self.server_logs,
                                       stderr=self.server_logs, stdin=subprocess.DEVNULL)
        wait_until(lambda: listen.exists() or self.server.poll() is not None, 60, 'the Codex app-server socket')
        assert self.server.poll() is None, 'codex app-server exited at startup'
        self.socket = Path(os.path.realpath(listen))
        # Alice's Codex client: one connection held open, as a native frontend holds it, so the thread stays loaded.
        self.count = 0
        self.frontend = subprocess.Popen([str(run.args.node), str(REPO / 'conformance/fixtures/codex/frontend.mjs'),
                                          str(self.socket)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=self.server_logs, text=True, env=run.alice.environment())
        assert json.loads(self.frontend.stdout.readline() or 'null') == {'ready': True}, 'the Codex frontend failed'
        # Read-only and never asking for approval: the run must not block on a prompt nobody answers.
        started = self.request('thread/start', {'cwd': str(self.workspace), 'approvalPolicy': 'never',
                                                'sandbox': 'read-only'})
        self.thread_id = started['thread']['id']
        self.attachment['thread'] = {'id': self.thread_id, 'model': started.get('model'),
                                     'reasoning_effort': started.get('reasoningEffort')}
        # An existing conversation, as Peerspan expects: one baseline turn before attaching.
        baseline = self.turn('Reply with BASELINE_READY and nothing else. Do not use tools.')
        self.attachment['baseline'] = {'completed': baseline['completed'], 'answer': baseline['answer']}
        self.sidecar = Sidecar(run, ['attach', 'codex', '--calls', '--directory', str(self.workspace),
                                     '--integrations', str(run.args.integrations), '--runner', str(run.args.node),
                                     '--option', f'thread={self.thread_id}', '--option', f'socket={self.socket}',
                                     '--option', f"executable={shutil.which('codex')}", '--', '--json'],
                               self.workspace)
        ready = self.sidecar.event('ready', 90)
        if not ready:
            raise AssertionError(f'Codex attach did not become ready (exit {self.sidecar.process.poll()}, events '
                                 f'{self.sidecar.events[-5:]}): {self.sidecar.errors()[-1500:]}')
        self.attachment['ready'] = ready
        # Live delivery: the sidecar queues the hello event; the model is expected to call peerspan_ready.
        verified = self.sidecar.event('tool_result', 300, tool='peerspan_ready')
        self.attachment['peerspan_ready'] = bool(verified and verified.get('success'))
        wait_until(lambda: self.thread()['status']['type'] == 'idle', 300, 'the Codex thread to be idle')

    def turn(self, prompt):
        before = len(self.thread()['turns'])
        events = len(self.sidecar.events) if self.sidecar else 0
        started = time.monotonic()
        self.request('turn/start', {'threadId': self.thread_id, 'input': [{'type': 'text', 'text': prompt}]})

        def finished():
            thread = self.thread()
            return thread if len(thread['turns']) > before and thread['status']['type'] == 'idle' else None
        thread = wait_until(finished, self.run.args.timeout, 'the Codex turn to finish')
        turns = thread['turns'][before:]
        sidecar = []
        if self.sidecar:
            self.sidecar.drain()
            sidecar = self.sidecar.events[events:]
        output = '\n'.join([json.dumps(turn) for turn in turns] + [json.dumps(event) for event in sidecar])
        answer = '\n'.join(item.get('text') or '' for turn in turns for item in turn.get('items', [])
                           if item.get('type') == 'agentMessage')
        return {'completed': all(turn.get('status') == 'completed' for turn in turns),
                'turn_status': [turn.get('status') for turn in turns], 'seconds': round(time.monotonic() - started),
                'tool_calls': tool_calls('\n'.join(json.dumps(turn) for turn in turns)), 'answer': answer,
                'output': output}

    def stop(self):
        if self.sidecar:
            self.sidecar.stop()
        if getattr(self, 'frontend', None):
            self.frontend.stdin.close()
            try:
                self.frontend.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.frontend.kill()
                self.frontend.wait()
        if self.server and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()


class OpenCodeDriver:
    """OpenCode attaches to an existing session of a running server, with Peerspan's plugin installed (harness
    integration contract). The run starts a private `opencode serve` on loopback with Alice's environment and the
    plugin in its configuration (OPENCODE_CONFIG_CONTENT, with a bindings path of this run), creates a session in
    the project whose permissions deny the tools that could reach GitHub otherwise, gives it one baseline turn (the sidecar keeps the
    session's model and agent), and runs `attach opencode --calls --option server=URL --option session=ID --option
    directory=PROJECT --option bindings=PATH -- --json`, whose sidecar stays running. Each turn is submitted with
    `prompt_async` (as live_opencode_agents.py does); tool calls and answers are read back from the session's
    messages."""

    def __init__(self, run, workspace):
        self.run, self.workspace = run, workspace
        self.server = self.sidecar = None
        self.attachment = {}

    def start(self):
        run = self.run
        bindings = self.workspace.parent / 'opencode-bindings'
        port = available_port()
        config = {'plugin': [[(run.args.integrations / 'opencode' / 'plugin.mjs').as_uri(), {'bindings': str(bindings)}]]}
        self.server_logs = tempfile.TemporaryFile()
        self.server = subprocess.Popen([shutil.which('opencode'), 'serve', '--hostname', '127.0.0.1', '--port', str(port)],
                                       cwd=str(self.workspace), stdout=self.server_logs, stderr=self.server_logs,
                                       stdin=subprocess.DEVNULL,
                                       env={**run.alice.environment(), 'OPENCODE_CONFIG_CONTENT': json.dumps(config)})
        url = f'http://127.0.0.1:{port}'

        def healthy():
            assert self.server.poll() is None, 'opencode serve exited at startup'
            try:
                return urllib.request.urlopen(url + '/global/health', timeout=5).status == 200
            except OSError:
                return False
        wait_until(healthy, 60, 'the OpenCode server')
        # Tools that could reach GitHub or change the machine are denied, so the model's way to the issues is Bob's
        # capability. (Denying every tool but Peerspan's makes OpenCode's free models refuse the request.)
        session = self.raw('POST', url, '/session', {'title': 'Peerspan capability live run', 'permission': [
            {'permission': name, 'pattern': '*', 'action': 'deny'}
            for name in ('bash', 'edit', 'webfetch', 'websearch', 'task', 'external_directory')]})
        self.conversation = Conversation(url, session['id'], self.workspace, bindings)
        # Submitted asynchronously and awaited with the turn timeout, as the later turns are; the server's default
        # model and agent answer it, and the sidecar keeps them for its own input.
        message_id = 'msg_' + secrets.token_hex(16)
        self.conversation.request('POST', f"/session/{session['id']}/prompt_async", {
            'messageID': message_id,
            'parts': [{'type': 'text', 'text': 'Reply with BASELINE_READY and nothing else. Do not use tools.'}]})
        replies = self.replies(message_id)
        info = replies[-1]['info']
        self.attachment['session'] = {'id': session['id'], 'model': info.get('modelID'),
                                      'provider': info.get('providerID')}
        self.attachment['baseline'] = {'error': info.get('error'), 'answer': '\n'.join(
            part.get('text', '') for m in replies for part in m['parts'] if part.get('type') == 'text')}
        self.attachment['version'] = self.conversation.request('GET', '/global/health').get('version')
        self.sidecar = Sidecar(run, ['attach', 'opencode', '--calls', '--directory', str(self.workspace),
                                     '--integrations', str(run.args.integrations), '--runner', str(run.args.node),
                                     '--option', f'server={url}', '--option', f"session={session['id']}",
                                     '--option', f'directory={self.workspace}', '--option', f'bindings={bindings}',
                                     '--', '--json'], self.workspace)
        ready = self.sidecar.event('ready', 90)
        if not ready:
            raise AssertionError(f'OpenCode attach did not become ready (exit {self.sidecar.process.poll()}, events '
                                 f'{self.sidecar.events[-5:]}): {self.sidecar.errors()[-1500:]}')
        self.attachment['ready'] = ready
        verified = self.sidecar.event('tool_result', 300, tool='peerspan_ready')
        self.attachment['peerspan_ready'] = bool(verified and verified.get('success'))
        self.idle(300)

    @staticmethod
    def raw(method, url, path, body):
        request = urllib.request.Request(url + path, json.dumps(body).encode(), {'Content-Type': 'application/json',
                                                                                'Accept': 'application/json'},
                                         method=method)
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())

    def idle(self, seconds):
        status = lambda: self.conversation.request('GET', '/session/status').get(self.conversation.session_id, {})
        wait_until(lambda: status().get('type', 'idle') == 'idle', seconds, 'the OpenCode session to be idle')

    def replies(self, message_id):
        """The assistant messages answering message_id, once all are finished and the session is idle, waiting up
        to the turn timeout."""
        def finished():
            replies = [m for m in self.conversation.messages() if m['info']['role'] == 'assistant'
                       and m['info'].get('parentID') == message_id]
            busy = self.conversation.request('GET', '/session/status').get(self.conversation.session_id, {})
            done = replies and all('completed' in m['info'].get('time', {}) or m['info'].get('error') for m in replies)
            return replies if done and busy.get('type', 'idle') == 'idle' else None
        return wait_until(finished, self.run.args.timeout, 'the OpenCode turn to finish')

    def turn(self, prompt):
        events = len(self.sidecar.events)
        started = time.monotonic()
        message_id = self.conversation.submit(prompt)
        replies = self.replies(message_id)
        self.sidecar.drain()
        output = '\n'.join([json.dumps(m) for m in replies] + [json.dumps(e) for e in self.sidecar.events[events:]])
        answer = '\n'.join(p['text'] for m in replies for p in m['parts'] if p.get('type') == 'text')
        errors = [m['info']['error'] for m in replies if m['info'].get('error')]
        return {'completed': not errors, 'errors': errors, 'seconds': round(time.monotonic() - started),
                'tool_calls': tool_calls('\n'.join(json.dumps(m) for m in replies)), 'answer': answer,
                'output': output}

    def stop(self):
        if self.sidecar:
            self.sidecar.stop()
        if self.server and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()


DRIVERS = {'claude': ClaudeDriver, 'codex': CodexDriver, 'opencode': OpenCodeDriver}


class Run:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.coord = Coordinator(args.coord, root / 'coord')
        self.token = os.environ.get(args.token_env)
        if not self.token:
            raise SystemExit(f'set {args.token_env} to a GitHub token that can read {args.repo}')

    def received(self):
        return self.bob.cli('calls', 'received', '--limit', '1000')

    def origin_session(self, origin):
        """Alice's session and adapter credential for a call's origin: the session must belong to the origin's agent
        on Alice's host. (session object, adapter record or None)."""
        if not isinstance(origin, dict):
            return None, None
        status, session = self.alice.call('GET', f"/v1/sessions/{origin.get('session_id')}")
        if status != 200 or session.get('agent_id') != origin.get('agent_id'):
            return None, None
        adapters = self.alice.cli('adapter', 'list')
        adapter = next((a for a in adapters if a.get('session_id') == origin.get('session_id')), None)
        return session, adapter

    def one(self, harness):
        repo = self.args.repo
        report = {'harness': harness, 'version': version_of(HARNESSES[harness])}
        workspace = self.root / 'projects' / harness / 'project'
        workspace.mkdir(parents=True)
        driver = DRIVERS[harness](self, workspace)
        try:
            self.bob.cli('share', 'github-issues', '--with', 'person:alice', '--yes', '--network', self.net)
            self.alice.run('network', 'sync', self.net)
            driver.start()
            report['attachment'] = driver.attachment
            before = len(self.received())
            turn = driver.turn(FIRST_PROMPT.format(repo=repo))
            calls, answer = turn['tool_calls'], turn['answer']
            report['first'] = {k: v for k, v in turn.items() if k != 'output'}
            listed = any(c['name'].endswith('list_capabilities') for c in calls)
            called = [c for c in calls if c['name'].endswith('call_capability') and isinstance(c['arguments'], dict)
                      and c['arguments'].get('address') == 'bob/github-issues'
                      and c['arguments'].get('operation') == 'list_issues']
            named = [i for i in self.issues if f"#{i['number']}" in answer or i['title'] in answer]
            received = self.received()[before:]
            origins = [r['request'].get('origin') for r in received]
            sessions = [self.origin_session(o) for o in origins]
            adapter = next((a for _, a in sessions if a), None)
            outbound = self.alice.cli('calls', 'list', '--limit', '1000')
            recorded = [o['call'] for o in outbound if (o['call'].get('request') or {}).get('call_id') in
                        {r['request']['call_id'] for r in received}]
            report['checks'] = {
                'model_called_list_capabilities': listed,
                'model_called_call_capability_with_address_and_operation': bool(called),
                'answer_names_issues': bool(named) if self.issues else None,
                'bob_recorded_the_call': bool(received),
                'alice_recorded_the_call': bool(recorded),
                'origin_is_alices_agent': bool(received) and all(session for session, _ in sessions),
            }
            report['received'] = [{'call_id': r['request']['call_id'], 'operation': r['request']['operation'],
                                   'origin': r['request'].get('origin'), 'state': (r.get('status') or {}).get('state')}
                                  for r in received]
            report['alice_session'] = sessions[0][0] if sessions else None
            if adapter:
                connection = self.alice.cli('adapter', 'connection', adapter['id'])
                report['adapter_connection'] = connection
                report['negotiated_protocol'] = connection.get('protocol_version')
            # Recorded as the daemon has it; null means the adapter reported no revision at connect.
            report.setdefault('negotiated_protocol', None)

            # Unshared: the next call is refused with the not_found text, and nothing more runs on Bob's host.
            self.bob.cli('unshare', 'github-issues', '--with', 'person:alice', '--network', self.net)
            self.alice.run('network', 'sync', self.net)
            before = len(self.received())
            turn = driver.turn(SECOND_PROMPT.format(repo=repo))
            answer = turn['answer']
            report['after_unshare'] = {k: v for k, v in turn.items() if k != 'output'}
            report['checks'].update({
                'after_unshare_refused_with_not_found_text': NOT_FOUND in turn['output'],
                'after_unshare_nothing_executed_on_bob': len(self.received()) == before,
                'after_unshare_answer_says_unreachable': bool(UNREACHABLE.search(answer)),
            })
            report['checks']['first_turn_completed'] = report['first']['completed']
            report['checks']['after_unshare_turn_completed'] = turn['completed']
        except Exception as error:
            report.setdefault('checks', {})['run_completed'] = False
            report['error'] = f'{type(error).__name__}: {error}'
        finally:
            driver.stop()
        report['passed'] = bool(report['checks']) and all(v is not False for v in report['checks'].values())
        print(json.dumps({'harness': harness, 'checks': report['checks'], 'error': report.get('error')}), flush=True)
        return report

    def run(self):
        args, root = self.args, self.root
        coord_key = self.coord.start()['public_key']
        self.bob = Person(args.bob_binary, root / 'bob')
        self.alice = Person(args.alice_binary, root / 'alice', real_home=True, withheld=(args.token_env,))
        for person in (self.bob, self.alice):
            person.start()
        try:
            created = self.bob.cli('network', 'create', 'live', '--as', 'bob', '--untrusted', '--coordinator',
                                   self.coord.address, '--coordinator-key', coord_key)
            self.net = created['id']
            token = self.bob.cli('invite', 'alice', '--network', self.net)['token']
            self.alice.cli('join', token, '--untrusted')
            wait_for(lambda: len(self.bob.cli('network', 'members', self.net)) == 2, timeout=60,
                     message='both members')

            # Bob's GitHub server in his Claude Code user configuration, discovered at attach.
            server = {'command': args.github_command,
                      'args': args.github_arg or ['-y', '@modelcontextprotocol/server-github'],
                      'env': {'GITHUB_PERSONAL_ACCESS_TOKEN': '${GITHUB_PERSONAL_ACCESS_TOKEN}'}}
            (self.bob.home / '.claude.json').write_text(json.dumps({'mcpServers': {'github': server}}))
            # Attach's readiness checks need a signed-in Claude Code, also with --no-start.
            login = Path.home() / '.claude' / '.credentials.json'
            if login.exists():
                (self.bob.home / '.claude').mkdir(exist_ok=True)
                (self.bob.home / '.claude' / '.credentials.json').symlink_to(login)
            workspace = root / 'projects' / 'bob'
            workspace.mkdir(parents=True)
            result = self.bob.run('attach', 'claude', '--name', 'bob-claude', '--directory', str(workspace),
                                  '--integrations', str(args.integrations), '--runner', str(args.node), '--no-start',
                                  env={'GITHUB_PERSONAL_ACCESS_TOKEN': self.token}, timeout=300)
            if result.returncode != 0:
                raise SystemExit(f'Bob\'s attach failed: {result.stderr[-800:]}')
            sources = json.loads(result.stdout).get('sources')
            self.bob.cli('capability', 'create', 'github-issues', '--from', 'bob-claude/github', '--operations',
                         'list_issues')
            self.issues = open_issues(args.repo, self.token)
            reports = [self.one(h) for h in args.harness]
            return {'timestamp': datetime.now(timezone.utc).isoformat(), 'repository': args.repo,
                    'mode': 'real harnesses and models; Bob and Alice on one machine; local daemons '
                            f'({Path(args.bob_binary).name} for Bob, {Path(args.alice_binary).name} for Alice)',
                    'open_issues': self.issues, 'bob_sources': sources, 'harnesses': reports,
                    'passed': all(r['passed'] for r in reports),
                    'limits': ['One machine; cross-host connectivity is not established by this run.',
                               'Tool calls and answers come from Claude Code\'s JSON output, the Codex thread\'s '
                               'turns, and the OpenCode session\'s messages; the unreachable answer is a keyword '
                               'check recorded with the answer for review.',
                               'Codex and OpenCode run on private app-server and serve processes this run starts, '
                               'driven by the run rather than a native frontend.']}
        finally:
            stop_all((self.bob, self.alice))
            self.coord.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--bob-binary', type=Path, required=True, help='peerspan-host for Bob (Go or Rust)')
    parser.add_argument('--alice-binary', type=Path, required=True, help='peerspan-host for Alice (Go or Rust)')
    parser.add_argument('--coord', type=Path, required=True, help='peerspan-coord')
    parser.add_argument('--node', type=Path, default=shutil.which('node'), help='Node 22 or newer')
    parser.add_argument('--integrations', type=Path, default=REPO / 'integrations')
    parser.add_argument('--repo', default=os.environ.get('PEERSPAN_LIVE_REPO'),
                        help='the test repository, OWNER/NAME (or PEERSPAN_LIVE_REPO)')
    parser.add_argument('--token-env', default='GITHUB_TOKEN',
                        help='the environment variable holding the GitHub token (never written anywhere)')
    parser.add_argument('--github-command', default='npx')
    parser.add_argument('--github-arg', action='append', help='an argument of the GitHub MCP server; repeatable')
    parser.add_argument('--harness', action='append', choices=sorted(HARNESSES),
                        help='repeatable; default claude, codex, and opencode in turn')
    parser.add_argument('--claude-args', help='the Claude Code arguments after --, as a JSON array; {prompt} is '
                                              'replaced')
    parser.add_argument('--timeout', type=int, default=600, help='seconds for each harness turn')
    parser.add_argument('--output', type=Path, default=REPO / 'docs' / 'results' / 'capabilities-live.json')
    parser.add_argument('--keep', action='store_true', help='keep the temporary directory')
    args = parser.parse_args()
    if not args.repo or not re.fullmatch(r'[\w.-]+/[\w.-]+', args.repo):
        parser.error('--repo OWNER/NAME (or PEERSPAN_LIVE_REPO) is required')
    if not args.node:
        parser.error('--node is required (no node on PATH)')
    args.harness = args.harness or ['claude', 'codex', 'opencode']
    for key in ('bob_binary', 'alice_binary', 'coord', 'node', 'integrations', 'output'):
        setattr(args, key, Path(getattr(args, key)).resolve())
    root = Path(tempfile.mkdtemp(prefix='peerspan-capabilities-live-'))
    try:
        result = Run(args, root).run()
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'output': str(args.output)}))
    sys.exit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
