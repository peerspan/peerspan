#!/usr/bin/env python3
"""Real installed terminal lifecycle: final-acceptance contract section2.

Independent public-contract author; no product imports, native SDK mocks, cache
parsing or model calls. Root executes this source against the final real archive.
Requires Python3.12+ and pyte==0.8.2 (public screen/keyboard emulator only).
Public references checked2026-11-02:
https://code.claude.com/docs/en/plugins
https://code.claude.com/docs/en/cli-reference (--session-id)
https://code.claude.com/docs/en/interactive-mode (keyboard controls)
https://pyte.readthedocs.io/en/latest/api.html (Screen/Stream/Char.reverse)

Private PTY recordings and normal host state stay in --work. Published output
contains only fixed outcomes/counts/versions/hashes. This is not model receipt,
adapter delivery, participant authority, upgrade or physical-machine acceptance.
"""
import argparse
import codecs
from datetime import datetime, timezone
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.metadata
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tarfile
import termios
import threading
import time
import uuid

from onboarding_bundle import (CheckFailure, PLUGIN_ID, native, require,
                               safe_members, sha256_file, validate_layout,
                               verify_checksum)


LIMIT = 600
UI_LIMIT = 30
PHASE = 'initialization'
BASE = ['onboarding', 'project']
EFFECTS = dict(register_agent=True, attach_session=True, issue_adapter_credential=False,
               grant_network_access=False, share_files=False, share_conversation=False,
               capability_calls=False)


class Budget:
    def __init__(self):
        self.started = time.monotonic()
        self.deadline = self.started + LIMIT - 15  # Reserve bounded child/server cleanup.

    def until(self, cap):
        require(self.deadline > time.monotonic(), 'terminal suite whole deadline reached')
        return min(self.deadline, time.monotonic() + cap)

    def timeout(self, cap):
        return max(0.001, self.until(cap) - time.monotonic())


def private_dir(path):
    path.mkdir(mode=0o700)
    return path


def environment(work):
    # Never inherit authentication values or override HOME. No user config read.
    result = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG', 'USER', 'LOGNAME', 'SHELL')
              if key in os.environ}
    result.update(TERM='xterm-256color', COLORTERM='truecolor', LANG='C.UTF-8',
                  XDG_CONFIG_HOME=str(private_dir(work / 'xdg configuration')),
                  XDG_STATE_HOME=str(private_dir(work / 'xdg state')),
                  XDG_RUNTIME_DIR=str(private_dir(work / 'xdg runtime')),
                  TMPDIR=str(private_dir(work / 'temporary files')),
                  DISABLE_UPDATES='1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1')
    require(result.get('HOME') == os.environ.get('HOME'), 'HOME must remain inherited')
    return result


class RecordingProvider:
    """Record requests without retaining/printing authentication or request bodies."""
    def __init__(self):
        self.requests = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def record(self):
                owner.requests += 1
                self.send_response(503)
                self.send_header('Content-Length', '0')
                self.end_headers()
                self.close_connection = True

            do_POST = do_GET = do_PUT = do_DELETE = do_OPTIONS = do_HEAD = do_PATCH = do_TRACE = do_CONNECT = record

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return 'http://127.0.0.1:' + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


class Host:
    def __init__(self, executable, work, env, budget):
        self.executable, self.work, self.env, self.budget = executable, work, env, budget
        self.state = private_dir(work / 'explicit host state')
        self.process = None

    def cli(self, *args, body=None):
        try:
            result = subprocess.run([str(self.executable), '--state', str(self.state), *args],
                input=None if body is None else json.dumps(body), capture_output=True, text=True,
                env=self.env, cwd=self.work, timeout=self.budget.timeout(5))
        except subprocess.TimeoutExpired:
            raise CheckFailure('bounded host operation timed out') from None
        require(result.returncode == 0, 'public host operation refused')
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise CheckFailure('public host operation returned invalid JSON') from None

    def start(self):
        require(self.process is None, 'host already running')
        log = (self.work / 'private daemon.log').open('ab')
        self.process = subprocess.Popen([str(self.executable), '--state', str(self.state), 'run'],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=self.work,
            env=self.env, start_new_session=True)
        log.close()
        until = self.budget.until(30)
        while time.monotonic() < until:
            require(self.process.poll() is None, 'installed daemon exited during startup')
            try:
                self.cli('info')
                return
            except CheckFailure:
                time.sleep(min(.1, max(0, until - time.monotonic())))
        raise CheckFailure('installed daemon did not become available')

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=2)
            self.process = None

    def lookup(self, root, session):
        context = dict(project_root=str(root), native_session_id=session, integration='claude-code')
        value = self.cli(*BASE, 'lookup', '--stdin', body=context)
        require(type(value) is dict and value.get('context') == context,
                'public lookup changed native project context')
        return value['flow']

    def inspect(self, flow):
        return self.cli(*BASE, 'inspect', flow['flow_id'])

    def registry(self):
        return self.cli('agent', 'list'), self.cli('session', 'list'), self.cli('activity', '--limit', '1000')


class Terminal:
    """A real controlling PTY, decoded with a public VT100 screen emulator."""
    def __init__(self, claude, cwd, session, env, budget, log):
        import pyte
        self.budget, self.log = budget, log.open('ab')
        self.startup_events = log.with_suffix('.startup.jsonl')
        self.screen = pyte.Screen(160, 60)
        self.stream = pyte.Stream(self.screen)
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 60, 160, 0, 0))

        try:
            # setsid in Popen, then a fresh interpreter assigns the controlling
            # tty and execs the real CLI. No Python preexec_fn with server threads.
            setup = ('import fcntl,os,sys,termios;fcntl.ioctl(0,termios.TIOCSCTTY,0);'
                     'os.execv(sys.argv[1],sys.argv[1:])')
            self.process = subprocess.Popen([sys.executable, '-c', setup, str(claude), '--session-id', session],
                stdin=slave, stdout=slave, stderr=slave, cwd=cwd, env=env,
                start_new_session=True)
        except BaseException:
            os.close(self.master)
            self.log.close()
            raise
        finally:
            os.close(slave)
        try:
            self.startup()
        except BaseException:
            self.close()
            raise

    def send(self, value):
        os.write(self.master, value.encode() if isinstance(value, str) else value)

    def pump(self, timeout=.1):
        ready, _, _ = select.select([self.master], [], [], timeout)
        if ready:
            try:
                block = os.read(self.master, 65536)
            except OSError:
                block = b''
            require(bool(block), 'native terminal closed unexpectedly')
            self.log.write(block); self.log.flush()
            decoded = self.decoder.decode(block)
            self.stream.feed(decoded)
            # Public terminal capability replies; no native callbacks/state.
            if '\x1b[6n' in decoded:
                self.send(f'\x1b[{self.screen.cursor.y + 1};{self.screen.cursor.x + 1}R')
            if '\x1b[c' in decoded or '\x1b[0c' in decoded:
                self.send('\x1b[?1;2c')
            if '\x1b[>c' in decoded:
                self.send('\x1b[>0;136;0c')
        require(self.process.poll() is None, 'native terminal exited unexpectedly')

    def text(self):
        return '\n'.join(self.screen.display)

    def wait(self, predicate, message):
        until = self.budget.until(UI_LIMIT)
        while time.monotonic() < until:
            if predicate():
                return
            self.pump(min(.1, max(0, until - time.monotonic())))
        raise CheckFailure(message)

    def visible(self, text):
        self.wait(lambda: text in self.text(), 'native terminal expected public view unavailable')

    def startup(self):
        answered = set()
        active = None
        until = self.budget.until(UI_LIMIT)
        trace_started = time.monotonic()
        trace_last, trace_count = None, 0
        text, lower = '', ''
        stable_view, stable_since = None, None
        prompts = (
            ('style', ('text style', 'choose the text style', 'choose a theme'), None),
            ('key', ('custom api key', 'use this api key'), '\x1b[A'),
            ('security', ('security notes', 'security note'), None),
            ('trust', ('trust this folder', 'trust the files', 'trust this workspace'), '\x1b[B'),
        )

        def selected_yes(text):
            return re.search(r'^\s*[❯>]\s*(?:\d+\.\s*)?Yes\b', text, re.MULTILINE | re.IGNORECASE) is not None

        def trace(event='view', sent='none'):
            nonlocal trace_last, trace_count
            value = dict(event=event, matched_prompt=[name for name, phrases, _ in prompts
                if any(phrase in lower for phrase in phrases)],
                active_prompt=None if active is None else active[0],
                active_phase=None if active is None else active[2],
                rendered_selected_yes=selected_yes(text), sent=sent)
            signature = json.dumps(value, sort_keys=True)
            if trace_count >= 256 or signature == trace_last:
                return
            trace_last = signature
            trace_count += 1
            value['elapsed_ms'] = int((time.monotonic() - trace_started) * 1000)
            try:
                with self.startup_events.open('a') as output:
                    output.write(json.dumps(value, sort_keys=True) + '\n')
            except OSError:
                pass  # Private diagnostics cannot alter native input or verdict.

        while time.monotonic() < until:
            text = self.text()
            lower = text.lower()
            now = time.monotonic()
            view = (tuple(name for name, phrases, _ in prompts
                          if any(phrase in lower for phrase in phrases)), selected_yes(text))
            if view != stable_view:
                stable_view, stable_since = view, now
            # Cold-start native dialogs can briefly render a selection before
            # settling. Pace only these public setup answers, inside the same30s.
            settled = now - stable_since >= .250
            trace()
            if active is not None:
                name, phrases, phase = active
                if phase == 'select' and name in view[0] and selected_yes(text) and settled:
                    # Selection must be rendered before Enter is a separate event.
                    trace('send', 'confirm')
                    self.send('\r')
                    active = (name, phrases, 'confirm')
                elif phase == 'confirm' and not any(phrase in lower for phrase in phrases):
                    answered.add(name)
                    active = None
                    continue
            else:
                for name, phrases, arrow in prompts:
                    if name not in answered and any(phrase in lower for phrase in phrases):
                        if not settled:
                            break
                        if arrow is not None and not selected_yes(text):
                            trace('send', 'arrow_up' if arrow == '\x1b[A' else 'arrow_down')
                            self.send(arrow)
                            active = (name, phrases, 'select')
                        else:
                            trace('send', 'confirm')
                            self.send('\r')
                            active = (name, phrases, 'confirm')
                        break
                else:
                    if re.search(r'[❯>]\s*$', text, re.MULTILINE) and not any(
                            phrase in lower for phrase in ('no, exit', 'do you trust', 'use this api key')):
                        trace('ready')
                        return
            # Never answer the next prompt or resend Enter before this one leaves.
            self.pump(min(.1, max(0, until - time.monotonic())))
        trace('deadline')
        raise CheckFailure('native startup prompt unavailable or unsupported')

    def command(self, text):
        self.send('\x15' + text + '\r')

    def reversed_labels(self):
        labels = []
        for row in range(self.screen.lines):
            current = ''
            for col in range(self.screen.columns):
                char = self.screen.buffer[row][col]
                if char.reverse:
                    current += char.data
                elif current:
                    labels.append(current.strip()); current = ''
            if current:
                labels.append(current.strip())
        return labels

    def focus(self, label, *, input_field=False):
        until = self.budget.until(UI_LIMIT)
        for _ in range(64):
            focused = label in self.reversed_labels()
            if input_field:
                y = self.screen.cursor.y
                row = self.screen.display[y]
                above = self.screen.display[y - 1] if y else ''
                adjacent = label in row or (label in above and not any(
                    other in row for other in ('New agent name', 'Owner label')))
                focused = focused or (not self.screen.cursor.hidden and adjacent)
            if focused:
                return
            require(time.monotonic() < until, 'native control focus deadline reached')
            self.send('\t')
            self.pump(min(.15, max(0, until - time.monotonic())))
        raise CheckFailure('native exact control could not receive keyboard focus')

    def press(self, label):
        self.visible(label)
        self.focus(label)
        self.send('\r')

    def fill(self, label, value):
        self.visible(label)
        self.focus(label, input_field=True)
        self.send('\x01\x0b' + value)
        self.visible(value)
        self.send('\t')
        self.pump()

    def open_project(self):
        self.command('/peerspan')
        self.press('Connect this project')

    def close_pane(self):
        self.press('Close')
        self.wait(lambda: 'Close' not in self.reversed_labels(), 'native pane did not relinquish button focus')

    def close(self):
        if hasattr(self, 'process') and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=2)
        if hasattr(self, 'master'):
            os.close(self.master)
        self.log.close()


def assert_review(flow, root, session, name, owner, *, existing=False):
    require(type(flow) is dict and flow.get('state') == 'review' and flow.get('attachment') is None,
            'native preparation did not retain an unapproved review')
    review = flow['review']
    require(review['project_root'] == str(root) and review['native_session_id'] == session
            and review['integration'] == 'claude-code' and review['agent']['name'] == name
            and review['agent']['owner'] == owner and review['agent']['capabilities'] == []
            and review['create_agent'] is (not existing)
            and review['effects'] == {**EFFECTS, 'register_agent': not existing},
            'native review terms or nonsigning effects do not match human choice')
    canonical = json.dumps(review, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    require(flow['review_id'] == 'review_' + hashlib.sha256(b'peerspan-project-review-v1\n' + canonical).hexdigest(),
            'native project review digest mismatch')
    expiry = datetime.fromisoformat(review['expires_at'].replace('Z', '+00:00'))
    require(expiry.tzinfo is not None and expiry > datetime.now(timezone.utc), 'prepared review already expired')


def assert_same_review(before, after):
    require(after is not None and after['flow_id'] == before['flow_id']
            and after['review_id'] == before['review_id'] and after['review'] == before['review'],
            'resume changed exact native context, immutable review or original expiry')


def assert_preview(terminal, root, name, owner):
    terminal.visible('Approve attachment')
    rendered = re.sub(r'\s+', '', terminal.text())
    for value in (str(root), name, owner, 'Review expires', 'Record this local session attachment',
                  'Adapter credentials: none', 'Network access: none', 'File sharing: none',
                  'Conversation sharing: none', 'Capability calls: none'):
        require(re.sub(r'\s+', '', value) in rendered, 'human terminal did not show exact reviewed terms/effects')


def registry_delta(before, after, agents, sessions, registrations, attachments):
    require(len(after[0]) - len(before[0]) == agents and len(after[1]) - len(before[1]) == sessions,
            'native human action created an unexpected agent/session count')
    events = after[2][len(before[2]):]
    require(sum(e['kind'] == 'agent.registered' for e in events) == registrations
            and sum(e['kind'] == 'session.attached' for e in events) == attachments,
            'native human action duplicated or omitted ordinary registry events')


def prepare_human(terminal, host, root, session, name, owner):
    before = host.registry()
    terminal.open_project()
    terminal.visible('Project: choose an agent')
    terminal.fill('New agent name', name)
    terminal.fill('Owner label', owner)
    terminal.press('Review new agent')
    assert_preview(terminal, root, name, owner)
    flow = host.lookup(root, session)
    assert_review(flow, root, session, name, owner)
    require(host.registry() == before, 'preparing human review created registry/session/activity effects')
    return flow


def install(cli, marketplace, executable, host, config, env, cwd, budget):
    private_dir(config)
    result = native(cli, ['plugin', 'install', 'peerspan', '--marketplace', str(marketplace),
        '--scope', 'user', '--config', 'executable=' + str(executable),
        '--config', 'state=' + str(host.state), '--json'], operation='terminal fixture installation',
        environment={**env, 'CLAUDE_CONFIG_DIR': str(config)}, cwd=cwd,
        deadline=budget.until(30), as_json=True)
    require(result.get('pluginId') == PLUGIN_ID and result.get('configApplied') is True
            and result.get('outcome') == 'ok', 'installed terminal plugin configuration refused')
    configured = native(cli, ['plugin', 'configure', PLUGIN_ID, '--json'], operation='terminal config lookup',
        environment={**env, 'CLAUDE_CONFIG_DIR': str(config)}, cwd=cwd,
        deadline=budget.until(30), as_json=True)
    require(configured.get('inputs', {}).get('executable') == str(executable)
            and configured['inputs'].get('state') == str(host.state), 'installed executable/state pin changed')
    return {**env, 'CLAUDE_CONFIG_DIR': str(config)}


def loss_wrapper(work, executable):
    """Only this isolated public executable wrapper drops one genuine result."""
    path, attempts = work / 'one real decision wrapper', work / 'private decision attempts'
    source = '''#!SHEBANG
import json, os, subprocess, sys
REAL = REAL_LITERAL
ATTEMPTS = ATTEMPTS_LITERAL
args = sys.argv[1:]
if len(args) >= 6 and args[-4:] == ['onboarding', 'project', 'decide', '--stdin']:
    first = not os.path.exists(ATTEMPTS)
    with open(ATTEMPTS, 'a') as log:
        log.write('attempt\\n')
    if not first:
        raise SystemExit(3)
    payload = sys.stdin.buffer.read(65537)
    result = subprocess.run([REAL, *args], input=payload, capture_output=True)
    if result.returncode == 0:
        try:
            attached = json.loads(result.stdout).get('state') == 'attached'
        except (ValueError, AttributeError):
            attached = False
        if attached:
            raise SystemExit(1)  # Actual host committed; the frontend loses its reply.
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    raise SystemExit(result.returncode)
os.execv(REAL, [REAL, *args])
'''.replace('SHEBANG', sys.executable).replace('REAL_LITERAL', repr(str(executable))).replace(
        'ATTEMPTS_LITERAL', repr(str(attempts)))
    compile(source, '<private lost reply wrapper>', 'exec')
    path.write_text(source); path.chmod(0o700)
    return path, attempts


def check(archive, cli, work):
    global PHASE
    budget = Budget()
    require(importlib.metadata.version('pyte') == '0.8.2', 'terminal emulator must be pinned pyte0.8.2')
    require(hasattr(tarfile, 'data_filter'), 'safe extraction requires Python3.12+')
    require(not work.exists(), 'terminal fixture work directory must be fresh')
    private_dir(work)
    env = environment(work)
    archive_hash = verify_checksum(archive)
    with tarfile.open(archive, 'r:gz') as bundle:
        members, original = safe_members(bundle)
        bundle.extractall(work, members=members, filter='data')
    prefix = work / 'relocated installed prefix with spaces'
    (work / original).rename(prefix)
    metadata, marketplace, plugin, executable, hashes = validate_layout(prefix)
    version = native(cli, ['--version'], operation='version', environment=env, cwd=work,
                     deadline=budget.until(30))
    require(re.fullmatch(r'2\.1\.303(?:\s+\(Claude Code\))?\s*', version.strip()) is not None,
            'actual native runtime must be exactly2.1.303')
    for directory in (plugin, marketplace):
        native(cli, ['plugin', 'validate', str(directory), '--strict'], operation='strict validation',
               environment=env, cwd=work, deadline=budget.until(30))
    provider = RecordingProvider()
    host, terminals = Host(executable, work, env, budget), []
    ui_env = {**env, 'ANTHROPIC_API_KEY': 'sk-ant-terminal-fixture-not-a-real-key',
              'ANTHROPIC_BASE_URL': provider.url}
    try:
        PHASE = 'installed_host_start'
        host.start()
        normal_env = install(cli, marketplace, executable, host, work / 'normal Claude config',
                             ui_env, work, budget)

        def terminal(label, environment):
            root = private_dir(work / label)
            session = str(uuid.uuid4())
            instance = Terminal(cli, root, session, environment, budget, work / (label + '.pty'))
            terminals.append(instance)
            return instance, root, session

        PHASE = 'real_pending_review'
        ui, root, session = terminal('normal project', normal_env)
        pending = prepare_human(ui, host, root, session, 'terminal-agent', 'terminal owner')
        before = host.registry()
        ui.close_pane()
        ui.command('/reload-plugins --force')
        # Wait for actual public reload completion, then reopen the same native conversation.
        ui.wait(lambda: 'reload' in ui.text().lower() and any(
            token in ui.text().lower() for token in ('reloaded', 'reload complete', 'successfully')),
            'public plugin reload did not complete')
        ui.open_project()
        assert_preview(ui, root, 'terminal-agent', 'terminal owner')
        assert_same_review(pending, host.lookup(root, session))
        require(host.registry() == before, 'reload/resume duplicated preparation or attachment')

        PHASE = 'pending_daemon_restart'
        host.stop(); host.start()
        assert_same_review(pending, host.lookup(root, session))
        require(host.lookup(root, session)['state'] == 'review', 'restart consumed pending approval')
        ui.press('Refresh')
        assert_preview(ui, root, 'terminal-agent', 'terminal owner')
        PHASE = 'real_human_approval'
        ui.press('Approve attachment')
        ui.visible('Project: attachment recorded')
        attached = host.lookup(root, session)
        assert_same_review(pending, attached)
        require(attached['state'] == 'attached' and attached['attachment'] == {
            'agent_id': pending['review']['agent']['id'], 'session_id': pending['review']['session_id']},
            'human terminal approval did not commit the reviewed attachment')
        registry_delta(before, host.registry(), 1, 1, 1, 1)
        require(host.cli('onboarding')['agents'][0]['sessions'][0]['adapter_id'] is None,
                'metadata approval unexpectedly issued adapter credentials')
        ui.close_pane()

        PHASE = 'attached_restart_invalidation'
        host.stop(); host.start()
        invalidated = host.lookup(root, session)
        assert_same_review(attached, invalidated)
        require(invalidated['state'] == 'invalidated' and invalidated['attachment'] == attached['attachment'],
                'restart resurrected or erased attached outcome')
        after_restart = host.registry()
        ui.open_project()
        ui.visible('Review a replacement')
        require('Approve attachment' not in ui.text(), 'invalidated attachment remained actionable')
        require(host.registry() == after_restart, 'opening invalidated review reattached the session')
        ui.press('Review a replacement')
        ui.press('Review agent "terminal-agent"')
        assert_preview(ui, root, 'terminal-agent', 'terminal owner')
        replacement = host.lookup(root, session)
        assert_review(replacement, root, session, 'terminal-agent', 'terminal owner', existing=True)
        require(replacement['flow_id'] != pending['flow_id'] and replacement['review_id'] != pending['review_id'],
                'explicit replacement reused old review authority')
        require(host.inspect(pending)['state'] == 'invalidated', 'replacement changed old immutable history')
        ui.press('Approve attachment')
        ui.visible('Project: attachment recorded')
        registry_delta(after_restart, host.registry(), 0, 1, 0, 1)
        ui.close(); terminals.remove(ui)
        print('PASS installed terminal: same-session reload, exact pending restart, human approval, invalidation and explicit replacement')

        PHASE = 'failed_and_declined_review'
        ui, root, session = terminal('declined project', normal_env)
        before_failed = host.registry()
        ui.open_project()
        ui.fill('New agent name', '*')  # Public registry contract reserves this name.
        ui.fill('Owner label', 'declined owner')
        ui.press('Review new agent')
        ui.wait(lambda: any(word in ui.text().lower() for word in ('unavailable', 'invalid', 'unable', 'could not')),
                'failed preparation did not show controlled refusal')
        require('Approve attachment' not in ui.text() and host.lookup(root, session) is None,
                'failed project review became actionable or created a flow')
        require(host.registry() == before_failed, 'failed project review granted an attachment')
        ui.close_pane()
        declined = prepare_human(ui, host, root, session, 'declined-agent', 'declined owner')
        before = host.registry()
        ui.press('Decline attachment')
        ui.visible('Review a replacement')
        outcome = host.lookup(root, session)
        assert_same_review(declined, outcome)
        require(outcome['state'] == 'declined' and outcome['attachment'] is None,
                'actual decline attached a project')
        require(host.registry() == before, 'declined review granted registry/session effects')
        ui.close(); terminals.remove(ui)
        print('PASS installed terminal: failed preparation and declined human review grant no attachment')

        PHASE = 'real_lost_decision_reply'
        wrapper, attempts = loss_wrapper(work, executable)
        lost_env = install(cli, marketplace, wrapper, host, work / 'lost reply Claude config',
                           ui_env, work, budget)
        ui, root, session = terminal('lost reply project', lost_env)
        pending = prepare_human(ui, host, root, session, 'lost-reply-agent', 'lost reply owner')
        before = host.registry()
        ui.press('Approve attachment')
        ui.wait(lambda: 'Refresh' in ui.text() and any(word in ui.text().lower()
                for word in ('unknown', 'unavailable', 'could not', 'unable')),
                'lost real decision reply did not present controlled uncertainty')
        # No automatic mutation retry; lookup is the first durable-outcome recovery.
        require(attempts.read_text() == 'attempt\n', 'lost response repeated an owner decision')
        recovered = host.lookup(root, session)
        assert_same_review(pending, recovered)
        require(recovered['state'] == 'attached', 'lost reply did not follow a real committed attachment')
        ui.close_pane()
        ui.open_project()
        ui.visible('Project: attachment recorded')
        assert_same_review(recovered, host.lookup(root, session))
        require(attempts.read_text() == 'attempt\n', 'lookup recovery repeated the mutation')
        registry_delta(before, host.registry(), 1, 1, 1, 1)
        ui.close(); terminals.remove(ui)
        require(provider.requests == 0, 'UI-only terminal flow sent an inference request')
        require(validate_layout(prefix)[4] == hashes, 'terminal installation modified bundled source bytes')
        require(time.monotonic() < budget.deadline, 'terminal acceptance exceeded10 minutes')
        print('PASS installed terminal: one real decision with lost reply, exact lookup recovery, zero inference requests')
        print('claude_version=2.1.303 terminal_cases=3 decision_loss_invocations=1 model_requests=0')
        print('archive_sha256=' + archive_hash)
        print('source_sha256=' + sha256_file(Path(__file__)))
        print('LIMIT real terminal loopback fixture; no live model, adapter delivery, peer authority or physical-machine claim; fixed15-minute expiry preserved, not waited out')
    finally:
        for terminal in terminals:
            terminal.close()
        host.stop()
        provider.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--claude', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True, help='fresh private fixture path; retained on failure')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        check(args.archive.resolve(), args.claude.resolve(), args.work.resolve())
    except (CheckFailure, OSError, ValueError, KeyError, TypeError, ImportError,
            subprocess.SubprocessError, tarfile.TarError) as error:
        # Never print native/provider errors, paths, private UI strings or traceback.
        kind = 'contract' if isinstance(error, CheckFailure) else 'local_input_or_terminal'
        try:
            failure = dict(phase=PHASE, category=kind, check=str(error) if isinstance(error, CheckFailure)
                           else 'local input or terminal operation unavailable')
            # CheckFailure messages originate in this test/public bundle helper,
            # never captured CLI output. Keep even these fixed details private.
            with (args.work / 'terminal-failure.json').open('x') as output:
                json.dump(failure, output, sort_keys=True)
                output.write('\n')
        except OSError:
            pass  # Diagnostic failure cannot hide the original verdict.
        print('FAIL installed terminal: phase=' + PHASE + ' category=' + kind)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
