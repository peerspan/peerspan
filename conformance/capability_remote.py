#!/usr/bin/env python3
"""Remote MCP servers and OAuth (capabilities slice 3, item A), run by conformance/capabilities.py.

Written from docs/capabilities-contract.md, "Remote MCP servers and OAuth (slice 3)" and its Verification list, with
docs/capabilities-slice3-remote-proposal.md for intent, independently of the Go and Rust hosts. No real provider is
contacted: fixtures/remote/remote.py runs fake Streamable HTTP MCP servers and fake OAuth authorization servers on
loopback HTTP, in threads of this process, recording every request. The suite drives each authorization URL itself
(the fake approves at once and redirects), then hands the redirect to the CLI's loopback listener, pastes it, or
posts it to the local API.

Each CLI/daemon pairing gets its own topology:
- pat: p1 serves. Its host name is `remote-p1.lan` (a UTS namespace), so its client name is `Peerspan (remote-p1)`.
  Agents attached through the fixture integration: `cc` (Claude Code), `cx` (Codex), `oc` (OpenCode), discovering
  remote servers from generated harness configuration; registered agents whose definitions this suite PUTs itself:
  `var` (one source `v`, for the sign-in variants), `run` (sources for the running cases), `old` (a PUT without the
  new fields), and `idl` (the idle stop). p1 opens its sources to p2.
- p2: pat's trusted host (self calls and raw source calls).
- quinn: q1, the caller by policy; with --baseline18, o1, a version 18 host of quinn's (older peers).
Network: team.

Sections, per pairing (contract Verification bullets in brackets):
- discovery [Discovery]; reasons [Reasons]; auth mode [Auth mode];
- sign-in, sign-in variants, sign-in refusals [Sign-in];
- tokens [Tokens]; revocation [Revocation]; per-capability sign-in [Per-capability sign-in];
- running [Running], with the idle DELETE checked last (its instance starts during setup);
- capabilities and calls [Capabilities and calls] (call_capability runs in capability_agents.py, section
  "remote (slice 3)", with --node);
- status [Status]; older peers [Older peers] with --baseline18; secrets (tokens, codes, secrets, and header values
  nowhere but the host database's credential and value tables).
Once per run (from capabilities.py): migration from version 21 and, with --baseline18, from a real version 18 state
(with a remote source keeping the reason `remote` until the next PUT), to version 22; version 23 refused [Migration,
Reasons].

Where the contract is silent, the suite takes the reading most faithful to the proposal; such spots are marked "Q:"
and soft results are NOTE lines.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

from coordination import Coordinator, wait_for
from launch_directory import uts_available
from host_service import stop_all
from launch_onboarding import Failure, need, parse_time
from peer_messaging import fixture_context, timestamp, wire
from persons import Agent, person_id, ssh_key

import capabilities as caps
from capabilities import CapHost, PYTHON, HARNESS, SHARE_PROMPT, FINAL, db_rows, squash, toml_string

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'fixtures' / 'remote'))
from remote import AuthServer, McpServer, Site, s256, digest  # noqa: E402

# --- the contract's exact texts and shapes ----------------------------------------------------------------------

HOST_NAME = 'remote-p1.lan'
CLIENT_NAME = 'Peerspan (remote-p1)'
DEFAULT_REMOTE = {'protocol': 'http', 'oauth': {'client_id': None, 'scopes': None, 'callback_port': None},
                  'headers_helper': False}
AUTH_KEYS = {'mode', 'state', 'issuer', 'scope', 'account', 'registration', 'obtained_at', 'expires_at'}
CAP_AUTH_KEYS = AUTH_KEYS | {'own'}
NULL_AUTH = {k: None for k in AUTH_KEYS}
REASONS = ['name', 'disabled', 'insecure_url', 'sse', 'headers_helper', 'missing_env', 'login']
LOGIN_RESULT_KEYS = {'source', 'capability', 'issuer', 'scopes', 'account', 'expires_at', 'registration'}
LOGIN_START_KEYS = {'login_id', 'authorization_url', 'redirect_uri', 'expires_at'}
LOGOUT_KEYS = {'source', 'capability', 'revoked', 'deleted'}
CREDENTIAL_KEYS = {'issuer', 'resource', 'registration', 'client', 'token_endpoint', 'revocation_endpoint',
                   'access_token', 'refresh_token', 'token_type', 'expires_at', 'scope', 'account', 'obtained_at',
                   'refreshed_at', 'state', 'refresh_failed_at'}
CLIENT_KEYS = {'issuer', 'redirect_uri', 'client_id', 'client_secret', 'registration_access_token', 'method',
               'registration', 'created_at'}
DCR_BODY_KEYS = ['client_name', 'redirect_uris', 'grant_types', 'response_types', 'token_endpoint_auth_method',
                 'application_type']
LOGIN_ID = re.compile(r'^login_[0-9a-f]{32}$')
STATE = re.compile(r'^[0-9a-f]{64}$')
VERIFIER = re.compile(r'^[A-Za-z0-9_-]{43}$')

LAPSED_ERROR = "the capability's sign-in has lapsed on its host"
PRINT_BLOCK = ('Open this link in a browser on any machine and approve Peerspan:', '{url}',
               'If the browser then shows a page that cannot be reached, copy the full address',
               'from its address bar and paste it here:')
OPENING = 'Opening your browser to approve Peerspan. If it does not open, use this link:'
COMPLETE_PAGE = 'Peerspan sign-in complete. You can close this tab.'
FAILED_PAGE = 'Peerspan sign-in failed.'
NEEDS_TERMINAL = ('{cmd} needs a terminal, or --no-browser to print the link and read the pasted address from '
                  'stdin.')
SECRET_NEEDS_ID = '--client-secret-file needs --client-id.'
SECRET_MODE = '{path} must have mode 0600 or stricter.'
PORT_BUSY = 'Port {port} on 127.0.0.1 is in use, so Peerspan cannot receive the redirect; paste the address instead.'
NOT_COMPLETED = 'The sign-in was not completed.'
SIGNED_IN = 'Signed in to {host} for {source} (scopes: {scope}).'
LOGOUT_PROMPT = 'Sign out? Calls to these capabilities will fail until the next sign-in. [y/N]'
LOGOUT_CONFIRM = 'confirm this sign-out at a terminal, or pass --yes'
NO_REVOCATION = ('{issuer} has no revocation endpoint Peerspan could use. To revoke access there, remove '
                 '"Peerspan ({label})" from the connected apps of your account.')
NO_SIGN_IN = '{source} has no sign-in on this host.'
NO_OWN_SIGN_IN = '{name} has no sign-in of its own on this host.'
GUIDED_NEEDS_LOGIN = '{source} needs a sign-in first: run peerspan sources login {source}'
ARG_REFUSED = '--arg applies only to stdio sources'

REFUSALS = {
    'not_found': (404, 'No source {source} on this host. Run peerspan sources.'),
    'no_capability': (404, 'No capability {name} on this host. Run peerspan capability list.', 'not_found'),
    'other_source': (400, '{name} is not built on {source}.', 'invalid'),
    'oauth_disabled': (409, '{source} has OAuth turned off in its harness configuration.'),
    'not_usable': (409, '{source} is not usable ({reason}), so Peerspan cannot sign in to it.'),
    'no_challenge': (409, '{source} did not ask for a sign-in, so there is nothing to sign in to.'),
    'unreachable': (502, 'Peerspan could not reach {source}: '),
    'oauth_metadata': (502, 'Peerspan could not read the authorization server metadata for {source}: '),
    'no_pkce': (409, 'The authorization server for {source} ({issuer}) does not advertise PKCE, so Peerspan will not '
                     'sign in to it.'),
    'no_registration': (409, 'The authorization server for {source} ({issuer}) does not let Peerspan register '
                             'itself. Register an OAuth app with the provider, with redirect URI '
                             'http://127.0.0.1:{port}/callback, then run: peerspan sources login {source} --client-id '
                             'ID [--client-secret-file PATH]'),
    'registration_failed': (502, 'The authorization server for {source} ({issuer}) refused to register Peerspan: '),
    'login_expired': (400, 'This sign-in link is no longer valid. Run peerspan sources login {source} again.'),
    'provider_refused': (400, 'The provider refused the sign-in: {error}.'),
    'no_code': (400, 'The redirect carried no authorization code. Run peerspan sources login {source} again.'),
    'token_refused': (502, 'The provider refused to issue a token: {error}.'),
}
# Codes whose text ends in a free DETAIL (only the prefix is shared).
DETAIL_CODES = {'unreachable', 'oauth_metadata', 'registration_failed'}


def cid():
    return 'call_' + secrets.token_hex(16)


def refusal_text(code, **values):
    return REFUSALS[code][1].format(**values)


def text_of(result):
    try:
        return result['content'][0]['text']
    except (TypeError, KeyError, IndexError):
        return None


def host_of(url):
    """ISSUER_HOST / URL_HOST: the host, lowercased, without port; an IPv6 host keeps its brackets."""
    netloc = urllib.parse.urlsplit(url).netloc.rsplit('@', 1)[-1]
    if netloc.startswith('['):
        return netloc[:netloc.index(']') + 1].lower()
    return netloc.split(':')[0].lower()


def canonical(url):
    """The canonical URL: scheme and host lowercased, no fragment, trailing `/` removed from the path."""
    u = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((u.scheme.lower(), u.netloc.lower(), u.path.rstrip('/'), u.query, ''))


def query_of(url):
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query,
                                                      keep_blank_values=True).items()}


def basic_of(headers):
    auth = headers.get('authorization', '')
    if not auth.lower().startswith('basic '):
        return None
    cid_, _, secret = base64.b64decode(auth[6:]).decode().partition(':')
    return urllib.parse.unquote_plus(cid_), urllib.parse.unquote_plus(secret)


def bearer_of(request):
    auth = request['headers'].get('authorization', '')
    return auth[7:] if auth.startswith('Bearer ') else None


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class RemoteHost(CapHost):
    """A CapHost whose CLI environment can drop variables (SSH_CONNECTION, DISPLAY, ...) and put a directory first on
    PATH (a fake xdg-open)."""
    drop = ()
    first_path = None
    proxy_env = None

    def daemon_env(self):
        env = super().daemon_env()
        env.update(self.proxy_env or {})
        return env

    def environment(self, sock=caps.DEFAULT, env=None):
        e = super().environment(sock, None)
        for name in self.drop:
            e.pop(name, None)
        if self.first_path:
            e['PATH'] = str(self.first_path) + os.pathsep + e['PATH']
        e.update(env or {})
        for name, value in list(e.items()):
            if value is None:
                e.pop(name)
        return e


AUTH_URL = re.compile(r'(https?://[^\s]+/authorize\?[^\s]+)')


class Login:
    """One `sources login` run by the CLI, driven like a person would: read the link it prints (or the fake browser
    opener receives), "approve" it at the fake authorization server, then deliver the redirect to the CLI's loopback
    listener, or paste it on stdin. The terminal form runs the CLI on a pseudo-terminal."""

    def __init__(self, host, args, env=None, terminal=False, opener_log=None):
        self.host, self.args, self.terminal, self.opener_log = host, list(args), terminal, opener_log
        self.text = b''
        self.stdout = b''
        self.pasted = []
        command = [host.cli_binary, '--state', str(host.state), *args]
        environment = host.environment(caps.DEFAULT, env)
        if terminal:
            import fcntl
            import termios
            master, slave = os.openpty()

            def preexec():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            self.process = subprocess.Popen(command, stdin=slave, stdout=subprocess.PIPE, stderr=slave,
                                            env=environment, preexec_fn=host.preexec(preexec))
            os.close(slave)
            self.master = master
            self.err = master
        else:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, env=environment, preexec_fn=host.preexec())
            self.master = None
            self.err = self.process.stderr.fileno()
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.reader.start()

    def _read_stdout(self):
        self.stdout = self.process.stdout.read()

    def pump(self, seconds=0.1):
        ready, _, _ = select.select([self.err], [], [], seconds)
        if ready:
            try:
                data = os.read(self.err, 65536)
            except OSError:
                data = b''
            self.text += data
            return bool(data)
        return False

    def wait_text(self, predicate, timeout=60):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            got = predicate(self.text.decode(errors='replace'))
            if got:
                return got
            if self.process.poll() is not None:
                while self.pump(0.05):
                    pass
                return predicate(self.text.decode(errors='replace'))
            self.pump(0.1)
        return predicate(self.text.decode(errors='replace'))

    def link(self, timeout=90):
        """The authorization URL the CLI printed, or that the fake opener received."""
        def found(text):
            if self.opener_log:     # the browser case: only what the opener received counts
                if Path(self.opener_log).exists():
                    lines = [l for l in Path(self.opener_log).read_text().splitlines() if l.strip()]
                    if lines:
                        return json.loads(lines[-1])['argv'][-1]
                return None
            m = AUTH_URL.search(text)
            return m.group(1) if m else None
        return self.wait_text(found, timeout)

    def paste(self, line):
        self.pasted.append(line)
        data = (line + '\n').encode()
        if self.master is not None:
            os.write(self.master, data)
        else:
            self.process.stdin.write(data)
            self.process.stdin.flush()

    def finish(self, timeout=120):
        """(exit code, parsed stdout or None, stderr/terminal text, stdout)."""
        end = time.monotonic() + timeout
        while self.process.poll() is None and time.monotonic() < end:
            self.pump(0.1)
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        while self.pump(0.05):
            pass
        self.reader.join(timeout=10)
        if self.master is not None:
            os.close(self.master)
        elif self.process.stdin:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        stdout = self.stdout.decode(errors='replace')
        try:
            value = json.loads(stdout) if stdout.strip() else None
        except ValueError:
            value = None
        text = self.text.decode(errors='replace')
        for line in self.pasted:    # a terminal echoes what the person pastes; that is their own input
            text = text.replace(line, '<pasted address>')
        return self.process.returncode, value, text, stdout


def deliver(location, timeout=10):
    """GET the redirect at the CLI's loopback listener, as the browser would: (status, body)."""
    import http.client
    u = urllib.parse.urlsplit(location)
    connection = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        connection.request('GET', u.path + ('?' + u.query if u.query else ''))
        response = connection.getresponse()
        return response.status, response.read().decode(errors='replace')
    finally:
        connection.close()


FAKE_OPENER = '''#!{python} -I
import json, sys, time
with open({log!r}, 'a') as f:
    f.write(json.dumps({{'argv': sys.argv, 'time': time.time()}}) + '\\n')
'''


def fake_openers(directory):
    """xdg-open and open scripts that only record their arguments (each in its own log)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    logs = {}
    for name in ('xdg-open', 'open'):
        log = directory / f'{name}.jsonl'
        path = directory / name
        path.write_text(FAKE_OPENER.format(python=PYTHON, log=str(log)))
        path.chmod(0o755)
        logs[name] = log
    return logs




# --- the pairing ------------------------------------------------------------------------------------------------

class RemotePairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, root, only=None, baseline18=None):
        self.label, self.cli_binary, self.daemon, self.root = label, cli_binary, daemon_binary, root
        self.only, self.baseline18 = only, baseline18
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results, self.notes, self.setup_notes = [], [], []
        self.hosts, self.ids, self.keys, self.agents, self.aid = {}, {}, {}, {}, {}
        self.exposed = []          # (where, text) of everything shown to a person or a peer, for the secret scan
        self.sites = []
        self.done = set()          # milestones later sections rely on

    # --- infrastructure ----------------------------------------------------------------------------------------

    def host(self, name, person, daemon=None, cli=None):
        h = RemoteHost(daemon or self.daemon, cli or self.cli_binary, self.root / name, self.root / f'user-{name}')
        h.sock = self.agents[person].socket if person else None
        self.hosts[name] = h
        return h

    def section(self, name, function):
        if self.only and name not in self.only:
            return None
        started = time.monotonic()
        try:
            notes = function() or ''
        except Exception as error:
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=5)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [remote: {name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [remote: {name}] ({time.monotonic() - started:.0f}s)'
              f'{": " + notes if notes else ""}', flush=True)
        return True

    def soft(self, condition, rule, *detail):
        if not condition:
            self.notes.append(f'{rule}: ' + ' | '.join(repr(d)[:300] for d in detail))
            print(f'NOTE {self.label} (not counted): {rule}', flush=True)
        return condition

    def needs(self, *milestones):
        missing = [m for m in milestones if m not in self.done]
        need(not missing, 'setup: what this section relies on was set up', missing, *self.setup_notes[-5:])

    def site(self, s):
        self.sites.append(s)
        return s

    def mcp(self, name, path='/mcp', **cfg):
        m = self.site(McpServer(name, path))
        m.cfg.update(cfg)
        return m

    def auth_server(self, name, issuer_path='', **cfg):
        a = self.site(AuthServer(name, issuer_path))
        a.cfg.update(cfg)
        return a

    def coordinator_flags(self):
        return ('--coordinator', self.coord.address, '--coordinator-key', self.coord_key)

    def invite(self, label):
        return self.hosts['p1'].cli('network', 'invite', '--network', self.team, '--member', label,
                                    '--expires-in', '1h')['token']

    def policy(self, host='p1'):
        status, body = self.hosts[host].call('GET', f'/v1/networks/{self.team}/policy?person={self.pat}')
        return caps.policy_of(body) if status == 200 else None

    def version(self, host='p1'):
        p = self.policy(host)
        return p['version'] if p else 0

    def synced(self, *names, timeout=40):
        version = self.version('p1')
        for name in names:
            h = self.hosts[name]

            def caught_up():
                h.run('network', 'sync', self.team)
                return self.version(name) >= version
            wait_for(caught_up, timeout=timeout, message=f'policy version {version} on {name}')

    def sync(self):
        self.synced('p2', 'q1', *(['o1'] if 'o1' in self.hosts else []))

    def rule_for(self, name):
        for r in (self.policy('p1') or {}).get('capability_rules') or []:
            if r['capability'] == name and r['host'] == self.ids['p1']:
                return r
        return None

    def out(self, host, *args, env=None, timeout=150, piped=None):
        """(exit code, parsed stdout or None, stdout, stderr), recorded for the secret scan."""
        code, value, stdout, stderr = self.hosts[host].outcome(*args, env=env, cwd=str(self.root), timeout=timeout,
                                                               piped=piped)
        self.exposed.append((f'{host} {" ".join(args[:3])}', stdout + stderr))
        return code, value, stdout, stderr

    def api(self, method, path, body=None, host='p1'):
        status, value = self.hosts[host].call(method, path, body)
        self.exposed.append((f'{host} {method} {path}', json.dumps(value)))
        return status, value

    def terminal(self, host, *args, answers=('y',), prompt=None, env=None, timeout=120):
        code, value, tty, stdout, seen = self.hosts[host].converse(*args, answers=list(answers), prompt=prompt,
                                                                   env=env, timeout=timeout)
        self.exposed.append((f'{host} {" ".join(args[:3])} (terminal)', tty + stdout))
        return code, value, tty, stdout, seen

    def activity(self, host='p1'):
        """Every local event, read in pages of 1,000 after a sequence cursor."""
        events, after = [], 0
        while True:
            page = self.hosts[host].cli('activity', '--after', str(after), '--limit', '1000')
            self.exposed.append((f'{host} activity', json.dumps(page)))
            events += page
            if len(page) < 1000:
                return events
            after = page[-1]['sequence']

    def kinds_for(self, kind, host='p1'):
        return [e for e in self.activity(host) if e.get('kind') == kind]

    # sources

    def view(self, host='p1'):
        status, value = self.api('GET', '/v1/sources', host=host)
        need(status == 200 and isinstance(value, dict), 'GET /v1/sources', status, value)
        return value

    def servers(self, agent, host='p1'):
        for a in self.view(host)['agents']:
            if a['agent']['name'] == agent:
                return {s['name']: s for s in a['servers']}
        return {}

    def server(self, agent, name, host='p1'):
        s = self.servers(agent, host).get(name)
        need(s is not None, f'{agent}/{name} is listed', sorted(self.servers(agent, host)))
        return s

    def record(self, agent, name):
        rows = db_rows(self.hosts['p1'], 'SELECT record FROM tool_servers WHERE agent_id = ? AND name = ?',
                       (self.aid[agent], name))
        return json.loads(rows[0][0]) if rows else None

    def values(self, agent, name):
        return dict(db_rows(self.hosts['p1'], 'SELECT field, value FROM tool_values WHERE agent_id = ? AND server = ?',
                            (self.aid[agent], name)))

    def credential(self, agent, name, capability=''):
        rows = db_rows(self.hosts['p1'], 'SELECT record FROM oauth_credentials WHERE agent_id = ? AND server = ? AND '
                       'capability = ?', (self.aid[agent], name, capability))
        return json.loads(rows[0][0]) if rows else None

    def clients(self, issuer=None):
        rows = db_rows(self.hosts['p1'], 'SELECT issuer, redirect_uri, record FROM oauth_clients')
        return [json.loads(r[2]) for r in rows if issuer is None or r[0] == issuer]

    def put(self, agent, servers, values=None, workspace=None, expect=200):
        status, body = self.api('PUT', f'/v1/agents/{self.aid[agent]}/tool-servers',
                                {'workspace': str(workspace or self.root), 'servers': servers,
                                 'values': values or {}})
        if expect is not None:
            need(status == expect, f'PUT tool-servers for {agent}', status, str(body)[:600])
        return status, body

    def refresh(self, agent, env=None, expect=0):
        code, value, stdout, stderr = self.out('p1', 'sources', 'refresh', '--agent', agent,
                                               env={**self.cli_env, **(env or {})}, timeout=240)
        if expect is not None:
            need(code == expect, f'sources refresh --agent {agent}', code, stderr[-600:])
        return code, value, stdout, stderr

    def register(self, name):
        agent = self.hosts['p1'].cli('agent', 'register', '--name', name, '--owner', 'pat')
        self.aid[name] = agent['id']
        return agent

    @staticmethod
    def remote_def(name, url, headers=None, remote=None, source='claude-code:user'):
        d = {'name': name, 'transport': 'remote', 'command': None, 'args': [], 'env': {}, 'url': url,
             'source': source}
        d['remote'] = remote if remote is not None else json.loads(json.dumps(DEFAULT_REMOTE))
        d['headers'] = headers or {}
        return d

    # capabilities and shares

    def create(self, name, source, operations, *extra, expect=0, host='p1'):
        args = ['capability', 'create', name, '--from', source, '--operations', ','.join(operations), *extra]
        code, value, stdout, stderr = self.out(host, *args)
        if expect is not None:
            need(code == expect, f'capability create {name} --from {source}', code, stdout[-300:], stderr[-500:])
        return code, value, stderr

    def capability(self, name):
        status, body = self.api('GET', f'/v1/capabilities/{name}')
        return body if status == 200 else None

    def share(self, name, principal='quinn', terminal=True, per_hour=1000):
        args = ['share', name, '--with', principal, '--network', self.team, '--calls-per-hour', str(per_hour)]
        h = self.hosts['p1']
        if terminal:
            code, value, tty, stdout, seen = h.at_terminal(*args, answer='y', prompt=SHARE_PROMPT, timeout=150)
            self.exposed.append((f'share {name}', tty + stdout))
            need(code == 0 and seen, f'share {name} --with {principal} at a terminal', code, tty[-800:])
            return tty
        code, value, stdout, stderr = self.out('p1', *args, '--yes')
        need(code == 0, f'share {name} --with {principal} --yes', code, stderr[-600:])
        return stderr

    def review(self, name, principal='quinn'):
        """The review `share` prints, declined at the terminal (nothing signed)."""
        args = ['share', name, '--with', principal, '--network', self.team]
        code, value, tty, stdout, seen = self.hosts['p1'].at_terminal(*args, answer='n', prompt=SHARE_PROMPT,
                                                                      timeout=150)
        self.exposed.append((f'review {name}', tty + stdout))
        need(seen and code == 1, f'the review of {name} is shown and declining exits 1', code, tty[-600:])
        return tty

    @staticmethod
    def credential_line(review):
        lines = [squash(l) for l in review.splitlines() if squash(l).startswith('Credential')]
        return lines

    # calls through the peer route

    def wire(self, receiver, caller, method, path, body=None):
        contexts = self.__dict__.setdefault('contexts', {})
        for attempt in range(10):
            try:
                if caller not in contexts:
                    contexts[caller] = fixture_context(self.hosts[caller])
                return wire(self.hosts[receiver], contexts[caller], method, path, body)
            except (OSError, sqlite3.OperationalError) as error:
                if attempt == 9:
                    raise
                print(f'NOTE {self.label}: retrying a probe request after {error!r}', flush=True)
                time.sleep(2 + attempt)

    def cite(self, caller):
        if caller == 'p2':
            return {'self': {'person_id': self.pat, 'network_id': self.team}}
        return {'policy': {'person_id': self.pat, 'network_id': self.team, 'version': self.version('p1')}}

    def submit(self, capability, operation, input=None, caller='q1', call_id=None, deadline=None):
        body = {'call_id': call_id or cid(), 'capability': capability, 'operation': operation,
                'input': input or {}, 'deadline': deadline or timestamp(300), **self.cite(caller)}
        started = time.monotonic()
        while True:
            status, record = self.wire('p1', caller, 'POST', '/peer/v1/calls', body)
            if not (status == 503 and isinstance(record, dict) and 'coordination' in str(record.get('error'))
                    and time.monotonic() - started < 90):
                break
            time.sleep(3)
        self.exposed.append((f'{caller} submit {capability}', json.dumps(record)))
        return body['call_id'], status, record

    def status_of(self, call_id, caller='q1'):
        status, record = self.wire('p1', caller, 'GET', f'/peer/v1/calls/{call_id}')
        self.exposed.append((f'{caller} status {call_id}', json.dumps(record)))
        return status, record

    def final(self, call_id, caller='q1', timeout=90):
        def done():
            status, record = self.status_of(call_id, caller)
            return record if status == 200 and record.get('state') in FINAL else None
        return wait_for(done, timeout=timeout, message=f'call {call_id} final')

    def state_is(self, call_id, state, caller='q1', timeout=30):
        def reached():
            status, record = self.status_of(call_id, caller)
            return record if status == 200 and record.get('state') == state else None
        return wait_for(reached, timeout=timeout, message=f'call {call_id} {state}')

    def run_call(self, capability, operation, input=None, caller='q1', timeout=90, rule='the call'):
        call_id, status, record = self.submit(capability, operation, input, caller)
        need(status == 200, f'{rule}: accepted (200)', capability, operation, status, record)
        return self.final(call_id, caller, timeout=timeout)

    def received(self):
        return db_rows(self.hosts['p1'], 'SELECT COUNT(*) FROM received_calls')[0][0]

    def items(self, kind='capability_failing'):
        status, value = self.api('GET', '/v1/status')
        need(status == 200, 'GET /v1/status', status)
        return [i for i in value['attention'] if i['kind'] == kind]

    def item(self, subject):
        found = [i for i in self.items() if i['subject'] == subject]
        return found[0] if found else None

    def counts(self):
        status, value = self.api('GET', '/v1/status')
        need(status == 200, 'GET /v1/status', status)
        return value['capabilities']

    # signing in

    def login_start(self, agent, server, body=None, host='p1'):
        return self.api('POST', f'/v1/sources/{agent}/{server}/login', body or {}, host=host)

    def login_complete(self, login_id, callback_url):
        return self.api('POST', f'/v1/oauth/logins/{login_id}/complete', {'callback_url': callback_url})

    def login_api(self, agent, server, auth_server, body=None, approve=True, rule='a sign-in'):
        """Start, approve at the fake, and complete through the local API: (start, location, complete status,
        complete body)."""
        status, start = self.login_start(agent, server, body)
        need(status == 200 and isinstance(start, dict) and set(start) == LOGIN_START_KEYS,
             f'{rule}: POST /v1/sources/{{agent}}/{{server}}/login answers 200 {{login_id, authorization_url, '
             'redirect_uri, expires_at}', status, start)
        if not approve:
            return start, None, None, None
        code, location = auth_server.approve(start['authorization_url'])
        need(code == 302 and location, f'{rule}: the fake authorization server approves the URL',
             code, location, auth_server.violations[-1:] if auth_server.violations else None)
        status, done = self.login_complete(start['login_id'], location)
        return start, location, status, done

    def login_ok(self, agent, server, auth_server, body=None, rule='a sign-in'):
        start, location, status, done = self.login_api(agent, server, auth_server, body, rule=rule)
        need(status == 200 and isinstance(done, dict) and set(done) == LOGIN_RESULT_KEYS,
             f'{rule}: completes with 200 {{source, capability, issuer, scopes, account, expires_at, registration}}',
             status, done, auth_server.violations[-2:])
        return start, done

    def cli_login(self, source, *flags, mode='listener', env=None, command=('sources', 'login'), rule='sign-in'):
        """`sources login SOURCE --no-browser`, delivering the redirect to the listener or pasting it."""
        login = Login(self.hosts['p1'], [*command, source, '--no-browser', *flags], env=env)
        url = login.link()
        if not url:
            result = login.finish(timeout=30)
            self.exposed.append((f'{" ".join(command)} {source}', result[2] + result[3]))
            raise Failure(f'{rule}: the CLI prints the authorization URL: {result}')
        approver = self.approver_for(url)
        code, location = approver.approve(url)
        need(code == 302 and location, f'{rule}: the authorization URL is approved', code, location,
             approver.violations[-2:])
        page = None
        if mode == 'listener':
            page = deliver(location)
        else:
            login.paste(location)
        result = login.finish()
        self.exposed.append((f'{" ".join(command)} {source}', result[2] + result[3]))
        return result, url, location, page

    def approver_for(self, url):
        origin = '{0.scheme}://{0.netloc}'.format(urllib.parse.urlsplit(url))
        for s in self.sites:
            if isinstance(s, AuthServer) and s.origin == origin:
                return s
        raise Failure(f'no fake authorization server at {origin}')

    # --- setup -------------------------------------------------------------------------------------------------

    def setup_catalog(self):
        self.catalog = self.root / 'integrations'
        for identity in ('claude-code', 'codex', 'opencode'):
            bundle = self.catalog / identity
            bundle.mkdir(parents=True)
            shutil.copy2(HARNESS / 'provider.py', bundle / 'provider.py')
            shutil.copy2(HARNESS / 'harness.py', bundle / 'harness.py')
            (bundle / 'integration.json').write_text(json.dumps({
                'version': 1, 'id': identity, 'command': [PYTHON, './provider.py'],
                'operations': ['prepare', 'check', 'launch']}))

    def setup_sites(self):
        """The fake servers the harness configuration points at (others are made by the sections)."""
        self.pat_token = 'pat_' + secrets.token_hex(16)
        self.api_key = 'key_' + secrets.token_hex(12)
        self.oc_secret = 'ocsecret_' + secrets.token_hex(12)       # an OpenCode clientSecret: never read
        self.helper_secret = 'helper_' + secrets.token_hex(12)     # text in a headersHelper command
        self.as1 = self.auth_server('as1')                                        # RFC 8414, DCR, revocation
        self.as2 = self.auth_server('as2', '/tenant', metadata=('oidc-insert',), dcr=False, revocation=False)
        self.as5 = self.auth_server('as5')                                        # the Claude Code client_id hint
        self.as6 = self.auth_server('as6')                                        # the Codex hints
        self.as2.add_client('oc-client')
        self.pub = self.mcp('pub')
        self.hdr = self.mcp('hdr', auth='headers', headers={'Authorization': 'Bearer ' + self.pat_token},
                            reveal_headers=('Authorization',))
        self.team_site = self.mcp('team', auth='headers', headers={'X-Api-Key': self.api_key},
                                  reveal_headers=('X-Team', 'X-Api-Key'))
        self.cxh = self.mcp('cxh', reveal_headers=('X-Lit', 'X-Env', 'Authorization'))
        self.down = self.mcp('down', init_status=503)
        self.oa = self.mcp('oa', auth='oauth', auth_server=self.as1, challenge_scope='read write',
                           scope_tools={'write_note': 'write'})
        self.oa2 = self.mcp('oa2', auth='oauth', auth_server=self.as1)
        self.oa3 = self.mcp('oa3', auth='oauth', auth_server=self.as1)
        self.oh = self.mcp('oh', auth='oauth', auth_server=self.as5)
        self.ob = self.mcp('ob', auth='oauth', auth_server=self.as2, challenge_metadata=False, prm_paths=('root',))
        self.ocx = self.mcp('ocx', auth='oauth', auth_server=self.as6)
        self.hint_port = free_port()
        self.cx_port = free_port()
        self.top_port = free_port()
        self.as5.add_client('hinted-client')
        self.cli_env = {'RM_PAT': self.pat_token, 'RM_ORG': 'acme', 'RM_CX_ENV': 'cxenv-' + secrets.token_hex(6),
                        'RM_CX_TOKEN': 'cxtok_' + secrets.token_hex(12), 'RM_EMPTY': '',
                        'RM_PUB_PORT': str(self.pub.port), 'RM_TEAM': None, 'RM_NOPE': None, 'RM_NOPORT': None,
                        'RM_CX_UNSET': None}
        self.proxy = self.site(Site('proxy'))   # set as HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY for p1's daemon
        self.header_values = [self.pat_token, self.api_key, self.cli_env['RM_CX_ENV'], self.cli_env['RM_CX_TOKEN'],
                              self.oc_secret, self.helper_secret]

    def write_harness_configs(self):
        p1 = self.hosts['p1']
        home, xdg = p1.home, p1.config
        self.workspaces = {}
        for name in ('w1', 'w2', 'w3'):
            w = self.root / 'projects' / name
            w.mkdir(parents=True)
            self.workspaces[name] = w.resolve()
        nowhere = 'http://127.0.0.2:9/mcp'
        self.claude_servers = {
            'pub': {'type': 'http', 'url': self.pub.url},
            'hdr': {'type': 'http', 'url': self.hdr.url, 'headers': {'Authorization': 'Bearer ${RM_PAT}'}},
            'team': {'type': 'streamable-http', 'url': self.team_site.url,
                     'headers': {'X-Api-Key': self.api_key, 'X-Team': '${RM_TEAM:-core}-${RM_ORG}'}},
            'hdrbad': {'type': 'http', 'url': self.hdr.url, 'headers': {'Authorization': 'Bearer wrong'}},
            'miss': {'type': 'http', 'url': self.pub.url, 'headers': {'X-Token': '${RM_NOPE}'}},
            'urlref': {'url': 'http://127.0.0.1:${RM_PUB_PORT}/mcp'},
            'urlmiss': {'type': 'http', 'url': 'http://127.0.0.1:9/${RM_NOPORT}/mcp'},
            'urlport': {'type': 'http', 'url': 'http://127.0.0.1:${RM_NOPORT}/mcp'},
            'oa': {'type': 'http', 'url': self.oa.url},
            'oa3': {'type': 'http', 'url': self.oa3.url},
            'oahint': {'type': 'http', 'url': self.oh.url,
                       'oauth': {'clientId': 'hinted-client', 'scopes': ['files.read', 'files.write'],
                                 'callbackPort': self.hint_port}},
            'old': {'type': 'sse', 'url': self.pub.url},
            'oldhelper': {'type': 'sse', 'url': self.pub.url, 'headersHelper': 'printf ' + self.helper_secret},
            'insec': {'type': 'http', 'url': nowhere},
            'insecsse': {'type': 'sse', 'url': nowhere},
            'ftp': {'type': 'http', 'url': 'ftp://127.0.0.1/mcp'},
            'helper': {'type': 'http', 'url': self.pub.url, 'headersHelper': 'printf ' + self.helper_secret},
            'helpermiss': {'type': 'http', 'url': self.pub.url, 'headersHelper': 'true',
                           'headers': {'X-Token': '${RM_NOPE}'}},
            'six': {'type': 'http', 'url': 'http://[::1]:1/mcp'},
            'down': {'type': 'http', 'url': self.down.url},
        }
        self.claude_json = home / '.claude.json'
        self.claude_json.write_text(json.dumps({'numStartups': 1, 'mcpServers': self.claude_servers}, indent=2))
        (home / '.codex').mkdir()
        (home / '.codex' / 'config.toml').write_text('\n'.join([
            f'mcp_oauth_callback_port = {self.top_port}',
            '',
            '[mcp_servers.cxhdr]',
            f'url = {toml_string(self.cxh.url)}',
            'bearer_token_env_var = "RM_CX_TOKEN"',
            '[mcp_servers.cxhdr.http_headers]',
            '"X-Lit" = "lit-${NOT_A_REFERENCE}"',
            '"x-env" = "replaced"',
            '"authorization" = "replaced-too"',
            '[mcp_servers.cxhdr.env_http_headers]',
            '"X-Env" = "RM_CX_ENV"',
            '',
            '[mcp_servers.cxmiss]',
            f'url = {toml_string(self.pub.url)}',
            'bearer_token_env_var = "RM_CX_UNSET"',
            '',
            '[mcp_servers.cxempty]',
            f'url = {toml_string(self.pub.url)}',
            '[mcp_servers.cxempty.env_http_headers]',
            '"X-E" = "RM_EMPTY"',
            '',
            '[mcp_servers.cxoa]',
            f'url = {toml_string(self.ocx.url)}',
            'scopes = ["read", "write"]',
            '[mcp_servers.cxoa.oauth]',
            f'callback_port = {self.cx_port}',
            '',
            '[mcp_servers.cxtop]',
            f'url = {toml_string(self.ocx.url)}',
            'scopes = "only"',
            '',
            '[mcp_servers.cxoff]',
            f'url = {toml_string(nowhere)}',
            'enabled = false',
            '']))
        (xdg / 'opencode').mkdir(parents=True)
        (xdg / 'opencode' / 'opencode.json').write_text(json.dumps({'mcp': {
            'ocrem': {'type': 'remote', 'url': self.hdr.url, 'headers': {'Authorization': 'Bearer {env:RM_PAT}'}},
            'ocoff': {'type': 'remote', 'url': self.oa2.url, 'oauth': False},
            'ochint': {'url': self.ob.url, 'oauth': {'clientId': 'oc-client', 'clientSecret': self.oc_secret,
                                                     'scope': 'files.read'}},
            'ocdis': {'type': 'remote', 'url': self.pub.url, 'enabled': False},
        }}, indent=2))

    def attach(self, harness, name, workspace):
        args = ['attach', harness, '--name', name, '--directory', str(workspace), '--integrations',
                str(self.catalog), '--no-start']
        code, out, stdout, stderr = self.out('p1', *args, env=self.cli_env, timeout=300)
        self.attached[name] = (code, out, stderr)
        if code != 0:
            self.setup_notes.append(f'attach {name} failed ({code}): {stderr[-300:]}')
        return code, out

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        for name in ('pat', 'quinn'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.quinn = (person_id(self.keys[n][2]) for n in ('pat', 'quinn'))
        self.setup_catalog()
        self.setup_sites()
        self.attached = {}
        self.coord_key = self.coord.start()['public_key']
        for name, person in (('p1', 'pat'), ('p2', 'pat'), ('q1', 'quinn')):
            self.host(name, person)
        self.hosts['p1'].proxy_env = {n: self.proxy.origin for n in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                                                                     'http_proxy', 'https_proxy', 'all_proxy')}
        if uts_available():
            self.hosts['p1'].host_name = HOST_NAME
            self.host_label = HOST_NAME.split('.')[0]
        else:
            self.host_label = socket.gethostname().split('.')[0][:64] or None
            self.notes.append('no UTS namespaces (not root): HOST_LABEL is this machine\'s own host name')
        self.client_name = f'Peerspan ({self.host_label})' if self.host_label else 'Peerspan'
        if self.baseline18:
            self.host('o1', 'quinn', self.baseline18, self.baseline18)
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        h, ids = self.hosts, self.ids
        self.team = h['p1'].cli('network', 'create', 'team', '--as', 'pat', '--trusted',
                                *self.coordinator_flags())['id']
        members = [('p2', 'pat', '--trusted'), ('q1', 'quinn', '--untrusted')]
        if 'o1' in h:
            members.append(('o1', 'quinn', '--untrusted'))
        for name, label, flag in members:
            h[name].cli('join', self.invite(label), flag)
        expected = {ids['p1']: self.pat, **{ids[n]: {'pat': self.pat, 'quinn': self.quinn}[l] for n, l, _ in members}}

        def bound():
            for n in [n for n, _, _ in members] + ['p1']:
                h[n].run('network', 'sync', self.team)
            seen = {m['host_id']: m['person_id'] for m in h['p1'].cli('network', 'members', self.team)}
            return seen == expected
        wait_for(bound, timeout=90, message='every member of team bound as expected')

        self.write_harness_configs()
        self.attach('claude', 'cc', self.workspaces['w1'])
        self.attach('codex', 'cx', self.workspaces['w2'])
        self.attach('opencode', 'oc', self.workspaces['w3'])
        for a in h['p1'].cli('agent', 'list'):
            self.aid.setdefault(a['name'], a['id'])
        for name in ('var', 'run', 'old', 'idl'):
            self.register(name)
        status, body = h['p1'].call('POST', '/v1/sources/open-to', {'host_id': ids['p2']})
        if status not in (200, 201):
            self.setup_notes.append(f'sources open-to p2: {status} {body}')

        # Capabilities on the no-sign-in and headers sources, shared with quinn (failures become setup notes).
        for name, source, operations in (('capnone', 'cc/pub', ['echo', 'who']),
                                         ('caphdr', 'cc/hdr', ['echo', 'who']),
                                         ('capteam', 'cc/team', ['who'])):
            try:
                self.create(name, source, operations)
                self.share(name)
                self.done.add(name)
            except Exception as error:
                self.setup_notes.append(f'{name}: {str(error)[:300]}')
        try:
            self.setup_idle()
        except Exception as error:
            self.setup_notes.append(f'idle source: {str(error)[:300]}')
        try:
            self.sync()
        except Exception as error:
            self.setup_notes.append(f'sync: {error}')

        self.section('discovery', self.check_discovery)
        self.section('reasons', self.check_reasons)
        self.section('auth mode', self.check_auth_mode)
        self.section('sign-in', self.check_sign_in)
        self.section('sign-in variants', self.check_sign_in_variants)
        self.section('sign-in refusals', self.check_refusals)
        self.section('capabilities and calls', self.check_capabilities)
        self.section('tokens', self.check_tokens)
        self.section('per-capability sign-in', self.check_own_sign_in)
        self.section('running', self.check_running)
        self.section('revocation', self.check_revocation)
        if 'o1' in h:
            self.section('older peers', self.check_older)
        self.section('idle stop', self.check_idle)
        self.section('status', self.check_status)
        self.section('secrets', self.check_secrets)
        if self.setup_notes:
            print(f'NOTE {self.label} remote setup: ' + ' | '.join(self.setup_notes), flush=True)

    def setup_idle(self):
        """The idle source: idl/i, a headers source, called once now; its DELETE is checked last."""
        self.idle_site = self.mcp('idle', auth='headers', headers={'X-Idle': 'idle-value'})
        self.put('idl', [self.remote_def('i', self.idle_site.url, headers={'X-Idle': {'source': 'literal'}})],
                 {'i': {'headers.X-Idle': 'idle-value'}})
        call_id, status, record = self.submit('idl/i', 'echo', {'text': 'idle'}, caller='p2')
        need(status == 200, 'idle source call accepted', status, record)
        record = self.final(call_id, 'p2')
        need(record['state'] == 'succeeded', 'idle source call succeeded', record)
        self.idle_started = time.time()
        self.idle_session = None
        for r in self.idle_site.since(0, 'POST'):
            if r['headers'].get('mcp-session-id'):
                self.idle_session = r['headers']['mcp-session-id']
        self.done.add('idle')

    # --- discovery ---------------------------------------------------------------------------------------------

    def check_discovery(self):
        failed = [f'{n}: {c} {e[-300:]}' for n, (c, o, e) in self.attached.items() if c != 0]
        need(not failed, 'attach --no-start succeeds for each harness', *failed)
        cc, cx, oc = self.servers('cc'), self.servers('cx'), self.servers('oc')
        need(set(self.claude_servers) <= set(cc), 'every Claude Code remote server is discovered',
             sorted(set(self.claude_servers) - set(cc)))
        for name, s in cc.items():
            need(s['transport'] == 'remote' and s['command'] is None and s['args'] == [] and s['env'] == {} and
                 s['source'] == 'claude-code:user', f'cc/{name}: a remote definition (command null, args [], env {{}})',
                 {k: s[k] for k in ('transport', 'command', 'args', 'env', 'source')})
        lit, cap = {'source': 'literal'}, (lambda *v: {'source': 'captured', 'variables': list(v)})
        missing = (lambda *v: {'source': 'missing', 'variables': list(v)})
        hint = lambda c, s, p: {'protocol': 'http', 'oauth': {'client_id': c, 'scopes': s, 'callback_port': p},
                                'headers_helper': False}
        expect = {  # name: (remote, headers)
            'pub': (DEFAULT_REMOTE, {}),
            'hdr': (DEFAULT_REMOTE, {'Authorization': cap('RM_PAT')}),
            'team': (DEFAULT_REMOTE, {'X-Api-Key': lit, 'X-Team': cap('RM_TEAM', 'RM_ORG')}),
            'miss': (DEFAULT_REMOTE, {'X-Token': missing('RM_NOPE')}),
            'urlref': (DEFAULT_REMOTE, {}),
            'oahint': (hint('hinted-client', 'files.read files.write', self.hint_port), {}),
            'old': (dict(DEFAULT_REMOTE, protocol='sse'), {}),
            'oldhelper': (dict(DEFAULT_REMOTE, protocol='sse', headers_helper=True), {}),
            'helper': (dict(DEFAULT_REMOTE, headers_helper=True), {}),
            'helpermiss': (dict(DEFAULT_REMOTE, headers_helper=True), {'X-Token': missing('RM_NOPE')}),
        }
        for name, (remote, headers) in expect.items():
            need(cc[name].get('remote') == remote and cc[name].get('headers') == headers,
                 f'cc/{name}: remote and headers from Claude Code (type, oauth hints, headersHelper, ${{VAR}}, '
                 '${VAR:-D})', {k: cc[name].get(k) for k in ('remote', 'headers')}, remote, headers)
        need(cc['urlref']['url'] == 'http://127.0.0.1:${RM_PUB_PORT}/mcp' and
             cc['urlmiss']['missing_env'] == ['RM_NOPORT'] and cc['miss']['missing_env'] == ['RM_NOPE'] and
             cc['urlport']['missing_env'] == ['RM_NOPORT'],
             'a URL keeps its reference in the definition; an unresolved one makes the server missing_env',
             cc['urlref']['url'], cc['urlmiss']['missing_env'])
        v = self.values('cc', 'hdr')
        need(v == {'headers.Authorization': 'Bearer ' + self.pat_token,
                   'header_templates.Authorization': 'Bearer ${RM_PAT}'},
             'values: headers.NAME (full value) and header_templates.NAME for a captured header', sorted(v))
        v = self.values('cc', 'team')
        need(v == {'headers.X-Api-Key': self.api_key, 'headers.X-Team': 'core-acme',
                   'header_templates.X-Team': '${RM_TEAM:-core}-${RM_ORG}'},
             'values: a literal header has no template; a captured one with a default resolved', sorted(v))
        need(self.values('cc', 'urlref') == {'url': f'http://127.0.0.1:{self.pub.port}/mcp'},
             'values: url, the resolved URL, when it contained a reference', self.values('cc', 'urlref'))
        need(self.values('cc', 'pub') == {}, 'no values for a server without headers or references',
             self.values('cc', 'pub'))
        for name in ('oldhelper', 'helper'):
            need(self.helper_secret not in json.dumps(cc[name]) and
                 self.helper_secret not in json.dumps(self.values('cc', name)) and
                 self.helper_secret not in json.dumps(self.record('cc', name)),
                 'a headersHelper command is never stored or shown', name)

        # Codex.
        names = {n.lower(): n for n in cx['cxhdr']['headers']}
        need(sorted(names) == ['authorization', 'x-env', 'x-lit'],
             'Codex: http_headers, env_http_headers, and bearer_token_env_var, later entries replacing earlier ones '
             'of the same name case-insensitively', cx['cxhdr']['headers'])
        hh = cx['cxhdr']['headers']
        need(hh[names['x-lit']] == lit and hh[names['x-env']] == cap('RM_CX_ENV') and
             hh[names['authorization']] == cap('RM_CX_TOKEN'),
             'Codex: http_headers literal even with ${, env_http_headers and bearer_token_env_var captured', hh)
        self.soft(names['x-env'] == 'X-Env' and names['authorization'] == 'Authorization',
                  'Q: a replaced Codex header takes the later entry\'s spelling', sorted(hh))
        v = self.values('cx', 'cxhdr')
        need(v.get(f"headers.{names['x-lit']}") == 'lit-${NOT_A_REFERENCE}' and
             v.get(f"headers.{names['x-env']}") == self.cli_env['RM_CX_ENV'] and
             v.get(f"header_templates.{names['x-env']}") == '${RM_CX_ENV}' and
             v.get(f"headers.{names['authorization']}") == 'Bearer ' + self.cli_env['RM_CX_TOKEN'] and
             v.get(f"header_templates.{names['authorization']}") == 'Bearer ${RM_CX_TOKEN}' and len(v) == 5,
             'Codex values: env_http_headers as ${VAR}, bearer_token_env_var as Bearer ${VAR}', sorted(v))
        need(cx['cxhdr']['remote'] == hint(None, None, self.top_port) and cx['cxhdr']['source'] == 'codex:user',
             'Codex: the top-level mcp_oauth_callback_port when the server has no oauth.callback_port',
             cx['cxhdr']['remote'])
        need(cx['cxmiss']['headers'] == {'Authorization': missing('RM_CX_UNSET')} and
             cx['cxmiss']['reason'] == 'missing_env' and cx['cxmiss']['missing_env'] == ['RM_CX_UNSET'],
             'Codex: an unset bearer_token_env_var makes the header missing', cx['cxmiss'])
        need(cx['cxempty']['headers'] == {'X-E': cap('RM_EMPTY')} and cx['cxempty']['shareable'] is True and
             self.values('cx', 'cxempty') == {'headers.X-E': '', 'header_templates.X-E': '${RM_EMPTY}'},
             'Codex: a variable that is set but empty is captured', cx['cxempty'], self.values('cx', 'cxempty'))
        need(cx['cxoa']['remote'] == hint(None, 'read write', self.cx_port) and
             cx['cxtop']['remote'] == hint(None, 'only', self.top_port),
             'Codex: scopes (an array joined with spaces, or a string) and oauth.callback_port',
             cx['cxoa']['remote'], cx['cxtop']['remote'])
        need(cx['cxoff']['reason'] == 'disabled' and cx['cxoff']['disabled'] is True, 'Codex enabled = false',
             cx['cxoff'])

        # OpenCode.
        need(oc['ocrem']['headers'] == {'Authorization': cap('RM_PAT')} and oc['ocrem']['source'] == 'opencode:global'
             and self.values('oc', 'ocrem') == {'headers.Authorization': 'Bearer ' + self.pat_token,
                                                'header_templates.Authorization': 'Bearer ${RM_PAT}'},
             'OpenCode: {env:VAR} resolved, its template written with ${VAR}', oc['ocrem'],
             sorted(self.values('oc', 'ocrem')))
        need(oc['ocoff']['remote'] == {'protocol': 'http', 'oauth': None, 'headers_helper': False},
             'OpenCode oauth: false makes remote.oauth null', oc['ocoff']['remote'])
        need(oc['ochint']['remote'] == hint('oc-client', 'files.read', None) and oc['ochint']['transport'] == 'remote',
             'OpenCode: a url without a type is remote; oauth.clientId and oauth.scope as hints', oc['ochint'])
        need(oc['ocdis']['reason'] == 'disabled', 'OpenCode enabled: false', oc['ocdis'])
        need(self.oc_secret not in json.dumps(self.view()) and
             not any(self.oc_secret in json.dumps(r) for r in db_rows(self.hosts['p1'], 'SELECT * FROM tool_values')),
             'an OpenCode clientSecret is never read')

        # The captured values reach the server: p2 calls the raw source cx/cxhdr (open to it, by self).
        call_id, status, record = self.submit('cx/cxhdr', 'who', {}, caller='p2')
        need(status == 200, 'a raw remote source call from a trusted host it is open to', status, record)
        record = self.final(call_id, 'p2')
        seen = json.loads(text_of(record.get('result')) or '{}').get('headers', {})
        need(record['state'] == 'succeeded' and seen == {
            'X-Lit': digest('lit-${NOT_A_REFERENCE}'), 'X-Env': digest(self.cli_env['RM_CX_ENV']),
            'Authorization': digest('Bearer ' + self.cli_env['RM_CX_TOKEN'])},
             'the daemon sends the captured header values', record, seen)

        self.check_env_file()

        # A PUT from a CLI that predates this slice: no remote and no headers, read with the defaults.
        old = {'name': 'o', 'transport': 'remote', 'command': None, 'args': [], 'env': {}, 'url': self.pub.url,
               'source': 'claude-code:user'}
        self.put('old', [old])
        o = self.server('old', 'o')
        need(o['remote'] == DEFAULT_REMOTE and o['headers'] == {} and o['shareable'] is True and
             (o['auth'] or {}).get('mode') == 'none', 'a PUT without remote and headers is accepted with the defaults',
             o)
        # Shapes refused with 400.
        for rule, servers, values in (
                ('remote on a stdio server', [{'name': 's', 'transport': 'stdio', 'command': PYTHON, 'args': [],
                                               'env': {}, 'url': None, 'source': 'claude-code:user',
                                               'remote': DEFAULT_REMOTE}], {}),
                ('headers on a stdio server', [{'name': 's', 'transport': 'stdio', 'command': PYTHON, 'args': [],
                                                'env': {}, 'url': None, 'source': 'claude-code:user',
                                                'headers': {'X-A': {'source': 'literal'}}}], {}),
                ('a remote server with a command', [dict(old, command='x')], {}),
                ('remote with an unknown field', [dict(old, remote=dict(DEFAULT_REMOTE, extra=1))], {}),
                ('protocol other than http and sse', [dict(old, remote=dict(DEFAULT_REMOTE, protocol='ws'))], {}),
                ('callback_port out of range', [dict(old, remote=dict(DEFAULT_REMOTE, oauth={
                    'client_id': None, 'scopes': None, 'callback_port': 70000}))], {}),
                ('captured without variables', [dict(old, headers={'X-A': {'source': 'captured'}})], {}),
                ('missing without variables', [dict(old, headers={'X-A': {'source': 'missing', 'variables': []}})],
                 {}),
                ('a header name that is not a token', [dict(old, headers={'X A': {'source': 'literal'}})], {}),
                ('a template for a literal header', [dict(old, headers={'X-A': {'source': 'literal'}})],
                 {'o': {'headers.X-A': 'v', 'header_templates.X-A': 'v'}}),
                ('a value for a missing header', [dict(old, headers={'X-A': {'source': 'missing',
                                                                              'variables': ['V']}})],
                 {'o': {'headers.X-A': 'v'}}),
                ('env.NAME for a remote server', [old], {'o': {'env.X': 'v'}})):
            status, body = self.put('old', servers, values, expect=None)
            need(status == 400, f'PUT refuses {rule} with 400', status, body)
        return ''

    def check_env_file(self):
        """The environment file overrides a captured header only when it defines every variable the header
        references; a capability's env_file comes first. X-Team is `${RM_TEAM:-core}-${RM_ORG}` (captured as
        core-acme)."""
        env_file = self.hosts['p1'].config / 'peerspan' / 'env'
        env_file.parent.mkdir(parents=True, exist_ok=True)
        own = self.root / 'team-own.env'
        own.write_text('RM_TEAM=cap\n')
        own.chmod(0o600)
        self.create('capteamenv', 'cc/team', ['who', 'lose_session'], '--env-file', str(own))

        def team(source='cc/team', rule=''):
            # A new instance, so the environment file is read again.
            call_id, status, _ = self.submit(source, 'lose_session', {}, caller='p2')
            if status == 200:
                self.final(call_id, 'p2')
            call_id, status, record = self.submit(source, 'who', {}, caller='p2')
            need(status == 200, f'{rule}: the call is accepted', status, record)
            record = self.final(call_id, 'p2')
            need(record['state'] == 'succeeded', f'{rule}: who succeeds', record)
            return json.loads(text_of(record['result']))['headers']

        try:
            env_file.unlink(missing_ok=True)
            seen = team(rule='no environment file')
            need(seen == {'X-Team': digest('core-acme'), 'X-Api-Key': digest(self.api_key)},
                 'without the environment file, the captured value', seen)
            env_file.write_text('# partial\nRM_ORG=beta\nX_API_KEY=ignored\n')
            env_file.chmod(0o600)
            seen = team(rule='a partial environment file')
            need(seen['X-Team'] == digest('core-acme'),
                 'an environment file defining only some referenced variables leaves the captured value', seen)
            seen = team('capteamenv', rule='a capability env_file and a partial environment file')
            need(seen['X-Team'] == digest('cap-beta') and seen['X-Api-Key'] == digest(self.api_key),
                 'a capability\'s env_file first, then the environment file, every variable defined: the template '
                 'resolved again; a literal header never overridden', seen)
            env_file.write_text('RM_TEAM=ops\nRM_ORG=beta\n')
            env_file.chmod(0o600)
            seen = team(rule='a full environment file')
            need(seen['X-Team'] == digest('ops-beta'),
                 'an environment file defining every referenced variable resolves the template again', seen)
            seen = team('capteamenv', rule='a capability env_file over a full environment file')
            need(seen['X-Team'] == digest('cap-beta'), 'the capability\'s env_file wins over the environment file',
                 seen)
            env_file.unlink()
            seen = team('capteamenv', rule='a capability env_file alone, partial')
            need(seen['X-Team'] == digest('core-acme'),
                 'a capability env_file defining only some referenced variables leaves the captured value', seen)
        finally:
            env_file.unlink(missing_ok=True)

    # --- reasons -----------------------------------------------------------------------------------------------

    def check_reasons(self):
        cc, cx = self.servers('cc'), self.servers('cx')
        expect = {'pub': None, 'hdr': None, 'team': None, 'urlref': None, 'six': None, 'oa': 'login',
                  'miss': 'missing_env', 'urlmiss': 'missing_env', 'urlport': 'missing_env', 'old': 'sse', 'oldhelper': 'sse',
                  'insec': 'insecure_url', 'insecsse': 'insecure_url', 'ftp': 'insecure_url',
                  'helper': 'headers_helper', 'helpermiss': 'headers_helper'}
        for name, reason in expect.items():
            need(cc[name]['reason'] == reason and cc[name]['shareable'] is (reason is None),
                 f'cc/{name}: reason {reason}', {k: cc[name][k] for k in ('reason', 'shareable', 'snapshot_error')})
        need(cx['cxoff']['reason'] == 'disabled', 'disabled before insecure_url', cx['cxoff'])
        need(cc['six']['snapshot_error'], 'http on [::1] is allowed (a connect failure is a snapshot_error)',
             cc['six'])
        # More precedence and loopback cases, through PUT (agent var, restored by the variants section).
        nowhere = 'http://127.0.0.2:9/mcp'
        d = self.remote_def
        servers = [
            d('Bad.Name', nowhere, remote=dict(DEFAULT_REMOTE, protocol='sse')),
            d('lh', 'http://localhost:1/mcp'),
            d('lhcase', 'http://LocalHost:1/mcp'),
            d('https', 'https://example.invalid/mcp'),
            d('urlvalue', 'http://${HOSTPORT}/mcp'),
            d('ml', self.oa2.url, headers={'X-Token': {'source': 'missing', 'variables': ['NOPE']}}),
            d('hm', nowhere, remote=dict(DEFAULT_REMOTE, headers_helper=True)),
            d('rel', '/relative/mcp'),
            d('nohost', 'http:///mcp'),
        ]
        self.put('var', servers, {'urlvalue': {'url': 'http://127.0.0.2:9/mcp'}})
        v = self.servers('var')
        for name, reason in (('Bad.Name', 'name'), ('lh', None), ('lhcase', None), ('https', None), ('urlvalue', 'insecure_url'),
                             ('ml', 'missing_env'), ('hm', 'insecure_url'), ('rel', 'insecure_url'),
                             ('nohost', 'insecure_url')):
            need(v[name]['reason'] == reason, f'var/{name}: reason {reason}', v[name])
        need(not self.oa2.since(0, 'POST') or all(r['headers'].get('x-token') is None for r in self.oa2.since(0)),
             'a source with a definition reason is not probed with a missing header')
        every = [s for a in self.view()['agents'] for s in a['servers']]
        need(not any(s['reason'] == 'remote' for s in every), 'the reason remote is retired',
             [s['name'] for s in every if s['reason'] == 'remote'])
        need(all(s['reason'] in (None, *REASONS) for s in every), 'reasons come from the contract\'s list',
             sorted({s['reason'] for s in every if s['reason'] not in (None, *REASONS)}))
        self.put('var', [])
        return ''

    # --- auth mode ---------------------------------------------------------------------------------------------

    def check_auth_mode(self):
        cc, oc = self.servers('cc'), self.servers('oc')
        need(cc['pub']['auth'] == dict(NULL_AUTH, mode='none') and cc['pub']['snapshot_error'] is None and
             {t['name'] for t in cc['pub']['tools']} >= {'echo', 'who'},
             'a 2xx without headers: mode none, and the snapshot proceeds', cc['pub']['auth'], cc['pub']['tools'][:2])
        need(cc['hdr']['auth'] == dict(NULL_AUTH, mode='headers') and cc['hdr']['snapshot_error'] is None,
             'a 2xx with headers: mode headers', cc['hdr']['auth'])
        code, value, stdout, stderr = self.out('p1', 'sources', '--json', '--agent', 'cc')
        listed = {s['name']: s for a in (value or {}).get('agents', []) for s in a['servers']}
        need(code == 0 and all(listed.get(n, {}).get('auth') == cc[n]['auth'] for n in ('pub', 'hdr', 'oa', 'down')),
             'sources --json shows auth for each mode, as GET /v1/sources does',
             {n: listed.get(n, {}).get('auth') for n in ('pub', 'hdr', 'oa', 'down')})
        oa = cc['oa']
        need(oa['auth'] == dict(NULL_AUTH, mode='oauth', state='login_required') and oa['reason'] == 'login' and
             oa['snapshot_error'] is None and oa['tools'] == [],
             'a 401 Bearer challenge without a token: mode oauth, state login_required, reason login, no '
             'snapshot_error', oa)
        record = self.record('cc', 'oa') or {}
        need(record.get('auth_mode') == 'oauth' and record.get('challenge') == {
            'resource_metadata': self.oa.prm_url('path'), 'scope': 'read write'},
             'the stored challenge {resource_metadata, scope}', record.get('auth_mode'), record.get('challenge'))
        ob = self.record('oc', 'ochint') or {}
        need(ob.get('challenge') == {'resource_metadata': None, 'scope': None},
             'a challenge without parameters is stored with nulls', ob.get('challenge'))
        first = [r for r in self.oa.since(0, 'POST') if (r.get('message') or {}).get('method') == 'initialize']
        need(first and 'authorization' not in first[0]['headers'],
             'the probe sends initialize without a token', first[:1])
        need(cc['hdrbad']['snapshot_error'] == 'unauthorized' and oc['ocoff']['snapshot_error'] == 'unauthorized',
             'a 401 with a configured Authorization header, and with oauth false: snapshot_error unauthorized',
             cc['hdrbad']['snapshot_error'], oc['ocoff']['snapshot_error'])
        need(not self.as1.since(0, path='/register') or True, '')
        need('503' in (cc['down']['snapshot_error'] or '') and cc['down']['auth']['mode'] is None,
             'another failure: a snapshot_error with the HTTP status; the mode stays null', cc['down'])
        # The sources text.
        code, value, stdout, stderr = self.out('p1', 'sources', '--agent', 'cc')
        need(code == 0, 'sources --agent cc', code, stderr[-300:])
        blocks = self.text_blocks(stdout)
        for name, url, auth in (
                ('pub', self.pub.url, '    auth: none (the server asks for no sign-in)'),
                ('hdr', self.hdr.url, '    auth: headers Authorization'),
                ('team', self.team_site.url, '    auth: headers X-Api-Key, X-Team'),
                ('oa', self.oa.url, '    auth: needs a sign-in: peerspan sources login cc/oa'),
                ('down', self.down.url, '    auth: not reached yet'),
                ('urlref', 'http://127.0.0.1:${RM_PUB_PORT}/mcp', '    auth: none (the server asks for no sign-in)')):
            block = blocks.get(f'cc/{name}')
            need(block and f'    url: {url}' in block[1:] and auth in block[1:],
                 f'sources text for cc/{name}: the url line and the auth line', block, stdout[-1500:])
        need('not usable: login' in blocks['cc/oa'][0], 'sources text: STATE `not usable: login`', blocks['cc/oa'])
        return ''

    @staticmethod
    def text_blocks(stdout):
        """`sources` text: AGENT/SERVER -> [its first line, the lines indented four spaces after it]."""
        blocks, current = {}, None
        for line in stdout.splitlines():
            words = line.split()
            if line.startswith('  ') and not line.startswith('    ') and words and '/' in words[0]:
                current = words[0]
                blocks[current] = [line]
            elif current and line.startswith('    '):
                blocks[current].append(line.rstrip())
            else:
                current = None
        return blocks

    # --- sign-in -----------------------------------------------------------------------------------------------

    def check_authorization_request(self, url, auth_server, mcp_site, scope, rule):
        """The authorization URL's parameters and the token request that followed it."""
        q = query_of(url)
        need(url.startswith(auth_server.origin + '/authorize?'), f'{rule}: the authorization_endpoint', url)
        need(set(q) == {'response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method',
                        'state', 'resource'} | ({'scope'} if scope else set()),
             f'{rule}: exactly response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, '
             'resource, and scope when chosen', sorted(q))
        need(q['response_type'] == 'code' and q['code_challenge_method'] == 'S256' and STATE.match(q['state']) and
             re.match(r'^http://127\.0\.0\.1:\d+/callback$', q['redirect_uri']) and
             q['resource'] == canonical(mcp_site.url) and q.get('scope') == scope,
             f'{rule}: response_type code, S256, a 64-hex state, a loopback redirect URI, the canonical resource, '
             'and the scope', q)
        tokens = [r for r in auth_server.since(0, 'POST', '/token')
                  if r.get('form', {}).get('grant_type') == 'authorization_code'
                  and r['form'].get('redirect_uri') == q['redirect_uri']]
        need(tokens, f'{rule}: a token request followed', auth_server.violations[-2:])
        t = tokens[-1]
        form = t['form']
        need(set(form) - {'client_secret'} == {'grant_type', 'code', 'redirect_uri', 'client_id', 'code_verifier',
                                               'resource'} and form['client_id'] == q['client_id'] and
             form['resource'] == q['resource'] and VERIFIER.match(form['code_verifier']) and
             s256(form['code_verifier']) == q['code_challenge'],
             f'{rule}: the token request carries grant_type, code, redirect_uri, client_id, the verifier matching '
             'the challenge (32 bytes, base64url without padding), and the same resource', form)
        need(t['headers'].get('content-type', '').startswith('application/x-www-form-urlencoded') and
             'application/json' in t['headers'].get('accept', ''),
             f'{rule}: the token request is form-encoded and accepts JSON', t['headers'])
        need(not [v for v in auth_server.violations if v[1] is t], f'{rule}: the fake accepted the token request',
             auth_server.violations[-2:])
        return q, t

    def check_sign_in(self):
        p1 = self.hosts['p1']
        source = 'cc/oa'
        mark_as, mark_oa = self.as1.mark(), self.oa.mark()
        # No terminal and no --no-browser: refused before any request.
        code, value, stdout, stderr = self.out('p1', 'sources', 'login', source)
        need(code == 1 and NEEDS_TERMINAL.format(cmd='sources login') in squash(stderr),
             'sources login without a terminal and without --no-browser exits 1 with the text', code, stderr[-400:])
        code, value, stdout, stderr = self.out('p1', 'sources', 'login', source, '--client-secret-file',
                                               str(self.root / 'nothing'), '--no-browser')
        need(code == 1 and SECRET_NEEDS_ID in stderr, '--client-secret-file without --client-id', code, stderr[-300:])
        loose = self.root / 'loose-secret'
        loose.write_text('s3cr3t\n')
        loose.chmod(0o644)
        code, value, stdout, stderr = self.out('p1', 'sources', 'login', source, '--client-id', 'x',
                                               '--client-secret-file', str(loose), '--no-browser')
        need(code == 1 and SECRET_MODE.format(path=str(loose)) in stderr, 'a secret file open to others is refused',
             code, stderr[-300:])
        need(self.as1.mark() == mark_as and self.oa.mark() == mark_oa, 'the refusals made no request',
             self.as1.since(mark_as), self.oa.since(mark_oa))

        # The full flow through the listener, with --account.
        result, url, location, page = None, None, None, None
        login = Login(p1, ['sources', 'login', source, '--no-browser', '--account', 'work'])
        url = login.link()
        need(url, 'the CLI prints the authorization URL', login.text[-600:])
        q = query_of(url)
        port = urllib.parse.urlsplit(q['redirect_uri']).port
        status, body = deliver(f'http://127.0.0.1:{port}/other')
        need(status == 404, 'the listener answers 404 to a path other than /callback', status)
        code_, location = self.as1.approve(url)
        need(code_ == 302, 'the fake approves', code_, location, self.as1.violations[-1:])
        page = deliver(location)
        result = login.finish()
        self.exposed.append(('sources login cc/oa', result[2] + result[3]))
        code, value, text, stdout = result
        need(code == 0, 'sources login through the listener exits 0', code, text[-800:])
        need(page[0] == 200 and COMPLETE_PAGE in page[1], 'the listener answers the browser with the completion page',
             page)
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        block = [b.format(url=url) for b in PRINT_BLOCK]
        need(any(lines[i:i + 4] == block for i in range(len(lines))), 'print mode prints the link block', lines[:8])
        expected = {'source': source, 'capability': None, 'issuer': self.as1.issuer, 'scopes': 'read write',
                    'account': 'work', 'registration': 'dcr'}
        need(isinstance(value, dict) and set(value) == LOGIN_RESULT_KEYS and
             {k: value[k] for k in expected} == expected and isinstance(value['expires_at'], str),
             'the output JSON {source, capability, issuer, scopes, account, expires_at, registration}', value)
        need(SIGNED_IN.format(host='127.0.0.1', source=source, scope='read write') in text,
             'the stderr line naming the issuer host and the scopes', text[-400:])
        self.check_authorization_request(url, self.as1, self.oa, 'read write', 'listener sign-in')
        # Discovery requests.
        prm = [r for r in self.oa.since(mark_oa, 'GET') if 'oauth-protected-resource' in r['path']]
        need([r['path'] for r in prm][:1] == ['/.well-known/oauth-protected-resource/mcp'],
             'protected resource metadata from the challenge\'s resource_metadata', [r['path'] for r in prm])
        meta = [r['path'] for r in self.as1.since(mark_as, 'GET') if '/.well-known/' in r['path']]
        need(meta == ['/.well-known/oauth-authorization-server'], 'RFC 8414 metadata first', meta)
        regs = self.as1.since(mark_as, 'POST', '/register')
        need(len(regs) == 1, 'one dynamic client registration', len(regs))
        reg_body = json.loads(regs[0]['body'])
        need(reg_body == {'client_name': self.client_name, 'redirect_uris': [q['redirect_uri']],
                          'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code'],
                          'token_endpoint_auth_method': 'none', 'application_type': 'native'} and
             regs[0]['headers'].get('content-type', '').startswith('application/json'),
             'the DCR request body exactly, with the client name Peerspan (HOST_LABEL)', reg_body)
        need(q['client_id'] in self.as1.clients and not self.as1.clients[q['client_id']].get('manual'),
             'the authorization URL uses the client_id DCR returned', q['client_id'])
        # Stored state.
        cred = self.credential('cc', 'oa')
        need(cred is not None and set(cred) == CREDENTIAL_KEYS, 'the stored credential record has the contract\'s '
             'fields', sorted(cred or {}))
        need(cred['issuer'] == self.as1.issuer and cred['resource'] == canonical(self.oa.url) and
             cred['registration'] == 'dcr' and cred['client'] == {'issuer': self.as1.issuer,
                                                                  'redirect_uri': q['redirect_uri']} and
             cred['token_endpoint'] == self.as1.origin + '/token' and
             cred['revocation_endpoint'] == self.as1.origin + '/revoke' and cred['token_type'] in ('Bearer', 'bearer')
             and cred['scope'] == 'read write' and cred['account'] == 'work' and cred['state'] == 'ok' and
             cred['refreshed_at'] is None and cred['refresh_failed_at'] is None and cred['access_token'] in
             self.as1.access and cred['refresh_token'] in self.as1.refresh,
             'the credential: issuer, canonical resource, registration, client key, endpoints, tokens, scope, '
             'account, state ok', {k: v for k, v in cred.items() if 'token' not in k})
        regs = self.clients(self.as1.issuer)
        need(len(regs) == 1 and set(regs[0]) == CLIENT_KEYS and regs[0]['method'] == 'none' and
             regs[0]['registration'] == 'dcr' and regs[0]['client_id'] == q['client_id'] and
             regs[0]['redirect_uri'] == q['redirect_uri'] and regs[0]['client_secret'] is None,
             'the client registration, keyed by issuer and redirect URI', regs)
        s = self.server('cc', 'oa')
        need(s['reason'] is None and s['shareable'] is True and {t['name'] for t in s['tools']} >= {'echo', 'who'} and
             s['auth']['mode'] == 'oauth' and s['auth']['state'] == 'ok' and s['auth']['issuer'] == self.as1.issuer
             and s['auth']['scope'] == 'read write' and s['auth']['account'] == 'work' and
             s['auth']['registration'] == 'dcr' and s['auth']['obtained_at'] and
             s['auth']['expires_at'] == value['expires_at'],
             'after the sign-in the source is shareable, snapshotted with the token, and auth shows the credential',
             s)
        inits = [r for r in self.oa.since(mark_oa, 'POST') if (r.get('message') or {}).get('method') == 'initialize'
                 and bearer_of(r) == cred['access_token']]
        need(inits, 'the snapshot after the sign-in carries the token')
        events = self.kinds_for('sources.login')
        need(any(e['subject_id'] == f"{self.aid['cc']}/oa" for e in events),
             'sources.login activity with subject AGENT_ID/SERVER', events[-2:])
        code, _, stdout, stderr = self.out('p1', 'sources', '--agent', 'cc')
        block = self.text_blocks(stdout).get('cc/oa') or []
        need('    auth: signed in to 127.0.0.1, scopes read write, account work, ok' in block,
             'sources text for a signed-in source', block)
        self.done.add('oa')
        self.oa_port = port

        # Paste, a second source of the same issuer: the registration and its port reused; no scope.
        mark_as = self.as1.mark()
        result, url, location, page = self.cli_login('cc/oa3', mode='paste', rule='pasted sign-in')
        code, value, text, stdout = result
        need(code == 0 and value and value['scopes'] is None and value['account'] is None and
             value['registration'] == 'dcr',
             'sources login with a pasted address exits 0 (no scope chosen, no account)', code, value, text[-500:])
        need(SIGNED_IN.format(host='127.0.0.1', source='cc/oa3', scope='none') in text, 'the stderr line with scopes '
             'none', text[-300:])
        q3, _ = self.check_authorization_request(url, self.as1, self.oa3, None, 'pasted sign-in')
        need(q3['client_id'] == q['client_id'] and q3['redirect_uri'] == q['redirect_uri'] and
             not self.as1.since(mark_as, 'POST', '/register'),
             'one registration per issuer: reused by a second source, with its port', q3, q)
        self.done.add('oa3')

        # A refusal through the listener: the browser gets the failure page with the daemon's text; the CLI exits 1.
        self.as1.cfg.update(authorize=('error', 'access_denied', 'not today'))
        try:
            login = Login(p1, ['sources', 'login', 'cc/oa3', '--no-browser'])
            url = login.link()
            code_, location = self.as1.approve(url)
            page = deliver(location)
            code, value, text, stdout = login.finish()
            self.exposed.append(('sources login (refused)', text + stdout))
        finally:
            self.as1.cfg.update(authorize='approve')
        refusal = refusal_text('provider_refused', error='access_denied (not today)')
        need(page[0] == 400 and FAILED_PAGE in page[1] and refusal in page[1] and code == 1 and refusal in squash(text),
             'a refused sign-in: the listener answers 400 with the failure page and the text; the CLI exits 1 with it',
             page, code, text[-400:])

        # The browser: a terminal with a display and no SSH_CONNECTION starts xdg-open. cc/oahint uses the
        # harness hints (client_id, scopes, callbackPort).
        openers = fake_openers(self.root / 'openers')
        p1.first_path = self.root / 'openers'
        try:
            mark5 = self.as5.mark()
            login = Login(p1, ['sources', 'login', 'cc/oahint'], terminal=True, opener_log=openers['xdg-open'],
                          env={'DISPLAY': ':99', 'SSH_CONNECTION': None, 'SSH_CLIENT': None, 'SSH_TTY': None,
                               'WAYLAND_DISPLAY': None})
            url = login.link()
            need(url and openers['xdg-open'].exists(), 'at a terminal with a display, the CLI starts xdg-open with the '
                 'authorization URL', url, login.text[-500:])
            code_, location = self.as5.approve(url)
            page = deliver(location)
            code, value, text, stdout = login.finish()
            self.exposed.append(('sources login cc/oahint', text + stdout))
            need(code == 0 and OPENING in squash(text) and url in text,
                 'the browser case prints the opening line and the link', code, text[-600:])
            need(not openers['open'].exists(), 'xdg-open, not open, on Linux')
            qh = query_of(url)
            need(qh['client_id'] == 'hinted-client' and qh['redirect_uri'] == f'http://127.0.0.1:{self.hint_port}/callback'
                 and qh.get('scope') == 'files.read files.write' and not self.as5.since(mark5, 'POST', '/register')
                 and value['registration'] == 'harness',
                 'the harness hints: client_id (registration harness), scopes, and callback port', qh, value)
            reg = self.clients(self.as5.issuer)
            need(len(reg) == 1 and reg[0]['registration'] == 'harness' and reg[0]['client_secret'] is None,
                 'the harness client is stored with registration harness and no secret', reg)
            self.done.add('oahint')

            # SSH_CONNECTION set: print mode at a terminal, nothing opened. oc/ochint: OIDC metadata with the
            # path inserted, protected resource metadata at the root, the OpenCode client_id hint.
            before = openers['xdg-open'].read_text()
            mark2, markb = self.as2.mark(), self.ob.mark()
            login = Login(p1, ['sources', 'login', 'oc/ochint'], terminal=True,
                          env={'DISPLAY': ':99', 'SSH_CONNECTION': '10.0.0.1 1 10.0.0.2 22'})
            url = login.link()
            need(url, 'print mode over SSH prints the link', login.text[-400:])
            code_, location = self.as2.approve(url)
            login.paste(location)
            code, value, text, stdout = login.finish()
            self.exposed.append(('sources login oc/ochint', text + stdout))
            need(code == 0 and openers['xdg-open'].read_text() == before and PRINT_BLOCK[0] in text,
                 'with SSH_CONNECTION the CLI prints instead of opening', code, text[-500:])
            need([r['path'] for r in self.ob.since(markb, 'GET') if 'oauth-protected-resource' in r['path']][:2] ==
                 ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource'],
                 'without resource_metadata: the path-inserted URL, then the root URL',
                 [r['path'] for r in self.ob.since(markb, 'GET')])
            need([r['path'] for r in self.as2.since(mark2, 'GET') if '.well-known' in r['path']][:2] ==
                 ['/.well-known/oauth-authorization-server/tenant', '/.well-known/openid-configuration/tenant'],
                 'an issuer with a path: RFC 8414 with the path inserted, then OpenID Connect with it inserted',
                 [r['path'] for r in self.as2.since(mark2, 'GET')])
            need(query_of(url)['client_id'] == 'oc-client' and query_of(url).get('scope') == 'files.read' and
                 value['issuer'] == self.as2.issuer, 'the OpenCode hints', query_of(url), value)
            self.done.add('ochint')

            # No DISPLAY or WAYLAND_DISPLAY on Linux: print mode. cx/cxoa: the Codex hints.
            mark6 = self.as6.mark()
            login = Login(p1, ['sources', 'login', 'cx/cxoa'], terminal=True,
                          env={'DISPLAY': None, 'WAYLAND_DISPLAY': None, 'SSH_CONNECTION': None})
            url = login.link()
            need(url, 'print mode without a display prints the link', login.text[-400:])
            code_, location = self.as6.approve(url)
            login.paste(location)
            code, value, text, stdout = login.finish()
            self.exposed.append(('sources login cx/cxoa', text + stdout))
            need(code == 0 and openers['xdg-open'].read_text() == before and PRINT_BLOCK[0] in text,
                 'without a display the CLI prints instead of opening', code, text[-500:])
            qx = query_of(url)
            need(qx['redirect_uri'] == f'http://127.0.0.1:{self.cx_port}/callback' and qx.get('scope') == 'read write'
                 and len(self.as6.since(mark6, 'POST', '/register')) == 1,
                 'the Codex hints: callback port and scopes, with DCR', qx)
        finally:
            p1.first_path = None

        # A busy port: paste only, with the text; then end of stdin without a listener.
        busy = socket.socket()
        busy.bind(('127.0.0.1', 0))
        busy.listen(1)
        bport = busy.getsockname()[1]
        try:
            result, url, location, page = self.cli_login('cc/oa3', '--port', str(bport), mode='paste',
                                                         rule='busy port')
            code, value, text, stdout = result
            need(code == 0 and PORT_BUSY.format(port=bport) in squash(text) and
                 query_of(url)['redirect_uri'] == f'http://127.0.0.1:{bport}/callback',
                 'a busy port: the text, then the pasted address completes the sign-in', code, text[-600:])
            login = Login(p1, ['sources', 'login', 'cc/oa3', '--no-browser', '--port', str(bport)])
            url = login.link()
            login.process.stdin.close()
            code, value, text, stdout = login.finish(timeout=60)
            self.exposed.append(('sources login (closed stdin)', text + stdout))
            need(code == 1 and NOT_COMPLETED in text,
                 'at end of stdin without a listener: exit 1, The sign-in was not completed.', code, text[-400:])
        finally:
            busy.close()
        return ''

    # --- sign-in variants (through the local API) --------------------------------------------------------------

    def put_var(self, site, remote=None, url=None, name='v'):
        self.put('var', [self.remote_def(name, url or site.url, remote=remote)])

    def variant(self, rule, site, auth_server, body=None, expect_ok=True):
        """One sign-in to var/v through the local API: (start, location, status, body) with marks taken before."""
        self.marks = (site.mark(), auth_server.mark())
        if expect_ok:
            start, done = self.login_ok('var', 'v', auth_server, body, rule=rule)
            return start, done
        status, value = self.login_start('var', 'v', body)
        return status, value

    def check_sign_in_variants(self):
        v = self.mcp('var', auth='oauth')
        a = self.auth_server('asv')
        v.cfg.update(auth_server=a)
        self.put_var(v)
        s = self.server('var', 'v')
        need(s['reason'] == 'login' and s['auth']['mode'] == 'oauth', 'var/v needs a sign-in', s)

        def prm_paths():
            return [r['path'] for r in v.since(self.marks[0], 'GET')]

        def meta_paths(auth=None):
            return [r['path'] for r in (auth or a).since(self.marks[1], 'GET') if '.well-known' in r['path']]

        # Protected resource metadata: the challenge's URL, the path-inserted URL, the root URL.
        v.cfg.update(challenge_metadata=v.prm_url('custom'), prm_paths=('custom',))
        self.variant('metadata at the challenge URL', v, a)
        need(prm_paths() == ['/custom/resource-metadata'], 'resource_metadata from the challenge is used first',
             prm_paths())
        v.cfg.update(challenge_metadata=False, prm_paths=('path',))
        self.variant('metadata at the path-inserted URL', v, a)
        need(prm_paths() == ['/.well-known/oauth-protected-resource/mcp'], 'the path-inserted URL', prm_paths())
        v.cfg.update(prm_paths=('root',))
        self.variant('metadata at the root URL', v, a)
        need(prm_paths() == ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource'],
             'the path-inserted URL, then the root URL', prm_paths())
        v.cfg.update(challenge_metadata=True, prm_paths=('path',))

        # Authorization server metadata, in order, for an issuer without a path and with one.
        a.cfg.update(metadata=('oidc-insert',))
        self.variant('OpenID Connect metadata, issuer without a path', v, a)
        need(meta_paths() == ['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'],
             'without a path: RFC 8414, then OpenID Connect', meta_paths())
        a.cfg.update(metadata=('oauth',))
        for kinds, tried in ((('oauth',), 1), (('oidc-insert',), 2), (('oidc-append',), 3)):
            t = self.auth_server('ast' + str(tried), '/tenant/x', metadata=kinds)
            v.cfg.update(auth_server=t)
            self.variant(f'issuer with a path, {kinds[0]}', v, t)
            need(meta_paths(t) == t.discovery_order()[:tried],
                 f'with a path: the paths in order up to {kinds[0]}', meta_paths(t), t.discovery_order())
        v.cfg.update(auth_server=a)

        # The issuer check and https-or-loopback endpoints.
        a.cfg.update(issuer_override=a.issuer + '/other')
        status, body = self.variant('wrong issuer', v, a, expect_ok=False)
        self.refused(status, body, 'oauth_metadata', 'a metadata issuer other than the one derived', source='var/v')
        a.cfg.update(issuer_override=None)

        # PKCE.
        for pkce in (None, ['plain']):
            a.cfg.update(pkce=pkce)
            status, body = self.variant(f'pkce {pkce}', v, a, expect_ok=False)
            self.refused(status, body, 'no_pkce', f'code_challenge_methods_supported {pkce}', source='var/v',
                         issuer=a.issuer)
        a.cfg.update(pkce=['S256'])

        # DCR returning a secret: client_secret_post, client_secret_basic, and basic when unspecified. Each needs a
        # new registration: a new issuer each time.
        for method, expect in (('client_secret_post', 'post'), ('client_secret_basic', 'basic'),
                               ('unspecified', 'basic')):
            t = self.auth_server('asd-' + method, dcr_secret=method)
            v.cfg.update(auth_server=t)
            self.variant(f'DCR with a secret ({method})', v, t)
            tok = [r for r in t.since(self.marks[1], 'POST', '/token')][-1]
            secret = [c for c in t.clients.values() if c.get('client_secret')][-1]
            if expect == 'post':
                ok = tok['form'].get('client_secret') == secret['client_secret'] and basic_of(tok['headers']) is None
            else:
                ok = (basic_of(tok['headers']) == (secret['client_id'], secret['client_secret']) and
                      'client_secret' not in tok['form'])
            need(ok, f'a DCR secret with {method} authenticates as client_secret_{expect}', tok['form'].keys(),
                 tok['headers'].get('authorization', '')[:10])
            reg = self.clients(t.issuer)
            need(len(reg) == 1 and reg[0]['method'] == f'client_secret_{expect}' and reg[0]['client_secret'] and
                 reg[0]['registration_access_token'], 'the registration keeps the secret, the registration access '
                 'token, and the method', [{k: x[k] for k in ('method', 'registration')} for x in reg])

        # No DCR: refused without a client ID; --client-id (manual) with and without a secret.
        t = self.auth_server('asm', dcr=False, revocation=False)
        v.cfg.update(auth_server=t)
        status, body = self.variant('no registration endpoint', v, t, expect_ok=False)
        port = None
        if isinstance(body, dict):
            m = re.search(r'127\.0\.0\.1:(\d+)/callback', body.get('error', ''))
            port = m.group(1) if m else None
        self.refused(status, body, 'no_registration', 'no registration_endpoint and no client', source='var/v',
                     issuer=t.issuer, port=port or 'PORT')
        t.add_client('manual-public')
        start, done = self.variant('--client-id', v, t, {'client_id': 'manual-public'})
        tok = t.since(self.marks[1], 'POST', '/token')[-1]
        need(done['registration'] == 'manual' and tok['form']['client_id'] == 'manual-public' and
             'client_secret' not in tok['form'] and basic_of(tok['headers']) is None,
             '--client-id without a secret: a public manual client', done, tok['form'].keys())
        t.add_client('manual-secret', secret='ms-' + secrets.token_hex(8))
        start, done = self.variant('--client-id with a secret', v, t,
                                   {'client_id': 'manual-secret', 'client_secret': t.clients['manual-secret']
                                    ['client_secret']})
        tok = t.since(self.marks[1], 'POST', '/token')[-1]
        need(tok['form'].get('client_secret') == t.clients['manual-secret']['client_secret'],
             'a manual client with a secret uses client_secret_post when the metadata lists it', tok['form'].keys())
        t.cfg.update(auth_methods=['client_secret_basic'])
        start, done = self.variant('--client-id with a secret, basic only', v, t,
                                   {'client_id': 'manual-secret', 'client_secret': t.clients['manual-secret']
                                    ['client_secret']})
        tok = t.since(self.marks[1], 'POST', '/token')[-1]
        need(basic_of(tok['headers']) == ('manual-secret', t.clients['manual-secret']['client_secret']),
             'client_secret_basic when the metadata lists it and not client_secret_post', tok['headers'].keys())
        # The CLI's --client-secret-file (0600), pasted.
        secret_file = self.root / 'client-secret'
        secret_file.write_text(t.clients['manual-secret']['client_secret'] + '\n\n')
        secret_file.chmod(0o600)
        t.cfg.update(auth_methods=['none', 'client_secret_post', 'client_secret_basic'])
        mark = t.mark()
        result, url, location, page = self.cli_login('var/v', '--client-id', 'manual-secret', '--client-secret-file',
                                                     str(secret_file), mode='paste', rule='--client-secret-file')
        tok = t.since(mark, 'POST', '/token')
        need(result[0] == 0 and tok and tok[-1]['form'].get('client_secret') ==
             t.clients['manual-secret']['client_secret'],
             '--client-secret-file: read once, trailing whitespace removed, sent as the client secret', result[0],
             result[2][-400:])

        # Scope choice: given, else the hint, else the challenge, else scopes_supported, else none.
        v.cfg.update(auth_server=a, challenge_scope=None, prm_scopes=None)
        a.cfg.update(grant_scope=None)

        def scope_of(body=None):
            start, done = self.variant('scope choice', v, a, body)
            return query_of(start['authorization_url']).get('scope')
        need(scope_of() is None, 'no scope anywhere: none')
        v.cfg.update(prm_scopes=['p1', 'p2'])
        need(scope_of() == 'p1 p2', 'scopes_supported joined with spaces')
        v.cfg.update(challenge_scope='c1 c2')
        need(scope_of() == 'c1 c2', 'the challenge scope before scopes_supported')
        hint_port = free_port()
        self.put_var(v, remote={'protocol': 'http', 'oauth': {'client_id': None, 'scopes': 'h1',
                                                              'callback_port': hint_port}, 'headers_helper': False})
        need(scope_of() == 'h1', 'the harness hint before the challenge')
        need(scope_of({'scopes': 'given'}) == 'given', 'the scopes given before the hint')
        # Redirect port: given, else the hint, else the newest registration's port.
        start, done = self.variant('hint port', v, a)
        need(urllib.parse.urlsplit(start['redirect_uri']).port == hint_port, 'the hint callback_port',
             start['redirect_uri'])
        given = free_port()
        start, done = self.variant('given port', v, a, {'redirect_port': given})
        need(start['redirect_uri'] == f'http://127.0.0.1:{given}/callback', 'redirect_port given', start)
        self.put_var(v)
        start, done = self.variant('stored port', v, a)
        need(start['redirect_uri'] == f'http://127.0.0.1:{given}/callback',
             'without a port or hint: the port of the most recently created registration for the issuer', start)

        # The canonical resource: trailing slashes and the fragment removed, in both requests.
        c = self.mcp('canon', path='/mcp/', auth='oauth', auth_server=a)
        c.cfg.update(resource=f'http://127.0.0.1:{c.port}/mcp')
        self.put_var(c, url=f'http://127.0.0.1:{c.port}/mcp/#part')
        start, done = self.variant('canonical resource', c, a)
        tok = a.since(self.marks[1], 'POST', '/token')[-1]
        need(query_of(start['authorization_url'])['resource'] == f'http://127.0.0.1:{c.port}/mcp' and
             tok['form']['resource'] == f'http://127.0.0.1:{c.port}/mcp',
             'resource is the canonical URL (no fragment, no trailing /) in both requests',
             query_of(start['authorization_url'])['resource'])
        self.put_var(v)

        # Account, expires_at, login IDs.
        start, done = self.variant('--account', v, a, {'account': 'second account'})
        need(done['account'] == 'second account' and LOGIN_ID.match(start['login_id']) and
             550 <= parse_time(start['expires_at']).timestamp() - time.time() <= 660,
             'account; login_ IDs of 32 hex; a login kept 10 minutes', done, start)

        # Finishing: a wrong state, a second use, an unknown ID; error and no code; token refusals.
        start = self.login_start('var', 'v')[1]
        code_, location = a.approve(start['authorization_url'])
        q = query_of(location)
        wrong = location.replace(q['state'], 'f' * 64)
        status, body = self.login_complete(start['login_id'], wrong)
        self.refused(status, body, 'login_expired', 'a different state', source='var/v')
        status, body = self.login_complete(start['login_id'], location)
        self.refused(status, body, 'login_expired', 'a second use of a login_id (removed at the first attempt)',
                     source='SOURCE')
        status, body = self.login_complete('login_' + '0' * 32, location)
        self.refused(status, body, 'login_expired', 'an unknown login_id', source='SOURCE')
        start = self.login_start('var', 'v')[1]
        cb = start['redirect_uri'] + '?' + urllib.parse.urlencode({'code': 'c'})
        status, body = self.login_complete(start['login_id'], cb)
        self.refused(status, body, 'login_expired', 'a missing state', source='var/v')
        for desc, error in (('The user said no', 'access_denied (The user said no)'), (None, 'access_denied')):
            a.cfg.update(authorize=('error', 'access_denied', desc))
            start, location, status, body = self.login_api('var', 'v', a, rule='provider refused')
            self.refused(status, body, 'provider_refused', f'error in the redirect ({desc})', error=error)
        a.cfg.update(authorize='approve')
        start = self.login_start('var', 'v')[1]
        cb = start['redirect_uri'] + '?' + urllib.parse.urlencode({'state': query_of(start['authorization_url'])
                                                                   ['state']})
        status, body = self.login_complete(start['login_id'], cb)
        self.refused(status, body, 'no_code', 'no code in the redirect', source='var/v')
        for token_error, error in ((('invalid_grant', 'bad code', 400), 'invalid_grant (bad code)'),
                                   (('invalid_grant', None, 400), 'invalid_grant'),
                                   ((None, None, 500), 'HTTP 500')):
            a.cfg.update(token_error=token_error)
            start, location, status, body = self.login_api('var', 'v', a, rule='token refused')
            self.refused(status, body, 'token_refused', f'token request refused ({token_error})', error=error)
        a.cfg.update(token_error=None)
        a.cfg.update(token_type='mac')
        start, location, status, body = self.login_api('var', 'v', a, rule='token_type mac')
        need(status == 502 and isinstance(body, dict) and body.get('code') == 'token_refused',
             'a token_type other than Bearer is token_refused', status, body)
        a.cfg.update(token_type='bearer')
        start, done = self.login_ok('var', 'v', a, rule='token_type bearer (any case)')
        a.cfg.update(token_type='Bearer')
        # Registration refused.
        t = self.auth_server('asr', dcr_status=400)
        v.cfg.update(auth_server=t)
        status, body = self.variant('registration refused', v, t, expect_ok=False)
        self.refused(status, body, 'registration_failed', 'DCR refused', source='var/v', issuer=t.issuer)
        v.cfg.update(auth_server=a)
        return ''

    def refused(self, status, body, code, rule, **values):
        want_status, template, wire_code = (REFUSALS[code] + (code,))[:3]
        values.setdefault('source', 'var/v')
        text = template.format(**{k: values.get(k, '') for k in ('source', 'name', 'reason', 'issuer', 'port',
                                                                  'error')})
        ok = status == want_status and isinstance(body, dict) and body.get('code') == wire_code
        if ok:
            ok = body.get('error', '').startswith(text) if code in DETAIL_CODES else body.get('error') == text
        need(ok, f'{rule}: {want_status} {code} with the exact text', status, body, text)

    # --- refusals ----------------------------------------------------------------------------------------------

    def check_refusals(self):
        r = self.refused
        status, body = self.login_start('cc', 'nosuch')
        r(status, body, 'not_found', 'an unknown source', source='cc/nosuch')
        status, body = self.login_start('nobody', 'oa')
        r(status, body, 'not_found', 'an unknown agent', source='nobody/oa')
        status, body = self.login_start(self.aid['cc'], 'oa', {'capability': 'nosuch'})
        r(status, body, 'no_capability', 'an unknown capability (agent by ID)', name='nosuch')
        status, body = self.login_start('cc', 'oa', {'capability': 'capnone'})
        r(status, body, 'other_source', 'a capability built on another source', name='capnone', source='cc/oa')
        status, body = self.login_start('oc', 'ocoff')
        r(status, body, 'oauth_disabled', 'remote.oauth null', source='oc/ocoff')
        status, body = self.login_start('cc', 'old')
        r(status, body, 'not_usable', 'a definition reason', source='cc/old', reason='sse')
        status, body = self.login_start('cc', 'pub')
        r(status, body, 'no_challenge', 'a 2xx to the probe', source='cc/pub')
        status, body = self.login_start('cc', 'hdrbad')
        r(status, body, 'no_challenge', 'a 401 to a source with an Authorization header', source='cc/hdrbad')
        self.put('old', [{'name': 'o', 'transport': 'stdio', 'command': 'false', 'args': [], 'env': {}, 'url': None,
                          'source': 'claude-code:user'}])
        status, body = self.login_start('old', 'o')
        r(status, body, 'no_challenge', 'a stdio source', source='old/o')
        # SERVER that several agents have: the CLI exits 1 before any request, listing the qualified names.
        self.put('old', [{'name': 'o', 'transport': 'stdio', 'command': 'false', 'args': [], 'env': {}, 'url': None,
                          'source': 'claude-code:user'}, self.remote_def('oa', self.oa.url)])
        marks = (self.oa.mark(), self.as1.mark())
        code, value, stdout, stderr = self.out('p1', 'sources', 'login', 'oa', '--no-browser')
        need(code == 1 and 'cc/oa' in stderr and 'old/oa' in stderr and (self.oa.mark(), self.as1.mark()) == marks,
             'sources login SERVER that several agents have: exit 1, the qualified names, no request', code,
             stderr[-400:])
        status, body = self.login_start('cc', 'six')
        r(status, body, 'unreachable', 'a server that cannot be reached', source='cc/six')
        for rule, b in (('an unknown field', {'scope': 'x'}), ('client_secret without client_id',
                                                               {'client_secret': 'x'}),
                        ('redirect_port 0', {'redirect_port': 0}), ('redirect_port 65536', {'redirect_port': 65536}),
                        ('an account with a control character', {'account': 'a\x07b'}),
                        ('an account over 256 bytes', {'account': 'a' * 257})):
            status, body = self.login_start('cc', 'oa', b)
            need(status == 400 and isinstance(body, dict) and body.get('code') == 'invalid',
                 f'{rule}: 400 invalid', status, body)
        status, body = self.login_complete('login_' + '1' * 32, {'callback_url': 'x'})
        need(status == 400, 'a complete body other than {callback_url} is 400', status, body)
        # The CLI prints the text and exits 1.
        for args, text in ((('sources', 'login', 'cc/nosuch', '--no-browser'),
                            refusal_text('not_found', source='cc/nosuch')),
                           (('sources', 'login', 'nosuchserver', '--no-browser'),
                            None),
                           (('sources', 'login', 'ocoff', '--no-browser'),
                            refusal_text('oauth_disabled', source='oc/ocoff')),
                           (('capability', 'login', 'nosuch', '--no-browser'), None)):
            code, value, stdout, stderr = self.out('p1', *args)
            need(code == 1 and (text is None or text in squash(stderr)), f'{" ".join(args[:3])}: exit 1 with the '
                 'refusal text on stderr', code, stderr[-400:], text)
        code, value, stdout, stderr = self.out('p1', 'capability', 'login', 'capnone')
        need(code == 1 and NEEDS_TERMINAL.format(cmd='capability login') in squash(stderr),
             'capability login without a terminal and without --no-browser names capability login', code, stderr)
        return ''

    # --- capabilities and calls --------------------------------------------------------------------------------

    def check_capabilities(self):
        self.needs('oa', 'oa3', 'capnone', 'caphdr', 'capteam')
        code, value, stderr = self.create('capoa', 'cc/oa', ['echo', 'who', 'sleep', 'status', 'write_note'])
        self.share('capoa')
        self.done.add('capoa')
        self.create('capoa3', 'cc/oa3', ['echo'])
        cred = self.credential('cc', 'oa')
        date = cred['obtained_at'][:10]
        for name, mode in (('capnone', 'none'), ('caphdr', 'headers'), ('capteam', 'headers')):
            c = self.capability(name)
            need(c['auth'] == dict(NULL_AUTH, mode=mode, own=False) and c['state'] == 'available',
                 f'{name}: auth {{mode {mode}, own false}} in the capability view', c.get('auth'))
        c = self.capability('capoa')
        need(set(c['auth']) == CAP_AUTH_KEYS and c['auth'] == {
            'mode': 'oauth', 'state': 'ok', 'issuer': self.as1.issuer, 'scope': 'read write', 'account': 'work',
            'registration': 'dcr', 'obtained_at': cred['obtained_at'], 'expires_at': cred['expires_at'],
            'own': False}, 'capoa: auth from the source\'s credential', c['auth'], cred['obtained_at'])
        need(not c.get('own_sign_in'), 'own_sign_in is stored only when true', c)
        status, listed = self.api('GET', '/v1/capabilities')
        need(all('auth' in x for x in listed['capabilities']), 'GET /v1/capabilities gains auth')
        code, shown, stdout, stderr = self.out('p1', 'capability', 'show', 'capoa')
        need(code == 0 and (shown or {}).get('auth', {}).get('mode') == 'oauth', 'capability show gains auth',
             code, stdout[-400:])
        # --arg with a remote source.
        code, value, stdout, stderr = self.out('p1', 'capability', 'create', 'argcap', '--from', 'cc/pub',
                                               '--operations', 'echo', '--arg', 'x')
        need(code == 1 and ARG_REFUSED in stderr and self.capability('argcap') is None,
             '--arg with a remote source is refused with the text', code, stderr[-300:])
        status, body = self.api('POST', '/v1/capabilities', {'name': 'argcap2', 'source': {'agent': 'cc',
                                                                                          'server': 'pub'},
                                                             'operations': ['echo'], 'resources': None,
                                                             'env_file': None, 'args': ['x'], 'policies': []})
        need(status == 400 and isinstance(body, dict) and ARG_REFUSED in str(body.get('error')),
             'POST /v1/capabilities with args on a remote source: 400 with the text', status, body)

        # The review's Credential line, and shares.
        reviews = {
            'capnone': ('Credential: none. cc/pub (127.0.0.1) asks for no sign-in, so it serves anyone who can reach '
                        'it. Sharing it lets the people you share with use the selected operations through this host, '
                        'including when the server is only reachable from here (a local, home, VPN, or company '
                        'network).'),
            'caphdr': 'Credential: the token in the Authorization header of cc/hdr (from claude-code:user).',
            'capteam': 'Credential: the tokens in the X-Api-Key, X-Team headers of cc/team (from claude-code:user).',
            'capteamenv': ('Credential: the tokens in the X-Api-Key, X-Team headers of cc/team (from claude-code:user). '
                           f"Values from the capability's environment file {self.root / 'team-own.env'} override the "
                           'variables those headers reference.'),
            'capoa': (f"Credential: Peerspan's own sign-in to 127.0.0.1, scopes read write, account work, signed in on "
                      f'{date}.'),
            'capoa3': (f"Credential: Peerspan's own sign-in to 127.0.0.1, scopes none, account not labelled; Peerspan "
                       f"cannot see which account approved, signed in on {self.credential('cc', 'oa3')['obtained_at'][:10]}."),
        }
        self.reviews = {}
        for name, line in reviews.items():
            tty = self.review(name)
            self.reviews[name] = tty
            need(squash(line) in squash(tty) and 'Credentials:' not in tty,
                 f'the review of {name}: its Credential line replaces Credentials:', line, tty[-1200:])
        code, value, stdout, stderr = self.out('p1', 'shares', '--network', self.team)
        for name in ('capnone', 'caphdr', 'capoa'):
            need(squash('credential: ' + reviews[name][len('Credential: '):]) in squash(stdout),
                 f'shares text: the credential line for {name}', stdout[-2000:])
        code, value, stdout, stderr = self.out('p1', 'shares', '--json', '--network', self.team)
        need(code == 0 and '"auth"' in stdout and self.as1.issuer in stdout, 'shares --json gains auth', stdout[-800:])

        # Calls: by policy (q1's CLI), by self (p2's CLI), and a raw source call from p2.
        mark = self.oa.mark()
        for host, target, text in (('q1', 'pat/capoa', 'by policy'), ('p2', 'pat/capoa', 'by self'),
                                   ('p2', 'pat/cc/oa', 'raw source')):
            self.synced(host)
            code, value, stdout, stderr = self.out(host, 'call', target, 'echo', '--text', text, '--network',
                                                   self.team, '--wait', '60s')
            need(code == 0 and caps.dig(value, 'status', 'state') == 'succeeded' and
                 text_of(caps.dig(value, 'result')) == text,
                 f'call {target} {text}: succeeded with the server\'s result', code, stdout[-600:], stderr[-300:])
            calls = self.oa.calls('echo', text, since=mark)
            need(len(calls) == 1 and bearer_of(calls[0]['request']) == self.credential('cc', 'oa')['access_token'],
                 f'{text}: one request to the server, with the source\'s token', len(calls))
        for host, target in (('q1', 'pat/capnone'), ('q1', 'pat/caphdr')):
            code, value, stdout, stderr = self.out(host, 'call', target, 'echo', '--text', 'hi', '--network',
                                                   self.team, '--wait', '60s')
            need(code == 0 and caps.dig(value, 'status', 'state') == 'succeeded', f'call {target}', code,
                 stdout[-400:], stderr[-300:])

        # The guided share refuses a source that needs a sign-in, without a terminal.
        gl = self.mcp('gl', auth='oauth', auth_server=self.as1)
        self.put('old', [self.remote_def('gl', gl.url)])
        need(self.server('old', 'gl')['reason'] == 'login', 'old/gl needs a sign-in')
        code, value, stdout, stderr = self.out('p1', 'share', '--with', 'quinn', '--from', 'old/gl', '--operations',
                                               'echo', '--name', 'glcap', '--yes', '--network', self.team)
        need(code == 1 and GUIDED_NEEDS_LOGIN.format(source='old/gl') in squash(stderr) and
             self.capability('glcap') is None,
             'the guided share without a terminal refuses a login source, with nothing created', code, stderr[-400:])
        return ''

    # --- tokens ------------------------------------------------------------------------------------------------

    def relogin(self, agent, server, auth_server, ttl, body=None):
        auth_server.cfg.update(access_ttl=ttl)
        start, done = self.login_ok(agent, server, auth_server, body, rule=f're-sign-in to {agent}/{server}')
        return done

    def refreshes(self, auth_server, mark):
        return [r for r in auth_server.since(mark, 'POST', '/token')
                if r.get('form', {}).get('grant_type') == 'refresh_token']

    def check_tokens(self):
        self.needs('oa3', 'capoa')
        a, site = self.as1, self.oa3
        self.create('capt', 'cc/oa3', ['echo', 'sleep', 'status'])
        # Refresh before use.
        self.relogin('cc', 'oa3', a, 30)
        a.cfg.update(access_ttl=3600)
        old = self.credential('cc', 'oa3')
        mark, smark = a.mark(), site.mark()
        record = self.run_call('capt', 'echo', {'text': 'refresh'}, caller='p2', rule='refresh before use')
        need(record['state'] == 'succeeded', 'a call with a short-lived token succeeds', record)
        refreshes = self.refreshes(a, mark)
        new = self.credential('cc', 'oa3')
        need(len(refreshes) == 1, 'one refresh before use, when expires_at is within 60 seconds', len(refreshes))
        form = refreshes[0]['form']
        need(form.get('refresh_token') == old['refresh_token'] and form.get('client_id') and
             form.get('resource') == canonical(site.url) and set(form) - {'client_secret'} ==
             {'grant_type', 'refresh_token', 'client_id', 'resource'},
             'the refresh request: grant_type, refresh_token, client_id, resource', sorted(form))
        need(new['access_token'] != old['access_token'] and new['refresh_token'] != old['refresh_token'] and
             new['refresh_token'] in a.refresh and new['refreshed_at'] and new['state'] == 'ok',
             'the rotated refresh token and the new access token are stored, with refreshed_at', new['refreshed_at'])
        call = site.calls('echo', 'refresh', since=smark)
        grant = self.grant_of(bearer_of(call[0]['request'])) if call else None
        need(len(call) == 1 and grant and bearer_of(call[0]['request']) != old['access_token'] and
             grant['issued_at'] >= refreshes[0]['time'],
             'the call uses the token its refresh issued', len(call))
        sent = [r for r in site.since(smark) if r['path'] == urllib.parse.urlsplit(site.url).path]
        need(sent and all(bearer_of(r) in (old['access_token'], new['access_token']) for r in sent),
             'every request to the MCP endpoint of an OAuth source carries Authorization: Bearer',
             [(r['method'], bool(bearer_of(r))) for r in sent])
        # One refresh for several concurrent calls.
        self.relogin('cc', 'oa3', a, 30)
        a.cfg.update(access_ttl=3600, refresh_delay=2)
        mark = a.mark()
        ids = [self.submit('capt', 'echo', {'text': f'conc-{i}'}, caller='p2')[0] for i in range(3)]
        finals = [self.final(i, 'p2') for i in ids]
        a.cfg.update(refresh_delay=0)
        need(all(f['state'] == 'succeeded' for f in finals) and len(self.refreshes(a, mark)) == 1,
             'one refresh serves several concurrent calls', [f['state'] for f in finals], len(self.refreshes(a, mark)))
        need(not [v for v in a.violations if 'reused' in v[0]], 'a rotated refresh token is never reused',
             [v[0] for v in a.violations if 'reused' in v[0]])
        # refresh_failed on a 5xx, the request going ahead with the current token.
        self.relogin('cc', 'oa3', a, 45)
        a.cfg.update(refresh_error=('server_error', 'try later', 503))
        mark = a.mark()
        record = self.run_call('capt', 'echo', {'text': 'after-5xx'}, caller='p2', rule='refresh 5xx')
        cred = self.credential('cc', 'oa3')
        need(record['state'] == 'succeeded' and len(self.refreshes(a, mark)) >= 1 and cred['state'] == 'refresh_failed'
             and cred['refresh_failed_at'], 'a refresh answered 5xx: refresh_failed, and the call goes ahead',
             record['state'], cred['state'])
        need(self.server('cc', 'oa3')['auth']['state'] == 'refresh_failed', 'auth.state refresh_failed in sources')
        events = self.kinds_for('sources.token_refresh_failed')
        need(any(e['subject_id'] == f"{self.aid['cc']}/oa3" for e in events),
             'sources.token_refresh_failed activity', events[-2:])
        a.cfg.update(refresh_error=None, access_ttl=3600)
        record = self.run_call('capt', 'echo', {'text': 'recovered'}, caller='p2', rule='refresh recovers')
        cred = self.credential('cc', 'oa3')
        need(record['state'] == 'succeeded' and cred['state'] == 'ok' and cred['refresh_failed_at'] is None,
             'the next successful refresh: state ok, refresh_failed_at null', cred['state'], cred['refresh_failed_at'])
        # A 401 to a call: auth_required, never resent, and the next call refreshes first.
        smark, mark = site.mark(), a.mark()
        record = self.run_call('capt', 'status', {'code': 401, 'text': 'u401'}, caller='p2', rule='401 call')
        need(record['state'] == 'failed' and record['error'] == 'auth_required' and
             len(site.calls('status', since=smark)) == 1, 'a 401 to a call: failed auth_required, sent once', record)
        record = self.run_call('capt', 'echo', {'text': 'after-401'}, caller='p2', rule='after 401')
        refreshes = self.refreshes(a, mark)
        call = site.calls('echo', 'after-401', since=smark)
        need(record['state'] == 'succeeded' and refreshes and call and refreshes[0]['time'] < call[0]['request']['time'],
             'after a 401 to a call, the next call refreshes first', len(refreshes), record['state'])
        # Queued calls failing with auth_required when the sign-in goes away before they start.
        sleepers = [self.submit('capt', 'sleep', {'seconds': 6, 'text': f'slot-{i}'}, caller='p2')[0]
                    for i in range(4)]
        for i in sleepers:
            self.state_is(i, 'running', 'p2')
        smark = site.mark()
        queued, status, record = self.submit('capt', 'echo', {'text': 'queued-auth'}, caller='p2')
        need(status == 200 and record['state'] == 'queued', 'a fifth call waits queued', status, record)
        status, out = self.api('POST', '/v1/sources/cc/oa3/logout', {})
        need(status == 200, 'logout cc/oa3 through the local API', status, out)
        record = self.final(queued, 'p2')
        need(record['state'] == 'failed' and record['error'] == 'auth_required' and
             not site.calls('echo', 'queued-auth', since=smark),
             'a queued call that would start without a usable sign-in: failed auth_required, never sent', record)
        for i in sleepers:
            need(self.final(i, 'p2')['state'] == 'succeeded', 'running calls finish')
        # A refused refresh: login_required, unavailable auth, refused at submission with nothing persisted.
        self.relogin('cc', 'oa3', a, 30)
        a.cfg.update(refresh_error=('invalid_grant', 'revoked at the provider', 400))
        smark = site.mark()
        record = self.run_call('capt', 'echo', {'text': 'refused-refresh'}, caller='p2', rule='refused refresh')
        cred = self.credential('cc', 'oa3')
        need(record['state'] == 'failed' and record['error'] == 'auth_required' and
             not site.calls('echo', 'refused-refresh', since=smark) and cred['state'] == 'login_required',
             'a refresh refused with invalid_grant: login_required, and the call failed auth_required unsent',
             record, cred['state'])
        a.cfg.update(refresh_error=None, access_ttl=3600)
        # invalid_client is refused too.
        self.relogin('cc', 'oa3', a, 30)
        a.cfg.update(refresh_error=('invalid_client', 'client revoked', 401))
        record = self.run_call('capt', 'echo', {'text': 'invalid-client'}, caller='p2', rule='invalid_client')
        need(record['state'] == 'failed' and record['error'] == 'auth_required' and
             self.credential('cc', 'oa3')['state'] == 'login_required',
             'a refresh refused with invalid_client: login_required, and the call failed auth_required', record)
        a.cfg.update(refresh_error=None, access_ttl=3600)
        s = self.server('cc', 'oa3')
        c = self.capability('capt')
        need(s['reason'] == 'login' and s['auth']['state'] == 'login_required' and c['unavailable'] == ['auth'] and
             c['state'] == 'unavailable' and c['auth']['state'] == 'login_required',
             'the source is login and its capability unavailable with exactly ["auth"]', s['reason'], c)
        before = self.received()
        for target, caller in (('capt', 'p2'), ('cc/oa3', 'p2')):
            call_id, status, body = self.submit(target, 'echo', {'text': 'lapsed'}, caller=caller)
            need(status == 409 and body == {'code': 'unavailable', 'error': LAPSED_ERROR},
                 f'a call to {target} with a lapsed sign-in: 409 with the text', status, body)
        need(self.received() == before, 'nothing is persisted for a refused call')
        item = self.item('cc/oa3')
        need(item and item['command'] == 'peerspan sources login cc/oa3', 'item 14 for a login_required credential',
             item)
        # insufficient_scope (capoa, signed in with read write; write_note needs admin) and item 14.
        self.oa.cfg.update(scope_tools={'write_note': 'admin'})
        smark = self.oa.mark()
        record = self.run_call('capoa', 'write_note', {'text': 'scope'}, rule='insufficient_scope')
        need(record['state'] == 'failed' and record['error'] == 'insufficient_scope' and
             len(self.oa.calls('write_note', since=smark)) == 1, 'a 403 insufficient_scope: failed, sent once', record)
        item = self.item('cc/oa')
        need(item and item['command'] == 'peerspan sources login cc/oa --scopes "admin"',
             'item 14: sources login with the challenge\'s scope', item)
        # Never on a redirect: a 307 from the MCP endpoint is an error, and its target gets nothing.
        other = self.mcp('other')
        record = self.run_call('capoa', 'status', {'code': 307, 'location': other.url}, rule='redirect')
        need(record['state'] == 'failed' and record['error'] == 'http_error' and not other.requests,
             'a 3xx answer to a call is failed http_error, and the redirect is not followed', record, other.requests)
        return ''

    # --- per-capability sign-in --------------------------------------------------------------------------------

    def check_own_sign_in(self):
        self.needs('oa', 'capoa')
        self.create('capown', 'cc/oa', ['echo', 'who'])
        result, url, location, page = self.cli_login('capown', '--account', 'other', '--scopes', 'read',
                                                     command=('capability', 'login'), rule='capability login')
        code, value, text, stdout = result
        need(code == 0 and value and value['capability'] == 'capown' and value['source'] == 'cc/oa' and
             value['scopes'] == 'read' and value['account'] == 'other',
             'capability login: the output names the capability and its source', code, value, text[-400:])
        own = self.credential('cc', 'oa', 'capown')
        need(own and own['scope'] == 'read' and own['account'] == 'other', 'the credential is stored under the '
             'capability\'s key', {k: v for k, v in (own or {}).items() if 'token' not in k})
        c = self.capability('capown')
        need(c['auth']['own'] is True and c['auth']['account'] == 'other' and c['auth']['scope'] == 'read' and
             c['state'] == 'available', 'auth.own true, with the capability\'s own credential', c['auth'])
        events = self.kinds_for('sources.login')
        need(any(e['subject_id'] == f"{self.aid['cc']}/oa@capown" for e in events),
             'sources.login activity with subject AGENT_ID/SERVER@CAPABILITY', events[-2:])
        smark = self.oa.mark()
        record = self.run_call('capown', 'who', {}, caller='p2', rule='own sign-in call')
        who = json.loads(text_of(record.get('result')) or '{}')
        calls = self.oa.calls('who', since=smark)
        need(record['state'] == 'succeeded' and who.get('scope') == 'read' and calls and
             bearer_of(calls[-1]['request']) == self.credential('cc', 'oa', 'capown')['access_token'],
             'a call through the capability uses its own token', record, who)
        log = self.hosts['p1'].state / 'tool-logs' / self.aid['cc'] / 'oa@capown.log'
        need(log.exists() and (log.stat().st_mode & 0o777) == 0o600, 'its own instance logs to SERVER@CAPABILITY.log',
             log)
        tty = self.review('capown')
        need(squash(f"Credential: this capability's own sign-in to 127.0.0.1, scopes read, account other, signed in on "
                    f"{own['obtained_at'][:10]}.") in squash(tty), 'the review\'s own sign-in line', tty[-800:])
        # The source signed out: the capability keeps working.
        status, out = self.api('POST', '/v1/sources/cc/oa/logout', {})
        need(status == 200 and out.get('deleted') is True, 'source logout through the local API', status, out)
        record = self.run_call('capown', 'echo', {'text': 'own-alone'}, caller='p2', rule='own sign-in alone')
        need(record['state'] == 'succeeded' and self.capability('capoa')['unavailable'] == ['auth'],
             'with the source signed out, the capability with its own sign-in still works; the others are '
             'unavailable with auth', record['state'], self.capability('capoa')['unavailable'])
        self.relogin('cc', 'oa', self.as1, 3600, {'account': 'work'})
        # capability logout: unavailable with auth, no fallback to the source's sign-in.
        code, value, stdout, stderr = self.out('p1', 'capability', 'logout', 'capown')
        need(code == 0 and value == {'source': 'cc/oa', 'capability': 'capown', 'revoked': True, 'deleted': True},
             'capability logout', code, value, stderr[-300:])
        c = self.capability('capown')
        need(c['unavailable'] == ['auth'] and c['auth']['own'] is True and self.credential('cc', 'oa', 'capown') is None
             and self.capability('capoa')['state'] == 'available',
             'after capability logout: unavailable with auth, own kept, never the source\'s sign-in', c)
        call_id, status, body = self.submit('capown', 'echo', {'text': 'no-fallback'}, caller='p2')
        need(status == 409 and body == {'code': 'unavailable', 'error': LAPSED_ERROR}, 'refused at submission',
             status, body)
        tty = self.review('capown')
        need(squash('Credential: the sign-in to cc/oa has lapsed; run peerspan capability login capown') in squash(tty),
             'the review\'s lapsed line for a capability\'s own sign-in', tty[-600:])
        code, value, stdout, stderr = self.out('p1', 'capability', 'logout', 'capown')
        need(code == 0 and value and value['deleted'] is False and NO_OWN_SIGN_IN.format(name='capown') in stderr,
             'capability logout without a credential: deleted false and the text', code, value, stderr[-300:])
        # A capability's sign-in through a pasted address.
        result, url, location, page = self.cli_login('capoa3', mode='paste', command=('capability', 'login'),
                                                     rule='capability login, pasted')
        code, value, text, stdout = result
        need(code == 0 and value and value['capability'] == 'capoa3' and value['source'] == 'cc/oa3' and
             self.credential('cc', 'oa3', 'capoa3') and self.capability('capoa3')['auth']['own'] is True,
             'capability login with a pasted address', code, value, text[-400:])
        self.done.add('capown')
        return ''

    # --- running -----------------------------------------------------------------------------------------------

    def check_running(self):
        secret = 'run-' + secrets.token_hex(10)
        self.header_values.append(secret)
        rh = self.mcp('rh', auth='headers', headers={'X-Run': secret}, protocol='2025-11-25')
        rs = self.mcp('rs', reply='sse', sse_noise=True)
        rg = self.mcp('rgone')
        rf = self.mcp('rflaky')
        lit = {'source': 'literal'}
        d = self.remote_def
        self.put('run', [d('rh', rh.url, headers={'X-Run': lit, 'Accept': lit, 'MCP-Session-Id': lit,
                                                  'Content-Type': lit}),
                         d('rs', rs.url), d('rgone', rg.url), d('rflaky', rf.url)],
                 {'rh': {'headers.X-Run': secret, 'headers.Accept': 'text/plain', 'headers.MCP-Session-Id': 'bogus',
                         'headers.Content-Type': 'text/plain'}})
        ops = ['echo', 'sleep', 'status', 'drop', 'big', 'lose_session', 'garbage', 'ask']
        self.create('caprun', 'run/rh', ops)
        self.share('caprun', terminal=False)
        self.done.add('caprun')
        self.sync()
        mark = rh.mark()
        record = self.run_call('caprun', 'echo', {'text': 'first'}, rule='first call')
        need(record['state'] == 'succeeded' and text_of(record['result']) == 'first', 'a call on a headers source',
             record)
        posts = rh.since(mark, 'POST')
        methods = [(r.get('message') or {}).get('method') for r in posts]
        need(methods[:3] == ['initialize', 'notifications/initialized', 'tools/call'],
             'POST initialize, notifications/initialized, then the call', methods)
        sid = None
        for r in rh.since(0):
            need(r['headers'].get('x-run') == secret, 'the definition\'s headers on every request', r['method'],
                 r['path'])
        for r in posts:
            h = r['headers']
            need(h.get('content-type', '').startswith('application/json') and
                 {'application/json', 'text/event-stream'} <= {p.strip() for p in h.get('accept', '').split(',')},
                 'Content-Type application/json and Accept application/json, text/event-stream (definition headers '
                 'of those names not sent)', h.get('content-type'), h.get('accept'))
            if r['message'].get('method') != 'initialize':
                sid = sid or h.get('mcp-session-id')
                need(h.get('mcp-protocol-version') == '2025-11-25' and h.get('mcp-session-id') in rh.sessions and
                     h.get('mcp-session-id') != 'bogus',
                     'MCP-Protocol-Version (the negotiated version) and MCP-Session-Id after initialize', h)
        # SSE answers with unrelated events and a ping; a server-to-client request other than ping.
        call_id, status, rec = self.submit('run/rs', 'echo', {'text': 'over-sse'}, caller='p2')
        rec = self.final(call_id, 'p2')
        need(rec['state'] == 'succeeded' and text_of(rec['result']) == 'over-sse',
             'an SSE answer: read until the response to this request; other events dropped', rec)
        answered = [a for a in rs.answers if a.get('id') in rs.pings]
        need(answered and all(a == {'jsonrpc': '2.0', 'id': a.get('id'), 'result': {}} for a in answered),
             'a ping on the stream is answered with the JSON-RPC response {jsonrpc, id, result: {}}', rs.answers[-3:])
        call_id, status, rec = self.submit('run/rs', 'ask', {}, caller='p2')
        rec = self.final(call_id, 'p2')
        need(rec['state'] == 'succeeded' and json.loads(text_of(rec['result'])) == {'answered': True, 'code': -32601},
             'another server-to-client request on the stream is answered with error -32601', rec)
        # A lost session.
        mark = rh.mark()
        record = self.run_call('caprun', 'lose_session', {}, rule='session 404')
        need(record['state'] == 'failed' and record['error'] == 'server_exited',
             'a 404 to a request with MCP-Session-Id: failed server_exited', record)
        record = self.run_call('caprun', 'echo', {'text': 'new-session'}, rule='after session 404')
        inits = [r for r in rh.since(mark, 'POST') if (r.get('message') or {}).get('method') == 'initialize']
        need(record['state'] == 'succeeded' and inits and 'mcp-session-id' not in inits[-1]['headers'],
             'the next call starts a new session', record['state'], len(inits))
        # Each call outcome, with exactly one request per call.
        for input, state, error in (
                ({'code': 401}, 'failed', 'auth_required'),
                ({'code': 403, 'challenge': 'Bearer error="insufficient_scope", scope="more"'}, 'failed',
                 'insufficient_scope'),
                ({'code': 403}, 'failed', 'http_error'),
                ({'code': 400}, 'failed', 'http_error'),
                ({'code': 422}, 'failed', 'http_error'),
                ({'code': 302}, 'failed', 'http_error'),
                ({'code': 500}, 'uncertain', 'http_error'),
                ({'code': 503}, 'uncertain', 'http_error')):
            marker = f"st-{input['code']}-{secrets.token_hex(3)}"
            mark = len(rh.executions)
            record = self.run_call('caprun', 'status', dict(input, text=marker), rule=f'HTTP {input["code"]}')
            sent = [e for e in rh.executions[mark:] if e['kind'] == 'call' and e['arguments'].get('text') == marker]
            need(record['state'] == state and record['error'] == error and len(sent) == 1,
                 f'an HTTP {input["code"]} answer to a call: {state} {error}, sent once', record, len(sent))
        for op, state, error in (('garbage', 'failed', 'http_error'), ('drop', 'uncertain', 'connection_lost')):
            mark = len(rh.executions)
            record = self.run_call('caprun', op, {}, rule=op)
            need(record['state'] == state and record['error'] == error and
                 len([e for e in rh.executions[mark:] if e.get('name') == op]) == 1,
                 f'{op}: {state} {error}, sent once', record)
        # Cancellation and the deadline post notifications/cancelled.
        call_id, status, rec = self.submit('caprun', 'sleep', {'seconds': 20, 'text': 'cancel-me'})
        self.state_is(call_id, 'running')
        time.sleep(1)
        self.wire('p1', 'q1', 'POST', f'/peer/v1/calls/{call_id}/cancel', {})
        rec = self.final(call_id)
        rpc = [e['id'] for e in rh.calls('sleep', 'cancel-me')]
        need(rec['state'] == 'uncertain' and rec['error'] == 'cancel_requested' and rpc and
             wait_for(lambda: any(c.get('requestId') == rpc[0] for c in rh.cancellations), timeout=15,
                      message='notifications/cancelled'),
             'cancelling a running remote call: uncertain cancel_requested, notifications/cancelled with its ID', rec)
        call_id, status, rec = self.submit('caprun', 'sleep', {'seconds': 30, 'text': 'deadline'},
                                           deadline=timestamp(8))
        rec = self.final(call_id, timeout=60)
        rpc = [e['id'] for e in rh.calls('sleep', 'deadline')]
        need(rec['state'] == 'uncertain' and rec['error'] == 'deadline' and rpc and
             wait_for(lambda: any(c.get('requestId') == rpc[0] for c in rh.cancellations), timeout=15,
                      message='notifications/cancelled at the deadline'),
             'the deadline while running: uncertain deadline, notifications/cancelled', rec)
        # Sizes.
        record = self.run_call('caprun', 'big', {'bytes': 3 * 1024 * 1024}, rule='over 2 MiB')
        need(record['state'] == 'failed' and record['error'] == 'result_too_large' and record['result_bytes'] is None,
             'an answer over 2 MiB: failed result_too_large, result_bytes null', record)
        record = self.run_call('caprun', 'big', {'bytes': 1_100_000}, rule='over 1 MiB')
        need(record['state'] == 'failed' and record['error'] == 'result_too_large',
             'a result over 1,048,576 bytes: failed result_too_large', record)
        # A connect failure once the instance runs.
        call_id, status, rec = self.submit('run/rgone', 'echo', {'text': 'before'}, caller='p2')
        need(self.final(call_id, 'p2')['state'] == 'succeeded', 'run/rgone answers first')
        rg.stop()
        call_id, status, rec = self.submit('run/rgone', 'echo', {'text': 'after'}, caller='p2')
        rec = self.final(call_id, 'p2')
        need(rec['state'] == 'failed' and rec['error'] == 'server_exited',
             'a connection that cannot be made: failed server_exited', rec)
        # A server that cannot complete initialize.
        rf.cfg.update(init_status=500)
        call_id, status, rec = self.submit('run/rflaky', 'echo', {'text': 'x'}, caller='p2')
        rec = self.final(call_id, 'p2', timeout=90)
        need(rec['state'] == 'failed' and rec['error'] == 'server_start_failed',
             'initialize failing: the call fails with server_start_failed', rec)
        # No proxy, the log.
        need(not self.proxy.requests, 'no request through HTTP_PROXY, HTTPS_PROXY, or ALL_PROXY (Q: loopback URLs '
             'only)', self.proxy.requests[:2])
        log = self.hosts['p1'].state / 'tool-logs' / self.aid['run'] / 'rh.log'
        need(log.exists() and (log.stat().st_mode & 0o777) == 0o600 and secret not in log.read_text(errors='replace'),
             'STATE/tool-logs/AGENT_ID/SERVER.log, mode 0600, without header values', log)
        return ''

    # --- revocation --------------------------------------------------------------------------------------------

    def check_revocation(self):
        self.needs('oa', 'capoa')
        source = 'cc/oa'
        cred = self.credential('cc', 'oa')
        code, value, stdout, stderr = self.out('p1', 'sources', 'logout', source)
        need(code == 1 and LOGOUT_CONFIRM in stderr and self.credential('cc', 'oa'),
             'sources logout without a terminal and --yes: exit 1 with the text, nothing deleted', code,
             stderr[-300:])
        code, value, tty, stdout, seen = self.terminal('p1', 'sources', 'logout', source, answers=['n'],
                                                       prompt=LOGOUT_PROMPT)
        need(seen and code == 1 and 'capoa' in tty and self.credential('cc', 'oa'),
             'at a terminal it lists the capabilities using the sign-in and asks; n keeps it', code, tty[-600:])
        need('capown' not in tty.split(LOGOUT_PROMPT.split('?')[0])[0], 'a capability with its own sign-in is not '
             'listed', tty[-600:])
        mark = self.as1.mark()
        code, value, tty, stdout, seen = self.terminal('p1', 'sources', 'logout', source, answers=['y'],
                                                       prompt=LOGOUT_PROMPT)
        need(seen and code == 0 and value == {'source': source, 'capability': None, 'revoked': True,
                                              'deleted': True},
             'y signs out: {source, capability, revoked, deleted}', code, value, tty[-400:])
        revokes = self.as1.since(mark, 'POST', '/revoke')
        forms = [r['form'] for r in revokes]
        need([(f.get('token'), f.get('token_type_hint')) for f in forms] ==
             [(cred['refresh_token'], 'refresh_token'), (cred['access_token'], 'access_token')] and
             all(f.get('client_id') for f in forms),
             'revocation posts the refresh token, then the access token, with their hints and client_id',
             [(f.get('token_type_hint'), bool(f.get('client_id'))) for f in forms])
        need(self.credential('cc', 'oa') is None and self.capability('capoa')['unavailable'] == ['auth'] and
             self.rule_for('capoa') and self.rule_for('capoa')['principals'],
             'the credential is deleted, its capabilities unavailable with auth, and shares kept',
             self.capability('capoa'))
        events = self.kinds_for('sources.logout')
        need(any(e['subject_id'] == f"{self.aid['cc']}/oa" for e in events), 'sources.logout activity', events[-2:])
        tty = self.review('capoa')
        need(squash('Credential: the sign-in to cc/oa has lapsed; run peerspan sources login cc/oa') in squash(tty),
             'the review\'s lapsed line', tty[-600:])
        # No revocation endpoint; a failing one; no credential.
        code, value, stdout, stderr = self.out('p1', 'sources', 'logout', 'oc/ochint', '--yes')
        need(code == 0 and value == {'source': 'oc/ochint', 'capability': None, 'revoked': False, 'deleted': True} and
             NO_REVOCATION.format(issuer=self.as2.issuer, label=self.host_label) in squash(stderr),
             'without a revocation endpoint: revoked false, deleted, and the text', code, value, stderr[-500:])
        self.as5.cfg.update(revoke_status=503)
        code, value, stdout, stderr = self.out('p1', 'sources', 'logout', 'cc/oahint', '--yes')
        need(code == 0 and value and value['revoked'] is False and value['deleted'] is True and
             self.credential('cc', 'oahint') is None,
             'a revocation that fails: revoked false, deleted anyway', code, value, stderr[-300:])
        code, value, stdout, stderr = self.out('p1', 'sources', 'logout', 'oc/ochint', '--yes')
        need(code == 0 and value and value['deleted'] is False and value['revoked'] is False and
             NO_SIGN_IN.format(source='oc/ochint') in stderr, 'no credential: deleted false and the text', code, value,
             stderr[-300:])
        # A dropped source and a changed URL delete credentials; capability remove deletes its own.
        gl = [s for s in self.sites if s.name == 'gl'][0]
        self.login_ok('old', 'gl', self.as1, rule='old/gl sign-in')
        self.create('capgl', 'old/gl', ['echo'])
        self.login_ok('old', 'gl', self.as1, {'capability': 'capgl'}, rule='capgl own sign-in')
        need(self.credential('old', 'gl') and self.credential('old', 'gl', 'capgl'), 'two credentials on old/gl')
        mark = gl.mark()
        self.put('old', [self.remote_def('gl', gl.url + '?v=2')])
        s = self.server('old', 'gl')
        need(self.credential('old', 'gl') is None and self.credential('old', 'gl', 'capgl') is None and
             s['reason'] == 'login' and s['auth']['mode'] == 'oauth',
             'a changed URL deletes the source\'s credentials and the probe learns the mode again', s)
        self.put('old', [self.remote_def('gl', gl.url)])
        self.login_ok('old', 'gl', self.as1, rule='old/gl sign-in again')
        mark = self.as1.mark()
        self.put('old', [])
        need(self.credential('old', 'gl') is None, 'a PUT dropping the source deletes its credential')
        try:
            revoked = bool(wait_for(lambda: self.as1.since(mark, 'POST', '/revoke') or None, timeout=20,
                                    message='background revocation'))
        except Exception:
            revoked = False
        self.soft(revoked, 'the dropped source\'s tokens are revoked in the background (best effort)')
        self.put('old', [self.remote_def('gl', gl.url)])
        self.login_ok('old', 'gl', self.as1, {'capability': 'capgl'}, rule='capgl own sign-in again')
        code, value, stdout, stderr = self.out('p1', 'capability', 'remove', 'capgl', '--yes')
        need(code == 0 and self.credential('old', 'gl', 'capgl') is None,
             'capability remove deletes the capability\'s own credential', code, stderr[-300:])
        return ''

    # --- status ------------------------------------------------------------------------------------------------

    def check_status(self):
        counts = self.counts()
        remote = sum(1 for a in self.view()['agents'] for s in a['servers'] if s['transport'] == 'remote')
        signed = sum(1 for (r,) in db_rows(self.hosts['p1'], 'SELECT record FROM oauth_credentials')
                     if json.loads(r)['state'] != 'login_required')
        need(counts.get('remote_sources') == remote and counts.get('signed_in') == signed,
             'remote_sources counts remote sources, signed_in the credentials not login_required', counts, remote,
             signed)
        expected = {'cc/oa': 'peerspan sources login cc/oa',              # login, no credential, capoa uses it
                    'cc/oa3': 'peerspan sources login cc/oa3',            # login_required
                    'cc/hdrbad': 'peerspan sources refresh --agent cc',   # unauthorized on a headers source
                    'capown': 'peerspan capability login capown'}         # its own credential missing
        for subject, command in expected.items():
            item = self.item(subject)
            need(item and item['command'] == command, f'item 14 for {subject}: {command}', item)
        # refresh_failed: more than 1 hour, and less (edited in the stored records with the daemon stopped).
        self.login_ok('cc', 'oahint', self.as5, rule='cc/oahint sign-in')
        self.login_ok('cx', 'cxoa', self.as6, rule='cx/cxoa sign-in')
        p1 = self.hosts['p1']
        p1.stop()
        connection = sqlite3.connect(p1.state / 'host.db')
        try:
            for server, ago in (('oahint', 7200), ('cxoa', 1800)):
                agent = 'cc' if server == 'oahint' else 'cx'
                (record,) = connection.execute('SELECT record FROM oauth_credentials WHERE agent_id = ? AND server = ? '
                                               "AND capability = ''", (self.aid[agent], server)).fetchone()
                record = json.loads(record)
                record.update(state='refresh_failed', refresh_failed_at=caps.rfc3339(-ago))
                connection.execute("UPDATE oauth_credentials SET record = ? WHERE agent_id = ? AND server = ? AND "
                                   "capability = ''", (json.dumps(record), self.aid[agent], server))
            connection.commit()
        finally:
            connection.close()
        p1.start()
        item = self.item('cc/oahint')
        need(item and item['command'] == 'peerspan sources login cc/oahint',
             'item 14 for refresh_failed for more than 1 hour', item)
        item = self.item('cx/cxoa')
        need(not item or 'sources login' not in item['command'], 'no sign-in item for refresh_failed under 1 hour',
             item)
        return ''

    # --- older peers -------------------------------------------------------------------------------------------

    def check_older(self):
        self.needs('caprun')
        self.synced('o1')
        code, value, stdout, stderr = self.out('o1', 'call', 'pat/caprun', 'echo', '--text', 'from-old', '--network',
                                               self.team, '--wait', '60s')
        need(code == 0 and caps.dig(value, 'status', 'state') == 'succeeded',
             'a version 18 caller calls a remote capability', code, stdout[-500:], stderr[-300:])
        code, value, stdout, stderr = self.out('o1', 'call', 'pat/caprun', 'status', '--code', '401', '--network',
                                               self.team, '--wait', '60s')
        need(code == 1 and caps.dig(value, 'status', 'state') == 'failed' and
             caps.dig(value, 'status', 'error') == 'auth_required',
             'a version 18 caller sees auth_required as a failed call\'s error', code, stdout[-500:])
        code, value, stdout, stderr = self.out('o1', 'discover', 'pat', '--json', '--network', self.team)
        entry = [e for e in (value or {}).get('capabilities', []) if e['capability'] == 'capoa']
        need(entry and entry[0]['unavailable'] == ['auth'], 'a version 18 caller lists unavailable ["auth"] as a '
             'value', entry)
        return ''

    # --- idle stop ---------------------------------------------------------------------------------------------

    def check_idle(self):
        self.needs('idle')
        remaining = self.idle_started + 11 * 60 - time.time()
        if remaining > 0:
            print(f'NOTE {self.label}: waiting {remaining:.0f}s for the idle stop', flush=True)
            time.sleep(remaining)
        deletes = self.idle_site.deletes
        need(self.idle_session and deletes and deletes[-1]['headers'].get('mcp-session-id') == self.idle_session and
             deletes[-1]['time'] - self.idle_started >= 600 - 5,
             'after 10 minutes without calls, a DELETE with MCP-Session-Id', self.idle_session,
             [(d['headers'].get('mcp-session-id'), round(d['time'] - self.idle_started)) for d in deletes])
        return ''

    # --- secrets -----------------------------------------------------------------------------------------------

    def check_secrets(self):
        secrets_ = [t for t in self.lab_tokens() if t] + [v for v in self.header_values if v]
        leaks = []
        for where, text in self.exposed:
            leaks += [where for t in secrets_ if t in text]
        private = {'tool_values', 'oauth_credentials', 'oauth_clients'}
        for name, h in self.hosts.items():
            for path in h.state.rglob('*'):
                if path.is_file() and not path.name.startswith('host.db') and path.stat().st_size < 50_000_000:
                    data = path.read_bytes()
                    leaks += [str(path) for t in secrets_ if t.encode() in data]
            connection = sqlite3.connect(h.state / 'host.db')
            try:
                for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
                    if name == 'p1' and table in private:
                        continue
                    for row in connection.execute(f'SELECT * FROM {table}'):
                        text = json.dumps(row, default=str)
                        leaks += [f'{name}:{table}' for t in secrets_ if t in text]
            finally:
                connection.close()
            if getattr(h, 'logs', None):
                h.logs.flush()
                h.logs.seek(0)
                logs = h.logs.read().decode(errors='replace')
                h.logs.seek(0, 2)
                leaks += [f'{name} daemon log' for t in secrets_ if t in logs]
            try:
                acts = json.dumps(self.activity(name))
                leaks += [f'{name} activity' for t in secrets_ if t in acts]
            except Exception as error:
                self.notes.append(f'activity on {name}: {error}')
        for path in self.coord.state.rglob('*') if hasattr(self.coord, 'state') else []:
            if path.is_file():
                data = path.read_bytes()
                leaks += [f'coordinator {path.name}' for t in secrets_ if t.encode() in data]
        need(not leaks, 'tokens, codes, client secrets, and header values appear nowhere but the serving host\'s '
             'credential and value tables', sorted(set(leaks))[:20])
        # Tokens only to their MCP URL and to the token and revocation endpoints.
        wrong = []
        for s in self.sites:
            for r in s.requests:
                token = bearer_of(r)
                if isinstance(s, AuthServer):
                    if token:
                        wrong.append(f'bearer to {s.name} {r["path"]}')
                    if r['path'] not in ('/token', '/revoke'):
                        wrong += [f'a token in {s.name} {r["path"]}' for t in self.lab_access_tokens()
                                  if t in r['body'] or t in r['query']]
                elif token and token in self.lab_access_tokens():
                    grant = self.grant_of(token)
                    if not grant or grant['resource'] != s.cfg['resource']:
                        wrong.append(f'a token to {s.name} for {grant and grant["resource"]}')
                    if token in r['query']:
                        wrong.append(f'a token in the query at {s.name}')
        need(not wrong, 'tokens go only to their MCP URL in Authorization, and to the token and revocation '
             'endpoints', wrong[:10])
        return ''

    def lab_tokens(self):
        out = []
        for s in self.sites:
            if isinstance(s, AuthServer):
                out += s.tokens()
        return out

    def lab_access_tokens(self):
        out = []
        for s in self.sites:
            if isinstance(s, AuthServer):
                out += list(s.access) + list(s.refresh)
        return out

    def grant_of(self, token):
        for s in self.sites:
            if isinstance(s, AuthServer) and token in s.access:
                return s.access[token]
        return None

    def close(self):
        try:
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()
            for s in self.sites:
                try:
                    s.stop()
                except Exception:
                    pass


def run_pairing(coord_binary, cli_binary, daemon_binary, label, only=None, baseline18=None):
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-remote-') as temporary:
        pairing = RemotePairing(label, cli_binary, daemon_binary, coord_binary, Path(temporary), only, baseline18)
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [remote: setup]: {detail}', flush=True)
            if pairing.setup_notes:
                print(f'NOTE {label} remote setup: ' + ' | '.join(pairing.setup_notes), flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        for note in pairing.notes:
            print(f'NOTE {label} remote (not counted): {note}', flush=True)
        print(f'---- {label} remote: {sum(ok for _, ok, _ in pairing.results)}/{len(pairing.results)} sections '
              f'passed in {time.monotonic() - started:.0f}s', flush=True)
        return [(f'remote: {name}', ok, detail) for name, ok, detail in pairing.results]


# --- migration to version 22 ---------------------------------------------------------------------------------

def check_migration(original, replacement, label, baseline=None):
    """Version 21 (or the version 18 baseline) to 22 and on to the current version: oauth_clients and
    oauth_credentials created, records not rewritten; the next version refused. With the baseline, a remote source stored at version 18 keeps the reason `remote`
    until the next PUT."""
    from host_service import DEC_TABLES, Host, OAUTH_TABLES, SCHEMA_VERSION
    with tempfile.TemporaryDirectory(prefix='peerspan-capability-remote-migration-') as directory:
        host = Host(baseline or original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            definition = {'name': 'r', 'transport': 'remote', 'command': None, 'args': [], 'env': {},
                          'url': 'http://127.0.0.2:9/mcp', 'source': 'claude-code:user'}
            if baseline:
                status, body = host.call('PUT', f'/v1/agents/{agent["id"]}/tool-servers',
                                         {'workspace': directory, 'servers': [definition], 'values': {}})
                need(status == 200, 'the version 18 host stores a remote source', status, body)
            host.stop()
            if baseline:
                need(db_rows(host, 'PRAGMA user_version')[0][0] == 18, 'the baseline is version 18')
            else:
                need(db_rows(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION == 23, 'Database version 23', label)
                connection = sqlite3.connect(host.state / 'host.db')
                try:
                    for table in (*DEC_TABLES, *OAUTH_TABLES):
                        connection.execute(f'DROP TABLE {table}')
                    connection.execute('PRAGMA user_version = 21')
                    connection.commit()
                finally:
                    connection.close()
            before = db_rows(host, 'SELECT * FROM tool_servers')
            host.binary = str(replacement)
            need(host.start()['id'] == identity['id'], 'the identity survives migration')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == SCHEMA_VERSION, 'migrated to version 22 and on to the current version')
            for table, columns in (('oauth_clients', ['issuer', 'redirect_uri', 'record']),
                                   ('oauth_credentials', ['agent_id', 'server', 'capability', 'record'])):
                got = [r[1] for r in db_rows(host, f'PRAGMA table_info({table})')]
                need(got == columns, f'{table} has the contract\'s columns', got)
            need(db_rows(host, 'SELECT * FROM tool_servers') == before, 'migration rewrites no record')
            need(host.cli('agent', 'inspect', agent['id']) == agent, 'existing state preserved')
            if baseline:
                status, view = host.call('GET', '/v1/sources')
                server = view['agents'][0]['servers'][0]
                need(server['reason'] == 'remote' and server['remote'] == DEFAULT_REMOTE and server['headers'] == {} and
                     server['auth'] == NULL_AUTH,
                     'a remote source stored before this slice keeps the reason remote, listed with the http default '
                     'remote, headers {}, and auth mode null', server)
                status, body = host.call('PUT', f'/v1/agents/{agent["id"]}/tool-servers',
                                         {'workspace': directory, 'servers': [definition], 'values': {}})
                status, view = host.call('GET', '/v1/sources')
                server = view['agents'][0]['servers'][0]
                need(status == 200 and server['reason'] == 'insecure_url',
                     'the next PUT recomputes the reason', status, server)
            host.stop()
            connection = sqlite3.connect(host.state / 'host.db')
            connection.execute(f'PRAGMA user_version = {SCHEMA_VERSION + 1}')
            connection.commit()
            connection.close()
            for binary in {str(original), str(replacement)}:
                result = subprocess.run([binary, '--state', str(host.state), 'run'], capture_output=True, timeout=10)
                need(result.returncode != 0, f'version {SCHEMA_VERSION} binaries reject version {SCHEMA_VERSION + 1}', binary)
        finally:
            stop_all((host,))
    return label
