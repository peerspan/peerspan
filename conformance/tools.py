#!/usr/bin/env python3
"""Exercise remote tools (milestone 10 slice 1: discovery and owner calls) across CLI/daemon pairings.

Written from docs/tools-contract.md (and the remote tools proposal, tool credentials, coordination, launch, and
task contracts it builds on), independently of both implementations. Runs every Go/Rust CLI and daemon pairing
(all hosts of a pairing run that pairing's daemon and are driven by its CLI), with one Go coordinator per pairing,
real ssh-agents, the peer probe for raw peer requests, and the fixture MCP stdio server in
fixtures/mcp/server.py. Harness configuration (Claude Code ~/.claude.json and .mcp.json, Codex config.toml,
OpenCode opencode.json) is generated under each host's temporary HOME and XDG_CONFIG_HOME; the integrations
`claude-code`, `codex`, and `opencode` are the explicit fixture integration (fixtures/harness), attached with
`--no-start`, so no harness or model runs.

Hosts: pat's p1 (shares tools; agents cc, cc2, cc3 for Claude Code, cx and cx2 for Codex, oc for OpenCode), p2
(joined --trusted), p3 (no terminal: untrusted), p4 (trusted at the join prompt); quinn's q1 and q2; rhea's r;
u1 and u2 (members bound to no person); n (a manually configured peer of p1 in no network).
Networks: team (everyone but n), other (p1, p2 untrusted, q1), and v1net (p1, for a v1 policy).

Each pairing reports these sections separately (contract Verification items in brackets):
- trust at create and join: --trusted/--untrusted, the terminal prompt, no terminal meaning no, `trusted`
  in the output, and trusted_hosts in the next policy [trust/untrust: the join prompt and flags];
- discovery: each harness's sources and precedence, remote/disabled/misnamed servers, ${VAR} and
  ${VAR:-DEFAULT} captured and missing ones reported, an unparsable source in `errors`, `tools`
  [Discovery];
- allow --tools: each SPEC form, one rule per local agent, refusal with no such server, --agent '*' with
  --yes and its warning, write tools without a profile, unshareable servers, reach confirmation (terminal,
  --yes, neither, not asked twice) with the resources clause only for tool.call resource.read, SERVER sharing
  read-only tools and all resources, named tools sharing no resources, no --resources flag, set semantics, and
  deny --tools removing rules whatever their actions or scope [allow --tools];
- policy v2: the v2 statement verified with ssh-keygen over this suite's encoding, the JSON shape, coordinator
  acceptance, the other implementation's view through the coordinator, sibling propagation by direct push with
  the coordinator stopped, and a v1 policy accepted and read with no tool rules [Policy v2];
- trust/untrust: network selection and HOST defaulting, refusal for another person's host, and per-network
  trust [trust/untrust];
- authorization: policy (tools and every resource), self from a trusted host, self refused from an untrusted
  host and another person's host, named tools sharing no resources, a grant_id citation refused with 400, the
  read-only rule under policy but not self, blocks except under self, budgets per (rule, caller): per person
  and per host for unbound senders, 413, and lapsed authorization before start [Authorization];
- no grants: grant create refusing tool.call and resource.read, a manually configured peer outside any network
  listing nothing, citing a grant refused with 400, and its `call` refused locally [Authorization, Routes];
- routes: GET /peer/v1/tools filtered by authorization (also ?network=), its shape, via with only self and
  policy in order, and empty for a peer outside any network; call status and cancel 404 for a non-submitter
  [Routes];
- calls (from p2 under self): the lifecycle for tools and resources, isError and JSON-RPC errors, result_too_large, duplicate and
  conflicting submission, a lost submit response recovered by retry with one execution, expiry before start,
  cancellation queued and running, the deadline while running, a daemon restart and a server exit while
  running, concurrency capped at 4, and activity [Calls];
- values: captured values and the environment file reaching the server only for variables the definition
  names (others never reach it), the file ignored when too open, a
  literal token, the server's environment by name, and secrets nowhere else [Discovery, Literal values];
- profiles: a profile instance with its own environment file and arguments, a share of a profile (tools and
  resources) not matching the bare server, and removal [Profiles];
- snapshots: pagination, snapshot_error keeping the previous snapshot (error, the 30-second bound, over
  1 MiB) [Snapshots];
- configuration changes: a dropped server refusing new calls while a running call finishes, and a new tool
  shared only when named or read-only under `readonly` [Discovery];
- owner CLI: tools, tools remote, call and read exit codes, calls listings, target resolution by person and
  host ID with ambiguous and not-found errors, and --network scoping and via order deciding the citation
  [Owner CLI];
- status: tools counts and attention item 14 for each cause [Status];
- tie-break: equal-version v2 policies signed on two siblings converge on the lower hash [Policy v2];
- idle stop: an instance stopped after 10 minutes without calls, not before [Calls].
Shapes and rules follow the contract's "Local API and clarifications" section. Once per run: the v1 policy
test vector and the adopted v2 vector reproduced with this suite's encoding and signing [Policy v2: the test
vector], and migration from version 15 to 16 in each direction
[Migration].

Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen), OpenSSL, and peerspan-peer-probe. A pairing takes about
20 minutes, half of it the idle-stop wait. Exits non-zero listing every failed section.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback

from datetime import datetime, timezone

from coordination import Coordinator, wait_for
from host_service import Host, stop_all
from launch_directory import DirectoryHost
from launch_onboarding import DEFAULT, Failure, need, parse_time
from peer_messaging import DropResponse, fixture_context, set_probe, timestamp, wire
from persons import Agent, coord_db, person_id, ssh_key, ssh_sign, ssh_verify
from policy import policy_lines as policy_lines_v1

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / 'fixtures' / 'mcp' / 'server.py'
HARNESS = HERE / 'fixtures' / 'harness'
PYTHON = str(Path(sys.executable).resolve())

STATUS_KEYS = {'call_id', 'sender_host_id', 'receiver_host_id', 'target_agent_id', 'server', 'profile', 'kind', 'name',
               'uri', 'state', 'cancel_requested', 'error', 'result_bytes', 'created_at', 'started_at', 'finished_at'}
OUTBOUND_KEYS = {'peer_host_id', 'target', 'network_id', 'request', 'submit_state', 'status', 'result',
                 'cancel_state', 'attempts', 'next_attempt_at', 'error', 'status_queries'}
ATTACH_SERVER_KEYS = {'name', 'transport', 'shareable', 'reason', 'missing_env', 'tools', 'read_only_tools',
                      'snapshot_error'}
ATTACH_ERROR_KEYS = {'source', 'path', 'server', 'error'}
# Local API and clarifications: GET /v1/tools.
TOOLS_AGENT_KEYS = {'agent', 'workspace', 'servers'}
SERVER_KEYS = {'name', 'transport', 'command', 'args', 'env', 'url', 'source', 'disabled', 'shareable', 'reason',
               'missing_env', 'tools', 'resources', 'snapshot_at', 'snapshot_error', 'start_failed_at',
               'auth_error_at', 'confirmed', 'profiles', 'shares'}
PROFILE_KEYS = {'name', 'env_file', 'args', 'created_at', 'tools', 'resources', 'snapshot_at', 'snapshot_error',
                'start_failed_at', 'auth_error_at', 'confirmed'}
REMOTE_ENTRY_KEYS = {'host_id', 'address', 'agent', 'agent_id', 'server', 'profile', 'tools', 'resources'}
POLICY_V2_ORDER = ['format', 'network_id', 'person_public_key', 'version', 'issued_at', 'valid_until', 'rules',
                   'tool_rules', 'trusted_hosts', 'signature']
SHARE_PROMPT = 'Share? [y/N]'
LISTING_KEYS = {'agent', 'agent_id', 'server', 'profile', 'tools', 'resources'}
LISTED_TOOL_KEYS = {'name', 'description', 'input_schema', 'read_only', 'via'}
LISTED_RESOURCE_KEYS = {'uri', 'name', 'description', 'mime_type', 'via'}
TOOL_RULE_KEYS = {'agent', 'server', 'principals', 'actions', 'scope', 'max_input_bytes', 'allow_disconnected',
                  'max_calls_per_hour'}
ALLOW_TOOLS_KEYS = {'policy', 'principal', 'rules'}
BOTH = ['tool.call', 'resource.read']
ALL_RESOURCES = {'fixture://docs/readme', 'fixture://docs/guide', 'file:///srv/docs/a.txt', 'file:///srv/private/b.txt'}
FINAL = {'succeeded', 'failed', 'rejected', 'expired', 'cancelled', 'uncertain'}
LAPSED = 'authorization lapsed before start'
JOIN_PROMPT = 'Let this machine use tools shared from your other machines? [y/N]'
# The fixture's tools (fixtures/mcp/server.py): readOnlyHint true, false, and absent.
RO_TOOLS = {'echo', 'info', 'env_names', 'env_matches', 'sleep', 'fail', 'tool_error', 'big', 'crash'}
WRITE_TOOLS = {'write_note', 'purge'}
TOOL_TABLES = ['tool_servers', 'tool_values', 'tool_profiles', 'tool_confirmations', 'received_calls',
               'outbound_calls']
# Python sets LC_CTYPE itself when started in the C locale (PEP 538), so the fixture may report it although the
# daemon did not pass it.
INTERPRETER_NAMES = {'LC_CTYPE'}
CANARY = 'PEERSPAN_TOOLS_CANARY'
DAY = 86400


def call_id():
    return 'call_' + secrets.token_hex(16)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def squash(text):
    return ' '.join(text.split())


def first_text(result):
    """The first text content of a CallToolResult, parsed as JSON when it is JSON."""
    text = result['content'][0]['text']
    try:
        return json.loads(text)
    except ValueError:
        return text


def find_key(value, key):
    """Every value of `key` anywhere in a JSON value."""
    found = []
    if isinstance(value, dict):
        for k, v in value.items():
            if k == key:
                found.append(v)
            found += find_key(v, key)
    elif isinstance(value, list):
        for v in value:
            found += find_key(v, key)
    return found


# --- policy statement, version 2 -----------------------------------------------------------------------------

def tool_rule_lines(t):
    bounds = f"{t['max_input_bytes']} {'true' if t['allow_disconnected'] else 'false'} {t['max_calls_per_hour']}"
    return ['tool_rule', t['agent'], t['server'], ' '.join(t['principals']), ' '.join(t['actions']), ' '.join(t['scope']),
            bounds, 'end']


def policy_lines_v2(p):
    """The signed lines of a v2 statement (tools contract, Policy statement, version 2)."""
    lines = policy_lines_v1(p)
    lines[0] = 'peerspan-policy-v2'
    for t in p.get('tool_rules') or []:
        lines += tool_rule_lines(t)
    lines.append(' '.join(['trusted', *sorted(p.get('trusted_hosts') or [])]))
    return lines


def statement_lines(p):
    return policy_lines_v2(p) if p.get('format') == 2 or 'tool_rules' in p or 'trusted_hosts' in p \
        else policy_lines_v1(p)


def policy_hash(p):
    return hashlib.sha256('\n'.join(statement_lines(p)).encode()).hexdigest()


def plain(rules):
    """v1 rules without an absent or zero max_artifact_bytes."""
    return [{k: v for k, v in r.items() if not (k == 'max_artifact_bytes' and not v)} for r in rules]


def policy_of(value):
    return {k: v for k, v in value.items() if k != 'expires_soon'}


def crafted_v2(current, version, key, directory, tool_rules=None, trusted=None):
    """The next v2 policy, signed here with OpenSSH, with chosen tool rules and trusted hosts."""
    now = time.time()
    issued = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60))
    until = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 7 * DAY))
    p = {'format': 2, 'network_id': current['network_id'], 'person_public_key': current['person_public_key'],
         'version': version, 'issued_at': issued, 'valid_until': until, 'rules': current.get('rules') or [],
         'tool_rules': current.get('tool_rules') or [] if tool_rules is None else tool_rules,
         'trusted_hosts': sorted(current.get('trusted_hosts') or [] if trusted is None else trusted)}
    p['signature'] = ssh_sign(policy_lines_v2(p), key, directory)
    return p


def crafted_v1(network_id, person_public_key, version, rules, key, directory):
    now = time.time()
    p = {'network_id': network_id, 'person_public_key': person_public_key, 'version': version,
         'issued_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 60)),
         'valid_until': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 7 * DAY)), 'rules': rules}
    p['signature'] = ssh_sign(policy_lines_v1(p), key, directory)
    return p


# --- hosts ----------------------------------------------------------------------------------------------------

class ToolsHost(DirectoryHost):
    """A daemon of one implementation driven by a CLI of either, with its own HOME and XDG_CONFIG_HOME. The CLI
    never inherits CODEX_HOME or FX_* from the suite; the daemon gets a canary variable that must never reach a
    server's environment."""

    def environment(self, sock=DEFAULT, env=None):
        e = super().environment(sock, None)
        for name in list(e):
            if name == 'CODEX_HOME' or name.startswith('FX_'):
                e.pop(name)
        e.update(env or {})
        return e

    def daemon_env(self):
        env = super().daemon_env()
        env.pop('CODEX_HOME', None)
        env[CANARY] = 'daemon-only'
        return env

    def run(self, *args, sock=DEFAULT, env=None, argv=None, cwd=None, timeout=90, piped=None):
        """As DirectoryHost.run, with stdin from /dev/null (or the text `piped`, through a pipe): no CLI call is at
        a terminal unless at_terminal."""
        command = argv or [self.cli_binary, '--state', str(self.state), *args]
        stdin = {'input': piped} if piped is not None else {'stdin': subprocess.DEVNULL}
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, **stdin,
                              env=self.environment(sock, env), cwd=cwd, preexec_fn=self.preexec())

    def outcome(self, *args, env=None, cwd=None, timeout=90, piped=None):
        """(exit code, parsed stdout or None, stdout, stderr)."""
        r = self.run(*args, env=env, cwd=cwd, timeout=timeout, piped=piped)
        try:
            value = json.loads(r.stdout) if r.stdout.strip() else None
        except ValueError:
            value = None
        return r.returncode, value, r.stdout, r.stderr

    def at_terminal(self, *args, answer='y', prompt=None, env=None, timeout=60):
        """Run the CLI with stdin and stderr on a pseudo-terminal that is its controlling terminal, and stdout
        on a pipe. Answers once the prompt (whitespace-insensitive) appears, or after 8 seconds without it.
        Returns (exit code, parsed stdout or None, terminal text, stdout, whether the prompt was seen)."""
        master, slave = os.openpty()

        def preexec():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        process = subprocess.Popen([self.cli_binary, '--state', str(self.state), *args], stdin=slave,
                                   stdout=subprocess.PIPE, stderr=slave, env=self.environment(DEFAULT, env),
                                   preexec_fn=preexec)
        os.close(slave)
        chunks = []
        reader = threading.Thread(target=lambda: chunks.append(process.stdout.read()), daemon=True)
        reader.start()
        seen, answered, prompt_seen = b'', False, False
        started = time.monotonic()
        try:
            while time.monotonic() - started < timeout:
                ready, _, _ = select.select([master], [], [], 0.2)
                if master in ready:
                    try:
                        data = os.read(master, 4096)
                    except OSError:
                        data = b''
                    seen += data
                    if not data and process.poll() is not None:
                        break
                elif process.poll() is not None:
                    break
                text = squash(seen.decode(errors='replace'))
                if not answered and prompt and squash(prompt) in text:
                    prompt_seen = True
                if not answered and (prompt_seen or time.monotonic() - started > 8):
                    os.write(master, (answer + '\n').encode())
                    answered = True
            process.wait(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
        reader.join(timeout=10)
        stdout = (chunks[0] if chunks else b'').decode(errors='replace')
        try:
            value = json.loads(stdout) if stdout.strip() else None
        except ValueError:
            value = None
        if prompt and not prompt_seen and squash(prompt) in squash(stdout):
            prompt_seen = True
        return process.returncode, value, seen.decode(errors='replace'), stdout, prompt_seen


class DropCallResponse(DropResponse):
    """Drops the receiver's packets once it has committed a new received call."""

    def __init__(self, receiver):
        self.baseline = received_count(receiver)
        super().__init__(receiver, None)

    def committed(self):
        return received_count(self.receiver) > self.baseline


def received_count(host):
    connection = sqlite3.connect(host.state / 'host.db')
    try:
        return connection.execute('SELECT COUNT(*) FROM received_calls').fetchone()[0]
    finally:
        connection.close()


def db_rows(host, statement, args=()):
    connection = sqlite3.connect(host.state / 'host.db')
    try:
        return connection.execute(statement, args).fetchall()
    finally:
        connection.close()


# --- the fixture -----------------------------------------------------------------------------------------------

class Fixture:
    """Logs and control files for fixture server definitions, one pair per definition key."""

    def __init__(self, root):
        self.root = root
        (root / 'logs').mkdir(parents=True)
        (root / 'control').mkdir()

    def log(self, key):
        return self.root / 'logs' / f'{key}.jsonl'

    def control(self, key):
        return self.root / 'control' / f'{key}.json'

    def set(self, key, **values):
        self.control(key).write_text(json.dumps(values))

    def args(self, key, *labels, page_size=None, generate=None):
        args = ['-I', str(FIXTURE), f'log={self.log(key)}', f'control={self.control(key)}']
        args += [f'label={label}' for label in labels]
        if page_size:
            args.append(f'page-size={page_size}')
        if generate:
            args.append(f'generate={generate}')
        return args

    def entries(self, key):
        path = self.log(key)
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def calls(self, key, marker=None, name=None):
        """Executions recorded by the fixture, optionally those whose arguments carry `marker` as text."""
        out = []
        for e in self.entries(key):
            if e['event'] != 'call':
                continue
            if name and e['name'] != name:
                continue
            if marker is not None and (e.get('arguments') or {}).get('text') != marker:
                continue
            out.append(e)
        return out

    def claude(self, key, *labels, env=None, args=None, **options):
        entry = {'command': PYTHON, 'args': args if args is not None else self.args(key, *labels, **options)}
        if env is not None:
            entry['env'] = env
        return entry


def toml_string(value):
    return json.dumps(value)


def toml_table(name, entry):
    lines = [f'[mcp_servers.{name}]']
    for key in ('command', 'url'):
        if key in entry:
            lines.append(f'{key} = {toml_string(entry[key])}')
    if 'args' in entry:
        lines.append('args = [' + ', '.join(toml_string(a) for a in entry['args']) + ']')
    if 'enabled' in entry:
        lines.append(f"enabled = {'true' if entry['enabled'] else 'false'}")
    if 'startup_timeout_ms' in entry:
        lines.append(f"startup_timeout_ms = {entry['startup_timeout_ms']}")
    if entry.get('env'):
        lines.append(f'[mcp_servers.{name}.env]')
        for k, v in entry['env'].items():
            lines.append(f'{k} = {toml_string(v)}')
    return '\n'.join(lines) + '\n'


# --- the pairing -----------------------------------------------------------------------------------------------

class Pairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, root):
        self.label, self.cli_binary, self.daemon, self.root = label, cli_binary, daemon_binary, root
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results = []
        self.hosts = {}
        self.agents = {}
        self.keys = {}
        self.ids = {}
        self.aid = {}
        self.notes = {}
        self.secrets = {}
        self.exposed = []   # (where, text) collected for the secret scan

    # --- infrastructure --------------------------------------------------------------------------------------

    def host(self, name):
        h = ToolsHost(self.daemon, self.cli_binary, self.root / name, self.root / f'user-{name}')
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

    def coordinator_flags(self):
        return ('--coordinator', self.coord.address, '--coordinator-key', self.coord_key)

    def policy(self, host='p1', net=None, person=None):
        status, body = self.hosts[host].call('GET', f'/v1/networks/{net or self.team}/policy?person={person or self.pat}')
        return policy_of(body) if status == 200 else None

    def version(self, host='p1', net=None):
        p = self.policy(host, net)
        return p['version'] if p else 0

    def synced(self, version, *names, net=None, timeout=40):
        net = net or self.team
        for name in names:
            h = self.hosts[name]

            def caught_up():
                h.run('network', 'sync', net)
                return self.version(name, net) >= version
            wait_for(caught_up, timeout=timeout, message=f'policy version {version} on {name}')

    def sync_all(self, net=None, names=None):
        version = self.version('p1', net)
        members = names or (self.team_members if (net or self.team) == self.team else self.other_members)
        self.synced(version, *[n for n in members if n != 'p1'], net=net)
        return version

    def tool_rules(self, net=None, host='p1'):
        p = self.policy(host, net)
        return (p or {}).get('tool_rules') or []

    def rules_for(self, principal_id, net=None, server=None):
        return [r for r in self.tool_rules(net) if principal_id in r['principals']
                and (server is None or r['server'] == server)]

    def allow(self, *args, net=None, host='p1', terminal=None, env=None, piped=None):
        """`allow` with tool forms. Returns (exit code, output, stderr); a success must sign version + 1."""
        h = self.hosts[host]
        before = self.version(host, net)
        argv = ['allow', *args, '--network', net or self.team]
        if terminal is not None:
            code, out, tty, stdout, seen = h.at_terminal(*argv, answer=terminal, env=env, prompt=SHARE_PROMPT)
            need(seen or code != 0, f'allow asks once: {SHARE_PROMPT}', tty[-400:])
            stderr = tty
        else:
            code, out, stdout, stderr = h.outcome(*argv, env=env, piped=piped)
        if code == 0:
            need(isinstance(out, dict) and set(out) == ALLOW_TOOLS_KEYS,
                 'allow --tools prints {policy, principal, rules}', args, out)
            need(self.version(host, net) == before + 1, 'allow --tools signs version + 1', args, before,
                 self.version(host, net))
            need(out['policy'].get('version') == before + 1, 'allow prints the signed policy', out['policy'])
        else:
            need(self.version(host, net) == before, 'a refused allow signs nothing', args)
        return code, out, stderr

    def allowed(self, *args, **kwargs):
        code, out, stderr = self.allow(*args, **kwargs)
        need(code == 0, f'allow {" ".join(args)}', code, stderr[-600:])
        return out

    def deny(self, *args, net=None, host='p1'):
        before = self.version(host, net)
        out = self.hosts[host].cli('deny', *args, '--network', net or self.team)
        need(isinstance(out, dict) and 'removed' in out and 'policy' in out, 'deny --tools prints {policy, removed}',
             args, out)
        if out['removed'] == 0:
            need('note' in out and self.version(host, net) == before,
                 'deny --tools removing nothing: removed 0 with a note, and no new version', out)
        else:
            need(self.version(host, net) == before + 1, 'deny --tools signs the next version', args)
        return out

    def clear(self, label='rhea'):
        """Remove a principal from every tool rule in team, so that a failed section leaves nothing behind."""
        principal = 'person:' + {'rhea': self.rhea, 'quinn': self.quinn}[label]
        for server in sorted({r['server'].split('@')[0] for r in self.rules_for(principal)}):
            self.hosts['p1'].run('deny', label, '--tools', server, '--network', self.team)

    def listing(self, receiver, caller, network=None):
        path = '/peer/v1/tools' + (f'?network={network}' if network else '')
        return wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'GET', path)

    def entry(self, listing, agent, server, profile=None):
        for e in listing:
            if e.get('agent') == agent and e.get('server') == server and e.get('profile') == profile:
                return e
        return None

    def listed_tools(self, receiver, caller, agent, server, profile=None, network=None):
        status, body = self.listing(receiver, caller, network)
        need(status == 200, 'GET /peer/v1/tools answers 200', receiver, caller, status, body)
        e = self.entry(body, agent, server, profile)
        return {t['name']: t for t in e['tools']} if e else {}

    def body(self, agent, server, name=None, arguments=None, uri=None, profile=None, deadline=None, cid=None,
             cite=None):
        b = {'call_id': cid or call_id(), 'target_agent_id': self.aid[agent], 'server': server, 'profile': profile,
             'kind': 'resource' if uri else 'tool', 'deadline': deadline or timestamp(300)}
        if uri:
            b['uri'] = uri
        else:
            b['name'] = name
            b['arguments'] = arguments if arguments is not None else {}
        b.update(cite or {})
        return b

    def submit(self, caller, body, receiver='p1'):
        return wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'POST', '/peer/v1/calls', body)

    def status_of(self, caller, cid, receiver='p1'):
        return wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'GET', f'/peer/v1/calls/{cid}')

    def final(self, caller, cid, receiver='p1', timeout=60):
        def done():
            status, record = self.status_of(caller, cid, receiver)
            return record if status == 200 and record.get('state') in FINAL else None
        return wait_for(done, timeout=timeout, message=f'call {cid} final')

    def state_is(self, caller, cid, state, receiver='p1', timeout=30):
        def reached():
            status, record = self.status_of(caller, cid, receiver)
            return record if status == 200 and record.get('state') == state else None
        return wait_for(reached, timeout=timeout, message=f'call {cid} {state}')

    def policy_cite(self, net=None):
        return {'policy': {'person_id': self.pat, 'version': self.version('p1', net)}}

    def self_cite(self):
        return {'self': {'person_id': self.pat}}

    def call(self, caller, target, tool, arguments=None, *extra, wait='30s', timeout=120):
        argv = ['call', target, tool]
        if arguments is not None:
            argv += ['--arguments', json.dumps(arguments)]
        argv += ['--wait', wait, *extra]
        code, out, stdout, stderr = self.hosts[caller].outcome(*argv, timeout=timeout)
        self.exposed.append((f'{caller} call stdout', stdout))
        self.exposed.append((f'{caller} call stderr', stderr))
        return code, out, stderr

    def read(self, caller, target, uri, *extra, wait='30s'):
        code, out, stdout, stderr = self.hosts[caller].outcome('read', target, uri, '--wait', wait, *extra,
                                                                timeout=120)
        return code, out, stderr

    def inspect(self, caller, peer, cid):
        return self.hosts[caller].cli('calls', 'inspect', '--peer', peer, cid)

    def settle(self, caller, record, timeout=90):
        peer, cid = record['peer_host_id'], record['request']['call_id']

        def done():
            r = self.inspect(caller, peer, cid)
            return r if r.get('status') and r['status'].get('state') in FINAL else None
        return wait_for(done, timeout=timeout, message=f'outbound call {cid} final')

    def outbound_count(self, caller):
        return db_rows(self.hosts[caller], 'SELECT COUNT(*) FROM outbound_calls')[0][0]

    def tools_view(self, host='p1', agent=None):
        args = ['tools', '--json'] + (['--agent', agent] if agent else [])
        code, out, stdout, stderr = self.hosts[host].outcome(*args)
        need(code == 0 and out is not None, 'tools --json', args, code, stderr[-400:])
        self.exposed.append((f'{host} tools --json', stdout))
        return out

    def servers(self, agent, host='p1'):
        """The SERVER entries of one agent in GET /v1/tools (`tools --json`), by server name."""
        view = self.tools_view(host)
        need(isinstance(view, dict) and set(view) == {'agents'} and isinstance(view['agents'], list),
             'GET /v1/tools is {agents: [AGENT]}', str(view)[:400])
        names = [a['agent']['name'] for a in view['agents']]
        need(names == sorted(names), 'agents sorted by agent name', names)
        for a in view['agents']:
            need(set(a) == TOOLS_AGENT_KEYS and set(a['agent']) == {'id', 'name'},
                 'AGENT is {agent: {id, name}, workspace, servers}', a.get('agent'), sorted(a))
            if agent in (a['agent']['name'], a['agent']['id']):
                for server in a['servers']:
                    need(set(server) == SERVER_KEYS, 'SERVER has exactly the contract\'s fields', server.get('name'),
                         sorted(set(server) ^ SERVER_KEYS))
                    for profile in server['profiles']:
                        need(set(profile) == PROFILE_KEYS, 'PROFILE has exactly the contract\'s fields',
                             sorted(set(profile) ^ PROFILE_KEYS))
                return {server['name']: server for server in a['servers']}
        raise Failure(f'GET /v1/tools: agent {agent} listed: {json.dumps(view)[:800]}')

    @staticmethod
    def snapshot_tools(server):
        return {t['name']: t for t in server['tools']}

    @staticmethod
    def snapshot_resources(server):
        return {r['uri']: r for r in server['resources']}

    def refresh(self, agent='cc', timeout=150):
        code, out, stdout, stderr = self.hosts['p1'].outcome('tools', 'refresh', '--agent', agent,
                                                              env=self.cli_env, timeout=timeout)
        self.exposed.append(('tools refresh stdout', stdout))
        self.exposed.append(('tools refresh stderr', stderr))
        need(code == 0, f'tools refresh --agent {agent}', code, stderr[-500:])
        return out

    def attention(self, host='p1'):
        status, value = self.hosts[host].call('GET', '/v1/status')
        need(status == 200, 'GET /v1/status', status)
        return value

    def items(self, host='p1', kind='tool_server_failing'):
        return [i for i in self.attention(host).get('attention', []) if i.get('kind') == kind]

    def activity(self, host):
        return self.hosts[host].cli('activity', '--limit', '1000')

    def restart(self, name):
        h = self.hosts[name]
        h.stop()
        h.logs.seek(0)
        self.exposed.append((f'{name} daemon log before restart', h.logs.read().decode(errors='replace')))
        h.logs.close()
        h.logs = tempfile.TemporaryFile()
        return h.start()

    def fill_slots(self, seconds, count=4):
        """Occupy the fx instance's 4 slots with self calls from p2 (no hourly budget), returning their IDs once
        the fixture has started them all."""
        before = len(self.fixture.calls('fx-local', name='sleep'))
        ids = []
        for _ in range(count):
            b = self.body('cc', 'fx', 'sleep', {'seconds': seconds, 'text': 'slot'}, cite=self.self_cite())
            status, record = self.submit('p2', b)
            need(status == 200, 'setup: a self call from a trusted host fills a slot', status, record)
            ids.append(b['call_id'])
        wait_for(lambda: len(self.fixture.calls('fx-local', name='sleep')) >= before + count, timeout=30,
                 message='4 running calls')
        return ids

    # --- setup -------------------------------------------------------------------------------------------------

    def setup_catalog(self):
        """The explicit fixture integration under the IDs claude-code, codex, and opencode."""
        self.catalog = self.root / 'integrations'
        for identity in ('claude-code', 'codex', 'opencode'):
            bundle = self.catalog / identity
            bundle.mkdir(parents=True)
            shutil.copy2(HARNESS / 'provider.py', bundle / 'provider.py')
            shutil.copy2(HARNESS / 'harness.py', bundle / 'harness.py')
            (bundle / 'integration.json').write_text(json.dumps({
                'version': 1, 'id': identity, 'command': [PYTHON, './provider.py'],
                'operations': ['prepare', 'check', 'launch']}))

    def write_harness_configs(self):
        """Fixture harness configuration under p1's temporary HOME and XDG_CONFIG_HOME, and in the workspaces."""
        f, p1 = self.fixture, self.hosts['p1']
        home, xdg = p1.home, p1.config
        self.workspaces = {}
        for name in ('w1', 'w2', 'w3', 'w4', 'w5', 'w6'):
            w = (self.root / 'projects' / name)
            w.mkdir(parents=True)
            self.workspaces[name] = w.resolve()
        w1, w3, w5 = self.workspaces['w1'], self.workspaces['w3'], self.workspaces['w5']
        lit = self.secrets['literal']

        # Claude Code: user scope, then project (.mcp.json), then local (projects[WORKSPACE]) scope.
        self.user_servers = {
            'fx': f.claude('fx-user', 'user'),
            'Bad.Name': f.claude('bad-name'),
            'rem': {'type': 'http', 'url': 'https://example.invalid/mcp'},
            # Peerspan's own entries are never discovered.
            'peerspan': f.claude('own'),
            'peerspan_' + '0123456789abcdef' * 2: f.claude('own-profile'),
        }
        project_servers = {
            'fx': f.claude('fx-project', 'project'),
            'proj': f.claude('proj', 'x', env={'TOKEN_A': '${FX_TOKEN}', 'TOKEN_B': '${FX_UNSET:-fallback-b}'},
                             args=f.args('proj', '${FX_LABEL}', '${FX_UNSET_LABEL:-dflt}',
                                         '${FX_EMPTY:-wasempty}')),
        }
        self.local_servers = {
            'fx': f.claude('fx-local', 'local', env={'FX_CAPTURED': '${FX_TOKEN}'}),
            'lit': f.claude('lit', env={'LIT_TOKEN': lit}),
            'needy': f.claude('needy', env={'NEED': '${FX_MISSING_VAR}'}),
            'needyarg': f.claude('needyarg', args=f.args('needyarg', '${FX_MISSING_ARG}')),
            'gone': f.claude('gone'),
            'slow': f.claude('slow'),
            'paged': f.claude('paged', page_size=3, generate=10),
            'budget': f.claude('budget'),
            'budget2': f.claude('budget2'),
            'startfail': f.claude('startfail'),
            'startslow': f.claude('startslow'),
            'sserem': {'type': 'sse', 'url': 'https://example.invalid/sse'},
            'nocmd': {'args': ['no command']},  # reported in errors, not sent
        }
        self.claude_json = home / '.claude.json'
        self.write_claude_json()
        (w1 / '.mcp.json').write_text(json.dumps({'mcpServers': project_servers}, indent=2))
        (w5 / '.mcp.json').write_text('{"mcpServers": {"broken": ')  # does not parse

        # Codex: $CODEX_HOME/config.toml, default ~/.codex/config.toml.
        (home / '.codex').mkdir()
        (home / '.codex' / 'config.toml').write_text('\n'.join([
            'model = "fixture"\n',
            toml_table('cxs', {'command': PYTHON, 'args': f.args('cxs', 'codexhome'),
                               'env': {'CX_TOKEN': '${FX_TOKEN}'}, 'startup_timeout_ms': 20000}),
            toml_table('cxoff', {'command': PYTHON, 'args': f.args('cxoff'), 'enabled': False}),
            toml_table('cxrem', {'url': 'https://example.invalid/mcp'}),
            toml_table('cxoffrem', {'url': 'https://example.invalid/mcp', 'enabled': False}),
        ]))
        self.codex_alt = self.root / 'codex-alt'
        self.codex_alt.mkdir()
        (self.codex_alt / 'config.toml').write_text(toml_table('cxalt', {'command': PYTHON,
                                                                         'args': f.args('cxalt', 'alt')}))

        # OpenCode: $XDG_CONFIG_HOME/opencode/opencode.json, then WORKSPACE/opencode.json.
        (xdg / 'opencode').mkdir(parents=True)
        (xdg / 'opencode' / 'opencode.json').write_text(json.dumps({
            '$schema': 'https://opencode.ai/config.json',
            'mcp': {
                'ocs': {'type': 'local', 'command': [PYTHON, *f.args('ocs', 'opencode')],
                        'environment': {'OC_TOKEN': '${FX_TOKEN}'}, 'enabled': True},
                'ocover': {'type': 'local', 'command': [PYTHON, *f.args('ocover-global', 'global')]},
                'ocoff': {'type': 'local', 'command': [PYTHON, *f.args('ocoff')], 'enabled': False},
                'ocrem': {'type': 'remote', 'url': 'https://example.invalid/mcp'},
                'ocenv': {'type': 'local', 'command': [PYTHON, *f.args('ocenv')], 'env': {'OC_FALLBACK': '${FX_TOKEN}'}},
            }}, indent=2))
        (w3 / 'opencode.json').write_text(json.dumps({
            'mcp': {'ocover': {'type': 'local', 'command': [PYTHON, *f.args('ocover-project', 'project')]}}},
            indent=2))

    def write_claude_json(self):
        w1 = self.workspaces['w1']
        self.claude_json.write_text(json.dumps({
            'numStartups': 3,
            'mcpServers': self.user_servers,
            'projects': {str(w1): {'allowedTools': [], 'mcpServers': self.local_servers}},
        }, indent=2))

    def attach(self, harness, name, workspace, env=None):
        args = ['attach', harness, '--name', name, '--directory', str(workspace), '--integrations',
                str(self.catalog), '--no-start']
        code, out, stdout, stderr = self.hosts['p1'].outcome(*args, env={**self.cli_env, **(env or {})},
                                                              cwd=str(self.root), timeout=240)
        self.exposed += [(f'attach {name} stdout', stdout), (f'attach {name} stderr', stderr)]
        self.attached[name] = (code, out, stderr)
        return code, out, stderr

    def put_servers(self, host, agent, workspace, servers):
        """PUT /v1/agents/{id}/tool-servers with normalized stdio definitions, as the CLI sends them."""
        definitions = [{'name': name, 'transport': 'stdio', 'command': PYTHON, 'args': args, 'env': {}, 'url': None,
                        'source': 'claude-code:user'} for name, args in servers.items()]
        status, body = self.hosts[host].call('PUT', f'/v1/agents/{self.aid[agent]}/tool-servers',
                                             {'workspace': str(workspace), 'servers': definitions, 'values': {}})
        need(status == 200, 'PUT /v1/agents/{agent_id}/tool-servers', host, agent, status, body)
        need(isinstance(body, dict) and set(body) == TOOLS_AGENT_KEYS and body['agent']['id'] == self.aid[agent] and
             sorted(x['name'] for x in body['servers']) == sorted(servers),
             'the PUT response is the agent object, returned once snapshots finish', str(body)[:400])
        return body

    def invite(self, label, net=None):
        return self.hosts['p1'].cli('network', 'invite', '--network', net or self.team, '--member', label,
                                    '--expires-in', '1h')['token']

    def join(self, name, token, *flags, terminal=None):
        h = self.hosts[name]
        if terminal is not None:
            code, out, tty, stdout, seen = h.at_terminal('join', token, *flags, answer=terminal, prompt=JOIN_PROMPT)
            self.join_terminal[name] = (code, out, tty, seen)
            if code == 0:
                return out
            self.setup_notes.append(f'join at a terminal on {name} failed ({code}): {tty[-300:]}')
        else:
            code, out, stdout, stderr = h.outcome('join', token, *flags)
            if code == 0:
                return out
            self.setup_notes.append(f'join {" ".join(flags)} on {name} failed ({code}): {stderr[-300:]}')
        # Fall back to a plain join, so that later sections can run; the trust section reports the failure.
        return h.cli('join', token)

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        for name in ('pat', 'quinn', 'rhea'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.quinn, self.rhea = (person_id(self.keys[n][2]) for n in ('pat', 'quinn', 'rhea'))
        self.secrets = {'captured': 'captured-' + secrets.token_hex(12), 'literal': 'literal-' + secrets.token_hex(12),
                        'file': 'file-' + secrets.token_hex(12), 'profile': 'profile-' + secrets.token_hex(12)}
        self.cli_env = {'FX_TOKEN': self.secrets['captured'], 'FX_LABEL': 'fromenv', 'FX_EMPTY': ''}
        self.fixture = Fixture(root / 'fixture')
        self.setup_catalog()
        self.setup_notes, self.join_terminal, self.attached = [], {}, {}

        self.coord_key = self.coord.start()['public_key']
        persons = {'p1': 'pat', 'p2': 'pat', 'p3': 'pat', 'p4': 'pat', 'q1': 'quinn', 'q2': 'quinn', 'r': 'rhea',
                   'u1': None, 'u2': None, 'n': None}
        for name, person in persons.items():
            self.host(name).sock = self.agents[person].socket if person else None
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids, p1 = self.ids, self.hosts['p1']

        # Networks, with the trust flags and prompt (checked in the first section).
        self.create_outputs = {}
        code, out, stdout, stderr = p1.outcome('network', 'create', 'team', '--as', 'pat', '--untrusted',
                                               *self.coordinator_flags())
        if code != 0:
            self.setup_notes.append(f'network create --untrusted failed ({code}): {stderr[-300:]}')
            out = p1.cli('network', 'create', 'team', '--as', 'pat', *self.coordinator_flags())
        self.create_outputs['team'] = out
        self.team = out['id']
        self.join_outputs = {}
        self.join_outputs['p2'] = self.join('p2', self.invite('pat'), '--trusted')
        self.join_outputs['p3'] = self.join('p3', self.invite('pat'))
        self.join_outputs['p4'] = self.join('p4', self.invite('pat'), terminal='y')
        for name, label in (('q1', 'quinn'), ('q2', 'quinn'), ('r', 'rhea')):
            self.join_outputs[name] = self.join(name, self.invite(label))
        for name in ('u1', 'u2'):
            self.join_outputs[name] = self.hosts[name].cli('join', self.invite(name), '--no-person')
        self.team_members = ['p1', 'p2', 'p3', 'p4', 'q1', 'q2', 'r', 'u1', 'u2']

        code, out, stdout, stderr = p1.outcome('network', 'create', 'other', '--as', 'pat', '--trusted',
                                               *self.coordinator_flags())
        if code != 0:
            self.setup_notes.append(f'network create --trusted failed ({code}): {stderr[-300:]}')
            out = p1.cli('network', 'create', 'other', '--as', 'pat', *self.coordinator_flags())
        self.create_outputs['other'] = out
        self.other = out['id']
        self.join_outputs['p2-other'] = self.join('p2', self.invite('pat', self.other), '--untrusted')
        self.join_outputs['q1-other'] = self.join('q1', self.invite('quinn', self.other))
        self.other_members = ['p1', 'p2', 'q1']
        code, out, tty, stdout, seen = p1.at_terminal('network', 'create', 'v1net', '--as', 'pat',
                                                     *self.coordinator_flags(), answer='n', prompt=JOIN_PROMPT)
        self.create_terminal = (code, out, tty, seen)
        self.v1net = out['id'] if code == 0 and out else p1.cli('network', 'create', 'v1net2', '--as', 'pat',
                                                               *self.coordinator_flags())['id']

        expected = {ids[n]: {'pat': self.pat, 'quinn': self.quinn, 'rhea': self.rhea}.get(persons[n])
                    for n in self.team_members}

        def bound():
            for n in self.team_members:
                self.hosts[n].run('network', 'sync', self.team)
            seen = {m['host_id']: m['person_id'] for m in p1.cli('network', 'members', self.team)}
            return seen == expected
        wait_for(bound, timeout=60, message='every member of team bound as expected')
        for n in self.other_members:
            self.hosts[n].run('network', 'sync', self.other)

        # n: a manually configured peer of p1, in no network.
        for a, b in (('p1', 'n'), ('n', 'p1')):
            identity = self.hosts[b].call('GET', '/v1/host')[1]
            self.hosts[a].configure(self.hosts[b], identity)

        # Harness configuration and attach.
        self.write_harness_configs()
        w = self.workspaces
        self.attach('claude', 'cc', w['w1'])
        self.attach('claude', 'cc2', w['w4'])
        self.attach('claude', 'cc3', w['w5'])
        self.attach('codex', 'cx', w['w2'])
        self.attach('codex', 'cx2', w['w6'], env={'CODEX_HOME': str(self.codex_alt)})
        self.attach('opencode', 'oc', w['w3'])
        for name in ('p1', 'p2', 'p4'):
            for a in self.hosts[name].cli('agent', 'list'):
                self.aid.setdefault(a['name'], a['id'])
        for name, (code, out, stderr) in self.attached.items():
            if code != 0:
                self.setup_notes.append(f'attach {name} failed ({code}): {stderr[-300:]}')

        # The profile fx@acme on cc, with its own environment file and arguments.
        self.profile_env = self.root / 'acme.env'
        self.profile_env.write_text(f"# the acme profile\nFX_CAPTURED={self.secrets['profile']}\n"
                                    "PROFILE_ONLY=unnamed\n")
        self.profile_env.chmod(0o600)
        profile_args = [str(FIXTURE), f"log={self.fixture.log('fx-acme')}", f"control={self.fixture.control('fx-acme')}",
                        'label=acme']
        code, out, stdout, stderr = p1.outcome('tools', 'profile', 'add', 'fx', 'acme', '--env-file',
                                               str(self.profile_env), *[x for a in profile_args for x in ('--arg', a)],
                                               '--agent', 'cc', timeout=120)
        self.profile_added = (code, out, stderr)
        if code != 0:
            self.setup_notes.append(f'tools profile add failed ({code}): {stderr[-300:]}')

        # The idle-stop server: on p4, called once by p2 (self) right after setup, and checked at the end.
        self.hosts['p4'].cli('agent', 'register', '--name', 'idler', '--owner', 'pat')
        self.aid['idler'] = next(a['id'] for a in self.hosts['p4'].cli('agent', 'list') if a['name'] == 'idler')
        self.idle_started = None
        try:
            self.put_servers('p4', 'idler', self.root, {'idle': self.fixture.args('idle')})
            self.synced(self.version('p1'), 'p2', 'p4')
            b = {'call_id': call_id(), 'target_agent_id': self.aid['idler'], 'server': 'idle', 'profile': None,
                 'kind': 'tool', 'name': 'echo', 'arguments': {'text': 'idle'}, 'deadline': timestamp(300),
                 **self.self_cite()}
            status, _ = self.submit('p2', b, receiver='p4')
            if status == 200:
                self.final('p2', b['call_id'], receiver='p4')
                self.idle_started = time.time()
                threading.Thread(target=self.watch_idle, daemon=True).start()
        except Exception as error:
            self.setup_notes.append(f'idle server setup: {error}')

        self.section('trust at create and join', self.check_trust_at_join)
        discovered = self.section('discovery', self.check_discovery)
        allowed = self.section('allow --tools', self.check_allow)
        self.setup_shares()
        self.section('policy v2', self.check_policy_v2)
        self.section('trust/untrust', self.check_trust)
        self.section('authorization', self.check_authorization)
        self.section('no grants', self.check_no_grants)
        self.section('routes', self.check_routes)
        self.section('calls', self.check_calls)
        self.section('values', self.check_values)
        self.section('profiles', self.check_profiles)
        self.section('snapshots', self.check_snapshots)
        self.section('configuration changes', self.check_configuration_changes)
        self.section('owner CLI', self.check_owner_cli)
        self.section('status', self.check_status)
        self.section('tie-break', self.check_tie_break)
        self.section('idle stop', self.check_idle_stop)
        if self.setup_notes:
            print(f'NOTE {self.label} setup: ' + ' | '.join(self.setup_notes), flush=True)
        return discovered and allowed

    def setup_shares(self):
        """The shares later sections rely on, made with --yes (soft: failures surface in those sections)."""
        team, other = self.team, self.other
        steps = [
            (('quinn', '--tools', 'fx', '--agent', 'cc', '--yes'), team),
            (('quinn', '--tools', 'fx@acme:write_note', '--agent', 'cc', '--yes'), team),
            (('quinn', '--tools', 'budget', '--agent', 'cc', '--calls-per-hour', '3', '--yes'), team),
            (('network', '--tools', 'budget2', '--agent', 'cc', '--calls-per-hour', '2', '--yes'), team),
            (('quinn', '--tools', 'fx', '--agent', 'cc', '--yes'), other),
            (('quinn', '--tools', 'lit', '--agent', 'cc', '--yes'), other),
        ]
        for args, net in steps:
            try:
                code, out, stderr = self.allow(*args, net=net)
                if code != 0:
                    self.setup_notes.append(f'share {args} failed: {stderr[-200:]}')
            except Exception as error:
                self.setup_notes.append(f'share {args}: {error}')
        try:
            self.sync_all(team)
            self.sync_all(other)
        except Exception as error:
            self.setup_notes.append(f'share sync: {error}')

    # --- sections ------------------------------------------------------------------------------------------

    def check_trust_at_join(self):
        failures = list(n for n in self.setup_notes if 'join' in n or 'network create' in n)
        need(not failures, 'join and network create accept --trusted and --untrusted', *failures)
        team, other = self.create_outputs['team'], self.create_outputs['other']
        need(team.get('trusted') is False, 'network create --untrusted: output trusted false', team)
        need(other.get('trusted') is True, 'network create --trusted: output trusted true', other)
        need(self.join_outputs['p2'].get('trusted') is True, 'join --trusted: output trusted true',
             self.join_outputs['p2'])
        need(self.join_outputs['p3'].get('trusted') is False,
             'join with neither flag and no terminal: the answer is no (trusted false)', self.join_outputs['p3'])
        code, out, tty, seen = self.join_terminal['p4']
        need(seen, f'join at a terminal asks: {JOIN_PROMPT}', tty[-400:])
        need(out and out.get('trusted') is True, 'join at a terminal answered y: trusted true', out)
        need(self.join_outputs['p2-other'].get('trusted') is False, 'join --untrusted: trusted false',
             self.join_outputs['p2-other'])
        code, out, tty, seen = self.create_terminal
        need(code == 0 and seen, 'network create at a terminal asks the trust question', code, tty[-400:])
        need(out.get('trusted') is False, 'network create answered n: trusted false', out)
        ids = self.ids

        def trusted():
            self.hosts['p1'].run('network', 'sync', self.team)
            return (self.policy('p1') or {}).get('trusted_hosts') == sorted([ids['p2'], ids['p4']])
        try:
            wait_for(trusted, timeout=30, message='trusted_hosts of team')
        except AssertionError:
            pass
        p = self.policy('p1')
        need(p.get('format') == 2 and p['trusted_hosts'] == sorted([ids['p2'], ids['p4']]),
             'a yes adds the host to trusted_hosts in the next signed version (sorted); no adds nothing',
             p.get('trusted_hosts'), ids)
        o = self.policy('p1', self.other)
        need(o and o['trusted_hosts'] == [ids['p1']], 'network create --trusted adds the creator to trusted_hosts',
             o)
        need(self.policy('p1', self.v1net) is None or not self.policy('p1', self.v1net).get('trusted_hosts'),
             'network create answered n: no trusted host', self.policy('p1', self.v1net))
        q = self.join_outputs['q1']
        need(q.get('trusted') is False, 'another person without a terminal: trusted false', q)
        for name, out in [*self.join_outputs.items(), *self.create_outputs.items()]:
            if name in ('u1', 'u2'):
                continue
            need(isinstance(out.get('trusted'), bool) and 'trusted_error' not in out,
                 'join and network create always output trusted as a boolean, signing the change at once', name, out)

    def check_discovery(self):
        failures = [f'{name}: {code} {stderr[-300:]}' for name, (code, out, stderr) in self.attached.items()
                    if code != 0]
        need(not failures, 'attach --no-start succeeds for each harness', *failures)

        def attach_servers(name):
            out = self.attached[name][1]
            need(isinstance(out.get('tools'), dict) and set(out['tools']) == {'servers', 'errors'},
                 'attach adds tools: {servers, errors}', name, out)
            for x in out['tools']['servers']:
                need(set(x) == ATTACH_SERVER_KEYS, 'attach servers are {name, transport, shareable, reason, missing_env, '
                     'tools, read_only_tools, snapshot_error}', x)
                need(isinstance(x['tools'], int) and isinstance(x['read_only_tools'], int),
                     'tools and read_only_tools are counts', x)
            for e in out['tools']['errors']:
                need(set(e) == ATTACH_ERROR_KEYS, 'attach errors are {source, path, server, error}', e)
            return {x['name']: x for x in out['tools']['servers']}

        cc = attach_servers('cc')
        expected = {'fx', 'Bad.Name', 'rem', 'proj', 'lit', 'needy', 'needyarg', 'gone', 'slow', 'paged', 'budget',
                    'budget2', 'startfail', 'startslow', 'sserem'}
        need(set(cc) == expected, 'Claude Code: user, project, and local scopes; peerspan and peerspan_HEX skipped; '
             'a stdio entry without a command not sent', sorted(cc), sorted(expected))
        errors = self.attached['cc'][1]['tools']['errors']
        need([e['server'] for e in errors] == ['nocmd'], 'a stdio entry without a command is reported in errors',
             errors)
        for name, transport, shareable, reason in (('fx', 'stdio', True, None), ('Bad.Name', 'stdio', False, 'name'),
                                                   ('rem', 'remote', False, 'remote'),
                                                   ('sserem', 'remote', False, 'remote'),
                                                   ('needy', 'stdio', False, 'missing_env'),
                                                   ('proj', 'stdio', True, None), ('lit', 'stdio', True, None)):
            x = cc[name]
            need(x['transport'] == transport and x['shareable'] is shareable and x['reason'] == reason,
                 f'{name}: transport {transport}, shareable {shareable}, reason {reason}', x)
        need(cc['needy']['missing_env'] == ['FX_MISSING_VAR'] and cc['fx']['missing_env'] == [] and
             cc['needyarg']['reason'] == 'missing_env' and cc['needyarg']['missing_env'] == ['FX_MISSING_ARG'],
             'missing_env lists the referenced variables that could not be resolved, never env keys', cc['needy'])
        fx = cc['fx']
        need(fx['tools'] == len(RO_TOOLS | WRITE_TOOLS) + 1 and fx['read_only_tools'] == len(RO_TOOLS) + 1 and
             fx['snapshot_error'] is None, 'counts: read_only only for readOnlyHint true (purge has no annotations)', fx)

        servers = self.servers('cc')
        need(set(servers) == expected, 'GET /v1/tools lists the same servers', sorted(servers))
        need(servers['needy']['missing_env'] == ['FX_MISSING_VAR'], 'GET /v1/tools missing_env', servers['needy'])
        fxs = servers['fx']
        need(fxs['source'] == 'claude-code:local' and fxs['command'] == PYTHON and fxs['url'] is None and
             fxs['disabled'] is False and fxs['env'] == {'FX_CAPTURED': {'source': 'captured'}},
             'the normalized definition (source INTEGRATION:SCOPE)', {k: fxs[k] for k in ('source', 'env', 'url')})
        need(fxs['confirmed'] is False and fxs['shares'] == [] and fxs['snapshot_at'] and
             fxs['snapshot_error'] is None, 'before sharing: confirmed false, no shares', fxs['confirmed'],
             fxs['shares'])
        fx_tools = self.snapshot_tools(fxs)
        need('from_local' in fx_tools and 'from_user' not in fx_tools and 'from_project' not in fx_tools,
             'Precedence: the local scope definition is taken whole', sorted(fx_tools))
        need(set(fx_tools) == RO_TOOLS | WRITE_TOOLS | {'from_local'}, 'the snapshot lists every tool', sorted(fx_tools))
        for name, t in fx_tools.items():
            need(set(t) == {'name', 'description', 'input_schema', 'read_only'},
                 'stored tool entries are {name, description, input_schema, read_only}', t)
            need(t['read_only'] is (name in RO_TOOLS or name == 'from_local'),
                 'read_only is true only when annotations.readOnlyHint is true', name, t)
        resources = self.snapshot_resources(fxs)
        need(set(resources) == ALL_RESOURCES, 'the snapshot lists resources', sorted(resources))
        for r in resources.values():
            need(set(r) == {'uri', 'name', 'description', 'mime_type'},
                 'stored resource entries are {uri, name, description, mime_type}', r)
        proj = servers['proj']
        need({'from_fromenv', 'from_dflt', 'from_wasempty'} <= set(self.snapshot_tools(proj)),
             'References: ${NAME}, and ${NAME:-D} using D when NAME is unset or empty', sorted(self.snapshot_tools(proj)))
        need(proj['env'] == {'TOKEN_A': {'source': 'captured'}, 'TOKEN_B': {'source': 'captured'}} and
             proj['source'] == 'claude-code:project', 'env entries with references are captured', proj['env'])
        need(servers['lit']['env'] == {'LIT_TOKEN': {'source': 'literal'}}, 'literal env entries', servers['lit']['env'])
        need(servers['needy']['env'] == {'NEED': {'source': 'missing', 'variables': ['FX_MISSING_VAR']}},
             'unresolved references are {source: missing, variables: [NAME]}', servers['needy']['env'])
        need(servers['needyarg']['missing_env'] == ['FX_MISSING_ARG'],
             'missing_env names unresolved references in args too', servers['needyarg'])
        need(servers['rem']['tools'] == [] and servers['rem']['resources'] == [] and servers['rem']['url'],
             'tools and resources are [] without a snapshot', servers['rem'])

        cc2 = attach_servers('cc2')
        need(set(cc2) == {'fx', 'Bad.Name', 'rem'}, 'Claude Code: only the user scope for another workspace', sorted(cc2))
        need('from_user' in self.snapshot_tools(self.servers('cc2')['fx']) and
             self.servers('cc2')['fx']['source'] == 'claude-code:user', 'the user scope definition')
        out = self.attached['cc3'][1]
        need(any(e['path'] and e['path'].endswith('.mcp.json') for e in out['tools']['errors']),
             'Unreadable sources: a source that does not parse is reported in errors with its path', out['tools'])
        need('fx' in attach_servers('cc3'), 'discovery continues with the rest after an unparsable source',
             out['tools'])

        cx = attach_servers('cx')
        need(set(cx) == {'cxs', 'cxoff', 'cxrem', 'cxoffrem'}, 'Codex: [mcp_servers.NAME] in ~/.codex/config.toml',
             sorted(cx))
        need(cx['cxs']['shareable'] is True and cx['cxs']['reason'] is None, 'Codex stdio server shareable '
             '(startup_timeout_ms ignored)', cx['cxs'])
        need(cx['cxoff']['shareable'] is False and cx['cxoff']['reason'] == 'disabled', 'Codex enabled = false: '
             'disabled', cx['cxoff'])
        need(cx['cxrem']['transport'] == 'remote' and cx['cxrem']['reason'] == 'remote', 'Codex url: remote',
             cx['cxrem'])
        need(cx['cxoffrem']['reason'] == 'remote', 'reason precedence: remote before disabled', cx['cxoffrem'])
        cx_servers = self.servers('cx')
        need(cx_servers['cxoff']['disabled'] is True and cx_servers['cxs']['source'] == 'codex:user',
             'disabled and source codex:user', cx_servers['cxoff'])
        need('from_codexhome' in self.snapshot_tools(cx_servers['cxs']), 'Codex command and args', cx_servers['cxs'])
        cx2 = attach_servers('cx2')
        need(set(cx2) == {'cxalt'}, 'Codex: $CODEX_HOME/config.toml replaces the default', sorted(cx2))

        oc = attach_servers('oc')
        need(set(oc) == {'ocs', 'ocover', 'ocoff', 'ocrem', 'ocenv'},
             'OpenCode: mcp in the global and project opencode.json', sorted(oc))
        need(oc['ocoff']['reason'] == 'disabled' and oc['ocrem']['reason'] == 'remote', 'OpenCode enabled false and '
             'type remote', oc)
        oc_servers = self.servers('oc')
        need('from_project' in self.snapshot_tools(oc_servers['ocover']) and
             'from_global' not in self.snapshot_tools(oc_servers['ocover']),
             'OpenCode: the project file takes precedence', oc_servers['ocover'])
        need(oc_servers['ocover']['source'] == 'opencode:project' and oc_servers['ocs']['source'] == 'opencode:global',
             'sources opencode:project and opencode:global', oc_servers['ocover']['source'])
        need('from_opencode' in self.snapshot_tools(oc_servers['ocs']),
             'OpenCode: the first element of command, and the rest as args', oc_servers['ocs'])
        need(oc_servers['ocs']['env'] == {'OC_TOKEN': {'source': 'captured'}} and
             oc_servers['ocenv']['env'] == {'OC_FALLBACK': {'source': 'captured'}},
             'OpenCode reads environment, falling back to env', oc_servers['ocs']['env'], oc_servers['ocenv']['env'])

        # PUT validation (refusals change nothing).
        good = {'name': 'idle', 'transport': 'stdio', 'command': PYTHON, 'args': self.fixture.args('idle'), 'env': {},
                'url': None, 'source': 'claude-code:user'}
        path = f"/v1/agents/{self.aid['idler']}/tool-servers"
        missing = {'X': {'source': 'missing', 'variables': ['FX_X']}}
        for bad in ({'servers': [{**good, 'extra': 1}]},
                    {'servers': [{**good, 'env': missing}], 'values': {'idle': {'env.X': 'v'}}},
                    # env entries are exactly {source} for literal or captured, or {source: missing, variables}
                    # with non-empty variables.
                    {'servers': [{**good, 'env': {'X': {'source': 'missing'}}}]},
                    {'servers': [{**good, 'env': {'X': {'source': 'missing', 'variables': []}}}]},
                    {'servers': [{**good, 'env': {'X': {'source': 'literal', 'variables': ['FX_X']}}}],
                     'values': {'idle': {'env.X': 'v'}}},
                    {'servers': [{**good, 'env': {'X': {'source': 'captured', 'value': 'v'}}}],
                     'values': {'idle': {'env.X': 'v'}}},
                    {'servers': [{**good, 'env': {'X': {'source': 'other'}}}]},
                    {'servers': [{**good, 'env': {'X': 'literal'}}]}):
            status, body = self.hosts['p4'].call('PUT', path, {'workspace': str(self.root), **bad})
            need(status == 400, 'PUT refuses unknown definition fields, env values for missing entries, and env '
                 'entries of any other shape', bad, status, body)

        events = [e for e in self.activity('p1') if e['kind'] == 'tools.discovered']
        need({self.aid[a] for a in ('cc', 'cx', 'oc')} <= {e['subject_id'] for e in events},
             'tools.discovered activity with the agent ID', events[:5])
        code, out, stdout, stderr = self.hosts['p1'].outcome('tools')
        need(code == 0 and 'fx' in stdout, 'tools prints a readable listing', code, stdout[:300])
        need(self.secrets['captured'] not in stdout, 'tools never prints values')
        out = self.tools_view('p1', 'cc')
        need([a['agent']['name'] for a in out['agents']] == ['cc'], 'tools --agent NAME limits to one agent', out)

    def check_allow(self):
        rhea = 'person:' + self.rhea
        policy_before = self.version()

        # Reach confirmation: refused with neither a terminal nor --yes.
        code, out, stderr = self.allow('rhea', '--tools', 'fx', '--agent', 'cc')
        need(code == 1, 'Without a terminal and without --yes, allow refuses with exit 1', code, stderr[-300:])
        code, out, stderr = self.allow('rhea', '--tools', 'fx', '--agent', 'cc', piped='y\n')
        need(code == 1, '"At a terminal" means stdin is a terminal: a piped y does not confirm', code, stderr[-300:])
        need(self.servers('cc')['fx']['confirmed'] is False, 'nothing confirmed yet')
        code, out, tty = self.allow('rhea', '--tools', 'fx', '--agent', 'cc', terminal='n')
        need(code == 1, 'declining exits 1 with nothing signed', code, tty[-300:])
        # At a terminal: the statements on stderr, then one question; y agrees.
        code, out, tty = self.allow('rhea', '--tools', 'fx', '--agent', 'cc', terminal='yes')
        text = squash(tty)
        need('can call these tools of fx on cc with the credentials it runs with there:' in text and
             'Anything those credentials can reach through these tools,' in text and
             'can also read every resource it offers.' in text and ', and read its resources,' not in text,
             'the reach statement, followed by the resources sentence when the actions include resource.read',
             tty[-600:])
        need(code == 0, 'confirmation is y or yes at a terminal', code, tty[-300:])
        need(self.servers('cc')['fx']['confirmed'] is True, 'the confirmation appears as confirmed in GET /v1/tools')
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx', 'actions': BOTH, 'scope': ['readonly']}],
             'SPEC SERVER: scope readonly, actions tool.call resource.read; output rules [{agent, server, actions, '
             'scope}]', out)
        need(out['principal'] in ('rhea', rhea, self.rhea), 'output principal', out)
        rule = [r for r in self.rules_for(rhea) if r['agent'] == 'cc']
        need(len(rule) == 1 and set(rule[0]) == TOOL_RULE_KEYS, 'a tool rule {agent, server, principals, actions, '
             'scope, max_input_bytes, allow_disconnected, max_calls_per_hour}', rule)
        need((rule[0]['max_input_bytes'], rule[0]['allow_disconnected'], rule[0]['max_calls_per_hour']) ==
             (65536, False, 100), 'Settings: max_input_bytes 65,536, allow_disconnected false, max_calls_per_hour 100',
             rule)
        # Named tools at a terminal, first time for (cc2, fx): no resources clause.
        code, out, tty = self.allow('rhea', '--tools', 'fx:echo', '--agent', 'cc2', terminal='y')
        text = squash(tty)
        need(code == 0 and 'can call these tools of fx on cc2 with the credentials it runs with there:' in text and
             'can also read every resource' not in text,
             'The resources clause appears only when the actions include resource.read', code, tty[-600:])
        need(out['rules'] == [{'agent': 'cc2', 'server': 'fx', 'actions': ['tool.call'], 'scope': ['echo']}],
             'SPEC SERVER:TOOL: those tools, action tool.call only', out)

        # Not asked twice for (cc, fx, no profile); set semantics move rhea to the named-tool rule.
        code, out, stderr = self.allow('rhea', '--tools', 'fx:echo,info', '--agent', 'cc')
        need(code == 0, 'Confirmations are stored per (agent, server, profile) and not asked again', code,
             stderr[-300:])
        mine = [r for r in self.rules_for(rhea) if r['agent'] == 'cc' and r['server'] == 'fx']
        need(len(mine) == 1 and sorted(mine[0]['scope']) == ['echo', 'info'] and mine[0]['actions'] == ['tool.call'],
             'Set semantics: removed from every tool rule for that server, whatever its actions; empty rules dropped',
             mine)

        # Without --agent: one rule per local agent with the server, named explicitly.
        agents_with_fx = {a for a in ('cc', 'cc2', 'cc3') if self.servers(a).get('fx', {}).get('shareable')}
        code, out, stderr = self.allow('rhea', '--tools', 'fx', '--yes')
        need(code == 0, 'allow --tools SERVER without --agent', code, stderr[-300:])
        need({r['agent'] for r in out['rules']} == agents_with_fx and
             all(r['server'] == 'fx' and r['scope'] == ['readonly'] and r['actions'] == BOTH for r in out['rules']),
             'one rule for each agent on this host whose snapshot has the server as shareable', out['rules'],
             agents_with_fx)
        need(not any(r['agent'] == '*' for r in self.tool_rules()), 'tool shares never default to *',
             self.tool_rules())
        code, out, stderr = self.allow('rhea', '--tools', 'nosuch', '--yes')
        need(code != 0, 'allow refuses when no local agent has the server', code)

        # --agent '*': --yes required even after confirmations, with a warning.
        code, out, stderr = self.allow('rhea', '--tools', 'fx', '--agent', '*')
        need(code != 0, "--agent '*' requires --yes even after earlier confirmations", code)
        code, out, stderr = self.allow('rhea', '--tools', 'fx', '--agent', '*', '--yes')
        need(code == 0 and out['rules'] == [{'agent': '*', 'server': 'fx', 'actions': BOTH, 'scope': ['readonly']}],
             "--agent '*' makes one * rule", code, out)
        code, out, tty = self.allow('rhea', '--tools', 'fx', '--agent', '*', terminal='y')
        need(code != 0, "--agent '*' always needs --yes, even at a terminal", code, tty[-300:])
        need(stderr.strip(), "--agent '*' warns that the rule covers servers on every machine", stderr)

        # Write tools without a profile, and unshareable servers.
        for spec, tool in (('fx:write_note', 'write_note'), ('fx:echo,purge', 'purge')):
            code, out, stderr = self.allow('rhea', '--tools', spec, '--agent', 'cc', '--yes')
            need(code != 0 and tool in stderr and 'tools profile add' in stderr,
                 'No write tools without a profile: the error names the tools and says to add a profile', spec,
                 code, stderr[-400:])
        code, out, stderr = self.allow('rhea', '--tools', 'fx:*', '--agent', 'cc', '--yes')
        need(code != 0, '* is valid only with a profile', code)
        for spec, agent, reason in (('rem', 'cc', 'remote'), ('needy', 'cc', 'missing_env'),
                                    ('cxoff', 'cx', 'disabled'), ('Bad.Name', 'cc', None)):
            code, out, stderr = self.allow('rhea', '--tools', spec, '--agent', agent, '--yes')
            need(code != 0 and (reason is None or reason in stderr),
                 'a remote, disabled, misnamed, or missing_env server is refused with its reason', spec, code,
                 stderr[-300:])
        code, out, stderr = self.allow('rhea', '--resources', 'fx', '--agent', 'cc', '--yes')
        need(code != 0, 'there is no --resources flag', code)

        # Profile forms.
        need(self.profile_added[0] == 0, 'setup: tools profile add', self.profile_added)
        out = self.allowed('rhea', '--tools', 'fx@acme', '--agent', 'cc', '--yes')
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx@acme', 'actions': BOTH, 'scope': ['readonly']}],
             'SPEC SERVER@PROFILE: readonly tools and every resource', out)
        out = self.allowed('rhea', '--tools', 'fx@acme:*', '--agent', 'cc', '--yes')
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx@acme', 'actions': BOTH, 'scope': ['*']}],
             'SPEC SERVER@PROFILE:*: every tool and resource of the profile', out)
        need(len(self.rules_for(rhea, server='fx@acme')) == 1, 'set semantics within the profile',
             self.rules_for(rhea, server='fx@acme'))
        out = self.allowed('rhea', '--tools', 'fx@acme:write_note', '--agent', 'cc', '--yes')
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx@acme', 'actions': ['tool.call'], 'scope': ['write_note']}],
             'SPEC SERVER@PROFILE:TOOL names a write tool, action tool.call only', out)
        out = self.allowed('quinn', '--tools', 'fx@acme:write_note', '--agent', 'cc', '--yes')
        shared = [r for r in self.tool_rules() if r['server'] == 'fx@acme' and r['agent'] == 'cc']
        need(len(shared) == 1 and set(shared[0]['principals']) == {rhea, 'person:' + self.quinn},
             'Set semantics: added to the first remaining rule with identical settings and scope', shared)
        out = self.allowed('quinn', '--tools', 'fx@acme:write_note', '--agent', 'cc', '--calls-per-hour', '5', '--yes')
        shared = [r for r in self.tool_rules() if r['server'] == 'fx@acme' and r['agent'] == 'cc']
        need(len(shared) == 2 and sorted(r['max_calls_per_hour'] for r in shared) == [5, 100],
             'different settings make a new rule (--calls-per-hour)', shared)

        # Repeated --tools makes one rule each, within one invocation even for the same server.
        out = self.allowed('rhea', '--tools', 'fx:echo', '--tools', 'fx:info', '--agent', 'cc', '--yes')
        mine = sorted(r['scope'] for r in self.rules_for(rhea, server='fx') if r['agent'] == 'cc')
        need(len(out['rules']) == 2 and mine == [['echo'], ['info']],
             'repeated --tools for one server in one invocation keeps every requested scope', out, mine)
        out = self.allowed('rhea', '--tools', 'fx:echo', '--tools', 'lit', '--agent', 'cc', '--yes')
        mine = [r['scope'] for r in self.rules_for(rhea, server='fx') if r['agent'] == 'cc']
        need(len(out['rules']) == 2 and {r['server'] for r in out['rules']} == {'fx', 'lit'} and mine == [['echo']],
             '--tools may be repeated; a later allow naming the server replaces its rules', out, mine)

        # deny --tools.
        out = self.deny('rhea', '--tools', 'fx@acme', '--agent', 'cc')
        need(out['removed'] == 1 and not self.rules_for(rhea, server='fx@acme'),
             'deny --tools SERVER@PROFILE removes the principal from rules naming that profile', out)
        need(any(r['server'] == 'fx' and r['agent'] == 'cc' for r in self.rules_for(rhea)),
             'deny of a profile leaves the bare server', self.rules_for(rhea))
        # A profile rule, and two more rules for rhea on cc/fx with different actions and scope (signed here):
        # one deny of the bare server removes them all.
        self.allowed('rhea', '--tools', 'fx@acme', '--agent', 'cc', '--yes')
        current = self.policy()
        extra = [{'agent': 'cc', 'server': 'fx', 'principals': [rhea], 'actions': actions, 'scope': scope,
                  'max_input_bytes': 1000, 'allow_disconnected': False, 'max_calls_per_hour': 7}
                 for actions, scope in ((BOTH, ['readonly']), (['tool.call'], ['info']))]
        signed = crafted_v2(current, current['version'] + 1, self.keys['pat'][0], self.root,
                            tool_rules=current['tool_rules'] + extra)
        status, body = self.hosts['p1'].call('POST', f'/v1/networks/{self.team}/policy', {'policy': signed})
        need(status == 201, 'setup: rules for one server with different actions and scope', status, body)
        holding = len([r for r in self.rules_for(rhea) if r['agent'] == 'cc' and r['server'] in ('fx', 'fx@acme')])
        out = self.deny('rhea', '--tools', 'fx', '--agent', 'cc')
        need(out['removed'] == holding == 4 and not [r for r in self.rules_for(rhea) if r['agent'] == 'cc' and
                                                      r['server'] in ('fx', 'fx@acme')],
             'deny --tools SERVER removes every rule for the server and for every SERVER@PROFILE within the agent '
             'scope, whatever their actions or scope', out, holding)
        need([r for r in self.rules_for(rhea, server='fx') if r['agent'] != 'cc'], 'other agents untouched',
             self.rules_for(rhea))
        out = self.deny('rhea', '--tools', 'fx')
        need(out['removed'] == len(agents_with_fx - {'cc'}) + 1 and not self.rules_for(rhea, server='fx'),
             "deny --tools without --agent removes the principal under every agent name, * included", out,
             self.rules_for(rhea))
        self.deny('rhea', '--tools', 'lit')
        out = self.deny('rhea', '--tools', 'fx')
        need(out['removed'] == 0, 'deny --tools with nothing to remove reports 0', out)
        self.deny('quinn', '--tools', 'fx@acme')
        need(not self.rules_for(rhea) and not self.rules_for('person:' + self.quinn), 'cleanup', self.tool_rules())
        # Allow without tool forms never touches tool rules.
        self.allowed('rhea', '--tools', 'lit', '--agent', 'cc', '--yes')
        rules = self.tool_rules()
        self.hosts['p1'].cli('allow', 'rhea', '--agent', 'cc', '--network', self.team)
        need(self.tool_rules() == rules, 'allow without --tools never touches tool rules', rules)
        self.hosts['p1'].cli('deny', 'rhea', '--network', self.team)
        need(self.tool_rules() == rules, 'deny without --tools never touches tool rules', self.tool_rules())
        self.deny('rhea', '--tools', 'lit')
        return f'policy {policy_before} → {self.version()}'

    def check_policy_v2(self):
        p = self.policy()
        need(p and p.get('format') == 2 and isinstance(p.get('tool_rules'), list) and
             isinstance(p.get('trusted_hosts'), list), 'The JSON gains format 2, tool_rules, and trusted_hosts', p)
        need(len(p['tool_rules']) >= 4, 'setup: the shares', p['tool_rules'])
        need(list(p) == POLICY_V2_ORDER and p['trusted_hosts'] == sorted(p['trusted_hosts']),
             'the JSON keys in the contract\'s order, trusted_hosts sorted', list(p))
        ssh_verify(policy_lines_v2(p), p['signature'], self.keys['pat'][1], self.root)
        budget = next(r for r in p['tool_rules'] if r['server'] == 'budget')
        need(budget['max_calls_per_hour'] == 3 and budget['principals'] == ['person:' + self.quinn],
             '--calls-per-hour; principals by person ID', budget)
        net_rule = next(r for r in p['tool_rules'] if r['server'] == 'budget2')
        need(net_rule['principals'] == ['network'], 'the network principal', net_rule)

        # Coordinator acceptance, and the policy as another implementation's hosts see it.
        with coord_db(self.coord) as db:
            row = db.execute("SELECT statement FROM statements WHERE network_id = ? AND kind = 'policy' AND subject = ?",
                             (self.team, self.keys['pat'][2])).fetchone()
        need(row and json.loads(row[0]) == p, 'the coordinator accepts and serves the v2 policy', row and row[0][:300])
        for name in ('q1', 'u1', 'p3'):
            need(self.policy(name) == p, f'{name} stores the same v2 policy', self.policy(name))

        # Sibling propagation of v2, by direct push with the coordinator stopped.
        self.coord.stop()
        try:
            out = self.allowed('rhea', '--tools', 'lit', '--agent', 'cc', '--yes')
            pushed = out['policy']
            for name in ('p2', 'p3', 'p4'):
                wait_for(lambda: self.policy(name) == policy_of(pushed), timeout=30,
                         message=f'direct push of a v2 policy to {name}')
        finally:
            self.coord.start()
        wait_for(lambda: self.hosts['p1'].cli('access', 'sync', '--network', self.team) and all(
            d['state'] == 'delivered' for d in self.hosts['p1'].cli('access', 'sync', '--network', self.team,
                                                                     '--status')['deliveries']),
            timeout=40, message='v2 delivered to the coordinator after restart')
        self.deny('rhea', '--tools', 'lit')
        self.sync_all()

        # A v1 policy is accepted, and reads as v2 with no tool rules and no trusted hosts.
        rules = [{'agent': 'legacy', 'principals': ['network'], 'actions': ['message.append'],
                  'max_message_bytes': 1000, 'allow_disconnected': False}]
        current = self.policy('p1', self.v1net)
        v1 = crafted_v1(self.v1net, self.keys['pat'][2], (current or {}).get('version', 0) + 1, rules,
                        self.keys['pat'][0], self.root)
        status, body = self.hosts['p1'].call('POST', f'/v1/networks/{self.v1net}/policy', {'policy': v1})
        need(status == 201, 'a v1 policy is accepted', status, body)
        stored = self.policy('p1', self.v1net)
        need(stored['version'] == v1['version'] and plain(stored['rules']) == rules and
             stored['signature'] == v1['signature'] and not {'format', 'tool_rules', 'trusted_hosts'} & set(stored),
             'a v1 policy is stored in its v1 JSON shape, with no format, tool_rules, or trusted_hosts', stored)
        ssh_verify(statement_lines(stored), stored['signature'], self.keys['pat'][1], self.root)

        def at_coordinator():
            with coord_db(self.coord) as db:
                row = db.execute("SELECT statement FROM statements WHERE network_id = ? AND kind = 'policy' AND "
                                 "subject = ?", (self.v1net, self.keys['pat'][2])).fetchone()
            return row and json.loads(row[0])['version'] == v1['version']
        wait_for(at_coordinator, timeout=30, message='the coordinator accepts a v1 policy')
        out = self.hosts['p1'].cli('allow', 'network', '--agent', 'more', '--network', self.v1net)
        nxt = self.policy('p1', self.v1net)
        need(nxt['format'] == 2 and nxt['version'] == v1['version'] + 1 and plain(nxt['rules'])[0] == rules[0],
             'the CLI always signs v2, keeping the v1 rules', nxt)
        ssh_verify(policy_lines_v2(nxt), nxt['signature'], self.keys['pat'][1], self.root)
        # Bounds and validation.
        for bad in ({'max_input_bytes': 0}, {'max_input_bytes': 262145}, {'max_calls_per_hour': 0},
                    {'max_calls_per_hour': 10001}, {'scope': ['*']}, {'scope': ['readonly', 'echo']},
                    {'server': 'Bad.Name'}, {'actions': ['resource.read']},
                    {'actions': ['resource.read', 'tool.call']}, {'actions': BOTH, 'scope': ['echo']},
                    {'actions': ['tool.call', 'tool.call']}, {'scope': ['fixture://docs/*']},
                    {'server': 'fx@Bad.Profile'}):
            rule = {'agent': 'cc', 'server': 'fx', 'principals': ['network'], 'actions': ['tool.call'],
                    'scope': ['readonly'], 'max_input_bytes': 65536, 'allow_disconnected': False,
                    'max_calls_per_hour': 100, **bad}
            v = crafted_v2(nxt, nxt['version'] + 1, self.keys['pat'][0], self.root, tool_rules=[rule])
            status, _ = self.hosts['p1'].call('POST', f'/v1/networks/{self.v1net}/policy', {'policy': v})
            need(status == 400, 'v2 bounds and validation refuse the policy', bad, status)
        for bad_trusted in (['not-a-host'], ['host_xyz'], [self.ids['p1'], self.ids['p1']]):
            v = crafted_v2(nxt, nxt['version'] + 1, self.keys['pat'][0], self.root, trusted=bad_trusted)
            status, _ = self.hosts['p1'].call('POST', f'/v1/networks/{self.v1net}/policy', {'policy': v})
            need(status == 400, 'trusted hosts must be host IDs, without duplicates', bad_trusted, status)
        ok = crafted_v2(nxt, nxt['version'] + 1, self.keys['pat'][0], self.root, tool_rules=[{
            'agent': '*', 'server': 'fx@acme', 'principals': ['network'], 'actions': BOTH, 'scope': ['*'],
            'max_input_bytes': 262144, 'allow_disconnected': True, 'max_calls_per_hour': 10000}])
        status, body = self.hosts['p1'].call('POST', f'/v1/networks/{self.v1net}/policy', {'policy': ok})
        need(status == 201 and policy_of(body) == ok, 'a v2 policy signed here (this suite\'s encoding) is accepted '
             'at the bounds', status, body)
        return f"team v{p['version']}, {len(p['tool_rules'])} tool rules"

    def check_trust(self):
        ids, p3, p1 = self.ids, self.hosts['p3'], self.hosts['p1']
        current = self.policy()
        need(current and 'trusted_hosts' in current, 'setup: a v2 policy for team', current)
        before = current['trusted_hosts']
        need(ids['p3'] not in before, 'p3 starts untrusted', before)
        v = self.version('p3')
        out = p3.cli('trust')
        need(ids['p3'] in self.policy('p3')['trusted_hosts'], 'trust: HOST defaults to this host; --network optional '
             'with one network', out, self.policy('p3'))
        need(isinstance(out, dict) and set(out) == {'policy', 'host', 'trusted', 'changed'} and
             out['host'] == ids['p3'] and out['trusted'] is True and out['changed'] is True and
             out['policy']['version'] == v + 1, 'trust prints {policy, host, trusted, changed}', out)
        again = p3.cli('trust')
        need(again['changed'] is False and again['trusted'] is True and self.version('p3') == v + 1,
             'when nothing changes, changed is false and no version is signed', again)
        self.synced(self.version('p3'), 'p1')
        need(any(e['agent'] == 'cc' for e in self.listing('p1', 'p3')[1]), 'a trusted host lists tools by self')
        out = p3.cli('untrust', ids['p3'])
        need(out['trusted'] is False and out['changed'] is True and out['host'] == ids['p3'],
             'untrust prints {policy, host, trusted, changed}', out)
        self.synced(self.version('p3'), 'p1')
        need(ids['p3'] not in self.policy()['trusted_hosts'], 'untrust HOST removes it')
        status, body = self.listing('p1', 'p3')
        need(status == 200 and not any(v['kind'] == 'self' for e in body for t in e['tools'] for v in t['via']),
             'an untrusted host has no self entries', body)
        code, out, stdout, stderr = p1.outcome('trust')
        need(code != 0, 'trust without --network fails on a host in several networks', code)
        code, out, stdout, stderr = p1.outcome('trust', ids['q1'], '--network', self.team)
        need(code != 0, 'trust HOST must be bound to this person in the selected network', code)
        code, out, stdout, stderr = p1.outcome('trust', ids['u1'], '--network', self.team)
        need(code != 0, 'trust refuses a host bound to no person', code)
        # Per-network trust: p2 is trusted in team, not in other.
        status, body = self.listing('p1', 'p2', network=self.other)
        need(status == 200 and not any(v['kind'] == 'self' for e in body for t in e['tools'] for v in t['via']),
             'Trust is per network: no self entries from a network where the host is untrusted', body)
        status, body = self.listing('p1', 'p2', network=self.team)
        need(status == 200 and body and all(t['via'][0] == {'kind': 'self', 'network_id': self.team}
                                            for e in body for t in e['tools']),
             'self entries from the network where it is trusted, first in via', body[:2])
        count = self.outbound_count('p2')
        code, out, stderr = self.call('p2', 'pat/cc/fx', 'write_note', {'text': 'per-network'}, '--network',
                                      self.other)
        need(code != 0 and self.outbound_count('p2') == count,
             'a call relying on a network where the host is untrusted is refused locally, persisting nothing', code)
        v = self.version('p1', self.other)
        p1.cli('trust', ids['p2'], '--network', self.other)
        need(ids['p2'] in self.policy('p1', self.other)['trusted_hosts'] and self.version('p1', self.other) == v + 1,
             'trust HOST --network signs the next version of that network\'s policy')
        p1.cli('untrust', ids['p2'], '--network', self.other)
        need(ids['p2'] not in self.policy('p1', self.other)['trusted_hosts'], 'untrust HOST --network')
        need(ids['p2'] in self.policy()['trusted_hosts'], 'other networks untouched', self.policy()['trusted_hosts'])
        self.sync_all(self.other)

    def check_authorization(self):
        self.clear('rhea')
        ids = self.ids
        f = self.fixture
        # By policy, and by self from a trusted host.
        marker = 'by-policy-' + secrets.token_hex(4)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': marker}, '--network', self.team)
        need(code == 0 and out['status']['state'] == 'succeeded', 'policy authorizes a read-only tool', code,
             out, stderr[-300:])
        need(out['request'].get('policy') == {'person_id': self.pat, 'version': self.version()},
             'the CLI cites the policy from the listing', out['request'])
        need(first_text(out['result']) == marker and len(f.calls('fx-local', marker)) == 1,
             'the tool\'s own result', out['result'])
        code, out, stderr = self.read('q1', 'pat/cc/fx', 'file:///srv/private/b.txt', '--network', self.team)
        need(code == 0 and out['status']['state'] == 'succeeded',
             '--tools SERVER (actions tool.call resource.read) covers every resource in the snapshot', code, out,
             stderr[-300:])
        code, out, stderr = self.call('p2', 'pat/cc/fx', 'write_note', {'text': 'by self'})
        need(code == 0 and out['request'].get('self') == {'person_id': self.pat},
             'self from a trusted host covers write tools without a profile', code, out, stderr[-300:])
        # Self refused from an untrusted host of the same person, and from another person's host.
        status, body = self.submit('p3', self.body('cc', 'fx', 'echo', {'text': 'x'}, cite=self.self_cite()))
        need(status == 403, 'self is refused from an untrusted host of the same person', status, body)
        count = self.outbound_count('p3')
        code, out, stderr = self.call('p3', 'pat/cc/fx', 'echo', {'text': 'x'})
        need(code != 0 and self.outbound_count('p3') == count, 'an entry without a usable via is refused locally '
             'before anything is persisted', code, out)
        for claimed in (self.pat, self.quinn):
            status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x'},
                                                       cite={'self': {'person_id': claimed}}))
            need(status == 403, "another person's host is never covered by self", claimed, status)
        # Named tools share no resources.
        self.allowed('rhea', '--tools', 'fx:echo', '--agent', 'cc', '--yes')
        try:
            self.synced(self.version(), 'r')
            status, _ = self.submit('r', self.body('cc', 'fx', 'echo', {'text': 'named'}, cite=self.policy_cite()))
            need(status == 200, 'a named tool is authorized', status)
            status, _ = self.submit('r', self.body('cc', 'fx', uri='fixture://docs/readme', cite=self.policy_cite()))
            need(status == 403, 'named tools share no resources (action tool.call only)', status)
            status, _ = self.submit('r', self.body('cc', 'fx', 'info', {}, cite=self.policy_cite()))
            need(status == 403, 'a tool outside the named scope is refused', status)
        finally:
            self.deny('rhea', '--tools', 'fx', '--agent', 'cc')
        # A grant citation is refused with 400, even with a real grant held by this host.
        message_grant = self.hosts['p1'].cli('grant', 'create', '--peer', ids['q1'], '--agent', self.aid['cc'],
                                             '--expires-in', '1h')
        status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x'},
                                                   cite={'grant_id': message_grant['id']}))
        need(status == 400, 'a grant_id citation is refused with 400', status, body)
        self.hosts['p1'].cli('grant', 'revoke', message_grant['id'])
        # The read-only rule under policy (a policy signed here names write tools on the bare server), not self.
        current = self.policy()
        extra = {'agent': 'cc', 'server': 'fx', 'principals': ['person:' + self.quinn], 'actions': ['tool.call'],
                 'scope': ['write_note', 'purge'], 'max_input_bytes': 65536, 'allow_disconnected': False,
                 'max_calls_per_hour': 100}
        signed = crafted_v2(current, current['version'] + 1, self.keys['pat'][0], self.root,
                            tool_rules=current['tool_rules'] + [extra])
        status, body = self.hosts['p1'].call('POST', f'/v1/networks/{self.team}/policy', {'policy': signed})
        need(status == 201, 'setup: a policy naming write tools on a server without a profile', status, body)
        self.synced(signed['version'], 'q1')
        for tool in ('write_note', 'purge'):
            status, body = self.submit('q1', self.body('cc', 'fx', tool, {'text': 'x'}, cite=self.policy_cite()))
            need(status == 403, 'the read-only rule under policy: 403 whatever the scope says', tool, status)
        need('write_note' not in self.listed_tools('p1', 'q1', 'cc', 'fx'), 'the listing applies the read-only rule')
        restored = crafted_v2(signed, signed['version'] + 1, self.keys['pat'][0], self.root,
                              tool_rules=current['tool_rules'])
        self.hosts['p1'].call('POST', f'/v1/networks/{self.team}/policy', {'policy': restored})
        self.sync_all()
        # Blocks, except under self.
        made = [self.hosts['p1'].cli('block', 'quinn'), self.hosts['p1'].cli('block', ids['p2'])]
        status, _ = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'blocked'}, cite=self.policy_cite()))
        need(status == 403, 'blocks apply under policy', status)
        status, _ = self.submit('u1', self.body('cc', 'budget2', 'echo', {'text': 'x'}, cite=self.policy_cite()))
        need(status == 200, 'blocks name only their subjects', status)
        status, _ = self.submit('p2', self.body('cc', 'fx', 'echo', {'text': 'self'}, cite=self.self_cite()))
        need(status == 200, 'blocks do not apply under self', status)
        for target in ('quinn', ids['p2']):
            self.hosts['p1'].cli('unblock', target)
        need(self.hosts['p1'].cli('access', 'blocks') == [], 'unblocked', made)
        # Budgets: per (rule, caller), the caller being the bound person, else the host.
        cite = self.policy_cite()
        results = [self.submit(h, self.body('cc', 'budget', 'echo', {'text': h}, cite=cite))[0]
                   for h in ('q1', 'q1', 'q2')]
        need(results == [200, 200, 200], 'budget: 3 accepted calls', results)
        for h in ('q1', 'q2'):
            status, body = self.submit(h, self.body('cc', 'budget', 'echo', {'text': h}, cite=cite))
            need(status == 429 and isinstance(body, dict) and set(body) == {'code', 'error', 'limit'} and
                 body['code'] == 'limit' and body['limit'] == 'max_calls_per_hour',
                 'over the limit: 429 {code: "limit", error, limit: "max_calls_per_hour"}, counted per person across '
                 'hosts', h, status, body)
        code, out, stderr = self.call('q1', 'pat/cc/budget', 'echo', {'text': 'over'}, '--network', self.team)
        need(code == 1 and out and out['submit_state'] == 'rejected' and out['next_attempt_at'] is None,
             'a 429 is a final rejected submission, not retried', code, out)
        # The budget key excludes the principals: adding rhea to the rule resets nobody's budget.
        self.allowed('rhea', '--tools', 'budget', '--agent', 'cc', '--calls-per-hour', '3', '--yes')
        rule = [r for r in self.tool_rules() if r['server'] == 'budget' and r['agent'] == 'cc']
        need(len(rule) == 1 and set(rule[0]['principals']) == {'person:' + self.quinn, 'person:' + self.rhea},
             'setup: rhea added to quinn\'s budget rule', rule)
        self.synced(self.version(), 'q1', 'r')
        cite = self.policy_cite()
        status, body = self.submit('q1', self.body('cc', 'budget', 'echo', {'text': 'still'}, cite=cite))
        need(status == 429, 'Budget key: the rule identity excludes principals, so changing them resets no budget',
             status, body)
        status, body = self.submit('r', self.body('cc', 'budget', 'echo', {'text': 'rhea'}, cite=cite))
        need(status == 200, 'each caller has its own count under the rule', status, body)
        self.deny('rhea', '--tools', 'budget')
        self.synced(self.version(), 'q1', 'q2', 'u1', 'u2', 'r')
        cite = self.policy_cite()
        # u1 made one budget2 call above, under the block check.
        got = [self.submit('u1', self.body('cc', 'budget2', 'echo', {'text': 'u1'}, cite=cite))[0] for _ in range(2)]
        need(got == [200, 429], 'an unbound sender is counted by its host ID', 'u1', got)
        got = [self.submit('u2', self.body('cc', 'budget2', 'echo', {'text': 'u2'}, cite=cite))[0] for _ in range(3)]
        need(got == [200, 200, 429], 'an unbound sender is counted by its host ID', 'u2', got)
        got = [self.submit(h, self.body('cc', 'budget2', 'echo', {'text': h}, cite=cite))[0] for h in ('q1', 'q2', 'q1')]
        need(got == [200, 200, 429], 'the same rule counts each person separately from unbound hosts', got)
        # 413 for oversized input.
        status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x' * 70000}, cite=cite))
        need(status == 413 and isinstance(body, dict) and set(body) == {'code', 'error'} and body['code'] == 'too_large',
             'input over max_input_bytes (the JSON encoding of arguments): 413 {code: "too_large", error}', status, body)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'x' * 70000}, '--network', self.team)
        need(code == 1 and out and out['submit_state'] == 'rejected' and out['next_attempt_at'] is None,
             'a 413 is a final rejected submission, not retried', code, out)
        status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x' * 60000}, cite=cite))
        need(status == 200, 'input within max_input_bytes', status, body)
        # The deadline at the receiver: in the future, and at most 15 minutes (plus 1 minute of skew) ahead.
        for seconds in (17 * 60, -5):
            status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x'}, cite=cite,
                                                       deadline=timestamp(seconds)))
            need(status == 400 and isinstance(body, dict) and body.get('code') == 'invalid',
                 'a deadline in the past or more than 15 minutes (plus skew) ahead: 400 invalid', seconds, status, body)
        status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'skew'}, cite=cite,
                                                   deadline=timestamp(15 * 60 + 20)))
        need(status == 200, 'a deadline within the minute of clock skew is accepted', status, body)
        # Lapsed authorization before start: rejected. rhea's call waits behind 4 running calls; deny lapses it.
        self.allowed('rhea', '--tools', 'fx', '--agent', 'cc', '--yes')
        self.synced(self.version(), 'r')
        lapsing = self.policy_cite()
        self.fill_slots(6)
        marker = 'lapsed-' + secrets.token_hex(4)
        b = self.body('cc', 'fx', 'echo', {'text': marker}, cite=lapsing)
        status, record = self.submit('r', b)
        need(status == 200 and record['state'] == 'queued', 'a fifth call waits as queued', status, record)
        self.deny('rhea', '--tools', 'fx', '--agent', 'cc')
        done = self.final('r', b['call_id'], timeout=40)
        need(done['state'] == 'rejected' and LAPSED in json.dumps(done),
             f'Rechecks: a failure at the start makes the call rejected, "{LAPSED}"', done)
        need(not f.calls('fx-local', marker), 'a rejected call never runs', f.calls('fx-local', marker))

    def check_no_grants(self):
        """Grants do not authorize calls in slice 1."""
        ids, p1 = self.ids, self.hosts['p1']
        for action in ('tool.call', 'resource.read'):
            code, out, stdout, stderr = p1.outcome('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'],
                                                   '--expires-in', '1h', '--action', action)
            need(code != 0, f'grant create does not accept {action}', code, stdout[-300:])
        status, body = self.listing('p1', 'n')
        need((status, body) == (200, []), 'a manually configured peer outside any network gets an empty listing',
             status, body)
        g = p1.cli('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'], '--expires-in', '1h')
        status, body = self.submit('n', self.body('cc', 'fx', 'echo', {'text': 'x'}, cite={'grant_id': g['id']}))
        need(status == 400, 'a grant_id citation is refused with 400', status, body)
        count = self.outbound_count('n')
        code, out, stderr = self.call('n', f"{ids['p1']}/cc/fx", 'echo', {'text': 'x'})
        need(code != 0 and self.outbound_count('n') == count,
             'a peer outside any network cannot call: nothing is listed, so nothing is cited or persisted', code)
        p1.cli('grant', 'revoke', g['id'])

    def check_routes(self):
        self.clear('rhea')
        ids = self.ids
        status, body = self.listing('p1', 'q1')
        need(status == 200 and isinstance(body, list), 'GET /peer/v1/tools', status, body)
        for e in body:
            need(set(e) == LISTING_KEYS, 'entries are {agent, agent_id, server, profile, tools, resources}', e)
            for t in e['tools']:
                need(set(t) == LISTED_TOOL_KEYS, 'tools are {name, description, input_schema, read_only, via}', t)
            for r in e['resources']:
                need(set(r) == LISTED_RESOURCE_KEYS, 'resources are {uri, name, description, mime_type, via}', r)
        need([(e['agent'], e['server'], e['profile'] or '') for e in body] ==
             sorted((e['agent'], e['server'], e['profile'] or '') for e in body),
             'sorted by agent, server, and profile', [(e['agent'], e['server'], e['profile']) for e in body])
        fx = self.entry(body, 'cc', 'fx')
        need(fx and fx['agent_id'] == self.aid['cc'], 'q1 lists cc/fx', body)
        need({t['name'] for t in fx['tools']} == RO_TOOLS | {'from_local'} and all(t['read_only'] for t in fx['tools']),
             'filtered by authorization: readonly covers read-only tools only', sorted(t['name'] for t in fx['tools']))
        need({r['uri'] for r in fx['resources']} == ALL_RESOURCES,
             '--tools SERVER lists every resource in the snapshot', fx['resources'])
        acme = self.entry(body, 'cc', 'fx', 'acme')
        need(acme and {t['name'] for t in acme['tools']} == {'write_note'} and acme['resources'] == [],
             'a profile share of named tools lists its tools and no resources', acme)
        echo = next(t for t in fx['tools'] if t['name'] == 'echo')
        nets = sorted([self.team, self.other])
        need([v['kind'] for v in echo['via']] == ['policy', 'policy'] and
             [v['network_id'] for v in echo['via']] == nets,
             'via: policy entries ordered by network ID', echo['via'])
        for v in echo['via']:
            need(set(v) == {'kind', 'network_id', 'person_id', 'version'} and v['person_id'] == self.pat,
                 'policy via {kind, network_id, person_id, version}', v)
        # ?network= evaluates only that network's authorizations.
        status, scoped = self.listing('p1', 'q1', network=self.other)
        need(status == 200 and all(v['kind'] == 'policy' and v['network_id'] == self.other
                                   for e in scoped for t in e['tools'] for v in t['via']),
             '?network=ID: only that network\'s authorizations', scoped)
        need(self.entry(scoped, 'cc', 'lit'), 'lit is shared with quinn in other', scoped)
        status, team_only = self.listing('p1', 'q1', network=self.team)
        need(not self.entry(team_only, 'cc', 'lit'), 'a share in another network is not listed with ?network',
             team_only)
        # A host with nothing, a peer outside any network, and a trusted sibling.
        status, body = self.listing('p1', 'r')
        need((status, body) == (200, []), 'a host with no authorization lists []', status, body)
        status, body = self.listing('p1', 'n')
        need((status, body) == (200, []), 'a manually configured peer outside any network gets an empty listing',
             status, body)
        status, body = self.listing('p1', 'p2')
        fx = self.entry(body, 'cc', 'fx')
        need(fx and {t['name'] for t in fx['tools']} == RO_TOOLS | WRITE_TOOLS | {'from_local'},
             'self covers every tool, including write tools', fx)
        need(not any(e['server'] in ('rem', 'needy', 'needyarg', 'Bad.Name', 'sserem') for e in body),
             'only shareable servers are listed', [e['server'] for e in body])
        need(self.entry(body, 'cx', 'cxs') and self.entry(body, 'cc', 'fx', 'acme'),
             'self covers every shareable server and profile of every agent', [e['server'] for e in body])
        need(all(v['kind'] in ('self', 'policy') for e in body for t in e['tools'] for v in t['via']),
             'via has only self and policy entries', body[:1])
        need(all(t['via'][0]['kind'] == 'self' for e in body for t in e['tools']), 'self before policy', body[:1])
        # Status and cancel: submitter only.
        b = self.body('cc', 'fx', 'echo', {'text': 'mine'}, cite=self.policy_cite())
        status, record = self.submit('q1', b)
        need(status == 200, 'setup: a call by q1', status, record)
        for method, path, payload in (('GET', f"/peer/v1/calls/{b['call_id']}", None),
                                      ('POST', f"/peer/v1/calls/{b['call_id']}/cancel", {})):
            for other in ('q2', 'n', 'p2'):
                status, _ = wire(self.hosts['p1'], fixture_context(self.hosts[other]), method, path, payload)
                need(status == 404, 'status and cancel from a non-submitter return 404', other, method, status)
        need(self.status_of('q1', call_id())[0] == 404, 'an unknown call ID is 404')
        self.final('q1', b['call_id'])

    def check_calls(self):
        f, ids = self.fixture, self.ids
        # The caller is p2, a trusted host of pat, under self: every tool, no hourly budget.
        cite = self.self_cite()
        # The lifecycle, on the wire.
        marker = 'life-' + secrets.token_hex(4)
        b = self.body('cc', 'fx', 'echo', {'text': marker}, cite=cite)
        status, record = self.submit('p2', b)
        need(status == 200 and set(record) == STATUS_KEYS, 'POST /peer/v1/calls returns the status record', status,
             record)
        need(record['state'] == 'queued' and record['call_id'] == b['call_id'] and record['kind'] == 'tool' and
             record['name'] == 'echo' and record['uri'] is None and record['server'] == 'fx' and
             record['profile'] is None and record['sender_host_id'] == ids['p2'] and
             record['receiver_host_id'] == ids['p1'] and record['cancel_requested'] is False,
             'persisted as queued', record)
        done = self.final('p2', b['call_id'])
        need(set(done) == STATUS_KEYS | {'result'} and done['state'] == 'succeeded' and done['error'] is None,
             'GET: the status record with result once final', done)
        need(done['result'] == {'content': [{'type': 'text', 'text': marker}]}, 'result is the JSON-RPC result',
             done['result'])
        need(done['started_at'] and done['finished_at'] and done['result_bytes'] > 0, 'timestamps and result_bytes',
             done)
        # Duplicate and conflicting submission.
        status, again = self.submit('p2', b)
        need(status == 200 and again['call_id'] == b['call_id'] and again['created_at'] == record['created_at'],
             'an identical repeat returns the existing record', status, again)
        need(len(f.calls('fx-local', marker)) == 1, 'retrying a submission never starts a second run')
        need(self.submit('p2', {**b, 'arguments': {'text': 'changed'}})[0] == 409, 'a changed repeat returns 409')
        for bad in ({**b, 'call_id': 'call_x'}, {k: v for k, v in b.items() if k != 'profile'},
                    {**b, 'extra': 1}, {**b, 'kind': 'prompt'}, {**b, 'call_id': call_id(), 'uri': 'fixture://x'},
                    {**b, 'call_id': call_id(), 'arguments': []},
                    {**b, 'call_id': call_id(), 'policy': {'person_id': self.pat, 'version': 1}},
                    {**{k: v for k, v in b.items() if k != 'self'}, 'call_id': call_id(),
                     'grant_id': 'grant_' + '0' * 32}):
            need(self.submit('p2', bad)[0] == 400, 'POST /peer/v1/calls takes exactly its fields and one citation', bad)
        # A resource.
        status, record = self.submit('q1', self.body('cc', 'fx', uri='fixture://docs/guide', cite=self.policy_cite()))
        need(status == 200 and record['kind'] == 'resource' and record['uri'] == 'fixture://docs/guide' and
             record['name'] is None, 'a resource call', status, record)
        done = self.final('q1', record['call_id'])
        need(done['state'] == 'succeeded' and done['result']['contents'][0]['uri'] == 'fixture://docs/guide',
             'the full lifecycle for resources', done)
        # isError and JSON-RPC errors; result_too_large.
        for name, arguments, error in (('tool_error', {'message': 'nope'}, 'tool_error'),
                                       ('fail', {'message': 'broken', 'code': -32001}, 'jsonrpc_error'),
                                       ('big', {'bytes': 1100000}, 'result_too_large')):
            b = self.body('cc', 'fx', name, arguments, cite=cite)
            self.submit('p2', b)
            done = self.final('p2', b['call_id'])
            need(done['state'] == 'failed' and done['error'] == error, f'{name}: failed with {error}', done)
            if error == 'jsonrpc_error':
                need(done['result'] == {'code': -32001, 'message': 'broken'}, 'a JSON-RPC error result is {code, '
                     'message}', done['result'])
            if error == 'tool_error':
                need(done['result'].get('isError') is True, 'isError result kept', done['result'])
            if error == 'result_too_large':
                need(done.get('result') is None, 'a result over 1 MiB is not stored', str(done)[:300])
        b = self.body('cc', 'fx', 'big', {'bytes': 1048000}, cite=cite)
        self.submit('p2', b)
        try:
            near = self.final('p2', b['call_id'])
        except OSError as error:
            raise Failure('peerspan-peer-probe accepts responses up to 4 MiB on GET /peer/v1/calls/{id}: '
                          f'{error}') from None
        need(near['state'] == 'succeeded', 'a result just under 1 MiB is kept', near['state'])

        # A lost submit response, recovered by retry: one execution.
        marker = 'lost-' + secrets.token_hex(4)
        relay = DropCallResponse(self.hosts['p1'])
        identity = self.hosts['p1'].call('GET', '/v1/host')[1]
        # A manual peer's address takes precedence for dialing (coordination contract), so p2 reaches p1 through
        # the relay until it is configured back to p1's own address.
        self.hosts['p2'].configure(self.hosts['p1'], identity, relay.address)
        try:
            code, out, stderr = self.call('p2', f"{ids['p1']}/cc/fx", 'echo', {'text': marker}, wait='1s')
            relay.close()
        finally:
            self.hosts['p2'].configure(self.hosts['p1'], identity)
        need(out and set(out) == OUTBOUND_KEYS and out['submit_state'] == 'unknown' and out['next_attempt_at'],
             'the outbound record after a lost response', code, out, stderr[-300:])
        need(code == 3, 'call exits 3 while pending', code)
        recovered = wait_for(lambda: (r := self.inspect('p2', ids['p1'], out['request']['call_id']))['submit_state'] ==
                             'accepted' and r, timeout=40, message='automatic call retry')
        need(recovered['attempts'] >= 2, 'retried', recovered)
        final = self.settle('p2', recovered)
        need(final['status']['state'] == 'succeeded' and first_text(final['result']) == marker,
             'the daemon polls and stores the final status and result', final)
        need(len(f.calls('fx-local', marker)) == 1, 'exactly one execution recorded by the fixture',
             f.calls('fx-local', marker))

        # Expiry before start, and cancellation while queued.
        self.fill_slots(8)
        marker = 'expire-' + secrets.token_hex(4)
        expiring = self.body('cc', 'fx', 'echo', {'text': marker}, cite=cite, deadline=timestamp(3))
        queued = self.body('cc', 'fx', 'echo', {'text': marker + '-cancel'}, cite=cite)
        need(self.submit('p2', expiring)[1]['state'] == 'queued', 'queued behind 4 running calls')
        need(self.submit('p2', queued)[1]['state'] == 'queued', 'queued behind 4 running calls')
        status, record = wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'POST',
                              f"/peer/v1/calls/{queued['call_id']}/cancel", {})
        need(status == 200 and record['state'] == 'cancelled' and record['cancel_requested'] is True,
             'cancelling a queued call: cancelled at once', status, record)
        need(self.final('p2', expiring['call_id'], timeout=40)['state'] == 'expired',
             'a call still queued at its deadline becomes expired')
        need(not f.calls('fx-local', marker) and not f.calls('fx-local', marker + '-cancel'),
             'expired and cancelled calls never ran')
        status, again = wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'POST',
                             f"/peer/v1/calls/{queued['call_id']}/cancel", {})
        need(status == 200 and again['state'] == 'cancelled', 'a cancel of a final call returns it unchanged', again)

        # Cancellation while running, and the deadline while running: uncertain, with notifications/cancelled.
        time.sleep(9)
        for how in ('cancel', 'deadline'):
            marker = f'{how}-' + secrets.token_hex(4)
            b = self.body('cc', 'fx', 'sleep', {'seconds': 30, 'text': marker}, cite=cite,
                          deadline=timestamp(6) if how == 'deadline' else None)
            self.submit('p2', b)
            wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
            if how == 'cancel':
                status, record = wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'POST',
                                      f"/peer/v1/calls/{b['call_id']}/cancel", {})
                need(status == 200 and record['cancel_requested'] is True, 'cancel sets cancel_requested', record)
            done = self.final('p2', b['call_id'], timeout=40)
            error = 'cancel_requested' if how == 'cancel' else 'deadline'
            need(done['state'] == 'uncertain' and done['error'] == error, f'a running call: uncertain with {error}',
                 done)
            request = f.calls('fx-local', marker)[0]['id']
            wait_for(lambda: any(e['event'] == 'cancelled' and e.get('request_id') == request
                                 for e in f.entries('fx-local')), timeout=10,
                     message='notifications/cancelled sent to the server')
        # The owner CLI's cancel.
        marker = 'cli-cancel-' + secrets.token_hex(4)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'sleep', {'seconds': 30, 'text': marker}, '--network',
                                      self.team, wait='1s')
        need(code == 3, 'call exits 3 while still pending', code, out)
        wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
        cancelled = self.hosts['q1'].cli('calls', 'cancel', '--peer', ids['p1'], out['request']['call_id'])
        need(cancelled['cancel_state'] == 'sent', 'calls cancel: cancel_state sent', cancelled)
        final = self.settle('q1', cancelled)
        need(final['status']['state'] == 'uncertain' and final['status']['error'] == 'cancel_requested',
             'calls cancel of a running call', final)

        # A daemon restart during a running call: uncertain, and never run again.
        marker = 'restart-' + secrets.token_hex(4)
        b = self.body('cc', 'fx', 'sleep', {'seconds': 15, 'text': marker}, cite=cite)
        self.submit('p2', b)
        wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
        self.restart('p1')
        done = self.final('p2', b['call_id'], timeout=30)
        need(done['state'] == 'uncertain' and done['error'] == 'daemon_restarted',
             'At daemon start, every call still running becomes uncertain (daemon_restarted)', done)
        time.sleep(18)
        need(len(f.calls('fx-local', marker)) == 1, 'No re-execution after a restart', f.calls('fx-local', marker))

        # A server exit: running calls uncertain (server_exited); the next call starts a new instance.
        marker = 'exit-' + secrets.token_hex(4)
        b1 = self.body('cc', 'fx', 'sleep', {'seconds': 30, 'text': marker}, cite=cite)
        self.submit('p2', b1)
        wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
        pid = f.calls('fx-local', marker)[0]['pid']
        b2 = self.body('cc', 'fx', 'crash', {'delay': 1}, cite=cite)
        self.submit('p2', b2)
        for b in (b1, b2):
            done = self.final('p2', b['call_id'], timeout=30)
            need(done['state'] == 'uncertain' and done['error'] == 'server_exited',
                 'an instance exit makes its running calls uncertain (server_exited)', done)
        marker = 'after-exit-' + secrets.token_hex(4)
        b = self.body('cc', 'fx', 'echo', {'text': marker}, cite=cite)
        self.submit('p2', b)
        need(self.final('p2', b['call_id'])['state'] == 'succeeded' and f.calls('fx-local', marker)[0]['pid'] != pid,
             'later calls start a new instance')

        # Concurrency capped at 4 per instance.
        marker = 'conc-' + secrets.token_hex(4)
        batch = [self.body('cc', 'fx', 'sleep', {'seconds': 3, 'text': marker}, cite=cite) for _ in range(6)]
        for b in batch:
            self.submit('p2', b)
        for b in batch:
            need(self.final('p2', b['call_id'], timeout=40)['state'] == 'succeeded', 'every call finishes')
        peak = max(e['concurrent'] for e in f.calls('fx-local', marker))
        need(peak == 4, 'An instance runs at most 4 calls concurrently', peak)
        need(len({e['pid'] for e in f.calls('fx-local', marker)}) == 1, 'one instance per (agent, server, profile)')

        # Activity on both sides; listings.
        kinds = {e['kind'] for e in self.activity('p1')}
        need({'call.received', 'call.started', 'call.finished', 'call.cancel_requested'} <= kinds,
             'receiver activity kinds', sorted(k for k in kinds if k.startswith('call.')))
        sent = [e for e in self.activity('q1') if e['kind'].startswith('call.')]
        need({e['kind'] for e in sent} == {'call.submitted', 'call.updated'} and
             any(e['subject_id'] == f"{ids['p1']}/{out['request']['call_id']}" for e in sent),
             'caller activity: call.submitted and call.updated, subject PEER/CALL_ID', sent[:4])
        received = [e for e in self.activity('p1') if e['kind'] == 'call.received']
        need(any(e['subject_id'] == f"{ids['p2']}/{batch[0]['call_id']}" for e in received),
             'receiver activity subject SENDER/CALL_ID', received[-3:])

    def check_values(self):
        f = self.fixture
        captured, literal = self.secrets['captured'], self.secrets['literal']

        def self_call(server, tool, arguments, profile=None):
            target = f'pat/cc/{server}' + (f'@{profile}' if profile else '')
            code, out, stderr = self.call('p2', target, tool, arguments)
            need(code == 0, f'self call {target} {tool}', code, out, stderr[-300:])
            return first_text(out['result'])

        def matches(server, name, value):
            return self_call(server, 'env_matches', {'name': name, 'sha256': sha(value)})
        need(matches('proj', 'TOKEN_A', captured) == {'present': True, 'matches': True},
             '${VAR} captured at attach reaches the server')
        need(matches('proj', 'TOKEN_B', 'fallback-b') == {'present': True, 'matches': True},
             '${VAR:-DEFAULT} resolved to its default')
        need(matches('lit', 'LIT_TOKEN', literal) == {'present': True, 'matches': True},
             'a server configured with a literal token starts with it')
        names = set(self_call('proj', 'env_names', {}))
        need({'PATH', 'HOME', 'TOKEN_A', 'TOKEN_B'} <= names and names <= {'PATH', 'HOME', 'TOKEN_A', 'TOKEN_B'} |
             INTERPRETER_NAMES, "an environment of the daemon's own PATH and HOME and the definition's env",
             sorted(names))
        need(CANARY not in names, 'the daemon\'s other variables never reach a server', sorted(names))
        need(self_call('proj', 'info', {})['cwd'] == str(self.workspaces['w1']),
             "the agent's workspace is the working directory")
        # The environment file overrides captured values, and is ignored when too open (item 14).
        env_file = self.hosts['p1'].config / 'peerspan' / 'env'
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_file.write_text(f"# overrides\nTOKEN_A={self.secrets['file']}\n\nLIT_TOKEN=from-file\n"
                            f"EXTRA_FROM_FILE={self.secrets['file']}\nNEED=from-file\nFX_MISSING_VAR=from-file\n")
        env_file.chmod(0o600)
        self.restart('p1')
        need(matches('proj', 'TOKEN_A', self.secrets['file']) == {'present': True, 'matches': True},
             'the environment file overrides captured values for variables the definition names')
        need(matches('lit', 'LIT_TOKEN', 'from-file') == {'present': True, 'matches': True},
             'the environment file overrides literals of the same name')
        names = set(self_call('proj', 'env_names', {}))
        need({'PATH', 'HOME', 'TOKEN_A', 'TOKEN_B'} <= names and names <= {'PATH', 'HOME', 'TOKEN_A', 'TOKEN_B'} |
             INTERPRETER_NAMES, 'other variables in the environment file do not reach the server', sorted(names))
        names = set(self_call('lit', 'env_names', {}))
        need('TOKEN_A' not in names and 'EXTRA_FROM_FILE' not in names,
             'a server receives only the environment-file variables its own definition names', sorted(names))
        need(not [i for i in self.items() if i['subject'] == 'env'], 'no item 14 for a 0600 file')
        self.refresh('cc')
        needy = self.servers('cc')['needy']
        need(needy['reason'] == 'missing_env' and needy['missing_env'] == ['FX_MISSING_VAR'],
             'a missing reference keeps the server missing_env even when the environment file has that name', needy)
        env_file.chmod(0o644)
        self.restart('p1')
        need(matches('proj', 'TOKEN_A', captured) == {'present': True, 'matches': True},
             'a file not mode 0600 or stricter is not used: servers start without it')
        item = [i for i in self.items() if i['subject'] == 'env']
        need(item and item[0]['command'] == f'chmod 600 {env_file}', 'status item 14 for the environment file',
             self.items())
        env_file.unlink()
        self.restart('p1')
        # Values never appear outside tool_values.
        self.scan_secrets([captured, literal, self.secrets['file'], self.secrets['profile']])

    def scan_secrets(self, values):
        found = []
        texts = list(self.exposed)
        for name in self.hosts:
            h = self.hosts[name]
            texts.append((f'{name} activity', json.dumps(self.activity(name))))
            h.logs.seek(0)
            texts.append((f'{name} daemon log', h.logs.read().decode(errors='replace')))
            texts.append((f'{name} status', json.dumps(self.attention(name))))
            for path in h.state.rglob('*'):
                if path.is_file() and not path.name.startswith('host.db') and not path.is_socket():
                    try:
                        texts.append((str(path), path.read_bytes().decode(errors='replace')))
                    except OSError:
                        pass
            connection = sqlite3.connect(h.state / 'host.db')
            try:
                tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
                for table in tables:
                    if table == 'tool_values':
                        continue
                    for row in connection.execute(f'SELECT * FROM "{table}"'):
                        texts.append((f'{name} table {table}', ' '.join(str(c) for c in row)))
            finally:
                connection.close()
        for caller in ('p2', 'q1', 'n'):
            status, body = self.listing('p1', caller)
            texts.append((f'GET /peer/v1/tools as {caller}', json.dumps(body)))
        texts.append(('GET /v1/tools', json.dumps(self.tools_view())))
        for where, text in texts:
            for value in values:
                if value in text:
                    found.append(where)
        need(not found, 'values never appear in definitions, listings, output, logs, activity, or the peer route; '
             'the daemon keeps them only in tool_values', sorted(set(found)))
        stored = {r[0] for r in db_rows(self.hosts['p1'], 'SELECT value FROM tool_values')}
        need(self.secrets['captured'] in stored and self.secrets['literal'] in stored,
             'captured and literal values are stored in tool_values', len(stored))

    def check_profiles(self):
        self.clear('rhea')
        f = self.fixture
        servers = self.servers('cc')
        profiles = {x['name']: x for x in servers['fx']['profiles']}
        need(set(profiles) == {'acme'}, 'GET /v1/tools lists the server\'s profiles', servers['fx']['profiles'])
        acme = profiles['acme']
        need(acme['env_file'] == str(self.profile_env) and acme['args'][0] == str(FIXTURE) and
             'from_acme' in {t['name'] for t in acme['tools']} and acme['snapshot_at'] and acme['confirmed'] is True,
             'PROFILE: its env_file and args, snapshotted with its own arguments, confirmed by an earlier allow', acme)

        # POST .../profiles directly: 201, an identical repeat 200, a different one 409, and refusals.
        api = self.hosts['p1']
        path = f"/v1/agents/{self.aid['cc']}/tool-servers/lit/profiles"
        body = {'name': 'narrow', 'env_file': str(self.profile_env), 'args': self.fixture.args('lit-narrow', 'narrow')}
        status, made = api.call('POST', path, body)
        need(status == 201 and set(made) == PROFILE_KEYS | {'agent_id', 'server'} and made['server'] == 'lit' and
             made['agent_id'] == self.aid['cc'] and made['name'] == 'narrow' and made['confirmed'] is False,
             'adding a profile: 201 with PROFILE plus agent_id and server', status, made)
        status, again = api.call('POST', path, body)
        need(status == 200 and again['name'] == 'narrow' and again['created_at'] == made['created_at'],
             'an identical repeat returns 200 with the existing profile', status, again)
        status, _ = api.call('POST', path, {**body, 'args': ['other']})
        need(status == 409, 'a different profile of the same name returns 409', status)
        for bad, why in (({**body, 'name': 'nullargs', 'args': None}, 'args null is 400'),
                         ({**body, 'name': 'nofile', 'env_file': str(self.root / 'missing.env')},
                          'a missing env_file is 400'),
                         ({**body, 'name': 'Bad.Name'}, 'an invalid name is 400'),
                         ({**body, 'name': 'extra', 'extra': 1}, 'an invalid body is 400')):
            status, _ = api.call('POST', path, bad)
            need(status == 400, why, status)
        status, _ = api.call('POST', f"/v1/agents/{self.aid['cc']}/tool-servers/needy/profiles",
                             {'name': 'x', 'env_file': str(self.profile_env)})
        need(status == 400, 'a server that is not shareable is 400', status)
        for where in (f"/v1/agents/{self.aid['cc']}/tool-servers/nosuch/profiles",
                      f"/v1/agents/agent_{'0' * 32}/tool-servers/lit/profiles"):
            status, _ = api.call('POST', where, {'name': 'x', 'env_file': str(self.profile_env)})
            need(status == 404, 'an unknown agent or server is 404', where, status)
        status, made = api.call('POST', path, {'name': 'noargs', 'env_file': str(self.profile_env)})
        need(status == 201, 'args is optional', status, made)
        # Recording a confirmation, then allow without --yes or a terminal.
        need(self.servers('cc')['paged']['confirmed'] is False, 'paged is not confirmed yet')
        status, body = api.call('POST', f"/v1/agents/{self.aid['cc']}/tool-servers/paged/confirmations",
                                {'profile': None})
        need(status == 200 and set(body) == {'agent_id', 'server', 'profile', 'confirmed_at'} and
             body['server'] == 'paged' and body['profile'] is None, 'recording a confirmation', status, body)
        need(self.servers('cc')['paged']['confirmed'] is True, 'confirmations appear as confirmed in GET /v1/tools')
        status, body = api.call('POST', f"/v1/agents/{self.aid['cc']}/tool-servers/lit/confirmations",
                                {'profile': 'narrow'})
        need(status == 200 and body['profile'] == 'narrow', 'a profile confirmation', status, body)
        need({x['name']: x for x in self.servers('cc')['lit']['profiles']}['narrow']['confirmed'] is True,
             'a profile confirmation appears on the PROFILE')
        self.allowed('rhea', '--tools', 'paged', '--agent', 'cc')
        self.deny('rhea', '--tools', 'paged')
        for name in ('narrow', 'noargs'):
            api.cli('tools', 'profile', 'remove', f'lit@{name}', '--agent', 'cc')

        def self_call(tool, arguments, target='pat/cc/fx@acme'):
            code, out, stderr = self.call('p2', target, tool, arguments)
            need(code == 0, f'self call {target} {tool}', code, out, stderr[-300:])
            return first_text(out['result'])
        need(self_call('env_matches', {'name': 'FX_CAPTURED', 'sha256': sha(self.secrets['profile'])}) ==
             {'present': True, 'matches': True},
             "a profile instance receives its own environment file, which comes last")
        need(self_call('env_matches', {'name': 'PROFILE_ONLY', 'sha256': sha('unnamed')}) ==
             {'present': True, 'matches': True},
             'a profile\'s own --env-file is applied whole, unfiltered')
        need(self_call('info', {})['labels'] == ['acme'], "--arg replaces the server's args")
        need(self_call('env_matches', {'name': 'FX_CAPTURED', 'sha256': sha(self.secrets['captured'])},
                       'pat/cc/fx') == {'present': True, 'matches': True},
             'the bare server does not get the profile environment')
        need(self_call('info', {}, 'pat/cc/fx')['labels'] == ['local'], 'the bare server keeps its args')
        need({e['pid'] for e in f.calls('fx-acme')}.isdisjoint({e['pid'] for e in f.calls('fx-local')}),
             'a profile runs a separate instance')
        # A share of a profile does not match the bare server.
        self.allowed('rhea', '--tools', 'fx@acme', '--agent', 'cc', '--yes')
        self.synced(self.version(), 'r')
        status, _ = self.submit('r', self.body('cc', 'fx', 'echo', {'text': 'bare'}, profile=None,
                                               cite=self.policy_cite()))
        need(status == 403, 'a share of a profile does not match the bare server', status)
        status, record = self.submit('r', self.body('cc', 'fx', 'echo', {'text': 'profile'}, profile='acme',
                                                    cite=self.policy_cite()))
        need(status == 200, 'the profile share', status, record)
        status, record = self.submit('r', self.body('cc', 'fx', uri='file:///srv/docs/a.txt', profile='acme',
                                                    cite=self.policy_cite()))
        need(status == 200, 'SERVER@PROFILE shares the profile\'s resources', status, record)
        status, _ = self.submit('r', self.body('cc', 'fx', uri='file:///srv/docs/a.txt', cite=self.policy_cite()))
        need(status == 403, 'but not the bare server\'s', status)
        code, out, stderr = self.call('q1', 'pat/cc/fx@acme', 'write_note', {'text': 'by profile'}, '--network',
                                      self.team)
        need(code == 0 and out['status']['state'] == 'succeeded', 'a write tool through a profile share', code, out)
        status, _ = self.submit('q1', self.body('cc', 'fx', 'write_note', {'text': 'x'}, cite=self.policy_cite()))
        need(status == 403, 'the write tool on the bare server stays refused', status)
        # Removal: shares stop matching.
        out = self.hosts['p1'].cli('tools', 'profile', 'remove', 'fx@acme', '--agent', 'cc')
        status, _ = self.submit('r', self.body('cc', 'fx', 'echo', {'text': 'gone'}, profile='acme',
                                               cite=self.policy_cite()))
        need(status in (403, 404), 'after tools profile remove, shares naming it stop matching', status)
        need(self.servers('cc')['fx']['profiles'] == [], 'the profile is removed')
        kinds = {e['kind'] for e in self.activity('p1')}
        need({'tools.profile_added', 'tools.profile_removed'} <= kinds, 'profile activity', sorted(kinds))
        self.deny('rhea', '--tools', 'fx@acme')

    def check_snapshots(self):
        f = self.fixture
        servers = self.servers('cc')
        paged = servers['paged']
        tools = self.snapshot_tools(paged)
        need({f'gen_{n:04d}' for n in range(10)} <= set(tools) and len(tools) == 21,
             'Snapshots follow nextCursor across tools/list pages', sorted(tools))
        need(len(self.snapshot_resources(paged)) == 4, 'and across resources/list pages', paged)
        need(len([e for e in f.entries('paged') if e['event'] == 'list' and e['kind'] == 'tools']) >= 7,
             'the fixture served several pages', len(f.entries('paged')))
        before = self.snapshot_tools(servers['slow'])
        for control, why in (({'list_error': True}, 'a failing tools/list'),
                             ({'huge_snapshot': True}, 'a snapshot larger than 1 MiB'),
                             ({'generate': 1001, 'page_size': 100}, 'following nextCursor beyond 1,000 entries'),
                             ({'list_delay': 40}, 'the 30-second bound')):
            f.set('slow', **control)
            started = time.monotonic()
            self.refresh('cc')
            elapsed = time.monotonic() - started
            slow = self.servers('cc')['slow']
            need(slow['snapshot_error'], f'{why} records snapshot_error', slow['snapshot_error'])
            if 'generate' in control:
                need('too_many_entries' in str(slow['snapshot_error']), 'the entry cap error is too_many_entries',
                     slow['snapshot_error'])
            need(self.snapshot_tools(slow) == before, f'{why} keeps the previous snapshot', slow)
            if 'list_delay' in control:
                need(28 <= elapsed <= 60, 'the whole snapshot must finish within 30 seconds', elapsed)
        f.set('slow')
        self.refresh('cc')
        need(self.servers('cc')['slow']['snapshot_error'] is None, 'a successful snapshot clears snapshot_error',
             self.servers('cc')['slow']['snapshot_error'])
        events = [e for e in self.activity('p1') if e['kind'] == 'tools.snapshot_failed']
        need(any(e['subject_id'] == f"{self.aid['cc']}/slow" for e in events),
             'tools.snapshot_failed activity, subject AGENT_ID/SERVER', events[-3:])

    def check_configuration_changes(self):
        self.clear('rhea')
        f, ids = self.fixture, self.ids
        # A server dropped from configuration: a running call finishes; new calls are refused as unknown.
        marker = 'dropped-' + secrets.token_hex(4)
        code, out, stderr = self.call('p2', 'pat/cc/gone', 'sleep', {'seconds': 10, 'text': marker}, wait='1s')
        need(code == 3, 'setup: a running call on gone', code, out, stderr[-300:])
        wait_for(lambda: f.calls('gone', marker), timeout=20, message='running')
        status, body = self.hosts['p1'].call('POST', f"/v1/agents/{self.aid['cc']}/tool-servers/gone/confirmations",
                                             {'profile': None})
        need(status == 200, 'setup: a confirmation for gone', status, body)
        gone = self.local_servers.pop('gone')
        self.write_claude_json()
        self.refresh('cc')
        need('gone' not in self.servers('cc'), 'a PUT that drops a server deletes its definition')
        final = self.settle('p2', out, timeout=40)
        need(final['status']['state'] == 'succeeded', 'calls already running on a dropped server finish', final)
        status, _ = self.submit('p2', self.body('cc', 'gone', 'echo', {'text': 'x'}, cite=self.self_cite()))
        need(status == 404, 'new calls to a dropped server are refused as unknown (404)', status)
        code, out, stderr = self.call('p2', 'pat/cc/gone', 'echo', {'text': 'x'})
        need(code != 0, 'call to a dropped server fails', code)
        self.local_servers['gone'] = gone
        self.write_claude_json()
        self.refresh('cc')
        need(self.servers('cc')['gone']['confirmed'] is False,
             'a dropped server loses its reach confirmations, so a returning server asks again')
        # A new tool: shared under `readonly` only when read-only, and never under named tools.
        f.set('fx-local', extra_tools=[{'name': 'new_ro', 'read_only': True}, {'name': 'new_rw', 'read_only': False}])
        self.allowed('rhea', '--tools', 'fx:echo', '--agent', 'cc', '--yes')
        self.synced(self.version(), 'q1', 'r')
        self.refresh('cc')
        try:
            q = self.listed_tools('p1', 'q1', 'cc', 'fx')
            need('new_ro' in q and 'new_rw' not in q, 'a new read-only tool is shared under readonly; a new write '
                 'tool is not', sorted(q))
            r = self.listed_tools('p1', 'r', 'cc', 'fx')
            need(set(r) == {'echo'}, 'a new tool is not shared under named tools', sorted(r))
            status, _ = self.submit('q1', self.body('cc', 'fx', 'new_ro', {}, cite=self.policy_cite()))
            need(status == 200, 'the new read-only tool is callable under readonly', status)
            status, _ = self.submit('q1', self.body('cc', 'fx', 'new_rw', {}, cite=self.policy_cite()))
            need(status == 403, 'the new write tool is refused', status)
            status, _ = self.submit('r', self.body('cc', 'fx', 'new_ro', {}, cite=self.policy_cite()))
            need(status == 403, 'the new tool is refused under named tools', status)
            status, _ = self.submit('q1', self.body('cc', 'fx', 'not_in_snapshot', {}, cite=self.policy_cite()))
            need(status == 404, 'a tool missing from the snapshot is 404', status)
        finally:
            f.set('fx-local')
            self.refresh('cc')
            self.deny('rhea', '--tools', 'fx')

    def check_owner_cli(self):
        ids, q1 = self.ids, self.hosts['q1']
        # Exit codes, and --wait.
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'zero'}, '--network', self.team)
        need(code == 0 and set(out) == OUTBOUND_KEYS, 'call: exit 0 for succeeded, printing the local record', code,
             out and sorted(out))
        need(out['target'] == 'pat/cc/fx' and out['network_id'] == self.team and 'grant_id' not in out['request'],
             'the outbound record keeps the target and the network of its citation; no grant_id', out)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'tool_error', {}, '--network', self.team)
        need(code == 1 and out['status']['state'] == 'failed', 'call: exit 1 for other final states', code, out)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'sleep', {'seconds': 6, 'text': 'pending'}, '--network',
                                      self.team, wait='0')
        need(code == 3, 'call: exit 3 if still pending (--wait 0)', code, out)
        pending = out
        for wait in ('1', '1s', '1m'):
            code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'w'}, '--network', self.team, wait=wait)
            need(code == 0, '--wait takes N, Ns, or Nm', wait, code, stderr[-200:])
        count = self.outbound_count('q1')
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'w'}, '--network', self.team, wait='16m')
        need(code != 0 and self.outbound_count('q1') == count, '--wait is at most 15 minutes', code)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'd'}, '--network', self.team,
                                      '--deadline', '5m')
        left = (parse_time(out['request']['deadline']) - datetime.now(timezone.utc)).total_seconds() if out else 0
        need(code == 0 and 240 <= left <= 300, 'the CLI\'s --deadline also accepts a duration', code, out and
             out['request'])
        code, out, stderr = self.read('q1', 'pat/cc/fx', 'fixture://docs/readme', '--network', self.team)
        need(code == 0 and out['status']['kind'] == 'resource', 'read: exit 0', code, out)
        code, out, stderr = self.read('q1', 'pat/cc/fx', 'fixture://docs/missing', '--network', self.team)
        need(code != 0, 'a resource call must name a URI present in the snapshot', code, out)
        # POST /v1/calls directly.
        count = self.outbound_count('q1')
        for deadline in (timestamp(-5), timestamp(16 * 60)):
            status, body = q1.call('POST', '/v1/calls', {'target': 'pat/cc/fx', 'kind': 'tool', 'name': 'echo',
                                                         'arguments': {'text': 'x'}, 'deadline': deadline,
                                                         'network': self.team})
            need(status == 400, 'POST /v1/calls refuses a past deadline or one over 15 minutes, before persisting',
                 deadline, status, body)
        need(self.outbound_count('q1') == count, 'nothing persisted')
        status, body = q1.call('POST', '/v1/calls', {'target': 'pat/cc/fx', 'kind': 'tool', 'name': 'echo',
                                                     'arguments': {'text': 'api'}, 'deadline': timestamp(300),
                                                     'network': self.team, 'uri': None, 'call_id': None})
        need(status == 200 and set(body) == OUTBOUND_KEYS and body['network_id'] == self.team,
             'POST /v1/calls returns 200 with the outbound record (null fields treated as absent)', status, body)
        # Listings.
        listed = q1.cli('calls', 'list', '--limit', '1000')
        need(listed and all(set(item) == {'sequence', 'call'} and set(item['call']) == OUTBOUND_KEYS
                            for item in listed), 'GET /v1/calls returns [{sequence, call}]', listed[:1])
        need([item['sequence'] for item in listed] == sorted(item['sequence'] for item in listed),
             'insertion order', [i['sequence'] for i in listed])
        need(pending['request']['call_id'] in {i['call']['request']['call_id'] for i in listed},
             'calls list shows outbound calls')
        need(len(q1.cli('calls', 'list', '--limit', '1')) == 1, 'calls list --limit')
        after = q1.cli('calls', 'list', '--after', str(listed[-2]['sequence']))
        need(len(after) == 1 and after[0]['sequence'] == listed[-1]['sequence'], 'calls list --after', after)
        received = self.hosts['p1'].cli('calls', 'received', '--limit', '1000')
        need(received and all(set(item) == {'sequence', 'request', 'status'} for item in received),
             'GET /v1/calls/received returns [{sequence, request, status}]', received[-1:])
        need(pending['request']['call_id'] in {i['status']['call_id'] for i in received},
             'calls received lists calls received', received[-1:])
        need(self.inspect('q1', ids['p1'], pending['request']['call_id'])['request']['call_id'] ==
             pending['request']['call_id'], 'calls inspect')
        # tools remote, and GET /v1/remote-tools.
        status, body = q1.call('GET', '/v1/remote-tools?target=pat')
        need(status == 200 and set(body) == {'entries', 'unanswered'} and body['entries'] and
             all(set(e) == REMOTE_ENTRY_KEYS for e in body['entries']),
             'GET /v1/remote-tools returns {entries: [{host_id, address, agent, agent_id, server, profile, tools, '
             'resources}], unanswered}', status, str(body)[:500])
        fx = [e for e in body['entries'] if e['agent'] == 'cc' and e['server'] == 'fx' and e['profile'] is None]
        need(len(fx) == 1 and fx[0]['host_id'] == ids['p1'] and fx[0]['agent_id'] == self.aid['cc'],
             'remote tools: cc/fx on p1', fx)
        status, body = q1.call('GET', f'/v1/remote-tools?target=pat/cc/fx&network={self.team}')
        need(status == 200 and {(e['agent'], e['server']) for e in body['entries']} == {('cc', 'fx')},
             'target PERSON/AGENT/SERVER', status, body)
        status, body = q1.call('GET', f'/v1/remote-tools?target=pat&network={self.team}')
        need(status == 200 and not [e for e in body['entries'] if e['server'] == 'lit'],
             'tools remote --network: a tool authorized only in another network is not listed', body)
        status, body = q1.call('GET', '/v1/remote-tools')
        need(status == 200 and {e['host_id'] for e in body['entries']} <= {ids[n] for n in self.team_members},
             'without a target, the members of the selected networks', status, str(body)[:300])
        code, out, stdout, stderr = q1.outcome('tools', 'remote', 'pat/cc', '--json')
        status, body = q1.call('GET', '/v1/remote-tools?target=pat/cc')
        need(code == 0 and out == body, 'tools remote --json prints the GET /v1/remote-tools object as is', code,
             stdout[:300], str(body)[:300])
        code, out, stdout, stderr = q1.outcome('tools', 'remote')
        need(code == 0 and 'fx' in stdout, 'tools remote readable output', code)
        # Citation by --network and via order.
        count = self.outbound_count('q1')
        code, out, stderr = self.call('q1', 'pat/cc/lit', 'echo', {'text': 'x'}, '--network', self.team)
        need(code != 0 and self.outbound_count('q1') == count,
             '--network scoping: a tool authorized only in another network is neither listed nor cited', code)
        code, out, stderr = self.call('q1', 'pat/cc/lit', 'echo', {'text': 'x'})
        need(code == 0 and out['network_id'] == self.other and
             out['request']['policy']['version'] == self.version('p1', self.other),
             'without --network, the first via entry (the other network\'s policy)', code, out)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'x'})
        need(code == 0 and out['network_id'] == min(self.team, self.other) and 'policy' in out['request'],
             'via order decides the citation: the policy of the lower network ID', out and out['network_id'])
        for net in (self.team, self.other):
            code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'x'}, '--network', net)
            need(code == 0 and out['network_id'] == net and
                 out['request']['policy']['version'] == self.version('p1', net), '--network cites that network',
                 net, out and out['request'])
        # Target resolution: by host ID, ambiguous, and not found.
        code, out, stderr = self.call('q1', f"{ids['p1']}/cc/fx", 'echo', {'text': 'by host'})
        need(code == 0 and out['peer_host_id'] == ids['p1'], 'HOST_ID/AGENT/SERVER names a host directly', code)
        for host in ('p1', 'p2'):
            self.hosts[host].cli('agent', 'register', '--name', 'dup', '--owner', 'pat')
            self.aid[f'dup@{host}'] = next(a['id'] for a in self.hosts[host].cli('agent', 'list') if a['name'] == 'dup')
            self.aid['dup'] = self.aid[f'dup@{host}']
            self.put_servers(host, 'dup', self.root, {'fx': self.fixture.args(f'dup-{host}')})
        self.allowed('quinn', '--tools', 'fx', '--agent', 'dup', '--yes')
        self.sync_all()
        count = self.outbound_count('q1')
        status, body = q1.call('POST', '/v1/calls', {'target': 'pat/dup/fx', 'kind': 'tool', 'name': 'echo',
                                                     'arguments': {}, 'deadline': timestamp(300)})
        need(status == 409 and body.get('code') == 'ambiguous' and
             sorted(body.get('candidates') or []) == sorted([f"{ids['p1']}/dup/fx", f"{ids['p2']}/dup/fx"]),
             '409 {code: "ambiguous", error, candidates: [HOST_ID/AGENT/SERVER]}', status, body)
        code, out, stderr = self.call('q1', 'pat/dup/fx', 'echo', {'text': 'x'})
        need(code != 0 and self.outbound_count('q1') == count, 'call: an ambiguous target persists nothing', code)
        code, out, stderr = self.call('q1', f"{ids['p2']}/dup/fx", 'echo', {'text': 'x'})
        need(code == 0, 'the HOST_ID form resolves the ambiguity', code, stderr[-300:])
        self.hosts['p3'].stop()
        try:
            count = self.outbound_count('q1')
            status, body = q1.call('POST', '/v1/calls', {'target': 'pat/nosuch/fx', 'kind': 'tool', 'name': 'echo',
                                                         'arguments': {}, 'deadline': timestamp(300)})
            need(status == 404 and body.get('code') == 'not_found' and
                 ids['p3'] in [u['host_id'] for u in body.get('unanswered') or []] and
                 all(set(u) == {'host_id', 'error'} for u in body['unanswered']),
                 '404 {code: "not_found", error, unanswered: [{host_id, error}]}', status, body)
            status, body = q1.call('POST', '/v1/calls', {'target': 'pat/cc/fx', 'kind': 'tool', 'name': 'echo',
                                                         'arguments': {}, 'deadline': timestamp(300)})
            need(status >= 400 and self.outbound_count('q1') == count,
                 'an unanswered host refuses the call with nothing persisted, even with one match', status, body)
            status, body = q1.call('GET', '/v1/remote-tools?target=pat')
            need(status == 200 and ids['p3'] in [u['host_id'] for u in body['unanswered']],
                 'remote tools lists unanswered hosts', status, body)
        finally:
            self.hosts['p3'].start()
        self.deny('quinn', '--tools', 'fx', '--agent', 'dup')

    def check_status(self):
        f, ids = self.fixture, self.ids
        status = self.attention()
        tools = status.get('tools')
        need(isinstance(tools, dict) and set(tools) == {'servers', 'shared_servers', 'calls_running'},
             'GET /v1/status: tools {servers, shared_servers, calls_running}', tools)
        # servers: discovered for agents on this host, profiles excluded. shared_servers: servers and profiles on
        # this host that a tool rule in this person's stored policies names. calls_running: received calls running.
        view = self.tools_view('p1')
        servers = sum(len(a['servers']) for a in view['agents'])
        rules = [r for net in (self.team, self.other, self.v1net) for r in self.tool_rules(net)]
        shared = 0
        for a in view['agents']:
            for server in a['servers']:
                for name in [server['name']] + [f"{server['name']}@{x['name']}" for x in server['profiles']]:
                    if any(r['server'] == name and r['agent'] in (a['agent']['name'], '*') for r in rules):
                        shared += 1
        running = sum(1 for item in self.hosts['p1'].cli('calls', 'received', '--limit', '1000')
                      if item['status']['state'] == 'running')
        need((tools['servers'], tools['shared_servers'], tools['calls_running']) == (servers, shared, running),
             'status tools counts: servers (profiles excluded), shared_servers, calls_running', tools,
             (servers, shared, running))
        b = self.body('cc', 'fx', 'sleep', {'seconds': 6, 'text': 'counted'}, cite=self.self_cite())
        self.submit('p2', b)
        self.state_is('p2', b['call_id'], 'running', timeout=20)
        need(self.attention()['tools']['calls_running'] >= 1, 'calls_running counts a running received call',
             self.attention()['tools'])
        self.final('p2', b['call_id'])
        command = 'peerspan tools refresh --agent cc'
        # A failed snapshot.
        f.set('slow', list_error=True)
        self.refresh('cc')
        # A start failure (exit at start), and a start that does not complete initialize within 30 seconds.
        f.set('startfail', exit_on_start=True)
        b = self.body('cc', 'startfail', 'echo', {'text': 'x'}, cite=self.self_cite())
        self.submit('p2', b)
        done = self.final('p2', b['call_id'], timeout=90)
        need(done['state'] == 'failed' and done['error'] == 'server_start_failed', 'a start failure fails waiting '
             'calls with server_start_failed', done)
        f.set('startslow', init_delay=40)
        b = self.body('cc', 'startslow', 'echo', {'text': 'x'}, cite=self.self_cite())
        started = time.monotonic()
        self.submit('p2', b)
        done = self.final('p2', b['call_id'], timeout=90)
        need(done['state'] == 'failed' and done['error'] == 'server_start_failed' and
             28 <= time.monotonic() - started <= 80, 'initialize not completed within 30 seconds: server_start_failed',
             done, time.monotonic() - started)
        # An authentication-looking JSON-RPC error.
        b = self.body('cc', 'fx', 'fail', {'message': '401 Unauthorized: invalid TOKEN'}, cite=self.self_cite())
        self.submit('p2', b)
        need(self.final('p2', b['call_id'])['error'] == 'jsonrpc_error', 'setup: an auth-looking JSON-RPC error')
        # The environment file.
        env_file = self.hosts['p1'].config / 'peerspan' / 'env'
        env_file.write_text('A=b\n')
        env_file.chmod(0o640)
        try:
            servers = self.servers('cc')
            need(servers['startfail']['start_failed_at'] and servers['startslow']['start_failed_at'] and
                 servers['fx']['auth_error_at'] and servers['slow']['snapshot_error'],
                 'GET /v1/tools records start_failed_at, auth_error_at, and snapshot_error',
                 {k: (servers[k]['start_failed_at'], servers[k]['auth_error_at'], servers[k]['snapshot_error'])
                  for k in ('startfail', 'startslow', 'fx', 'slow')})
            items = self.items()
            subjects = [i['subject'] for i in items]
            for subject in ('cc/slow', 'cc/startfail', 'cc/startslow', 'cc/fx'):
                need(subject in subjects, 'attention item 14 tool_server_failing for each cause', subject, items)
                item = next(i for i in items if i['subject'] == subject)
                need(item['command'] == command, 'item 14 command: peerspan tools refresh --agent AGENT_NAME', item)
            need('env' in subjects and next(i for i in items if i['subject'] == 'env')['command'] ==
                 f'chmod 600 {env_file}', 'item 14 for the environment file', items)
            need(subjects == sorted(subjects), 'within one kind, items are sorted by subject', subjects)
            kinds = [i['kind'] for i in self.attention()['attention']]
            need(kinds[-len(items):] == ['tool_server_failing'] * len(items), 'item 14 follows items 1 to 13', kinds)
            code, out, stdout, stderr = self.hosts['p1'].outcome('status', '--json')
            need(code == 1, 'status exits 1 with attention items', code)
        finally:
            env_file.unlink()
            for key in ('slow', 'startfail', 'startslow'):
                f.set(key)
            self.refresh('cc')

    def check_tie_break(self):
        p1, p2 = self.hosts['p1'], self.hosts['p2']
        self.coord.stop()
        try:
            p2.stop()
            x = self.allowed('rhea', '--tools', 'lit', '--agent', 'cc', '--yes')['policy']
            p1.stop()
            p2.start()
            y = p2.cli('allow', 'rhea', '--agent', 'tiebreak', '--network', self.team)['policy']
            need(x['version'] == y['version'] and x['signature'] != y['signature'], 'two v2 policies of one version',
                 x['version'], y['version'])
            winner = min((x, y), key=policy_hash)
            p1.start()
            for h in (p1, p2, p1):
                h.run('access', 'sync', '--network', self.team)
            for name in ('p1', 'p2'):
                wait_for(lambda: self.policy(name) == policy_of(winner), timeout=30,
                         message=f'tie-break convergence on {name}')
            view = p1.cli('access', 'sync', '--network', self.team, '--status')
            need(view['sha256'] == policy_hash(winner), 'the tie-break hashes the v2 lines', view, policy_hash(winner))
        finally:
            if p1.process is None or p1.process.poll() is not None:
                p1.start()
            if p2.process is None or p2.process.poll() is not None:
                p2.start()
            self.coord.start()

    def watch_idle(self):
        """At 9 minutes after the idle server's only call, note whether its instance is still running."""
        time.sleep(540)
        self.idle_alive_at_9 = any(e['event'] == 'start' for e in self.fixture.entries('idle')) and not any(
            e['event'] == 'exit' for e in self.fixture.entries('idle')) and self.pid_alive()

    def pid_alive(self):
        starts = [e for e in self.fixture.entries('idle') if e['event'] == 'start']
        if not starts:
            return False
        try:
            os.kill(starts[-1]['pid'], 0)
            return True
        except OSError:
            return False

    def check_idle_stop(self):
        need(self.idle_started, 'setup: one call to the idle server', self.setup_notes)
        remaining = self.idle_started + 660 - time.time()
        if remaining > 0:
            time.sleep(remaining)
        need(getattr(self, 'idle_alive_at_9', None) is True, 'an instance with calls in the last 10 minutes keeps '
             'running (alive 9 minutes after its last call)', getattr(self, 'idle_alive_at_9', None))
        need(not self.pid_alive(), 'An instance with no calls for 10 minutes is stopped')
        exits = [e for e in self.fixture.entries('idle') if e['event'] == 'exit']
        if exits:
            need(exits[-1]['time'] - self.idle_started >= 590, 'not stopped before 10 minutes', exits[-1])

    def close(self):
        try:
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()


# --- once per run --------------------------------------------------------------------------------------------

V2_VECTOR_LINES = """peerspan-policy-v2
net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e
bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=
1
2026-10-10T00:00:00Z
2026-10-17T00:00:00Z
rule
reviewer
person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2 group:backend
message.append
65536 false
rule
triage
network
message.append
4096 true
tool_rule
reviewer
github
person:person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2
tool.call resource.read
readonly
65536 false 100
end
tool_rule
*
github@acme-api
group:backend
tool.call
create_issue list_issues
4096 true 10
end
trusted host_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
host_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""".replace(' \\\n', ' ').split('\n')
V2_VECTOR_SIGNATURE = ('U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNw'
                       'YW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQN3R+JpYFSWwJYDv5TPcPhxvjwoOUVpE'
                       'rPzSlzkRC3DfkaZYNtdsjUSgm0C3KvvXJtNSlozD1UJ894T6bomQvgE=')
V2_VECTOR_HASH = '84e7e3312f15fa07d06aee1a9bb8953f01d47602ba3439b25bc656a9d4d01729'


def check_vector(directory):
    """Reproduce the coordination contract's v1 policy vector and the tools contract's v2 vector with this suite's
    encoding and signing."""
    from coord_move import sshsig
    from launch_service import Key
    person = Key(directory, base64.b64decode('BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU='))
    need(person.b64 == 'bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=', 'the vector person key')
    network = 'net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e'
    second = 'person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2'
    v1 = {'network_id': network, 'person_public_key': person.b64, 'version': 1, 'issued_at': '2026-10-10T00:00:00Z',
          'valid_until': '2026-10-17T00:00:00Z',
          'rules': [{'agent': 'reviewer', 'principals': [f'person:{second}', 'group:backend'],
                     'actions': ['message.append'], 'max_message_bytes': 65536, 'allow_disconnected': False},
                    {'agent': 'triage', 'principals': ['network'], 'actions': ['message.append'],
                     'max_message_bytes': 4096, 'allow_disconnected': True}]}
    need(sshsig(person, policy_lines_v1(v1)) ==
         'U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQI7LAL0jJtpQWmoMSHjIs49S3ZgRu1H8/I7LHRJ/N58B81ZTDeV854NluBUedCUW8GgzjOOTHLEM5pfE/iGPog8=',
         'self-check: the v1 policy test vector')
    # The v2 vector: trusted hosts given b then a, sorted in the statement.
    v2 = {'format': 2, **v1,
          'tool_rules': [{'agent': 'reviewer', 'server': 'github', 'principals': [f'person:{second}'],
                          'actions': ['tool.call', 'resource.read'], 'scope': ['readonly'], 'max_input_bytes': 65536,
                          'allow_disconnected': False, 'max_calls_per_hour': 100},
                         {'agent': '*', 'server': 'github@acme-api', 'principals': ['group:backend'],
                          'actions': ['tool.call'], 'scope': ['create_issue', 'list_issues'], 'max_input_bytes': 4096,
                          'allow_disconnected': True, 'max_calls_per_hour': 10}],
          'trusted_hosts': ['host_' + 'b' * 64, 'host_' + 'a' * 64]}
    lines = policy_lines_v2(v2)
    need(lines == V2_VECTOR_LINES, 'the v2 test vector statement lines', lines)
    need(hashlib.sha256('\n'.join(lines).encode()).hexdigest() == V2_VECTOR_HASH, 'the v2 test vector statement hash')
    need(sshsig(person, lines) == V2_VECTOR_SIGNATURE, 'the v2 test vector signature')
    ssh_public = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx'
    ssh_verify(lines, V2_VECTOR_SIGNATURE, ssh_public, directory)
    return 'v1 and v2 vectors reproduced; the v2 signature verifies with ssh-keygen'


def check_migration(original, replacement, label):
    """Version 15 (the tool tables dropped) to 16, and 17 refused."""
    with tempfile.TemporaryDirectory(prefix='peerspan-tools-migration-') as directory:
        host = Host(original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == 16, 'Database version 16', label)
            host.stop()
            connection = sqlite3.connect(host.state / 'host.db')
            try:
                for table in TOOL_TABLES:
                    connection.execute(f'DROP TABLE {table}')
                connection.execute('PRAGMA user_version = 15')
                connection.commit()
            finally:
                connection.close()
            host.binary = str(replacement)
            need(host.start()['id'] == identity['id'], 'the identity survives migration')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == 16, 'migrated to version 16')
            tables = {r[0] for r in db_rows(host, "SELECT name FROM sqlite_master WHERE type = 'table'")}
            need(set(TOOL_TABLES) <= tables, 'version 16 adds the tool tables', sorted(tables))
            need(host.cli('agent', 'inspect', agent['id']) == agent, 'existing state preserved')
            need(host.cli('calls', 'list') == [], 'no calls after migration')
            host.stop()
            connection = sqlite3.connect(host.state / 'host.db')
            connection.execute('PRAGMA user_version = 17')
            connection.commit()
            connection.close()
            for binary in (original, replacement):
                result = subprocess.run([str(binary), '--state', str(host.state), 'run'], capture_output=True,
                                        timeout=10)
                need(result.returncode != 0, 'version 16 binaries reject version 17', binary)
            need(db_rows(host, 'PRAGMA user_version')[0][0] == 17, 'refused without changes')
        finally:
            stop_all((host,))
    return label


def once(name, function, *args):
    try:
        notes = function(*args)
        print(f'PASS [{name}]: {notes}', flush=True)
        return []
    except Exception as error:
        detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=4)
        print(f'FAIL [{name}]: {detail}', flush=True)
        return [f'[{name}]: {detail.strip().splitlines()[-1] if detail.strip() else ""}']


def run_pairing(coord_binary, cli_binary, daemon_binary, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-tools-') as temporary:
        pairing = Pairing(label, cli_binary, daemon_binary, coord_binary, Path(temporary))
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [setup]: {detail}', flush=True)
            if getattr(pairing, 'setup_notes', None):
                print(f'NOTE {label} setup: ' + ' | '.join(pairing.setup_notes), flush=True)
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
    parser.add_argument('--probe', type=Path, required=True, help='peerspan-peer-probe test client')
    parser.add_argument('--pairing', action='append', help='CLI/DAEMON, such as Go/Rust; repeatable; default all four')
    parser.add_argument('--skip-migration', action='store_true', help='skip the version 15 to 16 migration checks')
    args = parser.parse_args()
    for tool in ('ssh-agent', 'ssh-add', 'ssh-keygen', 'openssl'):
        if not shutil.which(tool):
            parser.error(f'{tool} is required')
    set_probe(args.probe.resolve(strict=True))
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve() if args.rust else None}
    pairings = args.pairing or [f'{c}/{d}' for c in binaries for d in binaries]
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        if cli not in binaries or daemon not in binaries:
            parser.error(f'unknown pairing {pairing}')
        if binaries[cli] is None or binaries[daemon] is None:
            parser.error(f'pairing {pairing} needs --rust')
    failures = []
    with tempfile.TemporaryDirectory(prefix='peerspan-tools-vector-') as directory:
        failures += once('policy v2 vector', check_vector, Path(directory))
    if not args.skip_migration:
        available = [name for name, binary in binaries.items() if binary]
        for first in available:
            for second in available:
                failures += once(f'migration {first}→{second}', check_migration, binaries[first], binaries[second],
                                 f'{first} state opened by {second}')
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        label = f'{cli} CLI, {daemon} daemon'
        for name, ok, detail in run_pairing(args.coord.resolve(), binaries[cli], binaries[daemon], label):
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
