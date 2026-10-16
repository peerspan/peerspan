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
u1 and u2 (members bound to no person); n (a manually configured peer in no network, holding only grants).
Networks: team (everyone but n), other (p1, p2 untrusted, q1), and v1net (p1, for a v1 policy).

Each pairing reports these sections separately (contract Verification items in brackets):
- trust at create and join: --trusted/--untrusted, the terminal prompt, no terminal meaning no, `trusted`
  in the output, and trusted_hosts in the next policy [trust/untrust: the join prompt and flags];
- discovery: each harness's sources and precedence, remote/disabled/misnamed servers, ${VAR} and
  ${VAR:-DEFAULT} captured and missing ones reported, an unparsable source in `errors`, `tools`
  [Discovery];
- allow --tools: each SPEC form, one rule per local agent, refusal with no such server, --agent '*' with
  --yes and its warning, write tools without a profile, unshareable servers, reach confirmation (terminal,
  --yes, neither, not asked twice), set semantics, --resources, and deny --tools [allow --tools];
- policy v2: the v2 statement verified with ssh-keygen over this suite's encoding, the JSON shape, coordinator
  acceptance, the other implementation's view through the coordinator, sibling propagation by direct push with
  the coordinator stopped, and a v1 policy accepted and read with no tool rules [Policy v2];
- trust/untrust: network selection and HOST defaulting, refusal for another person's host, and per-network
  trust [trust/untrust];
- authorization: policy, grant, self from a trusted host, self refused from an untrusted host and another
  person's host, the read-only rule under policy and grants but not self, blocks except under self, budgets
  per person and per host for unbound senders, 413, and lapsed authorization before start [Authorization];
- grants: tool and resource grants with scope, input bound, budget, defaults, and ranges [Grants];
- routes: GET /peer/v1/tools filtered by authorization (also ?network=), its shape and via order, reachable by
  a grant-only peer outside any network; call status and cancel 404 for a non-submitter [Routes];
- calls: the lifecycle for tools and resources, isError and JSON-RPC errors, result_too_large, duplicate and
  conflicting submission, a lost submit response recovered by retry with one execution, expiry before start,
  cancellation queued and running, the deadline while running, a daemon restart and a server exit while
  running, concurrency capped at 4, and activity [Calls];
- values: captured values and the environment file reaching the server, the file ignored when too open, a
  literal token, the server's environment by name, and secrets nowhere else [Discovery, Literal values];
- profiles: a profile instance with its own environment file and arguments, a share of a profile not matching
  the bare server, and removal [Profiles];
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
Once per run: the v1 policy test vector reproduced with this suite's encoding and a provisional v2 vector
printed [Policy v2: the generated test vector], and migration from version 15 to 16 in each direction
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

from coordination import Coordinator, wait_for
from host_service import Host, stop_all
from launch_directory import DirectoryHost
from launch_onboarding import DEFAULT, Failure, need
from peer_messaging import DropResponse, fixture_context, set_probe, timestamp, wire
from persons import Agent, coord_db, person_id, ssh_key, ssh_sign, ssh_verify
from policy import policy_lines as policy_lines_v1

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / 'fixtures' / 'mcp' / 'server.py'
HARNESS = HERE / 'fixtures' / 'harness'
PYTHON = str(Path(sys.executable).resolve())

STATUS_KEYS = {'call_id', 'sender_host_id', 'receiver_host_id', 'target_agent_id', 'server', 'profile', 'kind', 'name',
               'uri', 'state', 'cancel_requested', 'error', 'result_bytes', 'created_at', 'started_at', 'finished_at'}
OUTBOUND_KEYS = {'peer_host_id', 'request', 'submit_state', 'status', 'result', 'cancel_state', 'attempts',
                 'next_attempt_at', 'error', 'status_queries'}
ATTACH_SERVER_KEYS = {'name', 'transport', 'shareable', 'reason', 'tools', 'read_only_tools'}
LISTING_KEYS = {'agent', 'agent_id', 'server', 'profile', 'tools', 'resources'}
LISTED_TOOL_KEYS = {'name', 'description', 'input_schema', 'read_only', 'via'}
LISTED_RESOURCE_KEYS = {'uri', 'name', 'description', 'mime_type', 'via'}
TOOL_RULE_KEYS = {'agent', 'server', 'principals', 'action', 'scope', 'max_input_bytes', 'allow_disconnected',
                  'max_calls_per_hour'}
ALLOW_TOOLS_KEYS = {'policy', 'principal', 'rules'}
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
    return ['tool_rule', t['agent'], t['server'], ' '.join(t['principals']), t['action'], ' '.join(t['scope']),
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


def definition(server, key):
    """A definition field of a GET /v1/tools server entry, at its top level or under `definition`."""
    found = [server[key]] if key in server else []
    if isinstance(server.get('definition'), dict) and key in server['definition']:
        found.append(server['definition'][key])
    return found


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

    def run(self, *args, sock=DEFAULT, env=None, argv=None, cwd=None, timeout=90):
        """As DirectoryHost.run, with stdin from /dev/null: no CLI call is at a terminal unless at_terminal."""
        command = argv or [self.cli_binary, '--state', str(self.state), *args]
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                              env=self.environment(sock, env), cwd=cwd, preexec_fn=self.preexec())

    def outcome(self, *args, env=None, cwd=None, timeout=90):
        """(exit code, parsed stdout or None, stdout, stderr)."""
        r = self.run(*args, env=env, cwd=cwd, timeout=timeout)
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

    def allow(self, *args, net=None, host='p1', terminal=None, env=None):
        """`allow` with tool forms. Returns (exit code, output, stderr); a success must sign version + 1."""
        h = self.hosts[host]
        before = self.version(host, net)
        argv = ['allow', *args, '--network', net or self.team]
        if terminal is not None:
            code, out, tty, stdout, seen = h.at_terminal(*argv, answer=terminal, env=env,
                                                         prompt='Anything those credentials can reach through')
            self.last_terminal = (tty, seen)
            stderr = tty
        else:
            code, out, stdout, stderr = h.outcome(*argv, env=env)
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
        """The server entries of one agent in `tools --json` (GET /v1/tools), by server name."""
        view = self.tools_view(host)
        agents = view.get('agents') if isinstance(view, dict) else view
        need(isinstance(agents, list), 'GET /v1/tools: a list of agents', view)
        for a in agents:
            names = {a.get('agent'), a.get('name'), a.get('agent_name'), a.get('agent_id'), a.get('id')}
            if isinstance(a.get('agent'), dict):
                names |= {a['agent'].get('name'), a['agent'].get('id')}
            if agent in names or self.aid.get(agent) in names:
                servers = a.get('servers') or []
                return {s.get('name') or s.get('server'): s for s in servers}
        raise Failure(f'GET /v1/tools: agent {agent} listed: {json.dumps(view)[:800]}')

    @staticmethod
    def snapshot_tools(server):
        tools = server.get('tools')
        if tools is None and isinstance(server.get('snapshot'), dict):
            tools = server['snapshot'].get('tools')
        return {t['name']: t for t in tools or []}

    @staticmethod
    def snapshot_resources(server):
        resources = server.get('resources')
        if resources is None and isinstance(server.get('snapshot'), dict):
            resources = server['snapshot'].get('resources')
        return {r['uri']: r for r in resources or []}

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
        }
        project_servers = {
            'fx': f.claude('fx-project', 'project'),
            'proj': f.claude('proj', 'x', env={'TOKEN_A': '${FX_TOKEN}', 'TOKEN_B': '${FX_UNSET:-fallback-b}'},
                             args=f.args('proj', '${FX_LABEL}', '${FX_UNSET_LABEL:-dflt}')),
        }
        self.local_servers = {
            'fx': f.claude('fx-local', 'local', env={'FX_CAPTURED': '${FX_TOKEN}'}),
            'lit': f.claude('lit', env={'LIT_TOKEN': lit}),
            'needy': f.claude('needy', env={'NEED': '${FX_MISSING_VAR}'}),
            'gone': f.claude('gone'),
            'slow': f.claude('slow'),
            'paged': f.claude('paged', page_size=3, generate=10),
            'budget': f.claude('budget'),
            'budget2': f.claude('budget2'),
            'startfail': f.claude('startfail'),
            'startslow': f.claude('startslow'),
            'sserem': {'type': 'sse', 'url': 'https://example.invalid/sse'},
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
        self.cli_env = {'FX_TOKEN': self.secrets['captured'], 'FX_LABEL': 'fromenv'}
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
        self.profile_env.write_text(f"# the acme profile\nPROFILE_ONLY={self.secrets['profile']}\n"
                                    "FX_CAPTURED=profile-value\n")
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
        self.section('grants', self.check_grants)
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
            (('quinn', '--resources', 'fx:fixture://docs/*', '--agent', 'cc', '--yes'), team),
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

    def check_discovery(self):
        notes = []
        failures = [f'{name}: {code} {stderr[-300:]}' for name, (code, out, stderr) in self.attached.items()
                    if code != 0]
        need(not failures, 'attach --no-start succeeds for each harness', *failures)

        def attach_servers(name):
            out = self.attached[name][1]
            need(isinstance(out.get('tools'), dict) and set(out['tools']) == {'servers', 'errors'},
                 'attach adds tools: {servers, errors}', name, out)
            for s in out['tools']['servers']:
                need(set(s) == ATTACH_SERVER_KEYS, 'attach servers are {name, transport, shareable, reason, tools, '
                     'read_only_tools}', s)
                need(isinstance(s['tools'], int) and isinstance(s['read_only_tools'], int),
                     'tools and read_only_tools are counts', s)
            return {s['name']: s for s in out['tools']['servers']}

        cc = attach_servers('cc')
        expected = {'fx', 'Bad.Name', 'rem', 'proj', 'lit', 'needy', 'gone', 'slow', 'paged', 'budget', 'budget2',
                    'startfail', 'startslow', 'sserem'}
        need(set(cc) == expected, 'Claude Code: user, project, and local scopes discovered for the workspace',
             sorted(cc), sorted(expected))
        need(self.attached['cc'][1]['tools']['errors'] == [], 'no errors when every source parses',
             self.attached['cc'][1]['tools'])
        for name, transport, shareable, reason in (('fx', 'stdio', True, None), ('Bad.Name', 'stdio', False, 'name'),
                                                   ('rem', 'remote', False, 'remote'),
                                                   ('sserem', 'remote', False, 'remote'),
                                                   ('needy', 'stdio', False, 'missing_env'),
                                                   ('proj', 'stdio', True, None), ('lit', 'stdio', True, None)):
            s = cc[name]
            need(s['transport'] == transport and s['shareable'] is shareable and s['reason'] == reason,
                 f'{name}: transport {transport}, shareable {shareable}, reason {reason}', s)
        fx = cc['fx']
        need(fx['tools'] == len(RO_TOOLS | WRITE_TOOLS) + 1 and fx['read_only_tools'] == len(RO_TOOLS) + 1,
             'counts: read_only only for readOnlyHint true (purge has no annotations)', fx)

        servers = self.servers('cc')
        need(set(servers) == expected, 'GET /v1/tools lists the same servers', sorted(servers))
        fx_tools = self.snapshot_tools(servers['fx'])
        need('from_local' in fx_tools and 'from_user' not in fx_tools and 'from_project' not in fx_tools,
             'Precedence: the local scope definition is taken whole', sorted(fx_tools))
        need(set(fx_tools) == RO_TOOLS | WRITE_TOOLS | {'from_local'}, 'the snapshot lists every tool', sorted(fx_tools))
        for name, t in fx_tools.items():
            need(set(t) >= {'name', 'description', 'input_schema', 'read_only'},
                 'stored tool entries are {name, description, input_schema, read_only}', t)
            need(t['read_only'] is (name in RO_TOOLS or name == 'from_local'),
                 'read_only is true only when annotations.readOnlyHint is true', name, t)
        resources = self.snapshot_resources(servers['fx'])
        need(set(resources) == {'fixture://docs/readme', 'fixture://docs/guide', 'file:///srv/docs/a.txt',
                                'file:///srv/private/b.txt'}, 'the snapshot lists resources', sorted(resources))
        for r in resources.values():
            need(set(r) >= {'uri', 'name', 'description', 'mime_type'},
                 'stored resource entries are {uri, name, description, mime_type}', r)
        for source in definition(servers['fx'], 'source'):
            need(source == 'claude-code:local', 'source is INTEGRATION:SCOPE (claude-code:local)', source)
        proj_tools = self.snapshot_tools(servers['proj'])
        need({'from_fromenv', 'from_dflt'} <= set(proj_tools),
             'References: ${NAME} and ${NAME:-DEFAULT} in args resolved from the CLI environment', sorted(proj_tools))
        for env in definition(servers['proj'], 'env'):
            if isinstance(env, dict) and 'TOKEN_A' in env:
                need(env['TOKEN_A'] == {'source': 'captured'} and env['TOKEN_B'] == {'source': 'captured'},
                     'env entries with references are captured', env)
        for env in definition(servers['lit'], 'env'):
            if isinstance(env, dict) and 'LIT_TOKEN' in env:
                need(env['LIT_TOKEN'] == {'source': 'literal'}, 'literal env entries', env)
        for env in definition(servers['needy'], 'env'):
            if isinstance(env, dict) and 'NEED' in env:
                need(env['NEED'] == {'source': 'missing'}, 'unresolved references are missing', env)
        need('FX_MISSING_VAR' in json.dumps(servers['needy']) or 'NEED' in json.dumps(servers['needy']),
             'missing_env names the variables', servers['needy'])

        cc2 = attach_servers('cc2')
        need(set(cc2) == {'fx', 'Bad.Name', 'rem'}, 'Claude Code: only the user scope for another workspace', sorted(cc2))
        need('from_user' in self.snapshot_tools(self.servers('cc2')['fx']), 'the user scope definition',
             self.servers('cc2')['fx'])
        out = self.attached['cc3'][1]
        need(len(out['tools']['errors']) >= 1, 'Unreadable sources: a source that does not parse is reported in errors',
             out['tools'])
        need('fx' in attach_servers('cc3'), 'discovery continues with the rest after an unparsable source',
             out['tools'])

        cx = attach_servers('cx')
        need(set(cx) == {'cxs', 'cxoff', 'cxrem'}, 'Codex: [mcp_servers.NAME] in ~/.codex/config.toml', sorted(cx))
        need(cx['cxs']['shareable'] is True and cx['cxs']['reason'] is None, 'Codex stdio server shareable '
             '(startup_timeout_ms ignored)', cx['cxs'])
        need(cx['cxoff']['shareable'] is False and cx['cxoff']['reason'] == 'disabled', 'Codex enabled = false: '
             'disabled', cx['cxoff'])
        need(cx['cxrem']['transport'] == 'remote' and cx['cxrem']['reason'] == 'remote', 'Codex url: remote',
             cx['cxrem'])
        need('from_codexhome' in self.snapshot_tools(self.servers('cx')['cxs']), 'Codex command and args',
             self.servers('cx')['cxs'])
        cx2 = attach_servers('cx2')
        need(set(cx2) == {'cxalt'}, 'Codex: $CODEX_HOME/config.toml replaces the default', sorted(cx2))

        oc = attach_servers('oc')
        need(set(oc) == {'ocs', 'ocover', 'ocoff', 'ocrem'}, 'OpenCode: mcp in the global and project opencode.json',
             sorted(oc))
        need(oc['ocoff']['reason'] == 'disabled' and oc['ocrem']['reason'] == 'remote', 'OpenCode enabled false and '
             'type remote', oc)
        oc_servers = self.servers('oc')
        need('from_project' in self.snapshot_tools(oc_servers['ocover']) and
             'from_global' not in self.snapshot_tools(oc_servers['ocover']),
             'OpenCode: the project file takes precedence', oc_servers['ocover'])
        need('from_opencode' in self.snapshot_tools(oc_servers['ocs']),
             'OpenCode: the first element of command, and the rest as args', oc_servers['ocs'])
        for source in definition(oc_servers['ocover'], 'source'):
            need(source == 'opencode:project', 'source opencode:project', source)

        events = [e for e in self.activity('p1') if e['kind'] == 'tools.discovered']
        need({self.aid[a] for a in ('cc', 'cx', 'oc')} <= {e['subject_id'] for e in events},
             'tools.discovered activity with the agent ID', events[:5])
        code, out, stdout, stderr = self.hosts['p1'].outcome('tools')
        need(code == 0 and 'fx' in stdout, 'tools prints a readable listing', code, stdout[:300])
        need(self.secrets['captured'] not in stdout, 'tools never prints values')
        out = self.tools_view('p1', 'cc')
        need('cxs' not in json.dumps(out), 'tools --agent NAME limits to one agent', out)
        return '; '.join(notes)

    def check_allow(self):
        rhea = 'person:' + self.rhea
        policy_before = self.version()

        # Reach confirmation: refused with neither a terminal nor --yes.
        code, out, stderr = self.allow('rhea', '--tools', 'fx', '--agent', 'cc')
        need(code == 1, 'Without a terminal and without --yes, allow refuses with exit 1', code, stderr[-300:])
        # At a terminal: the prompt, then y.
        code, out, tty = self.allow('rhea', '--tools', 'fx', '--agent', 'cc', terminal='y')
        text = squash(tty)
        need('can call these tools of fx on cc with the credentials it runs with there:' in text and
             'Anything those credentials can reach through these tools,' in text,
             'the reach prompt at a terminal', tty[-600:])
        need(code == 0, 'confirmation is y at a terminal', code, tty[-300:])
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx', 'action': 'tool.call', 'scope': ['readonly']}],
             'SPEC SERVER means readonly; output rules [{agent, server, action, scope}]', out)
        need(out['principal'] in ('rhea', rhea, self.rhea), 'output principal', out)
        rule = [r for r in self.rules_for(rhea) if r['agent'] == 'cc']
        need(len(rule) == 1 and set(rule[0]) == TOOL_RULE_KEYS, 'a tool rule {agent, server, principals, action, '
             'scope, max_input_bytes, allow_disconnected, max_calls_per_hour}', rule)
        need((rule[0]['max_input_bytes'], rule[0]['allow_disconnected'], rule[0]['max_calls_per_hour']) ==
             (65536, False, 100), 'Settings: max_input_bytes 65,536, allow_disconnected false, max_calls_per_hour 100',
             rule)

        # Not asked twice for (cc, fx, no profile); set semantics move rhea to the named-tool rule.
        code, out, stderr = self.allow('rhea', '--tools', 'fx:echo,info', '--agent', 'cc')
        need(code == 0, 'Confirmations are stored per (agent, server, profile) and not asked again', code,
             stderr[-300:])
        mine = [r for r in self.rules_for(rhea) if r['agent'] == 'cc' and r['server'] == 'fx']
        need(len(mine) == 1 and sorted(mine[0]['scope']) == ['echo', 'info'],
             'Set semantics: removed from every tool rule with the same action, then a new rule; empty rules dropped',
             mine)

        # Without --agent: one rule per local agent with the server, named explicitly.
        agents_with_fx = {a for a in ('cc', 'cc2', 'cc3') if self.servers(a).get('fx', {}).get('shareable')}
        code, out, stderr = self.allow('rhea', '--tools', 'fx', '--yes')
        need(code == 0, 'allow --tools SERVER without --agent', code, stderr[-300:])
        need({r['agent'] for r in out['rules']} == agents_with_fx and
             all(r['server'] == 'fx' and r['scope'] == ['readonly'] for r in out['rules']),
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
        need(code == 0 and out['rules'] == [{'agent': '*', 'server': 'fx', 'action': 'tool.call',
                                              'scope': ['readonly']}], "--agent '*' makes one * rule", code, out)
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

        # Profile forms.
        need(self.profile_added[0] == 0, 'setup: tools profile add', self.profile_added)
        out = self.allowed('rhea', '--tools', 'fx@acme', '--agent', 'cc', '--yes')
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx@acme', 'action': 'tool.call', 'scope': ['readonly']}],
             'SPEC SERVER@PROFILE means readonly', out)
        out = self.allowed('rhea', '--tools', 'fx@acme:*', '--agent', 'cc', '--yes')
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx@acme', 'action': 'tool.call', 'scope': ['*']}],
             'SPEC SERVER@PROFILE:*', out)
        need(len([r for r in self.rules_for(rhea, server='fx@acme')]) == 1, 'set semantics within the profile',
             self.rules_for(rhea, server='fx@acme'))
        out = self.allowed('rhea', '--tools', 'fx@acme:write_note', '--agent', 'cc', '--yes')
        need(out['rules'][0]['scope'] == ['write_note'], 'SPEC SERVER@PROFILE:TOOL names a write tool', out)
        out = self.allowed('quinn', '--tools', 'fx@acme:write_note', '--agent', 'cc', '--yes')
        shared = [r for r in self.tool_rules() if r['server'] == 'fx@acme' and r['agent'] == 'cc']
        need(len(shared) == 1 and set(shared[0]['principals']) == {rhea, 'person:' + self.quinn},
             'Set semantics: added to the first remaining rule with identical settings and scope', shared)
        out = self.allowed('quinn', '--tools', 'fx@acme:write_note', '--agent', 'cc', '--calls-per-hour', '5', '--yes')
        shared = [r for r in self.tool_rules() if r['server'] == 'fx@acme' and r['agent'] == 'cc']
        need(len(shared) == 2 and sorted(r['max_calls_per_hour'] for r in shared) == [5, 100],
             'different settings make a new rule (--calls-per-hour)', shared)

        # Repeated --tools makes one rule each; --resources.
        out = self.allowed('rhea', '--tools', 'fx:echo', '--tools', 'lit', '--agent', 'cc', '--yes')
        need(len(out['rules']) == 2 and {r['server'] for r in out['rules']} == {'fx', 'lit'},
             '--tools may be repeated, each occurrence its own rule', out)
        out = self.allowed('rhea', '--resources', 'fx:fixture://docs/*', '--agent', 'cc', '--yes')
        need(out['rules'] == [{'agent': 'cc', 'server': 'fx', 'action': 'resource.read',
                               'scope': ['fixture://docs/*']}], 'allow --resources SERVER:PATTERN', out)

        # deny --tools.
        out = self.deny('rhea', '--tools', 'fx@acme', '--agent', 'cc')
        need(out['removed'] == 1 and not self.rules_for(rhea, server='fx@acme'),
             'deny --tools SERVER@PROFILE removes the principal from rules naming that profile', out)
        need(any(r['server'] == 'fx' and r['agent'] == 'cc' for r in self.rules_for(rhea)),
             'deny of a profile leaves the bare server', self.rules_for(rhea))
        out = self.deny('rhea', '--tools', 'fx', '--agent', 'cc')
        need(out['removed'] >= 1 and not [r for r in self.rules_for(rhea, server='fx') if r['agent'] == 'cc'],
             'deny --tools within the agent scope', out)
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
        need(self.tool_rules() == rules, 'allow without --tools or --resources never touches tool rules', rules)
        self.hosts['p1'].cli('deny', 'rhea', '--network', self.team)
        need(self.tool_rules() == rules, 'deny without --tools never touches tool rules', self.tool_rules())
        self.deny('rhea', '--tools', 'lit')
        return f'policy {policy_before} → {self.version()}'

    def check_policy_v2(self):
        p = self.policy()
        need(p and p.get('format') == 2 and isinstance(p.get('tool_rules'), list) and
             isinstance(p.get('trusted_hosts'), list), 'The JSON gains format 2, tool_rules, and trusted_hosts', p)
        need(len(p['tool_rules']) >= 5, 'setup: the shares', p['tool_rules'])
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
        need(stored['version'] == v1['version'] and plain(stored['rules']) == rules and not stored.get('tool_rules') and
             not stored.get('trusted_hosts') and stored['signature'] == v1['signature'],
             'a v1 policy reads as v2 with no tool rules and no trusted hosts', stored)
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
                    {'server': 'Bad.Name'}):
            rule = {'agent': 'cc', 'server': 'fx', 'principals': ['network'], 'action': 'tool.call',
                    'scope': ['readonly'], 'max_input_bytes': 65536, 'allow_disconnected': False,
                    'max_calls_per_hour': 100, **bad}
            v = crafted_v2(nxt, nxt['version'] + 1, self.keys['pat'][0], self.root, tool_rules=[rule])
            status, _ = self.hosts['p1'].call('POST', f'/v1/networks/{self.v1net}/policy', {'policy': v})
            need(status == 400, 'v2 bounds and validation refuse the policy', bad, status)
        for bad_trusted in (['not-a-host'], ['host_xyz']):
            v = crafted_v2(nxt, nxt['version'] + 1, self.keys['pat'][0], self.root, trusted=bad_trusted)
            status, _ = self.hosts['p1'].call('POST', f'/v1/networks/{self.v1net}/policy', {'policy': v})
            need(status == 400, 'trusted hosts must be host IDs', bad_trusted, status)
        ok = crafted_v2(nxt, nxt['version'] + 1, self.keys['pat'][0], self.root, tool_rules=[{
            'agent': '*', 'server': 'fx@acme', 'principals': ['network'], 'action': 'tool.call', 'scope': ['*'],
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
        out = p3.cli('trust')
        need(ids['p3'] in self.policy('p3')['trusted_hosts'], 'trust: HOST defaults to this host; --network optional '
             'with one network', out, self.policy('p3'))
        self.synced(self.version('p3'), 'p1')
        need(any(e['agent'] == 'cc' for e in self.listing('p1', 'p3')[1]), 'a trusted host lists tools by self')
        p3.cli('untrust', ids['p3'])
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
        ids = self.ids
        f = self.fixture
        # By policy, by grant, and by self from a trusted host.
        marker = 'by-policy-' + secrets.token_hex(4)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': marker}, '--network', self.team)
        need(code == 0 and out['status']['state'] == 'succeeded', 'policy authorizes a read-only tool', code,
             out, stderr[-300:])
        need(out['request'].get('policy') == {'person_id': self.pat, 'version': self.version()},
             'the CLI cites the policy from the listing', out['request'])
        need(first_text(out['result']) == marker and len(f.calls('fx-local', marker)) == 1,
             'the tool\'s own result', out['result'])
        self.grant = self.hosts['p1'].cli('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'],
                                          '--expires-in', '2h', '--action', 'tool.call', '--server', 'fx', '--scope',
                                          'readonly', '--calls-per-hour', '10000', '--allow-disconnected')
        code, out, stderr = self.call('n', f"{ids['p1']}/cc/fx", 'echo', {'text': 'by grant'})
        need(code == 0 and out['request'].get('grant_id') == self.grant['id'], 'a grant authorizes a call from a '
             'peer in no network', code, out, stderr[-300:])
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
        # The read-only rule under policy (a policy signed here names a write tool on the bare server) and grants.
        current = self.policy()
        extra = {'agent': 'cc', 'server': 'fx', 'principals': ['person:' + self.quinn], 'action': 'tool.call',
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
        write_grant = self.hosts['p1'].cli('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'],
                                           '--expires-in', '1h', '--action', 'tool.call', '--server', 'fx', '--scope',
                                           'write_note')
        status, body = self.submit('n', self.body('cc', 'fx', 'write_note', {'text': 'x'},
                                                  cite={'grant_id': write_grant['id']}))
        need(status == 403, 'the read-only rule under a grant', status, body)
        self.hosts['p1'].cli('grant', 'revoke', write_grant['id'])
        restored = crafted_v2(signed, signed['version'] + 1, self.keys['pat'][0], self.root,
                              tool_rules=current['tool_rules'])
        self.hosts['p1'].call('POST', f'/v1/networks/{self.team}/policy', {'policy': restored})
        self.sync_all()
        # Blocks, except under self.
        made = [self.hosts['p1'].cli('block', 'quinn'), self.hosts['p1'].cli('block', ids['p2'])]
        status, _ = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'blocked'}, cite=self.policy_cite()))
        need(status == 403, 'blocks apply under policy', status)
        status, _ = self.submit('n', self.body('cc', 'fx', 'echo', {'text': 'x'}, cite={'grant_id': self.grant['id']}))
        need(status == 200, 'blocks name only their subjects', status)
        self.hosts['p1'].cli('block', ids['n'])
        status, _ = self.submit('n', self.body('cc', 'fx', 'echo', {'text': 'x'}, cite={'grant_id': self.grant['id']}))
        need(status == 403, 'blocks apply under grants', status)
        status, _ = self.submit('p2', self.body('cc', 'fx', 'echo', {'text': 'self'}, cite=self.self_cite()))
        need(status == 200, 'blocks do not apply under self', status)
        for target in ('quinn', ids['p2'], ids['n']):
            self.hosts['p1'].cli('unblock', target)
        need(self.hosts['p1'].cli('access', 'blocks') == [], 'unblocked', made)
        # Budgets: per (rule, caller), the caller being the bound person, else the host.
        cite = self.policy_cite()
        results = [self.submit(h, self.body('cc', 'budget', 'echo', {'text': h}, cite=cite))[0]
                   for h in ('q1', 'q1', 'q2')]
        need(results == [200, 200, 200], 'budget: 3 accepted calls', results)
        for h in ('q1', 'q2'):
            status, body = self.submit(h, self.body('cc', 'budget', 'echo', {'text': h}, cite=cite))
            need(status == 429 and 'max_calls_per_hour' in json.dumps(body),
                 'over the limit: 429 with the limit\'s name, counted per person across hosts', h, status, body)
        for h in ('u1', 'u2'):
            got = [self.submit(h, self.body('cc', 'budget2', 'echo', {'text': h}, cite=cite))[0] for _ in range(3)]
            need(got == [200, 200, 429], 'an unbound sender is counted by its host ID', h, got)
        got = [self.submit(h, self.body('cc', 'budget2', 'echo', {'text': h}, cite=cite))[0] for h in ('q1', 'q2', 'q1')]
        need(got == [200, 200, 429], 'the same rule counts each person separately from unbound hosts', got)
        # 413 for oversized input.
        status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x' * 70000}, cite=cite))
        need(status == 413, 'input over max_input_bytes (the JSON encoding of arguments): 413', status)
        status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x' * 60000}, cite=cite))
        need(status == 200, 'input within max_input_bytes', status, body)
        # Deadline within the policy's valid_until.
        status, body = self.submit('q1', self.body('cc', 'fx', 'echo', {'text': 'x'}, cite=cite,
                                                   deadline=timestamp(16 * 60)))
        need(status in (400, 403), 'a deadline more than 15 minutes ahead is refused', status, body)
        # Lapsed authorization before start: rejected.
        lapsing = self.hosts['p1'].cli('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'],
                                       '--expires-in', '1h', '--action', 'tool.call', '--server', 'fx', '--scope',
                                       'readonly')
        self.fill_slots(6)
        marker = 'lapsed-' + secrets.token_hex(4)
        b = self.body('cc', 'fx', 'echo', {'text': marker}, cite={'grant_id': lapsing['id']})
        status, record = self.submit('n', b)
        need(status == 200 and record['state'] == 'queued', 'a fifth call waits as queued', status, record)
        self.hosts['p1'].cli('grant', 'revoke', lapsing['id'])
        done = self.final('n', b['call_id'], timeout=40)
        need(done['state'] == 'rejected' and LAPSED in json.dumps(done),
             f'Rechecks: a failure at the start makes the call rejected, "{LAPSED}"', done)
        need(not f.calls('fx-local', marker), 'a rejected call never runs', f.calls('fx-local', marker))

    def check_grants(self):
        ids, p1 = self.ids, self.hosts['p1']

        def grant(*extra, success=True):
            return p1.cli('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'], '--expires-in', '1h',
                          *extra, success=success)
        g = grant('--action', 'tool.call', '--server', 'fx', '--scope', 'echo')
        need(g['action'] == 'tool.call' and g['server'] == 'fx' and g['scope'] == ['echo'] and
             g['max_input_bytes'] == 65536 and g['max_calls_per_hour'] == 100,
             'grants gain server, scope, max_input_bytes, and max_calls_per_hour, with defaults 65,536 and 100', g)
        grant('--action', 'tool.call', '--server', 'fx', success=False)
        for bad in (('--max-input-bytes', '0'), ('--max-input-bytes', '262145'), ('--calls-per-hour', '0'),
                    ('--calls-per-hour', '10001')):
            grant('--action', 'tool.call', '--server', 'fx', '--scope', 'echo', *bad, success=False)
        grant('--action', 'tool.call', '--server', 'fx', '--scope', 'readonly', '--scope', 'echo', success=False)
        cite = {'grant_id': g['id']}
        status, _ = self.submit('n', self.body('cc', 'fx', 'echo', {'text': 'g'}, cite=cite))
        need(status == 200, 'the grant scope covers the named tool', status)
        status, _ = self.submit('n', self.body('cc', 'fx', 'info', {}, cite=cite))
        need(status == 403, 'a tool outside the grant scope is refused', status)
        status, _ = self.submit('n', self.body('cc', 'lit', 'echo', {'text': 'g'}, cite=cite))
        need(status == 403, 'a grant names one server', status)
        small = grant('--action', 'tool.call', '--server', 'fx', '--scope', 'readonly', '--max-input-bytes', '100',
                      '--calls-per-hour', '2')
        status, _ = self.submit('n', self.body('cc', 'fx', 'echo', {'text': 'x' * 200}, cite={'grant_id': small['id']}))
        need(status == 413, 'the grant input bound: 413', status)
        got = [self.submit('n', self.body('cc', 'fx', 'echo', {'text': 's'}, cite={'grant_id': small['id']}))[0]
               for _ in range(3)]
        need(got == [200, 200, 429], 'the grant budget, counted for the grant and host', got)
        res = grant('--action', 'resource.read', '--server', 'fx', '--scope', 'fixture://docs/*')
        need(res['action'] == 'resource.read' and res['scope'] == ['fixture://docs/*'], 'a resource grant', res)
        b = self.body('cc', 'fx', uri='fixture://docs/readme', cite={'grant_id': res['id']})
        status, record = self.submit('n', b)
        need(status == 200 and record['kind'] == 'resource', 'a resource read by grant', status, record)
        done = self.final('n', b['call_id'])
        need(done['state'] == 'succeeded' and done['result']['contents'][0]['text'] ==
             'contents of fixture://docs/readme', 'the ReadResourceResult', done)
        status, _ = self.submit('n', self.body('cc', 'fx', uri='file:///srv/docs/a.txt', cite={'grant_id': res['id']}))
        need(status == 403, 'a URI outside the pattern is refused', status)
        status, _ = self.submit('n', self.body('cc', 'fx', 'echo', {'text': 'x'}, cite={'grant_id': res['id']}))
        need(status == 403, 'a resource.read grant does not cover tool.call', status)
        status, _ = self.submit('n', self.body('cc', 'fx', 'echo', {'text': 'x'},
                                               cite={'grant_id': p1.cli('grant', 'create', '--peer', ids['n'], '--agent',
                                                                        self.aid['cc'], '--expires-in', '1h')['id']}))
        need(status == 403, 'a message grant never covers tools', status)
        for item in (g, small, res):
            p1.cli('grant', 'revoke', item['id'])

    def check_routes(self):
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
        need({r['uri'] for r in fx['resources']} == {'fixture://docs/readme', 'fixture://docs/guide'},
             'resources matching the rule\'s URI pattern only', fx['resources'])
        acme = self.entry(body, 'cc', 'fx', 'acme')
        need(acme and {t['name'] for t in acme['tools']} == {'write_note'}, 'a profile share lists its own entry',
             acme)
        echo = next(t for t in fx['tools'] if t['name'] == 'echo')
        nets = sorted([self.team, self.other])
        need([v['kind'] for v in echo['via']] == ['policy', 'policy'] and
             [v['network_id'] for v in echo['via']] == nets,
             'via: policy entries ordered by network ID', echo['via'])
        for v in echo['via']:
            need(set(v) == {'kind', 'network_id', 'person_id', 'version'} and v['person_id'] == self.pat,
                 'policy via {kind, network_id, person_id, version}', v)
        # Grants are listed after policies; ?network= evaluates only that network's self and policy entries.
        g = self.hosts['p1'].cli('grant', 'create', '--peer', ids['q1'], '--agent', self.aid['cc'], '--expires-in',
                                 '1h', '--action', 'tool.call', '--server', 'fx', '--scope', 'readonly')
        self.q1_grant = g
        tools = self.listed_tools('p1', 'q1', 'cc', 'fx')
        need([v['kind'] for v in tools['echo']['via']] == ['policy', 'policy', 'grant'] and
             tools['echo']['via'][-1] == {'kind': 'grant', 'grant_id': g['id']}, 'via order: self, policy, grant',
             tools['echo']['via'])
        status, scoped = self.listing('p1', 'q1', network=self.other)
        need(status == 200 and all(v['kind'] == 'policy' and v['network_id'] == self.other
                                   for e in scoped for t in e['tools'] for v in t['via']),
             '?network=ID: only that network\'s authorizations, and no grants', scoped)
        need(self.entry(scoped, 'cc', 'lit'), 'lit is shared with quinn in other', scoped)
        status, team_only = self.listing('p1', 'q1', network=self.team)
        need(not self.entry(team_only, 'cc', 'lit'), 'a share in another network is not listed with ?network',
             team_only)
        # A host with nothing, the grant-only peer, a trusted sibling, an untrusted one.
        status, body = self.listing('p1', 'r')
        need((status, body) == (200, []), 'a host with no authorization lists []', status, body)
        g2 = self.hosts['p1'].cli('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'], '--expires-in',
                                  '1h', '--action', 'tool.call', '--server', 'lit', '--scope', 'echo')
        status, body = self.listing('p1', 'n')
        lit = self.entry(body, 'cc', 'lit')
        need(status == 200 and lit and [t['name'] for t in lit['tools']] == ['echo'] and
             lit['tools'][0]['via'] == [{'kind': 'grant', 'grant_id': g2['id']}],
             'reachable by a grant-only peer outside any network', status, body)
        self.hosts['p1'].cli('grant', 'revoke', g2['id'])
        status, body = self.listing('p1', 'p2')
        fx = self.entry(body, 'cc', 'fx')
        need(fx and {t['name'] for t in fx['tools']} == RO_TOOLS | WRITE_TOOLS | {'from_local'},
             'self covers every tool, including write tools', fx)
        need(not any(e['server'] in ('rem', 'needy', 'Bad.Name', 'sserem') for e in body),
             'only shareable servers are listed', [e['server'] for e in body])
        need(self.entry(body, 'cx', 'cxs') and self.entry(body, 'cc', 'fx', 'acme'),
             'self covers every shareable server and profile of every agent', [e['server'] for e in body])
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
        g = self.hosts['p1'].cli('grant', 'create', '--peer', ids['n'], '--agent', self.aid['cc'], '--expires-in', '2h',
                                 '--action', 'tool.call', '--server', 'fx', '--scope', 'readonly', '--calls-per-hour',
                                 '10000', '--allow-disconnected')
        cite = {'grant_id': g['id']}
        # The lifecycle, on the wire.
        marker = 'life-' + secrets.token_hex(4)
        b = self.body('cc', 'fx', 'echo', {'text': marker}, cite=cite)
        status, record = self.submit('n', b)
        need(status == 200 and set(record) == STATUS_KEYS, 'POST /peer/v1/calls returns the status record', status,
             record)
        need(record['state'] == 'queued' and record['call_id'] == b['call_id'] and record['kind'] == 'tool' and
             record['name'] == 'echo' and record['uri'] is None and record['server'] == 'fx' and
             record['profile'] is None and record['sender_host_id'] == ids['n'] and
             record['receiver_host_id'] == ids['p1'] and record['cancel_requested'] is False,
             'persisted as queued', record)
        done = self.final('n', b['call_id'])
        need(set(done) == STATUS_KEYS | {'result'} and done['state'] == 'succeeded' and done['error'] is None,
             'GET: the status record with result once final', done)
        need(done['result'] == {'content': [{'type': 'text', 'text': marker}]}, 'result is the JSON-RPC result',
             done['result'])
        need(done['started_at'] and done['finished_at'] and done['result_bytes'] > 0, 'timestamps and result_bytes',
             done)
        # Duplicate and conflicting submission.
        status, again = self.submit('n', b)
        need(status == 200 and again['call_id'] == b['call_id'] and again['created_at'] == record['created_at'],
             'an identical repeat returns the existing record', status, again)
        need(len(f.calls('fx-local', marker)) == 1, 'retrying a submission never starts a second run')
        need(self.submit('n', {**b, 'arguments': {'text': 'changed'}})[0] == 409, 'a changed repeat returns 409')
        for bad in ({**b, 'call_id': 'call_x'}, {k: v for k, v in b.items() if k != 'profile'},
                    {**b, 'extra': 1}, {**b, 'kind': 'prompt'}, {**b, 'call_id': call_id(), 'uri': 'fixture://x'},
                    {**b, 'call_id': call_id(), 'arguments': []},
                    {**b, 'call_id': call_id(), 'policy': {'person_id': self.pat, 'version': 1}}):
            need(self.submit('n', bad)[0] == 400, 'POST /peer/v1/calls takes exactly its fields and one citation', bad)
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
            self.submit('n', b)
            done = self.final('n', b['call_id'])
            need(done['state'] == 'failed' and done['error'] == error, f'{name}: failed with {error}', done)
            if error == 'jsonrpc_error':
                need(done['result'] == {'code': -32001, 'message': 'broken'}, 'a JSON-RPC error result is {code, '
                     'message}', done['result'])
            if error == 'tool_error':
                need(done['result'].get('isError') is True, 'isError result kept', done['result'])
            if error == 'result_too_large':
                need(done.get('result') is None, 'a result over 1 MiB is not stored', str(done)[:300])
        b = self.body('cc', 'fx', 'big', {'bytes': 1048000}, cite=cite)
        self.submit('n', b)
        need(self.final('n', b['call_id'])['state'] == 'succeeded', 'a result just under 1 MiB is kept')

        # A lost submit response, recovered by retry: one execution.
        marker = 'lost-' + secrets.token_hex(4)
        relay = DropCallResponse(self.hosts['p1'])
        identity = self.hosts['p1'].call('GET', '/v1/host')[1]
        self.hosts['n'].configure(self.hosts['p1'], identity, relay.address)
        try:
            code, out, stderr = self.call('n', f"{ids['p1']}/cc/fx", 'echo', {'text': marker}, '--grant', g['id'],
                                          wait='1s')
            relay.close()
        finally:
            self.hosts['n'].configure(self.hosts['p1'], identity)
        need(out and set(out) == OUTBOUND_KEYS and out['submit_state'] == 'unknown' and out['next_attempt_at'],
             'the outbound record after a lost response', code, out, stderr[-300:])
        need(code == 3, 'call exits 3 while pending', code)
        recovered = wait_for(lambda: (r := self.inspect('n', ids['p1'], out['request']['call_id']))['submit_state'] ==
                             'accepted' and r, timeout=40, message='automatic call retry')
        need(recovered['attempts'] >= 2, 'retried', recovered)
        final = self.settle('n', recovered)
        need(final['status']['state'] == 'succeeded' and first_text(final['result']) == marker,
             'the daemon polls and stores the final status and result', final)
        need(len(f.calls('fx-local', marker)) == 1, 'exactly one execution recorded by the fixture',
             f.calls('fx-local', marker))

        # Expiry before start, and cancellation while queued.
        self.fill_slots(8)
        marker = 'expire-' + secrets.token_hex(4)
        expiring = self.body('cc', 'fx', 'echo', {'text': marker}, cite=cite, deadline=timestamp(3))
        queued = self.body('cc', 'fx', 'echo', {'text': marker + '-cancel'}, cite=cite)
        need(self.submit('n', expiring)[1]['state'] == 'queued', 'queued behind 4 running calls')
        need(self.submit('n', queued)[1]['state'] == 'queued', 'queued behind 4 running calls')
        status, record = wire(self.hosts['p1'], fixture_context(self.hosts['n']), 'POST',
                              f"/peer/v1/calls/{queued['call_id']}/cancel", {})
        need(status == 200 and record['state'] == 'cancelled' and record['cancel_requested'] is True,
             'cancelling a queued call: cancelled at once', status, record)
        need(self.final('n', expiring['call_id'], timeout=40)['state'] == 'expired',
             'a call still queued at its deadline becomes expired')
        need(not f.calls('fx-local', marker) and not f.calls('fx-local', marker + '-cancel'),
             'expired and cancelled calls never ran')
        status, again = wire(self.hosts['p1'], fixture_context(self.hosts['n']), 'POST',
                             f"/peer/v1/calls/{queued['call_id']}/cancel", {})
        need(status == 200 and again['state'] == 'cancelled', 'a cancel of a final call returns it unchanged', again)

        # Cancellation while running, and the deadline while running: uncertain, with notifications/cancelled.
        time.sleep(9)
        for how in ('cancel', 'deadline'):
            marker = f'{how}-' + secrets.token_hex(4)
            b = self.body('cc', 'fx', 'sleep', {'seconds': 30, 'text': marker}, cite=cite,
                          deadline=timestamp(6) if how == 'deadline' else None)
            self.submit('n', b)
            wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
            if how == 'cancel':
                status, record = wire(self.hosts['p1'], fixture_context(self.hosts['n']), 'POST',
                                      f"/peer/v1/calls/{b['call_id']}/cancel", {})
                need(status == 200 and record['cancel_requested'] is True, 'cancel sets cancel_requested', record)
            done = self.final('n', b['call_id'], timeout=40)
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
        self.submit('n', b)
        wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
        self.restart('p1')
        done = self.final('n', b['call_id'], timeout=30)
        need(done['state'] == 'uncertain' and done['error'] == 'daemon_restarted',
             'At daemon start, every call still running becomes uncertain (daemon_restarted)', done)
        time.sleep(18)
        need(len(f.calls('fx-local', marker)) == 1, 'No re-execution after a restart', f.calls('fx-local', marker))

        # A server exit: running calls uncertain (server_exited); the next call starts a new instance.
        marker = 'exit-' + secrets.token_hex(4)
        b1 = self.body('cc', 'fx', 'sleep', {'seconds': 30, 'text': marker}, cite=cite)
        self.submit('n', b1)
        wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
        pid = f.calls('fx-local', marker)[0]['pid']
        b2 = self.body('cc', 'fx', 'crash', {'delay': 1}, cite=cite)
        self.submit('n', b2)
        for b in (b1, b2):
            done = self.final('n', b['call_id'], timeout=30)
            need(done['state'] == 'uncertain' and done['error'] == 'server_exited',
                 'an instance exit makes its running calls uncertain (server_exited)', done)
        marker = 'after-exit-' + secrets.token_hex(4)
        b = self.body('cc', 'fx', 'echo', {'text': marker}, cite=cite)
        self.submit('n', b)
        need(self.final('n', b['call_id'])['state'] == 'succeeded' and f.calls('fx-local', marker)[0]['pid'] != pid,
             'later calls start a new instance')

        # Concurrency capped at 4 per instance.
        marker = 'conc-' + secrets.token_hex(4)
        batch = [self.body('cc', 'fx', 'sleep', {'seconds': 3, 'text': marker}, cite=cite) for _ in range(6)]
        for b in batch:
            self.submit('n', b)
        for b in batch:
            need(self.final('n', b['call_id'], timeout=40)['state'] == 'succeeded', 'every call finishes')
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
        need(any(e['subject_id'] == f"{ids['n']}/{batch[0]['call_id']}" for e in received),
             'receiver activity subject SENDER/CALL_ID', received[-3:])
        self.hosts['p1'].cli('grant', 'revoke', g['id'])

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
        env_file.write_text(f"# overrides\nTOKEN_A={self.secrets['file']}\n\nLIT_TOKEN=from-file\n")
        env_file.chmod(0o600)
        self.restart('p1')
        need(matches('proj', 'TOKEN_A', self.secrets['file']) == {'present': True, 'matches': True},
             'the environment file overrides captured values')
        need(matches('lit', 'LIT_TOKEN', 'from-file') == {'present': True, 'matches': True},
             'the environment file overrides literals of the same name')
        need(not [i for i in self.items() if i['subject'] == 'env'], 'no item 14 for a 0600 file')
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
        f = self.fixture
        servers = self.servers('cc')
        need(find_key(servers['fx'], 'profiles'), 'GET /v1/tools lists the server\'s profiles', servers['fx'])
        profiles = find_key(servers['fx'], 'profiles')[0]
        need('acme' in json.dumps(profiles) and 'from_acme' in json.dumps(profiles),
             'the profile is snapshotted with its own arguments', profiles)

        def self_call(tool, arguments, target='pat/cc/fx@acme'):
            code, out, stderr = self.call('p2', target, tool, arguments)
            need(code == 0, f'self call {target} {tool}', code, out, stderr[-300:])
            return first_text(out['result'])
        need(self_call('env_matches', {'name': 'PROFILE_ONLY', 'sha256': sha(self.secrets['profile'])}) ==
             {'present': True, 'matches': True}, 'a profile instance receives its own environment file')
        need(self_call('env_matches', {'name': 'FX_CAPTURED', 'sha256': sha('profile-value')}) ==
             {'present': True, 'matches': True}, "the profile's --env-file comes last")
        need(self_call('info', {})['labels'] == ['acme'], "--arg replaces the server's args")
        need(self_call('env_matches', {'name': 'PROFILE_ONLY', 'sha256': 'x'}, 'pat/cc/fx')['present'] is False,
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
        need('acme' not in json.dumps(find_key(self.servers('cc')['fx'], 'profiles')), 'the profile is removed')
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
                             ({'list_delay': 40}, 'the 30-second bound')):
            f.set('slow', **control)
            started = time.monotonic()
            self.refresh('cc')
            elapsed = time.monotonic() - started
            slow = self.servers('cc')['slow']
            need(find_key(slow, 'snapshot_error'), f'{why} records snapshot_error', slow)
            need(self.snapshot_tools(slow) == before, f'{why} keeps the previous snapshot', slow)
            if 'list_delay' in control:
                need(28 <= elapsed <= 60, 'the whole snapshot must finish within 30 seconds', elapsed)
        f.set('slow')
        self.refresh('cc')
        need(not find_key(self.servers('cc')['slow'], 'snapshot_error') or
             not any(find_key(self.servers('cc')['slow'], 'snapshot_error')),
             'a successful snapshot clears snapshot_error', self.servers('cc')['slow'])
        events = [e for e in self.activity('p1') if e['kind'] == 'tools.snapshot_failed']
        need(any(e['subject_id'] == f"{self.aid['cc']}/slow" for e in events),
             'tools.snapshot_failed activity, subject AGENT_ID/SERVER', events[-3:])

    def check_configuration_changes(self):
        f, ids = self.fixture, self.ids
        # A server dropped from configuration: a running call finishes; new calls are refused as unknown.
        marker = 'dropped-' + secrets.token_hex(4)
        code, out, stderr = self.call('p2', 'pat/cc/gone', 'sleep', {'seconds': 10, 'text': marker}, wait='1s')
        need(code == 3, 'setup: a running call on gone', code, out, stderr[-300:])
        wait_for(lambda: f.calls('gone', marker), timeout=20, message='running')
        del self.local_servers['gone']
        self.write_claude_json()
        self.refresh('cc')
        need('gone' not in self.servers('cc'), 'a PUT that drops a server deletes its definition')
        final = self.settle('p2', out, timeout=40)
        need(final['status']['state'] == 'succeeded', 'calls already running on a dropped server finish', final)
        status, _ = self.submit('p2', self.body('cc', 'gone', 'echo', {'text': 'x'}, cite=self.self_cite()))
        need(status == 404, 'new calls to a dropped server are refused as unknown (404)', status)
        code, out, stderr = self.call('p2', 'pat/cc/gone', 'echo', {'text': 'x'})
        need(code != 0, 'call to a dropped server fails', code)
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
        ids = self.ids
        # Exit codes.
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'zero'}, '--network', self.team)
        need(code == 0 and set(out) == OUTBOUND_KEYS, 'call: exit 0 for succeeded, printing the local record', code)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'tool_error', {}, '--network', self.team)
        need(code == 1 and out['status']['state'] == 'failed', 'call: exit 1 for other final states', code, out)
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'sleep', {'seconds': 6, 'text': 'pending'}, '--network',
                                      self.team, wait='1s')
        need(code == 3, 'call: exit 3 if still pending', code, out)
        pending = out
        code, out, stderr = self.read('q1', 'pat/cc/fx', 'fixture://docs/readme', '--network', self.team)
        need(code == 0 and out['status']['kind'] == 'resource', 'read: exit 0', code, out)
        code, out, stderr = self.read('q1', 'pat/cc/fx', 'file:///srv/private/b.txt', '--network', self.team)
        need(code != 0, 'read of a URI not covered fails', code, out)
        # Listings.
        listed = self.hosts['q1'].cli('calls', 'list', '--limit', '1000')
        need(listed and all('sequence' in item for item in listed), 'calls list: paged as tasks are', listed[:1])
        need([item['sequence'] for item in listed] == sorted(item['sequence'] for item in listed),
             'insertion order', [i['sequence'] for i in listed])
        need(pending['request']['call_id'] in json.dumps(listed), 'calls list shows outbound calls')
        need(len(self.hosts['q1'].cli('calls', 'list', '--limit', '1')) == 1, 'calls list --limit')
        after = self.hosts['q1'].cli('calls', 'list', '--after', str(listed[-2]['sequence']))
        need(len(after) == 1 and after[0]['sequence'] == listed[-1]['sequence'], 'calls list --after', after)
        received = self.hosts['p1'].cli('calls', 'received', '--limit', '1000')
        need(pending['request']['call_id'] in json.dumps(received), 'calls received lists calls received', received[-1:])
        need(self.inspect('q1', ids['p1'], pending['request']['call_id'])['request']['call_id'] ==
             pending['request']['call_id'], 'calls inspect')
        # tools and tools remote.
        code, out, stdout, stderr = self.hosts['q1'].outcome('tools', 'remote', '--json')
        need(code == 0 and '"fx"' in stdout and 'cc' in stdout, 'tools remote lists what this host may call',
             code, stdout[:400])
        code, out, stdout, stderr = self.hosts['q1'].outcome('tools', 'remote', 'pat/cc', '--json')
        need(code == 0 and 'fx' in stdout, 'tools remote PERSON/AGENT', code, stdout[:300])
        code, out, stdout, stderr = self.hosts['q1'].outcome('tools', 'remote', 'pat', '--network', self.team, '--json')
        need(code == 0 and '"lit"' not in stdout, 'tools remote --network: a tool authorized only in another network '
             'is not listed', stdout[:400])
        code, out, stdout, stderr = self.hosts['q1'].outcome('tools', 'remote')
        need(code == 0 and 'fx' in stdout, 'tools remote readable output', code)
        # Citation by --network and via order.
        count = self.outbound_count('q1')
        code, out, stderr = self.call('q1', 'pat/cc/lit', 'echo', {'text': 'x'}, '--network', self.team)
        need(code != 0 and self.outbound_count('q1') == count,
             '--network scoping: a tool authorized only in another network is neither listed nor cited', code)
        code, out, stderr = self.call('q1', 'pat/cc/lit', 'echo', {'text': 'x'})
        need(code == 0 and out['request']['policy']['version'] == self.version('p1', self.other),
             'without --network, the first via entry (the other network\'s policy)', code, out)
        versions = {self.team: self.version('p1', self.team), self.other: self.version('p1', self.other)}
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'x'})
        first = min(versions)
        need(code == 0 and 'policy' in out['request'], 'via order: policy before grant', out['request'])
        if versions[self.team] != versions[self.other]:
            need(out['request']['policy']['version'] == versions[first], 'via order: by network ID', out['request'],
                 versions)
        for net in (self.team, self.other):
            code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'x'}, '--network', net)
            need(code == 0 and out['request']['policy']['version'] == versions[net], '--network cites that network',
                 net, out['request'])
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'x'}, '--grant', self.q1_grant['id'])
        need(code == 0 and out['request'].get('grant_id') == self.q1_grant['id'], '--grant cites that grant',
             out and out['request'])
        bogus = self.hosts['p1'].cli('grant', 'create', '--peer', ids['q1'], '--agent', self.aid['cc'], '--expires-in',
                                     '1h')
        count = self.outbound_count('q1')
        code, out, stderr = self.call('q1', 'pat/cc/fx', 'echo', {'text': 'x'}, '--grant', bogus['id'])
        need(code != 0 and self.outbound_count('q1') == count, '--grant must appear in via', code)
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
        code, out, stderr = self.call('q1', 'pat/dup/fx', 'echo', {'text': 'x'})
        need(code != 0 and f"{ids['p1']}/dup/fx" in stderr and f"{ids['p2']}/dup/fx" in stderr,
             'more than one match: an error listing the HOST_ID/AGENT/SERVER form of each', code, stderr[-500:])
        code, out, stderr = self.call('q1', f"{ids['p2']}/dup/fx", 'echo', {'text': 'x'})
        need(code == 0, 'the HOST_ID form resolves the ambiguity', code, stderr[-300:])
        self.hosts['p3'].stop()
        try:
            code, out, stderr = self.call('q1', 'pat/nosuch/fx', 'echo', {'text': 'x'})
            need(code != 0 and ids['p3'] in stderr, 'none: an error listing the hosts that did not answer', code,
                 stderr[-500:])
        finally:
            self.hosts['p3'].start()
        self.deny('quinn', '--tools', 'fx', '--agent', 'dup')

    def check_status(self):
        f, ids = self.fixture, self.ids
        status = self.attention()
        tools = status.get('tools')
        need(isinstance(tools, dict) and set(tools) == {'servers', 'shared_servers', 'calls_running'} and
             tools['servers'] >= 10 and tools['shared_servers'] >= 3,
             'GET /v1/status: tools {servers, shared_servers, calls_running}', tools)
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

def check_vector(directory):
    """Reproduce the coordination contract's v1 policy vector with this suite's encoding, then compute a
    provisional v2 vector (the contract has not published one yet)."""
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
    v2 = {**v1, 'format': 2,
          'tool_rules': [{'agent': 'claude-laptop', 'server': 'github@acme-api',
                          'principals': [f'person:{second}', 'group:eng'], 'action': 'tool.call',
                          'scope': ['create_issue', 'list_issues'], 'max_input_bytes': 65536,
                          'allow_disconnected': False, 'max_calls_per_hour': 100},
                         {'agent': '*', 'server': 'docs', 'principals': ['network'], 'action': 'resource.read',
                          'scope': ['file:///srv/docs/*'], 'max_input_bytes': 4096, 'allow_disconnected': True,
                          'max_calls_per_hour': 10}],
          'trusted_hosts': ['host_b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709']}
    signature = sshsig(person, policy_lines_v2(v2))
    print('NOTE provisional v2 policy vector (this suite\'s reading of the contract; the contract has none yet):',
          json.dumps({'lines': policy_lines_v2(v2), 'signature': signature}), flush=True)
    return 'v1 vector reproduced; provisional v2 vector printed'


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
