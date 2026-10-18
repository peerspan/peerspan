#!/usr/bin/env python3
"""Exercise capabilities (milestone 10 slice 1: sources, capabilities, sharing, and owner calls).

Written from docs/capabilities-contract.md (and the coordination, launch, and task contracts it builds on),
independently of both implementations. Runs every Go/Rust CLI and daemon pairing (all hosts of a pairing run that
pairing's daemon and are driven by its CLI), with one Go coordinator per pairing, real ssh-agents, the peer probe
for raw peer requests, and the fixture MCP stdio server in fixtures/mcp/server.py. Harness configuration (Claude
Code ~/.claude.json and .mcp.json, Codex config.toml, OpenCode opencode.json) is generated under each host's
temporary HOME and XDG_CONFIG_HOME; the integrations `claude-code`, `codex`, and `opencode` are the explicit fixture
integration (fixtures/harness), attached with `--no-start`, so no harness or model runs.

Hosts: pat's p1 (serves sources and capabilities; agents cc, cc2, cc3 for Claude Code, cx and cx2 for Codex, oc
for OpenCode), p2 (joined --trusted), p3 (no terminal: untrusted), p4 (trusted at the join prompt); quinn's q1 and
q2; rhea's r; u1 and u2 (members bound to no person); n (a manually configured peer of p1 in no network).
Networks: team (everyone but n), other (p1, p2 untrusted, q1), and v1net (p1, for a v1 policy).

Each pairing reports these sections separately (contract Verification items in brackets):
- trust at create and join: --trusted/--untrusted, the terminal prompt, no terminal meaning no, `trusted`, and
  trusted_hosts signed at once [Sharing: the join and create prompt and flags];
- sources: each harness's discovery, not-shareable reasons, references, missing_env, `sources` and
  `sources refresh`, the PUT route, and `attach` output [Sources];
- capabilities: create with operations, resources, and both (the local API with claim policies signed here as the
  CLI would, from the edit route); refusals, including the policies (missing, without the claim, not verifying);
  repeat and conflict (an identical CLI repeat signing nothing); list and show [Capabilities];
- claims: one per network at creation through the CLI (an edit, the empty principals line), never authorizing,
  refused on another of the person's hosts, kept after the last unshare, at the first share in a network bound
  later (`later`, created on p2) and refused there when another host holds the name, removed with the
  capability, none for a host without a person (u1) [Capabilities: claims]; the guided share's claims are checked
  under sharing;
- policy v2: capability rule lines and JSON (with `edits` and claims) verified with ssh-keygen over this suite's
  encoding, validation (one name bound to two hosts, 256 rules with claims, 0 to 64 principals, the `edits`
  bounds), v1 acceptance (in `v1only`, created on q2, where no host has edits), coordinator acceptance, sibling
  propagation, and each implementation's stored statement hash matching this suite's for a policy with claims,
  trusted hosts, and edits [Policy v2];
- sharing: `share NAME --with` (the review, `(can change things)`, --calls-per-hour on an existing rule, terminal,
  --yes, refusal), the guided share (flags, terminal, refusal), `shares`, `unshare`, several networks [Sharing];
- trust/untrust [Sharing];
- open list: `sources open-to`/`close-to`, --all, refusals, the listing, and activity [Sharing];
- authorization: policy, self, the source gate (open and trusted, trusted not open, open but untrusted, `*`
  covering a host trusted later), sources never reaching another person, a rule bound to another host, self
  refused, blocks, operations and URIs outside the capability, 413/429/deadline, budgets, rechecks (rejecting and
  leaving queued), and grant citations [Authorization];
- routes: GET /peer/v1/capabilities filtered, sorted, with via and ?network; non-submitter 404 [Routes];
- calls: the lifecycle for tool operations and `read`, on capabilities and sources; a tool added to a source;
  errors; duplicates; a lost response; expiry; cancellation; deadline; restart; server exit; concurrency; calls
  running across `unshare` [Calls];
- values: captured values, the environment file (filtered, too open), a literal token, and secrets nowhere
  outside tool_values [Sources];
- own credential: a separate instance, the whole env_file, and args [Capabilities];
- snapshots: pagination, snapshot_error keeping the previous snapshot, the bounds [Sources];
- configuration changes: a dropped server and a disappearing tool or resource making capabilities unavailable,
  and recovery [Sources, Capabilities];
- CLI: discover, call (--input, --KEY VALUE and errors, call's own flags, --deadline, --wait, exit codes),
  resolution errors, calls listings [CLI];
- status: the capabilities counts (shared excluding claims) with open_to, item 14 [Status];
- removal: `capability remove` with and without shares, keeping the record when signing fails and finishing on
  repeat [Removal, Capabilities];
- tie-break [Policy v2];
- idle stop [Calls];
- concurrent claims: p1 and p4 each create `clash` while the other and the coordinator are stopped; the loser's
  re-applied claim is dropped (closed, item 17), item 15 reports it, discover addresses the claimed copy as
  PERSON/CAPABILITY and the other only as HOST_ID/CAPABILITY, `call` resolves accordingly, and the losing copy
  cannot be shared [Capabilities: item 15, Status, CLI: discover].
Once per run: the adopted v2 test vector (and the v1 vector) built with this suite's encoding, signed, and
verified with ssh-keygen [Policy v2], and migration from version 15 to the current 17 in each direction
[Migration].

Where the contract is silent, the suite takes the narrowest reading or makes no assertion; those spots are marked
"ambiguous" in comments and soft results are printed as NOTE lines, not failures.

Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen), OpenSSL, and peerspan-peer-probe. A pairing takes about 25
minutes, part of it the idle-stop wait. Exits non-zero listing every failed section.
"""
import argparse
import base64
from datetime import datetime, timezone
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
from host_service import CAPABILITY_TABLES, POLICY_EDIT_TABLES, Host, stop_all
from launch_directory import DirectoryHost
from launch_onboarding import DEFAULT, Failure, need, parse_time
from peer_messaging import DropResponse, fixture_context, set_probe, timestamp, wire
from persons import Agent, coord_db, person_id, ssh_key, ssh_sign, ssh_verify
from policy import edit_start, edits_list, edits_map, policy_lines, policy_lines_v1, policy_lines_v2, sign_edit

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / 'fixtures' / 'mcp' / 'server.py'
HARNESS = HERE / 'fixtures' / 'harness'
PYTHON = str(Path(sys.executable).resolve())

# --- shapes from the contract ----------------------------------------------------------------------------------

ATTACH_SERVER_KEYS = {'name', 'transport', 'shareable', 'reason', 'missing_env', 'tools', 'read_only_tools',
                      'snapshot_error'}
ATTACH_ERROR_KEYS = {'source', 'path', 'server', 'error'}
SOURCES_AGENT_KEYS = {'agent', 'workspace', 'servers'}
SERVER_KEYS = {'name', 'transport', 'command', 'args', 'env', 'url', 'source', 'disabled', 'shareable', 'reason',
               'missing_env', 'tools', 'resources', 'snapshot_at', 'snapshot_error', 'start_failed_at',
               'auth_error_at', 'capabilities'}
RECORD_KEYS = {'name', 'source', 'operations', 'resources', 'credential', 'bounds', 'state', 'unavailable',
               'created_at'}
RECIPIENT_KEYS = {'network_id', 'principal', 'label'}
CAP_RULE_KEYS = {'host', 'capability', 'principals', 'max_input_bytes', 'allow_disconnected', 'max_calls_per_hour'}
POLICY_V2_ORDER = ['format', 'network_id', 'person_public_key', 'version', 'issued_at', 'valid_until', 'rules',
                   'capability_rules', 'trusted_hosts', 'edits', 'signature']
SHARE_KEYS = {'policy', 'capability', 'principal', 'created'}
UNSHARE_KEYS = {'policy', 'capability', 'principal', 'removed'}
TRUST_KEYS = {'policy', 'host', 'trusted', 'changed'}
PEER_ENTRY_KEYS = {'kind', 'capability', 'operations', 'resources', 'state', 'unavailable', 'via'}
OPERATION_KEYS = {'name', 'description', 'input_schema', 'read_only'}
RESOURCE_KEYS = {'uri', 'name', 'description', 'mime_type'}
STATUS_KEYS = {'call_id', 'sender_host_id', 'receiver_host_id', 'capability', 'operation', 'state',
               'cancel_requested', 'error', 'result_bytes', 'created_at', 'started_at', 'finished_at'}
OUTBOUND_KEYS = {'peer_host_id', 'target', 'network_id', 'request', 'submit_state', 'status', 'result',
                 'cancel_state', 'attempts', 'next_attempt_at', 'error', 'status_queries'}
DISCOVER_KEYS = {'agents', 'capabilities', 'unanswered'}
DISCOVER_ENTRY_KEYS = {'address', 'host_id', 'kind', 'capability', 'operations', 'resources', 'state',
                       'unavailable', 'via'}
CAPABILITY_COUNTS = {'sources', 'capabilities', 'shared', 'calls_running'}
FINAL = {'succeeded', 'failed', 'rejected', 'expired', 'cancelled', 'uncertain'}
LAPSED = 'authorization lapsed before start'
JOIN_PROMPT = ('Let this machine use your capabilities on your other machines, and the tools of those that allow '
               'it? [y/N]')
SHARE_PROMPT = 'Share? [y/N]'
REACH = ('can use these operations with the credentials they run with on this host. Anything those credentials '
         'can reach through them,')
CAN_CHANGE = '(can change things)'
# The fixture's tools (fixtures/mcp/server.py): readOnlyHint true, false, and absent; `read` is a tool literally
# named read, which the contract reserves as an operation name.
RO_TOOLS = {'echo', 'info', 'env_names', 'env_matches', 'sleep', 'fail', 'tool_error', 'big', 'crash', 'read',
            'typed', 'flags'}
WRITE_TOOLS = {'write_note', 'purge'}
ALL_RESOURCES = {'fixture://docs/readme', 'fixture://docs/guide', 'file:///srv/docs/a.txt', 'file:///srv/private/b.txt'}
DOCS = ['fixture://docs/guide', 'fixture://docs/readme']
WORK_OPERATIONS = ['echo', 'info', 'sleep', 'fail', 'tool_error', 'big', 'crash', 'write_note', 'typed', 'flags',
                   'env_names', 'env_matches']
# Python sets LC_CTYPE itself when started in the C locale (PEP 538), so the fixture may report it although the
# daemon did not pass it.
INTERPRETER_NAMES = {'LC_CTYPE'}
CANARY = 'PEERSPAN_TOOLS_CANARY'
CURRENT_VERSION = 17   # database version 17: policy_edits (coordination contract, Concurrent edits)
DAY = 86400

# The adopted test vector's inputs (Policy statement, version 2: Test vector). The contract gives inputs, not the
# statement; this suite's statement is printed for comparison with the implementations'.
SECOND_PERSON = 'person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2'
VECTOR_NETWORK = 'net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e'
VECTOR_PERSON_SEED = 'BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU='
VECTOR_PERSON_SSH = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx'


def call_id():
    return 'call_' + secrets.token_hex(16)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def squash(text):
    return ' '.join(text.split())


def dig(value, *keys):
    """value[k1][k2]..., or None where any step is missing or null (so checks fail with a message)."""
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, list) and isinstance(key, int) and -len(value) <= key < len(value):
            value = value[key]
        else:
            return None
    return value


def first_text(result):
    """The first text content of a CallToolResult, parsed as JSON when it is JSON."""
    need(isinstance(result, dict) and isinstance(result.get('content'), list) and result['content'] and
         isinstance(result['content'][0], dict) and 'text' in result['content'][0],
         'a result: a CallToolResult with text content', str(result)[:300])
    text = result['content'][0]['text']
    try:
        return json.loads(text)
    except ValueError:
        return text


def plain(rules):
    """v1 rules without an absent or zero max_artifact_bytes."""
    return [{k: v for k, v in r.items() if not (k == 'max_artifact_bytes' and not v)} for r in rules]


def policy_of(value):
    return {k: v for k, v in value.items() if k != 'expires_soon'}


def policy_hash(p):
    return hashlib.sha256('\n'.join(policy_lines(p)).encode()).hexdigest()


def rfc3339(seconds_from_now):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + seconds_from_now))


def crafted_v2(current, version, key, directory, capability_rules=None, trusted=None, edits=None):
    """The next v2 policy, signed here with OpenSSH over this suite's v2 lines, in the contract's key order.

    It is not an edit: like a renewal it copies `edits` (coordination contract, Concurrent edits) unless `edits` is
    given, so no host's edits stop being reflected (which would make them unsettled, re-applied, and enforced
    locally). The contract does not say how a daemon treats a policy submitted through its local API whose entry
    for this host is unchanged; this suite reads it, most literally, as no edit of this host (it cites no new seq)."""
    p = {'format': 2, 'network_id': current['network_id'], 'person_public_key': current['person_public_key'],
         'version': version, 'issued_at': rfc3339(-60), 'valid_until': rfc3339(7 * DAY),
         'rules': current.get('rules') or [],
         'capability_rules': (current.get('capability_rules') or []) if capability_rules is None else capability_rules,
         'trusted_hosts': sorted((current.get('trusted_hosts') or []) if trusted is None else trusted)}
    if edits is not None:
        p['edits'] = edits
    elif 'edits' in current:
        p['edits'] = edits_list(edits_map(current))
    p['signature'] = ssh_sign(policy_lines_v2(p), key, directory)
    return p


def crafted_v1(network_id, person_public_key, version, rules, key, directory):
    p = {'network_id': network_id, 'person_public_key': person_public_key, 'version': version,
         'issued_at': rfc3339(-60), 'valid_until': rfc3339(7 * DAY), 'rules': rules}
    p['signature'] = ssh_sign(policy_lines_v1(p), key, directory)
    return p


def cap_rule(host, capability, principals, max_input_bytes=65536, allow_disconnected=False, max_calls_per_hour=100):
    return {'host': host, 'capability': capability, 'principals': principals, 'max_input_bytes': max_input_bytes,
            'allow_disconnected': allow_disconnected, 'max_calls_per_hour': max_calls_per_hour}


# --- hosts ----------------------------------------------------------------------------------------------------

class CapHost(DirectoryHost):
    """A daemon of one implementation driven by a CLI of either, with its own HOME and XDG_CONFIG_HOME. The CLI
    never inherits CODEX_HOME or FX_* from the suite; the daemon gets a canary variable that must never reach a
    server's environment. No CLI call is at a terminal unless run through at_terminal or converse."""

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
        command = argv or [self.cli_binary, '--state', str(self.state), *args]
        stdin = {'input': piped} if piped is not None else {'stdin': subprocess.DEVNULL}
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, **stdin,
                              env=self.environment(sock, env), cwd=cwd, preexec_fn=self.preexec())

    def outcome(self, *args, env=None, cwd=None, timeout=90, piped=None, sock=DEFAULT):
        """(exit code, parsed stdout or None, stdout, stderr)."""
        r = self.run(*args, env=env, cwd=cwd, timeout=timeout, piped=piped, sock=sock)
        try:
            value = json.loads(r.stdout) if r.stdout.strip() else None
        except ValueError:
            value = None
        return r.returncode, value, r.stdout, r.stderr

    def converse(self, *args, answers=(), prompt=None, env=None, timeout=90, quiet=0.8):
        """Run the CLI with stdin and stderr on a pseudo-terminal that is its controlling terminal, and stdout on a
        pipe. Sends each answer in turn once output has grown since the last answer and then been quiet for
        `quiet` seconds (or after 8 seconds); the last answer waits for `prompt` when given. Returns (exit code,
        parsed stdout or None, terminal text, stdout, whether `prompt` was seen)."""
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
        pending = list(answers)
        seen, mark, last_output, last_answer = b'', 0, time.monotonic(), time.monotonic()
        prompt_seen = False
        started = time.monotonic()
        try:
            while time.monotonic() - started < timeout:
                ready, _, _ = select.select([master], [], [], 0.1)
                if master in ready:
                    try:
                        data = os.read(master, 4096)
                    except OSError:
                        data = b''
                    if data:
                        seen += data
                        last_output = time.monotonic()
                    elif process.poll() is not None:
                        break
                elif process.poll() is not None:
                    break
                text = squash(seen.decode(errors='replace'))
                if prompt and squash(prompt) in text:
                    prompt_seen = True
                if not pending:
                    continue
                now = time.monotonic()
                final = len(pending) == 1 and prompt is not None
                grown = len(seen) > mark and now - last_output >= quiet
                if (final and prompt_seen) or (not final and grown) or now - last_answer > 8:
                    os.write(master, (pending.pop(0) + '\n').encode())
                    mark, last_answer = len(seen), now
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
        return process.returncode, value, seen.decode(errors='replace'), stdout, prompt_seen

    def at_terminal(self, *args, answer='y', prompt=None, env=None, timeout=60):
        return self.converse(*args, answers=[answer], prompt=prompt, env=env, timeout=timeout)


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

    def args(self, key, *labels, page_size=None, generate=None, isolated=True):
        args = (['-I'] if isolated else []) + [str(FIXTURE), f'log={self.log(key)}', f'control={self.control(key)}']
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

    def reads(self, key, uri=None):
        return [e for e in self.entries(key) if e['event'] == 'read' and (uri is None or e['uri'] == uri)]

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
        self.secrets = {}
        self.exposed = []   # (where, text) collected for the secret scan
        self.notes = []     # soft results where the contract is silent
        self.pre_claims = False
        self.setup_notes = []

    # --- infrastructure --------------------------------------------------------------------------------------

    def host(self, name):
        h = CapHost(self.daemon, self.cli_binary, self.root / name, self.root / f'user-{name}')
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

    def soft(self, condition, rule, *detail):
        """Where the contract leaves something open: report, do not fail."""
        if not condition:
            self.notes.append(f'{rule}: ' + ' | '.join(repr(d)[:300] for d in detail))
            print(f'NOTE {self.label} (not counted; contract silent): {rule}', flush=True)

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

    def sync_all(self, net=None):
        net = net or self.team
        version = self.version('p1', net)
        members = self.team_members if net == self.team else self.other_members
        self.synced(version, *[n for n in members if n != 'p1'], net=net)
        return version

    def cap_rules(self, net=None, host='p1'):
        return (self.policy(host, net) or {}).get('capability_rules') or []

    def rule_for(self, capability, net=None, serving='p1'):
        rules = [r for r in self.cap_rules(net) if r['capability'] == capability and r['host'] == self.ids[serving]]
        return rules[0] if rules else None

    def principal(self, label):
        return {'quinn': 'person:' + self.quinn, 'rhea': 'person:' + self.rhea, 'pat': 'person:' + self.pat}[label]

    def share(self, name, *args, net=None, host='p1', terminal=None, piped=None, expect=True):
        """`share` with the given arguments. Returns (exit code, output, stderr or terminal text); a signing share
        must sign exactly version + 1."""
        h = self.hosts[host]
        before = self.version(host, net)
        argv = ['share', *([name] if name else []), *args, '--network', net or self.team]
        if terminal is not None:
            code, out, tty, stdout, seen = h.at_terminal(*argv, answer=terminal, prompt=SHARE_PROMPT)
            stderr = tty
            if code == 0:
                need(seen, f'share asks once: {SHARE_PROMPT}', tty[-500:])
        else:
            code, out, stdout, stderr = h.outcome(*argv, piped=piped)
        if code == 0:
            need(isinstance(out, dict) and set(out) == SHARE_KEYS, 'share prints {policy, capability, principal, '
                 'created}', args, out)
            after = self.version(host, net)
            need(after in (before, before + 1) and out['policy'].get('version') == after,
                 'share signs the next version (or nothing when unchanged) and prints the policy', before, after)
        else:
            need(self.version(host, net) == before, 'a refused share signs nothing', args, before)
        if expect is True:
            need(code == 0, f'share {name} {" ".join(args)}', code, stderr[-600:])
        return code, out, stderr

    def unshare(self, name, label, net=None, host='p1'):
        before = self.version(host, net)
        out = self.hosts[host].cli('unshare', name, '--with', label, '--network', net or self.team)
        if out.get('removed') == 0:
            need(set(out) == UNSHARE_KEYS | {'note'} and isinstance(out['note'], str) and out['note'].strip() and
                 self.version(host, net) == before,
                 'unshare removing nothing: {policy, capability, principal, removed: 0, note}, signing nothing', out)
        else:
            need(set(out) == UNSHARE_KEYS and self.version(host, net) == before + 1,
                 'unshare prints {policy, capability, principal, removed} and signs the next version', out)
        return out

    def claim_policies(self, host, name):
        """The `policies` the CLI sends with POST /v1/capabilities (capabilities contract, Claims: At creation),
        signed here as the CLI would: for each network in which the host is bound to its person, the edit route's
        policy plus this host's claim for NAME (65,536, false, 100), signed as an edit. A rule the policy already has
        for NAME is left as it is (so a name bound to another host stays bound there, for the daemon to refuse).
        Empty for a host without a person."""
        person = self.person_of.get(host)
        if not person:
            return []
        if self.pre_claims:
            return None
        hid, out = self.ids[host], []
        for net in self.bound[host]:
            status, start = edit_start(self.hosts[host], net)
            if status == 404 and not isinstance(start, dict):
                # A router's plain 404: an implementation from before claims. The record is sent without claims so
                # that sections unrelated to claims still run against it; the claims sections fail on their own.
                if not self.pre_claims:
                    self.pre_claims = True
                    self.setup_notes.append('no edit route (an implementation from before claims): capabilities '
                                            'created through the API without claim policies')
                return None
            need(status == 200 and isinstance(start, dict) and set(start) == {'policy', 'version', 'seq'},
                 'GET /v1/networks/{id}/policy/edit returns {policy, version, seq}', host, net, status, start)

            def change(p):
                if not any(r['capability'] == name for r in p['capability_rules']):
                    p['capability_rules'].append(cap_rule(hid, name, []))
            out.append(sign_edit(start, net, self.keys[person][2], hid, self.keys[person][0], self.root, change))
        return out

    def claims_field(self, host, name):
        """{'policies': claim_policies(...)}, or {} against an implementation from before claims."""
        policies = self.claim_policies(host, name)
        return {} if policies is None else {'policies': policies}

    def versions(self, host='p1'):
        """The host's stored version of its person's policy in each network where it is bound."""
        person = self.person_of.get(host)
        pid = {'pat': self.pat, 'quinn': self.quinn, 'rhea': self.rhea}.get(person)
        return {net: (self.policy(host, net, pid) or {}).get('version', 0) for net in self.bound[host]}

    def create(self, name, source, *args, host='p1', expect=201, policies=None):
        """`capability create` through the local API (so that status codes are checked), with the claims signed
        here (see claim_policies) unless `policies` is given. Returns (status, body)."""
        agent, _, server = source.partition('/')
        body = {'name': name, 'source': {'agent': agent, 'server': server}, 'operations': None, 'resources': None,
                'env_file': None}
        flags = list(args)
        while flags:
            flag, value = flags.pop(0), flags.pop(0)
            if flag == 'operations':
                body['operations'] = value
            elif flag == 'resources':
                body['resources'] = value
            elif flag == 'env_file':
                body['env_file'] = value
            elif flag == 'args':
                body['args'] = value
        body.update(self.claims_field(host, name) if policies is None else {'policies': policies})
        status, out = self.hosts[host].call('POST', '/v1/capabilities', body)
        if expect is not None:
            need(status == expect, f'POST /v1/capabilities {name}', expect, status, out)
        return status, out

    def capability(self, name, host='p1'):
        status, body = self.hosts[host].call('GET', f'/v1/capabilities/{name}')
        return body if status == 200 else None

    def capability_list(self, host='p1'):
        status, body = self.hosts[host].call('GET', '/v1/capabilities')
        need(status == 200 and isinstance(body, dict) and set(body) == {'capabilities'},
             'GET /v1/capabilities returns {capabilities: [...]}', status, str(body)[:300])
        return body['capabilities']

    def listing(self, receiver, caller, network=None):
        path = '/peer/v1/capabilities' + (f'?network={network}' if network else '')
        return wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'GET', path)

    def entry(self, listing, capability):
        for e in listing:
            if e.get('capability') == capability:
                return e
        return None

    def body(self, capability, operation, input=None, deadline=None, cid=None, cite=None):
        b = {'call_id': cid or call_id(), 'capability': capability, 'operation': operation,
             'input': input if input is not None else {}, 'deadline': deadline or timestamp(300)}
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
        net = net or self.team
        return {'policy': {'person_id': self.pat, 'network_id': net, 'version': self.version('p1', net)}}

    def self_cite(self, net=None):
        return {'self': {'person_id': self.pat, 'network_id': net or self.team}}

    def call(self, caller, target, operation, input=None, *extra, wait='30s', timeout=120):
        argv = ['call', target, operation]
        if input is not None:
            argv += ['--input', json.dumps(input)]
        argv += ['--wait', wait, *extra]
        code, out, stdout, stderr = self.hosts[caller].outcome(*argv, timeout=timeout)
        self.exposed += [(f'{caller} call stdout', stdout), (f'{caller} call stderr', stderr)]
        if isinstance(out, dict):
            self.check_final(out)
        return code, out, stderr

    def inspect(self, caller, peer, cid):
        return self.hosts[caller].cli('calls', 'inspect', '--peer', peer, cid)

    @staticmethod
    def check_final(record):
        """An outbound record's status is final only together with its result, from a GET: a final state that has
        a result (succeeded; failed with tool_error or jsonrpc_error) must carry it."""
        status = (record or {}).get('status') or {}
        if status.get('state') == 'succeeded' or (status.get('state') == 'failed' and
                                                  status.get('error') in ('tool_error', 'jsonrpc_error')):
            need(record.get('result') is not None, 'the outbound status is final only together with its result',
                 status, record.get('result'))

    def settle(self, caller, record, timeout=90):
        peer, cid = record['peer_host_id'], record['request']['call_id']

        def done():
            r = self.inspect(caller, peer, cid)
            return r if r.get('status') and r['status'].get('state') in FINAL else None
        final = wait_for(done, timeout=timeout, message=f'outbound call {cid} final')
        self.check_final(final)
        return final

    def outbound_count(self, caller):
        return db_rows(self.hosts[caller], 'SELECT COUNT(*) FROM outbound_calls')[0][0]

    def sources_view(self, host='p1', agent=None):
        args = ['sources', '--json'] + (['--agent', agent] if agent else [])
        code, out, stdout, stderr = self.hosts[host].outcome(*args)
        need(code == 0 and out is not None, 'sources --json', args, code, stderr[-400:])
        self.exposed.append((f'{host} sources --json', stdout))
        return out

    def servers(self, agent, host='p1'):
        """The SERVER entries of one agent in GET /v1/sources (`sources --json`), by server name."""
        view = self.sources_view(host)
        need(isinstance(view, dict) and set(view) == {'agents', 'open_to'} and isinstance(view['agents'], list),
             'GET /v1/sources is {agents: [AGENT], open_to}', str(view)[:400])
        names = [a['agent']['name'] for a in view['agents']]
        need(names == sorted(names), 'agents sorted by agent name', names)
        for a in view['agents']:
            need(set(a) == SOURCES_AGENT_KEYS and set(a['agent']) == {'id', 'name'},
                 'AGENT is {agent: {id, name}, workspace, servers}', a.get('agent'), sorted(a))
            if agent in (a['agent']['name'], a['agent']['id']):
                for server in a['servers']:
                    need(set(server) == SERVER_KEYS, 'SERVER has exactly the contract\'s fields', server.get('name'),
                         sorted(set(server) ^ SERVER_KEYS))
                return {server['name']: server for server in a['servers']}
        raise Failure(f'GET /v1/sources: agent {agent} listed: {json.dumps(view)[:800]}')

    def open_list(self, host='p1'):
        status, body = self.hosts[host].call('GET', '/v1/sources')
        need(status == 200, 'GET /v1/sources', status)
        return body['open_to']

    def open_to(self, host, target, expect=(200, 201)):
        status, body = self.hosts[host].call('POST', '/v1/sources/open-to', {'host_id': target})
        need(status in expect, f'POST /v1/sources/open-to {target}', expect, status, body)
        return status, body

    def close_to(self, host, target):
        status, body = self.hosts[host].call('DELETE', f'/v1/sources/open-to/{target}')
        need(status == 200, f'DELETE /v1/sources/open-to/{target}', status, body)
        return body

    @staticmethod
    def tool_names(server):
        return {t['name']: t for t in server['tools']}

    def refresh(self, agent='cc', timeout=150):
        code, out, stdout, stderr = self.hosts['p1'].outcome('sources', 'refresh', '--agent', agent,
                                                              env=self.cli_env, timeout=timeout)
        self.exposed += [('sources refresh stdout', stdout), ('sources refresh stderr', stderr)]
        need(code == 0, f'sources refresh --agent {agent}', code, stderr[-500:])
        return out

    def status(self, host='p1'):
        status, value = self.hosts[host].call('GET', '/v1/status')
        need(status == 200, 'GET /v1/status', status)
        return value

    def counts(self, host='p1'):
        value = self.status(host)
        need('open_to' not in value, 'open_to sits inside status capabilities', sorted(value))
        return dict(value.get('capabilities') or {})

    def items(self, host='p1', kind='capability_failing'):
        return [i for i in self.status(host).get('attention', []) if i.get('kind') == kind]

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
        """Occupy the cc/fx source instance's 4 slots with self calls from p2 on capability `work` (which runs on the
        source's own instance; self has no hourly budget), returning once the fixture has started them all."""
        before = len(self.fixture.calls('fx-local', name='sleep'))
        ids = []
        for _ in range(count):
            b = self.body('work', 'sleep', {'seconds': seconds, 'text': 'slot'}, cite=self.self_cite())
            status, record = self.submit('p2', b)
            need(status == 200, 'setup: a self call from a trusted host fills a slot', status, record)
            ids.append(b['call_id'])
        wait_for(lambda: len(self.fixture.calls('fx-local', name='sleep')) >= before + count, timeout=30,
                 message='4 running calls')
        return ids

    def clear(self, label='rhea'):
        """Remove a principal from every capability rule for p1 in team, so a failed section leaves nothing behind."""
        principal = self.principal(label)
        for r in self.cap_rules():
            if principal in r['principals'] and r['host'] == self.ids['p1']:
                self.hosts['p1'].run('unshare', r['capability'], '--with', label, '--network', self.team)

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
            w = self.root / 'projects' / name
            w.mkdir(parents=True)
            self.workspaces[name] = w.resolve()
        w1, w3, w5 = self.workspaces['w1'], self.workspaces['w3'], self.workspaces['w5']

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
                             args=f.args('proj', '${FX_LABEL}', '${FX_UNSET_LABEL:-dflt}', '${FX_EMPTY:-wasempty}')),
        }
        self.local_servers = {
            'fx': f.claude('fx-local', 'local', env={'FX_CAPTURED': '${FX_TOKEN}'}),
            'lit': f.claude('lit', env={'LIT_TOKEN': self.secrets['literal']}),
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
        need(isinstance(body, dict) and set(body) == SOURCES_AGENT_KEYS and body['agent']['id'] == self.aid[agent] and
             sorted(x['name'] for x in body['servers']) == sorted(servers),
             'the PUT response is the agent object, returned once snapshots finish', str(body)[:400])
        return body

    def register(self, host, name):
        self.hosts[host].cli('agent', 'register', '--name', name, '--owner', 'pat')
        agent = next(a for a in self.hosts[host].cli('agent', 'list') if a['name'] == name)
        self.aid[name] = agent['id']
        return agent

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
        return h.cli('join', token)

    def create_network(self, name, *flags, terminal=None):
        p1 = self.hosts['p1']
        argv = ('network', 'create', name, '--as', 'pat', *flags, *self.coordinator_flags())
        if terminal is not None:
            code, out, tty, stdout, seen = p1.at_terminal(*argv, answer=terminal, prompt=JOIN_PROMPT)
            self.create_terminal = (code, out, tty, seen)
        else:
            code, out, stdout, stderr = p1.outcome(*argv)
            if code != 0:
                self.setup_notes.append(f'network create {" ".join(flags)} failed ({code}): {stderr[-300:]}')
        if code != 0 or not out:
            out = p1.cli('network', 'create', name + '-plain', '--as', 'pat', *self.coordinator_flags())
        self.create_outputs[name] = out
        return out['id']

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
                        'file': 'file-' + secrets.token_hex(12), 'own': 'own-' + secrets.token_hex(12)}
        self.cli_env = {'FX_TOKEN': self.secrets['captured'], 'FX_LABEL': 'fromenv', 'FX_EMPTY': ''}
        self.fixture = Fixture(root / 'fixture')
        self.setup_catalog()
        self.join_terminal, self.attached, self.create_outputs, self.join_outputs = {}, {}, {}, {}

        self.coord_key = self.coord.start()['public_key']
        persons = {'p1': 'pat', 'p2': 'pat', 'p3': 'pat', 'p4': 'pat', 'q1': 'quinn', 'q2': 'quinn', 'r': 'rhea',
                   'u1': None, 'u2': None, 'n': None}
        for name, person in persons.items():
            self.host(name).sock = self.agents[person].socket if person else None
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids, p1 = self.ids, self.hosts['p1']

        # Networks, with the trust flags and prompt (checked in the first section).
        self.team = self.create_network('team', '--untrusted')
        self.join_outputs['p2'] = self.join('p2', self.invite('pat'), '--trusted')
        self.join_outputs['p3'] = self.join('p3', self.invite('pat'))
        self.join_outputs['p4'] = self.join('p4', self.invite('pat'), terminal='y')
        for name, label in (('q1', 'quinn'), ('q2', 'quinn'), ('r', 'rhea')):
            self.join_outputs[name] = self.join(name, self.invite(label))
        for name in ('u1', 'u2'):
            self.join_outputs[name] = self.hosts[name].cli('join', self.invite(name), '--no-person')
        self.team_members = ['p1', 'p2', 'p3', 'p4', 'q1', 'q2', 'r', 'u1', 'u2']
        self.other = self.create_network('other', '--trusted')
        self.join_outputs['p2-other'] = self.join('p2', self.invite('pat', self.other), '--untrusted')
        self.join_outputs['q1-other'] = self.join('q1', self.invite('quinn', self.other))
        self.other_members = ['p1', 'p2', 'q1']
        self.create_terminal = None
        self.v1net = self.create_network('v1net', terminal='n')
        self.person_of = persons
        # The networks in which each host is bound to its person (claims are signed in each).
        self.bound = {'p1': [self.team, self.other, self.v1net], 'p2': [self.team, self.other], 'p3': [self.team],
                      'p4': [self.team], 'q1': [self.team, self.other], 'q2': [self.team], 'r': [self.team],
                      'u1': [], 'u2': [], 'n': []}

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
        for a in p1.cli('agent', 'list'):
            self.aid.setdefault(a['name'], a['id'])
        for name, (code, out, stderr) in self.attached.items():
            if code != 0:
                self.setup_notes.append(f'attach {name} failed ({code}): {stderr[-300:]}')

        # The own-credential environment file.
        self.own_env = self.root / 'narrow.env'
        self.own_env.write_text(f"# the narrow capability\nFX_CAPTURED={self.secrets['own']}\nOWN_ONLY=unnamed\n")
        self.own_env.chmod(0o600)

        # Capabilities and shares later sections rely on (soft: failures surface in those sections).
        self.base = {}
        for name, source, args in (
                ('work', 'cc/fx', ('operations', WORK_OPERATIONS, 'resources', 'all')),
                ('docs', 'cc/fx', ('resources', DOCS)),
                ('budget', 'cc/budget', ('operations', ['echo'])),
                ('budget2', 'cc/budget2', ('operations', ['echo'])),
                ('litcap', 'cc/lit', ('operations', ['echo', 'env_matches'])),
                ('gonecap', 'cc/gone', ('operations', ['echo', 'sleep'])),
                ('narrow', 'cc/fx', ('operations', ['env_matches', 'env_names', 'info', 'write_note'],
                                     'env_file', str(self.own_env),
                                     'args', self.fixture.args('fx-narrow', 'narrow', isolated=False)))):
            try:
                self.base[name] = self.create(name, source, *args, expect=None)
            except Exception as error:
                self.setup_notes.append(f'capability {name}: {error}')
        p1.run('sources', 'open-to', ids['p2'])  # p2 calls p1's sources throughout
        for args, net in ((('work', '--with', 'quinn'), self.team), (('docs', '--with', 'quinn'), self.team),
                          (('budget', '--with', 'quinn', '--calls-per-hour', '3'), self.team),
                          (('budget2', '--with', 'everyone', '--calls-per-hour', '2'), self.team),
                          (('litcap', '--with', 'quinn'), self.other), (('work', '--with', 'quinn'), self.other)):
            code, out, stdout, stderr = p1.outcome('share', *args, '--yes', '--network', net)
            if code != 0:
                self.setup_notes.append(f'share {args} failed: {stderr[-200:]}')
        try:
            self.sync_all(self.team)
            self.sync_all(self.other)
        except Exception as error:
            self.setup_notes.append(f'share sync: {error}')

        # The idle-stop source: on p4, open to p2, called once by p2 (self) right after setup.
        self.idle_started = None
        try:
            self.register('p4', 'idler')
            self.put_servers('p4', 'idler', self.root, {'idle': self.fixture.args('idle')})
            self.hosts['p4'].call('POST', '/v1/sources/open-to', {'host_id': ids['p2']})
            b = self.body('idler/idle', 'echo', {'text': 'idle'}, cite=self.self_cite())
            status, _ = self.submit('p2', b, receiver='p4')
            if status == 200:
                self.final('p2', b['call_id'], receiver='p4')
                self.idle_started = time.time()
                threading.Thread(target=self.watch_idle, daemon=True).start()
            else:
                self.setup_notes.append(f'idle source call: {status}')
        except Exception as error:
            self.setup_notes.append(f'idle source setup: {error}')

        self.section('trust at create and join', self.check_trust_at_join)
        self.section('sources', self.check_sources)
        self.section('capabilities', self.check_capabilities)
        self.section('claims', self.check_claims)
        self.section('policy v2', self.check_policy_v2)
        self.section('sharing', self.check_sharing)
        self.section('trust/untrust', self.check_trust)
        self.section('open list', self.check_open_list)
        self.section('authorization', self.check_authorization)
        self.section('routes', self.check_routes)
        self.section('calls', self.check_calls)
        self.section('values', self.check_values)
        self.section('own credential', self.check_own_credential)
        self.section('snapshots', self.check_snapshots)
        self.section('configuration changes', self.check_configuration_changes)
        self.section('CLI', self.check_cli)
        self.section('status', self.check_status)
        self.section('removal', self.check_removal)
        self.section('idle stop', self.check_idle_stop)
        self.section('concurrent claims and item 15', self.check_concurrent_claims)
        self.section('tie-break', self.check_tie_break)
        if self.setup_notes:
            print(f'NOTE {self.label} setup: ' + ' | '.join(self.setup_notes), flush=True)

    # --- sections ------------------------------------------------------------------------------------------

    def check_trust_at_join(self):
        failures = [n for n in self.setup_notes if 'join' in n or 'network create' in n]
        need(not failures, 'join and network create accept --trusted and --untrusted', *failures)
        team, other = self.create_outputs['team'], self.create_outputs['other']
        need(team.get('trusted') is False, 'network create --untrusted: output trusted false', team)
        need(other.get('trusted') is True, 'network create --trusted: output trusted true', other)
        need(self.join_outputs['p2'].get('trusted') is True, 'join --trusted: trusted true', self.join_outputs['p2'])
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
        for name, value in [*self.join_outputs.items(), *self.create_outputs.items()]:
            if name in ('u1', 'u2'):
                continue
            need(isinstance(value.get('trusted'), bool) and 'trusted_error' not in value,
                 'join and network create always output trusted, signing the trust change at once', name, value)
        ids = self.ids
        self.hosts['p1'].run('network', 'sync', self.team)
        p = self.policy('p1')
        need(p and p.get('format') == 2 and p['trusted_hosts'] == sorted([ids['p2'], ids['p4']]),
             'a yes adds the host to trusted_hosts, signed at once (sorted); no adds nothing',
             p and p.get('trusted_hosts'), ids)
        o = self.policy('p1', self.other)
        need(o and o['trusted_hosts'] == [ids['p1']], 'network create --trusted adds the creator', o)
        v1 = self.policy('p1', self.v1net)
        need(v1 is None or not v1.get('trusted_hosts'), 'network create answered n: no trusted host', v1)

    def check_sources(self):
        failures = [f'{name}: {code} {stderr[-300:]}' for name, (code, out, stderr) in self.attached.items()
                    if code != 0]
        need(not failures, 'attach --no-start succeeds for each harness', *failures)

        def attach_servers(name):
            out = self.attached[name][1]
            need(isinstance(out.get('sources'), dict) and set(out['sources']) == {'servers', 'errors'},
                 'attach adds sources: {servers, errors}', name, out)
            for x in out['sources']['servers']:
                need(set(x) == ATTACH_SERVER_KEYS, 'attach servers are {name, transport, shareable, reason, '
                     'missing_env, tools, read_only_tools, snapshot_error}', x)
                need(isinstance(x['tools'], int) and isinstance(x['read_only_tools'], int),
                     'tools and read_only_tools are counts', x)
            for e in out['sources']['errors']:
                need(set(e) == ATTACH_ERROR_KEYS, 'attach errors are {source, path, server, error}', e)
            return {x['name']: x for x in out['sources']['servers']}

        cc = attach_servers('cc')
        expected = {'fx', 'Bad.Name', 'rem', 'proj', 'lit', 'needy', 'needyarg', 'gone', 'slow', 'paged', 'budget',
                    'budget2', 'startfail', 'startslow', 'sserem'}
        need(set(cc) == expected, 'Claude Code: user, project, and local scopes; peerspan and peerspan_HEX skipped; '
             'a stdio entry without a command not sent', sorted(cc), sorted(expected))
        errors = self.attached['cc'][1]['sources']['errors']
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
             'missing_env lists the referenced variables that could not be resolved (env and args), never env keys',
             cc['needy'], cc['needyarg'])
        fx = cc['fx']
        need(fx['tools'] == len(RO_TOOLS | WRITE_TOOLS) + 1 and fx['read_only_tools'] == len(RO_TOOLS) + 1 and
             fx['snapshot_error'] is None, 'counts: read_only only for readOnlyHint true (purge has no annotations)',
             fx)

        servers = self.servers('cc')
        need(set(servers) == expected, 'GET /v1/sources lists the same servers', sorted(servers))
        fxs = servers['fx']
        need(fxs['source'] == 'claude-code:local' and fxs['command'] == PYTHON and fxs['url'] is None and
             fxs['disabled'] is False and fxs['env'] == {'FX_CAPTURED': {'source': 'captured'}},
             'the normalized definition (source INTEGRATION:SCOPE)', {k: fxs[k] for k in ('source', 'env', 'url')})
        need(sorted(fxs['capabilities']) == sorted(n for n in ('work', 'docs', 'narrow') if n in self.base),
             'SERVER capabilities lists this host\'s capabilities built on the server', fxs['capabilities'])
        tools = self.tool_names(fxs)
        need('from_local' in tools and 'from_user' not in tools and 'from_project' not in tools,
             'Precedence: the local scope definition is taken whole', sorted(tools))
        need(set(tools) == RO_TOOLS | WRITE_TOOLS | {'from_local'}, 'the snapshot lists every tool', sorted(tools))
        for name, t in tools.items():
            need(set(t) == {'name', 'description', 'input_schema', 'read_only'},
                 'stored tool entries are {name, description, input_schema, read_only}', t)
            need(t['read_only'] is (name in RO_TOOLS or name == 'from_local'),
                 'read_only is true only when annotations.readOnlyHint is true', name, t)
        resources = {r['uri']: r for r in fxs['resources']}
        need(set(resources) == ALL_RESOURCES, 'the snapshot lists resources', sorted(resources))
        for r in resources.values():
            need(set(r) == RESOURCE_KEYS, 'stored resource entries are {uri, name, description, mime_type}', r)
        proj = servers['proj']
        need({'from_fromenv', 'from_dflt', 'from_wasempty'} <= set(self.tool_names(proj)),
             'References: ${NAME}, and ${NAME:-D} using D when NAME is unset or empty', sorted(self.tool_names(proj)))
        need(proj['env'] == {'TOKEN_A': {'source': 'captured'}, 'TOKEN_B': {'source': 'captured'}} and
             proj['source'] == 'claude-code:project', 'env entries with references are captured', proj['env'])
        need(servers['lit']['env'] == {'LIT_TOKEN': {'source': 'literal'}}, 'literal env entries', servers['lit']['env'])
        need(servers['needy']['env'] == {'NEED': {'source': 'missing', 'variables': ['FX_MISSING_VAR']}},
             'unresolved references are {source: missing, variables}', servers['needy']['env'])
        need(servers['rem']['tools'] == [] and servers['rem']['resources'] == [] and servers['rem']['url'],
             'tools and resources are [] without a snapshot', servers['rem'])

        cc2 = attach_servers('cc2')
        need(set(cc2) == {'fx', 'Bad.Name', 'rem'}, 'Claude Code: only the user scope for another workspace', sorted(cc2))
        need('from_user' in self.tool_names(self.servers('cc2')['fx']) and
             self.servers('cc2')['fx']['source'] == 'claude-code:user', 'the user scope definition')
        out = self.attached['cc3'][1]
        need(any(e['path'] and e['path'].endswith('.mcp.json') for e in out['sources']['errors']),
             'a source that does not parse is reported in errors with its path', out['sources'])
        need('fx' in attach_servers('cc3'), 'discovery continues after an unparsable source', out['sources'])

        cx = attach_servers('cx')
        need(set(cx) == {'cxs', 'cxoff', 'cxrem', 'cxoffrem'}, 'Codex: [mcp_servers.NAME] in ~/.codex/config.toml',
             sorted(cx))
        need(cx['cxs']['shareable'] is True and cx['cxs']['reason'] is None, 'Codex stdio server shareable '
             '(startup_timeout_ms ignored)', cx['cxs'])
        need(cx['cxoff']['reason'] == 'disabled' and cx['cxrem']['reason'] == 'remote' and
             cx['cxoffrem']['reason'] == 'remote', 'disabled, remote, and remote before disabled', cx)
        cx_servers = self.servers('cx')
        need(cx_servers['cxoff']['disabled'] is True and cx_servers['cxs']['source'] == 'codex:user' and
             'from_codexhome' in self.tool_names(cx_servers['cxs']), 'Codex definitions', cx_servers['cxs'])
        need(set(attach_servers('cx2')) == {'cxalt'}, 'Codex: $CODEX_HOME/config.toml replaces the default')

        oc = attach_servers('oc')
        need(set(oc) == {'ocs', 'ocover', 'ocoff', 'ocrem', 'ocenv'}, 'OpenCode: global and project files', sorted(oc))
        need(oc['ocoff']['reason'] == 'disabled' and oc['ocrem']['reason'] == 'remote', 'OpenCode enabled false and '
             'type remote', oc)
        ocs = self.servers('oc')
        need('from_project' in self.tool_names(ocs['ocover']) and 'from_global' not in self.tool_names(ocs['ocover'])
             and ocs['ocover']['source'] == 'opencode:project' and ocs['ocs']['source'] == 'opencode:global',
             'OpenCode: the project file takes precedence', ocs['ocover'])
        need('from_opencode' in self.tool_names(ocs['ocs']), 'OpenCode: command[0] and the rest as args')
        need(ocs['ocs']['env'] == {'OC_TOKEN': {'source': 'captured'}} and
             ocs['ocenv']['env'] == {'OC_FALLBACK': {'source': 'captured'}},
             'OpenCode reads environment, falling back to env', ocs['ocs']['env'], ocs['ocenv']['env'])

        # The PUT route's validation (refusals change nothing).
        good = {'name': 'idle', 'transport': 'stdio', 'command': PYTHON, 'args': self.fixture.args('idle'), 'env': {},
                'url': None, 'source': 'claude-code:user'}
        path = f"/v1/agents/{self.aid.get('idler', 'agent_' + '0' * 32)}/tool-servers"
        for bad in ({'servers': [{**good, 'extra': 1}]},
                    {'servers': [{**good, 'env': {'X': {'source': 'missing', 'variables': ['FX_X']}}}],
                     'values': {'idle': {'env.X': 'v'}}},
                    {'servers': [{**good, 'env': {'X': {'source': 'missing'}}}]},
                    {'servers': [{**good, 'env': {'X': {'source': 'missing', 'variables': []}}}]},
                    {'servers': [{**good, 'env': {'X': {'source': 'literal', 'variables': ['FX_X']}}}]},
                    {'servers': [{**good, 'env': {'X': {'source': 'other'}}}]},
                    {'servers': [{**good, 'env': {'X': 'literal'}}]}):
            status, body = self.hosts['p4'].call('PUT', path, {'workspace': str(self.root), **bad})
            need(status == 400, 'PUT refuses unknown fields, env values for missing entries, and other env shapes',
                 bad, status, body)

        # A literal or captured entry with no stored value is left unset, and is not missing_env.
        self.register('p4', 'envtest')
        definition = {'name': 'noval', 'transport': 'stdio', 'command': PYTHON, 'args': self.fixture.args('noval'),
                      'env': {'NOVAL_LIT': {'source': 'literal'}, 'NOVAL_CAP': {'source': 'captured'},
                              'WITH_VALUE': {'source': 'literal'}},
                      'url': None, 'source': 'claude-code:user'}
        status, body = self.hosts['p4'].call('PUT', f"/v1/agents/{self.aid['envtest']}/tool-servers",
                                             {'workspace': str(self.root), 'servers': [definition],
                                              'values': {'noval': {'env.WITH_VALUE': 'v'}}})
        need(status == 200, 'setup: PUT a definition with entries lacking stored values', status, body)
        noval = next(s for s in body['servers'] if s['name'] == 'noval')
        need(noval['shareable'] is True and noval['reason'] is None and noval['missing_env'] == [],
             'entries without a stored value do not make the server missing_env', noval)
        b = self.body('envtest/noval', 'env_names', {}, cite=self.self_cite())
        status, record = self.submit('p2', b, receiver='p4')
        need(status == 200, 'setup: p2 calls the source on p4', status, record)
        done = self.final('p2', b['call_id'], receiver='p4')
        names = set(first_text(done.get('result')))
        need('WITH_VALUE' in names and not {'NOVAL_LIT', 'NOVAL_CAP'} & names,
             'an entry without a stored value is left unset when the server starts', sorted(names))

        events = [e for e in self.activity('p1') if e['kind'] == 'sources.discovered']
        need({self.aid[a] for a in ('cc', 'cx', 'oc')} <= {e['subject_id'] for e in events},
             'sources.discovered activity with the agent ID', events[:5])
        code, out, stdout, stderr = self.hosts['p1'].outcome('sources')
        need(code == 0 and 'fx' in stdout and self.secrets['captured'] not in stdout,
             'sources prints a readable listing without values', code, stdout[:300])
        view = self.sources_view('p1', 'cc')
        need([a['agent']['name'] for a in view['agents']] == ['cc'], 'sources --agent NAME limits to one agent', view)

    def check_capabilities(self):
        api = self.hosts['p1']
        failures = [n for n in self.setup_notes if n.startswith('capability ')]
        need(not failures, 'setup: capability create', *failures)
        for name in ('work', 'docs', 'budget', 'narrow'):
            status, record = self.base[name]
            need(status == 201 and set(record) == RECORD_KEYS, 'POST /v1/capabilities returns 201 with the record',
                 name, status, record)
        status, work = self.base['work']
        need(work['name'] == 'work' and work['source'] == {'agent': 'cc', 'server': 'fx'} and
             work['operations'] == WORK_OPERATIONS and work['resources'] == 'all' and
             work['credential'] == {'env_file': None, 'args': None} and work['bounds'] == {} and
             work['state'] == 'available' and work['unavailable'] == [] and parse_time(work['created_at']),
             'the record: operations and resources (both)', work)
        docs = self.base['docs'][1]
        need(docs['operations'] == [] and sorted(docs['resources']) == DOCS, 'resources only (a URI list)', docs)
        budget = self.base['budget'][1]
        need(budget['operations'] == ['echo'] and budget['resources'] is None, 'operations only', budget)
        narrow = self.base['narrow'][1]
        need(narrow['credential']['env_file'] == str(self.own_env) and narrow['credential']['args'] ==
             self.fixture.args('fx-narrow', 'narrow', isolated=False), 'its own credential context', narrow)

        # Through the CLI: `--from SERVER` when exactly one agent has it, operations and resources.
        # (The CLI's output is not specified; the records are read back through the API.)
        code, out, stdout, stderr = api.outcome('capability', 'create', 'clitools', '--from', 'lit', '--operations',
                                                'echo')
        made = self.capability('clitools')
        need(code == 0 and made and made['source'] == {'agent': 'cc', 'server': 'lit'},
             'capability create --from SERVER when exactly one agent on this host has it', code, made, stderr[-300:])
        code, out, stdout, stderr = api.outcome('capability', 'create', 'clires', '--from', 'cc/fx', '--operations',
                                                'echo,info', '--resources', 'fixture://docs/readme,fixture://docs/guide')
        made = self.capability('clires')
        need(code == 0 and made and made['operations'] == ['echo', 'info'] and sorted(made['resources']) == DOCS,
             'capability create --operations and --resources lists', code, made, stderr[-300:])
        code, out, stdout, stderr = api.outcome('capability', 'create', 'cliall', '--from', 'cc/fx', '--resources',
                                                'all')
        made = self.capability('cliall')
        need(code == 0 and made and made['resources'] == 'all' and made['operations'] == [], '--resources all', code,
             made)
        code, out, stdout, stderr = api.outcome('capability', 'create', 'ambig', '--from', 'fx', '--operations', 'echo')
        need(code != 0, '--from SERVER refused when several agents have it', code)

        # Repeat and conflict. Through the CLI, an identical repeat signs nothing. Through the API, the body carries
        # claim policies signed here (the name is already claimed, so only the version and edits entry change); the
        # contract does not say whether a daemon stores such policies with an identical repeat, so only the status
        # is checked there.
        versions = self.versions()
        code, out, stdout, stderr = api.outcome('capability', 'create', 'clitools', '--from', 'lit', '--operations',
                                                'echo')
        need(code == 0 and self.versions() == versions, 'an identical repeat through the CLI succeeds and signs '
             'nothing', code, versions, self.versions(), stderr[-300:])
        body = {'name': 'clitools', 'source': {'agent': 'cc', 'server': 'lit'}, 'operations': ['echo'],
                'resources': None, 'env_file': None}
        status, again = api.call('POST', '/v1/capabilities', {**body, **self.claims_field('p1', 'clitools')})
        need(status == 200 and again['name'] == 'clitools', 'an identical repeat returns 200', status, again)
        versions = self.versions()
        status, _ = api.call('POST', '/v1/capabilities', {**body, 'operations': ['echo', 'env_names'],
                                                          **self.claims_field('p1', 'clitools')})
        need(status == 409 and self.versions() == versions,
             'a different record under the same name returns 409, storing nothing', status)

        # Refusals.
        for bad, code, why in (
                ({**body, 'name': 'nonshare', 'source': {'agent': 'cc', 'server': 'needy'}}, 400,
                 'a non-shareable source is 400'),
                ({**body, 'name': 'unknownop', 'source': {'agent': 'cc', 'server': 'fx'}, 'operations': ['nosuch']}, 400,
                 'an operation not in the snapshot is 400'),
                ({**body, 'name': 'unknownuri', 'source': {'agent': 'cc', 'server': 'fx'}, 'operations': None,
                  'resources': ['fixture://docs/missing']}, 400, 'a URI not in the snapshot is 400'),
                ({**body, 'name': 'readop', 'source': {'agent': 'cc', 'server': 'fx'}, 'operations': ['read']}, 400,
                 'a source tool named read cannot be an operation (400)'),
                ({**body, 'name': 'a/b'}, 400, 'a name containing / is 400'),
                ({**body, 'name': 'read'}, 400, 'a capability may not be named read'),
                ({**body, 'name': 'Bad.Name'}, 400, 'a name not matching the pattern is 400'),
                ({**body, 'name': 'noenv', 'source': {'agent': 'cc', 'server': 'fx'}, 'operations': ['echo'],
                  'env_file': str(self.root / 'missing.env')}, 400, 'a missing env_file is 400'),
                ({**body, 'name': 'relenv', 'source': {'agent': 'cc', 'server': 'fx'}, 'operations': ['echo'],
                  'env_file': 'relative.env'}, 400, 'env_file must be absolute'),
                ({**body, 'name': 'empty', 'source': {'agent': 'cc', 'server': 'fx'}, 'operations': None}, 400,
                 'at least one operation unless resources is set'),
                ({**body, 'name': 'extra', 'extra': 1}, 400, 'an invalid body is 400'),
                ({**body, 'name': 'nullargs', 'args': None}, 400, 'args is absent or an array'),
                ({**body, 'name': 'noagent', 'source': {'agent': 'nobody', 'server': 'fx'}}, 404,
                 'an unknown agent is 404'),
                ({**body, 'name': 'nosource', 'source': {'agent': 'cc', 'server': 'nosuch'}}, 404,
                 'an unknown source is 404'),
                ({**body, 'name': 'work'}, 409, 'a name in use on this host is 409')):
            versions = self.versions()
            # Each body carries valid claim policies, so that the refusal is the record's.
            status, out = api.call('POST', '/v1/capabilities', {**bad, **self.claims_field('p1', bad['name'])})
            need(status == code, why, status, out)
            need((self.capability(bad['name']) is None or bad['name'] == 'work') and self.versions() == versions,
                 'a refused create stores nothing (no record, no policy)', bad)
        # The policies: one per network in which this host is bound, each with this host's claim, each verifying.
        good = {**body, 'name': 'polcheck'}
        claims = self.claim_policies('p1', 'polcheck') or []
        unclaimed = []
        for net in (self.bound['p1'] if claims else []):
            status, start = edit_start(api, net)
            unclaimed.append(sign_edit(start, net, self.keys['pat'][2], self.ids['p1'], self.keys['pat'][0],
                                       self.root))
        tampered = [dict(claims[0], signature=claims[1]['signature'])] + claims[1:] if claims else []
        cases = [] if not claims else [
            ([], 'no policies'), (claims[:-1], 'a missing policy for a network in which this host is bound'),
            ([unclaimed[0]] + claims[1:], 'a policy without this host\'s claim'),
            (tampered, 'a policy that fails verification')]
        for policies, why in cases:
            versions = self.versions()
            status, out = api.call('POST', '/v1/capabilities', {**good, 'policies': policies})
            need(status == 400 and self.capability('polcheck') is None and self.versions() == versions,
                 f'POST /v1/capabilities refuses {why} with 400, storing nothing', status, out)
        # A name a stored rule binds to another host: a rule for `elsewhere` on p2, signed here.
        current = self.policy()
        signed = crafted_v2(current, current['version'] + 1, self.keys['pat'][0], self.root,
                            capability_rules=current['capability_rules'] +
                            [cap_rule(self.ids['p2'], 'elsewhere', ['person:' + self.rhea])])
        status, _ = api.call('POST', f'/v1/networks/{self.team}/policy', {'policy': signed})
        need(status == 201, 'setup: a stored rule binding a name to another host', status)
        versions = self.versions()
        status, out = api.call('POST', '/v1/capabilities', {**body, 'name': 'elsewhere',
                                                            **self.claims_field('p1', 'elsewhere')})
        # Ambiguous: the policies cannot carry this host's claim for a name bound to another host (the policy would
        # bind one name to two hosts, or lack the claim), which is also 400; the contract gives 409 for the name.
        need(status in (400, 409) and self.capability('elsewhere') is None and self.versions() == versions,
             'a name a stored capability rule binds to another host is refused, storing nothing', status, out)
        self.soft(status == 409, 'a name bound to another host: 409 rather than 400 for its policies', status, out)
        code, out, stdout, stderr = api.outcome('capability', 'create', 'elsewhere', '--from', 'cc/lit',
                                                '--operations', 'echo')
        need(code != 0 and self.versions() == versions, 'capability create refuses it too, before anything is '
             'signed', code)
        restored = crafted_v2(signed, signed['version'] + 1, self.keys['pat'][0], self.root,
                              capability_rules=current['capability_rules'])
        api.call('POST', f'/v1/networks/{self.team}/policy', {'policy': restored})

        # list and show, with recipients from the stored policies.
        listed = self.capability_list()
        names = [c['name'] for c in listed]
        need(names == sorted(names) and {'work', 'docs', 'clitools'} <= set(names), 'sorted by name', names)
        for c in listed:
            need(set(c) == RECORD_KEYS | {'recipients'} and all(set(r) == RECIPIENT_KEYS for r in c['recipients']),
                 'each record with its recipients [{network_id, principal, label}]', c)
        work = next(c for c in listed if c['name'] == 'work')
        need({(r['network_id'], r['principal']) for r in work['recipients']} ==
             {(self.team, 'person:' + self.quinn), (self.other, 'person:' + self.quinn)} and
             all(r['label'] == 'quinn' for r in work['recipients']),
             'recipients from this person\'s stored policies, with labels', work['recipients'])
        clitools = next(c for c in listed if c['name'] == 'clitools')
        need(clitools['recipients'] == [], 'an unshared capability has no recipients', clitools)
        code, out, stdout, stderr = api.outcome('capability', 'list', '--json')
        need(code == 0 and isinstance(out, dict) and [c['name'] for c in out['capabilities']] == names,
             'capability list --json', code, stdout[:300])
        code, out, stdout, stderr = api.outcome('capability', 'show', 'work')
        need(code == 0 and 'work' in stdout and 'cc/fx' in stdout or (out and out.get('name') == 'work'),
             'capability show NAME', code, stdout[:300])
        need(api.call('GET', '/v1/capabilities/nosuch')[0] == 404, 'GET /v1/capabilities/{unknown} is 404')
        kinds = [e for e in self.activity('p1') if e['kind'] == 'capability.created']
        need({'work', 'clitools'} <= {e['subject_id'] for e in kinds}, 'capability.created activity, subject the name',
             kinds[-3:])
        for name in ('clitools', 'clires', 'cliall'):
            api.run('capability', 'remove', name, '--yes')
        need(not self.pre_claims, 'the edit route exists, and the policies refusals were checked')

    def check_claims(self):
        """Claims (capabilities contract, Claims): one per network at creation, never authorizing, refused on another
        host, kept after the last unshare, at the first share in a network bound later (refused where another host
        holds the name), removed with the capability, and none for a host without a person. The guided share's
        claims are checked in the sharing section."""
        p1, p2, ids = self.hosts['p1'], self.hosts['p2'], self.ids
        nets = list(self.bound['p1'])
        before = {n: self.policy('p1', n) for n in nets}
        code, out, stdout, stderr = p1.outcome('capability', 'create', 'claimed', '--from', 'cc/lit', '--operations',
                                               'echo')
        need(code == 0 and self.capability('claimed'), 'capability create (bound in three networks)', code,
             stderr[-300:])
        for n in nets:
            p = self.policy('p1', n)
            need(p and p['version'] == (before[n] or {}).get('version', 0) + 1,
                 'the claim signs the next version in every network in which this host is bound', n, before[n], p)
            need(self.rule_for('claimed', n) == cap_rule(ids['p1'], 'claimed', []),
                 'a claim: this host, no principals, 65,536, false, 100', n, self.rule_for('claimed', n))
            need(edits_map(p).get(ids['p1'], 0) > edits_map(before[n]).get(ids['p1'], 0),
                 'the claim is signed as an edit: this host\'s edits entry rises', n, p.get('edits'))
            lines = policy_lines_v2(p)
            at = lines.index('claimed')
            need(lines[at - 2:at + 4] == ['capability_rule', ids['p1'], 'claimed', '', '65536 false 100', 'end'],
                 'a claim\'s principals line is empty', lines[at - 2:at + 4])
            ssh_verify(lines, p['signature'], self.keys['pat'][1], self.root)
        listed = next(c for c in self.capability_list() if c['name'] == 'claimed')
        need(listed['recipients'] == [], 'a claim has no recipients', listed)
        # Never authorizing.
        self.synced(self.version(), 'q1', 'u1')
        status, body = self.listing('p1', 'q1')
        need(status == 200 and not self.entry(body, 'claimed'), 'a claim lists nothing to another person', body)
        for caller in ('q1', 'u1'):
            status, _ = self.submit(caller, self.body('claimed', 'echo', {'text': 'x'}, cite=self.policy_cite()))
            need(status == 403, 'a claim authorizes no one', caller, status)
        # Another of the person's hosts is refused the name, before anything is signed.
        if 'dup2' not in self.aid:
            self.register('p2', 'dup2')
            self.put_servers('p2', 'dup2', self.root, {'fx': self.fixture.args('dup2-fx')})
        self.synced(self.version(), 'p2')
        self.synced(self.version('p1', self.other), 'p2', net=self.other)
        versions = self.versions('p2')
        code, out, stdout, stderr = p2.outcome('capability', 'create', 'claimed', '--from', 'dup2/fx', '--operations',
                                               'echo')
        need(code != 0 and self.capability('claimed', host='p2') is None and self.versions('p2') == versions,
             'capability create refuses a name another host claims, signing nothing', code)
        status, out = self.create('work', 'dup2/fx', 'operations', ['echo'], host='p2', expect=None)
        need(status in (400, 409) and self.capability('work', host='p2') is None and self.versions('p2') == versions,
             'the local API refuses it too, storing nothing', status, out)
        self.soft(status == 409, 'a name claimed by another host: 409 rather than 400 for its policies', status, out)
        # Kept after the last unshare.
        self.share('claimed', '--with', 'rhea', '--yes')
        need(self.rule_for('claimed')['principals'] == ['person:' + self.rhea], 'share adds to the claim')
        self.unshare('claimed', 'rhea')
        need(self.rule_for('claimed') == cap_rule(ids['p1'], 'claimed', []),
             'unshare removing the last principal keeps the rule as a claim', self.rule_for('claimed'))
        # A network bound later: p2 creates `later`, p1 joins it; the first share there claims the name.
        later = p2.cli('network', 'create', 'later', '--as', 'pat', '--untrusted', *self.coordinator_flags())['id']
        token = p2.cli('network', 'invite', '--network', later, '--member', 'pat', '--expires-in', '1h')['token']
        p1.cli('join', token, '--untrusted')
        self.later = later
        self.bound['p1'].append(later)
        self.bound['p2'].append(later)
        wait_for(lambda: p1.run('network', 'sync', later) and self.ids['p1'] in
                 {m['host_id'] for m in p2.cli('network', 'members', later)}, timeout=30, message='p1 in later')
        need(self.rule_for('claimed', later) is None, 'a network bound later has no claim yet',
             self.rule_for('claimed', later))
        self.share('claimed', '--with', 'everyone', '--yes', net=later)
        rule = self.rule_for('claimed', later)
        need(rule and rule['host'] == ids['p1'] and rule['principals'],
             'the next share in a network bound later creates the rule there', rule)
        # It is refused where another host holds the name: litcap bound to p2 in `later`, signed here.
        current = self.policy('p1', later)
        held = crafted_v2(current, current['version'] + 1, self.keys['pat'][0], self.root,
                          capability_rules=current['capability_rules'] + [cap_rule(ids['p2'], 'litcap', [])])
        status, _ = p1.call('POST', f'/v1/networks/{later}/policy', {'policy': held})
        need(status == 201, 'setup: litcap held by p2 in later', status)
        code, out, stderr = self.share('litcap', '--with', 'everyone', '--yes', net=later, expect=False)
        need(code != 0 and self.version('p1', later) == held['version'],
             'share refuses a name another host holds in that network, signing nothing', code)
        restored = crafted_v2(held, held['version'] + 1, self.keys['pat'][0], self.root,
                              capability_rules=current['capability_rules'])
        p1.call('POST', f'/v1/networks/{later}/policy', {'policy': restored})
        # Removed with the capability, claim included, in every network.
        code, out, stdout, stderr = p1.outcome('capability', 'remove', 'claimed', '--yes')
        need(code == 0 and self.capability('claimed') is None, 'capability remove', code, stderr[-300:])
        for n in self.bound['p1']:
            need(self.rule_for('claimed', n) is None, 'capability remove removes the rule, claim included', n)
        # A host without a person: no claims, `policies` empty.
        self.register('u1', 'ux')
        self.put_servers('u1', 'ux', self.root, {'fx': self.fixture.args('ux-fx')})
        team = self.version()
        status, out = self.create('loose', 'ux/fx', 'operations', ['echo'], host='u1', expect=None)
        need(status == 201, 'a host without a person creates the record with policies []', status, out)
        code, out, stdout, stderr = self.hosts['u1'].outcome('capability', 'create', 'loose2', '--from', 'ux/fx',
                                                             '--operations', 'echo')
        need(code == 0 and self.capability('loose2', host='u1'), 'capability create on a host without a person', code,
             stderr[-300:])
        self.hosts['u1'].run('network', 'sync', self.team)
        need(self.version() == team and self.version('u1') == team and
             not any(r['host'] == ids['u1'] for r in self.cap_rules(host='u1')),
             'no claim for a host without a person', self.cap_rules(host='u1'))
        for name in ('loose', 'loose2'):
            self.hosts['u1'].run('capability', 'remove', name, '--yes')
        self.sync_all()
        return f'claims in {len(nets)} networks; later network {later}'

    def check_policy_v2(self):
        p = self.policy()
        need(p and p.get('format') == 2 and isinstance(p.get('capability_rules'), list) and
             isinstance(p.get('trusted_hosts'), list), 'The JSON adds format 2, capability_rules, and trusted_hosts', p)
        need(list(p) == POLICY_V2_ORDER, 'the JSON keys in the contract\'s order', list(p))
        need(p['trusted_hosts'] == sorted(p['trusted_hosts']), 'trusted_hosts sorted', p['trusted_hosts'])
        edits = p.get('edits')
        need(isinstance(edits, list) and all(isinstance(e, dict) and set(e) == {'host', 'seq'} and
                                             isinstance(e['seq'], int) and 1 <= e['seq'] <= 2 ** 53 - 1 for e in edits)
             and [e['host'] for e in edits] == sorted(e['host'] for e in edits) and
             len({e['host'] for e in edits}) == len(edits) and self.ids['p1'] in edits_map(p),
             'edits is [{host, seq}], sorted by host, with an entry for the host whose CLI edited', edits)
        lines = policy_lines_v2(p)
        need(lines[-1] == ' '.join(['edits', *sorted(f"{e['host']}:{e['seq']}" for e in edits)]) and
             lines[-2].split()[0] == 'trusted', 'the final edits line follows the trusted line', lines[-2:])
        narrow = self.rule_for('narrow')
        need(narrow and narrow['principals'] == [], 'an unshared capability is a claim (principals [])', narrow)
        need(len(p['capability_rules']) >= 4, 'setup: the shares', p['capability_rules'])
        for r in p['capability_rules']:
            need(set(r) == CAP_RULE_KEYS and r['host'] == self.ids['p1'],
                 'a capability rule is {host, capability, principals, max_input_bytes, allow_disconnected, '
                 'max_calls_per_hour}, naming the serving host', r)
        work = self.rule_for('work')
        need(work and (work['max_input_bytes'], work['allow_disconnected'], work['max_calls_per_hour']) ==
             (65536, False, 100) and work['principals'] == ['person:' + self.quinn],
             'a share creates the rule with 65,536, false, and 100', work)
        need(self.rule_for('budget')['max_calls_per_hour'] == 3, '--calls-per-hour on a new rule',
             self.rule_for('budget'))
        ssh_verify(policy_lines_v2(p), p['signature'], self.keys['pat'][1], self.root)

        # The coordinator, and the other hosts' copies.
        with coord_db(self.coord) as db:
            row = db.execute("SELECT statement FROM statements WHERE network_id = ? AND kind = 'policy' AND subject = ?",
                             (self.team, self.keys['pat'][2])).fetchone()
        need(row and json.loads(row[0]) == p, 'the coordinator accepts and serves the v2 policy', row and row[0][:300])
        for name in ('q1', 'u1', 'p3'):
            self.hosts[name].run('network', 'sync', self.team)
            need(self.policy(name) == p, f'{name} stores the same v2 policy', self.policy(name))

        # Sibling propagation, by direct push with the coordinator stopped.
        self.coord.stop()
        try:
            code, out, stderr = self.share('litcap', '--with', 'rhea', '--yes')
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
        self.unshare('litcap', 'rhea')
        self.sync_all()

        # A v1 policy: accepted, stored in its v1 shape, read as v2 with no capability rules, no trusted hosts, and
        # no edits. It is stored in a network created on q2 (v1only, quinn's) where no host has signed an edit: in a
        # network with edits, a v1 policy reflects none of them, so they would be re-applied on top of it.
        q2 = self.hosts['q2']
        v1only = q2.cli('network', 'create', 'v1only', '--as', 'quinn', '--untrusted', *self.coordinator_flags())['id']
        self.bound['q2'].append(v1only)
        rules = [{'agent': 'legacy', 'principals': ['network'], 'actions': ['message.append'],
                  'max_message_bytes': 1000, 'allow_disconnected': False}]
        current = self.policy('q2', v1only, self.quinn)
        v1 = crafted_v1(v1only, self.keys['quinn'][2], (current or {}).get('version', 0) + 1, rules,
                        self.keys['quinn'][0], self.root)
        status, body = q2.call('POST', f'/v1/networks/{v1only}/policy', {'policy': v1})
        need(status == 201, 'a v1 policy is accepted', status, body)
        stored = self.policy('q2', v1only, self.quinn)
        need(stored['version'] == v1['version'] and plain(stored['rules']) == rules and
             stored['signature'] == v1['signature'] and
             not {'format', 'capability_rules', 'trusted_hosts', 'edits'} & set(stored),
             'a v1 policy is stored in its v1 JSON shape', stored)

        def at_coordinator():
            with coord_db(self.coord) as db:
                row = db.execute("SELECT statement FROM statements WHERE network_id = ? AND kind = 'policy' AND "
                                 "subject = ?", (v1only, self.keys['quinn'][2])).fetchone()
            return row and json.loads(row[0])['version'] == v1['version']
        wait_for(at_coordinator, timeout=30, message='the coordinator accepts a v1 policy')
        q2.cli('allow', 'network', '--agent', 'more', '--network', v1only)
        nxt = self.policy('q2', v1only, self.quinn)
        need(nxt['format'] == 2 and nxt['version'] == v1['version'] + 1 and plain(nxt['rules'])[0] == rules[0] and
             nxt['capability_rules'] == [] and nxt['trusted_hosts'] == [] and
             [e['host'] for e in nxt.get('edits') or []] == [self.ids['q2']],
             'the CLI always signs v2, keeping the v1 rules, with its own edits entry', nxt)
        ssh_verify(policy_lines_v2(nxt), nxt['signature'], self.keys['quinn'][1], self.root)
        mine = edits_map(nxt)
        need(policy_lines_v2(nxt)[-2] == 'trusted' and
             policy_lines_v2(nxt)[-1] == f"edits {self.ids['q2']}:{mine[self.ids['q2']]}",
             'with no trusted hosts the line is the bare word trusted; then the edits line', policy_lines_v2(nxt)[-2:])

        # Validation, with policies signed here over this suite's encoding (q2's own edits entry always kept, so
        # that no refusal is about an unknown number of this host).
        own = edits_list(mine)
        fake = ['host_' + format(i, '064x') for i in range(1, 300)]
        ok_rule = cap_rule('host_' + 'c' * 64, 'remote-only', ['network'])
        post = lambda v: q2.call('POST', f'/v1/networks/{v1only}/policy', {'policy': v})
        for bad, why in (
                ([{**ok_rule, 'max_input_bytes': 0}], 'max_input_bytes 1 to 262,144'),
                ([{**ok_rule, 'max_input_bytes': 262145}], 'max_input_bytes 1 to 262,144'),
                ([{**ok_rule, 'max_calls_per_hour': 0}], 'max_calls_per_hour 1 to 10,000'),
                ([{**ok_rule, 'max_calls_per_hour': 10001}], 'max_calls_per_hour 1 to 10,000'),
                ([{**ok_rule, 'capability': 'Bad.Name'}], 'a capability name not matching the pattern'),
                ([{**ok_rule, 'capability': 'cc/fx'}], 'capability rules refuse names containing /'),
                ([{**ok_rule, 'host': 'not-a-host'}], 'the host is a host ID'),
                ([ok_rule, {**ok_rule, 'host': 'host_' + 'd' * 64}], 'a name bound to two hosts is refused'),
                ([ok_rule, {**ok_rule, 'principals': ['group:x']}], 'at most one rule per capability name'),
                ([ok_rule, {**ok_rule, 'principals': []}], 'at most one rule per capability name, a claim included'),
                ([{**ok_rule, 'capability': f'c{i}', 'principals': []} for i in range(257)],
                 'at most 256 capability rules, claims included'),
                ([{**ok_rule, 'principals': [f'group:g{i}' for i in range(65)]}], 'at most 64 principals per rule')):
            v = crafted_v2(nxt, nxt['version'] + 1, self.keys['quinn'][0], self.root, capability_rules=bad)
            status, _ = post(v)
            need(status == 400, f'validation: {why} (400)', status)
        for bad_trusted in (['not-a-host'], [self.ids['p1'], self.ids['p1']],
                            ['host_' + format(i, '064x') for i in range(65)]):
            v = crafted_v2(nxt, nxt['version'] + 1, self.keys['quinn'][0], self.root, trusted=bad_trusted)
            status, _ = post(v)
            need(status == 400, 'trusted hosts: host IDs, at most 64, no duplicates (400)', len(bad_trusted), status)
        for bad_edits, why in (
                (own + [{'host': h, 'seq': 1} for h in fake[:256]], 'at most 256 edits entries'),
                (own + [{'host': fake[0], 'seq': 1}, {'host': fake[0], 'seq': 2}], 'edits hosts without duplicates'),
                (own + [{'host': fake[0], 'seq': 0}], 'seq from 1'),
                (own + [{'host': fake[0], 'seq': 2 ** 53}], 'seq at most 2^53 - 1'),
                (own + [{'host': 'not-a-host', 'seq': 1}], 'an edits entry is a host ID')):
            v = crafted_v2(nxt, nxt['version'] + 1, self.keys['quinn'][0], self.root,
                           edits=sorted(bad_edits, key=lambda e: e['host']))
            status, _ = post(v)
            need(status == 400, f'validation: {why} (400)', status)
        # At the bounds: 256 rules (claims and rules on hosts outside the network map), 0 and 64 principals, 256
        # edits entries with seq 2^53 - 1, and trusted hosts outside the map.
        at_bounds = [cap_rule('host_' + 'c' * 64, 'remote-only', ['network', 'group:backend'], 262144, True, 10000),
                     cap_rule('host_' + 'd' * 64, 'other-name', ['person:' + self.quinn], 1, False, 1),
                     cap_rule('host_' + 'd' * 64, 'wide', [f'group:g{i}' for i in range(64)])] + \
            [cap_rule('host_' + 'e' * 64, f'claim{i}', []) for i in range(253)]
        many = sorted(own + [{'host': h, 'seq': 2 ** 53 - 1} for h in fake[:255]], key=lambda e: e['host'])
        ok = crafted_v2(nxt, nxt['version'] + 1, self.keys['quinn'][0], self.root, capability_rules=at_bounds,
                        trusted=['host_' + 'e' * 64, self.ids['p1']], edits=many)
        status, body = post(ok)
        need(status == 201 and policy_of(body) == ok, 'a v2 policy signed with this suite\'s encoding is accepted at '
             'the bounds (256 rules with claims, 0 and 64 principals, 256 edits entries, seq 2^53 - 1)', status,
             str(body)[:400])
        # The implementation's own statement hash for it (access sync --status reports the stored statement's
        # sha256) matches this suite's: claims, the trusted line, and the edits line encode identically.
        view = q2.cli('access', 'sync', '--network', v1only, '--status')
        need(view['sha256'] == policy_hash(ok), 'the stored statement hash matches this suite\'s v2 encoding',
             view.get('sha256'), policy_hash(ok))
        # Leave a small clean policy.
        clean = crafted_v2(ok, ok['version'] + 1, self.keys['quinn'][0], self.root, capability_rules=[], trusted=[],
                           edits=own)
        status, body = post(clean)
        need(status == 201, 'setup: a clean v1only policy again', status, body)
        return f"team v{p['version']}, {len(p['capability_rules'])} capability rules"

    def check_sharing(self):
        self.clear('rhea')
        try:
            self.sharing_cases()
        finally:
            rule = self.rule_for('work')
            if rule and rule['max_calls_per_hour'] != 100:
                self.hosts['p1'].run('share', 'work', '--with', 'quinn', '--calls-per-hour', '100', '--yes',
                                     '--network', self.team)

    def sharing_cases(self):
        p1 = self.hosts['p1']
        # Refusal without a terminal or --yes, a piped y, and declining.
        code, out, stderr = self.share('docs', '--with', 'rhea', expect=False)
        need(code == 1, 'without a terminal and without --yes, share exits 1 with nothing signed', code, stderr[-300:])
        code, out, stderr = self.share('docs', '--with', 'rhea', piped='y\n', expect=False)
        need(code == 1, '"At a terminal" means stdin is a terminal: a piped y does not confirm', code)
        code, out, tty = self.share('work', '--with', 'rhea', terminal='n', expect=False)
        need(code == 1, 'declining exits 1 with nothing signed', code, tty[-300:])
        need(SHARE_PROMPT in squash(tty), f'the review ends with {SHARE_PROMPT}', tty[-300:])
        # The review, then yes at a terminal.
        code, out, tty = self.share('work', '--with', 'rhea', terminal='yes')
        text = squash(tty)
        need('pat/work' in text, 'the review shows the capability\'s address PERSON/CAPABILITY', tty[-1500:])
        need('cc/fx' in text and 'claude-code:local' in text, 'the review shows its source and where it came from',
             tty[-1500:])
        lines = tty.splitlines()
        marked = [l for l in lines if CAN_CHANGE in l]
        need(marked and all('write_note' in l for l in marked) and
             not any(CAN_CHANGE in l for l in lines if 'echo' in l and 'write_note' not in l),
             'the review marks only the tools that can change things', marked)
        need(all(op in text for op in ('echo', 'sleep', 'typed')), 'the review lists each operation', tty[-1500:])
        need('fixture://docs/readme' in text or 'all' in text, 'the review shows the resources', tty[-1500:])
        need('rhea' in text, 'the review shows the recipient', tty[-1500:])
        need(REACH in text, 'the review states the reach', tty[-1500:])
        need(code == 0 and out['capability'] == 'work' and out['created'] is False and
             out['principal'] in ('rhea', 'person:' + self.rhea, self.rhea), 'share prints its output', out)
        need('person:' + self.rhea in self.rule_for('work')['principals'], 'PRINCIPAL added to the capability\'s rule')
        # Every share asks again; --yes skips it; sharing again with no change signs nothing.
        before = self.version()
        code, out, stderr = self.share('work', '--with', 'rhea', expect=False)
        need(code == 1, 'every share shows the review and asks again', code)
        code, out, stderr = self.share('work', '--with', 'rhea', '--yes')
        need(self.version() == before, 'sharing again with a principal already in the rule signs nothing',
             before, self.version())
        # The credential context in the review: the source's own environment, or the env file.
        code, out, tty = self.share('narrow', '--with', 'rhea', terminal='y')
        need(code == 0 and str(self.own_env) in squash(tty), 'the review shows the capability\'s environment file',
             tty[-1200:])
        # --calls-per-hour on an existing rule replaces its limit for every recipient.
        code, out, tty = self.share('work', '--with', 'rhea', '--calls-per-hour', '7', terminal='y')
        text = squash(tty)
        # Recipients by label where the principal resolves to one.
        need(code == 0 and '100' in text and '7' in text and 'quinn' in text,
             'the review lists the old and new limits and the recipients affected', tty[-1200:])
        rule = self.rule_for('work')
        need(rule['max_calls_per_hour'] == 7 and set(rule['principals']) == {'person:' + self.quinn,
                                                                           'person:' + self.rhea},
             '--calls-per-hour replaces the limit for every recipient', rule)
        self.share('work', '--with', 'rhea', '--yes')
        need(self.rule_for('work')['max_calls_per_hour'] == 7, 'without the flag the existing limit is kept')
        self.share('work', '--with', 'rhea', '--calls-per-hour', '100', '--yes')

        # The guided share, with flags.
        code, out, stderr = self.share(None, '--with', 'rhea', '--from', 'cc/fx', '--operations', 'echo,info',
                                       '--name', 'guided', expect=False)
        need(code != 0 and self.capability('guided') is None,
             'the guided share without a terminal needs --yes, and creates nothing otherwise', code)
        code, out, stderr = self.share(None, '--with', 'rhea', '--from', 'cc/fx', '--yes', expect=False)
        need(code != 0 and self.capability('fx') is None,
             'without a terminal every selection must be given as a flag', code)
        code, out, stderr = self.share(None, '--with', 'rhea', '--from', 'cc/fx', '--operations', 'echo,info',
                                       '--resources', 'all', '--name', 'guided', '--yes')
        need(out['created'] is True and out['capability'] == 'guided' and self.capability('guided') and
             self.capability('guided')['operations'] == ['echo', 'info'] and
             self.capability('guided')['resources'] == 'all' and self.rule_for('guided'),
             'the guided share creates the capability and shares it', out, self.capability('guided'))
        need(self.rule_for('guided')['principals'] == ['person:' + self.rhea], 'in the selected network, the rule '
             'with its principal', self.rule_for('guided'))
        for n in self.bound['p1']:
            if n != self.team:
                need(self.rule_for('guided', n) == cap_rule(self.ids['p1'], 'guided', []),
                     'the guided share signs the claim in every other network in which this host is bound', n,
                     self.rule_for('guided', n))
        # The guided share at a terminal: source, operations, resources, name, then the review. The answer formats
        # are not specified (ambiguous), so this case is soft.
        code, out, tty, stdout, seen = p1.converse('share', '--with', 'rhea', '--network', self.team,
                                                   answers=['cc/lit', 'echo', 'n', 'guided-tty', 'y'],
                                                   prompt=SHARE_PROMPT)
        self.soft(code == 0 and out and out.get('created') is True and self.capability('guided-tty'),
                  'the guided share at a terminal (answers: cc/lit, echo, n, guided-tty, y)', code, tty[-600:])
        if seen:
            need(REACH in squash(tty), 'the guided share shows the review before confirming', tty[-800:])

        # shares.
        code, out, stdout, stderr = p1.outcome('shares', '--json', '--network', self.team)
        need(code == 0 and out is not None and 'work' in stdout and 'guided' in stdout,
             'shares --json lists every capability and rule', code, stdout[:300])
        self.soft('unshare' in stdout, 'shares shows the unshare command for each recipient', stdout[:300])
        code, out, stdout, stderr = p1.outcome('shares')
        need(code == 0 and 'work' in stdout and 'unshare' in stdout, 'shares readable output', code, stdout[:300])

        # unshare: output, the rule kept as a claim when it empties, and the zero-removal note.
        out = self.unshare('guided', 'rhea')
        need(out['removed'] == 1 and out['capability'] == 'guided' and
             self.rule_for('guided') == cap_rule(self.ids['p1'], 'guided', []),
             'unshare removes PRINCIPAL, keeping the rule as a claim when it empties', out, self.rule_for('guided'))
        out = self.unshare('guided', 'rhea')
        need(out['removed'] == 0, 'unshare when PRINCIPAL was not in the rule: removed 0 with a note', out)
        for name in ('work', 'narrow'):
            self.unshare(name, 'rhea')

        # Several networks: a share is written to the selected network's policy; --network is required here.
        code, out, stdout, stderr = p1.outcome('share', 'docs', '--with', 'quinn', '--yes')
        need(code != 0, 'share without --network on a host in several networks is refused', code)
        before_team = self.version()
        self.share('docs', '--with', 'quinn', '--yes', net=self.other)
        need((self.rule_for('docs', self.other) or {}).get('principals') == ['person:' + self.quinn] and
             self.version() == before_team and self.rule_for('docs')['principals'] == ['person:' + self.quinn],
             'a share is written to the selected network\'s policy only (there, onto the claim)',
             self.rule_for('docs', self.other))
        self.unshare('docs', 'quinn', net=self.other)
        need(self.rule_for('docs', self.other) == cap_rule(self.ids['p1'], 'docs', []), 'the claim stays',
             self.rule_for('docs', self.other))
        for name in ('guided', 'guided-tty'):
            p1.run('capability', 'remove', name, '--yes')
        for n in self.bound['p1']:
            need(self.rule_for('guided', n) is None, 'capability remove removes its rules and claims', n)
        self.sync_all()

    def check_trust(self):
        ids, p3, p1 = self.ids, self.hosts['p3'], self.hosts['p1']
        current = self.policy()
        need(current and ids['p3'] not in current['trusted_hosts'], 'p3 starts untrusted', current)
        v = self.version('p3')
        out = p3.cli('trust')
        need(isinstance(out, dict) and set(out) == TRUST_KEYS and out['host'] == ids['p3'] and out['trusted'] is True
             and out['changed'] is True and out['policy']['version'] == v + 1,
             'trust prints {policy, host, trusted, changed}; HOST defaults to this host; --network optional', out)
        again = p3.cli('trust')
        need(again['changed'] is False and self.version('p3') == v + 1, 'without a change, trust signs nothing', again)
        self.synced(self.version('p3'), 'p1')
        status, body = self.listing('p1', 'p3')
        need(status == 200 and self.entry(body, 'work'), 'a trusted host reaches the capabilities by self', body)
        out = p3.cli('untrust', ids['p3'])
        need(out['trusted'] is False and out['changed'] is True, 'untrust prints {policy, host, trusted, changed}', out)
        self.synced(self.version('p3'), 'p1')
        status, body = self.listing('p1', 'p3')
        need(status == 200 and not any(v['kind'] == 'self' for e in body for v in e['via']),
             'an untrusted host has no self entries', body)
        for args, why in ((('trust',), 'trust without --network fails on a host in several networks'),
                          (('trust', ids['q1'], '--network', self.team), 'trust HOST must be bound to this person'),
                          (('trust', ids['u1'], '--network', self.team), 'trust refuses a host bound to no person')):
            code, out, stdout, stderr = p1.outcome(*args)
            need(code != 0, why, code)
        # Per-network trust: p2 is trusted in team, not in other.
        status, body = self.listing('p1', 'p2', network=self.other)
        need(status == 200 and not any(v['kind'] == 'self' for e in body for v in e['via']),
             'trust is per network', body)
        v = self.version('p1', self.other)
        out = p1.cli('trust', ids['p2'], '--network', self.other)
        need(ids['p2'] in self.policy('p1', self.other)['trusted_hosts'] and self.version('p1', self.other) == v + 1,
             'trust HOST --network signs the next version of that network\'s policy', out)
        p1.cli('untrust', ids['p2'], '--network', self.other)
        need(ids['p2'] in self.policy()['trusted_hosts'], 'other networks untouched')
        self.sync_all(self.other)

    def check_open_list(self):
        ids, p1 = self.ids, self.hosts['p1']
        need(self.open_list() == [ids['p2']], 'setup: p1 open to p2 only (the list starts empty)', self.open_list())
        status, body = p1.call('POST', '/v1/sources/open-to', {'host_id': ids['p2']})
        need(status == 200, 'a repeat is unchanged and returns 200', status, body)
        status, body = p1.call('POST', '/v1/sources/open-to', {'host_id': ids['p4']})
        need(status == 201, 'an addition returns 201', status, body)
        for target, why in ((ids['q1'], 'a host bound to another person'), (ids['u1'], 'a host bound to no person'),
                            (ids['n'], 'a host in no network map'), (ids['p1'], 'this host'),
                            ('not-a-host', 'an invalid host ID')):
            status, body = p1.call('POST', '/v1/sources/open-to', {'host_id': target})
            need(status == 400, f'open-to refuses {why} with 400', status, body)
        status, body = p1.call('POST', '/v1/sources/open-to', {'host_id': '*'})
        need(status == 201, '* is added', status, body)
        need(self.open_list() == ['*', *sorted([ids['p2'], ids['p4']])], 'open_to sorted with * first',
             self.open_list())
        body = self.close_to('p1', '*')
        need(self.open_list() == sorted([ids['p2'], ids['p4']]), 'removing * does not remove hosts listed '
             'individually', self.open_list())
        body = self.close_to('p1', ids['p4'])
        body = self.close_to('p1', ids['p4'])
        need(body.get('removed') == 0, 'removing an absent entry returns 200 with removed: 0', body)
        # The CLI forms.
        for args in (('sources', 'open-to', ids['p4']), ('sources', 'open-to', '--all'),
                     ('sources', 'close-to', '--all'), ('sources', 'close-to', ids['p4'])):
            code, out, stdout, stderr = p1.outcome(*args)
            need(code == 0, ' '.join(args), code, stderr[-300:])
        code, out, stdout, stderr = p1.outcome('sources', 'open-to', ids['q1'])
        need(code != 0, 'sources open-to refuses another person\'s host', code)
        need(self.open_list() == [ids['p2']], 'the CLI changes the same list', self.open_list())
        kinds = {(e['kind'], e['subject_id']) for e in self.activity('p1')}
        need({('sources.opened', ids['p4']), ('sources.closed', ids['p4']), ('sources.opened', '*'),
              ('sources.closed', '*')} <= kinds, 'sources.opened and sources.closed activity', sorted(kinds)[:8])

    def check_authorization(self):
        self.clear('rhea')
        ids, f = self.ids, self.fixture
        # By policy, and by self.
        marker = 'by-policy-' + secrets.token_hex(4)
        status, record = self.submit('q1', self.body('work', 'echo', {'text': marker}, cite=self.policy_cite()))
        need(status == 200 and set(record) == STATUS_KEYS and record['state'] == 'queued',
             'policy authorizes the capability\'s operations', status, record)
        need(self.final('q1', record['call_id'])['state'] == 'succeeded', 'and the call runs')
        status, _ = self.submit('p2', self.body('work', 'write_note', {'text': 'self'}, cite=self.self_cite()))
        need(status == 200, 'self from a trusted host covers every capability', status)
        # A rule naming another host never authorizes here: a rule for `budget` bound to p2, signed here, while p1
        # serves its own budget capability.
        current = self.policy()
        moved = [r for r in current['capability_rules'] if r['capability'] != 'budget']
        rule = dict(self.rule_for('budget'))
        signed = crafted_v2(current, current['version'] + 1, self.keys['pat'][0], self.root,
                            capability_rules=moved + [{**rule, 'host': ids['p2']}])
        status, _ = self.hosts['p1'].call('POST', f'/v1/networks/{self.team}/policy', {'policy': signed})
        need(status == 201, 'setup: the budget rule bound to p2', status)
        self.synced(signed['version'], 'q1')
        status, _ = self.submit('q1', self.body('budget', 'echo', {'text': 'x'}, cite=self.policy_cite()))
        need(status == 403, 'a rule for the same name bound to another host authorizes nothing here', status)
        restored = crafted_v2(signed, signed['version'] + 1, self.keys['pat'][0], self.root,
                              capability_rules=current['capability_rules'])
        self.hosts['p1'].call('POST', f'/v1/networks/{self.team}/policy', {'policy': restored})
        self.sync_all()
        # Self is evaluated in the cited network only: p2 is trusted in team but not in other.
        status, _ = self.submit('p2', self.body('work', 'echo', {'text': 'x'}, cite=self.self_cite(self.other)))
        need(status == 403, 'a self citation is evaluated in the cited network only', status)
        status, _ = self.submit('p2', self.body('cc/fx', 'echo', {'text': 'x'}, cite=self.self_cite(self.other)))
        need(status == 403, 'and so is a source call\'s self citation', status)
        # Self refused from an untrusted host and from another person's host.
        status, _ = self.submit('p3', self.body('work', 'echo', {'text': 'x'}, cite=self.self_cite()))
        need(status == 403, 'self is refused from an untrusted host of the same person', status)
        for claimed in (self.pat, self.quinn):
            status, _ = self.submit('q1', self.body('work', 'echo', {'text': 'x'},
                                                    cite={'self': {'person_id': claimed, 'network_id': self.team}}))
            need(status == 403, "another person's host is never covered by self", claimed, status)
        # The source gate: trusted and open; trusted, not open; open, not trusted; * covering a host trusted later.
        status, _ = self.submit('p2', self.body('cc/fx', 'echo', {'text': 'source'}, cite=self.self_cite()))
        need(status == 200, 'a source called from a trusted host the server is open to', status)
        status, _ = self.submit('p4', self.body('cc/fx', 'echo', {'text': 'x'}, cite=self.self_cite()))
        need(status == 403, 'refused (403) from a trusted host it is not open to', status)
        self.open_to('p1', ids['p3'])
        status, _ = self.submit('p3', self.body('cc/fx', 'echo', {'text': 'x'}, cite=self.self_cite()))
        need(status == 403, 'refused (403) from an untrusted host it is open to', status)
        self.close_to('p1', ids['p3'])
        self.open_to('p1', '*')
        try:
            self.hosts['p3'].cli('trust')
            self.synced(self.version('p3'), 'p1')
            status, _ = self.submit('p3', self.body('cc/fx', 'echo', {'text': 'later'}, cite=self.self_cite()))
            need(status == 200, '* covers a host trusted later', status)
            self.hosts['p3'].cli('untrust', ids['p3'])
            self.synced(self.version('p3'), 'p1')
            # Another person never reaches a source, even with * open and a capability shared with everyone.
            status, body = self.listing('p1', 'q1')
            need(status == 200 and not any(e['kind'] == 'source' for e in body),
                 'a source is never listed to another person', body)
            for cite in (self.policy_cite(), {'self': {'person_id': self.quinn, 'network_id': self.team}}):
                status, _ = self.submit('q1', self.body('cc/fx', 'echo', {'text': 'x'}, cite=cite))
                need(status == 403, 'a source is never callable by another person (403)', status)
            status, body = self.listing('p1', 'u1')
            need(status == 200 and not any(e['kind'] == 'source' for e in body) and self.entry(body, 'budget2'),
                 'not even through everyone', body)
        finally:
            self.close_to('p1', '*')
        # Blocks, except under self.
        made = [self.hosts['p1'].cli('block', 'quinn'), self.hosts['p1'].cli('block', ids['p2'])]
        status, _ = self.submit('q1', self.body('work', 'echo', {'text': 'b'}, cite=self.policy_cite()))
        need(status == 403, 'blocks apply under policy', status)
        status, _ = self.submit('p2', self.body('work', 'echo', {'text': 'b'}, cite=self.self_cite()))
        need(status == 200, 'blocks do not apply under self', status)
        for target in ('quinn', ids['p2']):
            self.hosts['p1'].cli('unblock', target)
        need(self.hosts['p1'].cli('access', 'blocks') == [], 'unblocked', made)
        # An operation outside the capability, and a URI outside its resources.
        cite = self.policy_cite()
        status, _ = self.submit('q1', self.body('docs', 'echo', {'text': 'x'}, cite=cite))
        need(status == 404, 'an operation outside the capability is 404', status)
        status, _ = self.submit('q1', self.body('work', 'purge', {}, cite=cite))
        need(status == 404, 'a source tool not selected is not an operation (404)', status)
        status, _ = self.submit('q1', self.body('docs', 'read', {'uri': 'file:///srv/docs/a.txt'}, cite=cite))
        need(status == 404, 'a URI outside the capability\'s resources is 404', status)
        status, _ = self.submit('q1', self.body('budget', 'read', {'uri': 'fixture://docs/readme'}, cite=cite))
        need(status == 404, 'read on a capability without resources is 404', status)
        status, _ = self.submit('q1', self.body('narrow', 'info', {}, cite=cite))
        need(status == 403, 'an unshared capability is refused', status)
        # 413, the deadline window, and 429.
        status, body = self.submit('q1', self.body('work', 'echo', {'text': 'x' * 70000}, cite=cite))
        need(status == 413 and isinstance(body, dict) and set(body) == {'code', 'error'} and body['code'] == 'too_large',
             'input over max_input_bytes: 413 {code: "too_large", error}', status, body)
        status, body = self.submit('q1', self.body('work', 'echo', {'text': 'x' * 60000}, cite=cite))
        need(status == 200, 'input within max_input_bytes', status, body)
        for seconds in (17 * 60, -5):
            status, body = self.submit('q1', self.body('work', 'echo', {'text': 'x'}, cite=cite,
                                                       deadline=timestamp(seconds)))
            need(status == 400 and isinstance(body, dict) and body.get('code') == 'invalid',
                 'a deadline in the past or beyond 15 minutes plus a minute of skew: 400 invalid', seconds, status)
        status, _ = self.submit('q1', self.body('work', 'echo', {'text': 'skew'}, cite=cite,
                                                deadline=timestamp(15 * 60 + 20)))
        need(status == 200, 'a deadline within the minute of skew is accepted', status)
        got = [self.submit(h, self.body('budget', 'echo', {'text': h}, cite=cite))[0] for h in ('q1', 'q1', 'q2')]
        need(got == [200, 200, 200], 'budget: 3 accepted calls', got)
        for h in ('q1', 'q2'):
            status, body = self.submit(h, self.body('budget', 'echo', {'text': h}, cite=cite))
            need(status == 429 and isinstance(body, dict) and set(body) == {'code', 'error', 'limit'} and
                 body['code'] == 'limit' and body['limit'] == 'max_calls_per_hour',
                 '429 {code: "limit", error, limit}, counted per person across hosts', h, status, body)
        # The budget is not reset by changing principals: rhea joins the rule.
        self.share('budget', '--with', 'rhea', '--yes')
        self.synced(self.version(), 'q1', 'r')
        cite = self.policy_cite()
        status, _ = self.submit('q1', self.body('budget', 'echo', {'text': 'still'}, cite=cite))
        need(status == 429, 'the rule identity excludes principals: changing them resets no budget', status)
        status, _ = self.submit('r', self.body('budget', 'echo', {'text': 'rhea'}, cite=cite))
        need(status == 200, 'each caller has its own count', status)
        self.unshare('budget', 'rhea')
        self.sync_all()
        cite = self.policy_cite()
        for h in ('u1', 'u2'):
            got = [self.submit(h, self.body('budget2', 'echo', {'text': h}, cite=cite))[0] for _ in range(3)]
            need(got == [200, 200, 429], 'an unbound caller is counted by its host ID', h, got)
        # Grant citations are refused.
        g = self.hosts['p1'].cli('grant', 'create', '--peer', ids['q1'], '--agent', self.aid['cc'], '--expires-in', '1h')
        status, _ = self.submit('q1', self.body('work', 'echo', {'text': 'x'}, cite={'grant_id': g['id']}))
        need(status == 400, 'a grant_id citation is refused with 400', status)
        self.hosts['p1'].cli('grant', 'revoke', g['id'])
        code, out, stdout, stderr = self.hosts['p1'].outcome('grant', 'create', '--peer', ids['q1'], '--agent',
                                                             self.aid['cc'], '--expires-in', '1h', '--action',
                                                             'capability.call')
        self.soft(code != 0, 'grant create does not accept capability actions (no action name is specified)', code)
        # The recheck before start, rejecting: unshare while queued.
        self.share('work', '--with', 'rhea', '--yes')
        self.synced(self.version(), 'r')
        lapsing = self.policy_cite()
        self.fill_slots(6)
        marker = 'lapsed-' + secrets.token_hex(4)
        b = self.body('work', 'echo', {'text': marker}, cite=lapsing)
        status, record = self.submit('r', b)
        need(status == 200 and record['state'] == 'queued', 'a fifth call waits as queued', status, record)
        out = self.unshare('work', 'rhea')
        done = self.final('r', b['call_id'], timeout=40)
        need(done['state'] == 'rejected' and LAPSED in json.dumps(done),
             f'a queued call is rejected at the recheck, "{LAPSED}"', done)
        need(not f.calls('fx-local', marker), 'a rejected call never runs')
        # The recheck before start, leaving queued: with the coordinator stopped, p1's connected state lapses
        # (three coordination intervals, coordination contract), which recovers; the call stays queued, and one
        # whose deadline passes meanwhile expires.
        time.sleep(7)
        self.fill_slots(10)
        cite = self.policy_cite()
        waiting = self.body('work', 'echo', {'text': 'waits-' + secrets.token_hex(4)}, cite=cite)
        short = self.body('work', 'echo', {'text': 'expires-' + secrets.token_hex(4)}, cite=cite,
                          deadline=timestamp(16))
        for b in (waiting, short):
            need(self.submit('q1', b)[0] == 200, 'setup: queued policy calls')
        self.coord.stop()
        try:
            time.sleep(13)
            status, record = self.status_of('q1', waiting['call_id'])
            need(record['state'] == 'queued', 'a recoverable (503-type) failure at the recheck leaves the call queued',
                 record)
            need(self.final('q1', short['call_id'], timeout=20)['state'] == 'expired',
                 'rechecked until its deadline, then expired')
        finally:
            self.coord.start()
        need(self.final('q1', waiting['call_id'], timeout=60)['state'] == 'succeeded',
             'once the state recovers, the queued call runs')

    def check_routes(self):
        self.clear('rhea')
        ids = self.ids
        status, body = self.listing('p1', 'q1')
        need(status == 200 and isinstance(body, list), 'GET /peer/v1/capabilities', status, body)
        for e in body:
            need(set(e) == PEER_ENTRY_KEYS, 'entries are {kind, capability, operations, resources, state, '
                 'unavailable, via}', e)
            for o in e['operations']:
                need(set(o) == OPERATION_KEYS, 'operations are {name, description, input_schema, read_only}', o)
            for r in e['resources']:
                need(set(r) == RESOURCE_KEYS, 'resources are {uri, name, description, mime_type}', r)
        names = [e['capability'] for e in body]
        need(names == sorted(names), 'sorted by capability', names)
        need(set(names) == {'work', 'docs', 'budget', 'budget2', 'litcap'},
             'only the capabilities the sender may use (never narrow, never sources)', names)
        work = self.entry(body, 'work')
        need(work['kind'] == 'capability' and work['state'] == 'available' and work['unavailable'] == [],
             'kind capability, available', work)
        ops = {o['name']: o for o in work['operations']}
        need(set(ops) == set(WORK_OPERATIONS) | {'read'}, 'the operations, plus read for resources', sorted(ops))
        need(ops['write_note']['read_only'] is False and ops['echo']['read_only'] is True and
             ops['echo']['input_schema']['properties'] == {'text': {'type': 'string'}},
             'tool operations take description, input_schema, and read_only from the snapshot', ops['echo'])
        need(ops['read']['input_schema'] == {'type': 'object', 'properties': {'uri': {'type': 'string', 'enum':
             sorted(r['uri'] for r in work['resources'])}}, 'required': ['uri']} or
             (ops['read']['input_schema']['required'] == ['uri'] and
              sorted(ops['read']['input_schema']['properties']['uri']['enum']) == sorted(ALL_RESOURCES)),
             'read: the input schema with the URIs as enum', ops['read'])
        need({r['uri'] for r in work['resources']} == ALL_RESOURCES, 'resources all lists every resource',
             work['resources'])
        need([r['uri'] for r in self.entry(body, 'docs')['resources']] in (DOCS, DOCS[::-1]) and
             [o['name'] for o in self.entry(body, 'docs')['operations']] == ['read'], 'docs: read only', body)
        need(self.entry(body, 'budget')['resources'] == [] and
             'read' not in [o['name'] for o in self.entry(body, 'budget')['operations']],
             'a capability without resources has resources [] and no read', self.entry(body, 'budget'))
        nets = sorted([self.team, self.other])
        need([v['network_id'] for v in work['via']] == nets and all(v['kind'] == 'policy' for v in work['via']),
             'via: policy entries ordered by network ID', work['via'])
        for v in work['via']:
            need(set(v) == {'kind', 'network_id', 'person_id', 'version'} and v['person_id'] == self.pat,
                 'policy via {kind, network_id, person_id, version}', v)
        status, scoped = self.listing('p1', 'q1', network=self.other)
        need(status == 200 and {e['capability'] for e in scoped} == {'work', 'litcap'} and
             all(v['network_id'] == self.other for e in scoped for v in e['via']), '?network: only that network',
             scoped)
        # A trusted sibling: self before policy, and the sources opened to it.
        status, body = self.listing('p1', 'p2')
        need(status == 200 and self.entry(body, 'narrow') and all(e['via'][0]['kind'] == 'self' for e in body),
             'self covers every capability; self before policy', body[:2])
        source = self.entry(body, 'cc/fx')
        need(source and source['kind'] == 'source' and all(v['kind'] == 'self' for v in source['via']),
             'a source opened to the sender: kind source, capability AGENT/SERVER, via only self', source)
        source_ops = {o['name'] for o in source['operations']}
        need(source_ops == (RO_TOOLS | WRITE_TOOLS | {'from_local'}) - {'read'} | {'read'} and
             len([o for o in source['operations'] if o['name'] == 'read']) == 1 and
             'from_local' in source_ops, 'the implicit capability: every tool except one named read, plus read',
             sorted(source_ops))
        need(not any(e['capability'] in ('cc/needy', 'cc/rem', 'cc/Bad.Name') for e in body),
             'only shareable sources with a snapshot', [e['capability'] for e in body])
        # A member covered only by `everyone`, and a peer outside any network that no rule covers.
        status, body = self.listing('p1', 'r')
        need(status == 200 and [e['capability'] for e in body] == ['budget2'],
             'a member sees only what its rules cover (budget2, shared with everyone)', status, body)
        status, body = self.listing('p1', 'n')
        need((status, body) == (200, []), 'never listing unauthorized capabilities', status, body)
        # Status and cancel: submitter only.
        b = self.body('work', 'echo', {'text': 'mine'}, cite=self.policy_cite())
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
        cite = self.self_cite()   # p2 under self: every capability, no hourly budget
        # The lifecycle of a tool operation on a capability, on the wire.
        marker = 'life-' + secrets.token_hex(4)
        b = self.body('work', 'echo', {'text': marker}, cite=cite)
        status, record = self.submit('p2', b)
        need(status == 200 and set(record) == STATUS_KEYS, 'POST /peer/v1/calls returns the status record', status,
             record)
        need(record['state'] == 'queued' and record['capability'] == 'work' and record['operation'] == 'echo' and
             record['sender_host_id'] == ids['p2'] and record['receiver_host_id'] == ids['p1'] and
             record['cancel_requested'] is False and record['result_bytes'] is None,
             'persisted as queued; result_bytes null until there is a result', record)
        done = self.final('p2', b['call_id'])
        need(set(done) == STATUS_KEYS | {'result'} and done['state'] == 'succeeded' and done['error'] is None and
             done['result'] == {'content': [{'type': 'text', 'text': marker}]} and done['result_bytes'] > 0 and
             done['started_at'] and done['finished_at'], 'the full lifecycle; tools/call {name, arguments: input}',
             done)
        call_entry = f.calls('fx-local', marker)
        need(len(call_entry) == 1 and call_entry[0]['name'] == 'echo' and call_entry[0]['arguments'] == {'text': marker},
             'the fixture ran the tool once with the input as arguments', call_entry)
        # read on a capability, and on a source.
        for capability in ('docs', 'cc/fx'):
            b = self.body(capability, 'read', {'uri': 'fixture://docs/guide'}, cite=cite)
            self.submit('p2', b)
            done = self.final('p2', b['call_id'])
            need(done['state'] == 'succeeded' and dig(done, 'result', 'contents', 0, 'uri') == 'fixture://docs/guide',
                 f'read sends resources/read {{uri}} ({capability})', done)
        # A tool operation on a source.
        b = self.body('cc/fx', 'purge', {}, cite=cite)
        self.submit('p2', b)
        need(self.final('p2', b['call_id'])['state'] == 'succeeded', 'a source covers every tool, write tools too')
        before = len(f.calls('fx-local', name='read'))
        status, _ = self.submit('p2', self.body('cc/fx', 'read', {'text': 'the tool'}, cite=cite))
        need(status == 404 and len(f.calls('fx-local', name='read')) == before,
             'a source\'s tool named read is not an operation: read takes a URI in the snapshot, otherwise 404', status)
        # Duplicate and conflicting submission.
        b = self.body('work', 'echo', {'text': 'dup-' + secrets.token_hex(4)}, cite=cite)
        status, first = self.submit('p2', b)
        status, again = self.submit('p2', b)
        need(status == 200 and again['call_id'] == b['call_id'] and again['created_at'] == first['created_at'],
             'an identical repeat returns the existing record', again)
        need(self.submit('p2', {**b, 'input': {'text': 'changed'}})[0] == 409, 'a changed repeat returns 409')
        self.final('p2', b['call_id'])
        need(len(f.calls('fx-local', b['input']['text'])) == 1, 'never run twice')
        for bad in ({**b, 'call_id': 'call_x'}, {**b, 'extra': 1}, {**b, 'call_id': call_id(), 'input': []},
                    {k: v for k, v in {**b, 'call_id': call_id()}.items() if k != 'operation'},
                    {**b, 'call_id': call_id(), 'policy': self.policy_cite()['policy']}):
            need(self.submit('p2', bad)[0] == 400, 'POST /peer/v1/calls takes exactly its fields and one citation', bad)
        # isError, JSON-RPC errors, result_too_large.
        for name, arguments, error in (('tool_error', {'message': 'nope'}, 'tool_error'),
                                       ('fail', {'message': 'broken', 'code': -32001}, 'jsonrpc_error'),
                                       ('big', {'bytes': 1100000}, 'result_too_large')):
            b = self.body('work', name, arguments, cite=cite)
            self.submit('p2', b)
            done = self.final('p2', b['call_id'])
            need(done['state'] == 'failed' and done['error'] == error, f'{name}: failed with {error}', done)
            if error == 'jsonrpc_error':
                need(done['result'] == {'code': -32001, 'message': 'broken'}, 'a JSON-RPC error result is {code, '
                     'message}', done['result'])
            if error == 'result_too_large':
                need(done.get('result') is None, 'a result over 1 MiB is not stored', str(done)[:300])
        b = self.body('work', 'big', {'bytes': 1048000}, cite=cite)
        self.submit('p2', b)
        try:
            near = self.final('p2', b['call_id'])
        except OSError as error:
            raise Failure(f'peerspan-peer-probe accepts 4 MiB on GET /peer/v1/calls/{{id}}: {error}') from None
        need(near['state'] == 'succeeded', 'a result just under 1 MiB is kept', near['state'])

        # A lost submit response, recovered with exactly one execution (a manual peer address takes precedence).
        marker = 'lost-' + secrets.token_hex(4)
        relay = DropCallResponse(self.hosts['p1'])
        identity = self.hosts['p1'].call('GET', '/v1/host')[1]
        self.hosts['p2'].configure(self.hosts['p1'], identity, relay.address)
        try:
            code, out, stderr = self.call('p2', f"{ids['p1']}/work", 'echo', {'text': marker}, wait='1')
            relay.close()
        finally:
            self.hosts['p2'].configure(self.hosts['p1'], identity)
        need(out and set(out) == OUTBOUND_KEYS and out['submit_state'] == 'unknown' and out['next_attempt_at'] and
             code == 3, 'the outbound record after a lost response; exit 3 while pending', code, out, stderr[-300:])
        recovered = wait_for(lambda: (r := self.inspect('p2', ids['p1'], out['request']['call_id']))['submit_state'] ==
                             'accepted' and r, timeout=40, message='automatic call retry')
        final = self.settle('p2', recovered)
        need(dig(final, 'status', 'state') == 'succeeded' and first_text(final.get('result')) == marker and
             len(f.calls('fx-local', marker)) == 1, 'recovered by retry with exactly one execution', final)

        # Expiry, and cancellation while queued.
        self.fill_slots(8)
        expiring = self.body('work', 'echo', {'text': 'exp-' + secrets.token_hex(4)}, cite=cite, deadline=timestamp(3))
        queued = self.body('work', 'echo', {'text': 'cq-' + secrets.token_hex(4)}, cite=cite)
        for b in (expiring, queued):
            need(self.submit('p2', b)[1]['state'] == 'queued', 'queued behind 4 running calls')
        status, record = wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'POST',
                              f"/peer/v1/calls/{queued['call_id']}/cancel", {})
        need(status == 200 and record['state'] == 'cancelled' and record['cancel_requested'] is True,
             'cancelling a queued call: cancelled at once', record)
        need(self.final('p2', expiring['call_id'], timeout=40)['state'] == 'expired', 'expiry before start')
        need(not f.calls('fx-local', expiring['input']['text']) and not f.calls('fx-local', queued['input']['text']),
             'expired and cancelled calls never ran')
        status, again = wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'POST',
                             f"/peer/v1/calls/{queued['call_id']}/cancel", {})
        need(again['state'] == 'cancelled', 'a cancel of a final call returns it unchanged', again)
        time.sleep(9)
        # Cancellation while running, and the deadline while running.
        for how in ('cancel', 'deadline'):
            marker = f'{how}-' + secrets.token_hex(4)
            b = self.body('work', 'sleep', {'seconds': 30, 'text': marker}, cite=cite,
                          deadline=timestamp(6) if how == 'deadline' else None)
            self.submit('p2', b)
            wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
            if how == 'cancel':
                wire(self.hosts['p1'], fixture_context(self.hosts['p2']), 'POST', f"/peer/v1/calls/{b['call_id']}/cancel",
                     {})
            done = self.final('p2', b['call_id'], timeout=40)
            error = 'cancel_requested' if how == 'cancel' else 'deadline'
            need(done['state'] == 'uncertain' and done['error'] == error, f'a running call: uncertain with {error}',
                 done)
            request = f.calls('fx-local', marker)[0]['id']
            wait_for(lambda: any(e['event'] == 'cancelled' and e.get('request_id') == request
                                 for e in f.entries('fx-local')), timeout=10, message='notifications/cancelled')
        # A daemon restart while running.
        marker = 'restart-' + secrets.token_hex(4)
        b = self.body('work', 'sleep', {'seconds': 15, 'text': marker}, cite=cite)
        self.submit('p2', b)
        wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
        self.restart('p1')
        done = self.final('p2', b['call_id'], timeout=30)
        need(done['state'] == 'uncertain' and done['error'] == 'daemon_restarted',
             'a daemon restart: uncertain, daemon_restarted', done)
        time.sleep(18)
        need(len(f.calls('fx-local', marker)) == 1, 'no re-execution after a restart')
        # A server exit while running.
        marker = 'exit-' + secrets.token_hex(4)
        b1 = self.body('work', 'sleep', {'seconds': 30, 'text': marker}, cite=cite)
        self.submit('p2', b1)
        wait_for(lambda: f.calls('fx-local', marker), timeout=20, message='running')
        pid = f.calls('fx-local', marker)[0]['pid']
        b2 = self.body('work', 'crash', {'delay': 1}, cite=cite)
        self.submit('p2', b2)
        for b in (b1, b2):
            done = self.final('p2', b['call_id'], timeout=30)
            need(done['state'] == 'uncertain' and done['error'] == 'server_exited', 'a server exit: uncertain', done)
        marker = 'after-exit-' + secrets.token_hex(4)
        b = self.body('work', 'echo', {'text': marker}, cite=cite)
        self.submit('p2', b)
        need(self.final('p2', b['call_id'])['state'] == 'succeeded' and f.calls('fx-local', marker)[0]['pid'] != pid,
             'queued and later calls start a new instance')
        # Concurrency: at most 4, one instance per source shared by its capabilities.
        marker = 'conc-' + secrets.token_hex(4)
        batch = [self.body('work' if i % 2 else 'cc/fx', 'sleep', {'seconds': 3, 'text': marker}, cite=cite)
                 for i in range(6)]
        for b in batch:
            self.submit('p2', b)
        for b in batch:
            need(self.final('p2', b['call_id'], timeout=40)['state'] == 'succeeded', 'every call finishes')
        entries = f.calls('fx-local', marker)
        need(max(e['concurrent'] for e in entries) == 4 and len({e['pid'] for e in entries}) == 1,
             'one instance per source (the source and its capability share it), at most 4 at once',
             [(e['pid'], e['concurrent']) for e in entries])
        # A tool added to a source: callable through it, not through capabilities built on it.
        f.set('fx-local', extra_tools=[{'name': 'added', 'read_only': True}])
        try:
            self.refresh('cc')
            b = self.body('cc/fx', 'added', {}, cite=cite)
            status, _ = self.submit('p2', b)
            need(status == 200 and self.final('p2', b['call_id'])['state'] == 'succeeded',
                 'a tool added to a source is callable through it', status)
            status, _ = self.submit('p2', self.body('work', 'added', {}, cite=cite))
            need(status == 404, 'but not through capabilities built on it', status)
            need('added' not in self.capability('work')['operations'], 'never added to an existing capability')
        finally:
            f.set('fx-local')
            self.refresh('cc')
        # Running calls finish after unshare.
        self.share('litcap', '--with', 'rhea', '--yes')
        self.synced(self.version(), 'r')
        b = self.body('work', 'sleep', {'seconds': 6, 'text': 'across-' + secrets.token_hex(4)},
                      cite=self.policy_cite())
        status, _ = self.submit('q1', b)
        wait_for(lambda: f.calls('fx-local', b['input']['text']), timeout=20, message='running')
        out = self.unshare('work', 'quinn')
        need(self.final('q1', b['call_id'], timeout=30)['state'] == 'succeeded', 'running calls finish after unshare')
        self.share('work', '--with', 'quinn', '--yes')
        self.unshare('litcap', 'rhea')
        self.sync_all()
        # Activity.
        kinds = {e['kind'] for e in self.activity('p1')}
        need({'call.received', 'call.started', 'call.finished', 'call.cancel_requested'} <= kinds, 'receiver activity',
             sorted(k for k in kinds if k.startswith('call.')))
        received = [e for e in self.activity('p1') if e['kind'] == 'call.received']
        need(any(e['subject_id'] == f"{ids['p2']}/{batch[0]['call_id']}" for e in received),
             'call.* subjects SENDER_HOST_ID/CALL_ID', received[-3:])
        sent = [e for e in self.activity('p2') if e['kind'].startswith('call.')]
        need({e['kind'] for e in sent} == {'call.submitted', 'call.updated'} and
             any(e['subject_id'] == f"{ids['p1']}/{recovered['request']['call_id']}" for e in sent),
             'caller activity: call.submitted and call.updated, subject PEER_HOST_ID/CALL_ID', sent[:3])

    def check_values(self):
        captured, literal = self.secrets['captured'], self.secrets['literal']

        def source_call(source, tool, arguments):
            b = self.body(source, tool, arguments, cite=self.self_cite())
            status, record = self.submit('p2', b)
            need(status == 200, f'source call {source} {tool}', status, record)
            done = self.final('p2', b['call_id'])
            need(done['state'] == 'succeeded', f'source call {source} {tool}', done)
            return first_text(done['result'])

        def matches(source, name, value):
            return source_call(source, 'env_matches', {'name': name, 'sha256': sha(value)})
        need(matches('cc/proj', 'TOKEN_A', captured) == {'present': True, 'matches': True}, '${VAR} captured')
        need(matches('cc/proj', 'TOKEN_B', 'fallback-b') == {'present': True, 'matches': True}, '${VAR:-DEFAULT}')
        need(matches('cc/lit', 'LIT_TOKEN', literal) == {'present': True, 'matches': True},
             'a server configured with a literal token starts with it')
        names = set(source_call('cc/proj', 'env_names', {}))
        need({'PATH', 'HOME', 'TOKEN_A', 'TOKEN_B'} <= names <= {'PATH', 'HOME', 'TOKEN_A', 'TOKEN_B'} | INTERPRETER_NAMES,
             "the daemon's PATH and HOME and the definition's env, nothing else (no daemon variables)", sorted(names))
        need(source_call('cc/proj', 'info', {})['cwd'] == str(self.workspaces['w1']), 'the workspace as cwd')
        env_file = self.hosts['p1'].config / 'peerspan' / 'env'
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_file.write_text(f"# overrides\nTOKEN_A={self.secrets['file']}\n\nLIT_TOKEN=from-file\n"
                            f"EXTRA_FROM_FILE={self.secrets['file']}\nNEED=x\nFX_MISSING_VAR=x\n")
        env_file.chmod(0o600)
        self.restart('p1')
        need(matches('cc/proj', 'TOKEN_A', self.secrets['file']) == {'present': True, 'matches': True},
             'the environment file overrides captured values for names in the definition')
        need(matches('cc/lit', 'LIT_TOKEN', 'from-file') == {'present': True, 'matches': True}, 'and literals')
        names = set(source_call('cc/proj', 'env_names', {}))
        need(names <= {'PATH', 'HOME', 'TOKEN_A', 'TOKEN_B'} | INTERPRETER_NAMES,
             'other variables in the file never reach the server', sorted(names))
        need('TOKEN_A' not in set(source_call('cc/lit', 'env_names', {})), 'filtered to each definition\'s names')
        need(not [i for i in self.items() if i['subject'] == 'env'], 'no item 14 for a 0600 file')
        self.refresh('cc')
        needy = self.servers('cc')['needy']
        need(needy['reason'] == 'missing_env' and needy['missing_env'] == ['FX_MISSING_VAR'],
             'a missing reference stays missing_env even when the environment file has that name', needy)
        env_file.chmod(0o644)
        self.restart('p1')
        need(matches('cc/proj', 'TOKEN_A', captured) == {'present': True, 'matches': True},
             'a file not mode 0600 or stricter is not used')
        item = [i for i in self.items() if i['subject'] == 'env']
        need(item and item[0]['command'] == f'chmod 600 {env_file}', 'item 14 for the environment file', self.items())
        env_file.unlink()
        self.restart('p1')
        self.scan_secrets([captured, literal, self.secrets['file'], self.secrets['own']])

    def scan_secrets(self, values):
        found = []
        texts = list(self.exposed)
        for name in self.hosts:
            h = self.hosts[name]
            texts.append((f'{name} activity', json.dumps(self.activity(name))))
            h.logs.seek(0)
            texts.append((f'{name} daemon log', h.logs.read().decode(errors='replace')))
            texts.append((f'{name} status', json.dumps(self.status(name))))
            for path in h.state.rglob('*'):
                if path.is_file() and not path.name.startswith('host.db') and not path.is_socket():
                    try:
                        texts.append((str(path), path.read_bytes().decode(errors='replace')))
                    except OSError:
                        pass
            connection = sqlite3.connect(h.state / 'host.db')
            try:
                for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
                    if table == 'tool_values':
                        continue
                    for row in connection.execute(f'SELECT * FROM "{table}"'):
                        texts.append((f'{name} table {table}', ' '.join(str(c) for c in row)))
            finally:
                connection.close()
        for caller in ('p2', 'q1'):
            texts.append((f'GET /peer/v1/capabilities as {caller}', json.dumps(self.listing('p1', caller)[1])))
        texts.append(('GET /v1/sources', json.dumps(self.sources_view())))
        texts.append(('GET /v1/capabilities', json.dumps(self.capability_list())))
        for where, text in texts:
            for value in values:
                if value in text:
                    found.append(where)
        need(not found, 'values never appear outside tool_values: definitions, listings, output, logs, activity, '
             'or peer routes', sorted(set(found)))
        stored = {r[0] for r in db_rows(self.hosts['p1'], 'SELECT value FROM tool_values')}
        need(self.secrets['captured'] in stored and self.secrets['literal'] in stored,
             'captured and literal values are stored in tool_values', len(stored))

    def check_own_credential(self):
        f = self.fixture

        def run(operation, arguments, capability='narrow'):
            b = self.body(capability, operation, arguments, cite=self.self_cite())
            status, record = self.submit('p2', b)
            need(status == 200, f'{capability} {operation}', status, record)
            done = self.final('p2', b['call_id'])
            need(done['state'] == 'succeeded', f'{capability} {operation}', done)
            return first_text(done['result'])
        need(run('info', {})['labels'] == ['narrow'], "the capability's args replace the source's arguments")
        need(run('env_matches', {'name': 'FX_CAPTURED', 'sha256': sha(self.secrets['own'])}) ==
             {'present': True, 'matches': True}, 'its env_file is applied last, overriding the definition\'s env')
        need(run('env_matches', {'name': 'OWN_ONLY', 'sha256': sha('unnamed')}) == {'present': True, 'matches': True},
             'the whole env_file is applied, unfiltered')
        need(run('env_matches', {'name': 'FX_CAPTURED', 'sha256': sha(self.secrets['captured'])}, 'work') ==
             {'present': True, 'matches': True} and
             run('env_matches', {'name': 'OWN_ONLY', 'sha256': 'x'}, 'work')['present'] is False,
             'capabilities on the source\'s own credential keep the source\'s environment')
        need({e['pid'] for e in f.calls('fx-narrow')}.isdisjoint({e['pid'] for e in f.calls('fx-local')}),
             'a capability with its own credential context has its own instance')
        need(any(p.name.endswith('fx@narrow.log') for p in (self.hosts['p1'].state / 'tool-logs').rglob('*.log')),
             'its stderr goes to …/SERVER@CAPABILITY.log',
             [str(p) for p in (self.hosts['p1'].state / 'tool-logs').rglob('*.log')])
        # A sources PUT snapshots own-credential capabilities again: a tool hidden from the own-credential snapshot
        # makes that operation unavailable after a refresh; the others still run; recovery when it returns.
        f.set('fx-narrow', hide_tools=['info'])
        try:
            self.refresh('cc')
            narrow = self.capability('narrow')
            need(narrow['state'] == 'unavailable' and narrow['unavailable'] == ['info'],
                 'a sources PUT re-snapshots own-credential capabilities with their own credential', narrow)
            status, body = self.submit('p2', self.body('narrow', 'info', {}, cite=self.self_cite()))
            need(status == 409 and dig(body, 'code') == 'unavailable', 'the unavailable operation is refused (409)',
                 status, body)
            need(run('env_names', {}) is not None, 'other operations of an unavailable capability still run')
        finally:
            f.set('fx-narrow')
            self.refresh('cc')
        need(self.capability('narrow')['state'] == 'available', 'available again after the next refresh')
        # Operations are checked against the capability's own snapshot.
        status, body = self.create('narrow2', 'cc/fx', 'operations', ['from_local'], 'env_file', str(self.own_env),
                                   'args', self.fixture.args('fx-narrow2', 'other', isolated=False), expect=None)
        need(status == 400, 'operations are checked against the snapshot taken with its own credential', status, body)

    def check_snapshots(self):
        f = self.fixture
        servers = self.servers('cc')
        paged = servers['paged']
        need({f'gen_{n:04d}' for n in range(10)} <= set(self.tool_names(paged)) and
             len(paged['tools']) == len(RO_TOOLS | WRITE_TOOLS) + 10 and len(paged['resources']) == 4,
             'snapshots follow nextCursor across pages', len(paged['tools']))
        before = self.tool_names(servers['slow'])
        for control, why in (({'list_error': True}, 'a failing tools/list'),
                             ({'huge_snapshot': True}, 'a snapshot larger than 1 MiB'),
                             ({'generate': 1001, 'page_size': 100}, 'more than 1,000 entries'),
                             ({'list_delay': 40}, 'the 30-second bound')):
            f.set('slow', **control)
            started = time.monotonic()
            self.refresh('cc')
            elapsed = time.monotonic() - started
            slow = self.servers('cc')['slow']
            need(slow['snapshot_error'], f'{why} records snapshot_error', slow['snapshot_error'])
            need(self.tool_names(slow) == before, f'{why} keeps the previous snapshot')
            if 'generate' in control:
                need('too_many_entries' in str(slow['snapshot_error']), 'too_many_entries', slow['snapshot_error'])
            if 'list_delay' in control:
                need(28 <= elapsed <= 60, 'the whole snapshot finishes within 30 seconds', elapsed)
        f.set('slow')
        self.refresh('cc')
        need(self.servers('cc')['slow']['snapshot_error'] is None, 'a successful snapshot clears snapshot_error')
        events = [e for e in self.activity('p1') if e['kind'] == 'sources.snapshot_failed']
        need(any(e['subject_id'] == f"{self.aid['cc']}/slow" for e in events),
             'sources.snapshot_failed activity, subject AGENT_ID/SERVER', events[-3:])

    def check_configuration_changes(self):
        f, cite = self.fixture, self.self_cite()
        # A selected tool missing from the latest snapshot makes the operation unavailable; recovery.
        f.set('fx-local', hide_tools=['info'], hide_resources=['fixture://docs/guide'])
        try:
            self.refresh('cc')
            work = self.capability('work')
            need(work['state'] == 'unavailable' and work['unavailable'] == ['info'],
                 'a missing selected tool makes that operation unavailable', work)
            status, body = self.submit('p2', self.body('work', 'info', {}, cite=cite))
            need(status == 409 and body.get('code') == 'unavailable', 'an unavailable operation: 409 unavailable',
                 status, body)
            b = self.body('work', 'echo', {'text': 'still'}, cite=cite)
            need(self.submit('p2', b)[0] == 200 and self.final('p2', b['call_id'])['state'] == 'succeeded',
                 'other operations still run')
            status, _ = self.submit('p2', self.body('docs', 'read', {'uri': 'fixture://docs/guide'}, cite=cite))
            need(status == 404, 'a selected resource missing from the snapshot is excluded from read', status)
            status, listed = self.listing('p1', 'q1')
            entry = self.entry(listed, 'work')
            need(entry['state'] == 'unavailable' and entry['unavailable'] == ['info'], 'the listing shows it', entry)
            items = [i for i in self.items() if i['subject'] == 'work']
            need(items and items[0]['command'] == 'peerspan capability show work',
                 'item 14 for an unavailable capability', self.items())
        finally:
            f.set('fx-local')
            self.refresh('cc')
        need(self.capability('work')['state'] == 'available', 'recovery when the tool returns')
        b = self.body('docs', 'read', {'uri': 'fixture://docs/guide'}, cite=cite)
        need(self.submit('p2', b)[0] == 200, 'the resource returns to read')
        self.final('p2', b['call_id'])
        # A dropped server: its capabilities remain, unavailable (source); running calls finish; recovery.
        marker = 'dropped-' + secrets.token_hex(4)
        b = self.body('gonecap', 'sleep', {'seconds': 10, 'text': marker}, cite=cite)
        need(self.submit('p2', b)[0] == 200, 'setup: a running call on gonecap')
        wait_for(lambda: f.calls('gone', marker), timeout=20, message='running')
        gone = self.local_servers.pop('gone')
        self.write_claude_json()
        try:
            self.refresh('cc')
            need('gone' not in self.servers('cc'), 'a PUT that drops a server deletes its definition')
            cap = self.capability('gonecap')
            need(cap and cap['state'] == 'unavailable' and cap['unavailable'] == ['source'],
                 'capabilities built on a dropped server remain, unavailable with source', cap)
            need(self.final('p2', b['call_id'], timeout=40)['state'] == 'succeeded', 'calls already running finish')
            status, body = self.submit('p2', self.body('gonecap', 'echo', {'text': 'x'}, cite=cite))
            need(status == 409 and body.get('code') == 'unavailable', 'new calls to it are refused (409)', status, body)
            status, _ = self.submit('p2', self.body('cc/gone', 'echo', {'text': 'x'}, cite=cite))
            need(status in (404, 409), 'the source itself is gone', status)
        finally:
            self.local_servers['gone'] = gone
            self.write_claude_json()
            self.refresh('cc')
        need(self.capability('gonecap')['state'] == 'available', 'recovery when the server returns')

    def check_cli(self):
        ids, q1 = self.ids, self.hosts['q1']
        # A fresh budget for this section's calls (the rule identity includes its bounds).
        self.share('work', '--with', 'quinn', '--calls-per-hour', '10000', '--yes')
        self.synced(self.version(), 'q1', 'q2')
        # discover.
        code, out, stdout, stderr = q1.outcome('discover', 'pat', '--json')
        need(code == 0 and isinstance(out, dict) and set(out) == DISCOVER_KEYS, 'discover --json is {agents, '
             'capabilities, unanswered}', code, stdout[:300])
        for e in out['capabilities']:
            need(set(e) == DISCOVER_ENTRY_KEYS, 'discover capability entries', e)
        found = {e['capability']: e for e in out['capabilities']}
        need({'work', 'docs', 'budget', 'budget2', 'litcap'} <= set(found) and found['work']['address'] == 'pat/work'
             and found['work']['host_id'] == ids['p1'], 'capabilities with address PERSON/CAPABILITY', found.keys())
        status, body = q1.call('GET', f'/v1/discover?person=pat&network={self.team}')
        need(status == 200 and 'litcap' not in {e['capability'] for e in body['capabilities']},
             '--network: only that network', status, body)
        code, out, stdout, stderr = self.hosts['p2'].outcome('discover', 'pat', '--json')
        sources = [e for e in (out or {}).get('capabilities', []) if e['kind'] == 'source']
        need(code == 0 and any(e['address'] == 'pat/cc/fx' for e in sources), 'discover includes sources opened to '
             'this host, addressed PERSON/AGENT/SERVER', [e['address'] for e in sources])
        # Names on more than one host: since claims, a second host cannot create a claimed name, so the only way to
        # one name on two of a person's hosts is a lost concurrent claim. The address rule for that case (the claimed
        # copy as PERSON/CAPABILITY, the other only as HOST_ID/CAPABILITY, PERSON/CAPABILITY resolving to the claimed
        # copy) is checked in the concurrent claims section. A 409 `ambiguous` needs two entries both addressed
        # PERSON/CAPABILITY, which the contract no longer lets arise from the person's policies (owner decision 3);
        # it is not exercised (see the run's notes).
        # Unanswered hosts, and not found.
        self.hosts['p3'].stop()
        try:
            status, body = q1.call('GET', '/v1/discover?person=pat')
            need(status == 200 and ids['p3'] in [u['host_id'] for u in body['unanswered']] and
                 all(set(u) == {'host_id', 'error'} for u in body['unanswered']), 'discover lists unanswered hosts',
                 status, body)
            count = self.outbound_count('q1')
            status, body = q1.call('POST', '/v1/calls', {'target': 'pat/nosuch', 'operation': 'echo', 'input': {},
                                                         'deadline': timestamp(300)})
            need(status == 404 and body.get('code') == 'not_found' and 'unanswered' in body and
                 self.outbound_count('q1') == count, '404 {code: "not_found", error, unanswered}, nothing persisted',
                 status, body)
        finally:
            self.hosts['p3'].start()
        # call: --input, --KEY VALUE, call's own flags, errors.
        code, out, stderr = self.call('q1', 'pat/work', 'typed', None, '--count', '3', '--ratio', '1.5', '--flag',
                                      'true', '--text', 'hi', '--network', self.team)
        need(code == 0 and first_text(dig(out, 'result')) == {'count': 3, 'ratio': 1.5, 'flag': True, 'text': 'hi'} and
             out['request']['input'] == {'count': 3, 'ratio': 1.5, 'flag': True, 'text': 'hi'},
             '--KEY VALUE fills scalar properties, parsed by type', code, out, stderr[-300:])
        code, out, stderr = self.call('q1', 'pat/work', 'flags', {'network': 'n1', 'wait': 'w', 'deadline': 'd',
                                                                  'input': 'i'}, '--network', self.team)
        need(code == 0 and first_text(dig(out, 'result')) == {'network': 'n1', 'wait': 'w', 'deadline': 'd', 'input': 'i'},
             "a property named like call's own flags is given in --input", code, out)
        count = self.outbound_count('q1')
        for extra, why in ((('--obj', 'x'), 'a non-scalar property'), (('--nope', 'x'), 'an undeclared property'),
                           (('--count', 'three'), 'a value that does not parse by type'),
                           (('--text', 'a', '--input', '{"text": "b"}'), 'a KEY also present in --input')):
            code, out, stdout, stderr = q1.outcome('call', 'pat/work', 'typed', *extra, '--network', self.team,
                                                   '--wait', '5s')
            need(code != 0 and self.outbound_count('q1') == count, f'--KEY VALUE errors: {why}', code)
        # --deadline, --wait, exit codes.
        code, out, stderr = self.call('q1', 'pat/work', 'echo', {'text': 'd'}, '--network', self.team, '--deadline',
                                      '5m')
        left = (parse_time(dig(out, 'request', 'deadline')) - datetime.now(timezone.utc)).total_seconds() if dig(out, 'request', 'deadline') else 0
        need(code == 0 and 240 <= left <= 300, '--deadline accepts a duration', code, out and out['request'])
        code, out, stderr = self.call('q1', 'pat/work', 'echo', {'text': 'd'}, '--network', self.team, '--deadline',
                                      '300')
        left = (parse_time(dig(out, 'request', 'deadline')) - datetime.now(timezone.utc)).total_seconds() \
            if dig(out, 'request', 'deadline') else 0
        need(code == 0 and 240 <= left <= 300, 'a bare N duration is seconds', code, left)
        code, out, stderr = self.call('q1', 'pat/work', 'echo', {'text': 'd'}, '--network', self.team, '--deadline',
                                      timestamp(240))
        need(code == 0, '--deadline accepts RFC3339', code, stderr[-200:])
        code, out, stderr = self.call('q1', 'pat/work', 'echo', {'text': 'default'}, '--network', self.team)
        left = (parse_time(dig(out, 'request', 'deadline')) - datetime.now(timezone.utc)).total_seconds() if dig(out, 'request', 'deadline') else 0
        need(code == 0 and 800 <= left <= 900, 'the default deadline is 15 minutes', left)
        # The contract does not promise a call finishes within the wait, so exit 3 (pending) is acceptable; the
        # record must be printed either way, and a final state must match the exit code.
        for wait in ('1', '1s', '1m'):
            code, out, stderr = self.call('q1', 'pat/work', 'echo', {'text': 'w'}, '--network', self.team, wait=wait)
            need(code in (0, 3) and isinstance(out, dict) and set(out) == OUTBOUND_KEYS and
                 (code == 3) == (not out.get('status') or out['status'].get('state') not in FINAL),
                 '--wait takes N, Ns, or Nm; exit 0 when succeeded, 3 while pending', wait, code, out, stderr[-200:])
        count = self.outbound_count('q1')
        code, out, stderr = self.call('q1', 'pat/work', 'echo', {'text': 'w'}, '--network', self.team, wait='16m')
        need(code != 0 and self.outbound_count('q1') == count, '--wait is at most 15 minutes', code)
        code, out, stderr = self.call('q1', 'pat/work', 'tool_error', {}, '--network', self.team)
        need(code == 1 and dig(out, 'status', 'state') == 'failed', 'exit 1 for other final states', code, out)
        code, out, stderr = self.call('q1', 'pat/work', 'sleep', {'seconds': 6, 'text': 'pending'}, '--network',
                                      self.team, wait='0')
        need(code == 3, 'exit 3 if still pending', code, out)
        pending = out
        code, out, stderr = self.call('q1', 'pat/docs', 'read', {'uri': 'fixture://docs/readme'}, '--network', self.team)
        need(code == 0 and dig(out, 'status', 'operation') == 'read', 'call ... read', code, out)
        code, out, stderr = self.call('q1', 'pat/work', 'echo', {'text': 'x' * 70000}, '--network', self.team)
        need(code == 1 and dig(out, 'submit_state') == 'rejected' and dig(out, 'next_attempt_at') is None,
             '413 is a final rejected submission', code, out)
        # POST /v1/calls deadline refusals before persisting.
        count = self.outbound_count('q1')
        for deadline in (timestamp(-5), timestamp(16 * 60)):
            status, body = q1.call('POST', '/v1/calls', {'target': 'pat/work', 'operation': 'echo',
                                                         'input': {'text': 'x'}, 'deadline': deadline,
                                                         'network': self.team})
            need(status == 400, 'the daemon refuses a past deadline or one over 15 minutes, before persisting',
                 deadline, status, body)
        need(self.outbound_count('q1') == count, 'nothing persisted')
        status, body = q1.call('POST', '/v1/calls', {'target': 'pat/work', 'operation': 'echo', 'input': {'text': 'a'},
                                                     'deadline': timestamp(300), 'network': self.team, 'call_id': None})
        need(status == 200 and set(body) == OUTBOUND_KEYS and body['network_id'] == self.team and
             body['target'] == 'pat/work' and 'grant_id' not in body['request'],
             'POST /v1/calls returns the outbound record', status, body)
        # calls listings.
        listed = q1.cli('calls', 'list', '--limit', '1000')
        need(listed and all(set(i) == {'sequence', 'call'} and set(i['call']) == OUTBOUND_KEYS for i in listed),
             'calls list: [{sequence, call}]', listed[:1])
        need([i['sequence'] for i in listed] == sorted(i['sequence'] for i in listed), 'insertion order')
        need(pending['request']['call_id'] in {i['call']['request']['call_id'] for i in listed}, 'calls list')
        need(len(q1.cli('calls', 'list', '--limit', '1')) == 1, 'calls list --limit')
        after = q1.cli('calls', 'list', '--after', str(listed[-2]['sequence']))
        need(len(after) == 1 and after[0]['sequence'] == listed[-1]['sequence'], 'calls list --after', after)
        received = self.hosts['p1'].cli('calls', 'received', '--limit', '1000')
        need(received and all(set(i) == {'sequence', 'request', 'status'} for i in received) and
             pending['request']['call_id'] in {i['status']['call_id'] for i in received},
             'calls received: [{sequence, request, status}]', received[-1:])
        code, out, stdout, stderr = self.hosts['p1'].outcome('calls', 'cancel', '--peer', ids['q1'], call_id())
        need(code != 0, 'calls cancel of an unknown outbound call fails', code)

    def check_status(self):
        f, ids = self.fixture, self.ids
        counts = self.counts()
        need(set(counts) == CAPABILITY_COUNTS | {'open_to'}, 'capabilities {sources, capabilities, shared, '
             'calls_running} and open_to', counts)
        view = self.sources_view()
        all_servers = sum(len(a['servers']) for a in view['agents'])
        shareable = sum(1 for a in view['agents'] for s in a['servers'] if s['shareable'])
        records = self.capability_list()
        rules = [r for net in self.bound['p1'] for r in self.cap_rules(net) if r['host'] == ids['p1']]
        # `shared` counts capabilities named by a rule for this host with at least one principal (claims excluded).
        shared = sum(1 for c in records if any(r['capability'] == c['name'] and r['principals'] for r in rules))
        need(shared < len(records), 'setup: some capabilities only claimed', shared, len(records))
        running = sum(1 for i in self.hosts['p1'].cli('calls', 'received', '--limit', '1000')
                      if i['status']['state'] == 'running')
        # "discovered sources on this host": whether unshareable servers count is not said (ambiguous); either.
        need(counts['sources'] in (all_servers, shareable), 'sources counts the discovered sources', counts,
             all_servers, shareable)
        self.soft(counts['sources'] == all_servers, 'sources counts every discovered server (narrowest reading)',
                  counts['sources'], all_servers)
        need((counts['capabilities'], counts['shared'], counts['calls_running'], counts['open_to']) ==
             (len(records), shared, running, len(self.open_list())), 'the capabilities counts', counts,
             (len(records), shared, running, len(self.open_list())))
        b = self.body('work', 'sleep', {'seconds': 6, 'text': 'counted'}, cite=self.self_cite())
        self.submit('p2', b)
        self.state_is('p2', b['call_id'], 'running', timeout=20)
        need(self.counts()['calls_running'] >= 1, 'calls_running counts running received calls', self.counts())
        self.final('p2', b['call_id'])
        # Item 14 for each cause.
        f.set('slow', list_error=True)
        self.refresh('cc')
        self.create('failstart', 'cc/startfail', 'operations', ['echo'], expect=None)
        f.set('startfail', exit_on_start=True)
        b = self.body('cc/startfail', 'echo', {'text': 'x'}, cite=self.self_cite())
        self.submit('p2', b)
        done = self.final('p2', b['call_id'], timeout=90)
        need(done['state'] == 'failed' and done['error'] == 'server_start_failed',
             'after 3 start failures, queued calls fail with server_start_failed', done)
        f.set('startslow', init_delay=40)
        b = self.body('cc/startslow', 'echo', {'text': 'x'}, cite=self.self_cite())
        started = time.monotonic()
        self.submit('p2', b)
        done = self.final('p2', b['call_id'], timeout=90)
        need(done['state'] == 'failed' and done['error'] == 'server_start_failed' and
             28 <= time.monotonic() - started <= 80, 'initialize not completed within 30 seconds', done)
        b = self.body('work', 'fail', {'message': '401 Unauthorized: invalid TOKEN'}, cite=self.self_cite())
        self.submit('p2', b)
        need(self.final('p2', b['call_id'])['error'] == 'jsonrpc_error', 'setup: an auth-looking JSON-RPC error')
        env_file = self.hosts['p1'].config / 'peerspan' / 'env'
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_file.write_text('A=b\n')
        env_file.chmod(0o640)
        try:
            servers = self.servers('cc')
            need(servers['startfail']['start_failed_at'] and servers['startslow']['start_failed_at'] and
                 servers['fx']['auth_error_at'] and servers['slow']['snapshot_error'],
                 'start_failed_at, auth_error_at, snapshot_error in GET /v1/sources')
            items = self.items()
            subjects = [i['subject'] for i in items]
            for subject in ('cc/slow', 'cc/startfail', 'cc/startslow', 'cc/fx'):
                need(subject in subjects, 'item 14 capability_failing for each source cause', subject, items)
                item = next(i for i in items if i['subject'] == subject)
                need(item['command'] == 'peerspan sources refresh --agent cc', 'item 14 command for a source', item)
            need('env' in subjects and next(i for i in items if i['subject'] == 'env')['command'] ==
                 f'chmod 600 {env_file}', 'item 14 for the environment file', items)
            need(subjects == sorted(subjects), 'items sorted by subject', subjects)
        finally:
            env_file.unlink()
            for key in ('slow', 'startfail', 'startslow'):
                f.set(key)
            self.refresh('cc')
            self.hosts['p1'].run('capability', 'remove', 'failstart', '--yes')
        # Item 15 is checked in the concurrent claims section, the only way it now arises.

    def check_removal(self):
        p1 = self.hosts['p1']
        # Without shares: removed at once.
        self.create('plain', 'cc/lit', 'operations', ['echo'])
        code, out, stdout, stderr = p1.outcome('capability', 'remove', 'plain')
        need(code == 0 and self.capability('plain') is None, 'capability remove without shares (no confirmation)',
             code, stderr[-300:])
        for n in self.bound['p1']:
            need(self.rule_for('plain', n) is None, 'its claims are removed in every network', n)
        # With shares in two networks: confirmation, then every rule withdrawn before the record goes.
        self.create('shared2', 'cc/lit', 'operations', ['echo'])
        self.share('shared2', '--with', 'quinn', '--yes')
        self.share('shared2', '--with', 'quinn', '--yes', net=self.other)
        code, out, stdout, stderr = p1.outcome('capability', 'remove', 'shared2')
        need(code != 0 and self.capability('shared2'), 'a shared capability needs confirmation (or --yes)', code)
        code, out, tty, stdout, seen = p1.converse('capability', 'remove', 'shared2', answers=['n'])
        need(code != 0 and self.capability('shared2') and 'quinn' in squash(tty),
             'it shows the recipients and asks; declining keeps it', code, tty[-400:])
        # Signing fails (no person key reachable): the command fails and the record is kept.
        versions = (self.version(), self.version('p1', self.other))
        code, out, stdout, stderr = p1.outcome('capability', 'remove', 'shared2', '--yes', sock=None)
        need(code != 0 and self.capability('shared2'), 'if any signing fails, the command fails and the record is kept',
             code, stderr[-300:])
        need((self.version(), self.version('p1', self.other)) == versions or
             self.rule_for('shared2') is None or self.rule_for('shared2', self.other) is None,
             'policies already signed stay signed', versions)
        code, out, stdout, stderr = p1.outcome('capability', 'remove', 'shared2', '--yes')
        need(code == 0 and self.capability('shared2') is None and self.rule_for('shared2') is None and
             self.rule_for('shared2', self.other) is None,
             'repeating finishes the removal: every network\'s rule withdrawn, then the record deleted', code)
        for n in self.bound['p1']:
            need(self.rule_for('shared2', n) is None, 'no rule or claim left in any network', n)
        kinds = {(e['kind'], e['subject_id']) for e in self.activity('p1')}
        need(('capability.removed', 'shared2') in kinds, 'capability.removed activity')
        self.sync_all()

    def check_concurrent_claims(self):
        """Item 15 after two hosts each claim one name while the other and the coordinator are stopped (Claims:
        Concurrent claims; Status: item 15; Discovery: the address rule). p1 (in team, other, v1net, later) and p4
        (in team only) both create `clash`, so the claims conflict in team only. Both daemons hold pat's key as the
        renewal key, so the loser re-applies: its claim is dropped (item 17, the edit closed) and item 15 reports
        the capability, which stays reachable through self only as HOST_ID/CAPABILITY."""
        ids = self.ids
        hosts = {n: self.hosts[n] for n in ('p1', 'p2', 'p3', 'p4')}
        if 'dup4' not in self.aid:
            self.register('p4', 'dup4')
            self.put_servers('p4', 'dup4', self.root, {'fx': self.fixture.args('dup4-fx')})
        self.sync_all()
        for name in ('p1', 'p4'):
            self.hosts[name].agent_socket = self.agents['pat'].socket
            self.restart(name)
        claims = {}
        self.coord.stop()
        try:
            for name in ('p2', 'p3', 'p4'):   # p2 and p3 could relay p1's claim to p4 (see check_tie_break)
                hosts[name].stop()
            code, out, stdout, stderr = hosts['p1'].outcome('capability', 'create', 'clash', '--from', 'cc/lit',
                                                            '--operations', 'echo')
            need(code == 0, 'p1 claims clash', code, stderr[-300:])
            claims['p1'] = self.policy('p1')
            hosts['p1'].stop()
            hosts['p4'].start()
            code, out, stdout, stderr = hosts['p4'].outcome('capability', 'create', 'clash', '--from', 'dup4/fx',
                                                            '--operations', 'echo')
            need(code == 0, 'p4, out of contact, claims the same name', code, stderr[-300:])
            claims['p4'] = self.policy('p4')
            need(claims['p1']['version'] == claims['p4']['version'], 'both claims signed from the same version',
                 claims['p1']['version'], claims['p4']['version'])
            hosts['p1'].start()
            w = min(claims, key=lambda n: policy_hash(claims[n]))
            lost = 'p4' if w == 'p1' else 'p1'
            seq = edits_map(claims[lost]).get(ids[lost])
            need(seq, 'each claim is signed as an edit, with its host\'s edits entry', claims[lost].get('edits'))

            def converged():
                for name in ('p1', 'p4', 'p1'):
                    hosts[name].run('access', 'sync', '--network', self.team)
                return self.policy('p1') == claims[w] and self.policy('p4') == claims[w]
            wait_for(converged, timeout=60, message='both on the winning claim (the loser re-applies, changing '
                     'nothing, so signs nothing)')
            need(self.rule_for('clash', serving=w) and not self.rule_for('clash', serving=lost),
                 'the policy binds the name to one host', self.cap_rules())

            def closed():
                view = self.hosts[lost].cli('access', 'sync', '--network', self.team, '--status')
                entry = next((e for e in view.get('edits', []) if e['seq'] == seq), None)
                return entry if entry and entry['state'] == 'closed' else None
            entry = wait_for(closed, timeout=30, message='the losing claim closed')
            need(entry['dropped'], 'the dropped claim is listed', entry)
            dropped = [i for i in self.items(lost, 'policy_edit_dropped') if i['subject'] == f'{self.team}/{seq}']
            need(dropped and 'clash' in dropped[0]['detail'] and
                 dropped[0]['command'] == f'peerspan access show --network {self.team}',
                 'item 17 names the dropped claim', self.items(lost, 'policy_edit_dropped'))
            conflict = self.items(lost, 'capability_name_conflict')
            need([i['subject'] for i in conflict] == ['clash'], 'item 15 on the losing host, subject the name',
                 conflict)
            command = conflict[0]['command']
            source = 'dup4/fx' if lost == 'p4' else 'cc/lit'
            # The exact form of "followed by" is not specified; both commands must appear, in that order.
            need(command.startswith('peerspan capability create ') and f'--from {source}' in command and
                 'peerspan capability remove clash' in command and
                 command.index('capability create') < command.index('capability remove'),
                 'item 15 command: capability create NEW_NAME --from AGENT/SERVER ..., then capability remove NAME',
                 command)
            need(not self.items(w, 'capability_name_conflict'), 'no item 15 on the winning host',
                 self.items(w, 'capability_name_conflict'))
        finally:
            for name in ('p1', 'p2', 'p3', 'p4'):
                h = hosts[name]
                if h.process is None or h.process.poll() is not None:
                    h.start()
            self.coord.start()
        # Discovery from p2 (trusted in team): the claimed copy is PERSON/CAPABILITY, the other HOST_ID/CAPABILITY.
        self.synced(self.version(), 'p2')
        status, body = self.hosts['p2'].call('GET', '/v1/discover?person=pat')
        found = {e['host_id']: e['address'] for e in (body or {}).get('capabilities', []) if e['capability'] == 'clash'}
        need(status == 200 and found == {ids[w]: 'pat/clash', ids[lost]: f'{ids[lost]}/clash'},
             'the claimed copy is addressed PERSON/CAPABILITY; the copy that lost its claim only HOST_ID/CAPABILITY',
             status, found)
        code, out, stderr = self.call('p2', 'pat/clash', 'echo', {'text': 'claimed'})
        need(code == 0 and dig(out, 'peer_host_id') == ids[w], 'PERSON/CAPABILITY resolves to the claimed copy',
             code, out)
        code, out, stderr = self.call('p2', f'{ids[lost]}/clash', 'echo', {'text': 'lost'})
        need(code == 0 and dig(out, 'peer_host_id') == ids[lost],
             'the losing copy still works through self access as HOST_ID/CAPABILITY', code, out)
        code, out, stderr = self.share('clash', '--with', 'quinn', '--yes', host=lost, expect=False)
        need(code != 0, 'the losing copy cannot be shared under its name', code)
        self.hosts[lost].run('capability', 'remove', 'clash', '--yes')
        need(not self.items(lost, 'capability_name_conflict'), 'item 15 clears once the local copy is removed')
        self.hosts[w].run('capability', 'remove', 'clash', '--yes')
        for name in ('p1', 'p4'):
            self.hosts[name].agent_socket = None
            self.restart(name)
        self.sync_all()
        return f'{w} won the claim'

    def check_tie_break(self):
        p1, p2 = self.hosts['p1'], self.hosts['p2']
        # Every other sibling of pat (p3, p4) is stopped too, with the coordinator: under direct propagation p1
        # pushes its version to each sibling, and "on start ... a host asks each sibling for its stored policy of
        # their person" (coordination contract, Direct propagation: Sync). A running p3 or p4 could relay p1's
        # version to p2 when it starts, and p2 would then rightly sign the next version instead of an equal one.
        relays = [self.hosts['p3'], self.hosts['p4']]
        self.coord.stop()
        try:
            for h in relays:
                h.stop()
            p2.stop()
            x = self.share('litcap', '--with', 'rhea', '--yes')[1]['policy']
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
            for h in relays:
                if h.process is None or h.process.poll() is not None:
                    h.start()
            self.coord.start()

    def watch_idle(self):
        time.sleep(540)
        self.idle_alive_at_9 = self.pid_alive()

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
        need(self.idle_started, 'setup: one call to the idle source', self.setup_notes)
        remaining = self.idle_started + 660 - time.time()
        if remaining > 0:
            time.sleep(remaining)
        need(getattr(self, 'idle_alive_at_9', None) is True, 'an instance with a call in the last 10 minutes keeps '
             'running (alive 9 minutes after its last call)', getattr(self, 'idle_alive_at_9', None))
        need(not self.pid_alive(), 'an instance with no calls for 10 minutes is stopped')

    def close(self):
        try:
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()


# --- once per run --------------------------------------------------------------------------------------------

def vector_policy(person_b64):
    """The contract's amended test vector inputs (2026-10-18), as v2 policy JSON: trusted hosts and edits given b
    then a, as specified (the statement sorts both)."""
    return {'format': 2, 'network_id': VECTOR_NETWORK, 'person_public_key': person_b64, 'version': 1,
            'issued_at': '2026-10-10T00:00:00Z', 'valid_until': '2026-10-17T00:00:00Z',
            'rules': [{'agent': 'reviewer', 'principals': [f'person:{SECOND_PERSON}', 'group:backend'],
                       'actions': ['message.append'], 'max_message_bytes': 65536, 'allow_disconnected': False},
                      {'agent': 'triage', 'principals': ['network'], 'actions': ['message.append'],
                       'max_message_bytes': 4096, 'allow_disconnected': True}],
            'capability_rules': [cap_rule('host_' + 'a' * 64, 'github-issues', [f'person:{SECOND_PERSON}'],
                                          65536, False, 100),
                                 cap_rule('host_' + 'b' * 64, 'docs', ['group:backend'], 4096, True, 10),
                                 cap_rule('host_' + 'a' * 64, 'notes', [], 65536, False, 100)],
            'trusted_hosts': ['host_' + 'b' * 64, 'host_' + 'a' * 64],
            'edits': [{'host': 'host_' + 'b' * 64, 'seq': 1}, {'host': 'host_' + 'a' * 64, 'seq': 3}]}


def check_vector(directory):
    """Build the v1 vector (self-check against the coordination contract's signature) and the capabilities
    contract's v2 vector from its inputs, sign the v2 statement, and verify it with ssh-keygen -Y verify."""
    from coord_move import sshsig
    from launch_service import Key
    person = Key(directory, base64.b64decode(VECTOR_PERSON_SEED))
    need(person.b64 == 'bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=', 'the vector person key')
    p = vector_policy(person.b64)
    v1 = {k: p[k] for k in ('network_id', 'person_public_key', 'version', 'issued_at', 'valid_until', 'rules')}
    need(sshsig(person, policy_lines_v1(v1)) ==
         'U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQI7LAL0jJtpQWmoMSHjIs49S3ZgRu1H8/I7LHRJ/N58B81ZTDeV854NluBUedCUW8GgzjOOTHLEM5pfE/iGPog8=',
         'self-check: the v1 policy test vector (coordination contract)')
    lines = policy_lines_v2(p)
    need(lines[16:22] == ['capability_rule', 'host_' + 'a' * 64, 'github-issues', f'person:{SECOND_PERSON}',
                          '65536 false 100', 'end'] and
         lines[28:34] == ['capability_rule', 'host_' + 'a' * 64, 'notes', '', '65536 false 100', 'end'] and
         lines[-2] == 'trusted host_' + 'a' * 64 + ' host_' + 'b' * 64 and
         lines[-1] == 'edits host_' + 'a' * 64 + ':3 host_' + 'b' * 64 + ':1' and len(lines) == 36,
         'capability rules are six lines (a claim\'s principals line empty); trusted hosts sorted; the final edits '
         'line sorted', lines)
    signature = sshsig(person, lines)
    ssh_verify(lines, signature, VECTOR_PERSON_SSH, directory)  # raises unless OpenSSH accepts it
    digest = hashlib.sha256('\n'.join(lines).encode()).hexdigest()
    # The vector is adopted only when both implementations produce the same statement; their statements come
    # from their own tests, not from this suite. The same encoding is checked live against each implementation in
    # the policy v2 section (the stored statement's sha256 of a policy with claims, trusted hosts, and edits).
    print('NOTE amended v2 test vector (built from the contract inputs; compare with both implementations):',
          json.dumps({'lines': lines, 'sha256': digest, 'signature': signature}), flush=True)
    return f'v1 vector reproduced; v2 statement sha256 {digest}; ssh-keygen -Y verify accepts its signature'


def check_migration(original, replacement, label):
    """Version 15 (the version 16 and 17 tables dropped) to the current version, and the next refused.

    The capabilities contract specifies 15 to 16 and says version 16 binaries reject 17; database version 17
    (coordination contract, Concurrent edits) has since been added, so current binaries migrate 15 to 17 (through
    16) and reject 18."""
    with tempfile.TemporaryDirectory(prefix='peerspan-capabilities-migration-') as directory:
        host = Host(original, Path(directory) / 'host')
        try:
            identity = host.start()
            agent = host.cli('agent', 'register', '--name', 'kept', '--owner', 'pat')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == CURRENT_VERSION, 'Database version 17', label)
            host.stop()
            connection = sqlite3.connect(host.state / 'host.db')
            try:
                for table in (*CAPABILITY_TABLES, *POLICY_EDIT_TABLES):
                    connection.execute(f'DROP TABLE {table}')
                connection.execute('PRAGMA user_version = 15')
                connection.commit()
            finally:
                connection.close()
            host.binary = str(replacement)
            need(host.start()['id'] == identity['id'], 'the identity survives migration')
            need(db_rows(host, 'PRAGMA user_version')[0][0] == CURRENT_VERSION, 'migrated to version 17')
            tables = {r[0] for r in db_rows(host, "SELECT name FROM sqlite_master WHERE type = 'table'")}
            need(set(CAPABILITY_TABLES) | set(POLICY_EDIT_TABLES) <= tables, 'versions 16 and 17 add their tables',
                 sorted(tables))
            need(host.cli('agent', 'inspect', agent['id']) == agent, 'existing state preserved')
            need(host.cli('calls', 'list') == [], 'no calls after migration')
            host.stop()
            connection = sqlite3.connect(host.state / 'host.db')
            connection.execute(f'PRAGMA user_version = {CURRENT_VERSION + 1}')
            connection.commit()
            connection.close()
            for binary in (original, replacement):
                result = subprocess.run([str(binary), '--state', str(host.state), 'run'], capture_output=True,
                                        timeout=10)
                need(result.returncode != 0, 'current binaries reject the next version', binary)
            need(db_rows(host, 'PRAGMA user_version')[0][0] == CURRENT_VERSION + 1, 'refused without changes')
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
    with tempfile.TemporaryDirectory(prefix='peerspan-capabilities-') as temporary:
        pairing = Pairing(label, cli_binary, daemon_binary, coord_binary, Path(temporary))
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [setup]: {detail}', flush=True)
            if pairing.setup_notes:
                print(f'NOTE {label} setup: ' + ' | '.join(pairing.setup_notes), flush=True)
        finally:
            try:
                pairing.close()
            except Exception as error:
                pairing.results.append(('shutdown', False, repr(error)))
        for note in pairing.notes:
            print(f'NOTE {label} (not counted): {note}', flush=True)
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
    parser.add_argument('--skip-migration', action='store_true', help='skip the version 15 to 17 migration checks')
    parser.add_argument('--vector-only', action='store_true', help='only build and verify the v2 test vector')
    args = parser.parse_args()
    for tool in ('ssh-agent', 'ssh-add', 'ssh-keygen', 'openssl'):
        if not shutil.which(tool):
            parser.error(f'{tool} is required')
    failures = []
    with tempfile.TemporaryDirectory(prefix='peerspan-capabilities-vector-') as directory:
        failures += once('policy v2 vector', check_vector, Path(directory))
    if args.vector_only:
        raise SystemExit(1 if failures else 0)
    set_probe(args.probe.resolve(strict=True))
    binaries = {'Go': args.go.resolve(), 'Rust': args.rust.resolve() if args.rust else None}
    pairings = args.pairing or [f'{c}/{d}' for c in binaries for d in binaries]
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        if cli not in binaries or daemon not in binaries:
            parser.error(f'unknown pairing {pairing}')
        if binaries[cli] is None or binaries[daemon] is None:
            parser.error(f'pairing {pairing} needs --rust')
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
