#!/usr/bin/env python3
"""Exercise the agent directory and addressing (milestone 7 slice 4) across CLI/daemon pairings.

Written from docs/launch-contract.md ("Slice 4: directory and addressing", and "Attach
launches" in slice 5) and the contracts it builds on, independently of both implementations. Runs every Go/Rust
CLI and daemon pairing (all hosts of a pairing run that pairing's daemon and are
driven by its CLI), with one Go coordinator per pairing, real ssh-agents, the
peer probe for the peer route, and the real Node MCP adapter. Each pairing
reports these sections separately:

- root help: the new command set, and the moved commands listed in `help advanced`
  (that they still run is checked where they are used);
- peer route: listings through self access, a person rule, a `*` rule, a group
  rule, `everyone`, an `agent:` principal (`from_agent`), and grants; agents with
  no authorization unlisted, and `[]`; blocks hiding policy and grant entries but
  not self; `connected` before and after an adapter connects; 403 for a host that
  is not a member, 404 for an unknown network;
- discovery: the `GET /v1/directory` shape and refresh, a new agent appearing
  after `agents --refresh`, a policy change reflected within 10 seconds without a
  refresh, and a stopped host keeping its agents with `state: error`;
- addresses: both forms, case-folded labels, `unknown`, `ambiguous` (a duplicate
  injected with `agent register` on two hosts of one person), `local`, and a host
  without a person addressed by host ID;
- sending: `send` and `task` by address under self, policy, and grant with the
  authorization each cites, `--grant` overriding the choice, `from_agent` rules,
  `not_authorized` persisting nothing, and the moved `message send`/`task submit`;
- agents and status: `agents --json` fields (with `endpoint`), and status item 12 for
  the injected duplicate;
- attach: default naming (revised 2026-10-16) and each suffix rule across two hosts of
  one person that share this machine's host name (`BASE-HOSTNAME`, `-PROJECT`, `-HHHH`
  growing to 32 digits, then `-N`), cutting to 64 characters with a long project and
  with a 64-character integration ID as BASE, the bare base name only by `--name`, and,
  when run as root, hosts of other host names in UTS namespaces of their own (one
  lowercased and sanitized, one whose short name is empty and becomes `host`, and `***`,
  only observed); `--name` taken refused with no registration, an unprofiled agent reused by
  `--name`, re-attach with `reused: true` and after revocation, `unchecked_hosts`
  with a sibling stopped, and `session start`/`doctor` without `--directory`
  (these attach with `--no-start`, which prints the output object on stdout);
- attach launch: a new session launched with the fixture harness (the output object
  on stderr, the harness replacing attach in the workspace with the arguments after
  `--`, its adapter connecting), re-attaching while it runs (`ready`, renewed) refused
  with exit 1 and no change after the wait, re-attaching right after it exited
  waiting out the lease and launching the same agent with a fresh session,
  re-attaching once `offline` making a new setup, a reused (`registered`) session launched, `--no-start` (the object
  on stdout, `next` naming `peerspan session start`, nothing connected), and an
  integration without launch printing its output as before;
- directory sessions: MCP `list_agents`, `send` and `delegate_task` by `to`
  through the real adapter, `send_status` reporting `to`; `no_directory` for
  sessions from `session setup` and `adapter create`; the rate cap with retries and
  route sends not counted; the adapter deadlines; setup validation;
- attach after expiry: a new credential for the same agent;
- retry after a label change: an uncertain send by address whose target host is
  then unbound from its person, retried automatically to the stored target;
- endpoints: `endpoint` in `agents --json` (and its readable layout) and
  `GET /adapter/v1/agents` for this host (advertised address, and first candidate), a
  peer dialed by its advertised address, a direct peer (two wildcard-bound hosts after
  path discovery), a relayed peer (a dead advertised address, with UDP between the two
  hosts dropped by iptables when run as root), and a stopped host whose map entry has no
  address or candidates. `path` is checked against `peer path`, whose relay/none choice
  belongs to the peer messaging contract.

Needs OpenSSH (ssh-agent, ssh-add, ssh-keygen), peerspan-peer-probe, and Node for
the MCP cases. Exits non-zero listing every failed section. Each host has its own
HOME and XDG_CONFIG_HOME, so nothing touches the real ~/.config/peerspan.
"""
import argparse
import ctypes
import http.client
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from agent_adapter import Channel, adapter_call, sql
from coordination import Coordinator, wait_for
from host_service import UnixHTTPConnection, die_with_parent, stop_all
from launch_onboarding import DEFAULT, Failure, OnboardHost, near, need, parse_time
from peer_messaging import available_port, fixture_context, request_id, set_probe, timestamp, wire
from persons import Agent, person_id, ssh_key
from tasks import task_id, tool

ROOT_COMMANDS = [
    'status', 'install', 'run',
    'network create', 'join', 'invite',
    'attach', 'agents', 'send', 'task',
    'allow', 'deny', 'block', 'unblock',
    'network list', 'network members',
    'access show',
    'session start', 'session doctor',
]
MOVED_COMMANDS = ['session setup', 'message send', 'task submit']
SELF_ACTIONS = {'message.append', 'task.submit', 'task.delegate'}
DEFAULT_ACTIONS = ['message.append', 'task.submit']
GIB = 1073741824
SELF_KEYS = {'kind', 'actions', 'max_message_bytes', 'max_artifact_bytes'}
POLICY_KEYS = {'kind', 'actions', 'max_message_bytes', 'max_artifact_bytes', 'from_agent'}
GRANT_KEYS = {'kind', 'grant_id', 'actions', 'max_message_bytes', 'max_artifact_bytes', 'expires_at', 'from_agent'}
# `channel` added by the live delivery contract, slice 1.
LISTING_KEYS = {'name', 'agent_id', 'connected', 'channel', 'authorizations'}
DIRECTORY_KEYS = {'network_id', 'refreshed_at', 'hosts', 'agents'}
DIRECTORY_HOST_KEYS = {'host_id', 'person_id', 'person_label', 'state', 'refreshed_at', 'error'}
DIRECTORY_AGENT_KEYS = {'address', 'host_id', 'person_id', 'person_label', 'name', 'agent_id', 'connected',
                        'channel', 'authorizations'}
AGENTS_KEYS = {'network_id', 'refreshed_at', 'reachable', 'mine', 'inbound', 'hosts'}
# `endpoint` added to reachable, mine, and GET /adapter/v1/agents on 2026-10-16.
REACHABLE_KEYS = {'address', 'host_id', 'agent_id', 'connected', 'host_state', 'actions', 'endpoint'}
MINE_KEYS = {'address', 'host_id', 'agent_id', 'connected', 'endpoint'}
INBOUND_KEYS = {'agent', 'principals', 'actions', 'max_artifact_bytes'}
ADAPTER_AGENT_KEYS = {'address', 'network_id', 'connected', 'actions', 'max_message_bytes', 'max_artifact_bytes',
                      'endpoint'}
ENDPOINT_KEYS = {'address', 'path'}
ENDPOINT_PATHS = {'direct', 'relay', 'none', 'local'}
ATTACH_KEYS = {'agent', 'session_id', 'adapter_id', 'profile', 'workspace', 'reused', 'unchecked_hosts', 'next'}
ADDRESSABLE = re.compile(r'[a-z0-9][a-z0-9._-]{0,63}')
# Hosts run on this machine and share its host name, unless a host runs in a UTS namespace of its own.
REAL_HOST_NAME = socket.gethostname()
SHORT_HOST = re.sub(r'[^a-z0-9._-]', '-', REAL_HOST_NAME.split('.')[0].lower()) or 'host'
# A 64-character integration ID (IDs are 1 to 64 lowercase letters, digits, and hyphens), as BASE.
LONG_ID = 'long-' + 'i' * 59
CLONE_NEWUTS = 0x04000000
NOT_ADDRESSABLE = 'Not Addressable'
PROFILE_FLAG = '--peerspan-fixture-profile'
# The launch target written into the fixture bundles in place of fixtures/harness/harness.py. As that one, it
# prints its literal arguments and cwd as one JSON line (plus its pid). Given PROFILE_FLAG DIR among its arguments,
# it then connects the adapter configured in that attach profile (consumer.json's socket and credential.json, as
# the fixture provider writes them), reports the outcome as a second JSON line, and renews the lease until its
# stdin closes.
LAUNCH_HARNESS = r'''"""A launch target that exposes literal arguments, cwd, and pid, and can connect its adapter."""
import http.client
import json
import os
import secrets
import select
import socket
import sys
import time


class Unix(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.unix_path)


def call(path, token, instance, method, url, body=None):
    connection = Unix(path)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        connection.request(method, url, payload, {"Authorization": "Bearer " + token, "X-Peerspan-Instance": instance,
                                                  "Content-Type": "application/json"})
        response = connection.getresponse()
        data = response.read()
        try:
            return response.status, json.loads(data)
        except ValueError:
            return response.status, data.decode(errors="replace")
    finally:
        connection.close()


args = sys.argv[1:]
print(json.dumps({"arguments": args, "cwd": os.getcwd(), "pid": os.getpid()}), flush=True)
if "--peerspan-fixture-profile" in args:
    report = {}
    try:
        profile = args[args.index("--peerspan-fixture-profile") + 1]
        with open(os.path.join(profile, "credential.json")) as f:
            credential = json.load(f)
        with open(os.path.join(profile, "consumer.json")) as f:
            path = json.load(f)["socket"]
        token, adapter = credential["token"], credential["adapter"]
        instance = "instance_" + secrets.token_hex(32)
        body = {"adapter_id": adapter["id"], "session_id": adapter["session_id"], "instance_id": instance}
        report["connect"], value = call(path, token, instance, "POST", "/adapter/v1/connect", body)
        if report["connect"] != 200:
            report["error"] = value
        else:
            report["session"], _ = call(path, token, instance, "GET", "/adapter/v1/session")
            # Live delivery readiness: verify the channel, as peerspan_ready would.
            call(path, token, instance, "POST", "/adapter/v1/ready", {"nonce": secrets.token_hex(16)})
        report.update(adapter_id=adapter["id"], session_id=adapter["session_id"])
    except Exception as error:
        report["error"] = repr(error)
    print(json.dumps(report), flush=True)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        ready, _, _ = select.select([0], [], [], 4)
        if ready and not os.read(0, 4096):
            break
        if report.get("connect") == 200:
            try:
                call(path, token, instance, "POST", "/adapter/v1/connect", body)
            except Exception:
                pass
'''


def sanitized(text):
    """A suffix as the contract makes it: lowercased, other characters as `-`."""
    return re.sub(r'[^a-z0-9._-]', '-', text.lower())


def short_host(host_name):
    """The suffix for a host name: its short name (up to the first dot), sanitized, or `host` if nothing is left."""
    return sanitized(host_name.split('.')[0]) or 'host'


def default_name(base, host, project=None, host_hex=None, n=None):
    """A default attach name as the Naming rules build it: BASE-HOSTNAME[-PROJECT][-HHHH][-N]. So that the whole
    fits in 64 characters, parts are cut from the end, each down to 1 character before the next is cut: the host
    name, then the project, then BASE; -HHHH and -N are never cut. host is already the sanitized short name."""
    parts = [base, host] + ([sanitized(project)] if project is not None else [])
    fixed = (f'-{host_hex}' if host_hex else '') + (f'-{n}' if n else '')
    for index in ([1, 2, 0] if project is not None else [1, 0]):
        excess = len('-'.join(parts)) + len(fixed) - 64
        if excess > 0:
            parts[index] = parts[index][:max(1, len(parts[index]) - excess)]
    return '-'.join(parts) + fixed


def endpoint_shaped(endpoint):
    """{address, path}: address an IP:PORT string or null, path direct, relay, none, or local."""
    return (isinstance(endpoint, dict) and set(endpoint) == ENDPOINT_KEYS and endpoint['path'] in ENDPOINT_PATHS
            and (endpoint['address'] is None
                 or (isinstance(endpoint['address'], str)
                     and re.fullmatch(r'\[?[0-9a-fA-F.:]+\]?:[0-9]+', endpoint['address']) is not None)))


def host_hex(host_id, digits=4):
    """The first hex digits of a host's ID after `host_`."""
    return host_id[len('host_'):][:digits]


def in_uts(host_name, then=None):
    """A preexec function: a UTS namespace of the process's own, with host_name as its host name (needs root)."""
    def preexec():
        if then:
            then()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.unshare(CLONE_NEWUTS) != 0:
            raise OSError(ctypes.get_errno(), 'unshare(CLONE_NEWUTS)')
        socket.sethostname(host_name)
    return preexec


def uts_available():
    try:
        out = subprocess.run(['hostname'], preexec_fn=in_uts('uts-probe'), capture_output=True, text=True, timeout=10)
        return out.returncode == 0 and out.stdout.strip() == 'uts-probe'
    except (OSError, subprocess.SubprocessError):
        return False


def by_name(listing):
    return {entry['name']: entry for entry in listing}


def kinds(entry):
    """Entry kinds in served order: self, then policy entries in rule order, then grants by grant ID."""
    return [a['kind'] for a in entry['authorizations']]


def canonical(authorizations):
    return sorted(json.dumps(a, sort_keys=True) for a in authorizations)


def directory_order(a):
    """Directory agent order: by address, then host ID; null addresses last, by host ID, then agent ID."""
    if a['address'] is None:
        return (1, '', a['host_id'], a['agent_id'])
    return (0, a['address'], a['host_id'], '')


def mentions(value, text):
    return text in json.dumps(value)


class DirectoryHost(OnboardHost):
    """An onboarding host whose CLI may run in a chosen directory with a longer timeout. With host_name set, its
    daemon and every CLI call run in UTS namespaces with that host name, as if on a machine of that name."""

    host_name = None

    def preexec(self, then=None):
        if self.host_name is None:
            return then
        return in_uts(self.host_name, then)

    def start(self, command='run'):
        if self.host_name is None:
            return super().start(command)
        self.process = subprocess.Popen([self.binary, '--state', str(self.state), command, *self.daemon_args],
                                        stdout=self.logs, stderr=self.logs, env=self.daemon_env(),
                                        preexec_fn=self.preexec(die_with_parent))
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.logs.seek(0)
                raise AssertionError(f'host exited at startup: {self.logs.read().decode()}')
            try:
                status, identity = self.call('GET', '/v1/host')
                if status == 200:
                    return identity
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)
        raise AssertionError('host did not become ready')

    def environment(self, sock=DEFAULT, env=None):
        e = dict(os.environ)
        e.pop('SSH_AUTH_SOCK', None)
        chosen = self.sock if sock is DEFAULT else sock
        if chosen:
            e['SSH_AUTH_SOCK'] = chosen
        e['USER'] = e['LOGNAME'] = 'not-the-login-name'
        e.update(self.private_env())
        e.update(env or {})
        return e

    def run(self, *args, sock=DEFAULT, env=None, argv=None, cwd=None, timeout=90):
        command = argv or [self.cli_binary, '--state', str(self.state), *args]
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              env=self.environment(sock, env), cwd=cwd, preexec_fn=self.preexec())

    def cli(self, *args, success=True, sock=DEFAULT, cwd=None):
        result = self.run(*args, sock=sock, cwd=cwd)
        assert (result.returncode == 0) == success, (self.cli_binary, args, result.returncode, result.stdout[-800:],
                                                     result.stderr[-800:])
        return json.loads(result.stdout) if success else result.stderr

    def call(self, method, path, body=None, raw=None):
        """As Host.call, but a body that is not JSON (such as a router's plain 404) comes back as text."""
        connection = UnixHTTPConnection(self.state / 'admin.sock', timeout=30)
        try:
            payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
            if isinstance(payload, str):
                payload = payload.encode()
            connection.request(method, path, payload, {'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = response.read()
            try:
                return response.status, json.loads(data)
            except json.JSONDecodeError:
                return response.status, data.decode(errors='replace')
        finally:
            connection.close()

    def directory(self, network=None, refresh=False):
        query = f'?network={network}' if network else ''
        if refresh:
            return self.call('POST', '/v1/directory/refresh' + query, {})
        return self.call('GET', '/v1/directory' + query)


def output_object(text):
    """The first JSON object in text that looks like attach's output, or None."""
    decoder = json.JSONDecoder()
    for start in [m.start() for m in re.finditer(r'\{', text)]:
        try:
            value, _ = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and 'agent' in value:
            return value
    return None


class Launch:
    """`attach` run in the background, as a terminal keeps it, with its stdout lines read as they come."""

    def __init__(self, host, args, cwd):
        command = [host.cli_binary, '--state', str(host.state), *args]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=host.environment(), cwd=cwd,
                                        preexec_fn=host.preexec())
        self.lines = queue.Queue()
        self.stdout = []
        self.stderr = b''
        threading.Thread(target=self._read, daemon=True).start()
        self._errors = threading.Thread(target=self._read_errors, daemon=True)
        self._errors.start()

    def _read(self):
        for line in self.process.stdout:
            self.stdout.append(line)
            self.lines.put(line)
        self.lines.put(None)

    def _read_errors(self):
        self.stderr = self.process.stderr.read()

    def line(self, timeout=90):
        """The next stdout line as JSON; fails when stdout closes or nothing comes in time."""
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            need(False, 'attach: no output from the launched harness in time', self.errors())
        if line is None:
            need(False, 'attach: stdout closed before the harness wrote its line', self.process.poll(), self.text(),
                 self.errors())
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            need(False, 'Before launching, attach prints its output object on stderr, so stdout belongs to the '
                 'harness', line.decode(errors='replace'))

    def finish(self, timeout=30):
        """Close the harness's stdin, so it exits, and collect the rest."""
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self._errors.join(timeout=10)
        return self.process.returncode

    def text(self):
        return b''.join(self.stdout).decode(errors='replace')

    def errors(self):
        return self.stderr.decode(errors='replace')[-1500:]

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


class Pairing:
    def __init__(self, label, cli_binary, daemon_binary, coord_binary, node, root):
        self.label, self.cli_binary, self.daemon, self.node, self.root = label, cli_binary, daemon_binary, node, root
        self.coord = Coordinator(coord_binary, root / 'coord')
        self.results = []
        self.hosts = {}
        self.agents = {}
        self.keys = {}
        self.channels = []
        self.launches = []
        self.cleanups = []
        self.script = Path(__file__).resolve().parents[1] / 'integrations/claude-channel/channel.mjs'

    # --- infrastructure -----------------------------------------------------------------------------------

    def host(self, name):
        h = DirectoryHost(self.daemon, self.cli_binary, self.root / name, self.root / f'user-{name}')
        self.hosts[name] = h
        return h

    def section(self, name, function):
        started = time.monotonic()
        self.soft = []
        try:
            notes = function() or ''
            need(not self.soft, 'shapes', *sorted(set(self.soft)))
        except Exception as error:  # report and continue with the next section
            detail = str(error) if isinstance(error, Failure) else traceback.format_exc(limit=4)
            self.results.append((name, False, detail))
            print(f'FAIL {self.label} [{name}] ({time.monotonic() - started:.0f}s): {detail}', flush=True)
            return False
        self.results.append((name, True, notes))
        print(f'PASS {self.label} [{name}] ({time.monotonic() - started:.0f}s){": " + notes if notes else ""}',
              flush=True)
        return True

    def coordinator_flags(self):
        return ('--coordinator', self.coord.address, '--coordinator-key', self.coord_key)

    def listing(self, receiver, caller, network=None):
        status, body = wire(self.hosts[receiver], fixture_context(self.hosts[caller]), 'GET',
                            f'/peer/v1/networks/{network or self.net}/agents')
        return status, body

    def listed(self, receiver, caller, rule):
        status, body = self.listing(receiver, caller)
        need(status == 200 and isinstance(body, list), f'{rule}: 200 with an array', status, body)
        for entry in body:
            need(LISTING_KEYS <= set(entry), 'Peer route: entries are {name, agent_id, connected, authorizations}',
                 entry)
            if set(entry) != LISTING_KEYS:
                self.soft.append(f'Peer route: entry keys {sorted(entry)}')
            for a in entry['authorizations']:
                expected = {'self': SELF_KEYS, 'policy': POLICY_KEYS, 'grant': GRANT_KEYS}.get(a.get('kind'))
                need(expected is not None and expected <= set(a), 'Peer route: authorization shapes', a)
                # Extra fields are reported at the end of the section, so the remaining cases still run.
                if set(a) != expected:
                    self.soft.append(f"Peer route: shapes are exact: {a['kind']} entry is {sorted(expected)}, "
                                     f"got {sorted(a)}")
            order = [{'self': 0, 'policy': 1, 'grant': 2}.get(a['kind'], 3) for a in entry['authorizations']]
            grants = [a['grant_id'] for a in entry['authorizations'] if a['kind'] == 'grant']
            need(order == sorted(order) and grants == sorted(grants),
                 'Peer route: entries are ordered self, then policy entries, then grants by grant ID', entry)
        need([(e['name'], e['agent_id']) for e in body] == sorted((e['name'], e['agent_id']) for e in body),
             'Peer route: sorted by name, then ID', [e['name'] for e in body])
        need(all(e['authorizations'] for e in body), 'Peer route: an agent with no authorizations is never listed',
             body)
        return by_name(body)

    def policy_version(self, host, person=None):
        status, body = host.call('GET', f'/v1/networks/{self.net}/policy?person={person or self.pat}')
        return body['version'] if status == 200 else 0

    def synced(self, version, *hosts, person=None):
        for h in hosts:
            wait_for(lambda: self.policy_version(h, person) >= version, timeout=40,
                     message=f'policy version {version} on {h.state.name}')

    def allow(self, *args):
        out = self.p1.cli('allow', *args, '--network', self.net)
        return out['policy']['version']

    def refresh(self, host, network=None):
        status, body = host.directory(network or self.net, refresh=True)
        need(status == 200, 'POST /v1/directory/refresh returns 200 with the directory', status, body)
        return body

    def outbound(self, host, peer, rid):
        status, body = host.call('GET', f'/v1/outbound/{peer}/{rid}')
        return body if status == 200 else None

    def settle_message(self, host, peer, record, timeout=40):
        if record.get('state') != 'unknown':
            return record
        rid = record['request']['request_id']

        def done():
            r = self.outbound(host, peer, rid)
            return r if r and r['state'] != 'unknown' else None
        return wait_for(done, timeout=timeout, message='message outcome')

    def settle_task(self, host, record, timeout=40):
        if record.get('submit_state') != 'unknown':
            return record
        peer, tid = record['peer_host_id'], record['request']['task_id']

        def done():
            status, r = host.call('GET', f'/v1/tasks/{peer}/{tid}')
            return r if status == 200 and r['submit_state'] != 'unknown' else None
        return wait_for(done, timeout=timeout, message='task outcome')

    def received(self, host, rid):
        """Whether a host has received the message with this request ID."""
        return any(m['request']['request_id'] == rid for m in host.cli('message', 'list', '--limit', '1000'))

    def send(self, host, target, text, *extra, peer):
        out = host.cli('send', target, text, *extra)
        need(isinstance(out, dict) and 'request' in out, 'send prints the outbound record', out)
        out = self.settle_message(host, peer, out)
        return out

    def task(self, host, target, text, *extra):
        out = host.cli('task', target, text, *extra)
        need(isinstance(out, dict) and 'request' in out and 'submit_state' in out,
             'task prints the local task record', out)
        return self.settle_task(host, out)

    def counts(self, host):
        return (sql(host, 'SELECT COUNT(*) FROM outbound_messages')[0][0],
                sql(host, 'SELECT COUNT(*) FROM outbound_tasks')[0][0])

    def attach(self, host, *args, success=True, cwd=None):
        """attach with --no-start, which stops after setup and prints the output object on stdout."""
        return host.cli('attach', *args, '--integrations', str(self.catalog), '--no-start', success=success, cwd=cwd)

    def profile_secret(self, out):
        path = Path(out['profile']) / 'credential.json'
        need(path.exists(), 'attach writes the profile with its credential', path)
        return json.loads(path.read_text())

    # --- sections ------------------------------------------------------------------------------------------

    def check_help(self):
        def help_of(*args):
            r = subprocess.run([self.cli_binary, *args], capture_output=True, text=True, timeout=10)
            need(r.returncode == 0, 'help exits 0', args, r.stderr)
            return r.stdout

        def commands(text):
            lines = text.splitlines()
            need('Commands:' in lines, 'help has a Commands: header (slice 1)', text)
            paths = []
            for line in lines[lines.index('Commands:') + 1:]:
                if not line.strip():
                    break
                paths.append(re.split(r' {2,}', line.strip())[0])
            return paths
        root = commands(help_of('--help'))
        need(root == ROOT_COMMANDS, 'Root help now lists, in order: status, install, run, network create, join, '
             'invite, attach, agents, send, task, allow, deny, block, unblock, network list, network members, '
             'access show, session start, session doctor', root)
        advanced = commands(help_of('help', 'advanced'))
        missing = [c for c in ROOT_COMMANDS + MOVED_COMMANDS if c not in advanced]
        need(not missing, 'session setup, message send, and task submit move to help advanced, unchanged', missing)
        for path in MOVED_COMMANDS + ['attach', 'agents', 'send', 'task']:
            need('--' in help_of(*path.split(), '--help'), 'each command keeps its own --help', path)

    def check_peer_route(self):
        rule = 'Peer route'
        ids, agent = self.ids, self.agent
        # Captured during setup, before any policy or grant existed.
        need(self.before == {'c1': (200, []), 'b1': (200, [])},
             f'{rule}: a caller with no authorizations receives []', self.before)

        def policy_entry(entry, actions=DEFAULT_ACTIONS, from_agent=None):
            need(kinds(entry) == ['policy'], f'{rule}: exactly one policy entry for {entry["name"]}', entry)
            [a] = entry['authorizations']
            need(sorted(a['actions']) == sorted(actions) and a['max_message_bytes'] == 65536
                 and a['max_artifact_bytes'] == 0 and a['from_agent'] == from_agent,
                 f'{rule}: the policy entry carries the rule\'s settings ({entry["name"]})', a, actions, from_agent)

        # Carol: a person rule, a group rule, everyone, an agent: principal, and grants.
        carol = self.listed('p1', 'c1', rule)
        expected = ['alpha', 'beta', 'delta', 'eps', 'gamma', 'notask']
        need(sorted(carol) == expected, f'{rule}: carol sees exactly the agents she is authorized for; '
             'agents with no authorization are unlisted', sorted(carol))
        for name in ('alpha', 'beta', 'gamma'):
            policy_entry(carol[name])
            need(carol[name]['agent_id'] == agent[name]['id'], f'{rule}: agent_id', carol[name])
        policy_entry(carol['notask'], ['message.append'])
        policy_entry(carol['delta'], from_agent=agent['corig']['id'])
        eps = carol['eps']
        need(kinds(eps) == ['grant'] * 3, f'{rule}: each unexpired, unrevoked grant to the caller host is listed', eps)
        for a in eps['authorizations']:
            g = self.grants[a['grant_id']]
            need(a['actions'] == [g['action']] and a['max_message_bytes'] == g['max_message_bytes']
                 and a['max_artifact_bytes'] == g.get('max_artifact_bytes', 0)
                 and parse_time(a['expires_at']) == parse_time(g['expires_at']) and a['from_agent'] is None,
                 f'{rule}: a grant entry carries the grant\'s action, bounds, expiry, and from_agent (its requester '
                 'agent, here none)', a, g)
        need(not any(e['connected'] for e in carol.values()), f'{rule}: connected false without a session', carol)

        # Bob: a `*` rule reaches only agents without named rules (gamma's named rule is everyone's, so bob, a
        # member, has it too); names as registered.
        bob = self.listed('p1', 'b1', rule)
        need(sorted(bob) == sorted([NOT_ADDRESSABLE, 'eps', 'gamma', 'omega']),
             f'{rule}: a * rule applies to agents without named rules', sorted(bob))
        for entry in bob.values():
            policy_entry(entry)

        # n1, without a person: everyone, and a grant.
        nobody = self.listed('p1', 'n1', rule)
        need(sorted(nobody) == ['gamma', 'omega'] and kinds(nobody['gamma']) == ['policy']
             and kinds(nobody['omega']) == ['grant'], f'{rule}: everyone and a grant for a host without a person',
             nobody)

        # p2: self access on every agent, with the self bounds.
        sibling = self.listed('p1', 'p2', rule)
        need(sorted(sibling) == sorted(self.p1_agents), f'{rule}: self access lists every agent', sorted(sibling))
        for entry in sibling.values():
            selfs = [a for a in entry['authorizations'] if a['kind'] == 'self']
            need(len(selfs) == 1 and set(selfs[0]['actions']) == SELF_ACTIONS
                 and selfs[0]['max_message_bytes'] == 65536 and selfs[0]['max_artifact_bytes'] == GIB,
                 f'{rule}: the self entry allows every action with its bounds', entry)
        need(kinds(sibling['gamma']) == ['self', 'policy'], f'{rule}: everyone also covers a sibling host',
             sibling['gamma'])

        # Blocks hide policy and grant entries, not self.
        for target, caller in ((ids['c1'], 'c1'), ('carol', 'c1'), (ids['n1'], 'n1')):
            self.p1.cli('block', target)
            try:
                status, body = self.listing('p1', caller)
                need((status, body) == (200, []), f'{rule}: blocks hide policy and grant entries (block {target})',
                     status, body)
            finally:
                self.p1.cli('unblock', target)
        self.p1.cli('block', ids['p2'])
        try:
            blocked = self.listed('p1', 'p2', rule)
            need(sorted(blocked) == sorted(self.p1_agents) and all(kinds(e) == ['self'] for e in blocked.values()),
                 f'{rule}: blocks apply to policies, not to self access', blocked)
        finally:
            self.p1.cli('unblock', ids['p2'])
        need(sorted(self.listed('p1', 'c1', rule)) == expected, f'{rule}: unblocking restores the listing')

        # connected: before and after an adapter connects.
        session = self.p1.cli('session', 'attach', '--agent', agent['omega']['id'], '--integration', 'test')
        secret = self.p1.cli('adapter', 'create', '--session', session['id'], '--expires-at', timestamp(1800))
        need(self.listed('p1', 'p2', rule)['omega']['connected'] is False,
             f'{rule}: connected false before the adapter connects')
        status, _ = adapter_call(self.p1, secret['token'], 'GET', '/adapter/v1/session')
        need(status == 200, 'adapter connects', status)
        # Live delivery readiness: connected also needs a verified channel.
        adapter_call(self.p1, secret['token'], 'POST', '/adapter/v1/ready', {'nonce': secrets.token_hex(16)})
        need(self.listed('p1', 'p2', rule)['omega']['connected'] is True,
             f'{rule}: connected true when an attached session\'s adapter holds a valid lease')

        # 403 for a caller that is not a member of the network; 404 for an unknown network.
        status, body = self.listing('p1', 'x')
        need(status == 403, f'{rule}: a caller that is not a current member of that network gets 403', status, body)
        status, body = self.listing('p1', 'x', self.other)
        need((status, body) == (200, []), f'{rule}: the same caller is served in its own network', status, body)
        status, body = self.listing('p1', 'c1', 'net_' + secrets.token_hex(16))
        need(status == 404, f'{rule}: a network the receiver does not belong to returns 404', status, body)

    def check_discovery(self):
        c1, p2 = self.hosts['c1'], self.hosts['p2']
        ids = self.ids
        directory = self.refresh(c1)
        need(set(directory) == DIRECTORY_KEYS and directory['network_id'] == self.net
             and directory['refreshed_at'], 'Discovery: {network_id, refreshed_at, hosts, agents}', directory)
        hosts = directory['hosts']
        need(all(set(h) == DIRECTORY_HOST_KEYS for h in hosts), 'Discovery: host entries', hosts)
        need([h['host_id'] for h in hosts] == sorted(h['host_id'] for h in hosts), 'hosts are sorted by host ID', hosts)
        others = sorted(ids[n] for n in self.members if n != 'c1')
        need(sorted(h['host_id'] for h in hosts) == others,
             'Hosts queried: every current, unrevoked member other than itself', hosts, others)
        need(all(h['state'] == 'ok' and h['refreshed_at'] and h['error'] is None for h in hosts),
             'Discovery: every running host answered (state ok)', hosts)
        host = {h['host_id']: h for h in hosts}
        need(host[ids['p1']]['person_id'] == self.pat and host[ids['p1']]['person_label'] == 'pat'
             and host[ids['n1']]['person_id'] is None and host[ids['n1']]['person_label'] is None,
             'Discovery: hosts show their bound person, or null', host)
        agents = directory['agents']
        need(all(set(a) == DIRECTORY_AGENT_KEYS for a in agents), 'Discovery: agent entries', agents)
        need(agents == sorted(agents, key=directory_order),
             'agents are sorted by address, then host ID, with null addresses last', agents)
        entries = {a['address']: a for a in agents}
        alpha = entries.get('pat/alpha')
        need(alpha and alpha['host_id'] == ids['p1'] and alpha['person_id'] == self.pat
             and alpha['person_label'] == 'pat' and alpha['name'] == 'alpha'
             and alpha['agent_id'] == self.agent['alpha']['id'], 'Discovery: address PERSON/AGENT', entries)
        served = self.listed('p1', 'c1', 'Peer route')
        for name in served:
            entry = entries.get(f'pat/{name}')
            need(entry and entry['authorizations'] == served[name]['authorizations'],
                 'Discovery: authorizations as served by the peer', name, entry, served[name])
        nag = entries.get(f"{ids['n1']}/nagent")
        need(nag and nag['person_id'] is None and nag['person_label'] is None,
             'address is HOST_ID/AGENT when the host has no bound person', entries)
        need(not any(a['host_id'] == ids['c1'] for a in agents), 'the directory holds other hosts only', agents)

        # The bound person's own view: names that are not addressable have a null address.
        status, mirror = self.hosts['b1'].directory(self.net, refresh=True)
        odd = [a for a in mirror.get('agents', []) if a['name'] == NOT_ADDRESSABLE]
        need(status == 200 and len(odd) == 1 and odd[0]['address'] is None,
             'address is null for names that are not addressable (as registered in the peer response)', mirror)
        need(mirror['agents'] == sorted(mirror['agents'], key=directory_order) and mirror['agents'][-1] is odd[0],
             'null addresses sort last', [a['address'] for a in mirror['agents']])

        # Network defaulting on the API: c1 has one network; p1 has two.
        status, single = c1.directory()
        need(status == 200 and single.get('network_id') == self.net,
             'GET /v1/directory defaults to the only network', status, single)
        status, several = self.p1.directory()
        need(status == 400 and mentions(several, self.net) and mentions(several, self.other),
             'GET /v1/directory without network on a host in several networks is 400, listing them', status, several)
        status, unknown = c1.directory('net_' + secrets.token_hex(32))
        need(status == 404, 'GET /v1/directory for an unknown network is 404', status, unknown)

        self.agent['fresh'] = self.p1.cli('agent', 'register', '--name', 'fresh', '--owner', 'pat')
        # A policy change is reflected within 10 seconds, without a refresh.
        version = self.allow('carol', '--agent', 'fresh')
        started = time.monotonic()
        stored = seen = None
        while time.monotonic() - started < 60 and seen is None:
            if stored is None and self.policy_version(c1) >= version:
                stored = time.monotonic()
            status, view = c1.directory(self.net)
            if status == 200 and any(a['address'] == 'pat/fresh' and a['authorizations'] for a in view['agents']):
                seen = time.monotonic()
            time.sleep(0.2)
        need(seen is not None, 'Discovery: a policy change is reflected without a refresh')
        stored = stored or seen
        need(seen - stored <= 12, 'Discovery: within 10 seconds of a change to any stored policy',
             f'stored after {stored - started:.1f}s, reflected after {seen - started:.1f}s')
        notes = f'policy reflected {seen - stored:.1f}s after it was stored'

        # A stopped host keeps its previous agents, with state error.
        before = {h['host_id']: h for h in self.refresh(c1)['hosts']}[ids['n1']]
        need(before['state'] == 'ok', 'n1 answered before it stopped', before)
        n1 = self.hosts['n1']
        n1.stop()
        stopped_at = time.time()
        try:
            after = self.refresh(c1)
            entry = {h['host_id']: h for h in after['hosts']}[ids['n1']]
            need(entry['state'] == 'error' and isinstance(entry['error'], str) and entry['error'],
                 'Failures: a host that fails is marked with the error (state error)', entry)
            need(entry['refreshed_at'] and parse_time(entry['refreshed_at']).timestamp() <= stopped_at + 1
                 and parse_time(entry['refreshed_at']) >= parse_time(before['refreshed_at']),
                 'Failures: marked with the time of the last success', entry, before)
            need(any(a['address'] == f"{ids['n1']}/nagent" for a in after['agents']),
                 'Failures: a host that fails keeps its previous agents', after['agents'])
        finally:
            n1.start()

        # A new agent appears after `agents --refresh`.
        self.agent['later'] = self.p1.cli('agent', 'register', '--name', 'later', '--owner', 'pat')
        out = p2.cli('agents', '--refresh', '--json', '--network', self.net)
        mine = {m['address']: m for m in out.get('mine', [])}
        reach = {r['address']: r for r in out.get('reachable', [])}
        need('pat/later' in mine and mine['pat/later']['agent_id'] == self.agent['later']['id']
             and mine['pat/later']['host_id'] == ids['p1'], 'Discovery: a new agent appears after --refresh (mine)',
             out.get('mine'))
        need('pat/later' in reach and SELF_ACTIONS <= set(reach['pat/later']['actions']),
             'Discovery: a new agent appears after --refresh (reachable, through self access)', out.get('reachable'))

        return notes

    def check_addresses(self):
        c1, p1, ids = self.hosts['c1'], self.p1, self.ids
        before = self.counts(c1)

        def refused(host, to, status, code, **extra):
            body = {'to': to, 'content': 'refused', 'deadline': timestamp(600), 'request_id': request_id(), **extra}
            got, value = host.call('POST', '/v1/outbound', body)
            need(got == status and isinstance(value, dict) and value.get('code') == code
                 and {'code', 'error', 'matches'} <= set(value),
                 f'Resolution failures return {status} ({code}) with {{code, error, matches}}', to, got, value)
            return value

        # On the owner API first. unknown:
        for to in ('pat/nosuch', 'nobody/alpha', f"host_{'0' * 64}/alpha"):
            value = refused(c1, to, 404, 'unknown')
            need(value['matches'] == [], 'matches is empty unless ambiguous', value)
        got, value = c1.call('POST', '/v1/tasks', {'to': 'pat/nosuch', 'input': 'x'})
        need(got == 404 and isinstance(value, dict) and value.get('code') == 'unknown',
             'POST /v1/tasks accepts to, and resolves it', got, value)

        # ambiguous: a duplicate injected with agent register on two hosts of pat.
        directory = self.refresh(c1)
        dups = {a['host_id']: a['address'] for a in directory['agents'] if a['name'] == 'dup'}
        need(dups == {ids['p1']: f"{ids['p1']}/dup", ids['p2']: f"{ids['p2']}/dup"},
             'address is HOST_ID/AGENT when the name is duplicated within that person', dups)
        value = refused(c1, 'pat/dup', 409, 'ambiguous')
        want = sorted([{'address': f"{ids[h]}/dup", 'network_id': self.net} for h in ('p1', 'p2')],
                      key=lambda m: (m['network_id'], m['address']))
        need(value['matches'] == want, 'ambiguous: matches lists {address, network_id} objects, sorted by network ID, '
             'then address', value, want)

        # local
        for to in ('pat/alpha', f"{ids['p1']}/alpha"):
            refused(p1, to, 400, 'local', network=self.net)

        # Both forms at once.
        got, value = c1.call('POST', '/v1/outbound', {'to': 'pat/alpha', 'peer_host_id': ids['p1'],
                                                      'target_agent_id': self.agent['alpha']['id'],
                                                      'content': 'both', 'deadline': timestamp(600)})
        need(got == 400, 'POST /v1/outbound: giving both forms is 400', got, value)
        got, value = c1.call('POST', '/v1/tasks', {'to': 'pat/alpha', 'peer_host_id': ids['p1'],
                                                   'target_agent_id': self.agent['alpha']['id'], 'input': 'both'})
        need(got == 400, 'POST /v1/tasks: giving both forms is 400', got, value)
        need(self.counts(c1) == before, 'The daemon resolves the address before persisting anything',
             before, self.counts(c1))

        # An accepted send on the API, with network.
        rid = request_id()
        got, out = c1.call('POST', '/v1/outbound', {'to': 'pat/alpha', 'network': self.net, 'content': 'api',
                                                    'deadline': timestamp(600), 'request_id': rid})
        need(got == 200, 'POST /v1/outbound accepts to with optional network', got, out)
        out = self.settle_message(c1, ids['p1'], out)
        need(out['state'] == 'accepted' and out['request']['target_agent_id'] == self.agent['alpha']['id']
             and self.received(p1, rid), 'Addresses: PERSON/AGENT reaches that agent (API)', out)
        need(out.get('to') == 'pat/alpha', 'Persistence: the record shows to as given', out)

        # The CLI: both forms, and a case-folded label.
        out = self.send(c1, 'pat/alpha', 'by label', peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request']['target_agent_id'] == self.agent['alpha']['id']
             and self.received(p1, out['request']['request_id']), 'Addresses: PERSON/AGENT (send)', out)
        need(out.get('to') == 'pat/alpha', 'Persistence: the record shows to as given (send)', out)
        out = self.send(c1, f"{ids['p1']}/alpha", 'by host', peer=ids['p1'])
        need(out['state'] == 'accepted' and self.received(p1, out['request']['request_id'])
             and out['request']['target_agent_id'] == self.agent['alpha']['id'], 'Addresses: HOST_ID/AGENT', out)
        for label in ('PAT', 'Pat'):
            out = self.send(c1, f'{label}/alpha', 'folded', peer=ids['p1'])
            need(out['state'] == 'accepted' and self.received(p1, out['request']['request_id'])
                 and out.get('to') == f'{label}/alpha',
                 'Addresses: person labels compared with ASCII case folded; to shown as given', out)
        result = c1.run('send', 'pat/nosuch', 'nothing')
        need(result.returncode != 0, 'send to an unknown address fails', result.stdout)
        result = c1.run('send', 'pat/dup', 'which one')
        need(result.returncode != 0 and all(f"{ids[h]}/dup" in result.stderr for h in ('p1', 'p2'))
             and self.net in result.stderr, 'ambiguous: the error lists each match as HOST_ID/AGENT with its network',
             result.stderr)
        out = self.send(c1, f"{ids['p1']}/dup", 'picked', peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request']['target_agent_id'] == self.agent['dup1']['id'],
             'HOST_ID/AGENT picks one agent of a duplicate pair', out)
        need(p1.run('send', 'pat/alpha', 'to myself', '--network', self.net).returncode != 0,
             'send to a local agent fails')

        # A host without a person, by host ID; with --network.
        out = self.send(c1, f"{ids['n1']}/nagent", 'no person', '--network', self.net, peer=ids['n1'])
        need(out['state'] == 'accepted' and out['request'].get('grant_id') == self.n1_grant['id']
             and self.received(self.hosts['n1'], out['request']['request_id']),
             'Addresses: a host without a bound person, addressed by host ID', out)
        # Refused sends persisted nothing: the seven accepted sends were all that was stored.
        after = self.counts(c1)
        need(after == (before[0] + 7, before[1]), 'The daemon resolves the address before persisting anything',
             before, after)

    def check_sending(self):
        c1, p1, p2, ids = self.hosts['c1'], self.p1, self.hosts['p2'], self.ids
        cite = {'person_id': self.pat}

        # not_authorized, persisting nothing.
        before = self.counts(c1)
        status, value = c1.call('POST', '/v1/tasks', {'to': 'pat/notask', 'input': 'not allowed'})
        need(status == 403 and isinstance(value, dict) and value.get('code') == 'not_authorized',
             'When none allows the action: 403 not_authorized (task to a message-only rule)', status, value)
        status, value = c1.call('POST', '/v1/outbound', {'to': 'pat/delta', 'content': 'not from corig',
                                                         'deadline': timestamp(600), 'request_id': request_id()})
        need(status == 403 and isinstance(value, dict) and value.get('code') == 'not_authorized',
             'When none allows the action: 403 (a from_agent entry for another agent)', status, value)
        need(self.counts(c1) == before, 'not_authorized persists nothing', before, self.counts(c1))

        # Self.
        out = self.send(p2, 'pat/alpha', 'from a sibling', '--network', self.net, peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request'].get('self') == cite
             and out['request'].get('grant_id') is None and out['request'].get('policy') is None,
             'Choosing an authorization: self access first, cited as self (send)', out)
        path = self.root / 'input.txt'
        path.write_bytes(b'directory input ' * 32)
        t = self.task(p2, 'pat/alpha', 'self task', '--network', self.net, '--file', str(path))
        need(t['submit_state'] == 'accepted' and t['request'].get('self') == cite and t['peer_host_id'] == ids['p1']
             and t['request']['target_agent_id'] == self.agent['alpha']['id'],
             'Choosing an authorization: self (task)', t)
        need(len(t['request'].get('artifacts') or []) == 1, 'task --file is --artifact', t['request'])
        need(t.get('to') == 'pat/alpha', 'Persistence: the task record shows to as given', t)

        # Policy.
        out = self.send(c1, 'pat/alpha', 'by policy', peer=ids['p1'])
        need(out['state'] == 'accepted' and (out['request'].get('policy') or {}).get('person_id') == self.pat
             and out['request'].get('grant_id') is None and out['request'].get('self') is None,
             'Choosing an authorization: a policy entry, cited as the target owner\'s policy (send)', out)
        t = self.task(c1, 'pat/alpha', 'policy task')
        need(t['submit_state'] == 'accepted' and (t['request'].get('policy') or {}).get('person_id') == self.pat
             and t['request'].get('grant_id') is None, 'Choosing an authorization: policy (task)', t)
        # A from_agent entry applies only to requests from that agent.
        out = self.send(c1, 'pat/delta', 'from corig', '--from-agent', self.agent['corig']['id'], peer=ids['p1'])
        need(out['state'] == 'accepted' and (out['request'].get('policy') or {}).get('person_id') == self.pat,
             'a policy entry whose from_agent is the origin agent', out)

        # Grant: the one with the latest expires_at.
        out = self.send(c1, 'pat/eps', 'by grant', peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request'].get('grant_id') == self.eps_late['id'],
             'Choosing an authorization: the grant with the latest expires_at, cited by its ID (send)',
             out, self.eps_late['id'])
        t = self.task(c1, 'pat/eps', 'grant task')
        need(t['submit_state'] == 'accepted' and t['request'].get('grant_id') == self.eps_task['id'],
             'Choosing an authorization: a grant that allows task.submit (task)', t)

        # --grant overrides the choice.
        g = p1.cli('grant', 'create', '--peer', ids['c1'], '--agent', self.agent['alpha']['id'], '--expires-in', '2h',
                   '--allow-disconnected')
        out = self.send(c1, 'pat/alpha', 'explicit grant', '--grant', g['id'], peer=ids['p1'])
        need(out['state'] == 'accepted' and out['request'].get('grant_id') == g['id']
             and out['request'].get('policy') is None, 'An explicit grant_id (owner --grant) overrides the choice', out)

        before = self.counts(c1)
        need(c1.run('task', 'pat/notask', 'not allowed').returncode != 0, 'task refused by not_authorized fails')
        need(self.counts(c1) == before, 'not_authorized persists nothing (CLI)', before, self.counts(c1))

        # The moved commands still run.
        out = c1.cli('message', 'send', '--peer', ids['p1'], '--agent', self.agent['alpha']['id'], '--content',
                     'moved command')
        out = self.settle_message(c1, ids['p1'], out)
        need(out['state'] == 'accepted', 'message send still runs', out)
        need('to' not in out, 'Records not sent by address have no to key (outbound)', {'to': out.get('to')})
        t = c1.cli('task', 'submit', '--peer', ids['p1'], '--agent', self.agent['alpha']['id'], '--input', 'moved')
        t = self.settle_task(c1, t)
        need(t['submit_state'] == 'accepted', 'task submit still runs', t)
        need('to' not in t, 'Records not sent by address have no to key (task)', {'to': t.get('to')})

    def check_agents_and_status(self):
        c1, p1, p2, ids = self.hosts['c1'], self.p1, self.hosts['p2'], self.ids
        for h in (c1, p1, p2):
            self.refresh(h)
        # Item 12, for the duplicate injected on p1 and p2.
        for h in (p1, p2):
            def conflict():
                self.refresh(h, self.net)
                status, value = h.call('GET', '/v1/status')
                items = [i for i in value.get('attention', []) if i['kind'] == 'agent_name_conflict']
                return items or None
            try:
                items = wait_for(conflict, timeout=20, message='agent_name_conflict')
            except AssertionError:
                raise Failure(f'Status item 12: agent_name_conflict on {h.state.name} for a duplicate name of this '
                              'host\'s person')
            need([i['subject'] for i in items] == [f'{self.net}/dup'], 'item 12: subject NETWORK/NAME', items)
            need('attach' in items[0]['command'] and '--name' in items[0]['command'],
                 'item 12: command peerspan attach HARNESS --name NEW', items)
        status, value = c1.call('GET', '/v1/status')
        need(not [i for i in value.get('attention', []) if i['kind'] == 'agent_name_conflict'],
             'item 12 only on a host that has one of them', value.get('attention'))

        out = c1.cli('agents', '--json')
        need(set(out) == AGENTS_KEYS and out['network_id'] == self.net, 'agents --json prints {network_id, '
             'refreshed_at, reachable, mine, inbound, hosts}', out)
        need(all(set(r) == REACHABLE_KEYS for r in out['reachable']), 'reachable uses {address, host_id, agent_id, '
             'connected, host_state, actions, endpoint}', out['reachable'])
        need(all(endpoint_shaped(r['endpoint']) for r in out['reachable'] + out['mine']),
             'endpoint is {address, path}, address an IP:PORT string or null', out['reachable'], out['mine'])
        need(all(r['address'] and ADDRESSABLE.fullmatch(r['address'].split('/')[-1]) for r in out['reachable']),
             'reachable lists addressable agents', out['reachable'])
        reach = {r['address']: r for r in out['reachable']}
        alpha = reach.get('pat/alpha')
        need(alpha and alpha['host_id'] == ids['p1'] and alpha['agent_id'] == self.agent['alpha']['id']
             and alpha['host_state'] == 'ok' and set(DEFAULT_ACTIONS) <= set(alpha['actions']),
             'reachable: address, actions, connection, and whether its host answered', alpha)
        directory = c1.directory(self.net)[1]
        need([(h['host_id'], h['state']) for h in out['hosts']] == [(h['host_id'], h['state'])
                                                                     for h in directory['hosts']]
             and all(set(h) == DIRECTORY_HOST_KEYS for h in out['hosts']),
             'hosts is the directory\'s hosts', out['hosts'], directory['hosts'])
        need(all(set(m) == MINE_KEYS for m in out['mine']), 'mine uses {address, host_id, agent_id, connected, '
             'endpoint}', out['mine'])
        need({m['agent_id'] for m in out['mine']} >= {self.agent['corig']['id']}, 'mine: this host\'s agents',
             out['mine'])
        readable = c1.run('agents')
        need(readable.returncode == 0 and 'pat/alpha' in readable.stdout, 'agents prints the reachable addresses',
             readable.stdout)

        # The person's own hosts: mine spans this host and the directory; inbound mirrors the policy.
        mine = p2.cli('agents', '--json', '--network', self.net)
        addresses = {m['address'] for m in mine['mine']}
        need({'pat/alpha', 'pat/gamma'} <= addresses and f"{ids['p2']}/dup" in addresses,
             'mine: this person\'s agents on this host and in the directory', sorted(a for a in addresses if a))
        inbound = p1.cli('agents', '--json', '--network', self.net)['inbound']
        need(all(set(i) == INBOUND_KEYS for i in inbound), 'inbound uses {agent, principals, actions, '
             'max_artifact_bytes}', inbound)
        status, policy = p1.call('GET', f'/v1/networks/{self.net}/policy?person={self.pat}')
        expected = sorted(json.dumps([r['agent'], sorted(r['principals']), sorted(r['actions']),
                                      r.get('max_artifact_bytes', 0)]) for r in policy['rules'])
        got = sorted(json.dumps([i['agent'], sorted(i['principals']), sorted(i['actions']), i['max_artifact_bytes']])
                     for i in inbound)
        need(got == expected, 'inbound: one entry per rule of the stored policy, principals in policy form',
             got, expected)

    def check_attach(self):
        a1, a2, ids = self.hosts['a1'], self.hosts['a2'], self.ids
        ws = self.root / 'ws'

        def project(*parts):
            path = ws.joinpath(*parts)
            path.mkdir(parents=True, exist_ok=True)
            return path

        def attached(out, name, host, workspace, rule):
            need(set(out) == ATTACH_KEYS, 'attach prints {agent, session_id, adapter_id, profile, workspace, reused, '
                 'unchecked_hosts, next}', out)
            need(out['agent']['name'] == name, f'{rule}: agent name {name}', out['agent'])
            need(out['agent']['address'] == f'ana/{name}', 'agent.address is PERSON/NAME', out['agent'])
            need(Path(out['workspace']) == workspace.resolve(), 'the profile records the project\'s real path',
                 out['workspace'], workspace)
            want = host.config / 'peerspan' / 'sessions' / ids[host.state.name] / name
            need(Path(out['profile']).resolve() == want.resolve(),
                 'Profiles live in $XDG_CONFIG_HOME/peerspan/sessions/HOST_ID/AGENT_NAME/', out['profile'], want)
            return out

        # The expiring attach first, so that its minute passes during the rest.
        expiring = project('expiring')
        out = self.attach(a1, 'file-fixture', '--name', 'expiring', '--directory', str(expiring), '--expires-in', '1m')
        self.expiring = (expiring, out)

        # 1. BASE-HOSTNAME, for `claude` meaning claude-code; the bare base name is never a default.
        h = SHORT_HOST
        hex_a2 = ids['a2'][len('host_'):]
        w1 = project('app')
        out = attached(self.attach(a1, 'claude', '--directory', str(w1)), default_name('claude', h), a1, w1,
                       'Naming: BASE-HOSTNAME first (claude for claude-code), with this machine\'s short host name')
        need(out['reused'] is False and out['unchecked_hosts'] == [], 'a fresh attach', out)
        need(mentions(out['next'], 'session start'), 'next is peerspan session start for launch-capable integrations',
             out)
        registered = a1.cli('agent', 'inspect', out['agent']['id'])
        need(registered['owner'] == 'ana', 'Registering: owner is this host\'s bound person\'s label', registered)
        record = a1.cli('adapter', 'inspect', out['adapter_id'])
        need(record.get('directory') is True and record.get('max_sends_per_hour') == 100
             and record.get('renewable') is True, 'Setup: directory access, max_sends_per_hour 100, a renewable '
             'credential', record)
        session = a1.cli('session', 'inspect', out['session_id'])
        need(session['integration'] == 'claude-code' and session['agent_id'] == out['agent']['id'],
             'HARNESS claude means claude-code', session)
        self.w1 = (w1, out)

        # 2. BASE-HOSTNAME-PROJECT when BASE-HOSTNAME is used on this host, and -2 after it.
        w2 = project('proj-two')
        attached(self.attach(a1, 'claude', '--directory', str(w2)), default_name('claude', h, 'proj-two'), a1, w2,
                 'Naming: BASE-HOSTNAME-PROJECT when BASE-HOSTNAME is used on this host')
        w2b = project('other', 'proj-two')
        # -N goes on the last candidate that applied (settled with the owner).
        attached(self.attach(a1, 'claude', '--directory', str(w2b)), default_name('claude', h, 'proj-two', n=2), a1,
                 w2b, 'Naming: then -2 appended to the last candidate that applied')
        odd = project('My Proj!')
        attached(self.attach(a1, 'claude', '--directory', str(odd)), default_name('claude', h, 'My Proj!'), a1, odd,
                 'Naming: suffixes lowercased, other characters become -')
        long = project('p' * 80)
        out = self.attach(a1, 'claude', '--directory', str(long))
        want = default_name('claude', h, 'p' * 80)
        need(len(want) == 64 and out['agent']['name'] == want, 'Naming: the host name part is cut first (down to 1 '
             'character), then the project, so that the name fits in 64 characters', out['agent'], want)
        again = self.attach(a1, 'claude', '--directory', str(project('again', 'p' * 80)))
        want = default_name('claude', h, 'p' * 80, n=2)
        need(len(want) == 64 and again['agent']['name'] == want,
             'Naming: the whole name, including -N, fits in 64 characters; -N is never cut', again['agent'], want)

        # 3. BASE-HOSTNAME-HHHH when BASE-HOSTNAME is used only on another host: a2 runs on this machine too, so the
        # two hosts share a host name. Then 6, 8, and so on digits while that is taken, up to 32, then -2.
        w5 = project('second-machine')
        attached(self.attach(a2, 'claude', '--directory', str(w5)), default_name('claude', h, host_hex=hex_a2[:4]),
                 a2, w5, 'Naming: BASE-HOSTNAME-HHHH (the first 4 hex digits of this host\'s ID after host_) when '
                 'BASE-HOSTNAME is used only on another host')
        for digits in range(6, 33, 2):
            w = project(f'second-{digits}')
            attached(self.attach(a2, 'claude', '--directory', str(w)),
                     default_name('claude', h, host_hex=hex_a2[:digits]), a2, w,
                     f'Naming: HHHH grows to {digits} digits while the shorter one is taken')
        w6 = project('second-again')
        attached(self.attach(a2, 'claude', '--directory', str(w6)),
                 default_name('claude', h, host_hex=hex_a2[:32], n=2), a2, w6,
                 'Naming: HHHH grows to at most 32 digits, then -2 is appended')
        wf = project('fixture')
        attached(self.attach(a2, 'file-fixture', '--directory', str(wf)), default_name('file-fixture', h), a2, wf,
                 'Naming: the base name is otherwise the integration ID')

        # A 64-character integration ID as BASE: the host name is cut to 1 character, then the project, then BASE.
        wl1 = project('long-id')
        want = default_name(LONG_ID, h)
        need(want == LONG_ID[:62] + '-' + h[0], 'the expected cut (suite self-check)', want)
        attached(self.attach(a1, LONG_ID, '--directory', str(wl1)), want, a1, wl1,
                 'Naming: a 64-character integration ID as BASE is cut so the default name fits')
        wl2 = project('second-long')
        want = default_name(LONG_ID, h, 'second-long')
        need(want == LONG_ID[:60] + '-' + h[0] + '-s', 'the expected cut (suite self-check)', want)
        attached(self.attach(a1, LONG_ID, '--directory', str(wl2)), want, a1, wl2,
                 'Naming: BASE-HOSTNAME-PROJECT with a 64-character BASE: the host name and project cut to 1 '
                 'character, then BASE')
        wl3 = project('long-id-a2')
        want = default_name(LONG_ID, h, host_hex=hex_a2[:4])
        need(want == LONG_ID[:57] + '-' + h[0] + '-' + hex_a2[:4], 'the expected cut (suite self-check)', want)
        attached(self.attach(a2, LONG_ID, '--directory', str(wl3)), want, a2, wl3,
                 'Naming: BASE-HOSTNAME-HHHH with a 64-character BASE: -HHHH is never cut')
        notes = [f'host name {h!r}, a2 suffix {hex_a2[:4]}']

        # Hosts of ana on machines with other host names (each in a UTS namespace of its own; needs root).
        if not self.named_hosts:
            notes.append('SKIPPED (needs root for UTS namespaces): hosts with other host names, including one that '
                         'leaves nothing')
        for name, host_name in self.named_hosts.items():
            w = project(f'on-{name}')
            out = self.attach(self.hosts[name], 'claude', '--directory', str(w))
            if host_name == '***':
                # Ambiguous in the contract: `***` becomes `---` (characters outside the addressable set become
                # `-`), which is not nothing, so whether it is replaced by `host` is unsettled. Observed only.
                notes.append(f'host name {host_name!r} gave {out["agent"]["name"]!r}')
                need(ADDRESSABLE.fullmatch(out['agent']['name']) and out['agent']['name'] != 'claude',
                     'attach only creates addressable names, and the bare base name is never a default', out['agent'])
                continue
            if host_name.split('.')[0] == '':
                rule = 'Naming: a host name that leaves nothing is replaced by host'
            else:
                rule = 'Naming: BASE-HOSTNAME with this machine\'s short host name, lowercased'
            attached(out, default_name('claude', short_host(host_name)), self.hosts[name], w,
                     f'{rule} (host name {host_name!r})')

        # --name taken: refused with 409 before any registration, naming the host that has it.
        agents = a2.cli('agent', 'list')
        taken = project('taken')
        on_a1 = default_name('claude', h)
        error = self.attach(a2, 'claude', '--name', on_a1, '--directory', str(taken), success=False)
        need(ids['a1'] in error, 'a taken --name is refused, and the error names the host that has it', error)
        need(a2.cli('agent', 'list') == agents, 'a taken --name is refused before any registration')
        need(not (a2.config / 'peerspan' / 'sessions' / ids['a2'] / on_a1).exists(), 'a refused attach leaves no '
             'profile')
        error = self.attach(a1, 'claude', '--name', default_name('claude', h, 'proj-two'), '--directory', str(taken),
                            success=False)
        need(error, 'a --name used on this host by an attach profile is refused')
        bare = project('bare')
        attached(self.attach(a1, 'file-fixture', '--name', 'file-fixture', '--directory', str(bare)), 'file-fixture',
                 a1, bare, 'Naming: the bare base name is used when given as --name')

        # A --name naming an agent on this host that no attach profile records is reused.
        legacy = a1.cli('agent', 'register', '--name', 'legacy', '--owner', 'ana')
        wl = project('legacy')
        out = attached(self.attach(a1, 'file-fixture', '--name', 'legacy', '--directory', str(wl)), 'legacy', a1, wl,
                       '--name naming an unprofiled agent')
        need(out['agent']['id'] == legacy['id'], 'A --name naming an agent on this host that no attach profile '
             'records is reused', out, legacy)

        # Re-attaching: unchanged while the credential is valid; a new setup after revocation.
        w1, first = self.w1
        adapters = a1.cli('adapter', 'list')
        again = self.attach(a1, 'claude', '--directory', str(w1))
        need(again['reused'] is True and again['agent']['id'] == first['agent']['id']
             and again['adapter_id'] == first['adapter_id'] and again['session_id'] == first['session_id'],
             'Re-attaching with a valid credential changes nothing and reports reused: true', again, first)
        need(a1.cli('adapter', 'list') == adapters, 'reused: no new credential')
        a1.cli('adapter', 'revoke', first['adapter_id'])
        renewed = self.attach(a1, 'claude', '--directory', str(w1))
        need(renewed['reused'] is False and renewed['agent']['id'] == first['agent']['id']
             and renewed['adapter_id'] != first['adapter_id'],
             'Re-attaching after revocation performs a new setup for the same agent', renewed)
        secret = self.profile_secret(renewed)
        need(secret['adapter']['id'] == renewed['adapter_id'], 'the old profile is replaced once the setup succeeds',
             secret['adapter'])
        self.w1 = (w1, renewed)

        # session start / doctor without --directory, from the recorded workspace.
        report = a1.run('session', 'doctor', cwd=w1)
        need(report.stdout.strip(), 'session doctor without --directory reports', report.stderr)
        value = json.loads(report.stdout)
        need(value.get('harness') == 'claude-code', 'session doctor uses the attach profile of the current directory',
             value)
        launched = a1.cli('session', 'start', '--', '--example', 'x', cwd=w1)
        need(launched.get('arguments') == ['--example', 'x'] and Path(launched.get('cwd')).resolve() == w1.resolve(),
             'session start uses the attach profile of the current directory', launched)
        nowhere = project('no-profile')
        need(a1.run('session', 'doctor', cwd=nowhere).returncode != 0,
             'session doctor without --directory and without a profile for the current directory fails')
        need(a1.run('session', 'start', cwd=nowhere).returncode != 0,
             'session start without --directory and without a profile for the current directory fails')

        # unchecked_hosts with the sibling stopped.
        a2.stop()
        try:
            wu = project('unchecked')
            out = self.attach(a1, 'file-fixture', '--directory', str(wu))
            need(out['unchecked_hosts'] == [ids['a2']], 'a host of the person that could not be reached is '
                 'reported in unchecked_hosts, and does not block the attach', out)
            # a2's file-fixture-HOSTNAME stays in the directory (a host that fails keeps its previous agents).
            want = default_name('file-fixture', h, host_hex=host_hex(ids['a1']))
            need(out['agent']['name'] == want, 'Naming: BASE-HOSTNAME-HHHH when BASE-HOSTNAME is used only on another '
                 'host, here one that keeps its agents in the directory while stopped', out['agent'], want)
        finally:
            a2.start()
        return '; '.join(notes)

    def check_attach_launch(self):
        a1, ids = self.hosts['a1'], self.ids
        ws = self.root / 'ws-launch'
        sessions = a1.config / 'peerspan' / 'sessions' / ids['a1']
        notes = []

        def project(name):
            path = ws / name
            path.mkdir(parents=True, exist_ok=True)
            return path

        def launch(*args, harness_args=(), cwd=None):
            run = Launch(a1, ['attach', *args, '--integrations', str(self.catalog), '--', *harness_args],
                         cwd=cwd or self.root)
            self.launches.append(run)
            return run

        def connected(agent_id):
            mine = a1.cli('agents', '--json', '--network', self.net)['mine']
            return [m['connected'] for m in mine if m['agent_id'] == agent_id]

        def launched(run, name, workspace, harness_args, reused, rule, while_running=None):
            """The harness's lines, then attach's object on stderr once it exits."""
            first = run.line()
            need(first.get('arguments') == list(harness_args), f'{rule}: arguments after -- are passed to the '
                 'harness, as for session start', first, list(harness_args))
            need(first.get('cwd') and Path(first['cwd']).resolve() == workspace.resolve(),
                 f'{rule}: attach replaces itself with the harness in the workspace', first, workspace)
            need(first.get('pid') == run.process.pid, f'{rule}: attach replaces itself with the harness (the harness '
                 'runs as the attach process)', first.get('pid'), run.process.pid)
            report = run.line()
            need(report.get('connect') == 200 and report.get('session') == 200,
                 f'{rule}: the launched harness connects its adapter with the profile\'s credential', report)
            states = connected(out_agent(name))
            need(states == [True], f'{rule}: the agent is connected while the launched harness holds the lease',
                 states)
            if while_running:
                while_running()
            code = run.finish()
            need(code == 0, f'{rule}: the harness exits 0 when its stdin closes', code, run.errors())
            lines = [line for line in run.text().splitlines() if line.strip()]
            need(len(lines) == 2 and all('agent' not in json.loads(line) for line in lines),
                 'Before launching, attach prints its output object on stderr, so stdout belongs to the harness',
                 run.text())
            out = output_object(run.stderr.decode(errors='replace'))
            need(out is not None, 'Before launching, attach prints its output object on stderr', run.errors())
            need(set(out) == ATTACH_KEYS, 'the object on stderr is attach\'s output object', out)
            need(out['agent']['name'] == name and out['agent']['address'] == f'ana/{name}'
                 and out['reused'] is reused and Path(out['workspace']).resolve() == workspace.resolve(),
                 f'{rule}: the output object names the agent and its address', out)
            need(out['adapter_id'] == report['adapter_id'] and out['session_id'] == report['session_id'],
                 f'{rule}: the launched harness uses the session attach set up', out, report)
            need(Path(out['profile']).resolve() == (sessions / name).resolve(), 'Profiles live in '
                 '$XDG_CONFIG_HOME/peerspan/sessions/HOST_ID/AGENT_NAME/', out['profile'])
            return out

        def out_agent(name):
            return {a['name']: a['id'] for a in a1.cli('agent', 'list')}.get(name)

        # 1. A new session, launched: claude means claude-code, which supports launch; run from another directory.
        w1 = project('launched')
        extra = ('--example', 'two words', PROFILE_FLAG, str(sessions / 'launched'))
        run = launch('claude', '--name', 'launched', '--directory', str(w1), harness_args=extra)

        def refused_while_running():
            # Re-attaching while the session is connected (ready) is refused with exit 1 before changing anything.
            adapters = a1.cli('adapter', 'list')
            credential = (sessions / 'launched' / 'credential.json').read_bytes()
            for flags in ((), ('--no-start',)):
                result = a1.run('attach', 'claude', '--directory', str(w1), '--integrations', str(self.catalog),
                                *flags, cwd=self.root, timeout=60)
                need(result.returncode == 1, 'Re-attaching: connected now (ready), attach refuses with exit 1',
                     flags, result.returncode, result.stdout[-400:], result.stderr[-400:])
                need('running' in (result.stderr + result.stdout).lower(),
                     'Re-attaching (ready): the refusal says the session is already running', result.stderr[-400:])
                need('wait' in result.stderr.lower(), 'Re-attaching (ready): attach says on stderr that it is waiting',
                     result.stderr[-400:])
            need(a1.cli('adapter', 'list') == adapters
                 and (sessions / 'launched' / 'credential.json').read_bytes() == credential,
                 'Re-attaching (ready): refused before changing anything')
        first = launched(run, 'launched', w1, extra, False, 'Attach launches a new session',
                         while_running=refused_while_running)

        # 1b. Attach again right after the harness exits: its lease is still valid (ready), so attach says it is
        # waiting, sees the lease expire without renewal within 16 seconds, and starts the same agent with a fresh
        # session: a new setup, then the launch.
        started = time.monotonic()
        extra = (PROFILE_FLAG, str(sessions / 'launched'), '--after-exit')
        run = launch('claude', '--directory', str(w1), harness_args=extra, cwd=w1)
        fresh = launched(run, 'launched', w1, extra, False,
                         'Re-attaching right after the harness exited waits out its lease, then performs a new setup '
                         'and launches')
        waited = time.monotonic() - started
        need('wait' in run.errors().lower(), 'Re-attaching (ready): attach says on stderr that it is waiting',
             run.errors())
        notes.append(f'relaunch after exit took {waited:.0f}s')
        need(fresh['agent']['id'] == first['agent']['id'] and fresh['adapter_id'] != first['adapter_id']
             and fresh['session_id'] != first['session_id'],
             'running attach again after the harness exited starts the same agent with a fresh session', fresh, first)
        old = a1.cli('adapter', 'inspect', first['adapter_id'])
        connection = a1.cli('adapter', 'connection', first['adapter_id'])
        need(old.get('revoked') is True or old.get('revoked_at') or 'revoked' in json.dumps(list(connection.values())),
             'the old credential is replaced as the adapter contract allows for a lapsed lease (revoked)', old,
             connection)
        need(a1.cli('session', 'inspect', first['session_id']).get('state') == 'detached',
             'replacing a lapsed credential detaches its old session', first['session_id'])

        # 2. --no-start: setup only, the object on stdout, next naming peerspan session start; nothing connects.
        w2 = project('no-start')
        result = a1.run('attach', 'claude', '--name', 'relaunched', '--directory', str(w2), '--integrations',
                        str(self.catalog), '--no-start', cwd=self.root)
        need(result.returncode == 0, '--no-start exits 0', result.returncode, result.stderr[-800:])
        try:
            out = json.loads(result.stdout)
        except json.JSONDecodeError:
            need(False, '--no-start stops after setup and prints the output object as before (stdout is the object '
                 'only)', result.stdout[-800:])
        need(set(out) == ATTACH_KEYS and out['agent']['name'] == 'relaunched' and out['reused'] is False,
             '--no-start prints the output object as before', out)
        need(isinstance(out['next'], str) and 'peerspan session start' in out['next'],
             '--no-start: next names peerspan session start', out['next'])
        record = a1.cli('adapter', 'inspect', out['adapter_id'])
        need(record.get('directory') is True, '--no-start still sets up the directory session', record)
        need(connected(out['agent']['id']) == [False], '--no-start stops after setup: no harness connects',
             connected(out['agent']['id']))

        # 3. The reused session, launched: the same workspace again, without --no-start.
        extra = (PROFILE_FLAG, str(sessions / 'relaunched'), '--again')
        run = launch('claude', '--directory', str(w2), harness_args=extra, cwd=w2)
        again = launched(run, 'relaunched', w2, extra, True, 'Attach launches a reused session')
        need(again['adapter_id'] == out['adapter_id'] and again['session_id'] == out['session_id'],
             'a reused attach launches the existing session', again, out)

        # 3b. Once that harness has exited and its lease lapsed (offline after connecting), attach performs a new
        # setup for the same agent; with --no-start it prints the object on stdout.
        try:
            wait_for(lambda: connected(again['agent']['id']) == [False], timeout=40,
                     message='the exited harness\'s lease lapses')
        except AssertionError:
            need(False, 'connected is true only while the adapter holds a valid lease (15 seconds at most)',
                 connected(again['agent']['id']))
        renewed = self.attach(a1, 'claude', '--directory', str(w2))
        need(set(renewed) == ATTACH_KEYS and renewed['reused'] is False
             and renewed['agent']['id'] == again['agent']['id'] and renewed['adapter_id'] != again['adapter_id']
             and renewed['session_id'] != again['session_id'],
             'Re-attaching (offline after connecting): a new setup for the same agent', renewed, again)

        # 4. An integration without launch: attach prints its output as before, on stdout.
        w3 = project('no-launch')
        result = a1.run('attach', 'no-launch', '--directory', str(w3), '--integrations', str(self.catalog),
                        cwd=self.root, timeout=60)
        need(result.returncode == 0, 'attach with an integration without launch exits 0', result.stderr[-800:])
        try:
            plain = json.loads(result.stdout)
        except json.JSONDecodeError:
            need(False, 'For an integration without launch, attach prints its output as before', result.stdout)
        need(set(plain) == ATTACH_KEYS and plain['agent']['name'] == default_name('no-launch', SHORT_HOST)
             and plain['reused'] is False,
             'For an integration without launch, attach prints its output as before', plain)
        notes.append(f"launched {first['agent']['name']} and reused {again['agent']['name']}")
        return '; '.join(notes)

    def check_expired_attach(self):
        a1 = self.hosts['a1']
        if not getattr(self, 'expiring', None):
            raise Failure('attach: the expiring attach was not created')
        workspace, first = self.expiring
        record = a1.cli('adapter', 'inspect', first['adapter_id'])
        expires = parse_time(record['expires_at']).timestamp()
        need(record.get('renewable') is False and expires - time.time() < 70, 'attach --expires-in 1m is fixed', record)
        while time.time() < expires + 2:
            time.sleep(min(1, max(0.05, expires + 2 - time.time())))
        out = self.attach(a1, 'file-fixture', '--directory', str(workspace))
        need(out['reused'] is False and out['agent']['id'] == first['agent']['id']
             and out['adapter_id'] != first['adapter_id'],
             'Re-attaching after expiry performs a new setup for the same agent', out, first)

    def check_directory_sessions(self):
        c1, p1, a1, ids = self.hosts['c1'], self.p1, self.hosts['a1'], self.ids
        notes = []

        # Setup validation on the owner API.
        sample = self.agent['csetup']
        for extra in ({'max_sends_per_hour': 5}, {'directory': True, 'max_sends_per_hour': 0},
                      {'directory': True, 'max_sends_per_hour': 10001}):
            status, body = c1.call('POST', '/v1/adapters/setup', {
                'agent_id': sample['id'], 'session_id': 'session_' + secrets.token_hex(16), 'integration': 'test',
                'expires_at': timestamp(900), **extra})
            need(status == 400, 'max_sends_per_hour is 1 to 10,000 and requires directory', extra, status, body)

        # no_directory: a session from session setup, and one from adapter create.
        profile = self.root / 'setup-profile'
        configured = c1.cli('session', 'setup', '--harness', 'file-fixture', '--directory', str(profile), '--agent',
                            sample['id'], '--integrations', str(self.catalog))
        need(configured.get('session_id'), 'session setup still runs', configured)
        plain = json.loads((profile / 'credential.json').read_text())
        session = c1.cli('session', 'attach', '--agent', self.agent['corig']['id'], '--integration', 'test')
        created = c1.cli('adapter', 'create', '--session', session['id'], '--expires-in', '30m')
        for secret, what in ((plain, 'session setup'), (created, 'adapter create')):
            token = secret['token']
            for method, path, body in (
                    ('POST', '/adapter/v1/send', {'to': 'pat/alpha', 'request_id': request_id(), 'content': 'x'}),
                    ('POST', '/adapter/v1/delegations', {'to': 'pat/alpha', 'task_id': task_id(), 'input': 'x'}),
                    ('GET', '/adapter/v1/agents', None)):
                status, value = adapter_call(c1, token, method, path, body)
                need(status == 403 and isinstance(value, dict) and value.get('code') == 'no_directory',
                     f'Without directory access ({what}), a to request returns 403 no_directory', path, status, value)

        # The rate cap, on a directory session of carol's with a cap of 2.
        (self.root / 'ws-carol').mkdir(exist_ok=True)
        capped = self.attach(c1, 'file-fixture', '--directory', str(self.root / 'ws-carol'), '--max-sends-per-hour', '2')
        record = c1.cli('adapter', 'inspect', capped['adapter_id'])
        need(record.get('directory') is True and record.get('max_sends_per_hour') == 2,
             'The adapter\'s record shows directory and max_sends_per_hour', record)
        token = self.profile_secret(capped)['token']
        status, listing = adapter_call(c1, token, 'GET', '/adapter/v1/agents')
        need(status == 200 and isinstance(listing, list) and all(set(e) == ADAPTER_AGENT_KEYS for e in listing),
             'GET /adapter/v1/agents returns [{address, network_id, connected, actions, max_message_bytes, '
             'max_artifact_bytes, endpoint}]', status, listing)
        need(all(endpoint_shaped(e['endpoint']) for e in listing), 'endpoint is {address, path}', listing)
        need(all(e['address'] for e in listing), 'GET /adapter/v1/agents lists addressable agents only', listing)
        entry = {e['address']: e for e in listing}
        eps = entry.get('pat/eps')
        need(eps and set(eps['actions']) == set(DEFAULT_ACTIONS) and eps['network_id'] == self.net,
             'actions are the union over the agent\'s authorizations', eps)
        need('pat/delta' not in entry and 'pat/alpha' in entry,
             'an agent left with no actions (only from_agent entries for other agents) is omitted', sorted(entry))

        both = {'to': 'pat/alpha', 'destination': 'x', 'request_id': request_id(), 'content': 'both'}
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send', both)
        need(status == 400, 'POST /adapter/v1/send: giving both to and destination is 400', status, value)
        first = {'to': 'pat/alpha', 'network': self.net, 'request_id': request_id(), 'content': 'one'}
        status, sent = adapter_call(c1, token, 'POST', '/adapter/v1/send', first, timeout=15)
        need(status == 200, 'an adapter send by address', status, sent)
        delegated = {'to': 'pat/alpha', 'task_id': task_id(), 'input': 'two'}
        status, task = adapter_call(c1, token, 'POST', '/adapter/v1/delegations', delegated, timeout=15)
        need(status == 200, 'an adapter delegation by address', status, task)
        need(task.get('to') == 'pat/alpha', 'Persistence: the delegation record shows to as given', task)
        third = {'to': 'pat/alpha', 'request_id': request_id(), 'content': 'three'}
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send', third, timeout=15)
        need(status == 429 and value.get('code') == 'rate_limited' and type(value.get('retry_after')) is int
             and 1 <= value['retry_after'] <= 3600 and 'error' in value,
             'Rate cap: a request over max_sends_per_hour returns 429 {code: rate_limited, error, retry_after}',
             status, value)
        status, value = adapter_call(c1, token, 'GET', '/adapter/v1/sends/' + third['request_id'])
        need(status == 404, 'Rate cap: a refused request persists nothing', status, value)
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/delegations',
                                     {'to': 'pat/alpha', 'task_id': task_id(), 'input': 'four'}, timeout=15)
        need(status == 429, 'Rate cap: delegations count against the same cap', status, value)
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send', first, timeout=15)
        need(status == 200, 'Rate cap: a retry is never counted', status, value)
        c1.cli('adapter', 'route', 'add', '--adapter', capped['adapter_id'], '--name', 'alpha-route', '--peer',
               ids['p1'], '--agent', self.agent['alpha']['id'], '--expires-in', '10m')
        routed = request_id()
        status, value = adapter_call(c1, token, 'POST', '/adapter/v1/send',
                                     {'destination': 'alpha-route', 'request_id': routed, 'content': 'route'},
                                     timeout=15)
        need(status == 200, 'Rate cap: route sends keep their own budgets and are not counted', status, value)
        for rid, destination, to in ((routed, 'alpha-route', None), (first['request_id'], None, 'pat/alpha')):
            status, value = adapter_call(c1, token, 'GET', '/adapter/v1/sends/' + rid)
            need(status == 200 and 'destination' in value and 'to' in value and value['destination'] == destination
                 and value['to'] == to, 'the adapter send status always has both destination and to, one of them null',
                 status, value)

        # Deadlines: 1 hour for sends (live delivery contract, slice 1) and delegations.
        stored = self.outbound(c1, ids['p1'], first['request_id'])
        need(stored and near(stored['request']['deadline'], 3600, 30), 'Adapter sends by address get 1 hour',
             stored)
        need(stored.get('to') == 'pat/alpha', 'Persistence: the record shows to as given (adapter send)', stored)
        status, local = c1.call('GET', f"/v1/tasks/{ids['p1']}/{delegated['task_id']}")
        need(status == 200 and near(local['request']['deadline'], 3600, 60), 'adapter delegations get 1 hour',
             status, local)

        # MCP, through the real adapter, on ana's attached session.
        if not getattr(self, 'w1', None):
            raise Failure('MCP cases need the attach section\'s session')
        _, attached = self.w1
        secret = self.profile_secret(attached)
        channel = Channel(self.node, self.script, a1, secret, self.root / 'mcp-ana')
        self.channels.append(channel)
        failed, agents = tool(channel, 'list_agents', {})
        need(not failed and isinstance(agents, list), 'MCP list_agents', agents)
        addresses = {e.get('address') for e in agents}
        sibling = f"ana/{default_name('claude', SHORT_HOST, host_hex=host_hex(ids['a2']))}"
        need('pat/gamma' in addresses and sibling in addresses,
             'MCP list_agents: addressable agents in the directory', sorted(a for a in addresses if a), sibling)
        need(all(set(e) == ADAPTER_AGENT_KEYS and endpoint_shaped(e.get('endpoint')) for e in agents),
             'MCP list_agents returns the GET /adapter/v1/agents entries, endpoint included', agents)
        failed, sent = tool(channel, 'send', {'to': 'pat/gamma', 'network': self.net, 'content': 'from mcp'})
        need(not failed and sent.get('request_id'), 'MCP send by to', sent)
        rid = sent['request_id']

        def delivered():
            failed, status = tool(channel, 'send_status', {'request_id': rid})
            return status if not failed and status.get('state') == 'accepted' else None
        status = wait_for(delivered, timeout=40, message='MCP send accepted')
        need(status.get('to') == 'pat/gamma', 'send_status reports to for these sends', status)
        message = [m for m in p1.cli('message', 'list', '--limit', '1000') if m['request']['request_id'] == rid]
        need(message and message[0]['request']['target_agent_id'] == self.agent['gamma']['id']
             and (message[0]['request'].get('origin') or {}).get('agent_id') == attached['agent']['id'],
             'MCP send by to reaches the agent, with the session\'s agent as origin', message)
        failed, submitted = tool(channel, 'delegate_task', {'to': 'pat/gamma', 'input': 'mcp task'})
        need(not failed and submitted.get('task_id'), 'MCP delegate_task by to', submitted)
        tid = submitted['task_id']

        def accepted():
            failed, record = tool(channel, 'task_status', {'task_id': tid})
            return record if not failed and record.get('submit_state') == 'accepted' else None
        record = wait_for(accepted, timeout=40, message='MCP delegation accepted')
        need(record['request']['target_agent_id'] == self.agent['gamma']['id']
             and (record['request'].get('policy') or {}).get('person_id') == self.pat,
             'MCP delegate_task by to reaches the agent under the target owner\'s policy', record)
        notes.append(f'mcp list_agents {len(agents)} entries')
        return '; '.join(notes)

    def check_label_retry(self):
        """An uncertain send by address keeps its stored target after the address would resolve elsewhere."""
        c1, b1, b2, ids = self.hosts['c1'], self.hosts['b1'], self.hosts['b2'], self.ids
        self.refresh(c1)
        b1.stop()
        try:
            out = c1.cli('send', 'bob/bobby', 'retry me', '--network', self.net)
            need(out['state'] == 'unknown', 'a send to a stopped host is uncertain', out)
            rid = out['request']['request_id']
            need(self.outbound(c1, ids['b1'], rid), 'The resolved host and agent ID are stored with the request', out)
            # The address change made here (settled with the owner) is an unbinding of b1 from bob; bob's
            # other host then registers the same name, so the address would now resolve to b2.
            b2.cli('network', 'unbind', '--network', self.net, '--host', ids['b1'])
            moved = b2.cli('agent', 'register', '--name', 'bobby', '--owner', 'bob')
            b2.cli('grant', 'create', '--peer', ids['c1'], '--agent', moved['id'], '--expires-in', '2h',
                   '--allow-disconnected')
            wait_for(lambda: not any(m['host_id'] == ids['b1'] and m['person_id']
                                     for m in c1.cli('network', 'members', self.net)), timeout=30,
                     message='b1 unbound in c1\'s map')
        finally:
            b1.start()

        def done():
            r = self.outbound(c1, ids['b1'], rid)
            return r if r and r['state'] != 'unknown' else None
        record = wait_for(done, timeout=120, message='the automatic retry')
        need(record['state'] == 'accepted' and record['request']['target_agent_id'] == self.agent['bobby']['id'],
             'Retries use the stored target and never re-resolve', record)
        need(self.received(b1, rid) and not self.received(b2, rid), 'the retry reached the stored host', rid)
        need(record.get('to') == 'bob/bobby', 'the record still shows to as given', record)

    def block_udp(self, port_a, port_b):
        """Drop UDP between two local ports, in both directions, until the pairing closes; False without root."""
        if os.geteuid() != 0 or not shutil.which('iptables'):
            return False
        rules = [['INPUT', '-p', 'udp', '--sport', str(a), '--dport', str(b), '-j', 'DROP']
                 for a, b in ((port_a, port_b), (port_b, port_a))]
        for rule in rules:
            if subprocess.run(['iptables', '-I', *rule], capture_output=True).returncode != 0:
                return False
            self.cleanups.append(lambda rule=rule: subprocess.run(['iptables', '-D', *rule], capture_output=True))
        return True

    def check_endpoints(self):
        """`endpoint` in `agents --json` and GET /adapter/v1/agents: this host (an advertised address, and the
        first candidate when none is advertised), a peer dialed by its advertised address, a direct peer, a relayed
        peer, and a stopped host with no map address."""
        c1, p1, d1, d2, z1, ids = (self.hosts['c1'], self.p1, self.hosts['d1'], self.hosts['d2'], self.hosts['z1'],
                                   self.ids)
        notes = []

        def member(host, of):
            return {m['host_id']: m for m in host.cli('network', 'members', self.net)}[ids[of]]

        def path(host, of):
            view = host.cli('peer', 'path', ids[of])
            need(view.get('path') in ('direct', 'relay', 'none'), 'peer path reports direct, relay, or none', view)
            return view

        def agents(host):
            out = host.cli('agents', '--json', '--network', self.net)
            return ({r['address']: r for r in out['reachable']}, {m['address']: m for m in out['mine']})

        def readable_line(host, address):
            result = host.run('agents', '--network', self.net)
            need(result.returncode == 0, 'agents exits 0', result.stderr[-400:])
            lines = [line for line in result.stdout.splitlines() if address in line.split()]
            return lines[0] if lines else result.stdout

        for name, where in (('dself', 'd1'), ('dpeer', 'd2'), ('zed', 'z1')):
            self.agent[name] = self.hosts[where].cli('agent', 'register', '--name', name, '--owner', 'dana')
        p1.cli('grant', 'create', '--peer', ids['d1'], '--agent', self.agent['gamma']['id'], '--expires-in', '2h',
               '--allow-disconnected')
        # A directory session on d1, for GET /adapter/v1/agents.
        (self.root / 'ws-dana').mkdir(exist_ok=True)
        session = self.attach(d1, 'file-fixture', '--directory', str(self.root / 'ws-dana'))
        token = self.profile_secret(session)['token']

        def adapter_agents():
            status, listing = adapter_call(d1, token, 'GET', '/adapter/v1/agents')
            need(status == 200 and isinstance(listing, list), 'GET /adapter/v1/agents', status, listing)
            need(all(set(e) == ADAPTER_AGENT_KEYS and endpoint_shaped(e['endpoint']) for e in listing),
                 'GET /adapter/v1/agents entries carry endpoint {address, path}', listing)
            return {e['address']: e for e in listing}

        # This host with an advertised address (c1 binds 127.0.0.1, so it advertises its bound address).
        reach, mine = agents(c1)
        own = [m for m in mine.values() if m['host_id'] == ids['c1']]
        need(own, 'mine lists this host\'s agents', mine)
        want = {'address': member(c1, 'c1')['address'], 'path': 'local'}
        need(want['address'] == c1.address, 'the map has c1\'s advertised address (suite self-check)', want)
        need(all(m['endpoint'] == want for m in own), 'Endpoints: for this host, path local and its own advertised '
             'address from the network map', own, want)
        # p1 is dialed by its advertised address, with no discovered direct path. Whether peer path calls that
        # relay or none is the peer messaging contract's (a relay route to that host); endpoint follows it.
        view = path(c1, 'p1')
        need(reach['pat/alpha']['endpoint'] == {'address': member(c1, 'p1')['address'], 'path': view['path']},
             'Endpoints: another host without a direct path: path as peer path reports it, and its advertised '
             'address from the map', reach['pat/alpha'], view)
        notes.append(f"peer dialed by its advertised address: path {view['path']}")

        # A direct peer: d1 and d2 advertise no address, so they reach each other through the relay, and path
        # discovery (over their interface candidates) moves them to a direct path.
        need(member(d1, 'd2')['address'] == '' and member(d1, 'd2').get('candidates'),
             'a wildcard bind advertises no address and publishes candidates (suite self-check)', member(d1, 'd2'))

        # A relayed peer: z1 advertises a dead address, so d1 falls back to the relay. On one machine, path
        # discovery would still find a direct path (from ping sources and reflexive candidates), so UDP between
        # d1's and z1's peer ports is dropped (root and iptables), leaving only the relay, which runs over TCP.
        relayed = self.block_udp(d1.port, z1.port)
        if not relayed:
            notes.append('SKIPPED (needs root and iptables): a relayed peer')

        def direct():
            self.refresh(d1)
            return (path(d1, 'd2')['path'] == 'direct' and (not relayed or path(d1, 'z1')['path'] == 'relay')) or None
        try:
            wait_for(direct, timeout=75, message='a direct path from d1 to d2')
        except AssertionError:
            raise Failure('within 75 seconds, no direct path between two wildcard-bound hosts on this machine, or '
                          f'no relay path with UDP dropped (peer path {path(d1, "d2")}, {path(d1, "z1")})')

        def agree():
            """agents --json on d1, with the peer path read just before and after, when both agree."""
            before = {n: path(d1, n) for n in ('d2', 'p1', 'z1')}
            reach, mine = agents(d1)
            after = {n: path(d1, n) for n in ('d2', 'p1', 'z1')}
            return (reach, mine, after) if before == after else None
        reach, mine, paths = wait_for(agree, timeout=30, message='a stable peer path on d1')
        need(paths['d2']['path'] == 'direct', 'the direct path holds', paths['d2'])
        want = {'address': paths['d2']['endpoint'], 'path': 'direct'}
        for listing, what in ((reach, 'reachable'), (mine, 'mine')):
            need(listing.get('dana/dpeer', {}).get('endpoint') == want, f'Endpoints ({what}): another host on a direct '
                 'path: path direct, and the direct path\'s endpoint', listing.get('dana/dpeer'), paths['d2'])
        need(reach.get('pat/gamma', {}).get('endpoint') == {'address': member(d1, 'p1')['address'],
                                                             'path': paths['p1']['path']},
             'Endpoints: a peer by its advertised address, seen from d1', reach.get('pat/gamma'), paths['p1'])
        # This host without an advertised address: its own first candidates entry.
        d1_member = member(d1, 'd1')
        need(d1_member['address'] == '', 'd1 advertises no address (suite self-check)', d1_member)
        want_local = {'address': (d1_member.get('candidates') or [None])[0], 'path': 'local'}
        need(mine.get('dana/dself', {}).get('endpoint') == want_local, 'Endpoints: for this host with no advertised '
             'address, its first candidates entry, with path local', mine.get('dana/dself'), d1_member)
        # A relayed peer: z1 advertises a dead address, so it is reached through the relay (and path discovery is
        # not run for peers reached by an advertised address).
        zed = reach.get('dana/zed')
        if relayed:
            need(paths['z1']['path'] == 'relay', 'peer path: a peer whose advertised address is dead, with UDP '
                 'dropped, is reached through the relay', paths['z1'])
        want = ({'address': paths['z1']['endpoint'], 'path': 'direct'} if paths['z1']['path'] == 'direct'
                else {'address': self.z1_dead, 'path': paths['z1']['path']})
        need(zed and zed['endpoint'] == want and member(d1, 'z1')['address'] == self.z1_dead,
             'Endpoints: a relayed peer: path relay, and its advertised address from the map', zed, paths['z1'])
        listed = adapter_agents()
        for address, entry in (('dana/dpeer', reach['dana/dpeer']), ('pat/gamma', reach['pat/gamma']),
                               ('dana/zed', zed)):
            need(listed.get(address, {}).get('endpoint') == entry['endpoint'],
                 'GET /adapter/v1/agents: endpoint as for agents', address, listed.get(address), entry)
        own_listed = {a: e for a, e in listed.items() if a in mine and mine[a]['host_id'] == ids['d1']}
        need(all(e['endpoint'] == want_local for e in own_listed.values()),
             'GET /adapter/v1/agents: this host\'s entries (if listed) have path local', own_listed, want_local)
        notes.append(f"adapter agents list {len(own_listed)} of this host's agents")
        line = readable_line(d1, 'pat/gamma')
        need(f"{member(d1, 'p1')['address']} ({paths['p1']['path']})" in line or paths['p1']['path'] == 'direct',
             'agents: the address, then the path in parentheses when it is not direct or local', line)
        line = readable_line(d1, 'dana/dpeer')
        need(paths['d2']['endpoint'] in line and '(direct)' not in line,
             'agents: a direct endpoint prints its address alone', line)
        if relayed:
            line = readable_line(d1, 'dana/zed')
            need(f'{self.z1_dead} (relay)' in line, 'agents: the address, then (relay)', line)

        # A host with no map address: z1 restarts with no listener, so its map entry has address "" and no
        # candidates, and then stops; the directory keeps its agents.
        z1.stop()
        z1.daemon_args = ('--coordination-interval', '1')
        z1.start()
        wait_for(lambda: (lambda m: m['address'] == '' and not m.get('candidates'))(member(d1, 'z1')), timeout=40,
                 message='z1 without an address or candidates in d1\'s map')
        z1.stop()

        # z1 stopped: once its direct path (if any) lapses, its endpoint has no address, and path is whatever peer
        # path reports (relay or none: whether a relay route to a stopped host "exists" is the peer messaging
        # contract's), with the same entry in GET /adapter/v1/agents.
        seen = {}

        def lapsed():
            seen['z1'] = path(d1, 'z1')
            if seen['z1']['path'] == 'direct':
                return None
            reach, _ = agents(d1)
            again = path(d1, 'z1')
            return reach if again == seen['z1'] else None
        try:
            reach = wait_for(lapsed, timeout=60, message='z1\'s direct path lapsing')
        except AssertionError:
            raise Failure('peer path: a direct path to a stopped host is dropped after 15 seconds without a pong', seen)
        view = seen['z1']
        need('dana/zed' in reach, 'a host that fails keeps its previous agents in the directory', sorted(reach))
        want = {'address': None, 'path': view['path']}
        need(reach['dana/zed']['endpoint'] == want, 'Endpoints: a host with no direct path and no map address '
             '(advertised address "" and no candidates): address null, path as peer path reports it',
             reach['dana/zed'], view)
        need(adapter_agents().get('dana/zed', {}).get('endpoint') == want,
             'GET /adapter/v1/agents: endpoint as for agents (no map address)', want)
        line = readable_line(d1, 'dana/zed')
        need(view['path'] in line, 'agents: with no address, the path alone', line)
        notes.append(f"stopped host with no map address: path {view['path']}")
        z1.start()
        return '; '.join(notes)

    # --- the pairing ---------------------------------------------------------------------------------------

    def setup_catalog(self):
        """The fixture integration as `file-fixture`, as `claude-code` (no Claude needed), and with a 64-character
        ID, and as `no-launch` without the launch operation."""
        self.catalog = self.root / 'integrations'
        source = Path(__file__).with_name('fixtures') / 'harness'
        for identity in ('file-fixture', 'claude-code', LONG_ID):
            bundle = self.catalog / identity
            bundle.mkdir(parents=True)
            shutil.copy2(source / 'provider.py', bundle / 'provider.py')
            (bundle / 'harness.py').write_text(LAUNCH_HARNESS)
            (bundle / 'integration.json').write_text(json.dumps({
                'version': 1, 'id': identity, 'command': [str(Path(sys.executable).resolve()), './provider.py'],
                'operations': ['prepare', 'check', 'launch']}))
        # The same fixture without launch support.
        bundle = self.catalog / 'no-launch'
        bundle.mkdir(parents=True)
        shutil.copy2(source / 'provider.py', bundle / 'provider.py')
        (bundle / 'integration.json').write_text(json.dumps({
            'version': 1, 'id': 'no-launch', 'command': [str(Path(sys.executable).resolve()), './provider.py'],
            'operations': ['prepare', 'check']}))

    def join(self, name, label, person=True):
        token = self.p1.cli('network', 'invite', '--network', self.net, '--member', label, '--expires-in', '1h')['token']
        h = self.hosts[name]
        extra = () if person else ('--no-person',)
        out = h.cli('network', 'join', '--token', token, *extra)
        if person:
            assert out['person'] and out['person']['bound'], out
        return out

    def run(self):
        root = self.root
        (root / 'keys').mkdir()
        for name in ('pat', 'bob', 'carol', 'ana', 'dana'):
            self.keys[name] = ssh_key(root / 'keys', name)
            (root / f'agent-{name}').mkdir()
            self.agents[name] = Agent(root / f'agent-{name}')
            self.agents[name].add(self.keys[name][0])
        self.pat, self.bob, self.carol, self.ana, self.dana = (person_id(self.keys[n][2])
                                                               for n in ('pat', 'bob', 'carol', 'ana', 'dana'))
        self.setup_catalog()

        self.section('root help', self.check_help)
        self.coord_key = self.coord.start()['public_key']
        # d1 and d2 bind the IPv4 wildcard, so they advertise no address and publish interface candidates (a
        # direct path between them can be discovered); z1 advertises a dead address, so it is reached through the
        # relay, and later restarts without a listener (no map address).
        persons = {'p1': 'pat', 'p2': 'pat', 'b1': 'bob', 'b2': 'bob', 'c1': 'carol', 'a1': 'ana', 'a2': 'ana',
                   'd1': 'dana', 'd2': 'dana', 'z1': 'dana', 'n1': None, 'x': None}
        # More hosts of ana, on machines of other names: each daemon and CLI runs in a UTS namespace of its own.
        self.named_hosts = {'a3': 'Other_Box.lan', 'a4': '', 'a5': '***'} if uts_available() else {}
        persons.update({name: 'ana' for name in self.named_hosts})
        for name, person in persons.items():
            self.host(name).sock = self.agents[person].socket if person else None
        for name, host_name in self.named_hosts.items():
            self.hosts[name].host_name = host_name
        for name in ('d1', 'd2'):
            h = self.hosts[name]
            h.address = f'0.0.0.0:{h.port}'
            h.daemon_args = ('--peer-listen', h.address, *h.daemon_args[2:])
        self.z1_dead = f'127.0.0.1:{available_port()}'
        self.hosts['z1'].daemon_args = (*self.hosts['z1'].daemon_args, '--advertise', self.z1_dead)
        self.p1 = self.hosts['p1']
        self.ids = {name: h.start()['id'] for name, h in self.hosts.items()}
        ids = self.ids

        created = self.p1.cli('network', 'create', '--name', 'team', '--member', 'pat', *self.coordinator_flags())
        self.net = created['id']
        assert created['person']['bound'], created
        joining = ['p2', 'b1', 'b2', 'c1', 'a1', 'a2', *self.named_hosts, 'd1', 'd2', 'z1']
        for name in joining:
            self.join(name, persons[name])
        self.join('n1', 'nobody', person=False)
        self.members = ['p1', *joining, 'n1']
        expected = {ids[n]: {'pat': self.pat, 'bob': self.bob, 'carol': self.carol, 'ana': self.ana,
                             'dana': self.dana}.get(persons[n]) for n in self.members}

        def bound():
            for n in self.members:
                seen = {m['host_id']: m['person_id'] for m in self.hosts[n].cli('network', 'members', self.net)}
                if seen != expected:
                    return None
            return True
        wait_for(bound, timeout=60, message='every member bound as expected on every host')

        # A second network of p1's, so that x is a member of p1's but not of the team network.
        other = self.p1.cli('network', 'create', '--name', 'other', '--member', 'p1x', '--no-person',
                            *self.coordinator_flags(), sock=None)
        self.other = other['id']
        token = self.p1.cli('network', 'invite', '--network', self.other, '--member', 'xhost', '--expires-in', '1h',
                            sock=None)['token']
        self.hosts['x'].cli('network', 'join', '--token', token, '--no-person')
        wait_for(lambda: len(self.p1.cli('network', 'members', self.other)) == 2, timeout=30,
                 message='x in p1\'s map of the other network')

        # Agents.
        self.agent = {}
        self.p1_agents = ['alpha', 'beta', 'gamma', 'delta', 'eps', 'omega', 'notask', NOT_ADDRESSABLE]
        for host, names in (('p1', self.p1_agents), ('c1', ['corig', 'csetup']), ('n1', ['nagent']),
                            ('b1', ['bobby'])):
            for name in names:
                self.agent[name] = self.hosts[host].cli('agent', 'register', '--name', name, '--owner',
                                                        persons[host] or 'nobody')

        # Before any policy or grant: what the peer route serves to carol and bob.
        # The peer route may be missing; the peer route section reports it, and setup goes on.
        def probe(name):
            try:
                return self.listing('p1', name)
            except OSError as error:
                return (None, str(error))
        try:
            wait_for(lambda: probe('c1')[0] == 200, timeout=20, message='peer route reachable')
        except AssertionError:
            pass
        self.before = {name: probe(name) for name in ('c1', 'b1')}

        # pat's policy and the grants.
        self.p1.cli('network', 'group', 'set', '--network', self.net, '--group', 'team-g', '--person', 'carol')
        self.allow('carol', '--agent', 'alpha')
        self.allow('group:team-g', '--agent', 'beta')
        self.allow('everyone', '--agent', 'gamma')
        self.allow(f"agent:{ids['c1']}/{self.agent['corig']['id']}", '--agent', 'delta')
        self.allow('carol', '--agent', 'notask', '--no-tasks')
        version = self.allow('bob')
        self.grants = {}

        def grant(host, peer, agent, hours, *extra):
            g = self.hosts[host].cli('grant', 'create', '--peer', ids[peer], '--agent', self.agent[agent]['id'],
                                     '--expires-in', f'{hours}h', '--allow-disconnected', *extra)
            self.grants[g['id']] = g
            return g
        grant('p1', 'c1', 'eps', 1)
        self.eps_late = grant('p1', 'c1', 'eps', 2)
        self.eps_task = grant('p1', 'c1', 'eps', 2, '--action', 'task.submit')
        grant('p1', 'n1', 'omega', 1)
        self.n1_grant = grant('n1', 'c1', 'nagent', 2)
        grant('b1', 'c1', 'bobby', 2)
        self.synced(version, *(self.hosts[n] for n in self.members))

        self.section('peer route', self.check_peer_route)
        self.section('discovery', self.check_discovery)
        # The injected duplicate: the same name on two hosts of pat, allowed for carol.
        self.agent['dup1'] = self.p1.cli('agent', 'register', '--name', 'dup', '--owner', 'pat')
        self.agent['dup2'] = self.hosts['p2'].cli('agent', 'register', '--name', 'dup', '--owner', 'pat')
        self.synced(self.allow('carol', '--agent', 'dup'), self.hosts['c1'])
        self.section('addresses', self.check_addresses)
        self.section('sending', self.check_sending)
        self.section('agents and status', self.check_agents_and_status)
        self.section('attach', self.check_attach)
        self.section('attach launch', self.check_attach_launch)
        self.section('directory sessions', self.check_directory_sessions)
        self.section('attach after expiry', self.check_expired_attach)
        self.section('retry after a label change', self.check_label_retry)
        # Last: it changes and stops z1.
        self.section('endpoints', self.check_endpoints)

    def close(self):
        for cleanup in self.cleanups:
            cleanup()
        try:
            for run in self.launches:
                run.close()
            for channel in self.channels:
                try:
                    channel.close()
                except Exception:
                    if channel.process.poll() is None:
                        channel.process.kill()
            stop_all(tuple(self.hosts.values()))
        finally:
            self.coord.stop()
            self.coord.logs.close()
            for agent in self.agents.values():
                agent.stop()


def run_pairing(coord_binary, cli_binary, daemon_binary, node, label):
    with tempfile.TemporaryDirectory(prefix='peerspan-directory-') as temporary:
        pairing = Pairing(label, cli_binary, daemon_binary, coord_binary, node, Path(temporary))
        started = time.monotonic()
        try:
            pairing.run()
        except Exception:
            detail = traceback.format_exc(limit=6)
            pairing.results.append(('setup', False, detail))
            print(f'FAIL {label} [setup]: {detail}', flush=True)
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
    parser.add_argument('--node', type=Path, required=True, help='Node for the MCP adapter cases')
    parser.add_argument('--pairing', action='append', help='CLI/DAEMON, such as Go/Rust; repeatable; default all four')
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
    failures = []
    for pairing in pairings:
        cli, _, daemon = pairing.partition('/')
        label = f'{cli} CLI, {daemon} daemon'
        for name, ok, detail in run_pairing(args.coord.resolve(), binaries[cli], binaries[daemon],
                                            args.node.resolve(), label):
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
