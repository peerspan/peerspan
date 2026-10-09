#!/usr/bin/env python3
"""Scripted launch acceptance (milestone 7 slice 5): the quick start, run as written.

Written from docs/launch-contract.md ("Slice 5: acceptance") and
docs/quick-start.md. It is an end-to-end check, not a conformance suite.

Preparation, not counted:
- builds `capsule-coord` from the checkout and runs it on loopback, standing in
  for the hosted coordinator;
- packages each needed implementation with `scripts/package-release.sh`, with
  CAPSULE_COORDINATOR and CAPSULE_COORDINATOR_KEY naming that coordinator, and
  verifies each archive's checksum;
- copies the given Node binary into a world-readable directory on every
  machine's PATH (Node 22 is a documented prerequisite);
- for each machine, creates a new user `capsule-acc-N` with an empty home,
  enables linger for it (as a login would start its systemd user manager),
  copies the archive and checksum into the home, and, as the user, checks the
  checksum, extracts the bundle, and puts its `bin` first on PATH, as the quick
  start says; writes a fixture `claude` into `~/.local/bin` and makes
  `~/src/project`.

Every counted step then runs as that machine's user through `runuser`, with a
clean environment (HOME, USER, PATH, XDG_RUNTIME_DIR; no ssh-agent), exactly as
the documented path gives it, in the contract's order. TOKEN and LABEL come
from the previous commands' output. Each `attach claude` runs in the
background in `~/src/project`, as a terminal would keep it; `attach` must
replace itself with the fixture `claude`, which runs the MCP adapter from the
generated configuration (no model is called) and logs what the adapter sends.

Runs: solo and pair with each implementation; team with Go, Rust, and mixed
(Go, Rust, Go). The uncounted checks follow each path. Every unit, linger
setting, process, user, and home is removed afterwards, also after a failure
or a signal, unless --keep. `--cleanup` removes leftovers of an earlier --keep.

Results go to docs/results/launch-acceptance.json (--output). `--run NAME`
selects runs. `--pace SECONDS` waits at each hand-over between machines,
before each attach, and before the checks; it is a diagnostic for
coordination latency, recorded in the results, and acceptance uses none.

Needs root, systemd 250 or newer, Python 3.12, Node 22, Go, Cargo, npm, and
util-linux (runuser, flock).
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback

REPO = Path(__file__).resolve().parent.parent
VERSION = '0.0.0-acceptance'
USER_PREFIX = 'capsule-acc-'
SHORT_HOST = re.sub(r'[^a-z0-9._-]', '-', socket.gethostname().split('.')[0].lower())
RUNS = {
    'solo-go': ('solo', ['go', 'go']),
    'solo-rust': ('solo', ['rust', 'rust']),
    'pair-go': ('pair', ['go', 'go']),
    'pair-rust': ('pair', ['rust', 'rust']),
    'team-go': ('team', ['go', 'go', 'go']),
    'team-rust': ('team', ['rust', 'rust', 'rust']),
    'team-mixed': ('team', ['go', 'rust', 'go']),
}
EXPECTED_COUNTS = {'solo': {'capsule': 7, 'copy': 1}, 'pair': {'capsule': 9}, 'team': {'capsule': 14}}
STEP_TIMEOUT = 120
LAUNCH_SECONDS = 60
CHECK_SECONDS = 60

# The stand-in for Claude Code. It accepts what the claude-code integration
# passes (its prerequisite probes and the launch), runs the configured MCP
# server as Claude Code would, completes the MCP handshake, lists tools, answers
# pings, and logs every message the adapter sends. It never calls a model.
FIXTURE = r'''#!/usr/bin/env python3
"""Fixture claude for the launch acceptance run: runs the MCP adapter, no model."""
import json, os, signal, subprocess, sys, threading, time

args = sys.argv[1:]
LOG_DIR = os.path.join(os.path.expanduser("~"), ".claude-fixture")


def log(**entry):
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
    with open(os.path.join(LOG_DIR, "log.jsonl"), "a") as f:
        f.write(json.dumps({"time": time.time(), "pid": os.getpid(), **entry}) + "\n")


if "--version" in args:
    print("2.1.291 (fixture)")
    sys.exit(0)
if args[:2] == ["auth", "status"]:
    print(json.dumps({"loggedIn": True, "authMethod": "claude.ai"}))
    sys.exit(0)
if "--mcp-config" not in args:
    log(event="unexpected", arguments=args, cwd=os.getcwd())
    sys.exit(2)
value = args[args.index("--mcp-config") + 1]
if value.lstrip().startswith("{"):
    config = json.loads(value)
else:
    with open(value) as f:
        config = json.load(f)
server = config["mcpServers"]["capsule"]
log(event="launched", arguments=args, cwd=os.getcwd(), server_command=server.get("command"))
os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
errors = open(os.path.join(LOG_DIR, "server-%d.log" % os.getpid()), "ab")
child = subprocess.Popen([server["command"], *server.get("args", [])],
                         env={**os.environ, **server.get("env", {})},
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True)
lock = threading.Lock()


def send(message):
    with lock:
        child.stdin.write(json.dumps(message) + "\n")
        child.stdin.flush()


def stop(*_):
    try:
        child.stdin.close()
        child.wait(timeout=5)
    except Exception:
        child.kill()
    log(event="stopped")
    os._exit(0)


for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(number, stop)
send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
      "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                 "clientInfo": {"name": "claude-fixture", "version": "1"}}})
for line in child.stdout:
    try:
        message = json.loads(line)
    except ValueError:
        log(event="garbage", line=line[:500])
        continue
    if "id" in message and "method" in message:
        if message["method"] == "ping":
            send({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        else:
            send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "not supported"}})
        log(event="request", message=message)
    elif message.get("id") == 1:
        log(event="initialized", result=message.get("result"), error=message.get("error"))
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    elif message.get("id") == 2:
        log(event="tools", tools=[tool.get("name") for tool in (message.get("result") or {}).get("tools", [])],
            error=message.get("error"))
    else:
        log(event="notification" if "method" in message else "response", message=message)
log(event="server_exited", code=child.wait())
sys.exit(1)
'''


class Failure(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def wait_for(check, seconds, what):
    deadline = time.monotonic() + seconds
    last = None
    while True:
        last = check()
        if last and last[0]:
            return last[1]
        if time.monotonic() > deadline:
            raise Failure(f'timed out after {seconds}s waiting for {what}: {last[1] if last else None}')
        time.sleep(1)


def first_json(text):
    """The first JSON object in text, as a user reads the printed object."""
    start = text.find('{')
    while start >= 0:
        try:
            value, _ = json.JSONDecoder().raw_decode(text[start:])
            if isinstance(value, dict):
                return value
        except ValueError:
            pass
        start = text.find('{', start + 1)
    return None


def tail(text, limit=3000):
    text = text or ''
    return text if len(text) <= limit else '…' + text[-limit:]


# Users, linger, and cleanup.

def existing_users():
    return sorted(entry.pw_name for entry in pwd.getpwall() if entry.pw_name.startswith(USER_PREFIX))


def quiet(*argv, timeout=60):
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def remove_user(name):
    """Stop and remove the unit, disable linger, kill processes, delete the user and home."""
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return
    uid, home = entry.pw_uid, Path(entry.pw_dir)
    runtime = f'/run/user/{uid}'
    env = ['env', '-i', f'HOME={home}', f'USER={name}', f'LOGNAME={name}', f'XDG_RUNTIME_DIR={runtime}',
           'PATH=/usr/local/bin:/usr/bin:/bin']
    if Path(runtime, 'bus').exists():
        quiet('runuser', '-u', name, '--', *env, 'systemctl', '--user', 'disable', '--now', 'capsule.service')
    unit = home / '.config/systemd/user/capsule.service'
    if unit.exists() or unit.is_symlink():
        unit.unlink()
        if Path(runtime, 'bus').exists():
            quiet('runuser', '-u', name, '--', *env, 'systemctl', '--user', 'daemon-reload')
    quiet('loginctl', 'disable-linger', name)
    quiet('loginctl', 'terminate-user', name)
    quiet('systemctl', 'stop', f'user@{uid}.service')
    for _ in range(50):
        quiet('pkill', '-KILL', '-u', str(uid))
        if quiet('pgrep', '-u', str(uid)).returncode != 0:
            break
        time.sleep(0.2)
    result = quiet('userdel', '--remove', name)
    if result is None or result.returncode not in (0, 12):  # 12: could not remove the home (handled below)
        detail = result.stderr if result else 'timeout'
        if name in existing_users():
            raise RuntimeError(f'userdel {name} failed: {detail}')
    if home.exists() and home.name.startswith(USER_PREFIX):
        shutil.rmtree(home, ignore_errors=True)


def leftovers():
    """Anything the harness could have left behind."""
    found = {'users': existing_users(), 'homes': [], 'linger': [], 'processes': []}
    found['homes'] = sorted(str(p) for p in Path('/home').glob(USER_PREFIX + '*'))
    found['linger'] = sorted(p.name for p in Path('/var/lib/systemd/linger').glob(USER_PREFIX + '*'))
    ps = quiet('ps', '-eo', 'user:32,pid,args', '--no-headers')
    if ps is not None:
        found['processes'] = [line for line in ps.stdout.splitlines() if line.split(None, 1)[0].startswith(USER_PREFIX)]
    return found


# Coordinator and bundles, shared with live_launch_agents.py.

def start_coordinator(repo, work):
    """Build capsule-coord from the checkout and run it on loopback; returns (process, address, public key)."""
    binary = work / 'bin' / 'capsule-coord'
    binary.parent.mkdir(exist_ok=True)
    result = subprocess.run(['go', '-C', str(repo / 'go'), 'build', '-o', str(binary), './cmd/capsule-coord'],
                            capture_output=True, text=True, timeout=900)
    if result.returncode != 0:
        raise SystemExit('building capsule-coord failed:\n' + result.stderr[-4000:])
    state = work / 'coord'
    state.mkdir(mode=0o700)
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    address = f'127.0.0.1:{port}'
    log = open(work / 'coord.log', 'wb')
    process = subprocess.Popen([str(binary), '--state', str(state), 'run', '--listen', address],
                               stdout=log, stderr=log)
    deadline = time.monotonic() + 10
    while True:
        if process.poll() is not None:
            raise SystemExit('coordinator exited; see ' + str(work / 'coord.log'))
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                break
        except OSError:
            if time.monotonic() > deadline:
                process.kill()
                raise SystemExit('coordinator did not start')
            time.sleep(0.05)
    info = json.loads(subprocess.check_output([str(binary), '--state', str(state), 'info'], text=True))
    return process, address, info['public_key']


def package_bundles(repo, node, work, address, key, implementations):
    """scripts/package-release.sh for each implementation, with the coordinator as the default.

    Returns ({impl: (archive, checksum, bundle directory name)}, {impl: release metadata}).
    """
    dist = work / 'dist'
    dist.mkdir()
    env = dict(os.environ, PATH=f'{node.parent}:{os.environ.get("PATH", "")}',
               CAPSULE_COORDINATOR=address, CAPSULE_COORDINATOR_KEY=key, CAPSULE_PACKAGE_OVERWRITE='1')
    results, errors = {}, {}

    def build(impl):
        log = work / f'package-{impl}.log'
        with open(log, 'w') as out:
            result = subprocess.run([str(repo / 'scripts/package-release.sh'), impl, VERSION, str(dist)],
                                    stdout=subprocess.PIPE, stderr=out, text=True, env=env, timeout=3600)
        if result.returncode != 0:
            errors[impl] = f'package-release.sh {impl} exited {result.returncode}:\n' + tail(log.read_text())
        else:
            results[impl] = [Path(line) for line in result.stdout.split()[-2:]]

    threads = [threading.Thread(target=build, args=(impl,)) for impl in implementations]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise SystemExit('\n'.join(errors.values()))
    archives, release = {}, {}
    for impl, (archive, checksum) in sorted(results.items()):
        verify = subprocess.run(['sha256sum', '-c', checksum.name], cwd=dist, capture_output=True, text=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if verify.returncode != 0 or checksum.read_text().split()[0] != digest:
            raise SystemExit(f'checksum verification failed for {archive.name}: {verify.stdout}{verify.stderr}')
        with tarfile.open(archive) as bundle:
            root = bundle.getnames()[0].split('/')[0]
            metadata = json.load(bundle.extractfile(f'{root}/RELEASE.json'))
        archives[impl] = (archive, checksum, root)
        release[impl] = {'archive': archive.name, 'sha256': digest, 'checksum_verified': True, 'release': metadata}
        print(f'packaged {archive.name} (sha256 {digest[:16]}…, checksum verified)', flush=True)
    return archives, release


# The harness.

class Harness:
    def __init__(self, args, work):
        self.args = args
        self.work = work
        self.repo = args.repo.resolve()
        self.node = Path(shutil.which(str(args.node)) or args.node).resolve()
        self.users = []          # every user created, for cleanup
        self.processes = []      # background attaches, for cleanup
        self.coord = None
        self.next_user = 1
        self.archives = {}
        self.release = {}

    # Preparation.

    def check_prerequisites(self):
        problems = []
        if os.geteuid() != 0:
            problems.append('needs root')
        if sys.version_info < (3, 12):
            problems.append(f'needs Python 3.12 (found {platform.python_version()})')
        version = quiet('systemctl', '--version')
        match = re.search(r'systemd (\d+)', version.stdout if version else '')
        if not match or int(match.group(1)) < 250:
            problems.append('needs systemd 250 or newer')
        self.systemd = match.group(0) if match else None
        node = quiet(str(self.node), '--version')
        self.node_version = node.stdout.strip() if node and node.returncode == 0 else None
        if not self.node_version or int(self.node_version.lstrip('v').split('.')[0]) < 22:
            problems.append(f'needs Node 22 (--node {self.node}: {self.node_version})')
        for tool in ['runuser', 'useradd', 'userdel', 'loginctl', 'sha256sum', 'tar', 'go', 'npm', 'flock']:
            if not shutil.which(tool) and not (tool == 'npm' and (self.node.parent / 'npm').exists()):
                problems.append(f'missing {tool}')
        if existing_users():
            problems.append(f'users from an earlier run exist ({", ".join(existing_users())}); run with --cleanup')
        if problems:
            raise SystemExit('launch_acceptance: ' + '; '.join(problems))

    def start_coordinator(self):
        self.coord, self.coord_address, self.coord_key = start_coordinator(self.repo, self.work)

    def package(self, implementations):
        self.archives, self.release = package_bundles(self.repo, self.node, self.work, self.coord_address,
                                                      self.coord_key, implementations)

    def share_node(self):
        directory = self.work / 'node' / 'bin'
        directory.mkdir(parents=True)
        shutil.copy2(self.node, directory / 'node')
        for path in [self.work, self.work / 'node', directory]:
            path.chmod(0o755)
        (directory / 'node').chmod(0o755)
        self.shared_node = directory

    # Runs.

    def new_machine(self, label, impl):
        name = f'{USER_PREFIX}{self.next_user}'
        self.next_user += 1
        machine = Machine(self, label, name, impl)
        self.users.append(name)
        machine.create()
        return machine

    def stop_processes(self, processes):
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

    def cleanup_users(self, names):
        errors = []
        for name in names:
            try:
                remove_user(name)
            except Exception as error:  # keep cleaning the others
                errors.append(f'{name}: {error}')
        return errors

    def close(self):
        self.stop_processes(self.processes)
        errors = []
        if not self.args.keep:
            errors = self.cleanup_users(self.users)
        if self.coord is not None and self.coord.poll() is None:
            self.coord.terminate()
            try:
                self.coord.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.coord.kill()
        return errors


class Machine:
    def __init__(self, harness, label, user, impl):
        self.harness, self.label, self.user, self.impl = harness, label, user, impl
        self.attach_process = None

    def create(self):
        h = self.harness
        subprocess.run(['useradd', '--create-home', '--shell', '/bin/bash', '--user-group', self.user],
                       check=True, capture_output=True, text=True)
        entry = pwd.getpwnam(self.user)
        self.uid, self.gid, self.home = entry.pw_uid, entry.pw_gid, Path(entry.pw_dir)
        self.runtime = f'/run/user/{self.uid}'
        # As a login would: the user's systemd manager runs before the path.
        subprocess.run(['loginctl', 'enable-linger', self.user], check=True, capture_output=True, text=True)
        wait_for(lambda: (Path(self.runtime, 'bus').exists()
                          and quiet('systemctl', 'is-active', f'user@{self.uid}.service').stdout.strip() == 'active',
                          'user manager'), 30, f'{self.user}\'s systemd user manager')
        archive, checksum, root = h.archives[self.impl]
        for source in [archive, checksum]:
            shutil.copy(source, self.home / source.name)
            os.chown(self.home / source.name, self.uid, self.gid)
        self.bundle_bin = self.home / root / 'bin'
        self.env = {
            'HOME': str(self.home), 'USER': self.user, 'LOGNAME': self.user, 'SHELL': '/bin/bash',
            'LANG': 'C.UTF-8', 'XDG_RUNTIME_DIR': self.runtime,
            'PATH': f'{self.bundle_bin}:{self.home}/.local/bin:{h.shared_node}:/usr/local/bin:/usr/bin:/bin',
        }
        self.project = self.home / 'src' / 'project'
        for argv in (['sha256sum', '-c', checksum.name], ['tar', '-xzf', archive.name],
                     ['mkdir', '-p', str(self.home / '.local/bin'), str(self.project)]):
            result = self.run(argv)
            if result.returncode != 0:
                raise Failure(f'{self.label} preparation {" ".join(argv)} failed: {result.stdout}{result.stderr}')
        fixture = self.home / '.local/bin/claude'
        fixture.write_text(FIXTURE)
        fixture.chmod(0o755)
        os.chown(fixture, self.uid, self.gid)

    def argv(self, argv):
        return ['runuser', '-u', self.user, '--', 'env', '-i', *[f'{k}={v}' for k, v in self.env.items()], *argv]

    def run(self, argv, cwd=None, timeout=STEP_TIMEOUT):
        try:
            return subprocess.run(self.argv(argv), cwd=cwd or self.home, capture_output=True, text=True,
                                  timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as error:
            return subprocess.CompletedProcess(argv, 124, error.stdout or '', f'timed out after {timeout}s')

    def capsule_json(self, *args, cwd=None):
        result = self.run(['capsule', *args], cwd=cwd)
        return result, first_json(result.stdout)

    def fixture_log(self):
        path = self.home / '.claude-fixture' / 'log.jsonl'
        if not path.exists():
            return []
        entries = []
        for line in path.read_text().splitlines():
            try:
                entries.append(json.loads(line))
            except ValueError:
                pass
        return entries


class Run:
    def __init__(self, harness, name):
        self.h = harness
        self.name = name
        self.path, self.implementations = RUNS[name]
        self.machines = []
        self.commands = []
        self.checks = []
        self.attached = {}  # machine label -> attach output object
        self.notes = []
        self.nonce = os.urandom(3).hex()
        self.last_machine = None

    def handoff(self, machine, attach=False):
        """--pace: wait when the path moves to another machine, before each attach, and before the checks."""
        waited = None
        if self.last_machine is not None and (attach or machine.label != self.last_machine) and self.h.args.pace:
            time.sleep(self.h.args.pace)
            waited = self.h.args.pace
        self.last_machine = machine.label
        return waited

    # Counted steps.

    def step(self, machine, command, substitutions=None, cwd=None):
        """Run one counted Capsule command as the user typed it; return its parsed output."""
        argv = command.split() if isinstance(command, str) else command
        shown = ' '.join(argv)
        for value, placeholder in (substitutions or {}).items():
            shown = shown.replace(value, placeholder)
        waited = self.handoff(machine)
        started = time.monotonic()
        result = machine.run(argv, cwd=cwd)
        record = {'machine': machine.label, 'user': machine.user, 'implementation': machine.impl,
                  'command': shown, 'kind': 'capsule', 'cwd': '~' + str((cwd or machine.home))[len(str(machine.home)):],
                  'exit': result.returncode, 'seconds': round(time.monotonic() - started, 2)}
        if waited:
            record['paced_seconds'] = waited
        if substitutions:
            record['taken_from_output'] = {placeholder: source for placeholder, source in
                                           ((p, s) for p, s in self.sources.items() if p in substitutions.values())}
        self.commands.append(record)
        print(f'  {machine.label}$ {shown} -> exit {result.returncode}', flush=True)
        if result.returncode != 0:
            raise Failure(f'{machine.label} ({machine.user}, {machine.impl}): `{shown}` exited {result.returncode}\n'
                          f'stdout: {tail(result.stdout)}\nstderr: {tail(result.stderr)}')
        return result

    def copy_key(self, source, target):
        """The one counted non-Capsule step: the person key files to the same place."""
        command = 'copy ~/.config/capsule/person_ed25519 and person_ed25519.pub from M1 to the same place on M2'
        waited = self.handoff(target)
        directory = target.home / '.config' / 'capsule'
        for path in [target.home / '.config', directory]:
            if not path.exists():
                path.mkdir(mode=0o700)
                os.chown(path, target.uid, target.gid)
        exit_code = 0
        for name, mode in [('person_ed25519', 0o600), ('person_ed25519.pub', 0o644)]:
            origin = source.home / '.config' / 'capsule' / name
            if not origin.exists():
                exit_code = 1
                break
            shutil.copyfile(origin, directory / name)
            os.chown(directory / name, target.uid, target.gid)
            (directory / name).chmod(mode)
        self.commands.append({'machine': f'{source.label}→{target.label}', 'command': command, 'kind': 'copy',
                              'exit': exit_code, **({'paced_seconds': waited} if waited else {})})
        print(f'  {source.label}→{target.label}: {command} -> exit {exit_code}', flush=True)
        if exit_code:
            raise Failure(f'{source.label} has no ~/.config/capsule/person_ed25519 to copy')

    def attach(self, machine):
        """`capsule attach claude` in the project, kept running in the background."""
        out = open(self.h.work / f'{self.name}-{machine.label}-attach.out', 'w+')
        err = open(self.h.work / f'{self.name}-{machine.label}-attach.err', 'w+')
        waited = self.handoff(machine, attach=True)
        before = len(machine.fixture_log())
        process = subprocess.Popen(machine.argv(['capsule', 'attach', 'claude']), cwd=machine.project,
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        machine.attach_process = process
        self.h.processes.append(process)
        record = {'machine': machine.label, 'user': machine.user, 'implementation': machine.impl,
                  'command': 'capsule attach claude', 'kind': 'capsule', 'cwd': '~/src/project',
                  'background': True, 'exit': None}
        if waited:
            record['paced_seconds'] = waited
        self.commands.append(record)

        def launched():
            log = machine.fixture_log()[before:]
            ready = [e for e in log if e.get('event') == 'tools' and e.get('tools')]
            if ready:
                return True, log
            if process.poll() is not None:
                return None
            return False, 'fixture claude not ready'

        deadline = time.monotonic() + LAUNCH_SECONDS
        log = None
        while time.monotonic() < deadline:
            state = launched()
            if state is None:
                break
            if state[0]:
                log = state[1]
                break
            time.sleep(0.5)
        err.seek(0)
        out.seek(0)
        stderr, stdout = err.read(), out.read()
        if log is None:
            record['exit'] = process.poll()
            print(f'  {machine.label}$ capsule attach claude -> exit {record["exit"]} (no launch)', flush=True)
            raise Failure(
                f'{machine.label} ({machine.user}, {machine.impl}): `capsule attach claude` '
                + (f'exited {record["exit"]} without launching Claude Code' if record['exit'] is not None
                   else f'did not start the fixture claude within {LAUNCH_SECONDS}s')
                + f'\nstdout: {tail(stdout)}\nstderr: {tail(stderr)}\nfixture log: {machine.fixture_log()[before:]}')
        output = first_json(stderr)
        record['launched'] = True
        print(f'  {machine.label}$ capsule attach claude -> launched (running)', flush=True)
        if not output or not (output.get('agent') or {}).get('address'):
            raise Failure(f'{machine.label}: attach printed no output object with the address on stderr before '
                          f'launching\nstderr: {tail(stderr)}')
        launch = next(e for e in log if e.get('event') == 'launched')
        record['output'] = {key: output.get(key) for key in ('agent', 'reused', 'unchecked_hosts', 'next')}
        output['_launch'] = {'arguments': launch.get('arguments'), 'cwd': launch.get('cwd')}
        self.attached[machine.label] = output
        return output

    # The documented paths.

    def run_path(self):
        h = self.h
        labels = [f'M{i + 1}' for i in range(len(self.implementations))]
        for label, impl in zip(labels, self.implementations):
            self.machines.append(h.new_machine(label, impl))
        print(f'{self.name}: machines ' + ', '.join(f'{m.label}={m.user} ({m.impl})' for m in self.machines), flush=True)
        self.sources = {}
        getattr(self, 'path_' + self.path)(*self.machines)

    def token(self, machine, result, who):
        match = re.search(r'capsule join ([^\s"\']+)', result.stdout)
        if not match:
            raise Failure(f'{machine.label}: `capsule invite {who}` output lacks the `capsule join TOKEN` line: '
                          f'{tail(result.stdout)}')
        return match.group(1)

    def label_of(self, machine, result):
        output = first_json(result.stdout) or {}
        label = output.get('member') or ((output.get('person') or {}).get('label'))
        if not label:
            raise Failure(f'{machine.label}: `capsule network create acme` output names no member label: '
                          f'{tail(result.stdout)}')
        return label

    def path_solo(self, m1, m2):
        self.step(m1, 'capsule install')
        label = self.label_of(m1, self.step(m1, 'capsule network create acme'))
        self.sources['LABEL'] = 'the member label printed by M1 `capsule network create acme`'
        token = self.token(m1, self.step(m1, ['capsule', 'invite', label]), label)
        self.sources['TOKEN'] = f'the join line printed by M1 `capsule invite {label}`'
        self.attach(m1)
        self.copy_key(m1, m2)
        self.step(m2, 'capsule install')
        self.step(m2, ['capsule', 'join', token], {token: 'TOKEN'})
        self.attach(m2)
        self.person_labels = {m1.label: label, m2.label: label}

    def path_pair(self, m1, m2):
        self.step(m1, 'capsule install')
        alice = self.label_of(m1, self.step(m1, 'capsule network create acme'))
        token = self.token(m1, self.step(m1, 'capsule invite bob'), 'bob')
        self.sources['TOKEN'] = 'the join line printed by M1 `capsule invite bob`'
        self.sources['ALICE'] = 'the member label printed by M1 `capsule network create acme` (her login name)'
        self.step(m2, 'capsule install')
        self.step(m2, ['capsule', 'join', token], {token: 'TOKEN'})
        self.step(m2, ['capsule', 'allow', alice])
        self.attach(m2)
        self.step(m1, 'capsule allow bob')
        self.attach(m1)
        self.person_labels = {m1.label: alice, m2.label: 'bob'}
        self.notes.append(f'alice is the person label network create takes from M1\'s login name ({alice}); '
                          'bob types it in `capsule allow`.')

    def path_team(self, m1, m2, m3):
        self.step(m1, 'capsule install')
        alice = self.label_of(m1, self.step(m1, 'capsule network create acme'))
        tokens = {}
        for who in ['bob', 'carol']:
            tokens[who] = self.token(m1, self.step(m1, ['capsule', 'invite', who]), who)
            self.sources[f'TOKEN_{who.upper()}'] = f'the join line printed by M1 `capsule invite {who}`'
        self.step(m1, 'capsule allow everyone')
        self.attach(m1)
        for machine, who in [(m2, 'bob'), (m3, 'carol')]:
            self.step(machine, 'capsule install')
            self.step(machine, ['capsule', 'join', tokens[who]], {tokens[who]: f'TOKEN_{who.upper()}'})
            self.step(machine, 'capsule allow everyone')
            self.attach(machine)
        self.person_labels = {m1.label: alice, m2.label: 'bob', m3.label: 'carol'}

    # Uncounted checks.

    def check(self, name, machine, function):
        try:
            detail = function()
            passed = True
        except Failure as error:
            detail, passed = str(error), False
        except Exception as error:
            detail, passed = f'{type(error).__name__}: {error}', False
        entry = {'check': name, 'machine': machine.label if machine else None, 'passed': passed, 'detail': detail}
        self.checks.append(entry)
        print(f'  check {"PASS" if passed else "FAIL"} {entry["machine"] or ""} {name}'
              + ('' if passed else f': {tail(str(detail), 1500)}'), flush=True)
        return passed

    def counts(self):
        counts = {}
        for command in self.commands:
            counts[command['kind']] = counts.get(command['kind'], 0) + 1
        return counts

    def run_checks(self):
        expected = EXPECTED_COUNTS[self.path]

        def counted():
            if self.counts() != expected:
                raise Failure(f'counts {self.counts()} differ from the documented {expected}')
            return self.counts()
        self.check('counts match the documented path', None, counted)

        addresses = {label: out['agent']['address'] for label, out in self.attached.items()}
        names = {label: out['agent']['name'] for label, out in self.attached.items()}

        def naming():
            want = {m.label: 'claude' for m in self.machines}
            if self.path == 'solo':
                want['M2'] = ('claude-' + SHORT_HOST)[:64]
            for m in self.machines:
                want_address = f'{self.person_labels[m.label]}/{want[m.label]}'
                if names[m.label] != want[m.label] or addresses[m.label].lower() != want_address.lower():
                    raise Failure(f'agents {names} at {addresses}; expected names {want}')
            return addresses
        self.check('attach names and addresses' + (' (M2 is claude-HOSTNAME)' if self.path == 'solo' else ''),
                   None, naming)

        for m in self.machines:
            self.check('adapter connected through the fixture launched by attach', m,
                       lambda m=m: self.check_connected(m))
        for m in self.machines:
            self.check('status --json exits 0; service installed, active, linger', m,
                       lambda m=m: self.check_status(m))
        for m in self.machines:
            others = {label: address for label, address in addresses.items() if label != m.label}
            self.check('agents --json lists every other agent with message.append and task.submit', m,
                       lambda m=m, others=others: self.check_agents(m, others))
        cite = 'self' if self.path == 'solo' else 'policy'
        for m in self.machines:
            for label, address in addresses.items():
                if label == m.label:
                    continue
                target = next(x for x in self.machines if x.label == label)
                self.check(f'send {address} ends accepted, citing {cite}', m,
                           lambda m=m, a=address, t=target: self.check_send(m, a, t, cite))
                self.check(f'task {address} reaches the receiver, citing {cite}', m,
                           lambda m=m, a=address, t=target: self.check_task(m, a, t, cite))

    def check_connected(self, machine):
        output = self.attached[machine.label]
        launch = output['_launch']
        arguments = launch['arguments'] or []
        if launch['cwd'] != str(machine.project.resolve()):
            raise Failure(f'the fixture ran in {launch["cwd"]}, not the project')
        if '--dangerously-load-development-channels' not in arguments:
            raise Failure(f'launch arguments {arguments}')
        log = machine.fixture_log()
        initialized = [e for e in log if e.get('event') == 'initialized']
        if not initialized or initialized[-1].get('error'):
            raise Failure(f'MCP initialize failed: {initialized}')
        if any(e.get('event') == 'server_exited' for e in log):
            raise Failure('the MCP adapter exited: ' + json.dumps([e for e in log if e.get('event') == 'server_exited']))
        tools = next(e for e in reversed(log) if e.get('event') == 'tools')['tools']
        for tool in ['list_agents', 'send', 'delegate_task']:
            if tool not in tools:
                raise Failure(f'adapter tools {tools} lack {tool}')
        agent_id = output['agent']['id']

        def connected():
            result, value = machine.capsule_json('agents', '--json')
            if result.returncode != 0 or not value:
                return False, f'exit {result.returncode}: {tail(result.stderr)}'
            mine = [e for e in value.get('mine', []) if e.get('agent_id') == agent_id]
            return bool(mine and mine[0].get('connected') is True), mine or value.get('mine')
        mine = wait_for(connected, CHECK_SECONDS, f'{machine.label}\'s own agent connected in agents --json')
        return {'tools': tools, 'mine': mine, 'launch_arguments': arguments}

    def check_status(self, machine):
        def status():
            result, value = machine.capsule_json('status', '--json')
            service = (value or {}).get('service')
            good = (result.returncode == 0 and service
                    and service.get('installed') is True and service.get('active') is True
                    and service.get('linger') is True and service.get('manager') == 'systemd')
            return good, {'exit': result.returncode, 'service': service,
                          'attention': (value or {}).get('attention'), 'stderr': tail(result.stderr, 500)}
        return wait_for(status, CHECK_SECONDS, f'{machine.label} status --json')

    def check_agents(self, machine, others):
        refresh = []

        def listed():
            args = ['agents', '--json'] + (['--refresh'] if refresh else [])
            refresh.append(True)
            result, value = machine.capsule_json(*args)
            if result.returncode != 0 or not value:
                return False, f'exit {result.returncode}: {tail(result.stderr)}'
            reachable = {e.get('address'): e for e in value.get('reachable', [])}
            missing = []
            for label, address in others.items():
                entry = reachable.get(address)
                if not entry or not {'message.append', 'task.submit'} <= set(entry.get('actions') or []):
                    missing.append(address)
            return not missing, {'missing': missing, 'reachable': list(reachable.values())}
        value = wait_for(listed, CHECK_SECONDS, f'{machine.label} agents --json listing {sorted(others.values())}')
        return {address: next(e for e in value['reachable'] if e['address'] == address)['actions']
                for address in others.values()}

    def cites(self, request, cite):
        if cite == 'self':
            return request.get('self') is not None and not request.get('policy') and not request.get('grant_id')
        return request.get('policy') is not None and not request.get('self') and not request.get('grant_id')

    def check_send(self, machine, address, target, cite):
        text = f'acceptance message {self.nonce} from {machine.label} to {address}'
        result, value = machine.capsule_json('send', address, text)
        if result.returncode != 0 or not value:
            raise Failure(f'`capsule send {address} TEXT` exited {result.returncode}: '
                          f'{tail(result.stdout)}{tail(result.stderr)}')
        if value.get('state') != 'accepted':
            raise Failure(f'state {value.get("state")}: {value}')
        request = value.get('request') or {}
        if not self.cites(request, cite):
            raise Failure(f'the send does not cite {cite}: '
                          f'{ {k: request.get(k) for k in ("self", "policy", "grant_id")} }')
        delivered = self.received(target, text, seconds=20)
        return {'state': value['state'], 'cited': cite, 'in_receiver_session': delivered}

    def check_task(self, machine, address, target, cite):
        text = f'acceptance task {self.nonce} from {machine.label} to {address}'
        result, value = machine.capsule_json('task', address, text)
        if result.returncode != 0 or not value:
            raise Failure(f'`capsule task {address} TEXT` exited {result.returncode}: '
                          f'{tail(result.stdout)}{tail(result.stderr)}')
        if value.get('submit_state') != 'accepted':
            raise Failure(f'submit_state {value.get("submit_state")}: {value}')
        request = value.get('request') or {}
        if not self.cites(request, cite):
            raise Failure(f'the task does not cite {cite}: '
                          f'{ {k: request.get(k) for k in ("self", "policy", "grant_id")} }')
        if not self.received(target, text, seconds=CHECK_SECONDS):
            raise Failure(f'{target.label}\'s session received no channel event with the task text')
        return {'submit_state': value['submit_state'], 'cited': cite, 'in_receiver_session': True}

    def received(self, target, text, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            for entry in target.fixture_log():
                if entry.get('event') == 'notification' and text in json.dumps(entry.get('message')):
                    return True
            time.sleep(0.5)
        return False

    def report(self, error):
        return {
            'run': self.name,
            'path': self.path,
            'implementations': {m.label: m.impl for m in self.machines} or
                               {f'M{i + 1}': impl for i, impl in enumerate(self.implementations)},
            'users': {m.label: m.user for m in self.machines},
            'commands': self.commands,
            'counts': self.counts(),
            'expected_counts': EXPECTED_COUNTS[self.path],
            'addresses': {label: out['agent']['address'] for label, out in self.attached.items()},
            'checks': self.checks,
            'notes': self.notes,
            'passed': error is None and bool(self.checks) and all(c['passed'] for c in self.checks),
            'error': error,
        }


def execute(harness, name):
    run = Run(harness, name)
    error = None
    try:
        run.run_path()
        print(f'{name}: path complete; checking', flush=True)
        if harness.args.pace:
            time.sleep(harness.args.pace)
        run.run_checks()
    except Failure as failure:
        error = str(failure)
        print(f'{name}: FAILED: {tail(error, 4000)}', flush=True)
    except Exception:
        error = traceback.format_exc()
        print(f'{name}: ERROR: {error}', flush=True)
    finally:
        harness.stop_processes([m.attach_process for m in run.machines if m.attach_process])
        if not harness.args.keep:
            cleanup = harness.cleanup_users([m.user for m in run.machines])
            if cleanup:
                error = (error or '') + '\ncleanup: ' + '; '.join(cleanup)
    report = run.report(error)
    print(f'{name}: {"PASS" if report["passed"] else "FAIL"} {report["counts"]}', flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--node', type=Path, default=Path('node'), help='Node 22 executable to give the machines')
    parser.add_argument('--run', action='append', choices=sorted(RUNS), help='run only these (repeatable)')
    parser.add_argument('--repo', type=Path, default=REPO, help='checkout to package and build the coordinator from')
    parser.add_argument('--output', type=Path, default=REPO / 'docs/results/launch-acceptance.json')
    parser.add_argument('--pace', type=float, default=0,
                        help='seconds to wait whenever the path moves to another machine, before each attach, and '
                             'before the checks (default 0: none); a diagnostic for coordination latency, '
                             'recorded in the results; acceptance runs use 0')
    parser.add_argument('--keep', action='store_true', help='leave users, units, and the work directory')
    parser.add_argument('--cleanup', action='store_true', help=f'remove every {USER_PREFIX}N user and exit')
    args = parser.parse_args()
    if args.cleanup:
        if os.geteuid() != 0:
            raise SystemExit('needs root')
        for name in existing_users():
            remove_user(name)
        for path in Path('/var/tmp').glob('capsule-acceptance-*'):
            shutil.rmtree(path, ignore_errors=True)
        print(json.dumps(leftovers(), indent=2))
        return
    selected = [name for name in RUNS if not args.run or name in args.run]

    def interrupted(number, _frame):
        raise KeyboardInterrupt(f'signal {number}')
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)

    work = Path(tempfile.mkdtemp(prefix='capsule-acceptance-', dir='/var/tmp'))
    work.chmod(0o755)
    (work / 'bin').mkdir()
    harness = Harness(args, work)
    reports = []
    cleanup_errors = []
    try:
        harness.check_prerequisites()
        harness.share_node()
        harness.start_coordinator()
        print(f'coordinator on {harness.coord_address}', flush=True)
        harness.package(sorted({impl for name in selected for impl in RUNS[name][1]}))
        for name in selected:
            reports.append(execute(harness, name))
    finally:
        cleanup_errors = harness.close()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f'kept {work} and users {", ".join(harness.users)}; remove with --cleanup', flush=True)
    remaining = leftovers() if not args.keep else None
    result = {
        'checked_at': now(),
        'contract': 'docs/launch-contract.md, Slice 5: acceptance (scripted run); path from docs/quick-start.md',
        'environment': {'systemd': harness.systemd, 'node': harness.node_version,
                        'python': platform.python_version(), 'kernel': platform.release(),
                        'architecture': platform.machine()},
        'pace_seconds': args.pace,
        'coordinator': 'capsule-coord from the checkout on loopback, built into the bundles as the default',
        'release': harness.release,
        'runs': reports,
        'passed': bool(reports) and all(r['passed'] for r in reports) and len(reports) == len(selected),
        'cleanup': {'errors': cleanup_errors, 'leftovers': remaining} if remaining is not None else 'kept (--keep)',
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(f'wrote {args.output}', flush=True)
    for report in reports:
        print(f'{"PASS" if report["passed"] else "FAIL"} {report["run"]}: {report["counts"]}', flush=True)
    if remaining and any(remaining.values()):
        print('LEFTOVERS: ' + json.dumps(remaining), flush=True)
    sys.exit(0 if result['passed'] and not cleanup_errors else 1)


if __name__ == '__main__':
    main()
