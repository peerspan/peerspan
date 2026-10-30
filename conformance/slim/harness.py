"""Small shared harness for the slim conformance suites (DEC-OWN6, DEC-OWN9).

Starts real `peerspan-host` daemons on loopback, each in its own temporary
home and state directory, and drives them through the public CLI and the
owner-local API on `admin.sock`. Written from the spec in docs/ only.
"""
from __future__ import annotations

import argparse
import atexit
import base64
import http.client
import json
import os
import pty
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path


def redact(text):
    """Invite and request codes are secret (appendix 10): never print them."""
    import re
    return re.sub(r"ps[il]2-[A-Za-z0-9_-]+", "<code>", text)


class Failure(AssertionError):
    pass


class Skip(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


def wait_for(predicate, timeout=20.0, interval=0.2, message="condition"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise Failure(f"timed out after {timeout:.0f}s waiting for {message}")


def rfc3339(moment):
    return moment.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def in_future(**delta):
    return rfc3339(datetime.now(timezone.utc) + timedelta(**delta))


def parse_time(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def free_port(kind=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Result:
    """One CLI run: exit code, decoded JSON stdout (or None) and raw text."""

    def __init__(self, args, code, stdout, stderr):
        self.args, self.code, self.stdout, self.stderr = args, code, stdout, redact(stderr)
        try:
            self.json = json.loads(stdout) if stdout.strip() else None
        except ValueError:
            self.json = None

    @property
    def ok(self):
        return self.code == 0

    def __repr__(self):
        err = self.stderr.strip().splitlines()[-1:] if self.stderr.strip() else []
        return f"<{' '.join(self.args[:3])} exit={self.code} stderr={err}>"


class Host:
    def __init__(self, suite, name):
        self.suite, self.name = suite, name
        self.root = suite.work / name
        self.home = self.root / "home"
        self.state = self.root / "state"
        for d in (self.root, self.home, self.state):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o700)
        self.peer_port = free_port()
        self.bootstrap_port = free_port(socket.SOCK_STREAM)
        self.process = None
        self.log = self.root / "daemon.log"
        self.id = None
        self.public_key = None
        self.extra_env = {}
        self.extra_args = []  # more `run` flags, such as --transport-config
        self.clock = None  # a Clock of its own, else the suite's

    @property
    def env(self):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_STATE_HOME": str(self.home / ".state"),
            "XDG_RUNTIME_DIR": str(self.home / ".run"),
            "LANG": "C.UTF-8",
            "USER": self.name,
            "LOGNAME": self.name,
        }
        clock = self.clock or self.suite.clock
        if clock is not None:
            env["PEERSPAN_TEST_CLOCK_OFFSET_FILE"] = str(clock.path)
        env.update(self.extra_env)
        return env

    def now(self):
        """This host's now, on its test clock if it has one."""
        clock = self.clock or self.suite.clock
        return clock.now() if clock else datetime.now(timezone.utc)

    @property
    def peer_address(self):
        return f"127.0.0.1:{self.peer_port}"

    def start(self):
        check(self.process is None, f"{self.name} already running")
        log = self.log.open("ab")
        self.process = subprocess.Popen(
            [str(self.suite.host_bin), "--state", str(self.state), "run", "--peer-listen", self.peer_address,
             "--bootstrap-listen", f"127.0.0.1:{self.bootstrap_port}", *map(str, self.extra_args)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=self.env, start_new_session=True)
        log.close()
        sock = self.state / "admin.sock"
        wait_for(lambda: sock.exists() and self._ping(), timeout=30, message=f"{self.name} admin socket")
        info = self.api("GET", "/v1/host")[1]
        self.id, self.public_key = info["id"], info["public_key"]
        return self

    def _ping(self):
        try:
            return self.api("GET", "/v1/host")[0] == 200
        except OSError:
            return False

    def stop(self, kill=False):
        if self.process is None:
            return
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL if kill else signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        self.process = None

    def restart(self, kill=False):
        self.stop(kill=kill)
        return self.start()

    def api(self, method, path, body=None, timeout=60):
        conn = UnixHTTPConnection(str(self.state / "admin.sock"), timeout=timeout)
        try:
            payload = None if body is None else json.dumps(body).encode()
            headers = {"Content-Type": "application/json"} if payload is not None else {}
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            data = response.read()
        finally:
            conn.close()
        try:
            value = json.loads(data) if data.strip() else None
        except ValueError:
            value = data.decode(errors="replace")
        return response.status, value

    def cli(self, *args, input=None, tty=False, timeout=60, env=None):
        began = time.monotonic()
        try:
            return self._cli(*args, input=input, tty=tty, timeout=timeout, env=env)
        finally:
            if os.environ.get("SLIM_TRACE"):
                print(f"  [{self.name}] {' '.join(map(str, args[:2]))} {time.monotonic() - began:.1f}s",
                      file=sys.stderr, flush=True)

    def _cli(self, *args, input=None, tty=False, timeout=60, env=None):
        argv = [str(self.suite.host_bin), "--state", str(self.state), *map(str, args)]
        environment = {**self.env, **(env or {})}
        if tty:
            return self._cli_tty(argv, args, input or "", timeout, environment)
        try:
            p = subprocess.run(argv, input=(input or "").encode(), capture_output=True, env=environment,
                               timeout=timeout, cwd=str(self.root))
        except subprocess.TimeoutExpired as error:
            raise Failure(f"{self.name}: `{' '.join(map(str, args[:3]))}` did not finish within {timeout}s") from error
        return Result(list(map(str, args)), p.returncode, p.stdout.decode(errors="replace"),
                      p.stderr.decode(errors="replace"))

    def _cli_tty(self, argv, args, text, timeout, environment):
        master, slave = pty.openpty()
        p = subprocess.Popen(argv, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                             start_new_session=True, cwd=str(self.root))
        os.close(slave)
        try:
            os.write(master, text.encode())
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            raise Failure(f"{self.name}: `{' '.join(map(str, args[:3]))}` did not finish within {timeout}s") from error
        finally:
            os.close(master)
        return Result(list(map(str, args)), p.returncode, out.decode(errors="replace"), err.decode(errors="replace"))

    def ok(self, *args, **kw):
        result = self.cli(*args, **kw)
        check(result.ok, f"{self.name}: `{' '.join(map(str, args[:4]))}` failed: exit {result.code}: "
                         f"{result.stderr.strip()[-400:]}")
        return result.json

    def ok_incomplete(self, *args, **kw):
        """A link step: exit 0, or exit 1 with "linking is incomplete" (more stages follow)."""
        result = self.cli(*args, **kw)
        check(result.ok or (result.code == 1 and "linking is incomplete" in result.stderr),
              f"{self.name}: `{' '.join(map(str, args[:3]))}` failed: exit {result.code}: "
              f"{result.stderr.strip()[-400:]}")
        return result.json

    # Agents, through the owner API and the adapter socket.

    def agent(self, name, directory=True, calls=False, ready=True):
        """Register agent NAME and connect a fixture adapter session for it."""
        status, agent = self.api("POST", "/v1/agents", {"name": name, "owner": self.name})
        check(status in (200, 201), f"{self.name}: register {name}: {status} {agent}")
        return self.attach(agent, directory=directory, calls=calls, ready=ready)

    def attach(self, agent, directory=True, calls=False, ready=True, protocol_version=None):
        """Set up a fresh session and credential for an existing AGENT and connect a fixture adapter to it."""
        session_id = "session_" + os.urandom(16).hex()
        body = {"agent_id": agent["id"], "session_id": session_id, "integration": "fixture",
                "expires_at": rfc3339(self.now() + timedelta(hours=2))}
        if directory:
            body["directory"] = True
        if calls:
            body["calls"] = True
        status, setup = self.api("POST", "/v1/adapters/setup", body)
        check(status == 201, f"{self.name}: adapter setup for {agent['name']}: {status} {setup}")
        adapter = Adapter(self, agent, session_id, setup["credential"])
        adapter.setup = setup
        adapter.connect(ready=ready, protocol_version=protocol_version)
        return adapter


class Adapter:
    """A deterministic fixture agent: one adapter session on the host's adapter socket.

    A background thread renews its 15-second lease every 5 seconds (adapter recovery contract).
    """

    def __init__(self, host, agent, session_id, credential):
        self.host, self.agent, self.session_id = host, agent, session_id
        self.id, self.name = agent["id"], agent["name"]
        self.adapter_id, self.token = credential["adapter"]["id"], credential["token"]
        self.instance = "instance_" + os.urandom(32).hex()
        self._stop = False
        self._thread = None

    def connect(self, ready=True, protocol_version=None):
        body = {"adapter_id": self.adapter_id, "session_id": self.session_id, "instance_id": self.instance}
        if protocol_version is not None:
            body["protocol_version"] = protocol_version
        status, body = self.call("POST", "/adapter/v1/connect", body)
        check(status == 200, f"{self.host.name}: adapter connect {self.name}: {status} {body}")
        if ready:
            self.ready()
        if self._thread is None:
            import threading
            self._thread = threading.Thread(target=self._renew, daemon=True)
            self._thread.start()
        return body

    def ready(self, nonce=None):
        """The fixture plays the model's `peerspan_ready` (live delivery contract, slice 1)."""
        status, ready = self.post("/adapter/v1/ready", {"nonce": nonce or os.urandom(16).hex()})
        check(status == 200, f"{self.host.name}: adapter ready {self.name}: {status} {ready}")
        return ready

    def stop(self):
        """Stop renewing the lease, as an adapter process that exited would."""
        self._stop = True

    def _renew(self):
        while not self._stop:
            time.sleep(4)
            try:
                self.call("POST", "/adapter/v1/connect", {
                    "adapter_id": self.adapter_id, "session_id": self.session_id, "instance_id": self.instance})
            except OSError:
                pass

    def call(self, method, path, body=None, timeout=30):
        conn = UnixHTTPConnection(str(self.host.state / "adapter.sock"), timeout=timeout)
        try:
            payload = None if body is None else json.dumps(body).encode()
            headers = {"Authorization": f"Bearer {self.token}", "X-Peerspan-Instance": self.instance}
            if payload is not None:
                headers["Content-Type"] = "application/json"
            try:
                conn.request(method, path, body=payload, headers=headers)
            except BrokenPipeError:
                # A router may answer404 and close before a rejected body is
                # sent. Read that actual response; never retry or accept a
                # transport error in place of the caller's status assertions.
                pass
            response = conn.getresponse()
            data = response.read()
        finally:
            conn.close()
        try:
            value = json.loads(data) if data.strip() else None
        except ValueError:
            value = data.decode(errors="replace")
        return response.status, value

    def post(self, path, body=None):
        return self.call("POST", path, {} if body is None else body)

    def next_message(self, timeout=20):
        def claim():
            status, body = self.post("/adapter/v1/next")
            check(status == 200, f"{self.name}: next: {status} {body}")
            return body
        return wait_for(claim, timeout=timeout, interval=0.3, message=f"a message for {self.name}")

    def next_task(self, timeout=20):
        def claim():
            status, body = self.post("/adapter/v1/tasks/next")
            check(status == 200, f"{self.name}: tasks/next: {status} {body}")
            return body
        return wait_for(claim, timeout=timeout, interval=0.3, message=f"a task for {self.name}")


class Clock:
    """A debug test clock: an offset file that every process of the hosts using it reads (developer guide)."""

    def __init__(self, path):
        self.path = Path(path)
        self.offset = 0
        self.set(0)

    def set(self, seconds):
        """Move to real time + SECONDS, rewriting the file atomically as the developer guide asks."""
        self.offset = int(seconds)
        temporary = self.path.with_suffix(".new")
        temporary.write_text(("-" if seconds < 0 else "+") + f"{abs(int(seconds))}s\n")
        temporary.replace(self.path)

    def now(self):
        return datetime.now(timezone.utc) + timedelta(seconds=self.offset)


class Suite:
    """Runs named cases, one PASS/FAIL/SKIP line each, and keeps going."""

    def __init__(self, name, description):
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("--bin", type=Path, default=None,
                            help="directory holding peerspan-host (default: rust/target/debug)")
        parser.add_argument("--only", action="append", default=[], help="run only these cases")
        parser.add_argument("--skip", action="append", default=[], help="do not run these cases")
        parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
        self.args = parser.parse_args()
        repo = Path(__file__).resolve().parents[2]
        bindir = self.args.bin or repo / "rust" / "target" / "debug"
        self.host_bin = (bindir / "peerspan-host").resolve()
        self.probe_bin = (bindir / "peerspan-peer-probe").resolve()
        if not self.host_bin.exists():
            sys.exit(f"missing {self.host_bin}; build with cargo build --manifest-path rust/Cargo.toml --bins")
        self.name = name
        self.work = Path(tempfile.mkdtemp(prefix=f"slim-{name}-"))
        self.clock = None
        self.hosts = []
        self.processes = []  # other processes a suite started (helpers): stopped at exit
        self.results = []
        self.started = time.monotonic()
        self._cleaned = False
        # Stop every daemon, helper and ssh-agent on any exit: success, failure, an exception, Ctrl-C or a
        # SIGTERM/SIGHUP from a CI timeout.
        atexit.register(self.cleanup)
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, self._on_signal)

    def _on_signal(self, number, _frame):
        print(f"{self.name}: stopping on signal {number}", file=sys.stderr, flush=True)
        self.cleanup()
        os._exit(128 + number)

    def spawn(self, argv, **kw):
        """Start a helper process in its own session; cleanup stops it."""
        p = subprocess.Popen(argv, start_new_session=True, **kw)
        self.processes.append(p)
        return p

    def cleanup(self, remove=None):
        """Stop every process this suite started, then every leftover process (such as an ssh-agent a host or
        CLI started) whose command line names this suite's work directory. Idempotent."""
        if self._cleaned:
            return
        self._cleaned = True
        for h in self.hosts:
            try:
                h.stop(kill=True)
            except Exception:  # noqa: BLE001 - keep stopping the rest
                pass
        for p in self.processes:
            try:
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        marker = str(self.work).encode()
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                if marker in (entry / "cmdline").read_bytes() or marker in (entry / "environ").read_bytes():
                    os.kill(int(entry.name), signal.SIGKILL)
            except OSError:
                pass
        if remove is None:  # an early exit: keep the logs if anything failed
            remove = not self.args.keep and not any(o in ("FAIL", "XPASS") for o, _ in self.results)
        if remove:
            shutil.rmtree(self.work, ignore_errors=True)

    def use_clock(self):
        """Put every host and CLI of this suite on one shared debug test clock (DEC-OWN9, developer guide)."""
        self.clock = Clock(self.work / "clock-offset")
        return self.clock

    def set_offset(self, seconds):
        self.clock.set(seconds)

    @property
    def offset(self):
        return self.clock.offset

    def now(self):
        return self.clock.now()

    def host(self, name, start=True, clock=None):
        h = Host(self, name)
        h.clock = clock
        self.hosts.append(h)
        return h.start() if start else h


    def case(self, name, spec, known=None):
        """Decorator: run the function now as one case.

        KNOWN marks an expected product failure and gives its reason (the spec decision it breaks): the case
        still runs; a failure prints XFAIL and does not fail the suite; a pass prints XPASS and fails it, so the
        marker is removed once the product is fixed.
        """
        def run(function):
            if (self.args.only and name not in self.args.only) or name in self.args.skip:
                return function
            began = time.monotonic()
            try:
                function()
                outcome, detail = "PASS", ""
            except Skip as error:
                outcome, detail = "SKIP", str(error)
            except Failure as error:
                outcome, detail = "FAIL", str(error)
            except Exception as error:  # noqa: BLE001 - report and continue
                outcome, detail = "FAIL", f"{type(error).__name__}: {error}"
                traceback.print_exc(file=sys.stderr)
            took = time.monotonic() - began
            if known and outcome == "FAIL":
                outcome = "XFAIL"
                detail = f"({known}) {detail}"
            elif known and outcome == "PASS":
                outcome, detail = "XPASS", f"({known}) now passes; remove the expected-failure marker"
            self.results.append((outcome, name))
            line = f"{outcome} {name} [{spec}] ({took:.1f}s)"
            if detail:
                line += ": " + redact(" ".join(detail.split()))
            print(line, flush=True)
            return function
        return run

    def finish(self):
        total = time.monotonic() - self.started
        failed = [n for o, n in self.results if o in ("FAIL", "XPASS")]
        counts = {o: sum(1 for x, _ in self.results if x == o) for o in ("PASS", "FAIL", "XFAIL", "XPASS", "SKIP")}
        print(f"{self.name}: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['XFAIL']} expected failures, "
              f"{counts['XPASS']} unexpected passes, {counts['SKIP']} skipped in {total:.0f}s", flush=True)
        keep = bool(failed) or self.args.keep
        if keep:
            print(f"work directory kept: {self.work}", flush=True)
        self.cleanup(remove=not keep)
        sys.exit(1 if failed else 0)


def ssh_key(directory, name):
    """A fresh unencrypted ssh-ed25519 person key; returns its private key path."""
    path = Path(directory) / f"{name}_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(path)], check=True)
    return path


def ssh_public_base64(path):
    """The raw 32-byte Ed25519 public key of an OpenSSH key file, in standard Base64."""
    blob = base64.b64decode(Path(str(path) + ".pub").read_text().split()[1])
    # string "ssh-ed25519", then string key
    n = int.from_bytes(blob[:4], "big")
    key = blob[4 + n + 4:]
    return base64.b64encode(key).decode()


def b64url_json(code, prefix):
    body = code[len(prefix):]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


# Coordinator-free networks (docs/decentralized-spec.md sections 6 and 8).

def create_network(host, name, member):
    """`network create NAME --as MEMBER` on host; returns the network view."""
    view = host.ok("network", "create", name, "--as", member)
    check(view and view.get("mode") == "decentralized", f"network create returned {view}")
    host.network = view
    return view


def link_view(host, request_id):
    status, body = host.api("GET", f"/v2/link/requests/{request_id}")
    check(status == 200, f"{host.name}: GET link request {request_id}: {status} {body}")
    return body


def pull_until(host, request_id, field, timeout=30):
    """Run `link resume` on host until the request's field is set (stages travel by mailbox)."""
    def done():
        v = link_view(host, request_id)
        if v.get(field) not in (None, "-", False):
            return v
        host.cli("link", "resume", request_id, timeout=45)
        v = link_view(host, request_id)
        return v if v.get(field) not in (None, "-", False) else None
    return wait_for(done, timeout=timeout, interval=0.5, message=f"{host.name} {request_id[:12]} {field}")


def stage_body(view, **extra):
    body = {k: view[k] for k in ("network_id", "context_id", "person_public_key", "host_public_key",
                                 "device_public_key")}
    body.update(extra)
    return body


def select(host, view):
    status, body = host.api("POST", f"/v2/link/requests/{view['request_id']}/selection",
                            stage_body(view, owner_offer_id=view["owner_offer_id"], approve=True))
    check(status == 200, f"{host.name}: selection: {status} {body}")
    return body


def commit(host, view):
    status, body = host.api("POST", f"/v2/link/requests/{view['request_id']}/commit", stage_body(
        view, owner_offer_id=view["owner_offer_id"], selection_id=view["selection_id"],
        administrator_offer_id=view["administrator_offer_id"],
        owner_finalization_id=view["owner_finalization_id"], approve=True))
    check(status == 200, f"{host.name}: commit: {status} {body}")
    return body


def wait_linked(*hosts_and_request, timeout=30):
    *hosts, request_id = hosts_and_request
    for h in hosts:
        def linked(h=h):
            if link_view(h, request_id)["state"] == "linked":
                return True
            h.cli("link", "resume", request_id, timeout=45)
            return link_view(h, request_id)["state"] == "linked"
        wait_for(linked, timeout=timeout, interval=0.5, message=f"{h.name} applying {request_id[:12]}")


def invite(host, member, network_id=None):
    args = ["invite", member] + (["--network", network_id] if network_id else [])
    return host.ok(*args)


def join_request(joiner, invitation, key):
    """`join --invite-stdin --person-key KEY`; returns the pending LINK_VIEW with display_code."""
    result = joiner.cli("join", "--invite-stdin", "--person-key", key, input=invitation + "\n", timeout=90)
    check(result.json and result.json.get("request_id"), f"{joiner.name}: join gave no request: {result}")
    return result.json


def join_new_person(inviter, joiner, member, key, network_id, *, scopes=None, not_after=None):
    """The whole seven-stage join of a new person (spec 8.1, 8.2), driven to `linked` on both sides."""
    code = invite(inviter, member, network_id)["invitation"]
    request = join_request(joiner, code, key)
    rid, reply = request["request_id"], request.get("display_code")
    check(reply, "join printed no request code")
    terms = []
    if scopes is not None:
        terms += ["--scopes", str(scopes)]
    if not_after is not None:
        terms += ["--not-after", not_after]
    joiner.ok_incomplete("link", "approve", "--network", network_id, "--person-key", key, "--code-stdin",
                         "--approve", *terms, input=reply + "\n")
    view = pull_until(joiner, rid, "owner_offer_id")
    select(joiner, view)
    view = link_view(joiner, rid)
    inviter.ok_incomplete("link", "admit", "--network", network_id, "--owner-offer", view["owner_offer_id"],
                          "--selection", view["selection_id"], "--person", view["person_public_key"],
                          "--expect-host-key", view["host_public_key"], "--expect-device-key",
                          view["device_public_key"], "--code-stdin", "--approve", input=reply + "\n")
    view = pull_until(joiner, rid, "administrator_offer_id")
    finalize(joiner, view, key)
    view = pull_until(joiner, rid, "owner_finalization_id")
    commit(joiner, view)
    wait_linked(joiner, inviter, rid)
    return rid


def finalize(host, view, key=None):
    args = ["link", "finalize", view["request_id"], "--network", view["network_id"], "--context",
            view["context_id"], "--expect-person", view["person_public_key"], "--expect-host-key",
            view["host_public_key"], "--expect-device-key", view["device_public_key"], "--owner-offer",
            view["owner_offer_id"], "--selection", view["selection_id"], "--administrator-offer",
            view["administrator_offer_id"], "--approve"]
    if key:
        args += ["--person-key", key]
    return host.ok_incomplete(*args)


def link_machine(owner, machine, network_id, person_public_key, key=None, scopes=None):
    """`link` on a second machine of the owner's person, approved on the owner's host (spec 8.1, 8.2)."""
    request = machine.cli("link", "--network", network_id, "--expect-person", person_public_key, timeout=90).json
    check(request and request.get("display_code"), f"{machine.name}: link printed no request code")
    rid, code = request["request_id"], request["display_code"]
    signer = ["--person-key", key] if key else []
    args = ["link", "approve", "--network", network_id, "--person", person_public_key, "--expect-host-key",
            request["host_public_key"], "--expect-device-key", request["device_public_key"], "--code-stdin",
            "--approve", *signer]
    if scopes is not None:
        args += ["--scopes", str(scopes)]
    owner.ok_incomplete(*args, input=code + "\n")
    view = pull_until(machine, rid, "owner_offer_id")
    select(machine, view)
    view = link_view(machine, rid)
    if view["state"] == "needs_administrator":
        # Not folded: the owner's host also signs the administrator stage (root signer by default).
        owner.ok_incomplete("link", "admit", "--network", network_id, "--owner-offer", view["owner_offer_id"],
                            "--selection", view["selection_id"], "--person", person_public_key,
                            "--expect-host-key", view["host_public_key"], "--expect-device-key",
                            view["device_public_key"], "--code-stdin", "--approve", *signer, input=code + "\n")
        view = pull_until(machine, rid, "administrator_offer_id")
        owner.ok_incomplete("link", "finalize", rid, "--network", network_id, "--context", view["context_id"],
                            "--expect-person", person_public_key, "--expect-host-key", view["host_public_key"],
                            "--expect-device-key", view["device_public_key"], "--owner-offer",
                            view["owner_offer_id"], "--selection", view["selection_id"],
                            "--administrator-offer", view["administrator_offer_id"], "--approve", *signer)
    view = pull_until(machine, rid, "owner_finalization_id", timeout=40)
    commit(machine, view)
    wait_linked(machine, owner, rid)
    return rid


def statements(host, network_id, kind=None):
    """The decoded statements in HOST's public catalog (appendix 3.3): [(kind, envelope, payload)]."""
    status, body = host.api("GET", f"/v2/networks/{network_id}/catalog")
    check(status == 200, f"{host.name}: catalog: {status} {body}")
    found = []
    for item in body["catalog"]["objects"]:
        if kind and item["kind"] != kind:
            continue
        try:
            envelope = json.loads(base64.b64decode(item["body_base64"]))
            payload = json.loads(base64.b64decode(envelope["payload_base64"]))
        except (ValueError, KeyError):
            continue
        found.append((item["kind"], envelope, payload))
    return found


def members(host, network_id):
    status, body = host.api("GET", f"/v2/networks/{network_id}/members")
    check(status == 200, f"{host.name}: members: {status} {body}")
    return {m["host_public_key"]: m for m in body["members"]}


def attention(host):
    """Attention item kinds and their texts from GET /v2/status (spec 16)."""
    status, body = host.api("GET", "/v2/status")
    check(status == 200, f"{host.name}: status: {status} {body}")
    items = body.get("attention") or body.get("needs_attention") or []
    return {(i.get("kind"), i.get("detail") or "") for i in items}, body
