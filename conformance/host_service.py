#!/usr/bin/env python3
"""Run the same host-service contract checks against either implementation.

Uses only Python's standard library. Binaries must already be built. All state
is temporary; tests never open a developer's normal host state directory.
"""

import argparse
import base64
import ctypes
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time


# Tables added by database version 12 (policy propagation), dropped to model older state.
POLICY_DELIVERY_TABLES = ["policy_deliveries"]
# Tables added by database version 11 (delegation chains), dropped to model older state.
DELEGATION_TABLES = ["task_children"]
# Tables added by database version 10 (task artifacts), dropped to model older state.
ARTIFACT_TABLES = ["task_artifacts", "artifact_files"]
# Tables added by database version 9 (tasks), dropped to model older state.
TASK_TABLES = ["task_update_notifications", "task_deliveries", "outbound_task_events", "outbound_tasks",
               "task_events", "received_tasks"]


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=3):
        super().__init__("localhost", timeout=timeout)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def die_with_parent():
    """Kill test daemons if the suite process dies, e.g. on a runner timeout (Linux)."""
    try:
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
    except (AttributeError, OSError):
        pass


def stop_all(hosts):
    """Stop every host even if one fails, then raise the first failure."""
    failure = None
    for host in hosts:
        try:
            host.stop()
        except Exception as error:  # keep stopping the rest
            failure = failure or error
        finally:
            logs = getattr(host, 'logs', None)
            if logs is not None:
                logs.close()
    if failure is not None:
        raise failure


class Host:
    def __init__(self, binary, state, daemon_args=()):
        self.binary, self.state = str(binary), state
        self.daemon_args = daemon_args
        self.process = None
        self.logs = tempfile.TemporaryFile()
        # Each host's own user configuration, so a person key the CLI generates
        # (launch contract, slice 3) never lands in the real one or is shared.
        self.config_home = tempfile.mkdtemp(prefix="capsule-config-")

    def isolated(self, env):
        env["XDG_CONFIG_HOME"] = self.config_home
        return env

    def start(self, command="run"):
        self.process = subprocess.Popen(
            [self.binary, "--state", str(self.state), command, *self.daemon_args],
            stdout=self.logs, stderr=self.logs, preexec_fn=die_with_parent, env=self.daemon_env(),
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.logs.seek(0)
                raise AssertionError(f"host exited at startup: {self.logs.read().decode()}")
            try:
                status, identity = self.call("GET", "/v1/host")
                if status == 200:
                    return identity
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)
        raise AssertionError("host did not become ready")

    def daemon_env(self):
        """The daemon's environment: the suite's, with this host's configuration."""
        return self.isolated(dict(os.environ))

    def stop(self, crash=False):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError("host did not shut down")
            if not crash:
                assert self.process.returncode == 0, self.process.returncode

    def call(self, method, path, body=None, raw=None):
        connection = UnixHTTPConnection(self.state / "admin.sock")
        try:
            payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
            # Send headers and body in one write: http.client writes a str body
            # separately, and a server that answers early (e.g. 404) and closes can
            # then make the second write fail with a broken pipe.
            if isinstance(payload, str):
                payload = payload.encode()
            connection.request(method, path, payload, {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    # Suites are hermetic about ssh-agent: a developer's own agent must not
    # turn on person flows. Hosts that test persons set keep_agent.
    keep_agent = False

    def cli(self, *args, success=True):
        env = self.isolated(dict(os.environ))
        if not self.keep_agent:
            env.pop("SSH_AUTH_SOCK", None)
        result = subprocess.run(
            [self.binary, "--state", str(self.state), *args],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
        return json.loads(result.stdout) if success else result.stderr


def check_cli_without_daemon(binary):
    """Help and rejected/client commands must not initialize host state."""
    with tempfile.TemporaryDirectory(prefix="capsule-cli-") as temporary:
        state = Path(temporary) / "absent"
        environment = os.environ.copy()
        environment.pop("HOME", None)
        environment.pop("XDG_STATE_HOME", None)
        for args in [[], ["--help"], ["-h"], ["help"],
                     ["--state", str(state), "agent", "register", "--help"],
                     ["--state", str(state), "session", "attach", "--help"],
                     ["--state", str(state), "activity", "--help"]]:
            result = subprocess.run([str(binary), *args], env=environment,
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode == 0, (args, result.stderr)
            assert result.stdout or result.stderr, args
            assert not state.exists(), args

        invalid = [
            ["run", "unexpected"], ["serve", "unexpected"], ["unknown"],
            ["agent", "register", "--name"],
            ["agent", "register", "--name", "bob"],
            ["agent", "register", "--name", "bob", "--owner", "bob", "--unknown"],
            ["session", "attach", "--agent", "agent_example"],
            ["session", "inspect"], ["session", "detach", "one", "two"],
            ["activity", "--after", "bad"], ["activity", "--after=-1"],
            ["activity", "--limit", "0"], ["activity", "--limit", "1001"],
            ["info"],
        ]
        for args in invalid:
            result = subprocess.run([str(binary), "--state", str(state), *args],
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode != 0, (args, result.stdout, result.stderr)
            assert not state.exists(), args
        result = subprocess.run([str(binary), "--state"], capture_output=True, timeout=5)
        assert result.returncode != 0

        # The daemon validates filesystem paths; a client never opens the store.
        ordinary_file = Path(temporary) / "file"
        ordinary_file.write_text("keep")
        for command in ["run", "serve"]:
            result = subprocess.run([str(binary), "--state", str(ordinary_file), command],
                                    capture_output=True, timeout=5)
            assert result.returncode != 0
            assert ordinary_file.read_text() == "keep"


def check(binary, label):
    check_cli_without_daemon(binary)
    with tempfile.TemporaryDirectory(prefix="capsule-contract-") as temporary:
        host = Host(binary, Path(temporary) / "host")
        try:
            identity = host.start()
            public = base64.b64decode(identity["public_key"], validate=True)
            assert len(public) == 32
            assert identity["id"] == "host_" + hashlib.sha256(public).hexdigest()
            assert "private_key" not in identity
            assert host.cli("info") == identity
            for path, mode in [(host.state, 0o700), (host.state / "host.db", 0o600), (host.state / "admin.sock", 0o600)]:
                assert stat.S_IMODE(path.stat().st_mode) == mode, path
            assert host.cli("agent", "list") == []
            assert host.cli("session", "list") == []
            assert host.cli("activity") == []

            agent = host.cli("agent", "register", "--name", " bob ", "--owner", " bob ", "--capability", " conversation ", "--capability", "conversation")
            assert agent["name"] == "bob" and agent["owner"] == "bob"
            assert agent["capabilities"] == ["conversation"]
            assert agent["id"].startswith("agent_")
            assert host.cli("agent", "inspect", agent["id"]) == agent
            assert host.cli("agent", "list") == [agent]

            status, error = host.call("POST", "/v1/agents", {"name": "bob", "owner": "bob"})
            assert status == 409 and error["code"] == "conflict"
            for payload in [
                {"name": "", "owner": "bob"},
                {"name": "alice", "owner": ""},
                {"name": "alice", "owner": "alice", "unknown": True},
                {"name": "alice", "owner": "alice", "capabilities": None},
                {"Name": "alice", "owner": "alice"},
                {"name": "alice", "owner": "alice", "capabilities": [""]},
                {"name": "x" * 129, "owner": "bob"},
            ]:
                status, error = host.call("POST", "/v1/agents", payload)
                assert status == 400 and error["code"] == "invalid", payload
            for raw in ["{", "null", '{} {}', '{"name":"a","owner":"a"} trailing']:
                assert host.call("POST", "/v1/agents", raw=raw)[0] == 400, raw
            assert host.call("POST", "/v1/agents", raw='{"name":"' + 'a' * (1 << 20) + '"}')[0] == 400
            assert host.call("GET", "/v1/agents/missing")[0] == 404
            assert len(host.cli("activity")) == 1

            session = host.cli("session", "attach", "--agent", agent["id"], "--integration", "test")
            assert session["id"].startswith("session_")
            assert session["agent_id"] == agent["id"] and session["state"] == "attached"
            assert host.cli("session", "inspect", session["id"]) == session
            assert host.cli("session", "list", "--agent", agent["id"]) == [session]
            assert host.call("POST", "/v1/sessions", {"agent_id": "missing", "integration": "test"})[0] == 404
            assert host.call("GET", "/v1/sessions?agent_id=missing")[0] == 404
            assert host.call("GET", "/v1/sessions/missing")[0] == 404
            assert host.call("POST", "/v1/sessions/missing/detach")[0] == 404
            assert host.call("POST", "/v1/sessions", {"agent_id": agent["id"], "integration": ""})[0] == 400
            assert host.call("POST", "/v1/sessions", {"agent_id": agent["id"], "integration": None})[0] == 400

            # A second daemon must not disturb the existing socket or identity.
            second = subprocess.run([str(binary), "--state", str(host.state), "serve"], capture_output=True, timeout=5)
            assert second.returncode != 0
            assert host.cli("info") == identity

            detached = host.cli("session", "detach", session["id"])
            assert detached["state"] == "detached"
            events = host.cli("activity")
            assert [e["kind"] for e in events] == ["agent.registered", "session.attached", "session.detached"]
            assert host.cli("session", "detach", session["id"]) == detached
            assert host.cli("activity") == events
            assert host.cli("activity", "--after", str(events[0]["sequence"]), "--limit", "1") == [events[1]]
            for query in ["after=-1", "after=bad", "limit=0", "limit=1001", "limit=bad"]:
                assert host.call("GET", "/v1/activity?" + query)[0] == 400

            # Concurrent duplicate submissions have one successful mutation.
            def register_racer(_):
                return host.call("POST", "/v1/agents", {"name": "racer", "owner": "bob"})[0]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                statuses = list(executor.map(register_racer, range(8)))
            assert sorted(statuses) == [201] + [409] * 7, statuses

            attached = host.cli("session", "attach", "--agent", agent["id"], "--integration", "test")
            host.stop(crash=True)
            assert host.start(command="serve") == identity
            assert host.cli("agent", "inspect", agent["id"]) == agent
            assert host.cli("session", "inspect", attached["id"])["state"] == "detached"
            recovery = host.cli("activity")[-1]
            assert recovery["kind"] == "session.disconnected" and recovery["subject_id"] == attached["id"]
            assert host.cli("session", "inspect", session["id"]) == detached

            # Mutation and activity are atomic even if activity storage fails.
            connection = sqlite3.connect(host.state / "host.db")
            try:
                connection.execute("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
                connection.commit()
                status, error = host.call("POST", "/v1/agents", {"name": "failed", "owner": "bob"})
                assert status == 500 and error == {"code": "internal", "error": "internal error"}
                assert all(a["name"] != "failed" for a in host.cli("agent", "list"))
                connection.execute("DROP TRIGGER fail_event")
                connection.commit()
            finally:
                connection.close()
            host.cli("agent", "register", "--name", "failed", "--owner", "bob")
            host.cli("unknown", success=False)
            before_migration = host.cli("activity")
            host.stop()
            assert not (host.state / "admin.sock").exists()
            # Model an existing v1 installation, retaining its identity/registry.
            connection = sqlite3.connect(host.state / "host.db")
            try:
                for table in [*POLICY_DELIVERY_TABLES, *DELEGATION_TABLES, *ARTIFACT_TABLES, *TASK_TABLES, "access_blocks", "network_statements", "adapter_connections", "adapter_outbound", "adapter_routes", "outbound_replies", "received_replies", "deliveries", "adapter_credentials",
                              "network_members", "networks",
                              "outbound_messages", "received_messages", "grants", "peers"]:
                    connection.execute("DROP TABLE " + table)
                connection.execute("PRAGMA user_version = 1")
                connection.commit()
            finally:
                connection.close()
            assert host.start() == identity
            assert host.cli("agent", "inspect", agent["id"]) == agent
            assert host.cli("activity") == before_migration
            assert host.cli("peer", "list") == []
            assert host.cli("grant", "list") == []
            assert host.cli("message", "list") == []
            assert host.cli("network", "list") == []
            assert sqlite3.connect(host.state / "host.db").execute("PRAGMA user_version").fetchone()[0] == 12
            host.stop()
            assert not (host.state / "admin.sock").exists()
        finally:
            host.stop()
            host.logs.close()
    print(f"PASS {label}: local API, CLI, durability, crash recovery, exclusivity, concurrency, atomic activity, v1→v12 migration", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", type=Path)
    parser.add_argument("--rust", type=Path)
    args = parser.parse_args()
    if not (args.go or args.rust):
        parser.error("provide --go and/or --rust binaries")
    for label, binary in [("Go", args.go), ("Rust", args.rust)]:
        if binary:
            binary = binary.resolve(strict=True)
            check(binary, label)


if __name__ == "__main__":
    main()
