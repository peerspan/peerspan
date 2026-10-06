#!/usr/bin/env python3
"""Run isolated agent exchanges on two SSH hosts, without forwarding peer traffic.

Each host needs this checkout, built Capsule binaries, and the channel's npm
dependencies. Claude mode also needs an authenticated Claude Code installation.
--fixture substitutes a deterministic MCP consumer; it never calls a model.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from adapter_outbound import route
from adapter_recovery import atomic_credential
from agent_adapter import Channel, credential, sql
from claude_session import ClaudeSession
from coordination import Coordinator
from host_service import Host
from peer_messaging import PeerHost, timestamp


def endpoint(value, allow_loopback=False, listen=False):
    address, port = value.rsplit(":", 1)
    address = ipaddress.ip_address(address.strip("[]"))
    assert 0 < int(port) < 65536, "endpoint needs a fixed port"
    if not listen:
        assert not address.is_unspecified, "advertise a reachable IP"
        assert allow_loopback or not address.is_loopback, "advertise a cross-host IP"
    return str(address), int(port)


def machine_info():
    fingerprint = None
    for path in [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]:
        if path.is_file():
            value = path.read_text().strip()
            if value:
                fingerprint = hashlib.sha256(value.encode()).hexdigest()
                break
    return {
        "hostname": socket.gethostname(),
        "uid": os.getuid(),
        "machine_id_hash": fingerprint,
    }


class ExperimentHost(PeerHost):
    def __init__(self, settings, state):
        self.address = settings["advertise"]
        Host.__init__(
            self,
            settings["host_binary"],
            state,
            (
                "--peer-listen",
                settings["listen"],
                "--advertise",
                self.address,
                "--coordination-interval",
                "1",
            ),
        )


class ExperimentCoordinator(Coordinator):
    def __init__(self, settings, state):
        self.binary, self.state = settings["coord_binary"], state
        self.address = settings["coord_advertise"]
        self.listen = settings["coord_listen"]
        self.process = None
        self.logs = tempfile.TemporaryFile()

    def start(self):
        address, port = endpoint(self.listen, listen=True)
        if ipaddress.ip_address(address).is_unspecified:
            address = "::1" if ":" in address else "127.0.0.1"
        self.process = subprocess.Popen(
            [self.binary, "--state", str(self.state), "run", "--listen", self.listen],
            stdout=self.logs,
            stderr=self.logs,
        )
        until = time.monotonic() + 8
        while time.monotonic() < until:
            assert self.process.poll() is None, "test coordinator exited"
            try:
                with socket.create_connection((address, port), timeout=0.2):
                    return self.info()
            except OSError:
                time.sleep(0.05)
        raise AssertionError("test coordinator did not start")


class Experiment:
    """State and processes belong only to this worker's temporary directory."""

    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="capsule-cross-host-")
        self.root = Path(self.temporary.name)
        self.host = self.coord = self.consumer = None
        self.paused = False
        self.expected = set()
        self.observed = set()
        self.network = self.grant = None

    def initialize(self, settings, role, fixture):
        self.settings, self.role, self.fixture = settings, role, fixture
        self.host = ExperimentHost(settings, self.root / "host")
        self.identity = self.host.start()
        self.agent = self.host.cli("agent", "register", "--name", role, "--owner", role)
        self.session = self.host.cli(
            "session",
            "attach",
            "--agent",
            self.agent["id"],
            "--integration",
            "cross-host-experiment",
        )
        self.secret = credential(self.host, self.session)
        return {
            "identity": self.identity,
            "agent": self.agent,
            "address": self.host.address,
            "machine": machine_info(),
            "host_binary": self.host.binary,
        }

    def create_network(self):
        self.coord = ExperimentCoordinator(self.settings, self.root / "coord")
        info = self.coord.start()
        self.network = self.host.cli(
            "network",
            "create",
            "--name",
            "cross-host-test",
            "--member",
            "alice",
            "--coordinator",
            self.coord.address,
            "--coordinator-key",
            info["public_key"],
        )["id"]
        # This bearer invite stays in encrypted SSH pipes; it is never reported.
        return self.host.cli(
            "network",
            "invite",
            "--network",
            self.network,
            "--member",
            "bob",
            "--expires-at",
            timestamp(600),
        )["token"]

    def join(self, token):
        status, result = self.host.call("POST", "/v1/networks/join", {"token": token})
        assert status == 201, "test network enrollment failed"
        self.network = result["id"]
        return self.network

    def configure(self, peer):
        network = self.host.cli("network", "sync", self.network)
        assert network["last_sync_error"] is None
        members = self.host.cli("network", "members", self.network)
        member = next(m for m in members if m["host_id"] == peer["identity"]["id"])
        assert member["address"] == peer["address"]
        assert self.host.cli("peer", "list") == [], "manual peer pins bypass discovery"
        self.peer = peer
        # Each receiving owner grants its own direction, including outage use.
        self.grant = self.host.grant(peer["identity"], self.agent, allow=True)
        return self.grant

    def start_consumer(self, remote_grant):
        route(
            self.host,
            self.secret,
            self.peer["identity"],
            self.peer["agent"],
            remote_grant,
            budget=4,
        )
        script = Path(self.settings["repo"]) / "integrations/claude-channel/channel.mjs"
        directory = self.root / "consumer"
        node = Path(self.settings["node"]).resolve(strict=True)
        if self.fixture:
            self.consumer = Channel(node, script, self.host, self.secret, directory)
            self.credential_path = self.consumer.credential_path
            version, protocol = None, "2025-11-25"
        else:
            # Pin the executable so a CLI auto-update cannot change the version
            # reported for the process this experiment actually launched.
            claude = Path(self.settings["claude"]).resolve(strict=True)
            version = subprocess.check_output(
                [str(claude), "--version"], text=True, timeout=10
            ).strip()
            self.consumer = ClaudeSession(
                claude,
                node,
                script,
                self.host,
                self.secret,
                directory,
            )
            self.consumer.ready()
            self.credential_path = directory / "credential.json"
            # Older Claude versions log this metadata inside an escaped JSON
            # string. Read the negotiated value in either representation.
            protocol_match = re.search(
                r'"negotiatedProtocolVersion"\s*:\s*"([^"]+)"',
                self.consumer.debug().replace(r"\"", '"'),
            )
            assert protocol_match, "Claude did not log the negotiated MCP version"
            protocol = protocol_match.group(1)
        self.consumer_pid = self.consumer.process.pid
        return {
            "claude_version": version,
            "mcp_protocol": protocol,
            "session_id": self.session["id"],
            "adapter_id": self.secret["adapter"]["id"],
            "consumer_pid": self.consumer_pid,
        }

    def pause(self, paused):
        if self.paused != paused:
            sig = signal.SIGSTOP if paused else signal.SIGCONT
            if self.fixture:
                self.consumer.process.send_signal(sig)
            else:
                # ClaudeSession creates a separate process group for this test.
                os.killpg(self.consumer_pid, sig)
            self.paused = paused

    def begin(self, reply, observed):
        content = f"Use the Capsule reply tool to respond with exactly {reply}."
        self.current_reply, self.current_observed = reply, observed
        self.outbound_before = len(
            sql(self.host, "SELECT request_id FROM adapter_outbound")
        )
        if self.fixture:
            result = self.consumer.call(
                "tools/call",
                {
                    "name": "send",
                    "arguments": {
                        "destination": "remote",
                        "content": content,
                    },
                },
                # Establishment can take 5 s, and the adapter's send wait is
                # bounded at 12 s. The test client must outlast both.
                seconds=20,
            )
            assert not result.get("isError"), "fixture send failed"
        else:
            self.consumer.prompt(
                "This is a Capsule integration experiment. Use list_destinations, then send "
                f"to destination remote this exact message: {json.dumps(content)} "
                f"After its kind=reply event arrives, output exactly {observed}. "
                "The send result alone is not the reply. Send only once. Keep responding to "
                "later authorized kind=message events using the Capsule reply tool, even "
                "after this exchange finishes. Use only Capsule tools."
            )

    def pump_fixture(self):
        if not self.fixture or self.paused:
            return
        # The response drains already-arrived channel events into notifications.
        self.consumer.call("tools/list", {})
        events, self.consumer.notifications = self.consumer.notifications, []
        for event in events:
            if event.get("method") != "notifications/claude/channel":
                continue
            data = event["params"]
            if data["meta"]["kind"] == "message":
                match = re.fullmatch(
                    r"Use the Capsule reply tool to respond with exactly ([A-Z0-9_]+)\.",
                    data["content"],
                )
                assert match and match[1] in self.expected, "unexpected fixture request"
                result = self.consumer.reply(data["meta"]["delivery_id"], match[1])
                assert not result.get("isError"), "fixture reply failed"
            elif data["meta"]["kind"] == "reply":
                self.observed.add(data["content"])

    def retry(self):
        current = self.snapshot()["current_request_id"]
        assert current is not None
        rows = sql(
            self.host,
            "SELECT m.record FROM outbound_messages m JOIN adapter_outbound a ON a.peer=m.peer AND a.request_id=m.request_id WHERE a.adapter_id=? AND a.request_id=?",
            (self.secret["adapter"]["id"], current),
        )
        assert len(rows) == 1
        outbound = json.loads(rows[0][0])
        # The original attempt can finish between the controller's snapshot and
        # this command. An accepted operation needs no further send.
        if outbound["state"] != "unknown":
            return False
        arguments = {
            "destination": "remote",
            "request_id": current,
            "content": outbound["request"]["content"],
        }
        if self.fixture:
            result = self.consumer.call(
                "tools/call", {"name": "send", "arguments": arguments}, seconds=20
            )
            assert not result.get("isError"), "fixture retry failed"
        else:
            self.consumer.prompt(
                "Recover your existing uncertain Capsule send, using the send tool with exactly "
                f"these arguments: {json.dumps(arguments)}. This retries the original operation; "
                "do not generate a new request ID or change its destination or content. "
                f"After its kind=reply event arrives, output exactly {self.current_observed}. "
                "Keep responding to later authorized kind=message events through the reply tool. "
                "Use only Capsule tools."
            )
            # Give the model and the adapter's bounded send time to complete
            # before asking for another recovery attempt.
            until = time.monotonic() + 20
            while time.monotonic() < until:
                rows = sql(
                    self.host,
                    "SELECT record FROM outbound_messages WHERE peer=? AND request_id=?",
                    (self.peer["identity"]["id"], current),
                )
                if json.loads(rows[0][0])["state"] != "unknown":
                    return True
                self.consumer.running()
                time.sleep(0.1)
        return True

    def snapshot(self, pump=False):
        if pump:
            self.pump_fixture()
        assert self.consumer.process.poll() is None, "test consumer exited"
        assert self.consumer.process.pid == self.consumer_pid
        received_request_ids = [
            row[0] for row in sql(self.host, "SELECT request_id FROM received_messages")
        ]
        network = self.host.cli("network", "list")[0]
        synced = datetime.fromisoformat(network["last_sync_at"].replace("Z", "+00:00"))
        disconnected = (datetime.now(timezone.utc) - synced).total_seconds() > 3
        received_reply = False
        if hasattr(self, "current_reply"):
            received_reply = any(
                json.loads(row[0])["content"] == self.current_reply
                for row in sql(self.host, "SELECT record FROM outbound_replies")
            )
        observed = received_reply and (
            self.current_reply in self.observed
            if self.fixture
            else self.consumer.assistant_said(self.current_observed)
        )
        count = len(sql(self.host, "SELECT request_id FROM adapter_outbound"))
        messages = [
            json.loads(row[0])
            for row in sql(self.host, "SELECT record FROM outbound_messages")
        ]
        outbound = [
            {
                "request_id": item["request"]["request_id"],
                "state": item["state"],
                "error": item.get("error"),
            }
            for item in messages
        ]
        current_requests = [
            item["request"]["request_id"]
            for item in messages
            if hasattr(self, "current_reply")
            and self.current_reply in item["request"]["content"]
        ]
        assert len(current_requests) <= 1, "agent initiated duplicate requests"
        if observed:
            assert count == self.outbound_before + 1, "agent initiated duplicate sends"
            records = [
                json.loads(row[0])
                for row in sql(
                    self.host,
                    "SELECT reply_delivery FROM adapter_outbound WHERE reply_delivery IS NOT NULL",
                )
            ]
            assert all(r["session_id"] == self.session["id"] for r in records)
            assert all(r["adapter_id"] == self.secret["adapter"]["id"] for r in records)
            observed = bool(records) and all(r["state"] == "forwarded" for r in records)
        return {
            "received_request_ids": received_request_ids,
            "current_request_id": current_requests[0] if current_requests else None,
            "observed": bool(observed),
            "disconnected": disconnected,
            "sync_failed": network["last_sync_error"] is not None,
            "connection": self.host.cli(
                "adapter", "connection", self.secret["adapter"]["id"]
            ),
            "outbound_count": count,
            "outbound": outbound,
            "blocked_deliveries": sum(
                d["delivery"]["state"] == "blocked"
                for d in self.host.cli("delivery", "list")
            ),
        }

    def restart(self):
        assert not self.snapshot()["observed"], "exchange completed before restart"
        assert not any(
            json.loads(row[0])["content"] == self.current_reply
            for row in sql(self.host, "SELECT record FROM outbound_replies")
        )
        self.host.stop(crash=True)
        self.host.binary = self.settings.get("replacement_binary", self.host.binary)
        assert self.host.start() == self.identity
        # Also exercise the startup replacement guard on these actual hosts.
        candidate = self.host.cli(
            "session",
            "attach",
            "--agent",
            self.agent["id"],
            "--integration",
            "test-replacement-guard",
        )
        status, _ = self.host.call(
            "POST",
            "/v1/adapters",
            {
                "session_id": candidate["id"],
                "expires_at": timestamp(1200),
            },
        )
        assert status == 409, "restart let a fresh setup retire the original session"
        self.host.cli("session", "detach", candidate["id"])
        rotated = self.host.cli("adapter", "rotate", self.secret["adapter"]["id"])
        assert rotated["adapter"] == self.secret["adapter"]
        atomic_credential(self.credential_path, rotated)
        self.secret = rotated
        return {"replacement_guard_status": status, "host_binary": self.host.binary}

    def dispatch(self, operation, args):
        if operation == "initialize":
            return self.initialize(**args)
        if operation == "create_network":
            return self.create_network()
        if operation == "join":
            return self.join(**args)
        if operation == "configure":
            return self.configure(**args)
        if operation == "start_consumer":
            return self.start_consumer(**args)
        if operation == "expect":
            self.expected.add(args["reply"])
        elif operation == "begin":
            self.begin(**args)
        elif operation == "retry":
            return self.retry()
        elif operation == "pause":
            self.pause(**args)
        elif operation == "snapshot":
            return self.snapshot(**args)
        elif operation == "restart":
            return self.restart()
        elif operation == "stop_coordinator":
            self.coord.stop()
        elif operation == "revoke_grant":
            self.host.cli("grant", "revoke", self.grant["id"])
        elif operation != "close":
            raise ValueError("unknown worker operation")

    def close(self):
        errors = []
        for resource in [self.consumer, self.host, self.coord]:
            if resource is None:
                continue
            try:
                if resource is self.consumer:
                    self.pause(False)
                    resource.close()
                else:
                    resource.stop()
            except Exception as error:
                errors.append(error)
            finally:
                if resource.process is not None and resource.process.poll() is None:
                    resource.process.kill()
                    resource.process.wait(timeout=10)
                logs = getattr(resource, "logs", None)
                if logs is not None:
                    logs.close()
        self.temporary.cleanup()
        if errors:
            raise RuntimeError("test process cleanup failed") from None

    def failure_summary(self):
        """Report operation states without credentials, prompts, or CLI output."""
        if self.host is None or self.consumer is None:
            return {}
        records = [
            json.loads(row[0])
            for row in sql(self.host, "SELECT record FROM outbound_messages")
        ]
        return {
            "consumer_running": self.consumer.process.poll() is None,
            "outbound_states": [record["state"] for record in records],
            "current_operation_count": sum(
                hasattr(self, "current_reply")
                and self.current_reply in record["request"]["content"]
                for record in records
            ),
        }


def worker():
    def interrupted(_number, _frame):
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    experiment = Experiment()
    try:
        for line in sys.stdin:
            request = json.loads(line)
            operation = request["operation"]
            try:
                value = experiment.dispatch(operation, request.get("args", {}))
                response = {"ok": True, "value": value}
            except Exception as error:
                # CLI exceptions can contain invite/credential arguments. Never
                # export their text or private logs through this control stream.
                response = {
                    "ok": False,
                    "error": f"{operation} failed ({type(error).__name__})",
                }
                try:
                    response["diagnostics"] = experiment.failure_summary()
                except Exception:
                    response["diagnostics"] = {}
            print(json.dumps(response), flush=True)
            if operation == "close" or not response["ok"]:
                break
    finally:
        experiment.close()


class WorkerConnection:
    def __init__(self, settings, args):
        self.local = args.local or settings.get("local", False)
        if self.local:
            command = [sys.executable, str(Path(__file__).resolve()), "--worker"]
        else:
            command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
            if args.ssh_config:
                command += ["-F", str(args.ssh_config.resolve())]
            target = settings["ssh"]
            assert target and not target.startswith("-"), "invalid SSH target"
            command += [
                "--",
                target,
                shlex.join(
                    [
                        "python3",
                        "-u",
                        str(
                            Path(settings["repo"])
                            / "conformance/live_cross_host_agents.py"
                        ),
                        "--worker",
                    ]
                ),
            ]
        self.logs = tempfile.TemporaryFile()
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.logs,
            text=True,
        )
        self.responses = queue.Queue()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            for line in self.process.stdout:
                try:
                    self.responses.put(json.loads(line))
                except json.JSONDecodeError:
                    self.responses.put(
                        {"ok": False, "error": "invalid worker response"}
                    )
        finally:
            self.responses.put(None)

    def call(self, operation, **args):
        self.process.stdin.write(
            json.dumps({"operation": operation, "args": args}) + "\n"
        )
        self.process.stdin.flush()
        response = self.responses.get(timeout=120)
        assert response is not None, "worker exited; check SSH and remote prerequisites"
        assert response["ok"], (
            response["error"] + ": " + json.dumps(response.get("diagnostics", {}))
        )
        return response["value"]

    def close(self):
        closed = False
        if self.process.poll() is None:
            try:
                self.call("close")
                closed = True
            except (AssertionError, OSError, queue.Empty):
                pass
            try:
                self.process.stdin.close()
            except OSError:
                pass
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)
        self.reader.join(timeout=1)
        self.logs.close()
        if closed:
            assert self.process.returncode == 0, "worker cleanup failed"


def wait_pair(alice, bob, predicate, seconds=90, pump=True):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        a = alice.call("snapshot", pump=pump)
        b = bob.call("snapshot", pump=pump)
        result = predicate(a, b)
        if result:
            return result
        time.sleep(0.2)
    summaries = [
        {key: snapshot[key] for key in ["observed", "outbound", "blocked_deliveries"]}
        for snapshot in [a, b]
    ]
    raise AssertionError("cross-host condition timed out: " + json.dumps(summaries))


def wait_received(sender, receiver):
    """Explicit caller recovery uses the original operation, never a new send."""
    attempts = 0
    until = time.monotonic() + 90
    while time.monotonic() < until:
        source = sender.call("snapshot", pump=False)
        target = receiver.call("snapshot", pump=False)
        request_id = source["current_request_id"]
        if request_id in target["received_request_ids"]:
            return attempts
        # New intents are persisted as unknown before their first network
        # attempt finishes. A saved error identifies a completed failed attempt.
        uncertain = any(
            out["request_id"] == request_id
            and out["state"] == "unknown"
            and out["error"] is not None
            for out in source["outbound"]
        )
        if uncertain:
            assert (
                attempts < 3
            ), "original request remains uncertain after three caller retries"
            attempts += int(sender.call("retry"))
            time.sleep(1)
        else:
            time.sleep(0.2)
    raise AssertionError("receiver did not persist the current request")


def check(args, settings):
    connections = []
    allow_same = args.local or args.allow_same_machine
    for role in ["alice", "bob"]:
        actor = settings[role]
        assert isinstance(
            actor.get("local", False), bool
        ), f"{role}.local must be boolean"
        for name in ["repo", "host_binary", "node"] + (
            [] if args.fixture else ["claude"]
        ):
            assert Path(actor[name]).is_absolute(), f"{role}.{name} must be absolute"
        endpoint(actor["listen"], listen=True)
        endpoint(actor["advertise"], allow_loopback=allow_same)
    for name in ["coord_binary"]:
        assert Path(settings["alice"][name]).is_absolute()
    endpoint(settings["alice"]["coord_listen"], listen=True)
    endpoint(settings["alice"]["coord_advertise"], allow_loopback=allow_same)
    nonce = secrets.token_hex(8).upper()
    try:
        for role in ["alice", "bob"]:
            connection = WorkerConnection(settings[role], args)
            connections.append(connection)
        alice, bob = connections
        identities = [
            c.call(
                "initialize", settings=settings[role], role=role, fixture=args.fixture
            )
            for c, role in zip(connections, ["alice", "bob"])
        ]
        hashes = [i["machine"]["machine_id_hash"] for i in identities]
        distinct = hashes[0] != hashes[1] if all(hashes) else None
        assert (
            allow_same or distinct is not False
        ), "both workers are on the same installation"
        token = alice.call("create_network")
        network = bob.call("join", token=token)
        grants = [
            alice.call("configure", peer=identities[1]),
            bob.call("configure", peer=identities[0]),
        ]
        sessions = [
            alice.call("start_consumer", remote_grant=grants[1]),
            bob.call("start_consumer", remote_grant=grants[0]),
        ]
        wait_pair(
            alice,
            bob,
            lambda a, b: a["connection"]["state"]
            == b["connection"]["state"]
            == "ready",
            seconds=20,
        )
        print(
            "Both test sessions are ready; peers were discovered through signed enrollment.",
            flush=True,
        )

        exchanges = []
        for number, (sender, receiver, label, restart) in enumerate(
            [
                (alice, bob, "alice-to-bob-connected", False),
                (bob, alice, "bob-to-alice-connected", False),
                (alice, bob, "alice-to-bob-offline-restart", True),
                (bob, alice, "bob-to-alice-offline-restart", True),
            ]
        ):
            if number == 2:
                alice.call("stop_coordinator")
                wait_pair(
                    alice,
                    bob,
                    lambda a, b: a["disconnected"]
                    and b["disconnected"]
                    and a["sync_failed"]
                    and b["sync_failed"],
                    seconds=20,
                )
            reply, observed = f"REPLY_{nonce}_{number}", f"OBSERVED_{nonce}_{number}"
            receiver.call("expect", reply=reply)
            if restart:
                receiver.call("pause", paused=True)
            sender.call("begin", reply=reply, observed=observed)
            restarted = None
            retries = wait_received(sender, receiver)
            if restart:
                restarted = sender.call("restart")
                wait_pair(
                    sender,
                    receiver,
                    lambda a, _b: a["connection"]["state"] == "ready",
                    seconds=20,
                    pump=False,
                )
                receiver.call("pause", paused=False)
            wait_pair(sender, receiver, lambda a, _b: a["observed"])
            exchanges.append(
                {
                    "phase": label,
                    "observed": True,
                    "restart": restarted,
                    "explicit_caller_retries": retries,
                }
            )
            print(f"Passed {label}.", flush=True)

        # Queue one more request, withdraw its receiver-owned grant, then resume.
        reply = f"REPLY_{nonce}_4"
        bob.call("expect", reply=reply)
        bob.call("pause", paused=True)
        alice.call("begin", reply=reply, observed=f"OBSERVED_{nonce}_4")
        revocation_retries = wait_received(alice, bob)
        bob.call("revoke_grant")
        bob.call("pause", paused=False)
        wait_pair(
            alice, bob, lambda a, b: not a["observed"] and b["blocked_deliveries"] == 1
        )
        snapshots = [c.call("snapshot", pump=True) for c in connections]
        assert [s["outbound_count"] for s in snapshots] == [3, 2]
        for snapshot, session in zip(snapshots, sessions):
            assert snapshot["connection"]["adapter_id"] == session["adapter_id"]
            assert snapshot["connection"]["session_id"] == session["session_id"]
        return {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "consumer": "deterministic-mcp" if args.fixture else "claude",
            "control_transport": (
                "local-subprocess"
                if all(c.local for c in connections)
                else (
                    "mixed-local-and-ssh"
                    if any(c.local for c in connections)
                    else "ssh"
                )
            ),
            "worker_control_transports": {
                role: "local-subprocess" if connection.local else "ssh"
                for role, connection in zip(["alice", "bob"], connections)
            },
            "distinct_machine_ids": distinct,
            "hosts": identities,
            "sessions": sessions,
            "network_id": network,
            "grants": grants,
            "destination_max_messages": 4,
            "manual_peer_pins": False,
            "owner_cli_send_or_reply_fetch": False,
            "agent_initiated_both_directions": not args.fixture,
            "model_observed_automatic_replies_both_directions": not args.fixture,
            "same_consumer_processes_after_restart": True,
            "coordination_offline_exchanges": True,
            "queued_request_blocked_after_grant_revocation": True,
            "queued_revocation_explicit_caller_retries": revocation_retries,
            "builtin_tools_enabled": False,
            "permission_relay_enabled": False,
            "exchanges": exchanges,
            "limitations": [
                "Different machine IDs identify installations, not physical hardware or independently authenticated developer identities.",
                "The receiver was paused before restart to make the pending exchange deterministic.",
                "Tasks, full conversations, remote tools, and adapter-process replacement are outside this experiment.",
            ]
            + (
                ["Deterministic MCP consumers ran; no model execution was tested."]
                if args.fixture
                else []
            ),
        }
    finally:
        errors = []
        for connection in reversed(connections):
            try:
                connection.close()
            except Exception as error:
                errors.append(error)
        if errors:
            raise RuntimeError("worker cleanup failed") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument(
        "--fixture",
        action="store_true",
        help="Use deterministic MCP consumers; no model calls",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Validate workers on this machine; not cross-host evidence",
    )
    parser.add_argument(
        "--allow-same-machine",
        action="store_true",
        help="Permit SSH worker validation on one installation",
    )
    args = parser.parse_args()
    if args.worker:
        worker()
        return
    if not args.config or not args.output:
        parser.error("--config and --output are required")
    report = check(args, json.loads(args.config.read_text()))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Cross-host experiment passed:", args.output, flush=True)


if __name__ == "__main__":
    main()
