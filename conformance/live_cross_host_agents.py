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
        self.send_calls = 0
        self.status_results = []
        self.pending_marker = self.accepted_marker = None

    def initialize(self, settings, role, fixture):
        self.settings, self.role, self.fixture = settings, role, fixture
        self.host = ExperimentHost(settings, self.root / "host")
        self.identity = self.host.start()
        self.agent = self.host.cli("agent", "register", "--name", role, "--owner", role)
        self.session = None if settings.get("setup_flow") else self.host.cli(
            "session",
            "attach",
            "--agent",
            self.agent["id"],
            "--integration",
            "cross-host-experiment",
        )
        self.secret = None if settings.get("setup_flow") else credential(self.host, self.session)
        return {
            "identity": self.identity,
            "agent": self.agent,
            "address": self.host.address,
            "machine": machine_info(),
            "host_binary": self.host.binary,
            "host_binary_sha256": hashlib.sha256(Path(self.host.binary).read_bytes()).hexdigest(),
            "replacement_binary_sha256": hashlib.sha256(Path(settings.get("replacement_binary", self.host.binary)).read_bytes()).hexdigest(),
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
        script = Path(self.settings["repo"]) / "integrations/claude-channel/channel.mjs"
        directory = self.root / "consumer"
        node = Path(self.settings["node"]).resolve(strict=True)
        launch = None
        if self.settings.get("setup_flow"):
            self.setup_directory = self.root / "claude-setup"
            routes_file = self.root / "destinations.json"
            routes_file.write_text(json.dumps([{
                "name": "remote", "peer_host_id": self.peer["identity"]["id"],
                "target_agent_id": self.peer["agent"]["id"], "grant_id": remote_grant["id"],
                "expires_at": remote_grant["expires_at"], "max_message_bytes": 65536, "max_messages": 4,
            }]))
            configured = self.host.cli(
                "claude", "setup", "--agent", self.agent["id"],
                "--directory", str(self.setup_directory), "--channel", str(script),
                "--expires-at", timestamp(1200), "--routes", str(routes_file),
                "--node", str(node), "--claude", self.settings["claude"],
            )
            assert configured["state"] == "configured" and not configured["adapter_ready"]
            self.session = self.host.cli("session", "inspect", configured["session_id"])
            self.secret = json.loads((self.setup_directory / "credential.json").read_text())
            launch = [self.host.binary, "--state", str(self.host.state), "claude", "start",
                      "--directory", str(self.setup_directory), "--workspace", str(directory)]
        else:
            route(self.host, self.secret, self.peer["identity"], self.peer["agent"], remote_grant, budget=4)
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
                launch=launch,
                credential_path=self.setup_directory / "credential.json" if launch else None,
            )
            self.consumer.ready()
            self.credential_path = self.setup_directory / "credential.json" if launch else directory / "credential.json"
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
            "channel_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
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

    def begin(self, reply, observed, track_status=False):
        content = f"Use the Capsule reply tool to respond with exactly {reply}."
        self.current_reply, self.current_observed = reply, observed
        self.track_status = track_status
        self.pending_marker = "PENDING_" + observed
        self.accepted_marker = "ACCEPTED_" + observed
        self.outbound_before = len(
            sql(self.host, "SELECT request_id FROM adapter_outbound")
        )
        if self.fixture:
            self.send_calls += 1
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
                "The send result alone is not the reply. Send only once. "
                + (
                    "The receiver is temporarily offline. Once send returns unknown, call send_status "
                    f"with that request_id. If send_status returns unknown, output exactly {self.pending_marker} "
                    "and wait for the next instruction. Do not retry send. "
                    if track_status else ""
                )
                + "Keep responding to "
                "later authorized kind=message events using the Capsule reply tool, even "
                "after this exchange finishes. Use only Capsule tools."
            )

    def check_send_status(self, request_id):
        if self.fixture:
            result = self.consumer.call(
                "tools/call",
                {"name": "send_status", "arguments": {"request_id": request_id}},
            )
            assert not result.get("isError"), "fixture send_status failed"
            self.status_results.append(json.loads(result["content"][0]["text"]))
        else:
            self.consumer.prompt(
                "The receiver is available again. Use send_status for your existing request_id "
                f"{request_id}. If it is unknown, check send_status again; the daemon retries automatically. "
                f"Once send_status returns accepted, output exactly {self.accepted_marker}. "
                f"After the kind=reply event, output exactly {self.current_observed}. "
                "Do not call send again. Keep responding to later kind=message events with reply. "
                "Use only Capsule tools."
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
        budget_remaining = sql(
            self.host,
            "SELECT json_extract(r.record, '$.max_messages') - COUNT(o.request_id) FROM adapter_routes r LEFT JOIN adapter_outbound o ON o.route_id=r.id WHERE r.adapter_id=? GROUP BY r.id",
            (self.secret["adapter"]["id"],),
        )
        current_requests = [
            item["request"]["request_id"]
            for item in messages
            if hasattr(self, "current_reply")
            and self.current_reply in item["request"]["content"]
        ]
        assert len(current_requests) <= 1, "agent initiated duplicate requests"
        if self.fixture:
            status_results = self.status_results
            send_calls = self.send_calls
        else:
            status_results = [
                call["result"]
                for call in self.consumer.tool_exchanges("mcp__capsule__send_status")
                if isinstance(call["result"], dict)
            ]
            send_calls = len(self.consumer.tool_exchanges("mcp__capsule__send"))
        current_status = [result for result in status_results if result.get("request_id") in current_requests]
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
            "send_tool_calls": send_calls,
            "route_budget_remaining": sum(row[0] for row in budget_remaining),
            "send_status_results": current_status,
            "model_observed_unknown_status": self.fixture or self.consumer.assistant_said(self.pending_marker),
            "model_observed_accepted_status": self.fixture or self.consumer.assistant_said(self.accepted_marker),
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
        if hasattr(self, "setup_directory") and self.credential_path != self.setup_directory / "credential.json":
            atomic_credential(self.setup_directory / "credential.json", rotated)
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
        elif operation == "check_send_status":
            return self.check_send_status(**args)
        elif operation == "stop_peer_host":
            self.host.stop(crash=True)
        elif operation == "start_peer_host":
            assert self.host.start() == self.identity
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
        self.fixture = args.fixture
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
    """Wait for daemon recovery without making another send call."""
    until = time.monotonic() + 120
    while time.monotonic() < until:
        source = sender.call("snapshot", pump=False)
        target = receiver.call("snapshot", pump=False)
        request_id = source["current_request_id"]
        if request_id in target["received_request_ids"]:
            return 0
        time.sleep(0.2)
    raise AssertionError("receiver did not persist the current request")


def wait_status(sender, state, seconds=120):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        snapshot = sender.call("snapshot", pump=False)
        request_id = snapshot["current_request_id"]
        if request_id and sender.fixture:
            sender.call("check_send_status", request_id=request_id)
            snapshot = sender.call("snapshot", pump=False)
        results = [
            result for result in snapshot["send_status_results"]
            if result.get("state") == state
        ]
        if results and snapshot[f"model_observed_{state}_status"]:
            return results[-1]
        time.sleep(0.2)
    raise AssertionError(f"send_status did not report {state}: " + json.dumps(snapshot["send_status_results"]))


def check(args, settings):
    connections = []
    allow_same = args.local or args.allow_same_machine
    for role in ["alice", "bob"]:
        actor = settings[role]
        actor["setup_flow"] = args.setup_flow
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
        cases = [
            (alice, bob, "alice-to-bob-connected", False),
            (bob, alice, "bob-to-alice-connected", False),
            (alice, bob, "alice-to-bob-offline-restart", True),
            (bob, alice, "bob-to-alice-offline-restart", True),
        ]
        if args.send_status_only:
            cases = cases[:2]
        for number, (sender, receiver, label, restart) in enumerate(cases):
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
            track_status = args.send_status and number < 2
            if track_status:
                receiver.call("stop_peer_host")
            sender.call("begin", reply=reply, observed=observed, track_status=track_status)
            statuses = []
            if track_status:
                statuses.append(wait_status(sender, "unknown"))
                receiver.call("start_peer_host")
            restarted = None
            retries = wait_received(sender, receiver)
            if track_status:
                sender.call("check_send_status", request_id=statuses[0]["request_id"])
                statuses.append(wait_status(sender, "accepted"))
                assert statuses[0]["request_id"] == statuses[1]["request_id"]
                assert statuses[1]["attempts"] > statuses[0]["attempts"]
                assert statuses[1]["next_attempt_at"] is None
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
                    "send_status": statuses,
                    "model_observed_send_status": track_status and not args.fixture,
                }
            )
            print(f"Passed {label}.", flush=True)

        revocation_retries = None
        if not args.send_status_only:
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
        expected = [1, 1] if args.send_status_only else [3, 2]
        assert [s["outbound_count"] for s in snapshots] == expected
        assert [s["send_tool_calls"] for s in snapshots] == expected, "a consumer retried send"
        assert [s["route_budget_remaining"] for s in snapshots] == [
            4 - count for count in expected
        ], "recovery consumed extra route budget"
        for snapshot, session in zip(snapshots, sessions):
            assert snapshot["connection"]["adapter_id"] == session["adapter_id"]
            assert snapshot["connection"]["session_id"] == session["session_id"]
        return {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "source_revision": settings.get("source_revision"),
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
            "coordination_offline_exchanges": not args.send_status_only,
            "queued_request_blocked_after_grant_revocation": not args.send_status_only,
            "queued_revocation_explicit_caller_retries": revocation_retries,
            "send_tool_calls": {role: s["send_tool_calls"] for role, s in zip(["alice", "bob"], snapshots)},
            "route_budget_remaining": {role: s["route_budget_remaining"] for role, s in zip(["alice", "bob"], snapshots)},
            "send_status_tested": args.send_status,
            "send_status_only": args.send_status_only,
            "owner_cli_setup": args.setup_flow,
            "owner_cli_launch": args.setup_flow and not args.fixture,
            "builtin_tools_enabled": False,
            "permission_relay_enabled": False,
            "exchanges": exchanges,
            "limitations": [
                "Different machine IDs identify installations, not physical hardware or independently authenticated developer identities.",
                "The receiving daemon was stopped until send_status reported unknown." if args.send_status_only else "The receiver was paused before restart to make the pending exchange deterministic.",
                "Tasks, full conversations, remote tools, and adapter-process replacement are outside this experiment.",
            ]
            + (
                ["Coordinator outage, originating-daemon replacement, token rotation, and queued revocation were not exercised in this focused run."]
                if args.send_status_only else []
            )
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
    parser.add_argument("--setup-flow", action="store_true", help="Prepare and launch through the public claude CLI workflow")
    parser.add_argument(
        "--send-status", action="store_true",
        help="Stop each receiver until send_status reports unknown, then check automatic acceptance",
    )
    parser.add_argument(
        "--send-status-only", action="store_true",
        help="Run only the two send_status recovery exchanges",
    )
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
    args.send_status = args.send_status or args.send_status_only
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
