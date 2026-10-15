#!/usr/bin/env python3
"""Exercise owner setup/diagnostics against both CLIs and real daemons.

Claude prerequisites and launch arguments use an explicit fixture executable;
message exchange uses the actual MCP adapter. This suite makes no model calls.
"""
import argparse
import copy
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

from agent_adapter import Channel, sql
from host_service import UnixHTTPConnection
from peer_messaging import PeerHost, timestamp


def wait(check, seconds=20):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("setup condition timed out")


def snapshot(host):
    return {
        table: sql(host, "SELECT * FROM " + table)
        for table in ["sessions", "adapter_credentials", "adapter_connections", "adapter_routes", "adapter_outbound", "events"]
    }


def invoke(client, host, *args, success=True):
    result = subprocess.run([str(client), "--state", str(host.state), "session", *args],
                            capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    assert "token_" not in result.stdout + result.stderr
    return json.loads(result.stdout) if result.stdout else result.stderr


def fake_claude(path):
    path.write_text('''#!/usr/bin/env python3
import json,os,sys
if "--version" in sys.argv:
    print("2.1.291 (fixture)")
elif sys.argv[1:]==["auth","status"]:
    print(json.dumps({"loggedIn":True,"authMethod":"claude.ai"}))
else:
    print(json.dumps({"arguments":sys.argv[1:],"cwd":os.getcwd()}))
''')
    path.chmod(0o700)
    return path


class DropSetupResponse:
    """Private Unix proxy: commit setup on the real daemon, lose its response."""
    def __init__(self, host):
        self.original = host.state / "admin.sock"
        self.backend = host.state / "admin-real.sock"
        self.original.rename(self.backend)
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def handle_request(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                conn = UnixHTTPConnection(proxy.backend, timeout=15)
                try:
                    conn.request(self.command, self.path, body, {"Content-Type": "application/json"})
                    response = conn.getresponse()
                    data = response.read()
                    if self.command == "POST" and self.path == "/v1/adapters/setup" and not proxy.dropped:
                        proxy.dropped = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        return
                    self.send_response(response.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                finally:
                    conn.close()

            do_GET = do_POST = handle_request

        self.dropped = False
        self.server = socketserver.UnixStreamServer(str(self.original), Handler)
        self.original.chmod(0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.original.unlink()
        self.backend.rename(self.original)


def setup(client, host, agent, directory, node, claude, script, routes=None):
    args = ["setup", "--directory", str(directory), "--agent", agent["id"],
            "--harness", "claude-code", "--integrations", str(script.parent.parent), "--runner", str(node), "--option", "executable="+str(claude),
            "--expires-at", timestamp(900)]
    if routes is not None:
        path = directory.parent / (directory.name + "-routes.json")
        path.write_text(json.dumps(routes))
        args += ["--routes", str(path)]
    return invoke(client, host, *args)


def check(client, source_binary, receiver_binary, replacement, node, label):
    script = Path(__file__).resolve().parents[1] / "integrations/claude-channel/channel.mjs"
    with tempfile.TemporaryDirectory(prefix="peerspan-claude-setup-") as td:
        root = Path(td)
        source, receiver = PeerHost(source_binary, root / "source"), PeerHost(receiver_binary, root / "receiver")
        channels = []
        paused = None
        try:
            a, b = source.start(), receiver.start()
            source.configure(receiver, b)
            receiver.configure(source, a)
            mine = source.cli("agent", "register", "--name", "alice", "--owner", "alice")
            target = receiver.cli("agent", "register", "--name", "bob", "--owner", "bob")
            grant = receiver.grant(a, target)
            claude = fake_claude(root / "Claude fixture")
            route = {"name": "remote", "peer_host_id": b["id"], "target_agent_id": target["id"],
                     "grant_id": grant["id"], "max_messages": 1}
            directory = root / "private setup"
            configured = setup(client, source, mine, directory, node, claude, script, [route])
            assert configured["state"] == "configured" and not configured["adapter_ready"]
            assert directory.stat().st_mode & 0o077 == 0
            for name in ["profile.json", "credential.json", "mcp.json"]:
                assert (directory / name).stat().st_mode & 0o077 == 0
            secret = json.loads((directory / "credential.json").read_text())
            before = snapshot(source)
            files = {name: (directory / name).read_bytes() for name in ["profile.json", "credential.json", "mcp.json"]}
            # Existing configuration, private-file violations, and identity
            # mismatches must fail without changing authorization or activity.
            setup_args = ["setup", "--directory", str(directory), "--agent", mine["id"],
                          "--harness", "claude-code", "--integrations", str(script.parent.parent), "--runner", str(node), "--option", "executable="+str(claude),
                          "--expires-at", timestamp(900)]
            invoke(client, source, *setup_args, success=False)
            assert files == {name: (directory / name).read_bytes() for name in files}
            for name in files:
                path = directory / name
                path.chmod(0o644)
                invoke(client, source, "doctor", "--directory", str(directory), success=False)
                path.chmod(0o600)
                saved = directory / (name + ".saved")
                path.rename(saved); path.symlink_to(saved)
                invoke(client, source, "doctor", "--directory", str(directory), success=False)
                path.unlink(); saved.rename(path)
            # Nonregular files must be rejected without blocking on a FIFO.
            path = directory / "profile.json"
            saved = directory / "profile.saved"
            path.rename(saved); os.mkfifo(path, 0o600)
            invoke(client, source, "doctor", "--directory", str(directory), success=False)
            path.unlink(); saved.rename(path)
            profile = json.loads(files["profile.json"])
            (directory / "profile.json").write_text(json.dumps({**profile, "host_id": "host_" + "0" * 64}))
            report = invoke(client, source, "doctor", "--directory", str(directory), success=False)
            assert next(c for c in report["checks"] if c["name"] == "host_changed")["status"] == "error"
            (directory / "profile.json").write_bytes(files["profile.json"])
            (directory / "mcp.json").write_text('{"mcpServers":{}}')
            report = invoke(client, source, "doctor", "--directory", str(directory), success=False)
            assert next(c for c in report["checks"] if c["name"] == "harness/mcp_config")["status"] == "error"
            (directory / "mcp.json").write_bytes(files["mcp.json"])
            assert before == snapshot(source)

            report = invoke(client, source, "doctor", "--directory", str(directory), success=False)
            assert report["connection"]["state"] == "registered" and not report["adapter_ready"]
            assert before == snapshot(source), "doctor changed registered attachment state"
            launched = invoke(client, source, "start", "--directory", str(directory),
                              "--workspace", str(root), "--", "--name", "my session")
            assert launched["cwd"] == str(root)
            assert "--dangerously-load-development-channels" in launched["arguments"]
            assert launched["arguments"][-2:] == ["--name", "my session"]
            assert "--dangerously-skip-permissions" not in launched["arguments"]
            assert before == snapshot(source), "launch minted another attachment"
            invoke(client, source, "start", "--directory", str(directory), "--", "--mcp-config", "{}", success=False)
            invoke(client, source, "start", "--directory", str(directory), "unexpected", "--", "--name", "example", success=False)
            invoke(client, source, "start", "--directory", str(directory),
                   "--workspace", str(root / "absent"), success=False)
            assert before == snapshot(source)

            # Real MCP consumers use the prepared credentials/routes unchanged.
            other_dir = root / "receiver setup"
            setup(client, receiver, target, other_dir, node, claude, script)
            other_secret = json.loads((other_dir / "credential.json").read_text())
            sender = Channel(node, script, source, secret, root / "sender-consumer")
            responder = Channel(node, script, receiver, other_secret, root / "receiver-consumer")
            channels += [sender, responder]
            wait(lambda: source.cli("adapter", "connection", secret["adapter"]["id"])["state"] == "ready")
            wait(lambda: receiver.cli("adapter", "connection", other_secret["adapter"]["id"])["state"] == "ready")
            sent = sender.call("tools/call", {"name": "send", "arguments": {"destination": "remote", "content": "hello"}}, seconds=20)
            assert not sent.get("isError"), sent

            def received():
                responder.call("tools/list", {})
                return next((event for event in responder.notifications if event.get("method") == "notifications/claude/channel"), None)
            notification = wait(received)
            assert not responder.reply(notification["params"]["meta"]["delivery_id"], "hello back").get("isError")
            wait(lambda: len(sql(source, "SELECT record FROM outbound_replies")) == 1)
            # Let the consumer acknowledge its reply before freezing it. The
            # daemon's reply dispatcher legitimately changes activity and the
            # outbound row independently of an owner diagnostic request.
            wait(lambda: sql(source, "SELECT json_extract(reply_delivery,'$.state') FROM adapter_outbound") == [("forwarded",)])
            sender.process.send_signal(signal.SIGSTOP)
            paused = sender
            _, stopped = os.waitpid(sender.process.pid, os.WUNTRACED)
            assert os.WIFSTOPPED(stopped)
            time.sleep(0.1)  # Settle any request already received by the daemon.
            before = snapshot(source)
            report = invoke(client, source, "doctor", "--directory", str(directory))
            assert report["adapter_ready"] and report["model_availability"] == "unknown"
            assert report["destinations"][0]["messages_remaining"] == 0
            assert report["destinations"][0]["status"] == "budget_exhausted"
            assert before == snapshot(source), "doctor renewed a lease or changed messages/budgets"
            invoke(client, source, "start", "--directory", str(directory), success=False)
            assert before == snapshot(source), "start adopted an existing instance"
            original_profile = (directory / "profile.json").read_bytes()
            profile = json.loads(original_profile)
            (directory / "profile.json").write_text(json.dumps({**profile, "phase": "preparing"}))
            invoke(client, source, "start", "--directory", str(directory), success=False)
            assert before == snapshot(source), "preparing recovery rotated an already-bound attachment"
            (directory / "profile.json").write_bytes(original_profile)
            sender.process.send_signal(signal.SIGCONT)
            paused = None

            # Conflicting setup rolls back its new session and activity.
            sender.process.send_signal(signal.SIGSTOP)
            paused = sender
            before = snapshot(source)
            args = ["setup", "--directory", str(root / "conflict"), "--agent", mine["id"],
                    "--harness", "claude-code", "--integrations", str(script.parent.parent), "--runner", str(node), "--option", "executable="+str(claude), "--expires-at", timestamp(900)]
            invoke(client, source, *args, success=False)
            assert before == snapshot(source) and not (root / "conflict").exists()
            sender.process.send_signal(signal.SIGCONT)
            paused = None

            # The new setup and diagnostic routes stay off the adapter router.
            for method, path in [("POST", "/v1/adapters/setup"),
                                 ("POST", f'/v1/adapters/{secret["adapter"]["id"]}/verify-credential'),
                                 ("GET", f'/v1/adapters/{secret["adapter"]["id"]}/route-status')]:
                # Without a body: the daemon may answer 404 and close before reading one.
                c = UnixHTTPConnection(source.state / "adapter.sock")
                c.request(method, path)
                response = c.getresponse()
                assert response.status == 404
                response.read(); c.close()

            # Stale token, revocation, and offline-state diagnosis.
            rotated = source.cli("adapter", "rotate", secret["adapter"]["id"])
            report = invoke(client, source, "doctor", "--directory", str(directory), success=False)
            assert next(c for c in report["checks"] if c["name"] == "credential")["status"] == "error"
            (directory / "credential.json").write_text(json.dumps(rotated))
            # Update the deterministic consumer's private file as an owner does.
            sender.credential_path.write_text(json.dumps(rotated)); sender.credential_path.chmod(0o600)
            wait(lambda: source.cli("adapter", "connection", secret["adapter"]["id"])["state"] == "ready")
            source.stop(crash=True); source.binary = str(replacement)
            assert source.start() == a
            wait(lambda: source.cli("adapter", "connection", secret["adapter"]["id"])["state"] == "ready", 25)
            assert invoke(client, source, "doctor", "--directory", str(directory))["adapter_ready"]
            source.cli("adapter", "revoke", secret["adapter"]["id"])
            report = invoke(client, source, "doctor", "--directory", str(directory), success=False)
            assert report["connection"]["state"] == "revoked"

            # A bad route after a valid route rolls back the entire owner setup.
            independent = source.cli("agent", "register", "--name", "rollback", "--owner", "tester")
            bad_auth = root / "unauthenticated Claude"
            fake_claude(bad_auth)
            bad_auth.write_text(bad_auth.read_text().replace('"loggedIn":True', '"loggedIn":False'))
            before = snapshot(source)
            invoke(client, source, "setup", "--directory", str(root / "bad auth"), "--agent", independent["id"],
                   "--harness", "claude-code", "--integrations", str(script.parent.parent), "--runner", str(node), "--option", "executable="+str(bad_auth), "--expires-at", timestamp(900), success=False)
            assert before == snapshot(source) and not (root / "bad auth").exists()
            request = {"agent_id": independent["id"], "session_id": "session_" + secrets.token_hex(16),
                       "integration": "claude-code", "expires_at": timestamp(900),
                       "routes": [{**route, "expires_at": timestamp(600), "max_message_bytes": 1024},
                                  {**route, "name": "bad", "peer_host_id": "host_" + "0" * 64, "expires_at": timestamp(600), "max_message_bytes": 1024}]}
            before = snapshot(source)
            for routes in [[None], [{**request["routes"][0], "unknown": True}],
                           [{**request["routes"][0], "max_messages": None}], request["routes"][:1] * 101]:
                assert source.call("POST", "/v1/adapters/setup", {**request, "routes": routes})[0] == 400
                assert before == snapshot(source)
            assert source.call("POST", "/v1/adapters/setup", request)[0] == 404
            assert before == snapshot(source)
            # A commit failure after all insertions also rolls back.
            sql(source, "CREATE TRIGGER fail_setup BEFORE INSERT ON events WHEN NEW.kind='adapter.route_created' BEGIN SELECT RAISE(ABORT,'test'); END")
            request["routes"] = request["routes"][:1]
            assert source.call("POST", "/v1/adapters/setup", request)[0] == 500
            assert before == snapshot(source)
            sql(source, "DROP TRIGGER fail_setup")

            # The response is lost after commit; the private preparing profile
            # recovers its exact session and credential, never another session.
            lost_dir = root / "lost response"
            proxy = DropSetupResponse(source)
            try:
                args = ["setup", "--directory", str(lost_dir), "--agent", independent["id"],
                        "--harness", "claude-code", "--integrations", str(script.parent.parent), "--runner", str(node), "--option", "executable="+str(claude), "--expires-at", timestamp(900)]
                invoke(client, source, *args, success=False)
                assert proxy.dropped
            finally:
                proxy.close()
            profile = json.loads((lost_dir / "profile.json").read_text())
            assert profile["phase"] == "preparing"
            original_sessions = source.cli("session", "list", "--agent", independent["id"])
            before = snapshot(source)
            assert not invoke(client, source, "doctor", "--directory", str(lost_dir), success=False)["adapter_ready"]
            assert before == snapshot(source), "doctor completed interrupted setup"
            invoke(client, source, "start", "--directory", str(lost_dir))
            assert source.cli("session", "list", "--agent", independent["id"]) == original_sessions
            assert json.loads((lost_dir / "profile.json").read_text())["phase"] == "configured"
            assert json.loads((lost_dir / "credential.json").read_text())["adapter"]["session_id"] == profile["session_id"]

            # A setup that would replace an offline instance must leave that
            # instance intact if a destination fails later in the transaction.
            responder.close(); channels.remove(responder)
            # Expired-lease fixture avoids a wall-clock wait; actual lease
            # expiry/reconnect races are covered by adapter_recovery.py.
            sql(receiver, "UPDATE adapter_connections SET lease_until_ms = 0 WHERE adapter_id = ?", (other_secret["adapter"]["id"],))
            before = snapshot(receiver)
            request = {"agent_id": target["id"], "session_id": "session_" + secrets.token_hex(16),
                       "integration": "claude-code", "expires_at": timestamp(900),
                       "routes": [{**route, "peer_host_id": "host_" + "0" * 64, "expires_at": timestamp(600), "max_message_bytes": 1024}]}
            assert receiver.call("POST", "/v1/adapters/setup", request)[0] == 404
            assert before == snapshot(receiver), "failed setup retired the old offline instance"
            replacement_dir = root / "replacement setup"
            setup(client, receiver, target, replacement_dir, node, claude, script)
            new_secret = json.loads((replacement_dir / "credential.json").read_text())
            assert new_secret["replaced_adapter_ids"] == [other_secret["adapter"]["id"]]
            assert receiver.cli("session", "inspect", other_secret["adapter"]["session_id"])["state"] == "detached"
        finally:
            if paused is not None:
                paused.process.send_signal(signal.SIGCONT)
            for channel in reversed(channels):
                channel.close()
            source.stop(); receiver.stop()
            source.logs.close(); receiver.logs.close()
    print(f"PASS {label}: private setup/launch, real MCP exchange, read-only readiness/budgets, conflicts/rollback, rotation/restart/revocation, lost-response recovery", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ["go", "rust", "node"]:
        parser.add_argument("--" + flag, type=Path, required=True)
    args = parser.parse_args()
    binaries = {"Go": args.go.resolve(), "Rust": args.rust.resolve()}
    for client in binaries:
        for daemon in binaries:
            replacement = binaries["Rust" if daemon == "Go" else "Go"]
            check(binaries[client], binaries[daemon], binaries[client], replacement, args.node.resolve(), f"{client} CLI / {daemon} daemon")


if __name__ == "__main__":
    main()
