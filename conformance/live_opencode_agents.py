#!/usr/bin/env python3
"""Opt-in model check against two caller-selected, running OpenCode sessions.

This runner starts only disposable Capsule daemons and sidecars. OpenCode must
already be running with the plugin installed and a working model selected.
"""

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import time
import urllib.parse
import urllib.request

from claude_setup import invoke, wait
from codex_integration import Harness, ROOT
from peer_messaging import PeerHost, timestamp


class Conversation:
    def __init__(self, server, session_id, directory, bindings, auth_file=None):
        url = urllib.parse.urlsplit(server)
        if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"}
                or url.username or url.password or url.path not in {"", "/"}
                or url.query or url.fragment):
            raise ValueError("Select an existing loopback OpenCode server")
        self.server = server.rstrip("/")
        self.session_id, self.directory, self.bindings = session_id, directory, bindings
        self.auth_file = auth_file
        self.headers = {}
        if auth_file:
            metadata = auth_file.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o077):
                raise ValueError("The server auth file must be private and account-owned")
            auth = json.loads(auth_file.read_text())
            token = base64.b64encode((auth["username"] + ":" + auth["password"]).encode()).decode()
            self.headers["Authorization"] = "Basic " + token

    def request(self, method, path, body=None):
        url = self.server + path + ("&" if "?" in path else "?") + urllib.parse.urlencode({"directory": str(self.directory)})
        headers = {"Accept": "application/json", **self.headers, **({"Content-Type": "application/json"} if body is not None else {})}
        request = urllib.request.Request(url, None if body is None else json.dumps(body).encode(), headers, method=method)
        # An attachment endpoint must not redirect native credentials elsewhere.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(request, timeout=15) as response:
            encoded = response.read(1048577)
            if len(encoded) > 1048576:
                raise ValueError("OpenCode response exceeds 1 MiB")
            return json.loads(encoded) if encoded else None

    def state(self):
        session = self.request("GET", "/session/" + self.session_id)
        assert session["id"] == self.session_id and session["directory"] == str(self.directory)
        assert "archived" not in session.get("time", {})
        return session

    def messages(self):
        return self.request("GET", "/session/" + self.session_id + "/message?limit=100")

    def idle(self):
        wait(lambda: self.request("GET", "/session/status").get(self.session_id, {}).get("type", "idle") == "idle", 180)

    def submit(self, text):
        self.idle()
        latest = self.messages()[-1]["info"]
        model = latest.get("model") or {"providerID": latest["providerID"], "modelID": latest["modelID"]}
        message_id = "msg_" + secrets.token_hex(16)
        self.request("POST", "/session/" + self.session_id + "/prompt_async", {
            "messageID": message_id, "model": model, "agent": latest["agent"],
            "parts": [{"type": "text", "text": text}],
        })
        return message_id

    def completed_text(self, parent_id=None, contains=None):
        matches = []
        for message in self.messages():
            info = message["info"]
            if info["role"] != "assistant" or (parent_id and info.get("parentID") != parent_id):
                continue
            if info.get("error"):
                raise AssertionError("OpenCode model turn failed: " + str(info["error"].get("name", "unknown")))
            if "completed" not in info.get("time", {}):
                continue
            text = "\n".join(part["text"] for part in message["parts"] if part["type"] == "text")
            if not contains or contains in text:
                matches.append(text)
        return "\n".join(matches)


def setup(client, host, agent, profile, node, route, conversation):
    routes = profile.with_suffix(".routes.json")
    routes.write_text(json.dumps([route]))
    options = {"server": conversation.server, "session": conversation.session_id,
               "directory": str(conversation.directory), "bindings": str(conversation.bindings)}
    if conversation.auth_file:
        options["auth-file"] = str(conversation.auth_file)
    option_args = [item for key, value in options.items() for item in ["--option", key + "=" + value]]
    invoke(client, host, "setup", "--harness", "opencode", "--integrations", str(ROOT / "integrations"),
           "--runner", str(node), *option_args, "--directory", str(profile), "--agent", agent["id"],
           "--expires-at", timestamp(1800), "--routes", str(routes))


def run(args):
    conversations = [Conversation(getattr(args, "server_" + name), getattr(args, "session_" + name),
                                 getattr(args, "directory_" + name), getattr(args, "bindings_" + name),
                                 getattr(args, "auth_file_" + name)) for name in ["a", "b"]]
    left, right = conversations
    assert (left.server, left.session_id) != (right.server, right.session_id)
    before = [conversation.state() for conversation in conversations]
    phrases = ["before-capsule-" + secrets.token_hex(8) for _ in conversations]
    for conversation, phrase in zip(conversations, phrases):
        message_id = conversation.submit("Remember your private validation phrase: " + phrase +
            ". When a Capsule peer asks for your pre-attachment phrase, return it using the capsule_reply tool and the incoming delivery_id. Acknowledge with BASELINE_READY without tools.")
        wait(lambda: "BASELINE_READY" in conversation.completed_text(parent_id=message_id), 180)
        conversation.idle()

    with tempfile.TemporaryDirectory(prefix="capsule-existing-opencode-") as td:
        root = Path(td)
        a, b = PeerHost(args.go, root / "alice"), PeerHost(args.rust, root / "bob")
        bridges = []
        try:
            ai, bi = a.start(), b.start()
            a.configure(b, bi); b.configure(a, ai)
            aa = a.cli("agent", "register", "--name", "alice", "--owner", "alice")
            ba = b.cli("agent", "register", "--name", "bob", "--owner", "bob")
            ag, bg = a.grant(bi, aa), b.grant(ai, ba)
            def route(peer, agent, grant):
                return {"name": "remote", "peer_host_id": peer["id"], "target_agent_id": agent["id"], "grant_id": grant["id"], "max_messages": 2}
            setup(args.go, a, aa, root / "left", args.node, route(bi, ba, bg), left)
            setup(args.rust, b, ba, root / "right", args.node, route(ai, aa, ag), right)
            alice = Harness(args.go, a, root / "left"); bridges.append(alice)
            bob = Harness(args.rust, b, root / "right"); bridges.append(bob)
            def exchange(sender, receiver, conversation, phrase):
                conversation.submit("Use capsule_send to send to remote: Return your private pre-attachment validation phrase using capsule_reply. Omit request_id for this new send so Capsule generates it. Call capsule_send_status once for the returned request_id. When the kind=reply input arrives, report its exact content in your final answer. Do not use other tools.")
                rejected = []
                def successful_tool(bridge, name):
                    deadline = time.monotonic() + 180
                    while time.monotonic() < deadline:
                        event = bridge.event("tool_result", seconds=max(1, deadline - time.monotonic()), tool=name)
                        if event["success"]:
                            return event
                        rejected.append({"tool": name, "error": event["content"]})
                        assert len(rejected) <= 3, rejected
                    raise AssertionError("No successful " + name + " call")
                sent = successful_tool(sender, "send")
                successful_tool(receiver, "reply")
                status = successful_tool(sender, "send_status")
                sender.event("input_accepted", seconds=180, kind="reply")
                wait(lambda: conversation.completed_text(contains=phrase), 180)
                conversation.idle()
                return {"scoped_send": json.loads(sent["content"][0]["text"])["state"] == "accepted",
                        "send_status": json.loads(status["content"][0]["text"])["state"] == "accepted",
                        "model_called_reply": True, "model_observed_pre_attachment_phrase": True,
                        "rejected_model_calls_before_correction": rejected,
                        "sender_model_output": conversation.completed_text(contains=phrase)}
            forward = exchange(alice, bob, left, phrases[1]); right.idle()
            a.stop(); a.binary = str(args.rust); a.start()
            credential_path = root / "left/credential.json"
            credential = json.loads(credential_path.read_text())
            wait(lambda: a.cli("adapter", "connection", credential["adapter"]["id"])["state"] == "ready")
            rotated = a.cli("adapter", "rotate", credential["adapter"]["id"])
            temporary = credential_path.with_suffix(".next")
            temporary.write_text(json.dumps(rotated)); temporary.chmod(0o600); temporary.replace(credential_path)
            reverse = exchange(bob, alice, right, phrases[0]); left.idle()
            after = [conversation.state() for conversation in conversations]
            assert [session["id"] for session in after] == [session["id"] for session in before]
            assert [session.get("permission") for session in after] == [session.get("permission") for session in before]
            return {"timestamp": datetime.now(timezone.utc).isoformat(), "mode": "two already-running OpenCode server conversations; real models; local Go/Rust daemons",
                    "opencode_versions": [conversation.request("GET", "/global/health")["version"] for conversation in conversations],
                    "selected_sessions": [conversation.session_id for conversation in conversations],
                    "forward_Go_to_Rust": forward, "reverse_after_daemon_swap_and_token_rotation": reverse,
                    "session_ids_preserved": True, "native_permissions_unchanged": True,
                    "limits": ["One machine; cross-host connectivity is not established by this run.", "Existing server conversations tested; native TUI interaction is not separately verified."]}
        finally:
            for bridge in reversed(bridges):
                bridge.stop()
            a.stop(); b.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["go", "rust", "node", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ["a", "b"]:
        for option in ["server", "session"]:
            parser.add_argument("--" + option + "-" + name, required=True)
        for option in ["directory", "bindings"]:
            parser.add_argument("--" + option + "-" + name, type=Path, required=True)
        parser.add_argument("--auth-file-" + name, type=Path)
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.absolute())
    result = run(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
