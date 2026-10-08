"""Own one isolated interactive Claude session for explicit live experiments."""

import fcntl
import json
import os
from pathlib import Path
import pty
import re
import signal
import struct
import subprocess
import termios
import threading
import time
import uuid


def wait_for(check, seconds=60):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("live Claude condition timed out")


def session_environment():
    """The test session's environment, without an enclosing Claude session's
    variables, which would otherwise attach it to that session's state."""
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("CLAUDE_CODE_", "CLAUDE_PID", "CLAUDE_EFFORT")) and key not in ("CLAUDECODE", "AI_AGENT")
    }
    return dict(env, TERM="xterm-256color")


DEFAULT_TOOLS = ["list_destinations", "send", "send_status", "reply"]


class ClaudeSession:
    def __init__(self, claude, node, script, host, secret, directory, launch=None, credential_path=None,
                 allowed_tools=DEFAULT_TOOLS):
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.sid = str(uuid.uuid4())
        self.console = bytearray()
        self.debug_path = directory / "debug.log"
        cp = credential_path or directory / "credential.json"
        if credential_path is None:
            cp.write_text(json.dumps(secret))
            cp.chmod(0o600)
        config = directory / "mcp.json"
        config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "capsule": {
                            "command": str(node),
                            "args": [
                                str(script),
                                "--socket",
                                str(host.state / "adapter.sock"),
                                "--credential-file",
                                str(cp),
                                "--poll-ms",
                                "100",
                            ],
                        }
                    }
                }
            )
        )
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))

        def terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        command = [
            str(claude),
            "--session-id",
            self.sid,
            "--strict-mcp-config",
            "--mcp-config",
            str(config),
            "--settings",
            '{"disableAllHooks":true}',
            "--setting-sources",
            "",
            "--tools",
            "",
            "--allowedTools",
            ",".join("mcp__capsule__" + name for name in allowed_tools),
            "--permission-mode",
            "dontAsk",
            "--disable-slash-commands",
            "--dangerously-load-development-channels",
            "server:capsule",
            "--debug-file",
            str(self.debug_path),
        ]
        if launch is not None:
            # The public launcher supplies its generated MCP/channel options;
            # test-only settings still restrict this experiment to Capsule.
            for flag in ["--mcp-config", "--dangerously-load-development-channels"]:
                index = command.index(flag)
                del command[index:index + 2]
            command = launch + ["--"] + command[1:]
        self.process = subprocess.Popen(
            command,
            cwd=directory,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=session_environment(),
            preexec_fn=terminal,
        )
        os.close(slave)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.console.extend(chunk)
            if len(self.console) > 1048576:
                del self.console[:-524288]

    def running(self):
        assert self.process.poll() is None, "test Claude session exited"

    def screen(self):
        self.running()
        return re.sub(
            r"\s+",
            " ",
            re.sub(
                r"\x1b\[[0-?]*[ -/]*[@-~]", " ", self.console.decode(errors="replace")
            ),
        )

    def debug(self):
        self.running()
        return self.debug_path.read_text() if self.debug_path.exists() else ""

    def ready(self):
        self.startup_stage = "workspace_confirmation"
        wait_for(
            lambda: "Accessing" in self.screen()
            and "Enter to confirm" in self.screen(),
            20,
        )
        time.sleep(0.5)
        os.write(self.master, b"\x1b[B\r")
        self.startup_stage = "channel_confirmation"
        wait_for(
            lambda: "Loading" in self.screen()
            and "development" in self.screen()
            and "channels" in self.screen(),
            20,
        )
        os.write(self.master, b"\r")
        self.startup_stage = "channel_registration"
        wait_for(lambda: "Channel notifications registered" in self.debug(), 30)
        self.startup_stage = "ready"

    def prompt(self, text):
        # Bracketed paste avoids terminal interpretation of punctuation/newlines.
        os.write(self.master, b"\x1b[200~" + text.encode() + b"\x1b[201~")
        time.sleep(0.1)
        os.write(self.master, b"\r")

    def assistant_said(self, marker):
        self.running()
        # Read only this experiment's explicitly selected UUID transcript.
        for path in (Path.home() / ".claude/projects").glob("*/" + self.sid + ".jsonl"):
            for line in path.read_text().splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("type") == "assistant":
                    content = entry.get("message", {}).get("content", [])
                    if any(
                        block.get("type") == "text"
                        and any(line.strip() == marker for line in block.get("text", "").splitlines())
                        for block in content
                    ):
                        return True
        return False

    def tool_exchanges(self, name):
        """Read tool calls/results only from this experiment's UUID transcript."""
        self.running()
        calls = {}
        for path in (Path.home() / ".claude/projects").glob("*/" + self.sid + ".jsonl"):
            for line in path.read_text().splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                blocks = entry.get("message", {}).get("content", [])
                if not isinstance(blocks, list):
                    continue
                for block in blocks:
                    if (
                        entry.get("type") == "assistant"
                        and block.get("type") == "tool_use"
                        and block.get("name") == name
                    ):
                        calls.setdefault(
                            block["id"], {"input": block.get("input", {}), "result": None}
                        )
                    elif (
                        block.get("type") == "tool_result"
                        and block.get("tool_use_id") in calls
                    ):
                        content = block.get("content", [])
                        texts = (
                            [content] if isinstance(content, str) else [
                                part.get("text", "") for part in content
                                if part.get("type") == "text"
                            ]
                        )
                        for text in texts:
                            try:
                                calls[block["tool_use_id"]]["result"] = json.loads(text)
                            except json.JSONDecodeError:
                                pass
        return list(calls.values())

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        os.close(self.master)
        self.reader.join(timeout=1)
