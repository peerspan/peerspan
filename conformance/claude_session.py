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


class ClaudeSession:
    def __init__(self, claude, node, script, host, secret, directory):
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.sid = str(uuid.uuid4())
        self.console = bytearray()
        self.debug_path = directory / "debug.log"
        cp = directory / "credential.json"
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
            "mcp__capsule__list_destinations,mcp__capsule__send,mcp__capsule__reply",
            "--permission-mode",
            "dontAsk",
            "--disable-slash-commands",
            "--dangerously-load-development-channels",
            "server:capsule",
            "--debug-file",
            str(self.debug_path),
        ]
        self.process = subprocess.Popen(
            command,
            cwd=directory,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=dict(os.environ, TERM="xterm-256color"),
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
        wait_for(
            lambda: "Accessing" in self.screen()
            and "Enter to confirm" in self.screen(),
            20,
        )
        time.sleep(0.5)
        os.write(self.master, b"\x1b[B\r")
        wait_for(
            lambda: "Loading" in self.screen()
            and "development" in self.screen()
            and "channels" in self.screen(),
            20,
        )
        os.write(self.master, b"\r")
        wait_for(lambda: "Channel notifications registered" in self.debug(), 30)

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
                        block.get("type") == "text" and marker in block.get("text", "")
                        for block in content
                    ):
                        return True
        return False

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
