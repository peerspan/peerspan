#!/usr/bin/env python3
"""Smoke-test a packaged Capsule archive through its installed layout."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import tarfile
import tempfile

from agent_adapter import Channel
from claude_setup import fake_claude
from peer_messaging import PeerHost


def run(binary, state, cwd, *args, success=True, env=None):
    result = subprocess.run(
        [str(binary), "--state", str(state), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=40,
        env=env,
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    assert "token_" not in result.stdout + result.stderr
    return json.loads(result.stdout) if result.stdout else result.stderr


def safe_members(archive):
    members = archive.getmembers()
    assert members, "archive is empty"
    roots = set()
    for member in members:
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and ".." not in path.parts, member.name
        roots.add(path.parts[0])
        if member.issym() or member.islnk():
            target = PurePosixPath(member.linkname)
            assert not target.is_absolute(), member.linkname
            linked = target if member.islnk() else path.parent / target
            normalized = PurePosixPath(posixpath.normpath(str(linked)))
            assert normalized.parts and normalized.parts[0] == path.parts[0], member.linkname
    assert len(roots) == 1, roots
    return members, roots.pop()


def check(archive_path, node):
    with tempfile.TemporaryDirectory(prefix="capsule installed bundle ") as td:
        root = Path(td)
        with tarfile.open(archive_path, "r:gz") as archive:
            members, original_name = safe_members(archive)
            archive.extractall(root, members=members, filter="data")

        original = root / original_name
        prefix = root / "moved capsule prefix"
        original.rename(prefix)
        binary = prefix / "bin/capsule-host"
        metadata = json.loads((prefix / "RELEASE.json").read_text())
        assert metadata["implementation"] in {"go", "rust"}
        assert metadata["os"] == "linux" and metadata["node_requirement"] == ">=22"
        assert os.access(binary, os.X_OK)

        runtime = root / "runtime bin"
        runtime.mkdir()
        (runtime / "node").symlink_to(node)
        (runtime / "python3").symlink_to(Path(os.sys.executable).resolve())
        old_path = os.environ.get("PATH")
        old_override = os.environ.pop("CAPSULE_INTEGRATIONS_DIR", None)
        os.environ["PATH"] = os.pathsep.join([str(prefix / "bin"), str(runtime)])

        integrations = prefix / "share/capsule/integrations"
        for path in [
            integrations / "shared/adapter.mjs",
            integrations / "claude-channel/integration.json",
            integrations / "codex/integration.json",
            integrations / "opencode/integration.json",
            integrations / "claude-channel/node_modules/@modelcontextprotocol/sdk/package.json",
            integrations / "codex/node_modules/ws/package.json",
            integrations / "opencode/node_modules/@opencode-ai/plugin/package.json",
        ]:
            assert path.exists(), path

        host = PeerHost(binary, root / "host state")
        channel = None
        try:
            host.start()
            agent = host.cli("agent", "register", "--name", "packaged", "--owner", "tester")
            claude = fake_claude(root / "Claude fixture")
            profile = root / "private profile"
            invalid = run(
                "capsule-host",
                host.state,
                root,
                "session",
                "setup",
                "--directory",
                str(root / "invalid expiry profile"),
                "--harness",
                "claude-code",
                "--option",
                "executable=" + str(claude),
                "--agent",
                agent["id"],
                "--expires-in",
                "1💥",
                success=False,
            )
            assert "whole-minute or whole-hour" in invalid
            configured = run(
                "capsule-host",
                host.state,
                root,
                "session",
                "setup",
                "--directory",
                str(profile),
                "--harness",
                "claude-code",
                "--option",
                "executable=" + str(claude),
                "--agent",
                agent["id"],
                "--expires-in",
                "15m",
            )
            assert configured["harness"] == "claude-code"
            expiry = datetime.fromisoformat(configured["expires_at"].replace("Z", "+00:00"))
            remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
            assert 840 <= remaining <= 900, remaining
            saved = json.loads((profile / "profile.json").read_text())
            assert Path(saved["harness"]["command"][1]).is_relative_to(prefix)

            missing_path = root / "empty path"
            missing_path.mkdir()
            missing_env = dict(os.environ, PATH=str(missing_path))
            error = run(
                binary,
                host.state,
                root,
                "session",
                "setup",
                "--directory",
                str(root / "missing node profile"),
                "--harness",
                "claude-code",
                "--option",
                "executable=" + str(claude),
                "--agent",
                agent["id"],
                "--expires-in",
                "15m",
                success=False,
                env=missing_env,
            )
            assert "executable is missing" in error
            report = run(
                "capsule-host",
                host.state,
                Path("/"),
                "session",
                "doctor",
                "--directory",
                str(profile),
                success=False,
            )
            assert report["connection"]["state"] == "registered"
            launched = run(
                "capsule-host",
                host.state,
                Path("/"),
                "session",
                "start",
                "--directory",
                str(profile),
                "--workspace",
                str(root),
            )
            assert "--dangerously-load-development-channels" in launched["arguments"]
            for name in ["profile.json", "credential.json", "mcp.json"]:
                assert (profile / name).stat().st_mode & 0o077 == 0

            secret = json.loads((profile / "credential.json").read_text())
            channel = Channel(
                node,
                integrations / "claude-channel/channel.mjs",
                host,
                secret,
                root / "packaged channel",
            )
            tools = channel.call("tools/list", {})["tools"]
            assert "list_destinations" in {tool["name"] for tool in tools}
            ready = run(
                "capsule-host",
                host.state,
                Path("/"),
                "session",
                "doctor",
                "--directory",
                str(profile),
            )
            assert ready["adapter_ready"]
        finally:
            if channel:
                channel.close()
            host.stop()
            host.logs.close()
            if old_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old_path
            if old_override is not None:
                os.environ["CAPSULE_INTEGRATIONS_DIR"] = old_override

        print(
            f"PASS {metadata['implementation']} installed bundle: relocated layout, "
            "packaged MCP runtime, setup, doctor, launch, and private files"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    args = parser.parse_args()
    check(args.archive.resolve(), args.node.resolve())


if __name__ == "__main__":
    main()
