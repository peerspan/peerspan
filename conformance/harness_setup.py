#!/usr/bin/env python3
"""Verify native setup with a non-Claude integration and no Node on PATH."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

from adapter_recovery import connect
from agent_adapter import adapter_call
from claude_setup import DropSetupResponse, snapshot
from peer_messaging import PeerHost, timestamp


def invoke(client, host, *args, success=True):
    env = dict(os.environ, PATH=str(host.state.parent / "empty-path"))
    result = subprocess.run([str(client), "--state", str(host.state), "session", *args],
                            env=env, capture_output=True, text=True, timeout=40)
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    assert "token_" not in result.stdout + result.stderr, "CLI leaked a credential"
    return json.loads(result.stdout) if result.stdout else result.stderr


def catalog(root, launch=True, identity="file-fixture"):
    bundle = root / identity
    bundle.mkdir(parents=True)
    source = Path(__file__).with_name("fixtures") / "harness"
    for name in ["provider.py", "harness.py"]:
        shutil.copy2(source / name, bundle / name)
    manifest = {"version": 1, "id": identity,
                "command": [str(Path(sys.executable).resolve()), "./provider.py"],
                "operations": ["prepare", "check"] + (["launch"] if launch else [])}
    (bundle / "integration.json").write_text(json.dumps(manifest))
    return root


def setup(client, host, agent, directory, root, identity="file-fixture", *options):
    return invoke(client, host, "setup", "--directory", str(directory), "--harness", identity,
                  "--integrations", str(root), "--agent", agent["id"], "--expires-at", timestamp(900), *options)


def check(client, other_client, daemon, label):
    with tempfile.TemporaryDirectory(prefix="capsule-harness-setup-") as td:
        root = Path(td)
        host = PeerHost(daemon, root / "host")
        try:
            host.start()
            agent = host.cli("agent", "register", "--name", "fixture", "--owner", "tester")
            bundles = catalog(root / "integrations")
            directory = root / "private profile"
            marker = "literal $(touch unexpected) `shell`\nnewline"
            configured = setup(client, host, agent, directory, bundles, "file-fixture", "--option", "marker=" + marker)
            assert configured["harness"] == "file-fixture" and configured["launch_supported"]
            profile = json.loads((directory / "profile.json").read_text())
            assert profile["version"] == 2 and profile["provider_state"]["marker"] == marker
            assert profile["provider_state"]["transport"] == "json-file"
            assert "token" not in profile["provider_state"]["received_keys"]
            assert not (root / "unexpected").exists()
            for name in ["profile.json", "credential.json", "consumer.json"]:
                assert (directory / name).stat().st_mode & 0o077 == 0
            before = snapshot(host)
            report = invoke(other_client, host, "doctor", "--directory", str(directory), success=False)
            assert report["harness"] == "file-fixture" and report["connection"]["state"] == "registered"
            launched = invoke(other_client, host, "start", "--directory", str(directory), "--workspace", str(root), "--", "--example", marker)
            assert launched == {"arguments": ["--example", marker], "cwd": str(root)}
            assert before == snapshot(host), "launch minted another attachment"
            secret = json.loads((directory / "credential.json").read_text())
            assert connect(host, secret)[0] == 200
            # Live delivery readiness: the consumer verifies its channel.
            assert adapter_call(host, secret["token"], "POST", "/adapter/v1/ready",
                                {"nonce": secrets.token_hex(16)})[0] == 200
            before = snapshot(host)
            report = invoke(client, host, "doctor", "--directory", str(directory))
            assert report["adapter_ready"] and report["model_availability"] == "unknown" and report["message_consumption"] == "unverified"
            assert before == snapshot(host), "inspection changed a lease or activity"
            invoke(client, host, "start", "--directory", str(directory), success=False)
            assert before == snapshot(host), "launch adopted the bound instance"

            independent = host.cli("agent", "register", "--name", "independent", "--owner", "tester")
            for mode in ["malformed", "oversized", "stderr", "reserved-file", "traversal", "check-error"]:
                before = snapshot(host)
                bad_dir = root / ("bad-" + mode)
                result = invoke(client, host, "setup", "--directory", str(bad_dir), "--harness", "file-fixture",
                                "--integrations", str(bundles), "--agent", independent["id"], "--expires-at", timestamp(900),
                                "--option", "mode=" + mode, success=False)
                assert not bad_dir.exists() and before == snapshot(host), mode
                if mode == "check-error":
                    assert "[redacted]" in result

            # Losing the setup receipt recovers its exact profile using the
            # other implementation, independently of a Node bootstrap path.
            lost_dir = root / "lost-response"
            proxy = DropSetupResponse(host)
            try:
                invoke(client, host, "setup", "--directory", str(lost_dir), "--harness", "file-fixture",
                       "--integrations", str(bundles), "--agent", independent["id"], "--expires-at", timestamp(900), success=False)
                assert proxy.dropped
            finally:
                proxy.close()
            sid = json.loads((lost_dir / "profile.json").read_text())["session_id"]
            sessions = host.cli("session", "list", "--agent", independent["id"])
            invoke(other_client, host, "start", "--directory", str(lost_dir))
            assert host.cli("session", "list", "--agent", independent["id"]) == sessions
            assert json.loads((lost_dir / "credential.json").read_text())["adapter"]["session_id"] == sid

            # A file-only integration can configure and diagnose an external
            # consumer. Unsupported start refuses before setup recovery.
            catalog(bundles, launch=False, identity="external-fixture")
            external = host.cli("agent", "register", "--name", "external", "--owner", "tester")
            external_dir = root / "external-consumer"
            configured = setup(client, host, external, external_dir, bundles, "external-fixture")
            assert not configured["launch_supported"]
            original = (external_dir / "profile.json").read_bytes()
            profile = json.loads(original)
            profile["phase"] = "preparing"
            (external_dir / "profile.json").write_text(json.dumps(profile))
            (external_dir / "credential.json").unlink()
            before = snapshot(host)
            error = invoke(other_client, host, "start", "--directory", str(external_dir), success=False)
            assert "does not support launch" in error
            assert before == snapshot(host) and not (external_dir / "credential.json").exists()
            sid = profile["session_id"]
            # Recovery must also be usable by integrations without launch.
            resumed = invoke(other_client, host, "setup", "--directory", str(external_dir))
            assert resumed["session_id"] == sid and not resumed["launch_supported"]
            assert json.loads((external_dir / "profile.json").read_text())["phase"] == "configured"
            assert json.loads((external_dir / "credential.json").read_text())["adapter"]["session_id"] == sid
        finally:
            host.stop()
            host.logs.close()
    print(f"PASS {label}: non-Claude file integration without Node, cross-CLI profiles/recovery, read-only leases, literal launch, optional launch, malformed/oversized responses and artifact confinement", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["go", "rust"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    binaries = {"Go": args.go.resolve(), "Rust": args.rust.resolve()}
    for cli in binaries:
        for daemon in binaries:
            other = binaries["Rust" if cli == "Go" else "Go"]
            check(binaries[cli], other, binaries[daemon], f"{cli} CLI / {daemon} daemon")


if __name__ == "__main__":
    main()
