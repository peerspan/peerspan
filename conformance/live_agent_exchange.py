#!/usr/bin/env python3
"""Two real interactive Claude sessions initiate and receive replies via Capsule.

Uses real model calls. Built-in tools are disabled. Only temporary host/MCP
configuration is created; Claude records the test workspaces in normal account
state. No owner CLI send/fetch command participates in either exchange.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile

from agent_adapter import credential, sql
from adapter_outbound import route
from adapter_recovery import atomic_credential
from claude_session import ClaudeSession, wait_for
from peer_messaging import PeerHost


def check(args):
    script = (
        Path(__file__).resolve().parents[1] / "integrations/claude-channel/channel.mjs"
    )
    with tempfile.TemporaryDirectory(prefix="capsule-live-agents-") as directory:
        root = Path(directory)
        a = PeerHost(args.go.resolve(), root / "a")
        b = PeerHost(args.rust.resolve(), root / "b")
        ca = cb = None
        try:
            ai, bi = a.start(), b.start()
            a.configure(b, bi)
            b.configure(a, ai)
            aa = a.cli("agent", "register", "--name", "alice", "--owner", "alice")
            ba = b.cli("agent", "register", "--name", "bob", "--owner", "bob")
            ass = a.cli(
                "session",
                "attach",
                "--agent",
                aa["id"],
                "--integration",
                "claude-channel",
            )
            bss = b.cli(
                "session",
                "attach",
                "--agent",
                ba["id"],
                "--integration",
                "claude-channel",
            )
            ac, bc = credential(a, ass), credential(b, bss)
            ag, bg = a.grant(bi, aa), b.grant(ai, ba)
            route(a, ac, bi, ba, bg, budget=4)
            route(b, bc, ai, aa, ag, budget=4)
            ca = ClaudeSession(
                args.claude.resolve(),
                args.node.resolve(),
                script,
                a,
                ac,
                root / "claude-a",
            )
            cb = ClaudeSession(
                args.claude.resolve(),
                args.node.resolve(),
                script,
                b,
                bc,
                root / "claude-b",
            )
            ca.ready()
            cb.ready()
            session_pids = [ca.process.pid, cb.process.pid]
            print(
                "Both interactive Claude sessions registered their Capsule channels.",
                flush=True,
            )
            ca.prompt(
                'This is a Capsule integration experiment. Use list_destinations, then the Capsule send tool to send to destination remote this exact message: "Use the Capsule reply tool to respond with exactly BOB_REPLY_MARKER." After its kind=reply channel event arrives, respond in your own terminal with exactly AUTO_REPLY_OBSERVED_A. The send result alone is not the reply. Do not initiate any additional sends. Keep responding to later authorized kind=message events using the Capsule reply tool, even after your own exchange finishes. Use only Capsule tools.'
            )
            if args.restart_pending:
                wait_for(lambda: sql(b, "SELECT request_id FROM received_messages"), 60)
                a.stop(crash=True)
                a.binary = str(args.rust.resolve())
                assert a.start() == ai
                rotated = a.cli("adapter", "rotate", ac["adapter"]["id"])
                assert rotated["adapter"] == ac["adapter"]
                atomic_credential(ca.directory / "credential.json", rotated)
                print(
                    "Restarted Alice daemon and rotated its token while its exchange was pending.",
                    flush=True,
                )
            wait_for(lambda: ca.assistant_said("AUTO_REPLY_OBSERVED_A"), 90)
            assert len(sql(a, "SELECT request_id FROM adapter_outbound")) == 1
            out = json.loads(sql(a, "SELECT record FROM outbound_messages")[0][0])
            rid = out["request"]["request_id"]
            reply = json.loads(
                sql(
                    a, "SELECT record FROM outbound_replies WHERE request_id=?", (rid,)
                )[0][0]
            )
            assert reply["content"] == "BOB_REPLY_MARKER"
            notice = json.loads(
                sql(
                    a,
                    "SELECT reply_delivery FROM adapter_outbound WHERE request_id=?",
                    (rid,),
                )[0][0]
            )
            assert notice["state"] == "forwarded" and notice["session_id"] == ass["id"]
            print(
                "Alice initiated a send; Bob replied; Alice observed the automatic reply.",
                flush=True,
            )
            cb.prompt(
                'Now independently use list_destinations and the Capsule send tool to send to destination remote this exact message: "Use the Capsule reply tool to respond with exactly ALICE_REPLY_MARKER." After its kind=reply channel event arrives, respond in your own terminal with exactly AUTO_REPLY_OBSERVED_B. The send result alone is not the reply. Do not initiate any additional sends. Keep responding to later authorized kind=message events using the Capsule reply tool, even after your own exchange finishes. Use only Capsule tools.'
            )
            if args.restart_pending:
                wait_for(lambda: sql(a, "SELECT request_id FROM received_messages"), 60)
                b.stop(crash=True)
                b.binary = str(args.go.resolve())
                assert b.start() == bi
                rotated = b.cli("adapter", "rotate", bc["adapter"]["id"])
                assert rotated["adapter"] == bc["adapter"]
                atomic_credential(cb.directory / "credential.json", rotated)
                print(
                    "Restarted Bob daemon and rotated its token while its exchange was pending.",
                    flush=True,
                )
            wait_for(lambda: cb.assistant_said("AUTO_REPLY_OBSERVED_B"), 90)
            assert len(sql(b, "SELECT request_id FROM adapter_outbound")) == 1
            out2 = json.loads(sql(b, "SELECT record FROM outbound_messages")[0][0])
            rid2 = out2["request"]["request_id"]
            reply2 = json.loads(
                sql(
                    b, "SELECT record FROM outbound_replies WHERE request_id=?", (rid2,)
                )[0][0]
            )
            assert reply2["content"] == "ALICE_REPLY_MARKER"
            notice2 = json.loads(
                sql(
                    b,
                    "SELECT reply_delivery FROM adapter_outbound WHERE request_id=?",
                    (rid2,),
                )[0][0]
            )
            assert (
                notice2["state"] == "forwarded" and notice2["session_id"] == bss["id"]
            )
            assert ca.process.poll() is None and cb.process.poll() is None
            assert [ca.process.pid, cb.process.pid] == session_pids
            if args.restart_pending:
                assert (
                    len(
                        [
                            e
                            for e in a.cli("activity")
                            if e["kind"] == "session.reconnected"
                        ]
                    )
                    == 1
                )
                assert (
                    len(
                        [
                            e
                            for e in b.cli("activity")
                            if e["kind"] == "session.reconnected"
                        ]
                    )
                    == 1
                )
            print(
                "Bob independently initiated a send; Alice replied; Bob observed the automatic reply.",
                flush=True,
            )
            return {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "claude_version": subprocess.check_output(
                    [str(args.claude.resolve()), "--version"], text=True
                ).strip(),
                "mcp_protocols": [
                    re.search(
                        r'"negotiatedProtocolVersion":"([^"]+)"', c.debug()
                    ).group(1)
                    for c in [ca, cb]
                ],
                "host_pairing": "Go↔Rust",
                "daemon_restart_while_pending_both_directions": args.restart_pending,
                "credential_rotation_both_directions": args.restart_pending,
                "same_session_process_ids": True,
                "post_restart_host_pairing": (
                    "Rust↔Go" if args.restart_pending else None
                ),
                "two_same_running_sessions": True,
                "agent_initiated_both_directions": True,
                "model_observed_automatic_replies_both_directions": True,
                "owner_cli_send_or_reply_fetch": False,
                "builtin_tools_enabled": False,
                "permission_relay_enabled": False,
                "limitations": [
                    "Two isolated hosts over loopback, not separate physical machines.",
                    "Replacing an adapter process, extending authorization lifetime, and full conversation/task lifecycle remain separate milestones.",
                ],
            }
        except Exception:
            for name, c in [("alice", ca), ("bob", cb)]:
                if c and c.debug_path.exists():
                    print(
                        name + " channel trace:",
                        "\n".join(
                            line
                            for line in c.debug_path.read_text().splitlines()
                            if 'MCP server "capsule"' in line
                        )[-3000:],
                        flush=True,
                    )
            raise
        finally:
            if ca:
                ca.close()
            if cb:
                cb.close()
            a.stop()
            b.stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ["go", "rust", "node", "claude", "output"]:
        p.add_argument("--" + flag, type=Path, required=True)
    p.add_argument(
        "--restart-pending",
        action="store_true",
        help="Restart each originating daemon and rotate its token while waiting for a reply",
    )
    args = p.parse_args()
    report = check(args)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Live two-agent exchange passed:", args.output, flush=True)


if __name__ == "__main__":
    main()
