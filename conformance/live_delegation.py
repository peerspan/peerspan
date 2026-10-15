#!/usr/bin/env python3
"""Live acceptance of multi-hop task delegation (milestone 6 slice 5).

Three hosts on loopback join one network under the Go coordinator: Alice
(Go), Bob (Rust), and Carol (Go) by default; --mix swaps them. Each has a real
interactive Claude Code session attached through the claude-channel
integration with built-in tools disabled. The owners set up agents, sessions,
credentials, grants, and routes with the CLI. The models then drive the flow
through Peerspan MCP tools only: Alice delegates to Bob; Bob accepts and passes
a subtask on to Carol with parent_task_id; Carol accepts, reports progress, and
completes with an output and a result artifact; Bob saves the artifact and
completes the parent with Carol's result; Alice observes the final update.

The harness verifies the outcome from host state: the 2-link chain Carol
received, every task's state, artifact digests at Carol, Bob, and the saved
file, and that each task was submitted by an adapter route rather than an
owner CLI task command.

Uses real model calls. With --fixture, deterministic MCP consumers (the real
channel subprocess, no model) drive the same flow instead.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from agent_adapter import Channel, sql
from claude_session import ClaudeSession, wait_for
from coordination import Coordinator, CoordHost
from coordination import wait_for as wait_until
from peer_messaging import timestamp
from tasks import channel_event, tool

TOOLS = [
    "list_destinations",
    "delegate_task",
    "task_accept",
    "task_reject",
    "task_progress",
    "task_complete",
    "task_status",
    "artifact_save",
]
# Status polling of a delegated task backs off to a minute while it is idle.
FLOW_SECONDS = 480
NAMES = {"G": "Go", "R": "Rust"}


def setup(binaries, coord_binary, root):
    """Owner setup with the CLI only: network, agents, sessions, grants, routes."""
    coord = Coordinator(coord_binary, root / "coord")
    alice, bob, carol = (
        CoordHost(binary, root / name)
        for binary, name in zip(binaries, ("alice", "bob", "carol"))
    )
    hosts = (alice, bob, carol)
    ctx = {"coord": coord, "hosts": hosts, "alice": alice, "bob": bob, "carol": carol}
    coordinator = coord.start()
    A, B, C = (host.start()["id"] for host in hosts)
    ctx.update(A=A, B=B, C=C)
    net = alice.cli(
        "network", "create", "--name", "team", "--member", "alice",
        "--coordinator", coord.address, "--coordinator-key", coordinator["public_key"],
    )["id"]
    for host, member in ((bob, "bob"), (carol, "carol")):
        invite = alice.cli(
            "network", "invite", "--network", net, "--member", member,
            "--expires-at", timestamp(), "--host-only",
        )
        host.cli("network", "join", "--token", invite["token"])
    for host in hosts:
        host.cli("network", "sync", net)
    for host in hosts:
        wait_until(lambda: len(host.cli("network", "members", net)) == 3, timeout=20, message="three members")
    agents = {
        "alice": alice.cli("agent", "register", "--name", "alice", "--owner", "alice"),
        "bob": bob.cli("agent", "register", "--name", "bob", "--owner", "bob"),
        "carol": carol.cli("agent", "register", "--name", "carol", "--owner", "carol"),
    }
    sessions, secrets_ = {}, {}
    for name, host in (("alice", alice), ("bob", bob), ("carol", carol)):
        sessions[name] = host.cli(
            "session", "attach", "--agent", agents[name]["id"], "--integration", "claude-channel"
        )
        secrets_[name] = host.cli(
            "adapter", "create", "--session", sessions[name]["id"], "--expires-at", timestamp(3600)
        )
    # Bob's owner lets Alice's host delegate to bob, who may pass it on.
    to_bob = bob.cli(
        "grant", "create", "--peer", A, "--agent", agents["bob"]["id"],
        "--expires-at", timestamp(7200), "--action", "task.delegate",
    )
    # Carol's owner authorizes the originator, Alice's host, with artifacts.
    to_carol = carol.cli(
        "grant", "create", "--peer", A, "--agent", agents["carol"]["id"],
        "--expires-at", timestamp(7200), "--action", "task.submit", "--max-artifact-bytes", "65536",
    )
    assert to_bob["action"] == "task.delegate" and to_carol["max_artifact_bytes"] == 65536
    routes = {
        "alice": alice.cli(
            "adapter", "route", "add", "--adapter", secrets_["alice"]["adapter"]["id"], "--name", "bob",
            "--peer", B, "--agent", agents["bob"]["id"], "--grant", to_bob["id"], "--action", "task.submit",
            "--delegation-depth", "1", "--expires-at", timestamp(3000),
        ),
        "bob": bob.cli(
            "adapter", "route", "add", "--adapter", secrets_["bob"]["adapter"]["id"], "--name", "carol",
            "--peer", C, "--agent", agents["carol"]["id"], "--grant", to_carol["id"], "--action", "task.submit",
            "--expires-at", timestamp(3000),
        ),
    }
    assert routes["alice"]["delegation_depth"] == 1, routes
    nonce = secrets.token_hex(4)
    work = {name: root / f"{name}-work" for name in ("alice", "bob", "carol")}
    for directory in work.values():
        directory.mkdir(mode=0o700)
    result = work["carol"] / "result.txt"
    result.write_text(f"Carol's measured result {nonce}: 3 hops, 2 links, 1 artifact.\n")
    ctx.update(
        net=net, agents=agents, sessions=sessions, secrets=secrets_, routes=routes,
        grants={"bob": to_bob, "carol": to_carol}, nonce=nonce, result=result,
        saved=work["bob"] / "carol-result.txt", carol_output=f"CAROL_RESULT_{nonce}", work=work,
        digest=hashlib.sha256(result.read_bytes()).hexdigest(),
    )
    return ctx


def fixture_flow(ctx, node, script, root):
    """Deterministic MCP consumers drive the same tool sequence as the models."""
    channels = {}
    observed = {}
    try:
        for name in ("alice", "bob", "carol"):
            channels[name] = Channel(node, script, ctx[name], ctx["secrets"][name], root / f"{name}-channel")
        a, b, c = channels["alice"], channels["bob"], channels["carol"]
        failed, out = tool(a, "delegate_task", {"destination": "bob", "input": "Get Carol's result file."})
        assert not failed and out["submit_state"] == "accepted", out
        parent = channel_event(b, "task")
        assert parent["meta"]["delegable"] is True, parent
        assert not tool(b, "task_accept", {"task_id": parent["meta"]["task_id"]})[0]
        failed, sub = tool(b, "delegate_task", {
            "destination": "carol", "input": "Produce the result file.", "parent_task_id": parent["meta"]["task_id"]})
        assert not failed and sub["submit_state"] == "accepted", sub
        child = channel_event(c, "task")
        observed["carol_task_meta"] = child["meta"]
        tid = child["meta"]["task_id"]
        assert not tool(c, "task_accept", {"task_id": tid})[0]
        assert not tool(c, "task_progress", {"task_id": tid, "message": "carol is preparing the result"})[0]
        failed, done = tool(c, "task_complete", {"task_id": tid, "status": "succeeded",
                                                 "output": ctx["carol_output"], "artifacts": [str(ctx["result"])]})
        assert not failed, done
        while True:
            update = channel_event(b, "task_update")
            if update["meta"]["state"] == "succeeded":
                break
        artifact = update["meta"]["artifacts"][0]
        # The submitter fetches results after storing the final event, so the
        # first save may report the result as not fetched yet.
        saved = wait_for(lambda: (lambda out: None if out[0] else out[1])(tool(
            b, "artifact_save", {"task_id": sub["task_id"], "sha256": artifact["sha256"], "path": str(ctx["saved"])})),
            30)
        failed, done = tool(b, "task_complete", {"task_id": parent["meta"]["task_id"], "status": "succeeded",
                                                 "output": "BOB_FORWARDED: " + update["content"]})
        assert not failed, done
        while True:
            final = channel_event(a, "task_update")
            if final["meta"]["state"] == "succeeded":
                break
        observed["alice_final"] = final["content"]
        return observed
    finally:
        for channel in channels.values():
            channel.close()


def transcript(session):
    """The raw lines of this experiment's selected UUID transcript."""
    return "\n".join(
        path.read_text() for path in (Path.home() / ".claude/projects").glob("*/" + session.sid + ".jsonl")
    )


def assistant_text(session):
    texts = []
    for line in transcript(session).splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("type") == "assistant":
            for block in entry.get("message", {}).get("content", []):
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))
    return "\n".join(texts)


def live_prompts(ctx):
    preamble = "This is a Peerspan integration experiment. Use only Peerspan tools, and only the calls described here. "
    carol = preamble + (
        "You are Carol. When a kind=task channel event arrives: (1) call task_accept with its task_id; "
        '(2) call task_progress with that task_id and the message "carol is preparing the result"; '
        f'(3) call task_complete with that task_id, status succeeded, output exactly "{ctx["carol_output"]}", '
        f'and artifacts ["{ctx["result"]}"]. Then respond in your own terminal with exactly CAROL_TASK_COMPLETED. '
        "Handle only that one task. Right now, respond with exactly CAROL_STANDING_BY and wait for the event."
    )
    bob = preamble + (
        "You are Bob. When a kind=task channel event arrives from Alice: (1) call task_accept with its task_id; "
        '(2) call delegate_task with destination "carol", parent_task_id set to that task_id, and input '
        '"Produce the result file for Alice\'s request."; (3) kind=task_update events for that subtask will '
        "arrive; ignore them until one has state succeeded. Its content is Carol's output and its meta.artifacts "
        "lists one file. (4) Call artifact_save with the subtask's task_id, that artifact's sha256, and path "
        f'"{ctx["saved"]}"; if it reports that the result has not been fetched yet, retry the same call. (5) Call task_complete on Alice\'s original task_id with status succeeded and output '
        '"BOB_FORWARDED: " followed by Carol\'s output verbatim. Then respond in your own terminal with exactly '
        "BOB_TASK_COMPLETED. Right now, respond with exactly BOB_STANDING_BY and wait for the event."
    )
    alice = preamble + (
        'You are Alice. Use list_destinations, then delegate_task to destination "bob" with input '
        '"Please get Carol\'s result file and report its result." The delegate_task result alone is not the '
        "result: kind=task_update events for that task will arrive; ignore them until one has state succeeded. "
        "Then respond in your own terminal with exactly two lines: first ALICE_RESULT_OBSERVED, then that "
        "event's content verbatim. Do not delegate anything else."
    )
    return alice, bob, carol


def live_flow(ctx, args, script, root):
    sessions = {}
    try:
        for name in ("alice", "bob", "carol"):
            sessions[name] = ClaudeSession(
                args.claude.resolve(), args.node.resolve(), script, ctx[name], ctx["secrets"][name],
                root / f"claude-{name}", allowed_tools=TOOLS,
            )
        for session in sessions.values():
            session.ready()
        pids = {name: s.process.pid for name, s in sessions.items()}
        print("Three interactive Claude sessions registered their Peerspan channels.", flush=True)
        alice, bob, carol = live_prompts(ctx)
        sessions["carol"].prompt(carol)
        sessions["bob"].prompt(bob)
        wait_for(lambda: sessions["carol"].assistant_said("CAROL_STANDING_BY"), 90)
        wait_for(lambda: sessions["bob"].assistant_said("BOB_STANDING_BY"), 90)
        print("Bob and Carol are standing by; prompting Alice.", flush=True)
        sessions["alice"].prompt(alice)
        wait_for(lambda: sessions["carol"].assistant_said("CAROL_TASK_COMPLETED"), FLOW_SECONDS)
        print("Carol's session reported completion.", flush=True)
        wait_for(lambda: sessions["bob"].assistant_said("BOB_TASK_COMPLETED"), FLOW_SECONDS)
        print("Bob's session reported completion.", flush=True)
        wait_for(lambda: sessions["alice"].assistant_said("ALICE_RESULT_OBSERVED"), FLOW_SECONDS)
        print("Alice's session reported the final result.", flush=True)
        assert {name: s.process.pid for name, s in sessions.items()} == pids
        observed = {"alice_final": assistant_text(sessions["alice"])}
        observed["tools"] = {
            name: {tool_name: s.tool_exchanges("mcp__peerspan__" + tool_name) for tool_name in TOOLS}
            for name, s in sessions.items()
        }
        observed["carol_transcript"] = transcript(sessions["carol"])
        observed["protocols"] = [
            re.search(r'"negotiatedProtocolVersion"\s*:\s*"([^"]+)"', s.debug().replace('\\"', '"')).group(1) for s in sessions.values()
        ]
        return observed
    except Exception:
        for name, s in sessions.items():
            print(f"{name} stage:", getattr(s, "startup_stage", None), flush=True)
            if s.process.poll() is None:
                print(f"{name} screen tail:", s.screen()[-1500:], flush=True)
            if s.debug_path.exists():
                print(name + " channel trace:", "\n".join(
                    line for line in s.debug_path.read_text().splitlines() if 'MCP server "peerspan"' in line
                )[-3000:], flush=True)
        raise
    finally:
        for s in sessions.values():
            s.close()


def received(host, sender, tid):
    rows = sql(host, "SELECT request, record FROM received_tasks WHERE sender=? AND task_id=?", (sender, tid))
    assert len(rows) == 1, rows
    return json.loads(rows[0][0]), json.loads(rows[0][1])


def artifact_digests(host, side, peer, tid, direction):
    return sorted(
        row[0] for row in sql(
            host, "SELECT sha256 FROM task_artifacts WHERE side=? AND peer=? AND task_id=? AND direction=?",
            (side, peer, tid, direction))
    )


def verify(ctx, observed, fixture):
    """Check the outcome from host state; returns the verified booleans."""
    alice, bob, carol = ctx["alice"], ctx["bob"], ctx["carol"]
    A, B, C = ctx["A"], ctx["B"], ctx["C"]
    agents = ctx["agents"]
    outbound_a = [entry["task"] for entry in alice.cli("task", "list")]
    outbound_b = [entry["task"] for entry in bob.cli("task", "list")]
    assert len(outbound_a) == 1 and len(outbound_b) == 1, (outbound_a, outbound_b)
    assert carol.cli("task", "list") == []
    t0, t1 = outbound_a[0], outbound_b[0]
    t0_id, t1_id = t0["request"]["task_id"], t1["request"]["task_id"]
    r = {}
    # Submitted by the adapter routes, not an owner CLI task command.
    r["parent_submitted_by_alice_route"] = (
        t0["route_id"] == ctx["routes"]["alice"]["id"]
        and t0["adapter_id"] == ctx["secrets"]["alice"]["adapter"]["id"]
        and t0["request"]["origin"]["agent_id"] == agents["alice"]["id"]
        and t0["request"]["origin"]["session_id"] == ctx["sessions"]["alice"]["id"]
    )
    r["subtask_submitted_by_bob_route_with_parent"] = (
        t1["route_id"] == ctx["routes"]["bob"]["id"]
        and t1["adapter_id"] == ctx["secrets"]["bob"]["adapter"]["id"]
        and t1["parent"] == {"sender_host_id": A, "task_id": t0_id}
        and t1["request"]["origin"]["agent_id"] == agents["bob"]["id"]
    )
    # Carol's received task carries a 2-link chain with Alice as originator.
    request, record = received(carol, B, t1_id)
    chain = request["delegation"]
    r["carol_received_two_link_chain_from_alice"] = (
        len(chain) == 2
        and [link["issuer_host_id"] for link in chain] == [A, B]
        and [link["audience_host_id"] for link in chain] == [B, C]
        and all(link["originator_agent_id"] == agents["alice"]["id"] for link in chain)
        and chain[0]["task_id"] == t0_id and chain[1]["task_id"] == t1_id
        and [link["depth"] for link in chain] == [1, 0]
        and chain[0] == t0["delegation"][0]
    )
    r["carol_task_authorized_by_originator_grant"] = request.get("grant_id") == ctx["grants"]["carol"]["id"]
    # All tasks succeeded at every side.
    states = {
        "alice_view_of_parent": alice.cli("task", "inspect", "--peer", B, t0_id)["status"]["state"],
        "bob_view_of_subtask": bob.cli("task", "inspect", "--peer", C, t1_id)["status"]["state"],
        "bob_received_parent": received(bob, A, t0_id)[1]["state"],
        "carol_received_subtask": record["state"],
    }
    r["all_tasks_succeeded"] = set(states.values()) == {"succeeded"}
    sub_events = bob.cli("task", "events", "--peer", C, t1_id)
    parent_events = alice.cli("task", "events", "--peer", B, t0_id)
    r["carol_progress_and_output_recorded"] = (
        [e["kind"] for e in sub_events][-3:] == ["accepted", "progress", "succeeded"]
        and sub_events[-1]["output"] == ctx["carol_output"]
    )
    r["bob_output_includes_carol_result"] = ctx["carol_output"] in (parent_events[-1]["output"] or "")
    # The artifact digest matches at Carol, Bob, and the saved file.
    digest = ctx["digest"]
    r["artifact_digest_matches_carol_bob_and_saved_file"] = (
        artifact_digests(carol, "received", B, t1_id, "result") == [digest]
        and artifact_digests(bob, "sent", C, t1_id, "result") == [digest]
        and [a["sha256"] for a in sub_events[-1]["artifacts"]] == [digest]
        and ctx["saved"].exists()
        and hashlib.sha256(ctx["saved"].read_bytes()).hexdigest() == digest
    )
    # The harness ran no owner task command while the agents worked, and both
    # submissions came from adapter routes rather than the local task API.
    r["no_owner_cli_task_command_in_flow"] = (
        not observed["owner_cli_during_flow"]
        and r["parent_submitted_by_alice_route"]
        and r["subtask_submitted_by_bob_route_with_parent"]
    )
    # Alice's session observed Carol's result through Bob's output.
    r["alice_observed_final_update_with_carol_result"] = ctx["carol_output"] in observed["alice_final"]
    if fixture:
        meta = observed["carol_task_meta"]
        r["carol_event_meta_originator_fields"] = (
            meta["originator_host_id"] == A and meta["originator_agent_id"] == agents["alice"]["id"]
            and meta["chain_hosts"] == [A, B] and meta["delegable"] is False
        )
    else:
        # The delivered channel event, as recorded in Carol's transcript.
        text = observed["carol_transcript"].replace('\\"', '"')

        def attribute(key, value):
            return re.search(re.escape(key) + r'\W{1,4}' + re.escape(value), text) is not None

        r["carol_event_meta_originator_fields"] = (
            attribute("originator_host_id", A)
            and attribute("originator_agent_id", agents["alice"]["id"])
            and attribute("delegable", "false")
        )
    failed = [key for key, value in r.items() if not value]
    assert not failed, (failed, states, chain, sub_events, parent_events)
    return r, {"parent": t0_id, "subtask": t1_id, "digest": digest}


def check(args):
    script = Path(__file__).resolve().parents[1] / "integrations/claude-channel/channel.mjs"
    binaries = {"G": args.go.resolve(), "R": args.rust.resolve()}
    mix = args.mix
    assert len(mix) == 3 and set(mix) <= set(binaries), mix
    with tempfile.TemporaryDirectory(prefix="peerspan-live-delegation-") as directory:
        root = Path(directory)
        ctx = None
        try:
            ctx = setup([binaries[c] for c in mix], args.coord.resolve(), root)
            print("Owner setup complete: network, agents, sessions, grants, routes.", flush=True)
            commands = []
            for host in ctx["hosts"]:
                host.cli = (lambda cli: lambda *a, **k: commands.append(a) or cli(*a, **k))(host.cli)
            if args.fixture:
                observed = fixture_flow(ctx, args.node.resolve(), script, root)
            else:
                observed = live_flow(ctx, args, script, root)
            observed["owner_cli_during_flow"] = [c for c in commands if c[:1] == ("task",)]
            verified, ids = verify(ctx, observed, args.fixture)
            print("Verified from host state:", json.dumps(verified, indent=2), flush=True)
            report = {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "mode": "fixture" if args.fixture else "live",
                "host_implementations": {
                    name: NAMES[c] for name, c in zip(("alice", "bob", "carol"), mix)
                },
                "chain": "alice → bob → carol (2 links, depth 1 then 0)",
            }
            if not args.fixture:
                report["claude_version"] = subprocess.check_output(
                    [str(args.claude.resolve()), "--version"], text=True).strip()
                report["mcp_protocols"] = observed["protocols"]
                calls = observed["tools"]
                report["model_observed"] = {
                    "alice_delegated_with_delegate_task": len(calls["alice"]["delegate_task"]) == 1,
                    "bob_accepted_and_forwarded_with_parent_task_id": len(calls["bob"]["task_accept"]) == 1
                    and [c["input"].get("parent_task_id") for c in calls["bob"]["delegate_task"]] == [ids["parent"]],
                    "carol_accepted_progressed_completed_with_artifact": len(calls["carol"]["task_accept"]) == 1
                    and len(calls["carol"]["task_progress"]) >= 1
                    and [c["input"].get("artifacts") for c in calls["carol"]["task_complete"]] == [[str(ctx["result"])]],
                    "bob_saved_artifact_with_artifact_save": [
                        c["input"].get("sha256") for c in calls["bob"]["artifact_save"]] == [ids["digest"]],
                    "alice_reported_final_result_in_terminal": verified["alice_observed_final_update_with_carol_result"],
                    "tool_calls": {
                        name: {t: len(v) for t, v in per.items() if v} for name, per in calls.items()
                    },
                }
                report["three_same_running_sessions"] = True
                report["builtin_tools_enabled"] = False
                report["permission_relay_enabled"] = False
            if not args.fixture:
                # Alice's terminal text is the model's report, not host state.
                verified.pop("alice_observed_final_update_with_carol_result")
            report["harness_verified"] = verified
            report["evidence"] = (
                "harness_verified comes from host databases, owner CLI records read after the flow, and the "
                "saved file; model_observed comes from each session's own transcript (its Peerspan tool calls "
                "and terminal text)." if not args.fixture else
                "harness_verified comes from host databases, owner CLI records read after the flow, the saved "
                "file, and the deterministic consumers' MCP events."
            )
            report["limitations"] = [
                "Three isolated hosts over loopback, not separate physical machines.",
                "Hosts joined with host-only invites, so no person is bound and originator_person_id is null; "
                "person-bound originators are covered by conformance/delegation.py.",
            ]
            if args.fixture:
                report["limitations"].append("Deterministic MCP consumers, no model: this checks the flow, not model use.")
            else:
                report["limitations"] += [
                    "Each session followed explicit step-by-step instructions naming the tools, destinations, and "
                    "paths; this shows the MCP surface is usable by the models, not that they plan delegation unaided.",
                    "Carol's event meta is checked in her session transcript as delivered channel attributes; "
                    "the model's reading of it is not separately tested.",
                ]
            return report
        finally:
            if ctx:
                for host in ctx["hosts"]:
                    host.stop()
                ctx["coord"].stop()
                ctx["coord"].logs.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ["go", "rust", "coord", "node", "output"]:
        p.add_argument("--" + flag, type=Path, required=True)
    p.add_argument("--claude", type=Path, help="Claude Code executable; required unless --fixture")
    p.add_argument("--mix", default="GRG", help="implementations of alice, bob, and carol, such as RGR")
    p.add_argument("--fixture", action="store_true",
                   help="drive the flow with deterministic MCP consumers instead of Claude sessions")
    args = p.parse_args()
    if not args.fixture and not args.claude:
        p.error("--claude is required unless --fixture")
    report = check(args)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print("Live delegation passed:" if not args.fixture else "Fixture delegation passed:", args.output, flush=True)


if __name__ == "__main__":
    main()
