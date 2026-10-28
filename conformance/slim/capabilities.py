#!/usr/bin/env python3
"""Slim suite 8, capabilities: sources, create and share, calls from the CLI, per-call approval, sharing with
one agent, agent tools, bounds, a remote MCP server, and idle stop.

alice serves capabilities from her agent's fixture MCP server (conformance/fixtures/mcp/server.py) and from a
local fake remote MCP server (conformance/fixtures/remote/remote.py); bob calls them. Every host and CLI runs on
one shared debug test clock. Written from docs/capabilities-contract.md (slices 1 to 3) on a coordinator-free
network (docs/decentralized-spec.md).
"""
import json
import os
import sys
import time
from pathlib import Path

from harness import Suite, check, create_network, join_new_person, ssh_key, wait_for

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
sys.path.insert(0, str(FIXTURES / "remote"))
import remote  # noqa: E402  (the fake remote MCP server)

suite = Suite("capabilities", __doc__)
suite.use_clock()
a, b = suite.host("alice"), suite.host("bob")
log = suite.work / "fixture-mcp.log"
state = {}


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def fixture_log():
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


def call(host, address, operation, *args, wait="20s"):
    """`call ADDRESS OPERATION ...`; returns (exit code, local record)."""
    result = host.cli("call", address, operation, *args, "--wait", wait, timeout=90)
    return result.code, result.json, result


def stdio_server(name, *extra):
    return {"name": name, "transport": "stdio", "command": sys.executable,
            "args": ["-I", str(FIXTURES / "mcp" / "server.py"), "--log", str(log), *extra],
            "env": {}, "url": None, "source": "claude-code:project"}


@suite.case("setup_and_source_snapshot", "capabilities: Sources, Local commands, snapshots")
def _():
    net = create_network(a, "caps", "alice")
    state["net"] = net["id"]
    state["bob_key"] = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", state["bob_key"], net["id"])
    state["ada"], state["bert"] = a.agent("ada"), b.agent("bert", calls=True)
    state["site"] = remote.McpServer("mcp")
    remote_def = {"name": "far", "transport": "remote", "command": None, "args": [], "env": {},
                  "url": state["site"].url, "source": "claude-code:user"}
    status, body = a.api("PUT", f"/v1/agents/{state['ada'].id}/tool-servers",
                         {"workspace": str(a.root), "servers": [stdio_server("fixture"), remote_def], "values": {}},
                         timeout=90)
    check(status == 200, f"tool-servers: {status} {body}")
    sources = a.api("GET", "/v1/sources")[1]
    listed = {srv["name"]: srv for agent in sources["agents"] for srv in agent["servers"]}
    check("fixture" in listed and listed["fixture"]["shareable"], f"the stdio fixture source: {listed.get('fixture')}")
    tools = {t["name"]: t for t in listed["fixture"]["tools"]}
    check(tools["echo"]["read_only"] is True and tools["write_note"]["read_only"] is False,
          f"read_only from readOnlyHint: echo {tools['echo']['read_only']}, write_note {tools['write_note']['read_only']}")
    check("far" in listed and listed["far"]["shareable"], f"the remote source: {listed.get('far')}")


@suite.case("create_and_share", "capabilities: Capabilities, Claims, Sharing")
def _():
    need("ada")
    made = a.ok("capability", "create", "notes", "--from", "ada/fixture", "--operations", "echo,write_note")
    check(made["name"] == "notes" and made["operations"] == ["echo", "write_note"] and made["state"] == "available",
          f"capability record {made}")
    shared = a.ok("share", "notes", "--with", "bob", "--yes")
    check(shared["capability"]["name"] == "notes" if isinstance(shared["capability"], dict)
          else shared["capability"] == "notes", f"share output {shared}")
    check(shared["principal"].startswith("person:"), f"share principal {shared['principal']}")
    state["shared"] = True


@suite.case("call_from_cli", "capabilities: Discovery and calls from the CLI, Calls")
def _():
    need("shared")
    found = wait_for(lambda: [c for c in b.ok("discover", "--json")["capabilities"] if c["address"] == "alice/notes"]
                     or (b.api("POST", f"/v2/networks/{state['net']}/sync", {}) and None),
                     timeout=30, interval=1, message="bob's discover to list alice/notes")[0]
    check({o["name"] for o in found["operations"]} == {"echo", "write_note"}, f"operations {found['operations']}")
    before = len([e for e in fixture_log() if e.get("event") == "call"])
    code, record, raw = call(b, "alice/notes", "echo", "--text", "hello alice")
    check(code == 0 and record["status"]["state"] == "succeeded", f"call exit {code}: {raw.stderr.strip()[-200:]}")
    check("hello alice" in json.dumps(record["result"]), f"result {record['result']}")
    check(len([e for e in fixture_log() if e.get("event") == "call"]) == before + 1, "the server did not run it once")
    code, record, _ = call(b, "alice/nothing", "echo", "--text", "x")
    check(code != 0, "a call to a capability that does not exist succeeded")


@suite.case("approval_deny_and_approve", "capabilities: Per-call approval (slice 3)")
def _():
    need("shared")
    out = a.ok("capability", "approval", "notes", "changing")
    check(out["approval"] == {"operations": "changing", "agent_self": True}, f"approval {out.get('approval')}")
    # A read-only tool is not covered by "changing".
    code, _, raw = call(b, "alice/notes", "echo", "--text", "free")
    check(code == 0, f"read-only call under changing: exit {code} {raw.stderr.strip()[-200:]}")
    code, record, _ = call(b, "alice/notes", "write_note", "--text", "deny me", wait="2s")
    check(code == 3, f"a call needing approval returned exit {code}, want 3 (still pending)")
    pending = a.ok("approvals", "--json")["approvals"]
    check(len(pending) == 1 and pending[0]["operation"] == "write_note" and pending[0]["changes_things"] is True,
          f"pending approvals {pending}")
    item = pending[0]
    denied = a.ok("deny", f"{item['sender_host_id']}/{item['call_id']}", "--reason", "not now")
    check(denied["state"] == "denied" and denied["reason"] == "not now", f"deny {denied}")
    wait_for(lambda: b.ok("calls", "inspect", "--peer", a.id, item["call_id"])["status"]["state"] == "rejected",
             timeout=30, interval=1, message="bob's record of the denied call")
    check(not any("deny me" in json.dumps(e) for e in fixture_log()), "a denied call ran on the server")
    # approve needs a terminal, and then runs the call once.
    code, record, _ = call(b, "alice/notes", "write_note", "--text", "approve me", wait="2s")
    call_id = record["request"]["call_id"]
    refused = a.cli("approve", call_id)
    check(not refused.ok and "needs a terminal" in refused.stderr, "approve without a terminal was not refused")
    approved = a.cli("approve", call_id, tty=True, input="yes\n")
    check(approved.ok, f"approve at a terminal: exit {approved.code} {approved.stderr.strip()[-200:]}")
    wait_for(lambda: b.ok("calls", "inspect", "--peer", a.id, call_id)["status"]["state"] == "succeeded",
             timeout=30, interval=1, message="the approved call to succeed")
    a.ok("capability", "approval", "notes", "none")


@suite.case("share_with_one_agent", "capabilities: Sharing with one agent (slice 3), Agent tools (slice 2)")
def _():
    (bert,) = need("bert")
    a.ok("capability", "create", "solo", "--from", "ada/fixture", "--operations", "echo")
    out = a.ok("share", "solo", "--with", "bob/bert", "--yes")
    check(out["principal"] == f"agent:{b.id}/{bert.id}", f"agent principal {out['principal']}")

    def listed():
        b.api("POST", f"/v2/networks/{state['net']}/sync", {})
        status, body = bert.call("GET", "/adapter/v1/capabilities")
        check(status == 200, f"adapter capabilities: {status} {body}")
        return [c for c in body["capabilities"] if c["address"] == "alice/solo"]
    wait_for(listed, timeout=30, interval=1, message="bob's agent to see alice/solo")
    call_id = "call_" + os.urandom(16).hex()
    status, view = bert.post("/adapter/v1/calls", {"call_id": call_id, "address": "alice/solo", "operation": "echo",
                                                    "input": {"text": "from bert"}, "wait": 15})
    check(status == 200 and view["state"] == "succeeded", f"agent call: {status} {view}")
    check("from bert" in json.dumps(view["result"]), f"agent call result {view['result']}")
    code, _, raw = call(b, "alice/solo", "echo", "--text", "owner")
    check(code != 0, "bob's owner CLI called a capability shared only with his agent")


@suite.case("bounds_and_unshare", "capabilities: Resource bounds (slice 3), Sharing (unshare)")
def _():
    need("shared")
    made = a.ok("capability", "create", "bounded", "--from", "ada/fixture", "--operations", "echo",
                "--bound", "text=ok")
    check(made["bounds"] == {"arguments": [{"text": "ok"}]}, f"bounds {made['bounds']}")
    a.ok("share", "bounded", "--with", "bob", "--yes")
    b.api("POST", f"/v2/networks/{state['net']}/sync", {})
    code, _, raw = call(b, "alice/bounded", "echo", "--text", "ok")
    check(code == 0, f"a call inside the bound: exit {code} {raw.stderr.strip()[-200:]}")
    code, record, raw = call(b, "alice/bounded", "echo", "--text", "no")
    text = json.dumps(record) + raw.stderr
    check(code != 0 and ("out_of_bounds" in text or "limited to calls where text is ok" in text),
          f"a call outside the bound: exit {code} {text[-300:]}")
    check(not any(e.get("event") == "call" and (e.get("arguments") or {}).get("text") == "no" for e in fixture_log()),
          "the out-of-bounds call ran")
    out = a.ok("unshare", "bounded", "--with", "bob")
    check(out["removed"] == 1, f"unshare {out}")

    def refused_after_unshare():
        b.api("POST", f"/v2/networks/{state['net']}/sync", {})
        code, record, _ = call(b, f"{a.id}/bounded", "echo", "--text", "ok", wait="5s")
        return code != 0
    wait_for(refused_after_unshare, timeout=30, interval=1, message="a call after unshare to be refused")
    refused = a.cli("capability", "create", "bad", "--from", "ada/fixture", "--operations", "info", "--bound", "x=y")
    check(not refused.ok and ("bound_unenforceable" in refused.stderr + refused.stdout
                              or "no string argument" in refused.stderr), f"an unenforceable bound: {refused}")


@suite.case("remote_mcp_server", "capabilities: Remote MCP servers (slice 3), Running remote servers")
def _():
    (site,) = need("site")
    a.ok("capability", "create", "far", "--from", "ada/far", "--operations", "echo")
    a.ok("share", "far", "--with", "bob", "--yes")
    b.api("POST", f"/v2/networks/{state['net']}/sync", {})
    code, record, raw = call(b, "alice/far", "echo", "--text", "over http")
    check(code == 0 and "over http" in json.dumps(record["result"]), f"remote call: exit {code} "
          f"{raw.stderr.strip()[-200:]}")
    check(any(e.get("name") == "echo" or "over http" in json.dumps(e) for e in site.executions),
          f"the fake remote server saw no execution: {site.executions[-2:]}")


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@suite.case("idle_instance_stops_after_10_minutes", "capabilities: Running servers (idle stop); test clock")
def _():
    need("shared")
    code, _, _ = call(b, "alice/notes", "echo", "--text", "wake")
    check(code == 0, "warm-up call failed")
    pid = [e for e in fixture_log() if e.get("event") == "call"][-1]["pid"]
    check(alive(pid), "the instance is not running after a call")
    suite.set_offset(suite.offset + 9 * 60)
    time.sleep(2)
    check(alive(pid), "the instance stopped before 10 idle minutes")
    suite.set_offset(suite.offset + 2 * 60)
    wait_for(lambda: not alive(pid), timeout=15, interval=0.5, message="the idle instance to stop")


suite.finish()
