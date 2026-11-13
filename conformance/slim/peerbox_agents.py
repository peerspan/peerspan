#!/usr/bin/env python3
"""Slim suite, peerbox_agents: agents using peerboxes through the adapter (peerbox Agents).

alice creates a coordinator-free network and bob joins as another person; alice's host serves runtime tasks through
conformance/slim/fake_runtime.py, as in the runtime suites, and a peerbox on a Git fixture repository. bob's agents
use it: `bert` and `cleo`, fixture adapters on bob's adapter socket, through `POST /adapter/v1/peerbox`, and `bea`,
the real MCP adapter (claude-channel, no model), through the peerbox MCP tools into a repository of its own with an
unrelated checked-out branch, local edits and a directory beside it. `ada`, an agent on alice's home host, shows that
no agent reviews or shares. The operations themselves are peerbox.py and peerbox_runs.py; the shared fixtures are
peerbox_common.py, peerbox_fixtures.py and runtime_common.py.

Not suite cases: `peerbox_list` following `next` (a page needs more than 65,536 bytes of entries, about 200 peerboxes
shared with bob, each a signed policy version: far over two minutes; peerbox.py pages the operation itself), and
routes set in session setup (the setup route shape for a route naming a host is not given by the contract).

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the task, runtime task and adapter
contracts it extends. No VM, no KVM, no model calls. Nothing in the Agents section is implemented yet: every case past
the fixtures, the network setup and the MCP session is a strict expected failure.
"""
import json
import os
import re
from datetime import datetime, timedelta

from harness import Adapter, Skip, Suite, check, rfc3339, wait_for
from runtime_common import (FINAL, Channel, adapter_upload, bind, enable_for_both, need, new_task_id, peer_events,
                            policy_version, result_of, setup_network, state)
from peerbox_fixtures import (agent_space, branch_commit, checkout_state, files_under, owner_repo, self_check,
                              suite_clone)
from peerbox_common import (BUNDLE_TYPE, bundle, check_record, commit_files, create, git, outcome, refs, rev, settle,
                            share, submit_op)

suite = Suite("peerbox_agents", __doc__)
bind(suite)
REASON = "peerbox agent tools not implemented (peerbox contract, Agents)"
TOOLS = {"peerbox_list", "peerbox_fetch", "peerbox_submit", "peerbox_status", "peerbox_withdraw", "peerbox_run"}


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)


def pbx():
    return need("pbx")[0]


def when(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# Routes (peerbox Agents, Routes; task contract Submitter; adapter outbound contract).

def add_route(adapter_id, name, action, *extra, expires="1h", ok=True, host=None):
    host = host or state["b"]
    result = host.cli("adapter", "route", "add", "--adapter", adapter_id, "--name", name, "--peer", state["a"].id,
                      "--action", action, "--expires-in", expires, *extra)
    if ok:
        check(result.ok, f"route {name} ({action}): exit {result.code} {result.stderr.strip()[-300:]}")
    return result


def route(adapter_id, name):
    listed = state["b"].ok("adapter", "route", "list", "--adapter", adapter_id)
    found = [r for r in listed or [] if r.get("name") == name]
    check(len(found) == 1, f"route {name} in `adapter route list`: {listed}")
    return found[0]


def remaining(adapter_id, name):
    status, rows = state["b"].api("GET", f"/v1/adapters/{adapter_id}/route-status")
    check(status == 200, f"route-status: {status} {rows}")
    for row in rows:
        named = row["route"].get("name") if isinstance(row["route"], dict) else row["route"]
        if named in (name, route(adapter_id, name).get("id")):
            return row["messages_remaining"]
    raise AssertionError(f"route {name} missing from route-status {rows}")


# The adapter API (peerbox Agents: POST /adapter/v1/peerbox).

def post(adapter, destination, op, task_id=None, bundle_sha=None):
    body = {"destination": destination, "task_id": task_id or new_task_id(), "peerbox": op}
    if bundle_sha:
        body["bundle"] = bundle_sha
    status, record = adapter.post("/adapter/v1/peerbox", body)
    return status, record, body["task_id"]


def post_ok(adapter, destination, op, **kw):
    status, record, task_id = post(adapter, destination, op, **kw)
    check(status in (200, 201) and isinstance(record, dict) and record["request"].get("executor") == "peerbox"
          and record["request"].get("peerbox") == op and record["request"]["task_id"] == task_id,
          f"POST /adapter/v1/peerbox {op.get('op')} through {destination}: {status} {record}")
    return task_id, record


def succeeded(task_id):
    kind, value, last = outcome(task_id)
    check(kind == "succeeded" and isinstance(value, (dict, list)), f"task {task_id}: {kind} {value}")
    return value, last


def refused_403(adapter, path, body):
    """A use the route does not allow: 403, and nothing persisted on either host."""
    status, answer = adapter.post(path, body)
    check(status == 403, f"{path} through {body.get('destination')}: {status} {answer}, want 403")
    status, _ = adapter.call("GET", f"/adapter/v1/delegations/{body['task_id']}")
    check(status == 404, f"a refused request was persisted: GET delegations {status}")
    return answer


def api_bundle(adapter, branch, files):
    """A commit on BRANCH from main in the suite's clone, bundled and uploaded by ADAPTER: (op fields, digest, tip)."""
    clone, main = need("clone", "main")
    git(clone, "fetch", "-q", state["repo"], "main")  # main as it is now
    tip = branch_commit(clone, branch, main, files)
    data = bundle(clone, suite.work / f"api-{branch}.bundle", tip, exclude=[main], ref=branch)
    entry = adapter_upload(adapter, data, name=f"{branch}.bundle", media_type=BUNDLE_TYPE)
    op = {"op": "submit", "peerbox_id": pbx(), "base": main, "branch": branch, "bundle": entry["sha256"]}
    return op, entry["sha256"], tip


def bob_tasks(op):
    """bob's outbound peerbox tasks with peerbox `op` OP, oldest first (task contract, task list)."""
    found, after = [], 0
    while True:
        status, page = state["b"].api("GET", f"/v1/tasks?after={after}")
        check(status == 200, f"task list: {status} {page}")
        if not page:
            return found
        found += [item["task"] for item in page if item["task"]["request"].get("executor") == "peerbox"
                  and (item["task"]["request"].get("peerbox") or {}).get("op") == op]
        after = page[-1]["sequence"]


# The MCP tools (peerbox Agents, MCP tools).

def tool(name, **arguments):
    """One MCP tools/call: (answer, its text decoded as JSON where it is JSON)."""
    answer = need("channel")[0].call("tools/call", {"name": name, "arguments": arguments}, seconds=120)
    content = answer.get("content") or []
    text = content[0].get("text", "") if content else ""
    try:
        return answer, json.loads(text)
    except ValueError:
        return answer, text


def tool_ok(name, **arguments):
    answer, value = tool(name, **arguments)
    check(not answer.get("isError") and isinstance(value, (dict, list))
          and not (isinstance(value, dict) and set(value) == {"error", "message"}), f"{name}: {str(value)[:400]}")
    return value


def tool_error(code, name, **arguments):
    _, value = tool(name, **arguments)
    check(isinstance(value, dict) and set(value) == {"error", "message"} and value["error"] == code
          and isinstance(value["message"], str), f"{name}: {str(value)[:300]}, want {{error: {code}, message}}")
    return value


def mcp():
    if "channel_skip" in state:
        raise Skip(state["channel_skip"])
    return need("channel", "space")


def untouched(before, sibling, extra_branches=()):
    """The agent's checkout as BEFORE (branches the suite added since aside) and the sibling directory as SIBLING."""
    space = state["space"]
    after = checkout_state(space["repo"])
    for name in extra_branches:
        after["branches"].pop(f"refs/heads/{name}", None)
    changed = sorted(k for k in before if before[k] != after[k])
    check(not changed, f"the adapter changed the agent's checkout: {changed}")
    check(files_under(space["sibling"]) == sibling, "the adapter wrote beside the repository")


@suite.case("fixtures", "peerbox_fixtures.py: every Git fixture of the peerbox suites, built host-free and checked")
def _():
    print(f"  fixtures built and checked in {self_check(suite.work / 'fixture-check'):.1f}s", flush=True)


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration; agents and adapter sessions; fixtures")
def _():
    setup_network()
    enable_for_both()
    a, b = state["a"], state["b"]
    owner = owner_repo(suite.work / "alice-repo")
    state.update(repo=owner["repo"], main=owner["main"])
    state["clone"] = suite_clone(owner["repo"], suite.work / "suite-clone")
    state["space"] = agent_space(suite.work / "agent-space")
    state["learners"] = [b]
    state["bert"], state["cleo"], state["ada"] = b.agent("bert"), b.agent("cleo"), a.agent("ada")
    add_route(state["bert"].adapter_id, "rt", "runtime.run")


@suite.case("mcp_session", "runtime_common.Channel: the claude-channel MCP adapter on a session of bob's agent bea")
def _():
    b = state["b"]
    status, agent = b.api("POST", "/v1/agents", {"name": "bea", "owner": "bob"})
    check(status in (200, 201), f"register bea: {status} {agent}")
    session = "session_" + os.urandom(16).hex()
    status, setup = b.api("POST", "/v1/adapters/setup", {
        "agent_id": agent["id"], "session_id": session, "integration": "claude-channel",
        "expires_at": rfc3339(b.now() + timedelta(hours=2))})
    check(status == 201, f"adapter setup for bea: {status} {setup}")
    state.update(bea_agent=agent["id"], bea_session=session, bea_adapter=setup["credential"]["adapter"]["id"])
    try:
        channel = Channel(b, setup, suite.work / "mcp-bea")
    except Skip as error:
        state["channel_skip"] = str(error)
        raise
    state["channel"] = channel
    bea = Adapter(b, agent, session, setup["credential"])  # the channel's own instance, for task_status reads
    bea.instance = channel.instance
    state["bea"] = bea


@case("peerbox_setup", "peerbox CLI and local API: create; share read, submit and run with bob", known=None)
def _():
    state["pbx"] = create(state["repo"], title="agents")
    share(pbx(), state["bob_principal"], actions=("read", "submit", "run"), hosts=[state["b"]])


@case("routes_each_action", "peerbox Agents, Routes: peerbox.read, peerbox.submit and peerbox.run routes name a "
                            "host, shown in route records and destinations; list, fetch, status, submit, withdraw "
                            "and run each through a route that allows it")
def _():
    a, bert, main = need("a", "bert", "main")
    need("pbx")
    bad = state["b"].cli("adapter", "route", "add", "--adapter", bert.adapter_id, "--name", "pb-agent", "--peer",
                         a.id, "--agent", state["ada"].id, "--action", "peerbox.read", "--expires-in", "1h")
    check(not bad.ok, "a peerbox route naming an agent was created")
    for name, action in (("pb-read", "peerbox.read"), ("pb-submit", "peerbox.submit"), ("pb-run", "peerbox.run")):
        add_route(bert.adapter_id, name, action)
        record = route(bert.adapter_id, name)
        check(record.get("action") == action, f"route record {name}: {record}")
        if "bea_adapter" in state:
            add_route(state["bea_adapter"], name, action)
    status, destinations = bert.call("GET", "/adapter/v1/destinations")
    shown = {d.get("name"): d.get("action") for d in destinations or []} if status == 200 else {}
    check(status == 200 and {k: shown.get(k) for k in ("pb-read", "pb-submit", "pb-run")}
          == {"pb-read": "peerbox.read", "pb-submit": "peerbox.submit", "pb-run": "peerbox.run"},
          f"destinations {status} {destinations}")
    for name in ("pb-read", "pb-submit", "pb-run"):
        listed, _ = succeeded(post_ok(bert, name, {"op": "list"})[0])
        check([p["peerbox_id"] for p in listed["peerboxes"]] == [pbx()], f"list through {name}: {listed}")
        succeeded(post_ok(bert, name, {"op": "status", "peerbox_id": pbx()})[0])
    fetched, last = succeeded(post_ok(bert, "pb-read", {"op": "fetch", "peerbox_id": pbx()})[0])
    check(fetched["head"] == main and [x["name"] for x in last.get("artifacts") or []] == ["peerbox.bundle"],
          f"fetch through pb-read: {fetched} {last.get('artifacts')}")
    op, digest, tip = api_bundle(bert, "api-one", {"api.txt": "1\n"})
    task_id, record = post_ok(bert, "pb-submit", op, bundle_sha=digest)
    check([x["sha256"] for x in record["request"].get("artifacts") or []] == [digest],
          f"the bundle is not the request's artifact: {record['request'].get('artifacts')}")
    contribution = check_record(succeeded(task_id)[0], pbx())
    check(contribution["head"] == tip and contribution["state"] == "pending"
          and contribution["contributor"]["agent_id"] == bert.id
          and contribution["contributor"]["session_id"] == bert.session_id, f"submit through pb-submit: {contribution}")
    state["api_one"] = contribution
    kind, _, last = outcome(post_ok(bert, "pb-run", {"op": "run", "peerbox_id": pbx(), "commit": main,
                                                     "run": {"argv": ["echo", "through a route"]}})[0])
    check(kind == "succeeded" and result_of(last)["exit_code"] == 0, f"run through pb-run: {kind} {last}")
    withdrawn = check_record(succeeded(post_ok(bert, "pb-submit", {"op": "withdraw", "peerbox_id": pbx(),
                                                                   "contribution_id": contribution[
                                                                       "contribution_id"]})[0])[0], pbx())
    check(withdrawn["state"] == "superseded", f"withdraw through pb-submit: {withdrawn}")
    state["routes"] = True


@case("routes_refuse_other_uses", "peerbox Agents, Routes: a peerbox.read route refused for submit and run (403); "
                                  "peerbox.submit for run, peerbox.run for submit and withdraw; peerbox routes for "
                                  "delegations and runs, and a runtime.run route for peerbox tasks; nothing persisted")
def _():
    bert, main = need("bert", "main")
    need("routes")
    op, digest, _ = api_bundle(bert, "refused", {"refused.txt": "r\n"})
    run = {"op": "run", "peerbox_id": pbx(), "commit": main, "run": {"argv": ["echo", "never"]}}
    withdraw = {"op": "withdraw", "peerbox_id": pbx(), "contribution_id": state["api_one"]["contribution_id"]}
    for destination, body in (("pb-read", dict(peerbox=op, bundle=digest)), ("pb-read", dict(peerbox=run)),
                              ("pb-submit", dict(peerbox=run)), ("pb-run", dict(peerbox=op, bundle=digest)),
                              ("pb-run", dict(peerbox=withdraw)), ("rt", dict(peerbox={"op": "list"}))):
        task_id = new_task_id()
        refused_403(bert, "/adapter/v1/peerbox", {"destination": destination, "task_id": task_id, **body})
        settle(0.5)
        check(peer_events(task_id)[0] == 404, f"alice's host received a refused {body['peerbox']['op']}")
    for destination in ("pb-read", "pb-submit", "pb-run"):
        refused_403(bert, "/adapter/v1/delegations", {"destination": destination, "task_id": new_task_id(),
                                                      "input": "not a peerbox task"})
        refused_403(bert, "/adapter/v1/runs", {"destination": destination, "task_id": new_task_id(),
                                               "run": {"argv": ["echo"]}})


@case("adapter_ownership_repeats_deadline", "peerbox Agents: POST /adapter/v1/peerbox ownership, repeats and the "
                                            "deadline follow POST /adapter/v1/delegations (task contract; adapter "
                                            "outbound, Scoped send); origin; bundle required for submit")
def _():
    a, b, bert, cleo = need("a", "b", "bert", "cleo")
    need("routes")
    add_route(bert.adapter_id, "pb-short", "peerbox.read", expires="20m")
    op = {"op": "status", "peerbox_id": pbx()}
    task_id, record = post_ok(bert, "pb-short", op)
    request = record["request"]
    check(request.get("origin") == {"agent_id": bert.id, "session_id": bert.session_id}
          and record.get("adapter_id") == bert.adapter_id and record.get("route_id")
          and record.get("peer_host_id") == a.id, f"origin and route of the local record: {record}")
    expiry = when(route(bert.adapter_id, "pb-short")["expires_at"])
    check(abs((when(request["deadline"]) - expiry).total_seconds()) <= 1,
          f"deadline {request['deadline']}, want the route's expiry {expiry} (sooner than 1 hour)")
    add_route(bert.adapter_id, "pb-long", "peerbox.read", expires="90m")
    later_id, later = post_ok(bert, "pb-long", op)
    check(abs((when(later["request"]["deadline"]) - b.now()).total_seconds() - 3600) <= 60,
          f"deadline {later['request']['deadline']} through a route expiring after 1 hour")
    status, again, _ = post(bert, "pb-short", op, task_id=task_id)
    check(status == 200 and again["request"] == request, f"an identical repeat: {status} {again}")
    status, again, _ = post(bert, "pb-short", {"op": "list"}, task_id=task_id)
    check(status == 409, f"the same task_id with another peerbox: {status} {again}")
    status, again, _ = post(bert, "pb-read", op, task_id=task_id)
    check(status == 409, f"the same task_id through another destination: {status} {again}")
    add_route(cleo.adapter_id, "pb-read", "peerbox.read")
    status, again, _ = post(cleo, "pb-read", op, task_id=task_id)
    check(400 <= status < 500, f"another adapter reusing bert's task_id: {status} {again}")
    check(cleo.call("GET", f"/adapter/v1/delegations/{task_id}")[0] == 404, "cleo reads bert's task")
    owned = submit_op({"op": "list"}, task_id=new_task_id())  # the owner's own peerbox task
    status, again, _ = post(bert, "pb-read", {"op": "list"}, task_id=owned)
    check(400 <= status < 500, f"an adapter adopting the owner's task: {status} {again}")
    check(bert.call("GET", f"/adapter/v1/delegations/{owned}")[0] == 404, "bert reads the owner's task")
    status, view = bert.call("GET", f"/adapter/v1/delegations/{task_id}")
    check(status == 200 and view["request"]["peerbox"] == op, f"task_status of a peerbox task: {status} {view}")
    sub, digest, _ = api_bundle(bert, "no-digest", {"n.txt": "n\n"})
    status, answer, _ = post(bert, "pb-submit", sub)
    check(status == 400, f"submit without `bundle`: {status} {answer}")
    succeeded(task_id)
    succeeded(later_id)


@case("route_budget", "peerbox Agents, Routes: max_messages counts each peerbox task, a refused one included, "
                      "repeats not (adapter outbound, Owner-defined destinations)")
def _():
    bert = need("bert")[0]
    need("routes")
    add_route(bert.adapter_id, "pb-budget", "peerbox.read", "--max-messages", "3")
    check(remaining(bert.adapter_id, "pb-budget") == 3, "a new route's budget")
    first, _ = post_ok(bert, "pb-budget", {"op": "list"})
    check(post(bert, "pb-budget", {"op": "list"}, task_id=first)[0] == 200
          and remaining(bert.adapter_id, "pb-budget") == 2, "one task, then its identical repeat")
    unknown, _ = post_ok(bert, "pb-budget", {"op": "fetch", "peerbox_id": "pbx_" + os.urandom(16).hex()})
    wait_for(lambda: (bert.call("GET", f"/adapter/v1/delegations/{unknown}")[1] or {}).get("submit_state")
             == "rejected", timeout=30, message="the unknown peerbox's 404 at the home host")
    check(remaining(bert.adapter_id, "pb-budget") == 1, "a task the home host refused is still counted")
    post_ok(bert, "pb-budget", {"op": "status", "peerbox_id": pbx()})
    check(remaining(bert.adapter_id, "pb-budget") == 0, "the budget after three peerbox tasks")
    status, answer, over = post(bert, "pb-budget", {"op": "list"})
    check(400 <= status < 500 and bert.call("GET", f"/adapter/v1/delegations/{over}")[0] == 404,
          f"a peerbox task over the budget: {status} {answer}")
    succeeded(first)


@case("mcp_peerbox_list", "peerbox Agents, MCP tools: the six tools; peerbox_list returns the merged peerboxes")
def _():
    channel, _ = mcp()
    need("routes")
    names = {t["name"] for t in channel.call("tools/list", {})["tools"]}
    check(TOOLS <= names, f"missing tools {sorted(TOOLS - names)}")
    value = tool_ok("peerbox_list", destination="pb-read")
    entries = value["peerboxes"] if isinstance(value, dict) else value  # the merged array, or {peerboxes}
    check(isinstance(entries, list) and len(entries) == 1 and set(entries[0]) == {"peerbox_id", "title", "branch",
                                                                                   "head", "actions"}
          and entries[0]["peerbox_id"] == pbx() and entries[0]["title"] == "agents"
          and entries[0]["branch"] == "main" and entries[0]["head"] == state["main"]
          and entries[0]["actions"] == ["peerbox.read", "peerbox.submit", "peerbox.run"], f"peerbox_list {value}")


@case("mcp_peerbox_fetch", "peerbox Agents, MCP tools: peerbox_fetch sets refs/peerbox/PEERBOX/main with `have` from "
                           "the repository; checked-out branch, index, worktree and the directory beside untouched; "
                           "a repeat with nothing new returns the same head; Fetch")
def _():
    _, space = mcp()
    a, main = need("a", "main")
    need("routes")
    repo, ref = space["repo"], f"refs/peerbox/{pbx()}/main"
    before, sibling, others = checkout_state(repo), files_under(space["sibling"]), refs(repo)
    value = tool_ok("peerbox_fetch", destination="pb-read", peerbox_id=pbx(), repository_path=str(repo))
    check(value == {"head": main, "ref": ref} and rev(repo, ref) == main, f"peerbox_fetch {value}, ref {rev(repo, ref)}")
    check(git(repo, "rev-list", "--count", ref) == "3", "the fetched history")
    untouched(before, sibling)
    check({k: v for k, v in refs(repo).items() if k != ref} == others, "peerbox_fetch changed another ref")
    first = bob_tasks("fetch")[-1]
    check(first["adapter_id"] == state["bea_adapter"] and not first["request"]["peerbox"].get("have"),
          f"the first fetch's request {first['request']['peerbox']}")
    value = tool_ok("peerbox_fetch", destination="pb-read", peerbox_id=pbx(), repository_path=str(repo))
    check(value == {"head": main, "ref": ref} and rev(repo, ref) == main, f"a repeat: {value}")
    repeat = bob_tasks("fetch")[-1]
    check(main in repeat["request"]["peerbox"].get("have", []), f"the repeat's have {repeat['request']['peerbox']}")
    kind, result, last = outcome(repeat["request"]["task_id"])
    check(kind == "succeeded" and result == {"head": main, "bundle_sha256": None, "size": 0}
          and not last.get("artifacts"), f"a repeat with nothing new: {kind} {result} {last.get('artifacts')}")
    newer = commit_files(state["repo"], {"lib.txt": "three\n"}, "fourth")  # the owner moves main on
    value = tool_ok("peerbox_fetch", destination="pb-read", peerbox_id=pbx(), repository_path=str(repo))
    check(value == {"head": newer, "ref": ref} and rev(repo, ref) == newer, f"after main moved: {value}")
    moved = bob_tasks("fetch")[-1]
    check(main in moved["request"]["peerbox"].get("have", []), f"have {moved['request']['peerbox']}")
    untouched(before, sibling)
    state["main"] = newer


@case("mcp_peerbox_submit_status", "peerbox Agents, MCP tools: peerbox_submit bundles a branch beside the checkout "
                                   "and returns the contribution record, or {error, message}; peerbox_status")
def _():
    _, space = mcp()
    a, b, main = need("a", "b", "main")
    need("routes")
    repo = space["repo"]
    tip = branch_commit(repo, "agent-work", main, {"agent.txt": "from the agent\n"})
    before, sibling = checkout_state(repo), files_under(space["sibling"])
    record = check_record(tool_ok("peerbox_submit", destination="pb-submit", peerbox_id=pbx(),
                                  repository_path=str(repo), branch="agent-work"), pbx())
    check(record["head"] == tip and record["base"] == main and record["branch"] == "agent-work"
          and record["state"] == "pending" and record["contributor"] == {
              "person_id": state["bob_pid"], "host_id": b.id, "agent_id": state["bea_agent"],
              "session_id": state["bea_session"]}, f"peerbox_submit {record}")
    check(rev(state["repo"], f"refs/peerbox/{pbx()}/members/{state['bob_pid']}/agent-work") == tip,
          "the member ref on the home host")
    untouched(before, sibling)
    state["agent_work"] = record
    orphan = branch_commit(repo, "orphan-base", None, {"o.txt": "o\n"})
    branch_commit(repo, "elsewhere", main, {"e.txt": "e\n"})
    tool_error("base_unknown", "peerbox_submit", destination="pb-submit", peerbox_id=pbx(),
               repository_path=str(repo), branch="elsewhere", base=orphan)
    untouched(before, sibling, extra_branches=("orphan-base", "elsewhere"))
    one = tool_ok("peerbox_status", destination="pb-read", peerbox_id=pbx(),
                  contribution_id=record["contribution_id"])
    check(set(one) == {"contributions", "next"} and len(one["contributions"]) == 1 and one["next"] is None
          and check_record(one["contributions"][0], pbx())["contribution_id"] == record["contribution_id"],
          f"peerbox_status of one: {one}")
    every = tool_ok("peerbox_status", destination="pb-run", peerbox_id=pbx())
    ids = [r["contribution_id"] for r in every["contributions"]]
    check(ids[0] == record["contribution_id"] and state["api_one"]["contribution_id"] in ids
          and every["next"] is None, f"peerbox_status, newest first: {ids}")
    older = tool_ok("peerbox_status", destination="pb-submit", peerbox_id=pbx(), before=ids[0])
    check([r["contribution_id"] for r in older["contributions"]] == ids[1:], f"before {ids[0]}: {older}")


@case("mcp_peerbox_withdraw", "peerbox Agents, MCP tools: peerbox_withdraw returns the record, superseded, the "
                              "member ref deleted and the contribution ref kept; a decided one {error: decided}")
def _():
    _, space = mcp()
    a, main, record = need("a", "main", "agent_work")
    repo, cid = space["repo"], record["contribution_id"]
    branch_commit(repo, "agent-two", main, {"two.txt": "2\n"})
    second = check_record(tool_ok("peerbox_submit", destination="pb-submit", peerbox_id=pbx(),
                                  repository_path=str(repo), branch="agent-two"), pbx())
    gone = check_record(tool_ok("peerbox_withdraw", destination="pb-submit", peerbox_id=pbx(),
                                contribution_id=second["contribution_id"]), pbx())
    check(gone["contribution_id"] == second["contribution_id"] and gone["state"] == "superseded",
          f"peerbox_withdraw {gone}")
    check(rev(state["repo"], f"refs/peerbox/{pbx()}/members/{state['bob_pid']}/agent-two") is None
          and rev(state["repo"], f"refs/peerbox/{pbx()}/contributions/{second['contribution_id']}") == second["head"],
          "after withdraw: the member ref deleted, the contribution ref kept")
    result = a.cli("--json", "peerbox", "review", cid, "--reject", "--reason", "not now", timeout=60)
    check(result.ok, f"alice rejects {cid}: exit {result.code} {result.stderr.strip()[-300:]}")
    tool_error("decided", "peerbox_withdraw", destination="pb-submit", peerbox_id=pbx(), contribution_id=cid)


@case("mcp_peerbox_run_notifications", "peerbox Agents, MCP tools: peerbox_run returns the task ID; output "
                                       "notifications with meta.output, the final run result; task_status (runtime "
                                       "Agents, Output notifications)")
def _():
    channel, _ = mcp()
    a, b, main = need("a", "b", "main")
    need("routes")
    argv = ["cat", "README"]
    for i in range(5):
        argv += [";", "sleep", "0.4", ";", "echo", f"tick{i}"]
    answer, value = tool("peerbox_run", destination="pb-run", peerbox_id=pbx(), commit=main, argv=argv,
                         results="output")
    text = json.dumps(value) if not isinstance(value, str) else value
    found = re.search(r"task_[0-9a-f]{32}", text)
    check(not answer.get("isError") and found, f"peerbox_run returned no task ID: {text[:300]}")
    task_id = found.group(0)
    updates, contents = channel.task_updates(task_id)
    outputs = [m for m in updates if m.get("state") == "running" and m.get("output")]
    got = "".join(m["output"] for m in outputs)
    want = "project\n" + "".join(f"tick{i}\n" for i in range(5))
    check(got == want, f"meta.output across {len(outputs)} output notifications: {got!r}, want {want!r}")
    events = b.api("GET", f"/v1/tasks/{a.id}/{task_id}/events")[1]
    stored = len([e for e in events if e["kind"] == "output"])
    check(stored < 3 or len(outputs) < stored, f"{len(outputs)} output notifications for {stored} output events")
    last, content = updates[-1], contents[-1]
    final_text = "".join(c.get("text", "") for c in content) if isinstance(content, list) else str(content or "")
    check(last.get("state") == "succeeded" and '"exit_code":0' in final_text.replace(" ", ""),
          f"final update {last}, content {final_text[:300]!r}: want the run result")
    status, view = state["bea"].call("GET", f"/adapter/v1/delegations/{task_id}")
    check(status == 200 and view["request"]["executor"] == "peerbox" and view["request"]["peerbox"]["op"] == "run"
          and view["request"]["peerbox"]["commit"] == main and (view.get("status") or {}).get("state") in FINAL,
          f"task_status of the run: {status} {view}")


@case("no_review_share_invite", "peerbox Agents: no agent tool accepts or rejects, shares or invites; review is the "
                                "owner's local API and CLI only (peerbox Review)")
def _():
    a, ada, bert = need("a", "ada", "bert")
    need("routes")
    pending = need("api_one")[0]
    branch_op, digest, _ = api_bundle(bert, "for-review", {"review.txt": "r\n"})
    target = check_record(succeeded(post_ok(bert, "pb-submit", branch_op, bundle_sha=digest)[0])[0], pbx())
    version = policy_version(a, state["alice_public"])
    rule = {"principals": [f"person:{state['bob_pid']}"], "actions": ["peerbox.read"]}
    for method, path, body in (
            ("POST", f"/v1/peerboxes/contributions/{target['contribution_id']}/decision",
             {"decision": "accepted", "reason": "by an agent"}),
            ("PUT", f"/v1/peerboxes/{pbx()}/rule", rule), ("DELETE", f"/v1/peerboxes/{pbx()}/rule", None),
            ("POST", "/v1/peerboxes", {"repository": str(state["repo"]), "branch": "main"}),
            ("POST", "/adapter/v1/peerbox/decision", {"contribution_id": target["contribution_id"]})):
        status, answer = ada.call(method, path, body)
        check(not 200 <= status < 300, f"{method} {path} on alice's adapter socket: {status} {answer}")
    for op in ({"op": "review", "peerbox_id": pbx(), "contribution_id": target["contribution_id"],
                "decision": "accepted"}, {"op": "share", "peerbox_id": pbx()}, {"op": "invite", "peerbox_id": pbx()}):
        status, answer, task_id = post(bert, "pb-submit", op)
        if 200 <= status < 300:  # submitted: the home host refuses the op (peerbox Requests, 400 invalid)
            wait_for(lambda: (bert.call("GET", f"/adapter/v1/delegations/{task_id}")[1] or {}).get("submit_state")
                     == "rejected", timeout=30, message=f"op {op['op']} refused")
        else:
            check(status == 400, f"op {op['op']} through the adapter: {status} {answer}")
    status, listed = a.api("GET", f"/v1/peerboxes/{pbx()}/contributions")
    states = {r["contribution_id"]: r["state"] for r in listed} if status == 200 else {}
    check(states.get(target["contribution_id"]) == "pending" and rev(state["repo"], "main") == state["main"]
          and policy_version(a, state["alice_public"]) == version and len(states) >= 2
          and pending["contribution_id"] in states, f"after the agents' attempts: {status} {states}")
    if "channel_skip" not in state and "channel" in state:
        tools = need("channel")[0].call("tools/list", {})["tools"]
        named = sorted(t["name"] for t in tools if "peerbox" in (t["name"] + t.get("description", "")).lower())
        check(set(named) == TOOLS and not [t["name"] for t in tools if re.search(
            r"review|invite|unshare|accept|reject|decision", t["name"]) and "peerbox" in t["name"]],
            f"the peerbox tools are {named}, want exactly {sorted(TOOLS)}")
        for name in ("peerbox_review", "peerbox_share", "peerbox_invite", "peerbox_accept"):
            event = need("channel")[0].call("tools/call", {"name": name, "arguments": {"destination": "pb-submit"}},
                                            whole=True)
            check("error" in event or event["result"].get("isError"), f"{name} answered {event}")


suite.finish()
