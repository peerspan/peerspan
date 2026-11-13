#!/usr/bin/env python3
"""Slim suite, runtime_peerfs: runtime tasks on peerfs workspaces, and their snapshots (RUN-6, RUN-7).

alice creates a coordinator-free network and bob joins as another person. alice's host serves runtime tasks through
conformance/slim/fake_runtime.py (RUN-4) started with the peerfs workspaces `agent` and `other` and two run slots,
and her runtime rule names `agent`, `ghost` (which the runtime does not have) and `other`. bob submits through the
peer probe, the owner API, the CLI, the adapter socket and the MCP adapter. The rest of the runtime contract is
runtime.py and runtime_runs.py; the shared fixtures are runtime_common.py. `peerfs_workspaces` kept across an
automatic renewal is runtime.py's renewal case, whose rule names a peerfs workspace.

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task, artifact and
coordinator-free contracts it builds on. No VM, no KVM, no peerfs, no model calls.
"""
import hashlib
import os
import re
import time

from harness import Suite, check, wait_for
from runtime_common import (RULE_KEYS, adapter_upload, bind, enable, final, has_kind, learn, make_tar, mcp_channel,
                            need, peer_submit, policy_statement, policy_version, raw_task, receiver_events, result_of,
                            run_id, setup_network, show, sign_policy, state, stream, submit, with_runtime_rules)

suite = Suite("runtime_peerfs", __doc__)
bind(suite)
WORKSPACES = ["agent", "other"]  # the fake runtime's peerfs workspaces
NAMED = ["agent", "ghost", "other"]  # the rule's peerfs_workspaces, in ascending byte order
SNAPSHOT = re.compile(r"^[0-9a-f]{66}$")  # a peerfs object ID (runtime, The run result)


def exited(task_id):
    """The fake runtime's `exited` log entry for TASK_ID: the result it reported to the daemon."""
    rt, b = state["rt"], state["b"]
    found = wait_for(lambda: rt.entries("exited", run_id(b, task_id)), timeout=10, message="the runtime's exit")
    return found[-1]["result"]


def first(rt, event, rid):
    found = rt.entries(event, rid)
    return found[0]["at"] if found else None


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (runtime enable --peerfs-workspace)")
def _():
    setup_network(peerfs_workspace=WORKSPACES, max_concurrent_runs=2)
    rule = ["--for", state["alice_principal"], "--for", state["bob_principal"]]
    for name in NAMED:
        rule += ["--peerfs-workspace", name]
    state["rule_flags"] = rule
    _, state["version_rule"] = enable(*rule)
    state["ready"] = True


@suite.case("peerfs_rule_and_report", "runtime Runtime rules (peerfs_workspaces), Policy body; Runtime administration "
                                      "(runtime show); The runtime's local API (GET /v1/runtime peerfs)")
def _():
    a, b = need("a", "b")
    need("ready")
    shown = show(a)
    check(isinstance(shown["runtime"], dict) and shown["runtime"].get("peerfs") is True,
          f"the runtime's report with peerfs workspaces: {shown['runtime']}")
    check(shown["rule"] and shown["rule"]["peerfs_workspaces"] == NAMED, f"runtime show rule {shown['rule']}")
    rules = policy_statement(a, state["alice_public"])[3]["runtime_rules"]
    check(len(rules) == 1 and list(rules[0]) == RULE_KEYS and rules[0]["peerfs_workspaces"] == NAMED,
          f"the signed rule {rules}")
    # Admitted by a host of another person.
    learn(b, state["alice_public"], state["version_rule"])
    seen = policy_statement(b, state["alice_public"])[3].get("runtime_rules")
    check(seen == rules, f"bob's host holds {seen}, want {rules}")


@suite.case("peerfs_policy_refusals", "runtime Runtime rules: peerfs_workspaces 0 to 64 distinct names in ascending "
                                      "byte order; Policy body (Reading): out of range refused")
def _():
    a, b = need("a", "b")
    need("ready")
    good = policy_statement(a, state["alice_public"])[3]["runtime_rules"][0]
    before = policy_version(a, state["alice_public"])

    def names(value):
        return lambda body: with_runtime_rules(body, [{**good, "peerfs_workspaces": value}])
    cases = {
        "unsorted": names(["other", "agent"]),
        "duplicated": names(["agent", "agent"]),
        "an empty name": names(["", "agent"]),
        "the name .": names([".", "agent"]),
        "the name ..": names(["..", "agent"]),
        "a name with /": names(["a/b", "agent"]),
        "a name with NUL": names(["a\u0000b", "agent"]),
        "a 256-byte name": names(["agent", "x" * 256]),
        "65 names": names(sorted(f"w{i:02d}" for i in range(65))),
        "not a list": names("agent"),
    }
    accepted = []
    for label, mutate in cases.items():
        status, response = sign_policy(mutate)
        if status == 200 and response.get("committed"):
            accepted.append(f"{label} ({status})")
    check(not accepted, f"policies admitted: {accepted}")
    check(policy_version(a, state["alice_public"]) == before, "a refused policy changed the current version")
    # Control: 64 names, one of 255 bytes, sorted, is admitted.
    valid = sorted(NAMED + [f"w{i:02d}" for i in range(60)] + ["x" * 255])
    check(len(valid) == 64, "fixture: 64 names")
    status, response = sign_policy(names(valid))
    check(status == 200 and response.get("committed"), f"a valid rule with 64 workspace names: {status} {response}")
    learn(b, state["alice_public"], before + 1)
    # Back to the suite's rule.
    _, state["version_rule"] = enable(*state["rule_flags"])


@suite.case("peerfs_run_and_snapshot", "runtime Requests (peerfs workspace); The run result (snapshot); Snapshots; "
                                       "The runtime's local API (POST /v1/runs peerfs_workspace)")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    task_id = submit(["write", "notes.txt", "first", "words", ";", "echo", "wrote"], workspace={"peerfs": "agent"})
    events = final(task_id)
    check(events[-1]["kind"] == "succeeded" and stream(events, "stdout") == b"wrote\n",
          f"a run on a peerfs workspace: {[e['kind'] for e in events]} {stream(events, 'stdout')!r}")
    result = result_of(events[-1], peerfs=True)
    check(isinstance(result["snapshot"], str) and SNAPSHOT.match(result["snapshot"]),
          f"snapshot {result['snapshot']!r}, want 66 lowercase hex digits")
    check(result["snapshot"] == exited(task_id)["snapshot"], "the run result's snapshot is not the runtime's")
    check(result["exit_code"] == 0 and result["error"] is None, f"run result {result}")
    post = rt.entries("post", run_id(b, task_id))[0]
    check(post["status"] == 201 and post["request"]["peerfs_workspace"] == "agent"
          and post["request"]["workspace_archive"] is None and post["request"]["results"] == "output",
          f"the start request {post['request']}")
    record = b.api("GET", f"/v1/tasks/{a.id}/{task_id}")[1]
    check(record["request"]["run"].get("workspace") == {"peerfs": "agent"} and not record["request"].get("artifacts"),
          f"bob's record {record['request']}")
    state["first_snapshot"] = result["snapshot"]
    # A later run sees the earlier run's write; one that changes nothing has snapshot null; results none is allowed.
    task_id = submit(["cat", "notes.txt"], workspace={"peerfs": "agent"})
    events = final(task_id)
    result = result_of(events[-1], peerfs=True)
    check(events[-1]["kind"] == "succeeded" and stream(events, "stdout") == b"first words",
          f"a later run: {[e['kind'] for e in events]} {stream(events, 'stdout')!r}")
    check(result["snapshot"] is None, f"snapshot {result['snapshot']!r} after a run that changed nothing")
    task_id = submit(["write", "notes.txt", "second"], workspace={"peerfs": "agent"}, results="none")
    events = final(task_id)
    result = result_of(events[-1], peerfs=True)
    check(events[-1]["kind"] == "succeeded" and not events[-1].get("artifacts"), f"results none: {events[-1]}")
    check(SNAPSHOT.match(result["snapshot"] or "") and result["snapshot"] != state["first_snapshot"],
          f"a second change's snapshot {result['snapshot']!r}")


def refused_naming(cases):
    """The CASES [(label, body)] not refused as 400 invalid naming the field (runtime Requests)."""
    failures = []
    for label, body in cases:
        status, answer = peer_submit(body)
        if not (status == 400 and isinstance(answer, dict) and answer.get("code") == "invalid"
                and any(f in (answer.get("error") or "") for f in ("workspace", "peerfs", "results"))):
            failures.append(f"{label}: {status} {answer}")
    return failures


@suite.case("peerfs_request_validation", "runtime Requests: {\"peerfs\": NAME} name rules; results changes refused "
                                         "(400 invalid, field named)")
def _():
    need("ready")
    failures = refused_naming([
        ("results changes", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "agent"}, "results": "changes"})),
        ("empty name", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": ""}})),
        (".", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "."}})),
        ("..", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": ".."}})),
        ("a/b", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "agent/x"}})),
        ("NUL", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "ag\u0000ent"}})),
        ("256 bytes", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "x" * 256}})),
    ])
    check(not failures, "requests not refused as 400 invalid naming the field: " + "; ".join(failures))


@suite.case("peerfs_workspace_shape_named", "runtime Requests: workspace is {archive}, {peerfs} or null; failures are "
                                            "400 invalid with the field named")
def _():
    need("ready")
    sha = hashlib.sha256(b"x").hexdigest()
    manifest = [{"name": "ws.tar", "size": 1, "sha256": sha, "media_type": "application/x-tar"}]
    failures = refused_naming([
        ("a name that is not a string", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": 7}})),
        ("peerfs and archive", raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "agent", "archive": sha}},
                                        artifacts=manifest)),
    ])
    check(not failures, "requests not refused as 400 invalid naming the field: " + "; ".join(failures))


@suite.case("peerfs_workspace_not_in_rule", "runtime Checks step 3: a peerfs workspace not in peerfs_workspaces (403)")
def _():
    need("ready")
    status, body = peer_submit(raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "unnamed"}}))
    check(status == 403, f"a workspace the rule does not name: {status} {body}")
    status, body = peer_submit(raw_task(run={"argv": ["echo"], "workspace": {"peerfs": "other"}}))
    check(status == 200 and body["state"] == "queued", f"control, a named workspace: {status} {body}")
    final(body["task_id"])


@suite.case("peerfs_missing_workspace", "runtime Running: queued to failed for a peerfs workspace that does not exist")
def _():
    b, rt = need("b", "rt")
    need("ready")
    task_id = submit(["write", "x.txt", "x"], workspace={"peerfs": "ghost"})
    events = final(task_id)
    check([e["kind"] for e in events] == ["queued", "failed"], f"events {[e['kind'] for e in events]}")
    result = result_of(events[-1], peerfs=True)
    check(result["exit_code"] is None and result["duration_ms"] == 0 and result["error"]
          and result["snapshot"] is None, f"run result {result}")
    check(not rt.entries("started", run_id(b, task_id)), "the command started")


@suite.case("peerfs_runs_take_turns", "runtime Running: runs on one workspace take turns; another workspace starts "
                                      "beside (two slots)")
def _():
    b, rt = need("b", "rt")
    need("ready")
    holder = submit(["sleep", "2", ";", "write", "turns.txt", "one"], workspace={"peerfs": "agent"})
    receiver_events(holder, until=has_kind("accepted"))
    second = submit(["cat", "turns.txt"], workspace={"peerfs": "agent"})
    receiver_events(second, until=lambda evs: bool(evs))
    beside = submit(["echo", "beside"], workspace={"peerfs": "other"})
    events = {t: final(t, timeout=30) for t in (holder, second, beside)}
    for task_id, evs in events.items():
        check(evs[-1]["kind"] == "succeeded", f"{task_id}: {[e['kind'] for e in evs]}")
    check(stream(events[second], "stdout") == b"one", f"the second run read {stream(events[second], 'stdout')!r}")
    h, s, o = run_id(b, holder), run_id(b, second), run_id(b, beside)
    check(first(rt, "started", o) < first(rt, "exited", h),
          "the run on another workspace did not start beside the first")
    check(first(rt, "post", s) > first(rt, "exited", h),
          f"the second run on one workspace was dispatched while the first held it: "
          f"{[p['status'] for p in rt.entries('post', s)]}")


@suite.case("peerfs_held_by_runtime", "runtime Running: a 429 for a held peerfs workspace leaves the task queued; "
                                      "it starts later")
def _():
    b, rt = need("b", "rt")
    need("ready")
    # A run the daemon did not start holds `other` on the runtime (runtime local API, POST /v1/runs).
    outside = "run_" + os.urandom(32).hex()
    status, record = rt.api("POST", "/v1/runs", {
        "run_id": outside, "argv": ["sleep", "3"], "cwd": "/workspace", "env": {},
        "resources": {"cpus": 1, "memory_mib": 128, "timeout_seconds": 60}, "workspace_archive": None,
        "peerfs_workspace": "other", "results": "none"})
    check(status == 201, f"fixture: a run held outside the daemon: {status} {record}")
    try:
        task_id = submit(["echo", "after"], workspace={"peerfs": "other"})
        rid = run_id(b, task_id)
        wait_for(lambda: any(p["status"] == 429 for p in rt.entries("post", rid)), timeout=15, interval=0.2,
                 message="a dispatch answered 429")
        events = final(task_id, timeout=40)
        check(events[-1]["kind"] == "succeeded" and stream(events, "stdout") == b"after\n",
              f"events {[e['kind'] for e in events]}")
        statuses = [p["status"] for p in rt.entries("post", rid)]
        check(statuses[0] == 429 and statuses[-1] == 201, f"start answers {statuses}")
        check(first(rt, "started", rid) > first(rt, "exited", outside), "the task started while the workspace was held")
    finally:
        rt.api("DELETE", f"/v1/runs/{outside}")


@suite.case("peerfs_runtime_without_peerfs", "runtime Running: 422 unavailable ends rejected; Runtime administration: "
                                             "--peerfs-workspace refused when the runtime reports peerfs false")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    rt.restart(max_concurrent_runs=2)  # no peerfs workspaces: peerfs false
    try:
        check(show(a)["runtime"].get("peerfs") is False, f"the runtime's report: {show(a)['runtime']}")
        task_id = submit(["echo", "never"], workspace={"peerfs": "agent"})
        events = final(task_id, timeout=20)
        check([e["kind"] for e in events] == ["queued", "rejected"] and events[-1]["message"],
              f"events {[(e['kind'], e.get('message')) for e in events]}")
        posts = rt.entries("post", run_id(b, task_id))
        check(all(p["status"] == 422 for p in posts) and not rt.entries("started", run_id(b, task_id)),
              f"runtime answers {[p['status'] for p in posts]}")
        before = policy_version(a, state["alice_public"])
        out = a.cli("runtime", "enable", "--socket", str(rt.socket), "--person-key", state["alice_key"],
                    *state["rule_flags"], timeout=60)
        check(not out.ok, "runtime enable --peerfs-workspace accepted a runtime that reports peerfs false")
        check(policy_version(a, state["alice_public"]) == before, "the refused enable signed a policy")
    finally:
        rt.restart(peerfs_workspace=WORKSPACES, max_concurrent_runs=2)
        a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})


@suite.case("peerfs_lost_run", "runtime The runtime's local API (A lost run): the runtime restarted; the workspace "
                               "keeps what the command wrote, without a snapshot after it")
def _():
    rt, = need("rt")
    need("ready")
    task_id = submit(["write", "lost.txt", "kept", ";", "sleep", "30"], workspace={"peerfs": "agent"})
    receiver_events(task_id, until=has_kind("accepted"))
    wait_for(lambda: any(e["step"][0] == "sleep" for e in rt.entries("step", run_id(state["b"], task_id))),
             timeout=10, interval=0.1, message="the run to reach its sleep")
    rt.restart(peerfs_workspace=WORKSPACES, max_concurrent_runs=2)
    events = final(task_id, timeout=40)
    result = result_of(events[-1], peerfs=True)
    check(events[-1]["kind"] == "failed" and result["error"] == "the runtime restarted" and result["snapshot"] is None,
          f"a lost run: {[e['kind'] for e in events]} {result}")
    events = final(submit(["cat", "lost.txt"], workspace={"peerfs": "agent"}))
    check(stream(events, "stdout") == b"kept", f"the next run read {stream(events, 'stdout')!r}")


@suite.case("task_run_peerfs_workspace", "runtime CLI: task run --peerfs-workspace sends {\"peerfs\": NAME}, uploads "
                                         "nothing; --results changes refused")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    work = b.root / "cli-ws"
    work.mkdir(exist_ok=True)
    result = b.cli("task", "run", "--peer", a.id, "--peerfs-workspace", "agent", "--", "write", "cli.txt", "from",
                   "cli", ";", "cat", "cli.txt", timeout=90)
    check(result.code == 0 and result.stdout == "from cli",
          f"task run --peerfs-workspace: exit {result.code} {result.stdout!r} {result.stderr.strip()[-300:]}")
    post = rt.entries("post")[-1]["request"]
    check(post["peerfs_workspace"] == "agent" and post["workspace_archive"] is None, f"the start request {post}")
    result = b.cli("--json", "task", "run", "--peer", a.id, "--detach", "--peerfs-workspace", "agent", "--", "cat", "cli.txt",
                   timeout=30)
    check(result.ok and isinstance(result.json, dict), f"--detach: exit {result.code} {result.stderr.strip()[-300:]}")
    request = result.json["request"]
    check(request["run"].get("workspace") == {"peerfs": "agent"} and not request.get("artifacts"),
          f"the local record {request}")
    final(request["task_id"])
    posts = len(rt.entries("post"))
    for extra in (["--results", "changes"], ["--workspace", str(work)]):
        refused = b.cli("task", "run", "--peer", a.id, "--peerfs-workspace", "agent", *extra, "--", "echo", "x",
                        timeout=30)
        check(refused.code != 0, f"task run --peerfs-workspace {' '.join(extra)}: exit {refused.code}")
    time.sleep(0.5)
    check(len(rt.entries("post")) == posts, "a refused task run reached the runtime")


@suite.case("adapter_runs_peerfs", "runtime Agents: POST /adapter/v1/runs takes {\"peerfs\": NAME} in run.workspace")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    bert = b.agent("bert")
    route = b.cli("adapter", "route", "add", "--adapter", bert.adapter_id, "--name", "rt", "--peer", a.id,
                  "--action", "runtime.run", "--expires-in", "1h")
    check(route.ok, f"a runtime.run route: exit {route.code} {route.stderr.strip()[-300:]}")
    task_id = "task_" + os.urandom(16).hex()
    status, record = bert.post("/adapter/v1/runs", {"destination": "rt", "task_id": task_id, "run": {
        "argv": ["write", "agent.txt", "by", "bert", ";", "cat", "agent.txt"], "workspace": {"peerfs": "agent"}}})
    check(status == 200 and record["request"]["run"].get("workspace") == {"peerfs": "agent"}
          and not record["request"].get("artifacts"), f"POST /adapter/v1/runs: {status} {record}")
    events = final(task_id)
    check(events[-1]["kind"] == "succeeded" and stream(events, "stdout") == b"by bert",
          f"events {[e['kind'] for e in events]} {stream(events, 'stdout')!r}")
    check(SNAPSHOT.match(result_of(events[-1], peerfs=True)["snapshot"] or ""), "no snapshot for the agent's run")
    # Control: an archive workspace through the same route still works with a workspace_archive digest.
    entry = adapter_upload(bert, make_tar({"in.txt": b"archive"}))
    task_id = "task_" + os.urandom(16).hex()
    status, record = bert.post("/adapter/v1/runs", {"destination": "rt", "task_id": task_id,
                                                    "run": {"argv": ["cat", "in.txt"]},
                                                    "workspace_archive": entry["sha256"]})
    check(status == 200, f"POST /adapter/v1/runs with an archive: {status} {record}")
    check(stream(final(task_id), "stdout") == b"archive", "the archive run")


@suite.case("mcp_run_task_peerfs", "runtime Agents: MCP run_task with peerfs_workspace; at most one of workspace_path "
                                   "and peerfs_workspace")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    work = b.root / "mcp-ws"
    work.mkdir(exist_ok=True)
    channel = mcp_channel("bea", "rt-mcp")
    try:
        task_id = channel.run_task({"destination": "rt-mcp", "argv": ["cat", "notes.txt"],
                                    "peerfs_workspace": "agent"})
        updates, _ = channel.task_updates(task_id)
        check(updates[-1].get("state") == "succeeded", f"final update {updates[-1]}")
        events = final(task_id)
        check(stream(events, "stdout") == b"second", f"the MCP run read {stream(events, 'stdout')!r}")
        post = rt.entries("post", run_id(b, task_id))[0]["request"]
        check(post["peerfs_workspace"] == "agent" and post["workspace_archive"] is None, f"the start request {post}")
        posts = len(rt.entries("post"))
        answer = channel.call("tools/call", {"name": "run_task", "arguments": {
            "destination": "rt-mcp", "argv": ["echo", "x"], "workspace_path": str(work),
            "peerfs_workspace": "agent"}}, whole=True)
        check("error" in answer or answer.get("result", {}).get("isError"),
              f"run_task with workspace_path and peerfs_workspace: {answer}")
        time.sleep(0.5)
        check(len(rt.entries("post")) == posts, "the refused run_task reached the runtime")
    finally:
        channel.close()


suite.finish()
