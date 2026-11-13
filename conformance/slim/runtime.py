#!/usr/bin/env python3
"""Slim suite, runtime: runtime task requests, the local switch, and the authorization checks (RUN-1 to RUN-5).

alice creates a coordinator-free network and bob joins as another person. alice's host serves runtime tasks through
conformance/slim/fake_runtime.py (RUN-4). This suite covers the contract's Requests and the Authorization checks: the
local switch, a missing or non-matching rule (with `runtime enable`'s default rule), task.submit, the rule's bounds,
and the rechecks before a start. The runtime rules in the policy body, administration and persistence are
runtime_policy.py; the test-clock cases are runtime_renewal.py; running, output and restarts are runtime_runs.py;
workspaces, results and the submitter's tools are runtime_results.py; peerfs workspaces (RUN-6, RUN-7) are
runtime_peerfs.py; the shared fixtures are runtime_common.py.

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task, artifact and
coordinator-free contracts it builds on. No VM, no KVM, no model calls.
"""
import hashlib

from harness import Suite, check
from runtime_common import (DEFAULTS, REPORT_KEYS, bind, enable, final, learn, need, occupy, peer_submit, raw_task,
                            receiver_events, refused, run_id, setup_network, show, state, submit)

suite = Suite("runtime", __doc__)
bind(suite)


@suite.case("setup", "decentralized-spec 6, 8 (create, join)")
def _():
    setup_network()


# Authorization: the switch and the rule (runtime Authorization, Checks).

@suite.case("switch_off_refused", "runtime The local switch; Checks step 1 (403 runtime_disabled)")
def _():
    (a,) = need("a")
    shown = show(a)
    check(set(shown) == {"enabled", "socket", "runtime", "rule"} and shown["enabled"] is False
          and shown["rule"] is None, f"runtime show before enable: {shown}")
    status, body = peer_submit(raw_task())
    refused(status, body, 403, "runtime_disabled")


@suite.case("switch_on_without_rule", "runtime Checks step 2: no runtime rule (403); runtime show")
def _():
    a, rt = need("a", "rt")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(suite.work / "nothing.sock")})
    check(status == 503, f"PUT /v1/runtime with a socket where no runtime answers: {status} {body}")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200 and isinstance(body, dict) and body.get("version") == "fake-runtime-1"
          and body.get("max_concurrent_runs") == 1, f"PUT /v1/runtime returns the runtime's report: {status} {body}")
    check(set(body) == REPORT_KEYS and body["peerfs"] is False, f"the runtime's report has keys {sorted(body)}, "
                                                                f"want {sorted(REPORT_KEYS)} with peerfs false")
    switch = a.state / "runtime.json"
    check(switch.is_file() and (switch.stat().st_mode & 0o777) == 0o600,
          f"the switch is not runtime.json (0600) in the state directory: exists {switch.exists()}")
    shown = show(a)
    check(shown["enabled"] is True and shown["socket"] == str(rt.socket) and shown["rule"] is None,
          f"runtime show with the switch only: {shown}")
    check(isinstance(shown["runtime"], dict) and shown["runtime"].get("version") == "fake-runtime-1"
          and shown["runtime"].get("max_concurrent_runs") == 1, f"the runtime's own report: {shown['runtime']}")
    status, body = peer_submit(raw_task())
    check(status == 403 and (body or {}).get("code") != "runtime_disabled", f"no runtime rule: {status} {body}")


@suite.case("task_submit_rule_does_not_authorize", "runtime Checks: task.submit never authorizes a runtime task")
def _():
    a, b = need("a", "b")
    out = a.ok("allow", "bob")
    check("task.submit" in out["actions"], f"allow bob: {out}")
    learn(b, state["alice_public"], out["policy"]["version"])
    status, body = peer_submit(raw_task())
    check(status == 403, f"a runtime task under a task.submit rule only: {status} {body}")


@suite.case("enable_default_principal", "runtime Runtime administration (runtime enable defaults; RUN-5); Checks 2")
def _():
    (a,) = need("a")
    result, version = enable()
    said = (result.stdout + result.stderr).lower()
    check(any(word in said for word in ("software", "upgrade", "older", "earlier")),
          f"runtime enable did not state the compatibility warning (RUN-5): {said[-300:]!r}")
    rule = show(a)["rule"]
    want = {"host": a.id, "principals": [state["alice_principal"]], **DEFAULTS, "peerfs_workspaces": [],
            "allow_disconnected": False, "network_id": state["net"]}
    check(rule == want, f"the default rule {rule}, want {want} (the body rule plus network_id)")
    state["version_alice_only"] = version
    status, body = peer_submit(raw_task())
    check(status == 403, f"bob, not a principal of the rule: {status} {body}")


@suite.case("enable_for_both", "runtime Runtime administration (--for); Checks 1 to 3 pass")
def _():
    (a,) = need("a")
    _, version = enable("--for", state["alice_principal"], "--for", state["bob_principal"])
    state["version_rule"] = version
    rule = show(a)["rule"]
    check(rule["principals"] == [state["alice_principal"], state["bob_principal"]], f"rule principals {rule}")
    body = raw_task(("echo", "authorized"))
    status, record = peer_submit(body)
    check(status == 200 and record["state"] == "queued", f"an authorized runtime task: {status} {record}")
    events = final(body["task_id"])
    check(events[-1]["kind"] == "succeeded", f"the authorized run: {[e['kind'] for e in events]}")
    # Idempotency covers the whole request, run included (runtime Requests).
    status, again = peer_submit(body)
    check(status == 200 and again["task_id"] == body["task_id"], f"an identical repeat: {status} {again}")
    changed = dict(body, run={"argv": ["echo", "other"]})
    status, again = peer_submit(changed)
    check(status == 409, f"the same task_id with another run: {status} {again}")
    state["ready"] = True


# Requests (runtime Requests).

@suite.case("request_validation", "runtime Requests: executor, fields, run limits, manifest (400 invalid, field named)")
def _():
    a, b = need("a", "b")
    need("ready")
    sha = hashlib.sha256(b"x").hexdigest()
    manifest = [{"name": "ws.tar", "size": 1, "sha256": sha, "media_type": "application/x-tar"}]
    cases = [
        ("executor", raw_task(executor="vm")),
        ("target_agent_id", raw_task(target_agent_id="agent_" + "0" * 32)),
        ("grant_id", raw_task(grant_id="grant_" + "0" * 32)),
        ("delegation", raw_task(delegation=[])),
        ("chain", raw_task(chain=[])),  # any field not listed is 400 naming it
        ("argv", raw_task(run={"argv": []})),
        ("argv", raw_task(run={"argv": ["a\u0000b"]})),
        ("argv", raw_task(run={"argv": ["x" * 4097]})),
        ("argv", raw_task(run={"argv": ["x"] * 257})),
        ("cwd", raw_task(run={"argv": ["echo"], "cwd": "relative"})),
        ("env", raw_task(run={"argv": ["echo"], "env": {"1BAD": "x"}})),
        ("env", raw_task(run={"argv": ["echo"], "env": {f"V{i}": "x" for i in range(65)}})),
        ("cpus", raw_task(run={"argv": ["echo"], "resources": {"cpus": 0}})),
        ("memory_mib", raw_task(run={"argv": ["echo"], "resources": {"memory_mib": 127}})),
        ("timeout_seconds", raw_task(run={"argv": ["echo"], "resources": {"timeout_seconds": 86401}})),
        ("results", raw_task(run={"argv": ["echo"], "results": "everything"})),
        (("run", "stdin"), raw_task(run={"argv": ["echo"], "stdin": "x"})),
        (("workspace", "artifacts"), raw_task(run={"argv": ["echo"], "workspace": {"archive": sha}})),
        (("workspace", "artifacts", "media_type"), raw_task(run={"argv": ["echo"], "workspace": {"archive": sha}},
                                                            artifacts=[dict(manifest[0], media_type="text/plain")])),
    ]
    failures = []
    for field, body in cases:
        fields = (field,) if isinstance(field, str) else field
        status, answer = peer_submit(body)
        if not (status == 400 and isinstance(answer, dict) and answer.get("code") == "invalid"
                and any(f in (answer.get("error") or "") for f in fields)):
            failures.append(f"{'/'.join(fields)}: {status} {answer}")
    check(not failures, "requests not refused as 400 invalid naming the field: " + "; ".join(failures))


@suite.case("resources_over_rule_refused", "runtime Checks step 3: resources over the rule's maximum (403)")
def _():
    need("ready")
    for resources in ({"cpus": 3}, {"memory_mib": 4096}, {"timeout_seconds": 3601}):
        status, body = peer_submit(raw_task(run={"argv": ["echo"], "resources": resources}))
        check(status == 403, f"resources {resources} over the rule: {status} {body}")
    status, body = peer_submit(raw_task(run={"argv": ["echo"], "resources": {"cpus": 2, "memory_mib": 2048,
                                                                             "timeout_seconds": 3600}}))
    check(status == 200, f"resources at the rule's maximum: {status} {body}")
    final(body["task_id"])


# Rechecks at start (runtime Checks).

@suite.case("recheck_switch_off_while_queued", "runtime Checks: switch off while queued ends rejected; a started run "
                                               "finishes")
def _():
    a, rt = need("a", "rt")
    need("ready")
    holder = occupy(3)
    task_id = submit(["echo", "queued"])
    receiver_events(task_id, until=lambda evs: bool(evs))
    status, body = a.api("DELETE", "/v1/runtime")
    check(status == 200 and body == {"enabled": False}, f"DELETE /v1/runtime: {status} {body}")
    check(show(a)["rule"] is not None, "DELETE /v1/runtime changed the policy")
    try:
        events = final(task_id, timeout=20)
        check(events[-1]["kind"] == "rejected" and events[-1]["message"], f"events {[e['kind'] for e in events]}")
        check(final(holder)[-1]["kind"] == "succeeded", "the started run did not finish after the switch went off")
    finally:
        a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})


@suite.case("recheck_rule_withdrawn_while_queued", "runtime Checks: the rule withdrawn while queued ends rejected")
def _():
    a, rt = need("a", "rt")
    need("ready")
    holder = occupy(4)
    task_id = submit(["echo", "queued"])
    receiver_events(task_id, until=lambda evs: bool(evs))
    out = a.cli("runtime", "disable", "--person-key", state["alice_key"], timeout=90)
    check(out.ok, f"runtime disable: {out.stderr.strip()[-300:]}")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})  # the switch on again, without a rule
    check(status == 200, f"PUT /v1/runtime: {status} {body}")
    try:
        events = final(task_id, timeout=20)
        check(events[-1]["kind"] == "rejected" and events[-1]["message"], f"events {[e['kind'] for e in events]}")
        check(final(holder)[-1]["kind"] == "succeeded", "a started run was stopped by withdrawing the rule")
    finally:
        enable("--for", state["alice_principal"], "--for", state["bob_principal"])


@suite.case("recheck_runtime_maximums", "runtime Running: a 422 from the runtime ends rejected")
def _():
    b, rt = need("b", "rt")
    need("ready")
    rt.restart(max_cpus=1)
    try:
        task_id = submit(["echo", "too big"])
        events = final(task_id, timeout=20)
        check([e["kind"] for e in events] == ["queued", "rejected"] and events[-1]["message"],
              f"events {[e['kind'] for e in events]}")
        posts = rt.entries("post", run_id(b, task_id))
        check(all(p["status"] == 422 for p in posts) and not rt.entries("started", run_id(b, task_id)),
              f"runtime answers {[p['status'] for p in posts]}")
    finally:
        rt.restart()


suite.finish()
