#!/usr/bin/env python3
"""Slim suite, runtime_policy: runtime rules in the policy body, runtime administration and persistence (RUN-1 to
RUN-6).

alice creates a coordinator-free network and links a second machine (alice2); bob joins as another person. alice's
host serves runtime tasks through conformance/slim/fake_runtime.py (RUN-4). This suite covers the contract's Runtime
rules and Policy body (key order, admission by the owner's other host and by another person's host, refusals, a rule
naming another host, `runtime.run` refused for agents), Runtime administration (`runtime enable`, `disable`, `show`)
and Persistence. The checks and the defaults of `runtime enable` are runtime.py, the test-clock cases
runtime_renewal.py; the shared fixtures are runtime_common.py.

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task, artifact and
coordinator-free contracts it builds on. No VM, no KVM, no model calls.
"""
import shutil
import sqlite3

from harness import Suite, check
from runtime_common import (RULE_KEYS, bind, enable, enable_for_both, learn, need, peer_submit, policy_statement,
                            policy_version, raw_task, refused, setup_network, show, sign_policy, state,
                            with_runtime_rules)

suite = Suite("runtime_policy", __doc__)
bind(suite)


@suite.case("setup", "decentralized-spec 6, 8 (create, join, link)")
def _():
    setup_network(second_machine=True)


@suite.case("rule_for_both", "runtime Runtime administration (--for): a rule for alice and bob; one run passes "
                             "Checks 1 to 3")
def _():
    need("a")
    enable_for_both()


@suite.case("rule_naming_another_host", "runtime Runtime rules: a host honours only rules naming itself")
def _():
    a2, b, rt, version = need("a2", "b", "rt", "version_rule")
    learn(a2, state["alice_public"], version)
    status, body = a2.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200, f"alice2: PUT /v1/runtime: {status} {body}")
    try:
        # bob is a principal of alice's only runtime rule, but that rule names alice's host, not alice2.
        status, body = peer_submit(raw_task(receiver=a2), receiver=a2)
        check(status == 403 and (body or {}).get("code") != "runtime_disabled",
              f"a request to alice2, which no runtime rule names: {status} {body}")
    finally:
        a2.api("DELETE", "/v1/runtime")


# The policy body (runtime Runtime rules, Policy body).

@suite.case("policy_body_runtime_rules", "runtime Policy body: key order; admitted by the owner's other host and by "
                                         "another person's host")
def _():
    a, a2, b = need("a", "a2", "b")
    need("version_rule")
    _, _, payload, body = policy_statement(a, state["alice_public"])
    keys = list(body)
    check("runtime_rules" in keys, f"no runtime_rules in the body: {keys}")
    check(keys.index("runtime_rules") == keys.index("capability_rules") + 1,
          f"runtime_rules is not right after capability_rules: {keys}")
    rules = body["runtime_rules"]
    check(len(rules) == 1 and list(rules[0]) == RULE_KEYS, f"rule keys {[list(r) for r in rules]}, want {RULE_KEYS}")
    check(rules[0]["host"] == a.id and rules[0]["principals"] == [state["alice_principal"], state["bob_principal"]]
          and rules[0]["max_cpus"] == 2 and rules[0]["peerfs_workspaces"] == [], f"the signed rule {rules[0]}")
    check(body["version"] == payload["sequence"] == state["version_rule"], "body version and statement sequence")
    for host in (a2, b):
        learn(host, state["alice_public"], state["version_rule"])
        _, _, _, seen = policy_statement(host, state["alice_public"])
        check(seen.get("runtime_rules") == rules, f"{host.name} holds {seen.get('runtime_rules')}")


@suite.case("policy_without_runtime_rules", "runtime Policy body: omitted when empty, same body as before")
def _():
    b, a = need("b", "a")
    before = state.get("policy_before")
    check(before is not None and "runtime_rules" not in before, f"alice's body before enable: {list(before or {})}")
    _, _, _, bobs = policy_statement(a, state["bob_public"])
    check("runtime_rules" not in bobs, f"bob's policy, with no runtime rules, has keys {list(bobs)}")


@suite.case("policy_body_refusals", "runtime Policy body (Reading): empty, unknown key, duplicate host, out of range; "
                                    "runtime.run refused in rules")
def _():
    a, a2 = need("a", "a2")
    need("version_rule")
    if not policy_statement(a, state["alice_public"])[3]["rules"]:
        # Fixture: an agent rule to amend with runtime.run below.
        out = a.ok("allow", "bob")
        learn(state["b"], state["alice_public"], out["policy"]["version"])
    good = policy_statement(a, state["alice_public"])[3]["runtime_rules"][0]
    before = policy_version(a, state["alice_public"])
    cases = {
        "empty runtime_rules": lambda body: with_runtime_rules(body, []),
        "an unknown key": lambda body: with_runtime_rules(body, [{**good, "max_gpus": 1}]),
        "a missing key": lambda body: with_runtime_rules(body, [{k: v for k, v in good.items() if k != "max_seconds"}]),
        "two rules for one host": lambda body: with_runtime_rules(body, [good, {**good, "max_cpus": 1}]),
        "max_cpus 65": lambda body: with_runtime_rules(body, [{**good, "max_cpus": 65}]),
        "max_output_bytes over 64 MiB": lambda body: with_runtime_rules(body, [{**good, "max_output_bytes": 67108865}]),
        "runtime.run in an agent rule": lambda body: dict(body, rules=[
            dict(rule, actions=list(rule["actions"]) + ["runtime.run"]) for rule in body["rules"]]),
    }
    check(policy_statement(a, state["alice_public"])[3]["rules"], "alice has no agent rule to amend")
    accepted = []
    for label, mutate in cases.items():
        status, response = sign_policy(mutate)
        if status == 200 and response.get("committed"):
            accepted.append(f"{label} ({status})")
    check(not accepted, f"policies admitted: {accepted}")
    check(policy_version(a, state["alice_public"]) == before, "a refused policy changed the current version")
    # A valid successor with a second rule, for alice2, is admitted (control for the refusals above).
    second = {**good, "host": a2.id, "principals": [state["alice_principal"]]}
    status, response = sign_policy(lambda body: with_runtime_rules(body, body["runtime_rules"] + [second]))
    check(status == 200 and response.get("committed"), f"a valid policy with two runtime rules: {status} {response}")
    learn(state["b"], state["alice_public"], before + 1)


@suite.case("routes_refuse_runtime_run_for_agents", "runtime Agents: a runtime.run route names a host, not an agent")
def _():
    a, b = need("a", "b")
    bert = state.setdefault("bert", b.agent("bert"))
    ada = state.setdefault("ada", a.agent("ada"))
    control = a.cli("adapter", "route", "add", "--adapter", ada.adapter_id, "--name", "to-bert", "--peer", b.id,
                    "--agent", bert.id, "--action", "task.submit", "--expires-in", "1h")
    check(control.ok, f"control: a task.submit route to an agent: exit {control.code} {control.stderr.strip()[-300:]}")
    bad = a.cli("adapter", "route", "add", "--adapter", ada.adapter_id, "--name", "rt-agent", "--peer", b.id,
                "--agent", bert.id, "--action", "runtime.run", "--expires-in", "1h")
    check(not bad.ok, "a runtime.run route naming an agent was created")
    host_route = b.cli("adapter", "route", "add", "--adapter", bert.adapter_id, "--name", "rt", "--peer", a.id,
                       "--action", "runtime.run", "--expires-in", "1h")
    check(host_route.ok, f"a runtime.run route naming alice's host: exit {host_route.code} "
                         f"{host_route.stderr.strip()[-300:]}")
    state["route"] = "rt"


@suite.case("runtime_enable_disable_show", "runtime Runtime administration: enable checks, disable, show")
def _():
    a, rt = need("a", "rt")
    need("ready")
    over = a.cli("runtime", "enable", "--socket", str(rt.socket), "--person-key", state["alice_key"], "--max-cpus",
                 "9", timeout=60)
    check(not over.ok, "runtime enable accepted a maximum over the runtime's report")
    missing = a.cli("runtime", "enable", "--socket", str(suite.work / "nothing.sock"), "--person-key",
                    state["alice_key"], timeout=60)
    check(not missing.ok, "runtime enable accepted a socket where no runtime answers")
    out = a.cli("runtime", "disable", "--person-key", state["alice_key"], timeout=90)
    check(out.ok, f"runtime disable: exit {out.code} {out.stderr.strip()[-300:]}")
    shown = show(a)
    check(shown["enabled"] is False and shown["rule"] is None, f"after disable: {shown}")
    rules = policy_statement(a, state["alice_public"])[3].get("runtime_rules") or []
    check(all(r["host"] != a.id for r in rules), f"alice's host still has a runtime rule: {rules}")
    status, body = peer_submit(raw_task())
    refused(status, body, 403, "runtime_disabled")
    enable("--for", state["alice_principal"], "--for", state["bob_principal"])
    check(show(a)["enabled"] is True, "enable after disable")


# Persistence (runtime Persistence).

@suite.case("open_previous_schema", "runtime Persistence: a database of the previous schema version opens")
def _():
    a2, = need("a2")
    copy = suite.host("alice2-copy", start=False)
    a2.stop()
    shutil.copytree(a2.state, copy.state, dirs_exist_ok=True)
    for leftover in ("admin.sock", "adapter.sock"):
        (copy.state / leftover).unlink(missing_ok=True)
    path = None
    for candidate in sorted(copy.state.glob("*.db")):
        probe = sqlite3.connect(str(candidate))
        try:
            if probe.execute("SELECT 1 FROM sqlite_master WHERE name = 'networks'").fetchone():
                path = candidate
        finally:
            probe.close()
    check(path is not None, "no state database in the copy")
    db = sqlite3.connect(str(path))
    current = db.execute("PRAGMA user_version").fetchone()[0]
    check(current >= 25, f"schema version {current}; this contract needs the next version after 24")
    db.execute(f"PRAGMA user_version = {current - 1}")
    db.commit()
    db.close()
    copy.start()
    check(copy.id == a2.id, "the copy has another host ID")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        check(db.execute("PRAGMA user_version").fetchone()[0] == current, "the previous version was not upgraded")
    finally:
        db.close()
    check(copy.api("GET", "/v1/tasks")[0] == 200, "task list on the upgraded database")
    copy.stop()


suite.finish()
