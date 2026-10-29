#!/usr/bin/env python3
"""Exact local project review, from guided-session-contract.md sections 3 and 4.

Real temporary hosts and public owner APIs establish every flow and attachment.
Only offline storage-format fixtures edit SQLite: the additive legacy layout,
reserved-name collisions, malformed schemas and a future version. Protocol and
authority records are never manufactured or edited. This does not test a native
human callback, an adapter connection to a real model, or historical binaries.
"""
import hashlib
import http.client
import json
import math
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from harness import (Suite, UnixHTTPConnection, check, create_network, join_new_person,
                     parse_time, ssh_key)

suite = Suite("project_onboarding", __doc__)
suite.use_clock()
a = suite.host("owner")
state = {}
BASE = "/v1/onboarding/project-flows"
TABLE = "onboarding_project_flows"
TOP = {"version", "flow_id", "state", "review_id", "review", "attachment", "next_action"}
REVIEW = {"version", "kind", "flow_id", "host_id", "project_root", "native_session_id", "integration",
          "create_agent", "agent", "session_id", "expires_at", "effects"}
EFFECTS = {"register_agent": True, "attach_session": True, "issue_adapter_credential": False,
           "grant_network_access": False, "share_files": False, "share_conversation": False,
           "capability_calls": False}
COLUMNS = ["flow_id", "project_root", "native_session_id", "integration", "request", "review", "review_id",
           "state", "created_at", "expires_at", "session_id", "decided_at"]


def need(name):
    check(name in state, "a required earlier project-review fixture did not finish")
    return state[name]


def get(host, path):
    status, body = host.api("GET", path, timeout=10)
    check(status == 200, f"{host.name} GET public/local observation: HTTP {status}")
    return body


def proposal(label, *, agent=None, root=None, native=None):
    return {"project_root": root or str(suite.work / "projects" / label),
            "native_session_id": native or "native-" + label, "integration": "claude-code",
            "agent": agent or {"kind": "new", "name": "agent-" + label, "owner": "local owner"}}


def prepared(host, body, status=201):
    code, flow = host.api("POST", BASE, body, timeout=10)
    check(code == status, f"prepare project review: HTTP {code}, want {status}")
    validate(host, body, flow)
    return flow


def decision(flow, choice="approve"):
    return {"review_id": flow["review_id"], "project_root": flow["review"]["project_root"],
            "native_session_id": flow["review"]["native_session_id"], "integration": "claude-code",
            "decision": choice}


def decide(host, flow, choice="approve", status=200, code=None, body=None):
    actual, result = host.api("POST", BASE + "/" + flow["flow_id"] + "/decision",
                              body if body is not None else decision(flow, choice), timeout=10)
    check(actual == status, f"project decision: HTTP {actual}, want {status}")
    if code:
        check(isinstance(result, dict) and result.get("code") == code, f"project decision did not return {code}")
    else:
        check(result["review"] == flow["review"] and result["review_id"] == flow["review_id"],
              "decision changed immutable review terms")
        check(set(result) == TOP, "decision response shape")
    return result


def validate(host, body, flow):
    check(isinstance(flow, dict) and set(flow) == TOP and type(flow["version"]) is int and flow["version"] == 1,
          "project flow response shape/version")
    review = flow["review"]
    check(isinstance(review, dict) and set(review) == REVIEW, "immutable review shape")
    check(re.fullmatch(r"flow_[0-9a-f]{32}", flow["flow_id"]) is not None, "flow ID format")
    check(re.fullmatch(r"session_[0-9a-f]{32}", review["session_id"]) is not None, "planned session ID format")
    check(re.fullmatch(r"agent_[0-9a-f]{32}", review["agent"]["id"]) is not None, "review agent ID format")
    check(review["version"] == 1 and review["kind"] == "attach_project"
          and review["flow_id"] == flow["flow_id"] and review["host_id"] == host.id, "review identity/bindings")
    for field in ("project_root", "native_session_id", "integration"):
        check(review[field] == body[field], f"review changed its {field} binding")
    check(set(review["agent"]) == {"id", "name", "owner", "capabilities"}, "review agent metadata shape")
    is_new = body["agent"]["kind"] == "new"
    check(review["create_agent"] is is_new, "wrong create_agent effect")
    expected = {**EFFECTS, "register_agent": is_new}
    check(review["effects"] == expected, "review claims unintended authority, sharing or adapter effects")
    if is_new:
        check(review["agent"]["name"] == body["agent"]["name"].strip()
              and review["agent"]["owner"] == body["agent"]["owner"].strip()
              and review["agent"]["capabilities"] == [], "new-agent terms were not normalized exactly")
    else:
        check(review["agent"]["id"] == body["agent"]["id"], "an arbitrary existing agent was adopted")
    canonical = json.dumps(review, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    digest = hashlib.sha256(b"peerspan-project-review-v1\n" + canonical).hexdigest()
    check(flow["review_id"] == "review_" + digest, "review digest does not bind its canonical UTF-8 terms")
    parse_time(review["expires_at"])
    actions = {"review": "review", "attached": "continue_adapter_setup", "declined": "restart_review",
               "expired": "restart_review", "invalidated": "restart_review"}
    check(flow["state"] in actions and flow["next_action"] == actions[flow["state"]], "flow state/next action")


def db_path(host):
    # The public slim storage fixture identifies the host DB by `networks`;
    # ancillary stores may also use .db files in the same private directory.
    matches = []
    for path in sorted(host.state.glob("*.db")):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                matches.append(path)
    check(len(matches) == 1, "expected one host database containing the networks table")
    return matches[0]


def records(host, *, omit_flow=False):
    with closing(sqlite3.connect(f"file:{db_path(host)}?mode=ro", uri=True, timeout=5)) as db, db:
        db.execute("BEGIN")
        result = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                  "$version": db.execute("PRAGMA user_version").fetchone()}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            if omit_flow and name == TABLE:
                continue
            quoted = '"' + name.replace('"', '""') + '"'
            result[name] = tuple(sorted(db.execute(f"SELECT * FROM {quoted}"), key=repr))
        return result


def flow_rows(host):
    with closing(sqlite3.connect(f"file:{db_path(host)}?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM onboarding_project_flows ORDER BY flow_id")]


def events(host):
    return get(host, "/v1/activity?limit=1000")


def file_state(root):
    if not root.exists():
        return None
    return {str(p.relative_to(root)): (p.lstat().st_mode, p.lstat().st_mtime_ns,
            os.readlink(p) if p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in [root, *sorted(root.rglob("*"))]}


def parallel(call, count=6):
    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(lambda _: call(), range(count)))


def raw_api(host, path, data):
    conn = UnixHTTPConnection(str(host.state / "admin.sock"), timeout=10)
    try:
        conn.request("POST", path, body=data, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        payload = response.read()
        return response.status, json.loads(payload) if payload else None
    finally:
        conn.close()


def advance_to(moment):
    suite.set_offset(math.ceil((moment - datetime.now(timezone.utc)).total_seconds()))


def assert_private(host, flows):
    observation = json.dumps(get(host, "/v1/onboarding"), ensure_ascii=False)
    for flow in flows:
        for value in (flow["flow_id"], flow["review_id"], flow["review"]["project_root"], flow["review"]["native_session_id"]):
            check(value not in observation, "private project-review context leaked into public onboarding")


@suite.case("prepare_exact_read_only_review", "guided onboarding 3 verification 1")
def _():
    project = suite.work / 'projects' / 'École "notes"\\draft'
    body = proposal("unicode", root=str(project), agent={"kind": "new", "name": '  École-"agent"  ', "owner": '  東京\\owner  '})
    before = records(a, omit_flow=True)
    beginning = a.now()
    flow = prepared(a, body)
    check(flow["state"] == "review" and flow["attachment"] is None, "preparation committed an attachment")
    check(abs((parse_time(flow["review"]["expires_at"]) - beginning).total_seconds() - 900) < 2,
          "review deadline is not the fixed fifteen-minute deadline")
    check(get(a, BASE + "/" + flow["flow_id"]) == flow, "inspect changed the prepared review")
    check(prepared(a, body, 200) == flow, "identical prepare changed the immutable review")
    check(records(a, omit_flow=True) == before, "prepare/inspect/retry changed non-flow durable records")
    rows = flow_rows(a)
    check(len(rows) == 1 and rows[0]["flow_id"] == flow["flow_id"] and rows[0]["state"] == "review",
          "preparation did not retain exactly one private flow row")
    normalized = {**body, "agent": {"kind": "new", "name": 'École-"agent"', "owner": '東京\\owner'}}
    check(json.loads(rows[0]["request"]) == normalized and json.loads(rows[0]["review"]) == flow["review"],
          "stored request/review do not preserve normalized exact terms")
    check(rows[0]["session_id"] is None and rows[0]["decided_at"] is None, "prepare stored a decision/session")
    check(not project.exists(), "prepare created the nonexistent project directory")
    assert_private(a, [flow])
    state["prepared"] = (body, flow)


@suite.case("concurrent_prepare_and_restart_resume", "guided onboarding 3 verification 2")
def _():
    body = proposal("concurrent")
    before = records(a, omit_flow=True)
    replies = parallel(lambda: a.api("POST", BASE, body))
    check(sorted(code for code, _ in replies) == [200] * 5 + [201], "concurrent prepare did not create exactly once")
    flow = replies[0][1]
    check(all(value == flow for _, value in replies), "concurrent prepare allocated different exact reviews")
    validate(a, body, flow)
    other = {**body, "agent": {"kind": "new", "name": "different-choice", "owner": "local owner"}}
    status, error = a.api("POST", BASE, other)
    check(status == 409 and error.get("code") == "flow_conflict", "changed agent choice silently replaced an attempt")
    check(records(a, omit_flow=True) == before, "prepare race/conflict changed unrelated records")
    a.restart(kill=True)
    check(prepared(a, body, 200) == flow, "restart/resume changed IDs, deadline or review terms")
    different_native = prepared(a, {**body, "native_session_id": "another-conversation"})
    different_project = prepared(a, {**body, "project_root": str(suite.work / "another-project")})
    check(len({x["flow_id"] for x in (flow, different_native, different_project)}) == 3, "distinct contexts were merged")
    check(sum(row["flow_id"] == flow["flow_id"] for row in flow_rows(a)) == 1, "resume duplicated its flow row")


@suite.case("approval_atomic_idempotent_and_metadata_only", "guided onboarding 3 verification 3")
def _():
    body = proposal("approved")
    project = Path(body["project_root"])
    project.mkdir(parents=True)
    (project / "keep.txt").write_text("unchanged project material\n")
    project_before = file_state(project)
    flow = prepared(a, body)
    before = events(a)
    replies = parallel(lambda: a.api("POST", BASE + "/" + flow["flow_id"] + "/decision", decision(flow)))
    check(all(code == 200 for code, _ in replies), "concurrent exact approvals were not idempotent")
    approved = replies[0][1]
    check(all(value == approved for _, value in replies), "approval race returned different outcomes")
    expected_attachment = {"agent_id": flow["review"]["agent"]["id"], "session_id": flow["review"]["session_id"]}
    check(approved["state"] == "attached" and approved["attachment"] == expected_attachment,
          "approval did not attach the exact reviewed IDs")
    validate(a, body, approved)
    new_events = events(a)[len(before):]
    check([(e["kind"], e["subject_id"]) for e in new_events] == [
        ("agent.registered", expected_attachment["agent_id"]), ("session.attached", expected_attachment["session_id"])],
        "approval did not append exactly the ordinary registry events")
    check(decide(a, flow) == approved, "same approval changed the attachment outcome")
    session = get(a, "/v1/sessions/" + expected_attachment["session_id"])
    check(session["agent_id"] == expected_attachment["agent_id"] and session["state"] == "attached"
          and session["integration"] == "claude-code" and session.get("channel") is None, "wrong attached metadata")
    view = get(a, "/v1/onboarding")
    observed = next(s for agent in view["agents"] for s in agent["sessions"] if s["id"] == session["id"])
    check(observed["adapter_id"] is None and observed["connection"] is None and observed["expires_at"] is None
          and observed["renewable"] is False, "metadata approval claimed adapter/channel credentials")
    check(get(a, "/v2/networks") == [], "project attachment admitted a network")
    check(file_state(project) == project_before, "approval edited project files")
    assert_private(a, [flow])
    state["approved"] = (body, flow, approved)


@suite.case("explicit_existing_agent_and_input_validation", "guided onboarding 3 verification 4")
def _():
    status, agent = a.api("POST", "/v1/agents", {"name": "existing-choice", "owner": "other owner",
                                                "capabilities": ["descriptive", "étiquette"]})
    check(status == 201, "could not register explicit existing-agent fixture")
    body = proposal("existing", agent={"kind": "existing", "id": agent["id"]})
    flow = prepared(a, body)
    check(flow["review"]["agent"] == {key: agent[key] for key in ("id", "name", "owner", "capabilities")},
          "existing-agent metadata was not pinned exactly")
    before = events(a)
    decide(a, flow)
    check([(e["kind"], e["subject_id"]) for e in events(a)[len(before):]] == [("session.attached", flow["review"]["session_id"])],
          "existing-agent approval changed registry metadata or added another agent")
    check(get(a, "/v1/agents/" + agent["id"]) == agent, "existing-agent metadata changed on approval")
    invalid = []
    for path in ("relative", "/a/./b", "/a/../b", "/a//b", "/a/", "/a\nb", "/" + "a" * 4096):
        invalid.append({**proposal("bad-path"), "project_root": path})
    for native in ("", "has space", "has\ttab", "has\x00control", "é" * 129):
        invalid.append({**proposal("bad-native"), "native_session_id": native})
    for agent_value in ({"kind": "new", "name": "*", "owner": "owner"}, {"kind": "new", "name": " ", "owner": "owner"},
                        {"kind": "new", "name": "é" * 65, "owner": "owner"}, {"kind": "new", "name": "valid", "owner": ""},
                        {"kind": "existing", "id": "bad-id"}, {"kind": "existing", "id": agent["id"], "name": "extra"},
                        {"kind": "new", "name": "valid", "owner": "owner", "capabilities": []}, None):
        invalid.append({**proposal("bad-agent"), "agent": agent_value})
    invalid += [{**proposal("extra"), "unknown": True}, {**proposal("null"), "project_root": None},
                {**proposal("integration"), "integration": "opencode"}]
    before = records(a)
    for value in invalid:
        status, error = a.api("POST", BASE, value)
        check(status == 400 and error.get("code") == "invalid", f"invalid proposal accepted or wrong error: HTTP {status}")
    status, error = a.api("POST", BASE, proposal("unknown-agent", agent={"kind": "existing", "id": "agent_" + "f" * 32}))
    check(status == 404 and error.get("code") == "not_found", "well-formed unknown existing agent did not return 404")
    for data in (b'{"project_root":', b'null', b'\xff', json.dumps(proposal("duplicate")).replace('"integration":', '"integration":"claude-code","integration":').encode()):
        status, error = raw_api(a, BASE, data)
        check(status == 400 and error.get("code") == "invalid", "malformed JSON proposal was not rejected")
    encoded = json.dumps(proposal("body-bound")).encode()
    status, _ = raw_api(a, BASE, b" " * (1024 * 1024 + 1 - len(encoded)) + encoded)
    check(status in (400, 413), "owner administration body bound accepted a body larger than 1 MiB")
    unknown = {**flow, "flow_id": "flow_" + "f" * 32}
    check(a.api("GET", BASE + "/" + unknown["flow_id"])[0] == 404, "unknown flow inspection was not 404")
    decide(a, unknown, status=404, code="not_found")
    check(records(a) == before, "rejected proposals changed durable records")
    boundary = proposal("boundaries", root="/" + "a" * 4095, native="é" * 128,
                        agent={"kind": "new", "name": "é" * 64, "owner": "o" * 128})
    prepared(a, boundary)
    prepared(a, proposal("root-path", root="/"))


@suite.case("exact_decisions_decline_and_fixed_expiry", "guided onboarding 3 verification 5")
def _():
    flow = prepared(a, proposal("decision-binding"))
    before = records(a)
    for change in ({"review_id": "review_" + "0" * 64}, {"project_root": str(suite.work / "wrong-context")},
                   {"native_session_id": "wrong-conversation"}):
        decide(a, flow, status=409, code="review_changed", body={**decision(flow), **change})
    for change in ({"decision": True}, {"decision": "unknown"}, {"decision": None}, {"extra": True}, {"integration": "opencode"}):
        decide(a, flow, status=400, code="invalid", body={**decision(flow), **change})
    check(records(a) == before, "rejected exact decisions changed durable state")
    decline_body = proposal("declined")
    declined = prepared(a, decline_body)
    before = records(a, omit_flow=True)
    result = decide(a, declined, "decline")
    check(result["state"] == "declined" and result["attachment"] is None, "decline claimed an attachment")
    check(records(a, omit_flow=True) == before, "decline created registry, authority or activity records")
    check(decide(a, declined, "decline") == result, "same decline was not idempotent")
    decide(a, declined, status=409, code="flow_conflict")
    a.restart()
    check(decide(a, declined, "decline") == result, "declined retry changed after restart")
    timed_body = proposal("timed")
    timed = prepared(a, timed_body)
    before = records(a)
    advance_to(parse_time(timed["review"]["expires_at"]))
    observed = get(a, BASE + "/" + timed["flow_id"])
    check(observed["state"] == "expired" and observed["review"] == timed["review"], "deadline did not expire immutable review")
    check(prepared(a, timed_body, 200) == observed, "resume refreshed an expired review")
    decide(a, timed, status=409, code="review_expired")
    check(records(a) == before, "expiry inspection/refusal advanced or rewrote durable state")
    # This approval is made now, then retried after its deadline while still attached.
    live_body = proposal("after-deadline")
    live = prepared(a, live_body)
    attached = decide(a, live)
    advance_to(parse_time(live["review"]["expires_at"]))
    before = records(a)
    check(decide(a, live) == attached, "committed approval expired as consent")
    decide(a, live, "decline", status=409, code="flow_conflict")
    check(records(a) == before, "committed retry/opposite decision changed durable rows")
    state["expired"] = (timed_body, timed)
    state["declined"] = (decline_body, declined)


@suite.case("collision_detachment_and_replacement_races", "guided onboarding 3 verification 6")
def _():
    body = proposal("name-collision")
    flow = prepared(a, body)
    status, taken = a.api("POST", "/v1/agents", {"name": body["agent"]["name"], "owner": "different owner"})
    check(status == 201, "public name-collision fixture failed")
    before = records(a)
    invalid = get(a, BASE + "/" + flow["flow_id"])
    check(invalid["state"] == "invalidated" and invalid["review"] == flow["review"], "name collision changed or adopted review")
    check(prepared(a, body, 200) == invalid, "invalidated resume replaced the review")
    decide(a, flow, status=409, code="flow_conflict")
    check(records(a) == before, "invalidated inspection/decision changed rows")
    replacement = {**body, "agent": {"kind": "existing", "id": taken["id"]}, "replace_flow_id": flow["flow_id"]}
    replies = parallel(lambda: a.api("POST", BASE, replacement))
    check(sum(code == 201 for code, _ in replies) == 1 and all(code in (201, 409) for code, _ in replies),
          "concurrent replacements did not create at most one fresh review")
    current = next(value for code, value in replies if code == 201)
    check(current["flow_id"] != flow["flow_id"] and current["review"]["session_id"] != flow["review"]["session_id"],
          "replacement reused old review or planned session")
    validate(a, replacement, current)
    check(get(a, BASE + "/" + flow["flow_id"])["review"] == flow["review"], "replacement rewrote old terms")
    before = records(a)
    for bad in (replacement, {**replacement, "replace_flow_id": current["flow_id"]},
                {**replacement, "replace_flow_id": "flow_" + "f" * 32}):
        status, error = a.api("POST", BASE, bad)
        check(status == 409 and error.get("code") == "flow_conflict", "stale or reviewable replacement was accepted")
    decide(a, flow, status=409, code="flow_conflict")
    check(records(a) == before, "stale replacement/decision changed newer attempt")
    attached = decide(a, current)
    before = records(a)
    status, error = a.api("POST", BASE, {**replacement, "replace_flow_id": current["flow_id"]})
    check(status == 409 and error.get("code") == "flow_conflict" and records(a) == before,
          "replacement changed a still-attached attempt")
    status, _ = a.api("POST", "/v1/sessions/" + current["review"]["session_id"] + "/detach", {})
    check(status == 200, "owner detach fixture failed")
    before = records(a)
    detached = get(a, BASE + "/" + current["flow_id"])
    check(detached["state"] == "invalidated" and detached["attachment"] == attached["attachment"], "detach lost outcome IDs")
    decide(a, current, status=409, code="flow_conflict")
    check(records(a) == before and get(a, "/v1/sessions/" + current["review"]["session_id"])["state"] == "detached",
          "approval replay resurrected detached metadata")
    fresh_detached = prepared(a, {**replacement, "replace_flow_id": current["flow_id"]})
    check(fresh_detached["review"]["session_id"] != current["review"]["session_id"]
          and get(a, BASE + "/" + current["flow_id"])["review"] == current["review"],
          "replacement of detached metadata reused or rewrote its predecessor")
    for label in ("declined", "expired"):
        old_body, old = need(label)
        fresh = prepared(a, {**old_body, "replace_flow_id": old["flow_id"]})
        check(fresh["flow_id"] != old["flow_id"] and fresh["review_id"] != old["review_id"]
              and fresh["review"]["session_id"] != old["review"]["session_id"], "terminal replacement reused IDs")
        check(get(a, BASE + "/" + old["flow_id"])["review"] == old["review"], "terminal replacement rewrote its predecessor")
        decide(a, old, "decline" if label == "declined" else "approve", status=409, code="flow_conflict")
    # Ordinary host restart detaches metadata; it never replays successful consent.
    restart_flow = prepared(a, proposal("restart-attachment"))
    attached = decide(a, restart_flow)
    before_events = events(a)
    a.restart(kill=True)
    outcome = get(a, BASE + "/" + restart_flow["flow_id"])
    check(outcome["state"] == "invalidated" and outcome["attachment"] == attached["attachment"], "startup resurrected attachment")
    after_events = events(a)
    check(all(event["kind"] == "session.disconnected" for event in after_events[len(before_events):]),
          "startup replayed registry/approval events")
    before = records(a)
    decide(a, restart_flow, status=409, code="flow_conflict")
    check(records(a) == before, "post-restart consent replay changed durable state")


@suite.case("private_context_lookup_is_exact_read_only_and_resumable", "guided onboarding 4 verification 7")
def _():
    body = proposal("lookup-private", native="native-lookup-private-marker")
    context = {key: body[key] for key in ("project_root", "native_session_id", "integration")}

    def lookup(expected):
        before = records(a)
        status, value = a.api("POST", BASE + "/lookup", context)
        check(status == 200 and set(value) == {"version", "host_id", "context", "flow", "agents"}, "lookup response shape/status")
        check(type(value["version"]) is int and value["version"] == 1 and value["host_id"] == a.id
              and value["context"] == context, "lookup did not preserve the exact private host/context")
        check(value["flow"] == expected and value["agents"] == get(a, "/v1/agents"), "lookup picked the wrong flow/agent list")
        cli = a.cli("onboarding", "project", "lookup", "--stdin", input=json.dumps(context))
        check(cli.ok and cli.json == value, "lookup CLI differs from its owner API")
        check(records(a) == before, "context lookup changed consent, expiry, activity or logical records")
        return value

    lookup(None)
    flow = prepared(a, body)
    lookup(flow)
    attached = decide(a, flow)
    lookup(attached)
    expired_body = proposal("lookup-expired")
    expired = prepared(a, expired_body)
    advance_to(parse_time(expired["review"]["expires_at"]))
    context = {key: expired_body[key] for key in context}
    expired_view = get(a, BASE + "/" + expired["flow_id"])
    check(expired_view["state"] == "expired", "lookup expiry fixture is not expired")
    lookup(expired_view)
    fresh = prepared(a, {**expired_body, "replace_flow_id": expired["flow_id"]})
    lookup(fresh)
    check(get(a, BASE + "/" + expired["flow_id"])["review"] == expired["review"], "lookup replacement changed old terms")
    invalid_body = proposal("lookup-invalidated")
    invalid = prepared(a, invalid_body)
    check(a.api("POST", "/v1/agents", {"name": invalid_body["agent"]["name"], "owner": "name collision"})[0] == 201,
          "lookup invalidation fixture failed")
    context = {key: invalid_body[key] for key in context}
    invalid_view = get(a, BASE + "/" + invalid["flow_id"])
    check(invalid_view["state"] == "invalidated", "lookup invalidation fixture is not invalidated")
    lookup(invalid_view)
    before = records(a)
    for invalid_context in ({**context, "agent": body["agent"]}, {**context, "project_root": None},
                            {**context, "project_root": "relative"}, {**context, "native_session_id": "has space"},
                            {**context, "integration": "opencode"}):
        status, error = a.api("POST", BASE + "/lookup", invalid_context)
        check(status == 400 and error.get("code") == "invalid", "lookup accepted invalid/extra/null context")
    encoded = json.dumps(context)
    for data in ('{"project_root":', json.dumps({**context, "unknown": "private-extra-marker"}),
                 " " * (65537 - len(encoded.encode())) + encoded):
        result = a.cli("onboarding", "project", "lookup", "--stdin", input=data)
        check(not result.ok, "lookup CLI accepted malformed/extra/oversized stdin")
        check(context["project_root"] not in result.stdout + result.stderr
              and context["native_session_id"] not in result.stdout + result.stderr
              and "private-extra-marker" not in result.stdout + result.stderr, "lookup CLI echoed private input")
    check(not a.cli("onboarding", "project", "lookup", input=encoded).ok, "lookup selected stdin implicitly")
    check(records(a) == before, "rejected context lookups changed durable state")
    assert_private(a, [flow, expired, fresh, invalid])

    # Lookup must join its current flow and registry in one observation even
    # while another owner-local call commits that flow's new agent/session.
    racing_body = proposal("lookup-atomic")
    racing = prepared(a, racing_body)
    racing_context = {key: racing_body[key] for key in context}
    with ThreadPoolExecutor(max_workers=5) as pool:
        reads = [pool.submit(a.api, "POST", BASE + "/lookup", racing_context) for _ in range(8)]
        approval = pool.submit(decide, a, racing)
        observations = [read.result() for read in reads]
        approval.result()
    observations.append(a.api("POST", BASE + "/lookup", racing_context))
    for status, value in observations:
        check(status == 200 and value["context"] == racing_context, "concurrent lookup context/status")
        observed = value["flow"]
        check(observed["review"] == racing["review"] and observed["review_id"] == racing["review_id"],
              "concurrent lookup changed immutable terms")
        matching = [agent for agent in value["agents"] if agent["id"] == racing["review"]["agent"]["id"]]
        check(observed["state"] in {"review", "attached"}
              and bool(matching) == (observed["state"] == "attached"), "lookup tore flow/registry commit evidence")


@suite.case("cli_stdin_validation_and_unavailable_daemon", "guided onboarding 3 verification 7; 4 verification 7")
def _():
    body = proposal("cli-private", native="native-cli-private-marker")
    made = a.cli("onboarding", "project", "prepare", "--stdin", input=json.dumps(body))
    check(made.ok and made.json, "CLI prepare from explicit bounded stdin failed")
    flow = made.json
    validate(a, body, flow)
    check(get(a, BASE + "/" + flow["flow_id"]) == flow, "CLI prepare differs from owner API")
    check(a.ok("onboarding", "project", "inspect", flow["flow_id"]) == flow, "CLI inspect differs from owner API")
    payload = {"flow_id": flow["flow_id"], **decision(flow, "decline")}
    decided = a.cli("onboarding", "project", "decide", "--stdin", input=json.dumps(payload))
    check(decided.ok and decided.json == get(a, BASE + "/" + flow["flow_id"]), "CLI decision differs from owner API")
    before = records(a)
    for command in ("prepare", "decide"):
        valid_input = body if command == "prepare" else payload
        encoded = json.dumps(valid_input)
        for data in ('{"private_payload":', json.dumps({**valid_input, "unknown": "do-not-echo-private"}),
                     " " * (65537 - len(encoded.encode())) + encoded):
            result = a.cli("onboarding", "project", command, "--stdin", input=data)
            check(not result.ok, "malformed/extra/oversized CLI stdin was accepted")
            check(body["project_root"] not in result.stdout + result.stderr
                  and body["native_session_id"] not in result.stdout + result.stderr
                  and "do-not-echo-private" not in result.stdout + result.stderr, "CLI echoed private malformed input")
        check(not a.cli("onboarding", "project", command, input=json.dumps(body)).ok, "CLI read stdin without --stdin")
        check(not a.cli("onboarding", "project", command, "--approve", "--stdin", input=json.dumps(body)).ok,
              "CLI accepted an approval shorthand")
    check(records(a) == before, "invalid CLI input changed durable state")
    check("onboarding" not in a.cli("--help").stdout and "onboarding" in a.cli("help", "advanced").stdout,
          "advanced CLI changed reduced root help")
    a.stop()
    before_files = file_state(a.root)
    lookup_context = {key: body[key] for key in ("project_root", "native_session_id", "integration")}
    for command in (("prepare",), ("inspect", flow["flow_id"]), ("decide",), ("lookup",)):
        flags = ["--stdin"] if command[0] != "inspect" else []
        private_input = payload if command[0] == "decide" else lookup_context if command[0] == "lookup" else body
        check(not a.cli("onboarding", "project", *command, *flags, input=json.dumps(private_input)).ok,
              "project CLI succeeded with stopped daemon")
    check(file_state(a.root) == before_files, "stopped-daemon CLI changed files")
    absent = suite.host("absent", start=False)
    shutil.rmtree(absent.state)
    before_files = file_state(absent.root)
    for command in (("prepare",), ("inspect", flow["flow_id"]), ("decide",), ("lookup",)):
        flags = ["--stdin"] if command[0] != "inspect" else []
        private_input = payload if command[0] == "decide" else lookup_context if command[0] == "lookup" else body
        check(not absent.cli("onboarding", "project", *command, *flags,
                             input=json.dumps(private_input)).ok,
              "project CLI succeeded with missing daemon")
    check(file_state(absent.root) == before_files and not absent.state.exists(), "missing-daemon CLI created state")


@suite.case("project_routes_stay_owner_local", "guided onboarding 3 verification 7")
def _():
    host, peer, bootstrap = suite.host("boundary-owner"), suite.host("boundary-peer"), suite.host("bootstrap-only")
    net = create_network(host, "project-boundary", "owner")
    join_new_person(host, peer, "peer", ssh_key(peer.root, "peer"), net["id"])
    flow = prepared(host, proposal("private-route"))
    other = prepared(bootstrap, proposal("bootstrap-private-route"))
    adapter = host.agent("boundary-fixture", ready=False)
    lookup_context = {key: flow["review"][key] for key in ("project_root", "native_session_id", "integration")}
    for method, path, body in (("GET", BASE + "/" + flow["flow_id"], None), ("POST", BASE + "/lookup", lookup_context),
                               ("POST", BASE, proposal("forbidden")),
                               ("POST", BASE + "/" + flow["flow_id"] + "/decision", decision(flow))):
        check(adapter.call(method, path, body)[0] == 404, "scoped adapter exposed private project route")
        args = [str(suite.probe_bin), "--state", str(peer.state), "--address", host.peer_address,
                "--alpn", "peerspan-peer/1", "--path", path, "--method", method]
        if body is not None:
            args += ["--body-stdin"]
        result = subprocess.run(args, input=(json.dumps(body) if body is not None else "").encode(), capture_output=True, timeout=15)
        check(json.loads(result.stdout).get("status") == 404, "authenticated peer exposed private project route")
    cert, key = suite.work / "project-cert.pem", suite.work / "project-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=project-boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True, timeout=5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    context.load_cert_chain(str(cert), str(key))
    context.set_alpn_protocols(["peerspan-bootstrap/1"])
    lookup_context = {key: other["review"][key] for key in ("project_root", "native_session_id", "integration")}
    for method, path, body in (("GET", BASE + "/" + other["flow_id"], None), ("POST", BASE + "/lookup", lookup_context),
                               ("POST", BASE, proposal("bootstrap-forbidden")),
                               ("POST", BASE + "/" + other["flow_id"] + "/decision", decision(other))):
        data = b"" if body is None else json.dumps(body).encode()
        with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname="peerspan") as stream:
                stream.sendall((f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\n"
                                f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data)
                response = http.client.HTTPResponse(stream)
                response.begin()
                response.read()
                check(response.status == 404, f"bootstrap private project route returned HTTP {response.status}, want 404")
    check(get(host, BASE + "/" + flow["flow_id"])["state"] == "review", "remote calls decided the private flow")
    assert_private(host, [flow])


def clone_state(source, name):
    target = suite.host(name, start=False)
    shutil.copytree(source.state, target.state, dirs_exist_ok=True)
    for socket_name in ("admin.sock", "adapter.sock"):
        (target.state / socket_name).unlink(missing_ok=True)
    return target


def refuse_start(host):
    before = records(host)
    with host.log.open("ab") as log:
        process = suite.spawn([str(suite.host_bin), "--state", str(host.state), "run"],
                              stdout=log, stderr=log, env=host.env)
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        code = None
    check(code not in (None, 0), "malformed/colliding/future schema was opened")
    check(records(host) == before, "refused schema changed database schema, version or logical records")


@suite.case("schema24_additive_migration_and_refusals", "guided onboarding 3 verification 8; spec 17/59")
def _():
    source = suite.host("migration-source")
    create_network(source, "preserved-network", "owner")
    status, agent = source.api("POST", "/v1/agents", {"name": "preserved-agent", "owner": "local owner"})
    check(status == 201, "migration registry fixture failed")
    status, session = source.api("POST", "/v1/sessions", {"agent_id": agent["id"], "integration": "metadata"})
    check(status == 201, "migration history fixture failed")
    check(source.api("POST", "/v1/sessions/" + session["id"] + "/detach", {})[0] == 200, "detach migration fixture")
    identity, activity = get(source, "/v1/host"), events(source)
    source.stop()
    baseline = records(source)
    with closing(sqlite3.connect(f"file:{db_path(source)}?mode=ro", uri=True)) as db:
        columns = list(db.execute("PRAGMA table_info(onboarding_project_flows)"))
        foreign = list(db.execute("PRAGMA foreign_key_list(onboarding_project_flows)"))
    check([row[1] for row in columns] == COLUMNS and all(row[2].upper() == "TEXT" for row in columns), "schema-24 flow columns/types")
    check([bool(row[3]) for row in columns] == [True] * 10 + [False, False] and columns[0][5] == 1,
          "schema-24 flow nullability/primary key")
    check(any(row[2:5] == ("sessions", "session_id", "id") for row in foreign), "flow outcome session foreign key")
    legacy = clone_state(source, "legacy23")
    with closing(sqlite3.connect(db_path(legacy))) as db, db:
        db.execute("DROP TABLE onboarding_adapter_flows")
        db.execute("DROP TABLE onboarding_project_flows")
        db.execute("PRAGMA user_version = 23")
    old = records(legacy)
    legacy.start()
    check(get(legacy, "/v1/host") == identity and events(legacy) == activity, "migration changed identity or activity")
    check(get(legacy, "/v1/agents/" + agent["id"]) == agent, "migration changed agent metadata")
    check(get(legacy, "/v1/sessions/" + session["id"])["state"] == "detached", "migration attached historical session")
    legacy.stop()
    migrated = records(legacy)
    check(migrated["$version"] == (25,) and migrated[TABLE] == () and migrated["onboarding_adapter_flows"] == (),
          "migration did not create empty schema-24/25 flow tables")
    check({key: value for key, value in migrated.items() if key not in ("$schema", "$version", TABLE, "onboarding_adapter_flows")}
          == {key: value for key, value in old.items() if key not in ("$schema", "$version")},
          "additive migration changed legacy registry/DEC logical records")
    check(migrated["$schema"] == baseline["$schema"], "additive migration changed existing table definitions")
    for kind, ddl in (("table", "CREATE TABLE onboarding_project_flows (marker TEXT)"),
                      ("view", "CREATE VIEW onboarding_project_flows AS SELECT 'reserved' AS marker"),
                      ("index", "CREATE INDEX onboarding_project_flows ON sessions(id)")):
        collision = clone_state(source, "collision-" + kind)
        with closing(sqlite3.connect(db_path(collision))) as db, db:
            db.execute("DROP TABLE onboarding_adapter_flows")
            db.execute("DROP TABLE onboarding_project_flows")
            db.execute("PRAGMA user_version = 23")
            db.execute(ddl)
        refuse_start(collision)
    for name, ddl in (("missing", "DROP TABLE onboarding_project_flows"),
                      ("extra-column", "ALTER TABLE onboarding_project_flows ADD COLUMN unexpected TEXT"),
                      ("renamed-column", "ALTER TABLE onboarding_project_flows RENAME COLUMN review_id TO wrong_review_id")):
        corrupt = clone_state(source, "corrupt-" + name)
        with closing(sqlite3.connect(db_path(corrupt))) as db, db:
            db.execute(ddl)
        refuse_start(corrupt)
    # Same column names/order still cannot hide changed types or constraints.
    for fault in ("wrong-type", "nullable-required", "missing-primary-key", "missing-foreign-key"):
        corrupt = clone_state(source, "corrupt-" + fault)
        definitions = []
        for index, column in enumerate(COLUMNS):
            definition = column + (" BLOB" if fault == "wrong-type" and column == "review" else " TEXT")
            if index < 10 and not (fault == "nullable-required" and column == "project_root"):
                definition += " NOT NULL"
            if index == 0 and fault != "missing-primary-key":
                definition += " PRIMARY KEY"
            if column == "session_id" and fault != "missing-foreign-key":
                definition += " REFERENCES sessions(id)"
            definitions.append(definition)
        with closing(sqlite3.connect(db_path(corrupt))) as db, db:
            db.execute("DROP TABLE onboarding_project_flows")
            db.execute("CREATE TABLE onboarding_project_flows (" + ",".join(definitions) + ")")
        refuse_start(corrupt)
    future = clone_state(source, "future26")
    with closing(sqlite3.connect(db_path(future))) as db, db:
        db.execute("PRAGMA user_version = 26")
    refuse_start(future)


suite.finish()
