#!/usr/bin/env python3
"""Exact guided adapter authorization, from guided-session-contract.md section 5.

Real temporary hosts and public owner/scoped/peer interfaces establish all
attachments, credentials, conflicts and revocations. Read-only SQLite checks
observe persistence; only stopped-host migration/collision fixtures edit schema.
No protocol records, authority or credentials are fabricated. These checks prove
neither a native human callback nor model receipt or complete adapter delivery.
The private host-seed format and unavailable scope-edit APIs are outside scope.
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
from datetime import datetime, timedelta, timezone

from harness import Adapter, Suite, UnixHTTPConnection, check, create_network, parse_time, rfc3339

suite = Suite("adapter_onboarding", __doc__)
suite.use_clock()
BASE = "/v1/onboarding/adapter-flows"
PROJECT = "/v1/onboarding/project-flows"
TABLE = "onboarding_adapter_flows"
TOP = {"version", "flow_id", "state", "review_id", "review", "authorization", "connection", "next_action"}
CONTEXT = {"project_flow_id", "project_review_id", "project_root", "native_session_id", "integration"}
REVIEW = {"version", "kind", "flow_id", "host_id", *CONTEXT, "agent", "session_id", "adapter_id", "expires_at",
          "credential_expires_at", "renewable", "effects"}
EFFECTS = {"issue_adapter_credential": True, "receive_authorized_work": True, "reply_to_authorized_work": True,
           "handle_authorized_tasks": True, "task_artifacts": True, "register_agent": False, "attach_session": False,
           "grant_network_access": False, "directory_access": False, "outbound_routes": False,
           "capability_calls": False, "share_files": False, "share_conversation": False}
COLUMNS = ["flow_id", "project_flow_id", "request", "review", "review_id", "state", "created_at", "expires_at",
           "adapter_id", "decided_at"]
WORK = ("/adapter/v1/next", "/adapter/v1/tasks/next", "/adapter/v1/tasks/cancels/next",
        "/adapter/v1/task-updates/next", "/adapter/v1/replies/next")


def get(host, path):
    status, value = host.api("GET", path, timeout=10)
    check(status == 200, f"{host.name} owner observation: HTTP {status}")
    return value


def events(host):
    return get(host, "/v1/activity?limit=1000")


def db_path(host):
    matches = []
    for path in sorted(host.state.glob("*.db")):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                matches.append(path)
    check(len(matches) == 1, "expected one real host database")
    return matches[0]


def records(host):
    with closing(sqlite3.connect(f"file:{db_path(host)}?mode=ro", uri=True, timeout=5)) as db, db:
        db.execute("BEGIN")
        result = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                  "$version": db.execute("PRAGMA user_version").fetchone()}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            quoted = '"' + name.replace('"', '""') + '"'
            result[name] = tuple(sorted(db.execute(f"SELECT * FROM {quoted}"), key=repr))
        return result


def without(value, *keys):
    return {key: item for key, item in value.items() if key not in keys}


def file_state(root):
    if not root.exists():
        return None
    return {str(p.relative_to(root)): (p.lstat().st_mode, p.lstat().st_mtime_ns,
            os.readlink(p) if p.is_symlink() else hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
            for p in [root, *sorted(root.rglob("*"))]}


def parallel(call, count=4):
    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(lambda _: call(), range(count)))


def raw_post(host, path, data):
    conn = UnixHTTPConnection(str(host.state / "admin.sock"), timeout=10)
    try:
        conn.request("POST", path, body=data, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def advance_to(moment):
    suite.set_offset(math.ceil((moment - datetime.now(timezone.utc)).total_seconds()))


def project(host, label, *, agent=None, approve=True, native=None, root=None):
    body = {"project_root": root or str(suite.work / "private projects" / label),
            "native_session_id": native or "private-native-" + label, "integration": "claude-code",
            "agent": {"kind": "existing", "id": agent["id"]} if agent else
                     {"kind": "new", "name": "agent-" + label, "owner": "local owner 東京"}}
    status, flow = host.api("POST", PROJECT, body)
    check(status == 201, f"project fixture prepare: HTTP {status}")
    if approve:
        decision = {key: body[key] for key in ("project_root", "native_session_id", "integration")}
        status, flow = host.api("POST", PROJECT + "/" + flow["flow_id"] + "/decision",
                                {**decision, "review_id": flow["review_id"], "decision": "approve"})
        check(status == 200 and flow["state"] == "attached", "project fixture did not attach exact metadata")
    return flow


def context(project_flow):
    return {"project_flow_id": project_flow["flow_id"], "project_review_id": project_flow["review_id"],
            **{key: project_flow["review"][key] for key in ("project_root", "native_session_id", "integration")}}


def validate(host, project_flow, flow):
    check(isinstance(flow, dict) and set(flow) == TOP and type(flow["version"]) is int and flow["version"] == 1,
          "adapter flow response shape/version")
    review = flow["review"]
    check(isinstance(review, dict) and set(review) == REVIEW, "adapter immutable review shape")
    check(re.fullmatch(r"flow_[0-9a-f]{32}", flow["flow_id"]) is not None
          and re.fullmatch(r"adapter_[0-9a-f]{32}", review["adapter_id"]) is not None,
          "planned adapter/flow ID format")
    check(review["version"] == 1 and review["kind"] == "authorize_adapter"
          and review["flow_id"] == flow["flow_id"] and review["host_id"] == host.id, "adapter review identity")
    check({key: review[key] for key in CONTEXT} == context(project_flow), "adapter review changed project context")
    check(review["agent"] == project_flow["review"]["agent"] and review["session_id"] == project_flow["review"]["session_id"],
          "adapter review changed its selected agent or attached session")
    check(review["effects"] == EFFECTS and all(type(value) is bool for value in review["effects"].values())
          and review["renewable"] is False, "adapter review widened scope or promised renewal")
    for field in ("expires_at", "credential_expires_at"):
        check(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", review[field]) is not None, "deadline must be whole-second UTC")
    check(parse_time(review["credential_expires_at"]) - parse_time(review["expires_at"]) == timedelta(hours=23, minutes=45),
          "review and credential deadlines do not share fixed preparation time")
    canonical = json.dumps(review, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    check(flow["review_id"] == "review_" + hashlib.sha256(b"peerspan-adapter-review-v1\n" + canonical).hexdigest(),
          "adapter digest does not bind all canonical UTF-8 review terms")
    next_action = {"review": "review", "authorized": "connect_adapter", "declined": "restart_review",
                   "expired": "restart_review", "invalidated": "restart_review"}
    check(flow["state"] in next_action and flow["next_action"] == next_action[flow["state"]], "adapter state/next action")
    if flow["authorization"] is None:
        check(flow["connection"] is None and flow["state"] != "authorized", "unissued flow claimed a connection")
    else:
        check(flow["authorization"] == {"adapter_id": review["adapter_id"], "session_id": review["session_id"],
              "agent_id": review["agent"]["id"], "expires_at": review["credential_expires_at"], "renewable": False},
              "authorization does not retain exact issued bindings")
        check(flow["connection"] == get(host, "/v1/adapters/" + review["adapter_id"] + "/connection"),
              "flow connection differs from the ordinary adapter view")
    check("token_" not in json.dumps(flow) and "token_hash" not in json.dumps(flow)
          and "instance_" not in json.dumps(flow), "ordinary adapter flow exposes a secret/digest")


def prepare(host, project_flow, *, replace=None, status=201):
    body = {"context": context(project_flow)}
    if replace is not None:
        body["replace_flow_id"] = replace
    actual, flow = host.api("POST", BASE, body)
    check(actual == status, f"adapter prepare: HTTP {actual}, want {status}")
    validate(host, project_flow, flow)
    return flow


def decision(flow, choice="approve"):
    return {"context": {key: flow["review"][key] for key in CONTEXT}, "review_id": flow["review_id"], "decision": choice}


def decide(host, flow, choice="approve", *, status=200, code=None, body=None):
    actual, result = host.api("POST", BASE + "/" + flow["flow_id"] + "/decision",
                              body if body is not None else decision(flow, choice))
    check(actual == status, f"adapter decision: HTTP {actual}, want {status}")
    if code:
        check(result.get("code") == code, f"adapter decision did not return {code}")
    if status == 200:
        check(set(result) == TOP and result["review"] == flow["review"] and result["review_id"] == flow["review_id"],
              "adapter decision changed immutable terms")
        check("token_" not in json.dumps(result) and "token_hash" not in json.dumps(result), "decision exposed credential material")
    return result


def credential(host, flow, *, status=200, code=None, body=None):
    payload = {key: value for key, value in decision(flow).items() if key != "decision"}
    actual, value = host.api("POST", BASE + "/" + flow["flow_id"] + "/credential", body if body is not None else payload)
    check(actual == status, f"private credential retrieval: HTTP {actual}, want {status}")
    if code:
        check(value.get("code") == code, f"credential retrieval did not return {code}")
    if status == 200:
        check(set(value) == {"version", "adapter_id", "session_id", "token"} and value["version"] == 1,
              "private credential response shape")
        check(value["adapter_id"] == flow["review"]["adapter_id"] and value["session_id"] == flow["review"]["session_id"]
              and re.fullmatch(r"token_[0-9a-f]{64}", value["token"]) is not None, "retrieval changed planned credential bindings")
    else:
        check("token_" not in json.dumps(value), "refused credential retrieval exposed a secret")
    return value


def observe(host, project_flow, expected):
    before = records(host)
    status, value = host.api("POST", BASE + "/lookup", context(project_flow))
    check(status == 200 and set(value) == {"version", "host_id", "context", "flow"}
          and value["version"] == 1 and value["host_id"] == host.id
          and value["context"] == context(project_flow) and value["flow"] == expected, "lookup latest exact context/flow")
    if expected is not None:
        inspected = get(host, BASE + "/" + expected["flow_id"])
        check(inspected == expected, "inspect and lookup disagree")
        validate(host, project_flow, inspected)
    check(records(host) == before, "lookup/inspection changed logical state, credentials, deadlines or activity")
    return value


def approved(host, label):
    attached = project(host, label)
    flow = prepare(host, attached)
    flow = decide(host, flow)
    check(flow["state"] == "authorized", "approval did not authorize")
    return attached, flow


def fixture_adapter(host, flow, secret):
    return Adapter(host, flow["review"]["agent"], flow["review"]["session_id"],
                   {"adapter": {"id": flow["review"]["adapter_id"]}, "token": secret["token"]})


def connect(adapter):
    status, _ = adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id,
                              "session_id": adapter.session_id, "instance_id": adapter.instance})
    check(status == 200, f"guided credential failed ordinary scoped connect: HTTP {status}")


@suite.case("exact_preparation_and_strict_validation", "guided onboarding 5 verification 1/2")
def _():
    host = suite.host("prepare")
    attached = project(host, "exact-é")
    observe(host, attached, None)
    before = records(host)
    earliest = host.now().replace(microsecond=0)
    flow = prepare(host, attached)
    latest = host.now().replace(microsecond=0)
    check(earliest + timedelta(minutes=15) <= parse_time(flow["review"]["expires_at"]) <= latest + timedelta(minutes=15),
          "review deadline is not fixed at preparation plus 15 minutes")
    check(without(records(host), TABLE) == without(before, TABLE) and len(records(host)[TABLE]) == 1,
          "preparation changed records outside its single private row")
    check(flow["state"] == "review" and flow["authorization"] is None, "prepare issued credential authority")
    for resumed in parallel(lambda: prepare(host, attached, status=200)):
        check(resumed == flow, "concurrent identical prepare changed terms, IDs or deadlines")
    observe(host, attached, flow)
    before = records(host)
    ctx = context(attached)
    invalid = [None, {}, {"context": None}, {"context": ctx, "extra": True}, {"context": ctx, "replace_flow_id": None}]
    for field, value in (("project_flow_id", "flow_bad"), ("project_review_id", "review_bad"),
                         ("project_root", "relative"), ("native_session_id", "has space"), ("integration", "opencode")):
        invalid.append({"context": {**ctx, field: value}})
    invalid += [{"context": without(ctx, "project_review_id")}, {"context": {**ctx, "unknown": True}}]
    for body in invalid:
        status, error = host.api("POST", BASE, body)
        check(status == 400, "prepare accepted missing/extra/null/malformed terms")
        if isinstance(body, dict) and isinstance(body.get("context"), dict) and body["context"] != ctx:
            check(error.get("code") == "invalid_request", "malformed context did not return invalid_request")
    for path in (BASE, BASE + "/lookup", BASE + "/" + flow["flow_id"] + "/decision", BASE + "/" + flow["flow_id"] + "/credential"):
        for data in (b"null", b'{"context":', b"{} {}", b"\xff"):
            check(raw_post(host, path, data) == 400, "adapter route accepted malformed/nonobject JSON")
    for changed in ({**ctx, "project_root": "/other/absolute"}, {**ctx, "project_review_id": "review_" + "f" * 64}):
        status, error = host.api("POST", BASE, {"context": changed})
        check(status == 409 and error.get("code") == "review_changed", "prepare accepted wrong exact project context")
    unknown = {**ctx, "project_flow_id": "flow_" + "f" * 32}
    check(host.api("POST", BASE, {"context": unknown})[0] == 404, "unknown project did not return 404")
    check(host.api("POST", BASE + "/lookup", unknown)[0] == 404, "lookup accepted an unknown project")
    unknown_flow = {**flow, "flow_id": "flow_" + "f" * 32}
    check(host.api("GET", BASE + "/" + unknown_flow["flow_id"])[0] == 404, "unknown adapter inspection was not 404")
    decide(host, unknown_flow, status=404)
    credential(host, unknown_flow, status=404)
    check(records(host) == before, "rejected prepares changed durable state")
    simultaneous = project(host, "concurrent-first-prepare")
    before = records(host)
    results = parallel(lambda: host.api("POST", BASE, {"context": context(simultaneous)}))
    check(sum(status == 201 for status, _ in results) == 1 and all(status in (200, 201) for status, _ in results),
          "concurrent first prepare did not create exactly one attempt")
    check(all(value == results[0][1] for _, value in results), "concurrent first prepares returned different immutable reviews")
    validate(host, simultaneous, results[0][1])
    after = records(host)
    check(len(after[TABLE]) == len(before[TABLE]) + 1 and without(after, TABLE) == without(before, TABLE),
          "concurrent first prepare created duplicate rows or other effects")
    pending = project(host, "unattached", approve=False)
    before = records(host)
    status, error = host.api("POST", BASE, {"context": context(pending)})
    check(status == 409 and error.get("code") == "flow_conflict", "unattached project authorized an adapter review")
    check(records(host) == before, "ineligible project prepare wrote records")
    credential(host, flow, status=409, code="flow_conflict")


@suite.case("retained_outcomes_and_read_only_restart", "guided onboarding 5 verification 2")
def _():
    host = suite.host("restart")
    fixtures = []
    for state in ("review", "declined", "authorized"):
        attached = project(host, "restart-" + state)
        flow = prepare(host, attached)
        if state != "review":
            flow = decide(host, flow, "decline" if state == "declined" else "approve")
        observe(host, attached, flow)
        fixtures.append((attached, flow))
    agents = get(host, "/v1/agents")
    host.restart()
    check(get(host, "/v1/agents") == agents, "restart changed registered agents")
    before = records(host)
    for attached, old in fixtures:
        resumed = prepare(host, attached, status=200)
        check(resumed["review"] == old["review"] and resumed["review_id"] == old["review_id"]
              and resumed["authorization"] == old["authorization"], "restart changed retained adapter terms/outcome IDs")
        check(resumed["state"] == ("declined" if old["state"] == "declined" else "invalidated"),
              "restart silently restored detached project authority")
        observe(host, attached, resumed)
        credential(host, resumed, status=409, code="flow_conflict")
        if old["state"] != "declined":
            decide(host, old, status=409, code="flow_conflict")
        check(get(host, "/v1/sessions/" + old["review"]["session_id"])["state"] == "detached", "restart replay reattached a session")
    check(records(host) == before, "retained restart reads/replays changed consent or registry records")


@suite.case("approval_secret_recovery_and_scoped_handshake", "guided onboarding 5 verification 3/4")
def _():
    host = suite.host("approve")
    attached = project(host, "approved")
    flow = prepare(host, attached)
    agents, sessions, activity = get(host, "/v1/agents"), get(host, "/v1/sessions"), events(host)
    session_records = records(host)["sessions"]
    results = parallel(lambda: decide(host, flow))
    check(all(value == results[0] for value in results) and results[0]["state"] == "authorized", "concurrent approval was not idempotent")
    issued = results[0]
    validate(host, attached, issued)
    check(get(host, "/v1/agents") == agents and records(host)["sessions"] == session_records
          and {s["id"] for s in get(host, "/v1/sessions")} == {s["id"] for s in sessions},
          "adapter approval created/changed agent or session metadata")
    delta = events(host)[len(activity):]
    check(len(delta) == 1 and delta[0]["kind"] == "adapter.created" and delta[0]["subject_id"] == flow["review"]["adapter_id"],
          "approval did not append exactly one normal adapter.created event")
    adapters = host.ok("adapter", "list")
    check(len(adapters) == 1, "approval created duplicate credentials")
    record = host.ok("adapter", "inspect", issued["review"]["adapter_id"])
    check(record["id"] == issued["review"]["adapter_id"] and record["session_id"] == issued["review"]["session_id"]
          and record["expires_at"] == issued["review"]["credential_expires_at"] and record["renewable"] is False
          and record["directory"] is False and record["calls"] is False, "issued normal credential has widened/changed scope")
    check(host.ok("adapter", "route", "list", "--adapter", record["id"]) == [], "guided approval created an outbound route")
    observe(host, attached, issued)
    before = records(host)
    secret = credential(host, issued)
    check(all(value == secret for value in parallel(lambda: credential(host, issued))), "private retrieval retry changed the credential")
    check(records(host) == before, "private retrieval wrote records or activity")
    check(host.api("POST", "/v1/adapters/" + record["id"] + "/verify-credential", {"token": secret["token"]}) == (200, {"matches": True}),
          "recovered token does not match the normal credential")
    with closing(sqlite3.connect(f"file:{db_path(host)}?mode=ro", uri=True)) as db:
        digest = db.execute("SELECT token_hash FROM adapter_credentials WHERE id=?", (record["id"],)).fetchone()[0]
    check(digest == hashlib.sha256(secret["token"].encode()).hexdigest() and secret["token"] not in repr(records(host)),
          "credential persistence is not SHA256-only")
    for path in [host.log, *host.state.rglob("*")]:
        if path.is_file():
            check(secret["token"].encode() not in path.read_bytes(), "plaintext recovered token was persisted or logged")
    for view in (get(host, "/v1/onboarding"), get(host, "/v1/status"), adapters, record, issued):
        check(secret["token"] not in json.dumps(view) and "token_hash" not in json.dumps(view), "ordinary view exposed credential material")
    for path in ("/v1/onboarding", "/v1/status"):
        public = json.dumps(get(host, path))
        for private in (flow["flow_id"], flow["review_id"], attached["flow_id"], attached["review_id"],
                        flow["review"]["project_root"], flow["review"]["native_session_id"]):
            check(private not in public, "ordinary observation exposed private guided flow context")
    adapter = fixture_adapter(host, issued, secret)
    connect(adapter)
    for route in WORK:
        status, error = adapter.post(route)
        check(status == 409 and error.get("error") == "channel not verified", "guided issuance bypassed channel handshake")
    check(adapter.call("GET", "/v1/host")[0] == 404, "scoped credential reached owner administration")
    for method, path, body, code in (("GET", "/adapter/v1/agents", None, "no_directory"),
                                    ("POST", "/adapter/v1/send", {"to": "someone/agent", "request_id": "req_" + "1" * 32, "content": "private"}, "no_directory"),
                                    ("POST", "/adapter/v1/calls", {"call_id": "call_" + "1" * 32, "address": "someone/capability", "operation": "echo", "input": {}}, "no_calls")):
        status, error = adapter.call(method, path, body)
        check(status == 403 and error.get("code") == code, "guided credential escaped its reviewed scope")
    adapter.ready()
    check(adapter.post("/adapter/v1/next") == (200, None), "normal ready handshake did not open empty work polling")


@suite.case("exact_decisions_decline_and_explicit_replacement", "guided onboarding 5 verification 3/5")
def _():
    host = suite.host("decisions")
    attached = project(host, "decisions")
    flow = prepare(host, attached)
    before = records(host)
    for body in ({**decision(flow), "review_id": "review_" + "f" * 64},
                 {**decision(flow), "context": {**context(attached), "native_session_id": "different-native"}}):
        decide(host, flow, body=body, status=409, code="review_changed")
        credential(host, flow, body=without(body, "decision"), status=409, code="review_changed")
    for body in ({**decision(flow), "decision": "maybe"}, {**decision(flow), "extra": True},
                 {**decision(flow), "context": None}, without(decision(flow), "review_id")):
        decide(host, flow, body=body, status=400)
    credential(host, flow, body={**without(decision(flow), "decision"), "extra": True}, status=400)
    check(records(host) == before, "refused owner decisions/retrieval changed records")
    declined = parallel(lambda: decide(host, flow, "decline"))
    check(all(value == declined[0] for value in declined) and declined[0]["state"] == "declined", "decline retry changed its result")
    check(without(records(host), TABLE) == without(before, TABLE), "decline created activity/credential/registry effects")
    observe(host, attached, declined[0])
    check(prepare(host, attached, status=200) == declined[0], "ordinary resume silently replaced a declined review")
    decide(host, flow, status=409, code="flow_conflict")
    credential(host, flow, status=409, code="flow_conflict")
    fresh = prepare(host, attached, replace=flow["flow_id"])
    check(fresh["flow_id"] != flow["flow_id"] and fresh["review"]["adapter_id"] != flow["review"]["adapter_id"], "explicit replacement reused planned IDs")
    check(get(host, BASE + "/" + flow["flow_id"]) == declined[0], "replacement changed prior outcome")
    before = records(host)
    check(host.api("POST", BASE, {"context": context(attached), "replace_flow_id": flow["flow_id"]})[0] == 409,
          "stale replacement ID replaced the current attempt")
    decide(host, flow, "decline", status=409, code="flow_conflict")
    credential(host, flow, status=409, code="flow_conflict")
    check(host.api("POST", BASE, {"context": context(attached), "replace_flow_id": fresh["flow_id"]})[0] == 409,
          "reviewable attempt was replaced")
    check(records(host) == before, "obsolete callbacks/replacements changed records")


@suite.case("review_and_credential_deadlines_are_independent", "guided onboarding 5 verification 3/5")
def _():
    host = suite.host("expiry")
    attached = project(host, "expiry")
    pending = prepare(host, attached)
    advance_to(parse_time(pending["review"]["expires_at"]) - timedelta(seconds=2))
    check(get(host, BASE + "/" + pending["flow_id"])["state"] == "review", "review expired before its fixed deadline")
    advance_to(parse_time(pending["review"]["expires_at"]))
    expired = get(host, BASE + "/" + pending["flow_id"])
    check(expired["state"] == "expired", "review remained actionable at its deadline")
    observe(host, attached, expired)
    before = records(host)
    decide(host, pending, status=409, code="review_expired")
    credential(host, pending, status=409, code="flow_conflict")
    check(records(host) == before, "expired review refusal wrote state")
    flow = prepare(host, attached, replace=pending["flow_id"])
    authorized = decide(host, flow)
    secret = credential(host, authorized)
    advance_to(parse_time(flow["review"]["expires_at"]) + timedelta(seconds=1))
    check(decide(host, flow) == authorized and credential(host, flow) == secret, "old review deadline invalidated a current issued credential")
    advance_to(parse_time(flow["review"]["credential_expires_at"]))
    expired = get(host, BASE + "/" + flow["flow_id"])
    check(expired["state"] == "expired" and expired["authorization"] == authorized["authorization"], "credential expiry lost outcome bindings")
    observe(host, attached, expired)
    before = records(host)
    credential(host, flow, status=409, code="flow_conflict")
    decide(host, flow, status=409)
    check(records(host) == before, "expired authorization was renewed or revived")


@suite.case("existing_unbound_live_offline_and_recoverable_adapters_are_never_taken_over", "guided onboarding 5 verification 5")
def _():
    host = suite.host("conflicts")
    attached = project(host, "conflicts")
    agent = get(host, "/v1/agents/" + attached["review"]["agent"]["id"])
    session = host.ok("session", "attach", "--agent", agent["id"], "--integration", "fixture")
    old = host.ok("adapter", "create", "--session", session["id"], "--expires-at", rfc3339(host.now() + timedelta(hours=2)))
    adapter = Adapter(host, agent, session["id"], old)

    def refused(project_flow):
        before = records(host)
        status, error = host.api("POST", BASE, {"context": context(project_flow)})
        check(status == 409 and error.get("code") == "flow_conflict", "guided prepare took over a conflicting adapter")
        check(records(host) == before, "guided conflict revoked/replaced/detached the existing authorization")
        check(host.ok("adapter", "inspect", old["adapter"]["id"]) == old["adapter"], "guided conflict changed existing credential scope")

    refused(attached)  # unbound setup
    connect(adapter)
    refused(attached)  # live lease
    suite.set_offset(suite.offset + 17)
    check(get(host, "/v1/adapters/" + adapter.adapter_id + "/connection")["state"] == "offline", "offline fixture still has a lease")
    refused(attached)  # normal advanced issuance could replace this; guided cannot
    host.restart()
    fresh_project = project(host, "recoverable-reservation", agent=agent)
    refused(fresh_project)  # a different attached project cannot take its recovery reservation


@suite.case("conflicts_after_prepare_and_public_credential_changes_invalidate_without_repair", "guided onboarding 5 verification 3/5")
def _():
    host = suite.host("invalidation")
    attached = project(host, "late-conflict")
    pending = prepare(host, attached)
    ordinary = host.ok("adapter", "create", "--session", attached["review"]["session_id"],
                       "--expires-at", rfc3339(host.now() + timedelta(hours=2)))
    invalid = get(host, BASE + "/" + pending["flow_id"])
    check(invalid["state"] == "invalidated", "new competing authorization did not invalidate a pending review")
    before = records(host)
    decide(host, pending, status=409, code="flow_conflict")
    credential(host, pending, status=409, code="flow_conflict")
    observe(host, attached, invalid)
    check(records(host) == before and host.ok("adapter", "inspect", ordinary["adapter"]["id"]) == ordinary["adapter"],
          "late conflict changed/replaced the competing authorization")
    for mutation in ("revoke", "detach", "rotate"):
        attached, flow = approved(host, "changed-" + mutation)
        first = credential(host, flow)
        if mutation == "detach":
            host.ok("session", "detach", flow["review"]["session_id"])
        else:
            host.ok("adapter", mutation, flow["review"]["adapter_id"])
        invalid = get(host, BASE + "/" + flow["flow_id"])
        check(invalid["state"] == "invalidated" and invalid["authorization"] == flow["authorization"], "credential change lost invalidated outcome")
        observe(host, attached, invalid)
        before = records(host)
        credential(host, flow, status=409, code="flow_conflict")
        decide(host, flow, status=409, code="flow_conflict")
        check(records(host) == before, "invalidated approval/retrieval revived or repaired a credential")
        if mutation == "revoke":
            fresh = prepare(host, attached, replace=flow["flow_id"])
            second = credential(host, decide(host, fresh))
            check(second["token"] != first["token"] and second["adapter_id"] != first["adapter_id"], "different flow reused a revoked token/ID")
            credential(host, flow, status=409, code="flow_conflict")
            decide(host, flow, status=409, code="flow_conflict")
            check(get(host, BASE + "/" + flow["flow_id"])["authorization"] == flow["authorization"], "new attempt rewrote old authorization evidence")


@suite.case("stdin_cli_parity_bounds_and_inert_daemon_failures", "guided onboarding 5 verification 6")
def _():
    host = suite.host("cli")
    attached = project(host, "cli-private")
    ctx = context(attached)
    looked = host.cli("onboarding", "adapter", "lookup", "--stdin", input=json.dumps(ctx))
    check(looked.ok and looked.json == observe(host, attached, None), "lookup CLI/API differ")
    result = host.cli("onboarding", "adapter", "prepare", "--stdin", input=json.dumps({"context": ctx}))
    check(result.ok, "adapter prepare CLI failed")
    flow = result.json
    validate(host, attached, flow)
    check(host.ok("onboarding", "adapter", "inspect", flow["flow_id"]) == flow, "inspect CLI/API differ")
    payload = {"flow_id": flow["flow_id"], **decision(flow)}
    result = host.cli("onboarding", "adapter", "decide", "--stdin", input=json.dumps(payload))
    check(result.ok and result.json["state"] == "authorized" and "token_" not in result.stdout + result.stderr, "decision CLI exposed a token or failed")
    private_payload = without(payload, "decision")
    result = host.cli("onboarding", "adapter", "credential", "--stdin", input=json.dumps(private_payload))
    check(result.ok and result.json == credential(host, flow), "explicit private credential CLI/API differ")
    token = result.json["token"]
    before = records(host)
    inputs = {"prepare": {"context": ctx}, "lookup": ctx, "decide": payload, "credential": private_payload}
    for command, body in inputs.items():
        encoded = json.dumps(body)
        for data in ('{"private":', json.dumps({**body, "unknown": "private-extra-marker"}),
                     " " * (65537 - len(encoded.encode())) + encoded):
            failed = host.cli("onboarding", "adapter", command, "--stdin", input=data)
            check(not failed.ok, "adapter CLI accepted malformed/extra/oversized stdin")
            for private in (ctx["project_root"], ctx["native_session_id"], "private-extra-marker", token):
                check(private not in failed.stdout + failed.stderr, "controlled CLI error echoed private input/token")
        check(not host.cli("onboarding", "adapter", command, input=encoded).ok, "adapter CLI implicitly read stdin")
    check(records(host) == before, "rejected CLI input changed state")
    host.stop()
    for stopped in (host, suite.host("absent", start=False)):
        if stopped is not host:
            shutil.rmtree(stopped.state)
        before_files = file_state(stopped.root)
        for command, body in inputs.items():
            result = stopped.cli("onboarding", "adapter", command, "--stdin", input=json.dumps(body))
            check(not result.ok and token not in result.stdout + result.stderr, "unavailable daemon CLI succeeded or leaked a secret")
        check(not stopped.cli("onboarding", "adapter", "inspect", flow["flow_id"]).ok, "unavailable inspect succeeded")
        check(file_state(stopped.root) == before_files, "unavailable adapter CLI changed or created state")


@suite.case("owner_router_boundaries_and_owner_added_route_invalidation", "guided onboarding 5 verification 5/6")
def _():
    host, peer, bootstrap = suite.host("boundary-owner"), suite.host("registered-peer"), suite.host("bootstrap-only")
    for local, remote in ((host, peer), (peer, host)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    attached, flow = approved(host, "boundary")
    secret = credential(host, flow)
    adapter = fixture_adapter(host, flow, secret)
    connect(adapter)

    def routes(project_flow, adapter_flow):
        return (("GET", BASE + "/" + adapter_flow["flow_id"], None), ("POST", BASE, {"context": context(project_flow)}),
                ("POST", BASE + "/lookup", context(project_flow)),
                ("POST", BASE + "/" + adapter_flow["flow_id"] + "/decision", decision(adapter_flow)),
                ("POST", BASE + "/" + adapter_flow["flow_id"] + "/credential", without(decision(adapter_flow), "decision")))

    for method, path, body in routes(attached, flow):
        check(adapter.call(method, path, body)[0] == 404, "scoped router exposed private adapter onboarding")
        args = [str(suite.probe_bin), "--state", str(peer.state), "--address", host.peer_address,
                "--alpn", "peerspan-peer/1", "--method", method, "--path", path]
        if body is not None:
            args.append("--body-stdin")
        result = subprocess.run(args, input=(json.dumps(body) if body is not None else "").encode(), capture_output=True, timeout=15)
        check(result.returncode == 0 and json.loads(result.stdout).get("status") == 404, "authenticated peer exposed private adapter onboarding")
    # A quiescent host has no pending mailboxes consuming its source-rate budget.
    cert, key = suite.work / "adapter-boundary-cert.pem", suite.work / "adapter-boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=adapter-boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key))
    tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    bootstrap_project, bootstrap_flow = approved(bootstrap, "bootstrap-boundary")
    for method, path, body in routes(bootstrap_project, bootstrap_flow):
        data = b"" if body is None else json.dumps(body).encode()
        with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname="peerspan") as stream:
                stream.sendall((f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\n"
                                f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data)
                response = http.client.HTTPResponse(stream)
                response.begin()
                response.read()
                check(response.status == 404, f"bootstrap adapter onboarding returned HTTP {response.status}, want 404")
    status, target = peer.api("POST", "/v1/agents", {"name": "route-target", "owner": "peer owner"})
    check(status == 201, "real route-target fixture failed")
    expiry = rfc3339(host.now() + timedelta(minutes=30))
    grant = peer.ok("grant", "create", "--peer", host.id, "--agent", target["id"], "--expires-at", expiry, "--allow-disconnected")
    host.ok("adapter", "route", "add", "--adapter", adapter.adapter_id, "--name", "explicit-owner-route",
            "--peer", peer.id, "--agent", target["id"], "--grant", grant["id"], "--expires-at", expiry)
    invalid = get(host, BASE + "/" + flow["flow_id"])
    check(invalid["state"] == "invalidated" and invalid["authorization"] == flow["authorization"], "added route did not invalidate exact no-route terms")
    observe(host, attached, invalid)
    before = records(host)
    credential(host, flow, status=409, code="flow_conflict")
    decide(host, flow, status=409, code="flow_conflict")
    check(records(host) == before, "changed-route reads silently repaired or revoked authorization")


def clone_state(source, name):
    target = suite.host(name, start=False)
    shutil.copytree(source.state, target.state, dirs_exist_ok=True)
    for socket_name in ("admin.sock", "adapter.sock"):
        (target.state / socket_name).unlink(missing_ok=True)
    return target


def refuse_start(host):
    before = records(host)
    with host.log.open("ab") as log:
        process = suite.spawn([str(suite.host_bin), "--state", str(host.state), "run"], stdout=log, stderr=log, env=host.env)
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        code = None
    check(code not in (None, 0), "malformed/colliding/future adapter schema was opened")
    check(records(host) == before, "refused adapter migration changed schema, version or logical records")


@suite.case("schema25_additive_migration_collision_corruption_and_future_refusal", "guided onboarding 5 verification 7")
def _():
    source = suite.host("migration-source")
    create_network(source, "preserved-dec-network", "owner")
    attached = project(source, "preserved-project")
    source.ok("session", "detach", attached["review"]["session_id"])
    pending = project(source, "preserved-pending-project", approve=False)
    identity, activity = get(source, "/v1/host"), events(source)
    source.stop()
    baseline = records(source)
    with closing(sqlite3.connect(f"file:{db_path(source)}?mode=ro", uri=True)) as db:
        columns = list(db.execute("PRAGMA table_info(onboarding_adapter_flows)"))
        foreign = list(db.execute("PRAGMA foreign_key_list(onboarding_adapter_flows)"))
    check([row[1] for row in columns] == COLUMNS and all(row[2].upper() == "TEXT" for row in columns), "schema25 adapter table columns/types")
    check([bool(row[3]) for row in columns] == [True] * 8 + [False, False] and columns[0][5] == 1, "schema25 nullability/primary key")
    check(any(row[2:5] == ("onboarding_project_flows", "project_flow_id", "flow_id") for row in foreign)
          and any(row[2:5] == ("adapter_credentials", "adapter_id", "id") for row in foreign), "schema25 adapter foreign keys")
    legacy = clone_state(source, "legacy24")
    with closing(sqlite3.connect(db_path(legacy))) as db, db:
        db.execute("DROP TABLE onboarding_adapter_flows")
        db.execute("PRAGMA user_version = 24")
    old = records(legacy)
    legacy.start()
    check(get(legacy, "/v1/host") == identity and events(legacy) == activity, "migration changed identity/activity")
    check(get(legacy, PROJECT + "/" + pending["flow_id"]) == pending, "migration changed pending project review")
    check(get(legacy, PROJECT + "/" + attached["flow_id"])["state"] == "invalidated"
          and get(legacy, "/v1/sessions/" + attached["review"]["session_id"])["state"] == "detached", "migration resurrected historical attachment")
    legacy.stop()
    migrated = records(legacy)
    check(migrated["$version"] == (25,) and migrated[TABLE] == (), "migration did not add empty schema25 table")
    check(without(migrated, "$schema", "$version", TABLE) == without(old, "$schema", "$version"),
          "schema24 migration changed project/DEC/registry/history records")
    check(migrated["$schema"] == baseline["$schema"], "schema24 migration changed old table definitions")
    for kind, ddl in (("table", "CREATE TABLE onboarding_adapter_flows (marker TEXT)"),
                      ("view", "CREATE VIEW onboarding_adapter_flows AS SELECT 'reserved' AS marker"),
                      ("index", "CREATE INDEX onboarding_adapter_flows ON sessions(id)"),
                      ("trigger", "CREATE TRIGGER onboarding_adapter_flows AFTER INSERT ON sessions BEGIN SELECT 1; END")):
        collision = clone_state(source, "collision-" + kind)
        with closing(sqlite3.connect(db_path(collision))) as db, db:
            db.execute("DROP TABLE onboarding_adapter_flows")
            db.execute("PRAGMA user_version = 24")
            db.execute(ddl)
        refuse_start(collision)
    for name, ddl in (("missing", "DROP TABLE onboarding_adapter_flows"),
                      ("extra", "ALTER TABLE onboarding_adapter_flows ADD COLUMN unexpected TEXT"),
                      ("renamed", "ALTER TABLE onboarding_adapter_flows RENAME COLUMN review_id TO wrong_review_id")):
        corrupt = clone_state(source, "corrupt-" + name)
        with closing(sqlite3.connect(db_path(corrupt))) as db, db:
            db.execute(ddl)
        refuse_start(corrupt)
    for fault in ("wrong-type", "nullable-required", "missing-primary-key", "missing-project-reference", "missing-adapter-reference", "missing-state-check"):
        corrupt = clone_state(source, "corrupt-" + fault)
        definitions = []
        for index, column in enumerate(COLUMNS):
            part = column + (" BLOB" if fault == "wrong-type" and column == "review" else " TEXT")
            if index < 8 and not (fault == "nullable-required" and column == "project_flow_id"):
                part += " NOT NULL"
            if index == 0 and fault != "missing-primary-key":
                part += " PRIMARY KEY"
            if column == "project_flow_id" and fault != "missing-project-reference":
                part += " REFERENCES onboarding_project_flows(flow_id)"
            if column == "adapter_id" and fault != "missing-adapter-reference":
                part += " REFERENCES adapter_credentials(id)"
            if column == "state" and fault != "missing-state-check":
                part += " CHECK (state IN ('review','authorized','declined'))"
            definitions.append(part)
        with closing(sqlite3.connect(db_path(corrupt))) as db, db:
            db.execute("DROP TABLE onboarding_adapter_flows")
            db.execute("CREATE TABLE onboarding_adapter_flows (" + ",".join(definitions) + ")")
        refuse_start(corrupt)
    future = clone_state(source, "future26")
    with closing(sqlite3.connect(db_path(future))) as db, db:
        db.execute("PRAGMA user_version = 26")
    refuse_start(future)


suite.finish()
