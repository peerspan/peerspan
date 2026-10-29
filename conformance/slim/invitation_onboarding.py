#!/usr/bin/env python3
"""Exact contact-invitation reviews and recipient inspection, contract sections 9/11.

Independent real-host/public API/CLI checks; no production imports or fabricated
DEC, protocol, membership or credential records. Read-only SQLite snapshots
observe logical writes. Offline schema fixtures model additive migrations and
refusal; one authorized live schema-only ABORT trigger injects a failure on the
flow's issued-state update to test rollback of actual mint work. No model or
participant consent is simulated. A public join proves the code is a usable
introduction, never admission/access. Legacy networks and missing return-secret
records have no public construction/destruction fixture and remain separate
historic-fixture/source checks. Independent OpenSSL signatures construct legacy,
stale-contact and malformed recipient wire fixtures only; these prove signer
possession and wire validation, never current membership. No protocol rows are
manufactured. Transport reachability is not inferred.
"""
import base64
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
from pathlib import Path
from datetime import datetime, timedelta, timezone

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, b64url_json, check, create_network,
                     join_request, parse_time, ssh_key, ssh_public_base64, wait_for)

suite = Suite("invitation_onboarding", __doc__)
BASE = "/v1/onboarding/invitation-flows"
PROJECT = "/v1/onboarding/project-flows"
TABLE = "onboarding_invitation_flows"
TOP = {"version", "flow_id", "state", "review_id", "review", "invitation", "next_action"}
REVIEW = {"version", "kind", "flow_id", "host_id", "context", "agent", "network", "inviter_host_public_key",
          "member", "expected_person_public_key", "transport", "expires_at", "invitation_expires_at", "effects"}
EFFECTS = {"create_contact_invitation": True, "receive_join_requests": True, "grant_membership": False,
           "grant_agent_access": False, "approve_machine": False, "share_files": False,
           "share_conversation": False, "capability_calls": False}
COLUMNS = ["flow_id", "project_flow_id", "request", "review", "review_id", "state", "created_at", "expires_at",
           "invitation_id", "decided_at"]


def host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    h.transport_file = h.root / "transport.json"
    h.transport_body = {"format": 1, "advertise_bootstrap": [f"127.0.0.1:{h.bootstrap_port}"],
                        "advertise_quic": [h.peer_address], "rendezvous": [], "relays": [], "publish_contacts": False}
    h.transport_file.write_text(json.dumps(h.transport_body))
    h.transport_file.chmod(0o600)
    h.extra_args = ["--transport-config", h.transport_file]
    return h.start()


def get(h, path):
    status, value = h.api("GET", path, timeout=10)
    check(status == 200, f"{h.name} observation HTTP {status}")
    return value


def db_path(h):
    matches = []
    for path in h.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                matches.append(path)
    check(len(matches) == 1, "expected one actual host database")
    return matches[0]


def records(h):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True, timeout=5)) as db, db:
        db.execute("BEGIN")
        value = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                 "$version": db.execute("PRAGMA user_version").fetchone()}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            quoted = '"' + name.replace('"', '""') + '"'
            value[name] = tuple(sorted(db.execute(f"SELECT * FROM {quoted}"), key=repr))
        return value


def without(value, *keys):
    return {key: item for key, item in value.items() if key not in keys}


def rows(h):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute(f"SELECT * FROM {TABLE} ORDER BY flow_id")]


def public(value, *secrets):
    text = json.dumps(value, ensure_ascii=False)
    for marker in ("psi2-", "psl2-", "return_secret", "token_", *secrets):
        check(not marker or marker not in text, "public response/error exposed invitation or private input")


def advance_to(h, moment):
    h.clock.set(math.ceil((moment - datetime.now(timezone.utc)).total_seconds()))


def project(h, label, *, root=None, native=None, replace=None, agent=None):
    body = {"project_root": root or str(suite.work / "private projects" / label),
            "native_session_id": native or "private-conversation-" + label, "integration": "claude-code",
            "agent": {"kind": "existing", "id": agent["id"]} if agent else
                     {"kind": "new", "name": 'Agent "東京" ' + label, "owner": "Local owner é"}}
    if replace:
        body["replace_flow_id"] = replace
    status, flow = h.api("POST", PROJECT, body)
    check(status == 201, f"project fixture prepare HTTP {status}")
    decision = {key: body[key] for key in ("project_root", "native_session_id", "integration")}
    status, flow = h.api("POST", PROJECT + "/" + flow["flow_id"] + "/decision",
                         {**decision, "review_id": flow["review_id"], "decision": "approve"})
    check(status == 200 and flow["state"] == "attached", "project fixture failed exact metadata attachment")
    return flow


def context(parent):
    return {"project_flow_id": parent["flow_id"], "project_review_id": parent["review_id"],
            **{key: parent["review"][key] for key in ("project_root", "native_session_id", "integration")}}


def proposal(parent, network, member='Teammate "東京"', pin="-", replace=None):
    body = {"context": context(parent), "network_id": network["id"], "member": member,
            "expected_person_public_key": pin}
    if replace:
        body["replace_flow_id"] = replace
    return body


def validate(h, parent, network, flow):
    check(isinstance(flow, dict) and set(flow) == TOP and flow["version"] == 1, "exact invitation flow view")
    review = flow["review"]
    check(set(review) == REVIEW and review["version"] == 1 and review["kind"] == "create_contact_invitation", "exact invitation review")
    check(re.fullmatch(r"flow_[0-9a-f]{32}", flow["flow_id"]) is not None and review["flow_id"] == flow["flow_id"], "flow identity")
    check(review["host_id"] == h.id and review["inviter_host_public_key"] == h.public_key, "substituted owned-host signer")
    check(review["context"] == context(parent) and review["agent"] == parent["review"]["agent"], "changed exact parent/agent terms")
    check(review["network"] == {key: network[key] for key in ("id", "name", "context_id", "genesis_root_public_key")}, "wrong explicit verified network")
    check(review["transport"] == {"bootstrap_addresses": h.transport_body["advertise_bootstrap"],
          "quic_addresses": h.transport_body["advertise_quic"], "relays": [], "helpers": []}, "changed configured public transport hints")
    check(review["effects"] == EFFECTS and all(type(value) is bool for value in review["effects"].values()), "review grants unintended authority")
    check(parse_time(review["invitation_expires_at"]) - parse_time(review["expires_at"]) == timedelta(minutes=45), "fixed review/invitation deadlines diverged")
    canonical = json.dumps(review, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    check(flow["review_id"] == "review_" + hashlib.sha256(b"peerspan-invitation-review-v1\n" + canonical).hexdigest(), "canonical UTF-8 review digest")
    actions = {"review": "review", "issued": "share_private_invitation", "declined": "restart_review",
               "expired": "restart_review", "invalidated": "restart_review"}
    check(flow["state"] in actions and flow["next_action"] == actions[flow["state"]], "state/next action")
    if flow["invitation"] is not None:
        check(set(flow["invitation"]) == {"invitation_id", "expires_at"} and
              re.fullmatch(r"di_[0-9a-f]{64}", flow["invitation"]["invitation_id"]) is not None and
              flow["invitation"]["expires_at"] == review["invitation_expires_at"], "public issued outcome")
    else:
        check(flow["state"] != "issued", "issued flow lacks public outcome")
    public(flow)


def prepare(h, body, *, status=201, code=None):
    actual, flow = h.api("POST", BASE, body)
    check(actual == status, f"prepare HTTP {actual}, want {status}")
    if code:
        check(flow.get("code") == code, f"prepare expected {code}")
    public(flow)
    return flow


def decision(flow, choice="approve"):
    return {"context": flow["review"]["context"], "review_id": flow["review_id"], "decision": choice}


def decide(h, flow, choice="approve", *, status=200, code=None, body=None):
    actual, value = h.api("POST", BASE + "/" + flow["flow_id"] + "/decision", body if body is not None else decision(flow, choice))
    check(actual == status, f"decision HTTP {actual}, want {status}")
    if code:
        check(value.get("code") == code, f"decision expected {code}")
    if status == 200:
        check(value["review"] == flow["review"] and value["review_id"] == flow["review_id"], "decision refreshed immutable terms")
    public(value)
    return value


def handoff(h, flow, *, status=200, code=None, body=None):
    payload = without(decision(flow), "decision")
    actual, value = h.api("POST", BASE + "/" + flow["flow_id"] + "/handoff", body if body is not None else payload)
    check(actual == status, f"handoff HTTP {actual}, want {status}")
    if code:
        check(value.get("code") == code, f"handoff expected {code}")
    if status == 200:
        check(set(value) == {"version", "flow_id", "review_id", "network_id", "context_id", "invitation_id", "invitation", "expires_at"}, "private handoff shape")
        review = flow["review"]
        check(value["version"] == 1 and value["flow_id"] == flow["flow_id"] and value["review_id"] == flow["review_id"]
              and value["network_id"] == review["network"]["id"] and value["context_id"] == review["network"]["context_id"]
              and value["invitation_id"] == flow["invitation"]["invitation_id"] and value["expires_at"] == review["invitation_expires_at"]
              and value["invitation"].startswith("psi2-"), "private handoff changed exact outcome")
    else:
        public(value)
    return value


def observe(h, parent, expected):
    before = records(h)
    status, found = h.api("POST", BASE + "/lookup", {"context": context(parent)})
    check(status == 200 and set(found) == {"version", "host_id", "context", "flow"} and found["version"] == 1
          and found["host_id"] == h.id and found["context"] == context(parent) and found["flow"] == expected, "coherent exact lookup")
    if expected:
        check(get(h, BASE + "/" + expected["flow_id"]) == expected, "lookup/inspect disagreement")
    check(records(h) == before, "lookup/inspect changed logical records, pending return material, activity or cleanup")
    public(found)


def parallel(call, values=range(4)):
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(call, values))


def raw_post(h, path, data):
    conn = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=10)
    try:
        conn.request("POST", path, body=data, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        value = response.read()
        return response.status, json.loads(value) if value else None
    finally:
        conn.close()


def file_state(root):
    if not root.exists():
        return None
    return {str(path.relative_to(root)): (path.lstat().st_mode, path.lstat().st_mtime_ns,
            os.readlink(path) if path.is_symlink() else hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
            for path in [root, *sorted(root.rglob("*"))]}


@suite.case("exact_explicit_review_and_logically_read_only_resume", "guided onboarding 9 verification 1")
def _():
    h = host("exact")
    create_network(h, "first network must not be selected", "owner")
    network = create_network(h, 'Selected "東京"', "owner")
    parent = project(h, "é-exact")
    pin = ssh_public_base64(ssh_key(h.root, "only-a-pin"))
    body = proposal(parent, network, '  Teammate "é東京"  ', pin)
    observe(h, parent, None)
    before = records(h)
    earliest = h.now().replace(microsecond=0)
    flow = prepare(h, body)
    latest = h.now().replace(microsecond=0)
    validate(h, parent, network, flow)
    review = flow["review"]
    check(review["member"] == body["member"].strip() and review["expected_person_public_key"] == pin, "review normalized label or changed identity pin incorrectly")
    check(flow["state"] == "review" and flow["invitation"] is None, "preparation issued a code")
    check(earliest + timedelta(minutes=15) <= parse_time(review["expires_at"]) <= latest + timedelta(minutes=15)
          and earliest + timedelta(hours=1) <= parse_time(review["invitation_expires_at"]) <= latest + timedelta(hours=1), "preparation did not fix both deadlines")
    check(without(records(h), TABLE) == without(before, TABLE) and len(records(h)[TABLE]) == 1, "preparation changed records outside its private row")
    stored = rows(h)[0]
    check(json.loads(stored["request"]) == {**body, "member": body["member"].strip()}
          and json.loads(stored["review"]) == review and stored["state"] == "review"
          and stored["invitation_id"] is None and stored["decided_at"] is None, "private row changed exact request/review or contains issuance")
    for actual, resumed in parallel(lambda _: h.api("POST", BASE, {**body, "member": body["member"].strip()})):
        check(actual == 200 and resumed == flow, "concurrent identical prepare changed IDs, terms or deadlines")
    observe(h, parent, flow)
    check(without(records(h), TABLE) == without(before, TABLE), "resume/read minted, signed or changed authority")
    handoff(h, flow, status=409, code="flow_conflict")
    check(get(h, "/v1/agents") == [get(h, "/v1/agents/" + parent["review"]["agent"]["id"])], "prepare created another agent")
    public(get(h, "/v1/onboarding")); public(get(h, "/v2/status"))


@suite.case("atomic_concurrent_approval_private_handoff_and_public_join", "guided onboarding 9 verification 2/4")
def _():
    h, joiner = host("issuer"), host("joiner")
    network = create_network(h, "invitation-validity", "owner")
    parent = project(h, "approval")
    key = ssh_key(joiner.root, "teammate")
    body = proposal(parent, network, "teammate", ssh_public_base64(key))
    flow = prepare(h, body)
    before = records(h)
    activity = get(h, "/v1/activity?limit=1000")
    advance_to(h, parse_time(flow["review"]["expires_at"]) - timedelta(minutes=10))
    results = parallel(lambda _: h.api("POST", BASE + "/" + flow["flow_id"] + "/decision", decision(flow)))
    check(all(status == 200 for status, _ in results) and all(value == results[0][1] for _, value in results), "approval race minted conflicting public outcomes")
    issued = results[0][1]
    validate(h, parent, network, issued)
    check(issued["state"] == "issued", "approval did not issue")
    after = records(h)
    check(len(after["dec_pending"]) == len(before["dec_pending"]) + 1, "approval did not create exactly one return row")
    check(get(h, "/v1/activity?limit=1000") == activity, "contact-only approval emitted authority/registry/activity changes")
    for table in ("agents", "sessions", "network_members", "dec_objects", "dec_admissions", "dec_restrictions", "dec_activations", "dec_heads", "dec_highwater", "dec_signers"):
        check(after[table] == before[table], "contact-only approval changed " + table)
    baseline = records(h)
    private = handoff(h, issued)
    check(handoff(h, issued) == private and decide(h, flow) == issued, "retry changed the private bytes or public outcome")
    observe(h, parent, issued)
    check(records(h) == baseline, "private retrieval or same-choice decision refreshed records/deadlines/material")
    envelope = b64url_json(private["invitation"], "psi2-")
    payload = json.loads(base64.b64decode(envelope["payload_base64"], validate=True))
    check(envelope["context_id"] == network["context_id"] and envelope["inviter_host_public_key"] == h.public_key
          and payload["member"] == body["member"] and payload["expected_person_public_key"] == body["expected_person_public_key"]
          and payload["expires_at"] == flow["review"]["invitation_expires_at"], "ordinary code changed reviewed signer/member/pin/expiry")
    descriptor = payload["descriptor"]
    if isinstance(descriptor, str):
        descriptor = json.loads(base64.b64decode(descriptor, validate=True))
    check(descriptor["network_id"] == network["id"] and descriptor["name"] == network["name"]
          and descriptor["genesis_root_public_key"] == network["genesis_root_public_key"], "ordinary code changed the selected descriptor")
    check(parse_time(payload["issued_at"]) >= parse_time(flow["review"]["expires_at"]) - timedelta(minutes=10), "code was signed at preparation instead of approval")
    check(len(base64.b64decode(payload["return_secret_base64"], validate=True)) == 16, "ordinary code has no valid automatic return secret")
    for contact in payload["contacts"]:
        hints = json.loads(base64.b64decode(contact["payload_base64"], validate=True))
        check(contact["host_public_key"] == h.public_key and contact["context_id"] == network["context_id"]
              and hints == without(flow["review"]["transport"], "helpers"), "signed contact changed reviewed public hints or signer")
    check(payload["contacts"] and payload["helpers"] == flow["review"]["transport"]["helpers"], "ordinary invitation omitted reviewed public hints")
    for value in (get(h, BASE + "/" + issued["flow_id"]), get(h, "/v1/onboarding"), get(h, "/v2/status"), activity, rows(h)):
        public(value, private["invitation"], payload["return_secret_base64"])
    # Another explicit teammate never revokes the previously exported code.
    second = prepare(h, proposal(parent, network, "another teammate", replace=issued["flow_id"]))
    decide(h, second)
    check(handoff(h, issued) == private, "new invitation revoked or refreshed an older private handoff")
    # Match inviter's explicit five-minute advance so a future-issued code is valid.
    joiner.clock.set(h.clock.offset)
    request = join_request(joiner, private["invitation"], key)
    wait_for(lambda: any(item["request_id"] == request["request_id"] for item in get(h, "/v2/link/requests")),
             timeout=20, message="automatic return of the original issued introduction")
    check(get(joiner, "/v2/networks") == [], "valid introduction silently admitted the joiner")
    check(len(get(h, f"/v2/networks/{network['id']}/members")["members"]) == 1, "introduction granted membership")
    check(get(joiner, "/v1/agents") == [], "introduction granted agent access or registered an agent")


@suite.case("malformed_declined_changed_context_and_parent_cannot_mint", "guided onboarding 9 verification 3")
def _():
    h = host("invalid")
    parent = project(h, "invalid")
    unknown = {"id": "net_" + "0" * 64}
    before = records(h)
    prepare(h, proposal(parent, unknown), status=404, code="not_found")
    check(records(h) == before, "missing network manufactured authority or flow")
    network = create_network(h, "invalid-review", "owner")
    body = proposal(parent, network)
    variants = [without(body, "network_id"), {**body, "network_id": None}, {**body, "network_id": "NET_" + "a" * 64},
                {**body, "member": " "}, {**body, "member": "bad\nlabel"}, {**body, "member": "é" * 65},
                {**body, "member": None}, {**body, "expected_person_public_key": "not-base64"},
                {**body, "expected_person_public_key": None}, {**body, "context": None},
                {**body, "context": {**body["context"], "unknown": "private-extra-marker"}},
                {**body, "extra": "private-extra-marker"}, {**body, "replace_flow_id": None}]
    before = records(h)
    for bad in variants:
        prepare(h, bad, status=400, code="invalid")
    for data in ('null', '[]', '{"private":', json.dumps(body) + ' {}',
                 json.dumps(body).replace('"member":', '"member":"duplicate","member":')):
        status, value = raw_post(h, BASE, data.encode())
        check(status == 400 and value.get("code") == "invalid", "malformed/duplicate prepare was accepted")
        public(value, "private-extra-marker")
    missing_project = {**body, "context": {**body["context"], "project_flow_id": "flow_" + "0" * 32}}
    prepare(h, missing_project, status=404, code="not_found")
    check(records(h) == before, "invalid inputs wrote a flow or invitation")
    flow = prepare(h, body)
    for changed in ({**decision(flow), "review_id": "review_" + "0" * 64},
                    {**decision(flow), "context": {**body["context"], "native_session_id": "different-private-native"}}):
        decide(h, flow, status=409, code="review_changed", body=changed)
    for suffix, exact in (("/decision", decision(flow)), ("/handoff", without(decision(flow), "decision"))):
        for bad in ({**exact, "extra": "private-extra-marker"}, {**exact, "context": None}, {**exact, "review_id": None}):
            status, value = h.api("POST", BASE + "/" + flow["flow_id"] + suffix, bad)
            check(status == 400 and value.get("code") == "invalid", "malformed decision/private retrieval accepted")
            public(value, "private-extra-marker")
    before = records(h)
    declined = decide(h, flow, "decline")
    check(declined["state"] == "declined" and declined["invitation"] is None, "decline minted")
    check(without(records(h), TABLE) == without(before, TABLE), "decline changed outside its outcome")
    check(decide(h, flow, "decline") == declined and prepare(h, body, status=200) == declined, "decline retry did not resume fixed terminal outcome")
    decide(h, flow, status=409, code="flow_conflict"); handoff(h, declined, status=409, code="flow_conflict")
    pending = prepare(h, {**body, "replace_flow_id": declined["flow_id"]})
    h.ok("session", "detach", parent["review"]["session_id"])
    replacement = project(h, "new-parent", root=parent["review"]["project_root"], native=parent["review"]["native_session_id"],
                          replace=parent["flow_id"], agent=parent["review"]["agent"])
    invalid = get(h, BASE + "/" + pending["flow_id"])
    check(invalid["state"] == "invalidated" and invalid["invitation"] is None, "changed project retained invitation decision authority")
    before = records(h)
    decide(h, pending, status=409)
    check(records(h) == before, "old parent decision minted or repaired an attachment")
    observe(h, replacement, None)


@suite.case("fixed_deadline_decision_races_and_mint_rollback", "guided onboarding 9 verification 3")
def _():
    h = host("races")
    network = create_network(h, "races", "owner")
    parent = project(h, "expiry")
    body = proposal(parent, network)
    flow = prepare(h, body)
    advance_to(h, parse_time(flow["review"]["expires_at"]))
    before = records(h)
    expired = get(h, BASE + "/" + flow["flow_id"])
    check(expired["state"] == "expired" and expired["invitation"] is None, "fixed deadline remained actionable")
    observe(h, parent, expired)
    for status, value in parallel(lambda _: h.api("POST", BASE + "/" + flow["flow_id"] + "/decision", decision(flow))):
        check(status == 409 and value.get("code") == "review_expired", "approval at/after fixed deadline minted")
    handoff(h, expired, status=409, code="flow_conflict")
    check(records(h) == before, "expired reads or first decisions cleaned, signed or wrote state")
    pending = prepare(h, {**body, "replace_flow_id": flow["flow_id"]})
    decide(h, flow, status=409, code="flow_conflict")
    before = records(h)
    results = parallel(lambda choice: h.api("POST", BASE + "/" + pending["flow_id"] + "/decision", decision(pending, choice)),
                       ["approve", "decline", "approve", "decline"])
    successes = [value for status, value in results if status == 200]
    check(successes and all(value == successes[0] for value in successes)
          and all(status in (200, 409) for status, _ in results), "approve/decline race produced inconsistent outcomes")
    winner = successes[0]
    check(len(records(h)["dec_pending"]) - len(before["dec_pending"]) == (1 if winner["state"] == "issued" else 0), "opposite decisions minted more than one invitation")
    decide(h, pending, "decline" if winner["state"] == "issued" else "approve", status=409, code="flow_conflict")
    parent2 = project(h, "rollback")
    rollback = prepare(h, proposal(parent2, network))
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute(f"CREATE TRIGGER conformance_abort_invitation BEFORE UPDATE ON {TABLE} "
                   "WHEN NEW.state='issued' BEGIN SELECT RAISE(ABORT,'conformance-abort'); END")
    try:
        before = records(h)
        actual, error = h.api("POST", BASE + "/" + rollback["flow_id"] + "/decision", decision(rollback))
        check(actual == 500, f"injected flow-update failure did not remain a storage error: HTTP {actual}")
        public(error)
        check(records(h) == before, "failed flow update left contact sequence, return secret, flow decision or another partial write")
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute("DROP TRIGGER conformance_abort_invitation")
    issued = decide(h, rollback)
    check(issued["state"] == "issued" and handoff(h, issued)["invitation"].startswith("psi2-"), "rollback prevented a later exact valid decision")


@suite.case("explicit_replacement_restart_retention_and_changed_transport", "guided onboarding 9 verification 4")
def _():
    h = host("replacement")
    network = create_network(h, "retained-invitations", "owner")
    parent = project(h, "replacement")
    body = proposal(parent, network, "first teammate")
    first = prepare(h, body)
    changed = {**body, "member": "second teammate"}
    before = records(h)
    prepare(h, changed, status=409, code="flow_conflict")
    prepare(h, {**changed, "replace_flow_id": first["flow_id"]}, status=409, code="flow_conflict")
    check(records(h) == before, "pending invitation was silently or explicitly superseded")
    declined = decide(h, first, "decline")
    second = prepare(h, {**changed, "replace_flow_id": declined["flow_id"]})
    issued = decide(h, second); private = handoff(h, issued)
    third = prepare(h, proposal(parent, network, "third teammate", replace=issued["flow_id"]))
    check(third["flow_id"] != second["flow_id"] and third["invitation"] is None, "new explicit teammate reused old flow/outcome")
    check(decide(h, second) == issued and handoff(h, issued) == private, "new proposal disabled older retained approval/retrieval")
    observe(h, parent, third)
    # Supersede an invalidated pending review, then its old callback cannot mint.
    h.ok("session", "detach", parent["review"]["session_id"])
    check(get(h, BASE + "/" + third["flow_id"])["state"] == "invalidated", "detachment did not invalidate pending terms")
    before = records(h)
    newer = prepare(h, {**proposal(parent, network, "fourth teammate"), "replace_flow_id": third["flow_id"]}, status=409)
    public(newer)
    check(records(h) == before, "unattached parent minted a replacement")
    decide(h, third, status=409)
    # A separate latest issued flow exercises identical prepare after restart.
    retained_parent = project(h, "retained-issued")
    retained_body = proposal(retained_parent, network, "retained teammate")
    retained = decide(h, prepare(h, retained_body)); retained_private = handoff(h, retained)
    h.restart(kill=True)
    check(get(h, "/v1/sessions/" + retained_parent["review"]["session_id"])["state"] == "detached", "retrieval restart resurrected an attached session")
    before = records(h)
    check(prepare(h, retained_body, status=200) == retained and decide(h, retained) == retained
          and handoff(h, retained) == retained_private, "restart changed usable issued result or private bytes")
    check(get(h, BASE + "/" + third["flow_id"])["state"] == "invalidated", "restart repaired an invalidated pending attempt")
    check(records(h) == before, "restart retrieval duplicated invitation or repaired metadata/return material")
    advance_to(h, parse_time(retained["review"]["expires_at"]) + timedelta(seconds=1))
    check(handoff(h, retained) == retained_private and decide(h, retained) == retained, "issued result incorrectly expired at its old review deadline")
    h.stop()
    h.transport_body["advertise_bootstrap"] = [f"127.0.0.1:{h.bootstrap_port + 1 if h.bootstrap_port < 65535 else h.bootstrap_port - 1}"]
    h.transport_file.write_text(json.dumps(h.transport_body))
    h.start()
    invalid = get(h, BASE + "/" + retained["flow_id"])
    check(invalid["state"] == "invalidated" and invalid["invitation"] == retained["invitation"], "changed public hints lost retained outcome or claimed usability")
    before = records(h)
    handoff(h, retained, status=409, code="review_changed")
    check(decide(h, retained) == invalid, "terminal retry reminted or refreshed changed transport")
    check(records(h) == before, "invalidated retrieval/terminal retry repaired reviewed terms")


@suite.case("issued_expiration_preserves_public_outcome_and_denies_private_retrieval", "guided onboarding 9 verification 3/4")
def _():
    h = host("issued-expiry")
    network = create_network(h, "issued-expiry", "owner")
    parent = project(h, "issued-expiry")
    body = proposal(parent, network)
    issued = decide(h, prepare(h, body))
    advance_to(h, parse_time(issued["review"]["invitation_expires_at"]))
    expired = get(h, BASE + "/" + issued["flow_id"])
    check(expired["state"] == "expired" and expired["invitation"] == issued["invitation"], "issued expiry erased evidence or remained usable")
    handoff(h, issued, status=409, code="flow_conflict")
    check(decide(h, issued) == expired and prepare(h, body, status=200) == expired, "terminal retry extended or reminted expired invitation")
    observe(h, parent, expired)


@suite.case("private_stdin_cli_parity_bounds_and_unavailable_daemon", "guided onboarding 9 verification 5")
def _():
    h = host("cli")
    network = create_network(h, "cli", "owner")
    parent = project(h, "cli-private")
    body = proposal(parent, network)
    empty = h.cli("onboarding", "invitation", "lookup", "--stdin", input=json.dumps({"context": context(parent)}))
    check(empty.ok and empty.json["flow"] is None, "CLI lookup did not preserve exact null view")
    made = h.cli("onboarding", "invitation", "prepare", "--stdin", input=json.dumps(body))
    check(made.ok, "CLI prepare failed")
    flow = made.json
    validate(h, parent, network, flow)
    check(h.cli("onboarding", "invitation", "inspect", flow["flow_id"]).json == flow, "CLI inspect parity")
    decision_body = {"flow_id": flow["flow_id"], **decision(flow)}
    result = h.cli("onboarding", "invitation", "decide", "--stdin", input=json.dumps(decision_body))
    check(result.ok and result.json["state"] == "issued", "CLI exact approval failed")
    issued = result.json
    private_body = without(decision_body, "decision")
    private = h.cli("onboarding", "invitation", "handoff", "--stdin", input=json.dumps(private_body))
    check(private.ok and private.json == handoff(h, issued), "CLI private handoff parity")
    token = private.json["invitation"]
    inputs = {"lookup": {"context": context(parent)}, "prepare": body, "decide": decision_body, "handoff": private_body}
    before = records(h)
    for command, payload in inputs.items():
        encoded = json.dumps(payload)
        exact_bound = " " * (65536 - len(encoded.encode())) + encoded
        valid = h.cli("onboarding", "invitation", command, "--stdin", input=exact_bound)
        check(valid.ok, f"CLI {command} refused exact 64KiB input")
        if command != "handoff":
            public(valid.json, token)
        first_key = next(iter(payload))
        duplicate = '{' + json.dumps(first_key) + ':null,' + encoded[1:]
        for data in ('null', '["private-extra-marker"]', '{"private":', duplicate, encoded + ' {}',
                     json.dumps({**payload, "extra": "private-extra-marker"}), " " + exact_bound):
            failed = h.cli("onboarding", "invitation", command, "--stdin", input=data)
            check(not failed.ok, f"CLI {command} accepted malformed/extra/oversized stdin")
            for marker in (token, context(parent)["project_root"], context(parent)["native_session_id"], "private-extra-marker"):
                check(marker not in failed.stdout + failed.stderr, "controlled CLI error echoed private stdin/code")
        check(not h.cli("onboarding", "invitation", command, input=encoded).ok, "CLI implicitly read stdin")
    check(not h.cli("onboarding", "invitation", "decide", "approve", flow["flow_id"]).ok, "CLI accepted positional approval")
    check(not h.cli("onboarding", "invitation", "handoff", flow["flow_id"]).ok, "CLI accepted positional private retrieval")
    check(records(h) == before, "CLI reads/retries/refusals changed logical state")
    h.stop()
    absent = suite.host("absent", start=False)
    shutil.rmtree(absent.state)
    for stopped in (h, absent):
        baseline = file_state(stopped.root)
        for command, payload in inputs.items():
            failed = stopped.cli("onboarding", "invitation", command, "--stdin", input=json.dumps(payload))
            check(not failed.ok and token not in failed.stdout + failed.stderr, "unavailable daemon succeeded or echoed secret")
        check(not stopped.cli("onboarding", "invitation", "inspect", flow["flow_id"]).ok, "unavailable inspect succeeded")
        check(file_state(stopped.root) == baseline, "unavailable integration CLI created daemon/state files")


@suite.case("owner_only_routes_refuse_scoped_peer_and_quiescent_bootstrap", "guided onboarding 9 verification 5")
def _():
    h, peer, bootstrap = host("boundary"), host("peer"), host("bootstrap")
    for local, remote in ((h, peer), (peer, h)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    network = create_network(h, "boundary", "owner")
    parent = project(h, "boundary")
    body = proposal(parent, network)
    flow = prepare(h, body)
    adapter = h.agent("boundary-fixture", directory=False, ready=False)
    routes = (("POST", BASE, body), ("POST", BASE + "/lookup", {"context": context(parent)}),
              ("GET", BASE + "/" + flow["flow_id"], None),
              ("POST", BASE + "/" + flow["flow_id"] + "/decision", decision(flow)),
              ("POST", BASE + "/" + flow["flow_id"] + "/handoff", without(decision(flow), "decision")))
    cert, key = suite.work / "boundary-cert.pem", suite.work / "boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=invitation-boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    for method, path, payload in routes:
        status, denied = adapter.call(method, path, payload)
        check(status == 404, f"scoped invitation route HTTP {status}"); public(denied)
        args = [str(suite.probe_bin), "--state", str(peer.state), "--address", h.peer_address,
                "--alpn", "peerspan-peer/1", "--method", method, "--path", path]
        if payload is not None:
            args.append("--body-stdin")
        result = subprocess.run(args, input=(json.dumps(payload) if payload is not None else "").encode(), capture_output=True, timeout=15)
        check(result.returncode == 0 and json.loads(result.stdout).get("status") == 404, "authenticated peer exposed invitation owner routes")
        data = b"" if payload is None else json.dumps(payload).encode()
        with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname="peerspan") as stream:
                stream.sendall((f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\n"
                                f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, f"quiescent bootstrap invitation route HTTP {response.status}, want404")
    adapter.stop()
    check(get(h, BASE + "/" + flow["flow_id"]) == flow, "remote calls decided the private invitation")


def clone_state(source, name):
    target = suite.host(name, start=False)
    shutil.copytree(source.state, target.state, dirs_exist_ok=True)
    for socket_name in ("admin.sock", "adapter.sock"):
        (target.state / socket_name).unlink(missing_ok=True)
    return target


def refuse_start(h):
    before = records(h)
    with h.log.open("ab") as log:
        process = suite.spawn([str(suite.host_bin), "--state", str(h.state), "run"], stdout=log, stderr=log, env=h.env)
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=5); code = None
    check(code not in (None, 0), "colliding/malformed/future invitation schema was opened")
    check(records(h) == before, "refused migration changed logical records, version or schema")


@suite.case("schema26_additive_migration_reserved_names_corruption_and_future27", "guided onboarding 9 verification 6")
def _():
    source = host("migration")
    network = create_network(source, "preserved-network", "owner")
    parent = project(source, "preserved-project")
    status, adapter_flow = source.api("POST", "/v1/onboarding/adapter-flows", {"context": context(parent)})
    check(status == 201, "real pending adapter-review fixture failed")
    prepare(source, proposal(parent, network))
    source.ok("session", "detach", parent["review"]["session_id"])
    advanced = source.ok("invite", "historical invitation", "--network", network["id"])
    check(advanced["invitation"].startswith("psi2-"), "existing advanced invitation route changed")
    identity, activity = get(source, "/v1/host"), get(source, "/v1/activity?limit=1000")
    source.stop()
    baseline = records(source)
    with closing(sqlite3.connect(f"file:{db_path(source)}?mode=ro", uri=True)) as db:
        columns = list(db.execute(f"PRAGMA table_info({TABLE})"))
        foreign = list(db.execute(f"PRAGMA foreign_key_list({TABLE})"))
    check([row[1] for row in columns] == COLUMNS and all(row[2].upper() == "TEXT" for row in columns), "schema26 ordered TEXT columns")
    check([bool(row[3]) for row in columns] == [True] * 8 + [False, False] and columns[0][5] == 1, "schema26 nullability/primary key")
    check(len(foreign) == 1 and foreign[0][2:5] == ("onboarding_project_flows", "project_flow_id", "flow_id"), "schema26 project reference or forbidden return-material reference")
    legacy = clone_state(source, "legacy25")
    with closing(sqlite3.connect(db_path(legacy))) as db, db:
        db.execute(f"DROP TABLE {TABLE}"); db.execute("PRAGMA user_version = 25")
    old = records(legacy)
    legacy.start()
    check(get(legacy, "/v1/host") == identity and get(legacy, "/v1/activity?limit=1000") == activity, "migration changed host identity/activity")
    check(get(legacy, PROJECT + "/" + parent["flow_id"])["state"] == "invalidated"
          and get(legacy, "/v1/sessions/" + parent["review"]["session_id"])["state"] == "detached", "migration resurrected metadata attachment")
    check(get(legacy, "/v1/onboarding/adapter-flows/" + adapter_flow["flow_id"])["review"] == adapter_flow["review"], "migration changed retained adapter terms")
    legacy.stop()
    migrated = records(legacy)
    check(migrated["$version"] == (26,) and migrated[TABLE] == (), "schema25 migration did not add empty schema26 table")
    check(without(migrated, "$schema", "$version", TABLE) == without(old, "$schema", "$version"), "schema26 migration changed prior DEC/return/registry/project/adapter records")
    check(migrated["$schema"] == baseline["$schema"], "additive migration changed older table definitions")
    for kind, ddl in (("table", f"CREATE TABLE {TABLE} (marker TEXT)"),
                      ("view", f"CREATE VIEW {TABLE} AS SELECT 'reserved' AS marker"),
                      ("index", f"CREATE INDEX {TABLE} ON sessions(id)"),
                      ("trigger", f"CREATE TRIGGER {TABLE} AFTER INSERT ON sessions BEGIN SELECT 1; END")):
        collision = clone_state(source, "collision-" + kind)
        with closing(sqlite3.connect(db_path(collision))) as db, db:
            db.execute(f"DROP TABLE {TABLE}"); db.execute("PRAGMA user_version = 25"); db.execute(ddl)
        refuse_start(collision)
    for name, ddl in (("missing", f"DROP TABLE {TABLE}"), ("extra", f"ALTER TABLE {TABLE} ADD COLUMN unexpected TEXT"),
                      ("renamed", f"ALTER TABLE {TABLE} RENAME COLUMN review_id TO wrong_review_id")):
        corrupt = clone_state(source, "corrupt-" + name)
        with closing(sqlite3.connect(db_path(corrupt))) as db, db:
            db.execute(ddl)
        refuse_start(corrupt)
    for fault in ("wrong-type", "nullable-required", "missing-primary-key", "missing-project-reference", "missing-state-check"):
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
            if column == "state" and fault != "missing-state-check":
                part += " CHECK (state IN ('review','issued','declined'))"
            definitions.append(part)
        with closing(sqlite3.connect(db_path(corrupt))) as db, db:
            db.execute(f"DROP TABLE {TABLE}")
            db.execute(f"CREATE TABLE {TABLE} (" + ",".join(definitions) + ")")
        refuse_start(corrupt)
    future = clone_state(source, "future27")
    with closing(sqlite3.connect(db_path(future))) as db, db:
        db.execute("PRAGMA user_version = 27")
    refuse_start(future)



PREVIEW = "/v1/onboarding/invitation-preview"
PREVIEW_EFFECTS = {"verify_contact_signature": True, "create_identity": False, "create_link_request": False,
                   "select_owner": False, "grant_membership": False, "grant_agent_access": False,
                   "approve_machine": False, "share_files": False, "share_conversation": False, "capability_calls": False}
preview_state = {}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def state_snapshot(h):
    # Opening the auxiliary databases for logical reads can itself create WAL/SHM
    # files. Their names and bytes are live SQLite bookkeeping, not durable state.
    # Retain every logical table, durable DB name/mode and other private file.
    logical = records(h)
    def sqlite_bookkeeping(p):
        return any(str(p).endswith(suffix) and Path(str(p)[:-len(suffix)]).is_file()
                   for suffix in ("-wal", "-shm") if str(p)[:-len(suffix)].endswith(".db"))
    names = {str(p.relative_to(h.state)): p.lstat().st_mode for p in h.state.rglob("*") if not sqlite_bookkeeping(p)}
    files = {str(p.relative_to(h.state)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in h.state.rglob("*") if p.is_file() and not any(str(p).endswith(x) for x in (".db", ".db-wal", ".db-shm"))}
    return logical, names, files


class WireSigner:
    """Disposable Ed25519 fixture key, unrelated to any admitted host authority."""
    def __init__(self):
        self.key = suite.work / "preview-fixture-ed25519.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.key)], check=True, capture_output=True, timeout=5)
        self.key.chmod(0o600)
        der = subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"],
                             check=True, capture_output=True, timeout=5).stdout
        check(len(der) == 44, "fixture Ed25519 SubjectPublicKeyInfo shape")
        self.public = base64.b64encode(der[-32:]).decode()

    def sign(self, message):
        path = suite.work / "preview-fixture-signing-message"
        path.write_bytes(message); path.chmod(0o600)
        signed = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(path)],
                                check=True, capture_output=True, timeout=5).stdout
        check(len(signed) == 64, "fixture Ed25519 signature length")
        return base64.b64encode(signed).decode()

    def contact(self, context_id, now, sequence=0, hints=None, **changes):
        payload = hints or {"quic_addresses": ["[::1]:9"], "bootstrap_addresses": ["127.0.0.1:9"], "relays": []}
        value = {"format": 1, "context_id": context_id, "host_public_key": self.public, "sequence": sequence,
                 "issued_at": (now - timedelta(seconds=600)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "expires_at": (now - timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "payload_base64": base64.b64encode(compact(payload)).decode()}
        value.update(changes)
        message = "\n".join(["peerspan-decentralized-contact-v1", value["context_id"], value["host_public_key"], str(value["sequence"]),
                             value["issued_at"], value["expires_at"], hashlib.sha256(base64.b64decode(value["payload_base64"])).hexdigest()]).encode()
        value["signature"] = self.sign(message)
        return value

    def invitation(self, original, *, payload_changes=None, envelope_changes=None, raw_payload=None):
        envelope = b64url_json(original, "psi2-")
        payload = json.loads(base64.b64decode(envelope["payload_base64"], validate=True))
        if payload_changes:
            payload_changes(payload)
        envelope["inviter_host_public_key"] = self.public
        envelope["payload_base64"] = base64.b64encode(compact(payload) if raw_payload is None else raw_payload).decode()
        if envelope_changes:
            envelope_changes(envelope)
        message = "\n".join(["peerspan-decentralized-contact-invitation-v1", envelope["context_id"],
                             envelope["inviter_host_public_key"], hashlib.sha256(base64.b64decode(envelope["payload_base64"])).hexdigest()]).encode()
        envelope["signature"] = self.sign(message)
        return "psi2-" + base64.urlsafe_b64encode(compact(envelope)).decode().rstrip("=")


def recipient_fixture():
    if not preview_state:
        inviter, recipient = host("preview-inviter"), host("preview-recipient")
        network = create_network(inviter, 'Public "東京" network', "inviter")
        parent_source, parent = project(inviter, "preview-source"), project(recipient, "preview-recipient")
        pin = ssh_public_base64(ssh_key(suite.work, "public-pin-only"))
        issued = decide(inviter, prepare(inviter, proposal(parent_source, network, 'Exact "é東京" member', pin)))
        code = handoff(inviter, issued)["invitation"]
        preview_state.update(inviter=inviter, recipient=recipient, network=network, parent=parent, code=code, signer=WireSigner())
    return preview_state


def json_fields(value):
    if isinstance(value, dict):
        return set(value).union(*(json_fields(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(json_fields(item) for item in value))
    return set()


def preview(h, parent, code, *, status=200, error=None, body=None):
    actual, value = h.api("POST", PREVIEW, body if body is not None else {"context": context(parent), "invitation": code}, timeout=10)
    check(actual == status, f"recipient preview HTTP {actual}, want{status}")
    if error:
        check(value.get("code") == error, f"recipient preview expected{error}")
    public(value, code)
    if status != 200:
        check(not ({"payload_base64", "signature", "return_secret_base64"} & json_fields(value)), "private wire fields in preview error")
        return value
    check(set(value) == {"version", "host_id", "context", "review_id", "review", "next_action"}
          and value["version"] == 1 and value["host_id"] == h.id and value["context"] == context(parent)
          and value["next_action"] == "choose_join_identity", "exact recipient preview envelope")
    review = value["review"]
    check(set(review) == {"version", "kind", "host_id", "context", "agent", "network", "inviter_host_public_key", "invitation", "contacts", "helpers", "effects"}
          and review["version"] == 1 and review["kind"] == "inspect_contact_invitation" and review["host_id"] == h.id
          and review["context"] == context(parent) and review["agent"] == parent["review"]["agent"], "recipient review/context/agent shape")
    envelope = b64url_json(code, "psi2-")
    raw = base64.b64decode(envelope["payload_base64"], validate=True); payload = json.loads(raw)
    descriptor = payload["descriptor"]
    if isinstance(descriptor, str):
        descriptor = json.loads(base64.b64decode(descriptor, validate=True))
    check(review["network"] == {"id": descriptor["network_id"], **{k: descriptor[k] for k in ("name", "genesis_root_public_key")},
                                "context_id": envelope["context_id"]}, "preview changed verified signed descriptor")
    message = "\n".join(["peerspan-decentralized-contact-invitation-v1", envelope["context_id"], envelope["inviter_host_public_key"], hashlib.sha256(raw).hexdigest()]).encode()
    expected_id = "di_" + hashlib.sha256(message).hexdigest()
    check(review["inviter_host_public_key"] == envelope["inviter_host_public_key"] and review["invitation"] == {
        "id": expected_id, **{k: payload[k] for k in ("member", "expected_person_public_key", "issued_at", "expires_at")},
        "automatic_return": "return_secret_base64" in payload}, "preview signer/invitation/return projection")
    contacts = []
    for contact in payload["contacts"]:
        hints = json.loads(base64.b64decode(contact["payload_base64"], validate=True))
        contacts.append({"sequence": str(contact["sequence"]), **{k: contact[k] for k in ("issued_at", "expires_at")}, **hints})
    check(review["contacts"] == contacts and review["helpers"] == payload["helpers"], "preview lost order, u64 sequence bits or public contact/helper terms")
    check(review["effects"] == PREVIEW_EFFECTS and all(type(v) is bool for v in review["effects"].values()), "preview invented mutation/authority effects")
    digest_bytes = json.dumps(review, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    check(value["review_id"] == "review_" + hashlib.sha256(b"peerspan-invitation-preview-v1\n" + digest_bytes).hexdigest(), "recipient canonical review hash")
    for field in ("payload_base64", "signature", "return_secret_base64"):
        check(field not in json_fields(value), "preview returned private signed wire framing")
    for secret in (envelope["payload_base64"], envelope["signature"], payload.get("return_secret_base64", "")):
        if secret:
            public(value, secret)
    return value


@suite.case("recipient_exact_real_code_and_independently_signed_legacy_stale_hints_are_pure", "guided onboarding11 verification1")
def _():
    f = recipient_fixture(); inviter, recipient, parent, code, signer = (f[k] for k in ("inviter", "recipient", "parent", "code", "signer"))
    # A live inviter independently schedules automatic return work. Stop it
    # before the baseline: preview must verify the introduction entirely offline.
    inviter.stop()
    before = state_snapshot(recipient); source_before = records(inviter)
    first = preview(recipient, parent, code)
    check(preview(recipient, parent, code) == first, "same code/context changed preview or hash")
    check(state_snapshot(recipient) == before, "inspection changed recipient logical records or private files")
    check(records(inviter) == source_before, "offline inspection changed inviter logical records")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0)); listener.listen(); listener.settimeout(0.1)
        endpoint = f"127.0.0.1:{listener.getsockname()[1]}"
        hints = {"quic_addresses": ["[::1]:9"], "bootstrap_addresses": [endpoint], "relays": []}
        contacts = [signer.contact(f["network"]["context_id"], recipient.now(), seq, hints=hints) for seq in (0, 18446744073709551615)]
        def legacy_payload(payload):
            payload.pop("return_secret_base64", None); payload["contacts"] = contacts
            payload["helpers"] = [{"address": endpoint, "public_key": signer.public}]
        legacy = signer.invitation(code, payload_changes=legacy_payload)
        observed = preview(recipient, parent, legacy)
        check(observed["review"]["invitation"]["automatic_return"] is False, "legacy no-return introduction was rejected or gained a return secret")
        check([c["sequence"] for c in observed["review"]["contacts"]] == ["0", "18446744073709551615"], "u64 contact sequences were rounded")
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            connection = None
        if connection:
            connection.close()
        check(connection is None, "read-only preview attempted bootstrap/helper network I/O")
    check(state_snapshot(recipient) == before, "legacy/stale preview retained code, contacts or selected an identity")


@suite.case("recipient_signed_wire_refusals_strict_input_and_expiry_remain_private_and_pure", "guided onboarding11 verification2")
def _():
    f = recipient_fixture(); h, parent, signer, original = (f[k] for k in ("recipient", "parent", "signer", "code"))
    def initial(payload):
        payload["contacts"] = [signer.contact(f["network"]["context_id"], h.now(), 1)]
    valid = signer.invitation(original, payload_changes=initial)
    preview(h, parent, valid)
    before = state_snapshot(h)
    bad_signature = b64url_json(valid, "psi2-")
    bad_signature["signature"] = base64.b64encode(bytes(64)).decode()
    invalid = ["psi2-" + base64.urlsafe_b64encode(compact(bad_signature)).decode().rstrip("="),
               " " + valid, valid + "\n", "psi2-", "psi2-" + "A" * 32764]
    def descriptor_mismatch(payload):
        descriptor = payload["descriptor"]
        encoded = isinstance(descriptor, str)
        if encoded:
            descriptor = json.loads(base64.b64decode(descriptor))
        descriptor["network_id"] = "net_" + "0" * 64
        payload["descriptor"] = base64.b64encode(compact(descriptor)).decode() if encoded else descriptor
    invalid.append(signer.invitation(valid, payload_changes=descriptor_mismatch))
    invalid.append(signer.invitation(valid, envelope_changes=lambda e: e.update(context_id="ctx_" + "0" * 64)))
    invalid.append(signer.invitation(valid, payload_changes=lambda p: p.update(expected_person_public_key="bad-key")))
    invalid.append(signer.invitation(valid, payload_changes=lambda p: p.update(helpers=[{"address": "https://bad.example/path", "public_key": signer.public}])))
    invalid.append(signer.invitation(valid, payload_changes=lambda p: p.update(helpers=[{"address": "127.0.0.1:9", "public_key": "bad-key"}])))
    invalid.append(signer.invitation(valid, payload_changes=lambda p: p.update(contacts=[
        signer.contact(f["network"]["context_id"], h.now(), 2), signer.contact(f["network"]["context_id"], h.now(), 1)])))
    for mode in ("signature", "context", "endpoint", "time"):
        def change(payload, fault=mode):
            options = {"context_id": "ctx_" + "0" * 64} if fault == "context" else {}
            hints = {"quic_addresses": ["[0:0:0:0:0:0:0:1]:9"], "bootstrap_addresses": [], "relays": []} if fault == "endpoint" else None
            contact = signer.contact(options.get("context_id", f["network"]["context_id"]), h.now(), 1, hints=hints,
                                     **({"expires_at": h.now().strftime("%Y-%m-%dT%H:%M:%SZ")} if fault == "time" else {}))
            if fault == "signature":
                contact["signature"] = base64.b64encode(bytes(64)).decode()
            payload["contacts"] = [contact]
        invalid.append(signer.invitation(valid, payload_changes=change))
    payload = json.loads(base64.b64decode(b64url_json(valid, "psi2-")["payload_base64"]))
    invalid.append(signer.invitation(valid, raw_payload=compact(payload).replace(b'"member":', b'"member":"duplicate","member":')))
    for code in invalid:
        preview(h, parent, code, status=400, error="invalid")
    now = h.now().replace(microsecond=0)
    expired = signer.invitation(valid, payload_changes=lambda p: p.update(
        issued_at=(now - timedelta(seconds=3601)).strftime("%Y-%m-%dT%H:%M:%SZ"), expires_at=(now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    future = signer.invitation(valid, payload_changes=lambda p: p.update(
        issued_at=(now + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"), expires_at=(now + timedelta(seconds=3720)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    preview(h, parent, expired, status=409, error="expired")
    preview(h, parent, future, status=403, error="not_yet_valid")
    body = {"context": context(parent), "invitation": original}; encoded = json.dumps(body)
    exact = " " * (65536 - len(encoded.encode())) + encoded
    actual, value = raw_post(h, PREVIEW, exact.encode())
    check(actual == 200, "preview refused exact64KiB request body"); public(value, original)
    duplicate_context = encoded.replace('"project_flow_id":', '"project_flow_id":"duplicate","project_flow_id":')
    for data in ('null', '[]', encoded + ' {}', '{"private":', duplicate_context,
                 '{"context":null,' + encoded[1:], " " + exact,
                 json.dumps({**body, "extra": "PREVIEW_PRIVATE_MARKER"})):
        actual, value = raw_post(h, PREVIEW, data.encode())
        check(actual == 400 and value.get("code") == "invalid", "strict preview request accepted duplicate/extra/trailing/null/bounded JSON")
        public(value, original, "PREVIEW_PRIVATE_MARKER")
    check(state_snapshot(h) == before, "wire/input/expiry refusal changed recipient identity, state or files")


@suite.case("recipient_context_cli_bounds_router_and_no_daemon_boundaries", "guided onboarding11 verification2")
def _():
    f = recipient_fixture(); h, source, parent, code = (f[k] for k in ("recipient", "inviter", "parent", "code"))
    body = {"context": context(parent), "invitation": code}
    before = state_snapshot(h)
    exact = json.dumps(body); exact = " " * (65536 - len(exact.encode())) + exact
    result = h.cli("onboarding", "invitation", "preview", "--stdin", input=exact)
    check(result.ok and result.json == preview(h, parent, code), "private preview CLI/API parity at64KiB")
    public(result.json, code)
    for data in ('null', json.dumps(body) + ' {}', '{"context":null,' + json.dumps(body)[1:],
                 json.dumps({**body, "extra": "PREVIEW_PRIVATE_MARKER"}), " " + exact):
        result = h.cli("onboarding", "invitation", "preview", "--stdin", input=data)
        check(not result.ok, "preview CLI accepted malformed/duplicate/extra/oversized private input")
        for marker in (code, "PREVIEW_PRIVATE_MARKER", context(parent)["project_root"], context(parent)["native_session_id"]):
            check(marker not in result.stdout + result.stderr, "preview CLI echoed private input")
    check(not h.cli("onboarding", "invitation", "preview", input=json.dumps(body)).ok, "preview CLI implicitly consumed stdin")
    check(not h.cli("onboarding", "invitation", "preview", "positional-code").ok, "preview CLI accepted a positional invitation")
    unknown = {**body, "context": {**context(parent), "project_flow_id": "flow_" + "0" * 32}}
    preview(h, parent, code, body=unknown, status=404, error="not_found")
    changed = {**body, "context": {**context(parent), "native_session_id": "different-private-conversation"}}
    preview(h, parent, code, body=changed, status=409, error="review_changed")
    for method in ("GET", "PUT", "DELETE"):
        actual, value = h.api(method, PREVIEW, body if method != "GET" else None)
        check(actual in (404, 405), "wrong preview method was accepted"); public(value, code)
    check(state_snapshot(h) == before, "CLI/context/method observation mutated recipient")
    if source.process is None:
        source.start()
    for local, remote in ((h, source), (source, h)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    actual, agent = h.api("POST", "/v1/agents", {"name": "preview-boundary-fixture", "owner": "fixture"})
    check(actual == 201, "preview scoped-boundary agent fixture failed")
    attached = h.ok("session", "attach", "--agent", agent["id"], "--integration", "fixture")
    credential = h.ok("adapter", "create", "--session", attached["id"], "--expires-at", (h.now() + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    adapter = Adapter(h, agent, attached["id"], credential)
    actual, _ = adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id, "session_id": adapter.session_id, "instance_id": adapter.instance})
    check(actual == 200, "preview scoped-boundary connection fixture failed")
    actual, value = adapter.call("POST", PREVIEW, body)
    check(actual == 404, "scoped adapter exposed recipient preview"); public(value, code)
    probe = subprocess.run([str(suite.probe_bin), "--state", str(source.state), "--address", h.peer_address,
                            "--alpn", "peerspan-peer/1", "--method", "POST", "--path", PREVIEW, "--body-stdin"],
                           input=json.dumps(body).encode(), capture_output=True, timeout=15)
    check(probe.returncode == 0 and json.loads(probe.stdout).get("status") == 404, "authenticated peer exposed recipient preview")
    check(code not in probe.stdout.decode(errors="replace") + probe.stderr.decode(errors="replace"), "peer refusal echoed code")
    adapter.stop()
    bootstrap = host("preview-bootstrap")
    cert, key = suite.work / "preview-boundary-cert.pem", suite.work / "preview-boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=preview-boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    data = json.dumps(body).encode()
    with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
        with tls.wrap_socket(raw, server_hostname="peerspan") as stream:
            stream.sendall((f"POST {PREVIEW} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data)
            response = http.client.HTTPResponse(stream); response.begin(); payload = response.read()
            check(response.status == 404 and code.encode() not in payload, "bootstrap exposed recipient preview/code")
    h.ok("session", "detach", parent["review"]["session_id"])
    before = state_snapshot(h)
    preview(h, parent, code, status=409, error="review_changed")
    check(state_snapshot(h) == before, "detached-parent preview repaired attachment")
    newer = project(h, "replacement-preview", root=parent["review"]["project_root"], native=parent["review"]["native_session_id"],
                    replace=parent["flow_id"], agent=parent["review"]["agent"])
    before = state_snapshot(h)
    preview(h, parent, code, status=409, error="review_changed")
    preview(h, newer, code)
    check(state_snapshot(h) == before, "replacement context preview mutated project/identity")
    h.stop(); absent = suite.host("preview-absent", start=False); shutil.rmtree(absent.state)
    for stopped in (h, absent):
        before_files = file_state(stopped.root)
        failed = stopped.cli("onboarding", "invitation", "preview", "--stdin", input=json.dumps({"context": context(newer), "invitation": code}))
        check(not failed.ok and code not in failed.stdout + failed.stderr, "unavailable preview CLI succeeded or leaked code")
        check(file_state(stopped.root) == before_files, "unavailable preview created daemon/state/identity files")


suite.finish()
