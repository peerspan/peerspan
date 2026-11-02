#!/usr/bin/env python3
"""Exact first-original owner consent: guided contract section16.

Independent real hosts, public APIs/CLI, ordinary typed signing and documented
storage observations; no production imports or fabricated protocol/authority
rows. Only a schema-only ABORT trigger on an ordinary intent approval update
mutates SQLite. Offline, empty-advertisement fixtures isolate read purity from
mailbox workers; a separate live ceremony supplies original SSH signatures via
the existing advanced signing boundary, never a guided route. Missing/pruned/
corrupt retained evidence and the smaller expiry/after-commit race intervals
remain source/fault evidence where no public deterministic fixture exists.
No original-key import, membership, access or model receipt is inferred from
recorded approval. Original14 join and212 native cases remain unchanged.
"""
import base64
import hashlib
import http.client
import json
import math
import re
import socket
import sqlite3
import ssl
import subprocess
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, commit,
                     create_network, finalize, link_view, parse_time, pull_until,
                     rfc3339, select, ssh_key, ssh_public_base64, wait_for, wait_linked)

suite = Suite("owner_onboarding", __doc__)
BASE = "/v1/onboarding/join-flows"
PROJECT = "/v1/onboarding/project-flows"
EFFECTS = {"approve_owner_intent": True, "authorize_original_signature": True,
           "authorize_bounded_owner_finalization": True,
           "auto_select_single_offer_after_signature": True,
           "publish_owner_offer_after_signature": True,
           "grant_membership": False, "grant_agent_access": False,
           "approve_network_administrator": False, "commit_request": False,
           "share_files": False, "share_conversation": False, "capability_calls": False}
TOP = {"version", "host_id", "flow_id", "join_review_id", "context", "observed_at", "request", "owner"}
REVIEW = {"version", "kind", "host_id", "context", "flow_id", "join_review_id", "request_id", "intent_id",
          "network", "member", "person_public_key", "host_public_key", "device_public_key",
          "proposed_owner_offer_id", "scopes", "not_after", "expires_at", "effects"}
shared = {}

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def digest(domain, value):
    body = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return "review_" + hashlib.sha256(domain.encode() + b"\n" + body).hexdigest()


def host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    transport = h.root / "transport.json"
    transport.write_bytes(compact({"format": 1, "advertise_bootstrap": [], "advertise_quic": [],
                                  "rendezvous": [], "relays": [], "publish_contacts": False}))
    transport.chmod(0o600); h.extra_args = ["--transport-config", transport]
    return h.start()


def get(h, path):
    status, value = h.api("GET", path)
    check(status == 200, f"{h.name}: observation HTTP {status}")
    return value


def db_path(h):
    matches = []
    for p in h.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{p}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                matches.append(p)
    check(len(matches) == 1, "expected one host database")
    return matches[0]


def records(h):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True, timeout=5)) as db, db:
        db.execute("BEGIN")
        result = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                  "$version": db.execute("PRAGMA user_version").fetchone()}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            result[name] = tuple(sorted(db.execute('SELECT * FROM "' + name.replace('"', '""') + '"'), key=repr))
        return result


def without(value, *keys):
    return {key: item for key, item in value.items() if key not in keys}


def private_files(root):
    # Durable DB content is compared logically. WAL/SHM are mutable read locks
    # and checkpoint bookkeeping and can be created by our own read connections.
    result = {}
    for p in root.rglob("*"):
        if any(str(p).endswith(suffix) and str(p)[:-len(suffix)].endswith(".db") and Path(str(p)[:-len(suffix)]).is_file()
               for suffix in ("-wal", "-shm")):
            continue
        result[str(p.relative_to(root))] = (p.lstat().st_mode,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not str(p).endswith(".db") else None)
    return result


def project(h, name, *, replace=None, old=None):
    body = {"project_root": old["review"]["project_root"] if old else str(suite.work / ("private " + name)),
            "native_session_id": old["review"]["native_session_id"] if old else "private-conversation-" + name,
            "integration": "claude-code", "agent": {"kind": "new", "name": 'Agent "東京" ' + name, "owner": "Owner é"}}
    if replace:
        body["replace_flow_id"] = replace
    status, flow = h.api("POST", PROJECT, body)
    check(status == 201, f"project prepare HTTP {status}")
    status, flow = h.api("POST", PROJECT + "/" + flow["flow_id"] + "/decision", {
        **{key: body[key] for key in ("project_root", "native_session_id", "integration")},
        "review_id": flow["review_id"], "decision": "approve"})
    check(status == 200 and flow["state"] == "attached", "public parent attachment failed")
    return flow


def context(parent):
    return {"project_flow_id": parent["flow_id"], "project_review_id": parent["review_id"],
            **{key: parent["review"][key] for key in ("project_root", "native_session_id", "integration")}}


def advance_to(h, moment):
    h.clock.set(math.ceil((moment - datetime.now(timezone.utc)).total_seconds()))


def raw_post(h, path, data):
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=10)
    try:
        connection.request("POST", path, body=data, headers={"Content-Type": "application/json"})
        response = connection.getresponse(); body = response.read()
        return response.status, json.loads(body) if body else None
    finally:
        connection.close()


def progress_transport_host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    config = h.root / "transport.json"
    config.write_bytes(compact({"format": 1, "advertise_bootstrap": [f"127.0.0.1:{h.bootstrap_port}"], "advertise_quic": [h.peer_address],
                               "rendezvous": [], "relays": [], "publish_contacts": False})); config.chmod(0o600)
    h.extra_args = ["--transport-config", config]
    return h.start()


def public(value, *secrets):
    text = json.dumps(value, ensure_ascii=False, default=str)
    for marker in ('psi2-', 'psl2-', 'token_', 'return_secret', 'secret_base64',
                   'payload_base64', 'template_base64', 'message_base64',
                   'request_packet_base64', 'signing_requests', '"signature"',
                   '"seed"', 'admin.sock', 'adapter.sock', *secrets):
        check(not marker or marker not in text, "owner view/error/activity exposed private code, signing material or diagnostics")


def source():
    if not shared:
        issuer = host("issuer")
        network = create_network(issuer, 'Owner consent "é東京" network', "issuer")
        key = ssh_key(suite.work, "independent-original")
        person = ssh_public_base64(key)
        status, invitation = issuer.api("POST", f"/v2/networks/{network['id']}/invitations", {
            "member": 'New original "é東京"', "expected_person_public_key": person,
            "expires_at": rfc3339(issuer.now() + timedelta(hours=1))})
        check(status == 201, "real signed invitation fixture")
        issuer.stop()
        shared.update(issuer=issuer, network=network, key=key, person=person, code=invitation["invitation"])
    return shared


def join(h, parent, code, person, *, publish=True):
    status, flow = h.api("POST", BASE, {"context": context(parent), "invitation": code, "person_public_key": person})
    check(status == 201 and flow["state"] == "review", f"real join review HTTP {status}")
    if publish:
        status, flow = h.api("POST", BASE + "/" + flow["flow_id"] + "/decision", {
            "context": context(parent), "review_id": flow["review_id"], "decision": "approve", "invitation": code})
        check(status == 200 and flow["state"] == "requested", f"real request publication HTTP {status}")
    return flow


def fixture(name):
    state = source(); h = host(name); parent = project(h, name)
    return h, parent, join(h, parent, state["code"], state["person"])


def path(flow, action):
    return BASE + "/" + flow["flow_id"] + "/owner/" + action


def payload(flow, owner=None):
    result = {"context": flow["review"]["context"], "join_review_id": flow["review_id"]}
    if owner is not None:
        result["owner_review_id"] = owner["owner"]["review_id"]
    return result


def intent(h, intent_id):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?", (intent_id,)).fetchone()
    check(row is not None, "review references no ordinary durable intent")
    return {"network_id": row[0], "context_id": row[1], "kind": row[2], "record": json.loads(row[3]), "secret": row[4]}


def pending(h, rid):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT record,secret FROM dec_pending WHERE request_id=?", (rid,)).fetchone()
    check(row is not None, "ordinary request vanished")
    return json.loads(row[0]), row[1]


def packet_message(packet):
    # Wire9.2: semantic packet message excludes every signature.
    fields = ["peerspan-decentralized-packet-v1", packet["context_id"], packet["request_id"], packet["role"],
              packet["writer_host_public_key"], packet["signer_public_key"], packet["person_public_key"],
              packet["issuer_id"], packet["authority_signature_format"],
              hashlib.sha256(base64.b64decode(packet["payload_base64"], validate=True)).hexdigest()]
    return "\n".join(fields).encode()


def packet_id(packet):
    return "dpk_" + hashlib.sha256(packet_message(packet)).hexdigest()


def validate(h, flow, value, *, owner_required=True):
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1,
          "exact owner wrapper shape/version")
    check(value["host_id"] == h.id and value["flow_id"] == flow["flow_id"] and
          value["join_review_id"] == flow["review_id"] and value["context"] == flow["review"]["context"],
          "owner wrapper changed exact host/publication/context binding")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]) and
          abs((parse_time(value["observed_at"]) - h.now()).total_seconds()) < 5, "guarded whole-second observation time")
    rid = flow["outcome"]["request_id"]
    check(value["request"] == get(h, "/v2/link/requests/" + rid), "owner response is not exact ordinary LINK_VIEW")
    if value["owner"] is None:
        check(not owner_required, "missing prepared owner review")
        public(value); return
    owner = value["owner"]
    check(set(owner) == {"review_id", "review", "state", "next_action"}, "exact owner object shape")
    review = owner["review"]
    check(set(review) == REVIEW and type(review["version"]) is int and review["version"] == 1 and
          review["kind"] == "approve_new_original_owner", "exact new-original review shape")
    nested = flow["review"]["invitation"]
    check(review["host_id"] == h.id and review["flow_id"] == flow["flow_id"] and review["join_review_id"] == flow["review_id"] and
          review["context"] == flow["review"]["context"] and review["request_id"] == rid,
          "review changed exact consent context/request")
    check(review["network"] == nested["network"] and review["member"] == nested["invitation"]["member"] and
          review["person_public_key"] == flow["review"]["person_public_key"] and review["host_public_key"] == h.public_key and
          review["device_public_key"] == value["request"]["device_public_key"], "review changed signed identity/descriptor/label")
    check(re.fullmatch(r"dint_[0-9a-f]{32}", review["intent_id"]) and re.fullmatch(r"dpk_[0-9a-f]{64}", review["proposed_owner_offer_id"]),
          "malformed ordinary intent/proposed packet reference")
    check(type(review["scopes"]) is int and review["scopes"] == 7 and review["effects"] == EFFECTS and
          all(type(item) is bool for item in review["effects"].values()), "owner review widened authority/effects")
    record = intent(h, review["intent_id"])["record"]
    check(parse_time(review["not_after"]) == parse_time(value["request"]["created_at"]) + timedelta(days=7), "fixed signed-request seven-day target lifetime")
    check(parse_time(review["expires_at"]) == min(parse_time(value["request"]["expires_at"]), parse_time(record["created_at"]) + timedelta(minutes=15)),
          "owner review extended its immutable decision deadline")
    check(owner["review_id"] == digest("peerspan-onboarding-original-owner-review-v1", review), "canonical recursive UTF-8 owner digest")
    actions = {"review": "approve_owner_intent", "cancelled": "inspect_join_progress", "expired": "inspect_join_progress",
               "invalidated": "inspect_join_progress"}
    if owner["state"] == "approved":
        expected = "provide_original_signature" if value["request"]["owner_offer_id"] == "-" else "follow_join_progress"
    else:
        check(owner["state"] in actions, "unknown owner state")
        expected = actions[owner["state"]]
    check(owner["next_action"] == expected, "owner state/action claims a completed stage or omits next consent")
    public(value)


def owner(h, flow, action, prepared=None, *, status=200, error=None, body=None):
    actual, value = h.api("POST", path(flow, action), body if body is not None else payload(flow, prepared if action == "approve" else None))
    check(actual == status, f"{action} HTTP {actual}, want {status}")
    if error:
        check(isinstance(value, dict) and value.get("code") == error, f"{action} code {value.get('code') if isinstance(value, dict) else None}, want {error}")
    if actual == 200:
        validate(h, flow, value, owner_required=action != "lookup")
    public(value)
    return value


def settled(h):
    # Approval permits subsequent host-owned signing. Observe that maintenance
    # independently before attributing any state change to a pure retry/read.
    previous = records(h)
    def stable():
        nonlocal previous
        current = records(h); same = current == previous; previous = current
        return current if same else None
    time.sleep(0.1)
    return wait_for(stable, timeout=3, interval=0.1, message="quiescent ordinary host-owned maintenance")


def pure(h, flow, action, expected, prepared=None):
    before = settled(h); files, home = private_files(h.state), private_files(h.home)
    value = owner(h, flow, action, prepared)
    check(value["owner"] == expected["owner"], f"{action} changed fixed owner terms/state")
    check(records(h) == before and private_files(h.state) == files and private_files(h.home) == home,
          f"read-only {action} changed logical records/private files")
    return value


@suite.case("exact_pure_lookup_and_fixed_unapproved_original_intent", "guided onboarding16 verification1")
def _():
    h, parent, flow = fixture("exact")
    before, files, home = settled(h), private_files(h.state), private_files(h.home)
    empty = owner(h, flow, "lookup")
    check(empty["owner"] is None and records(h) == before and private_files(h.state) == files and private_files(h.home) == home,
          "lookup prepared an intent, wrote private data or selected an identity")
    rid = flow["outcome"]["request_id"]; old_pending, secret = pending(h, rid)
    prepared = owner(h, flow, "prepare"); review = prepared["owner"]["review"]
    check(prepared["owner"]["state"] == "review", "prepare approved owner consent")
    check(without(records(h), "dec_intents", "dec_pending", "dec_clock") == without(before, "dec_intents", "dec_pending", "dec_clock"),
          "prepare wrote registry/network/access/provider/events/extra secret store")
    check(private_files(h.state) == files and private_files(h.home) == home, "prepare wrote keys or duplicate private files")
    ordinary = intent(h, review["intent_id"]); record = ordinary["record"]
    check(ordinary["kind"] == "owner" and ordinary["secret"] is None and ordinary["network_id"] == review["network"]["id"] and
          ordinary["context_id"] == review["network"]["context_id"], "owner consent did not reuse ordinary secret-free intent")
    check(record["provider"] == {"kind": "original", "signer_public_key": review["person_public_key"], "signature_format": "sshsig", "lease_id": "-"} and
          record["root_state_id"] == "-" and record["scopes"] == 7 and record["not_after"] == review["not_after"], "wrong original/profile/provider terms")
    check(record["approved"] is False and record["approved_at"] == "-" and record["signatures"] == [] and record["completed"] is False and
          record["result_base64"] == "-", "unapproved preparation signed/completed/published work")
    templates = [t for t in record["templates"] if t["object_type"] == "owner_offer_packet"]
    check(len(templates) == 1, "expected one immutable first owner offer template")
    template = json.loads(base64.b64decode(templates[0]["template_base64"], validate=True))
    proposed = json.loads(base64.b64decode(template["payload_base64"], validate=True))
    check(packet_id(template) == review["proposed_owner_offer_id"] and template["authority_signature"] == "-" and
          template["device_signature"] == "-" and template["authority_signature_format"] == "sshsig" and template["issuer_id"] == "-" and
          template["signer_public_key"] == review["person_public_key"], "review did not bind the unsigned original possession template")
    check(proposed["root_state_id"] == proposed["person_lease_id"] == "-" and proposed["issuer_lease_ids"] == [] and proposed["mode"] == "new" and
          proposed["member"] == review["member"] and proposed["scopes"] == 7 and proposed["not_after"] == review["not_after"], "possession-only offer granted existing authority")
    current, same_secret = pending(h, rid)
    check(current["owner_intent_id"] == review["intent_id"] and set(current["roles"]) == {"requester", "owner"} and same_secret == secret and
          without(current, "roles", "owner_intent_id") == without(old_pending, "roles", "owner_intent_id"), "prepare replaced request pairing/device/packet/material")
    check(prepared["request"]["owner_offer_id"] == "-" and not prepared["request"]["selection_approved"] and not prepared["request"]["commit_approved"] and
          get(h, "/v2/networks") == [], "proposed owner offer became admission or later consent")
    pure(h, flow, "prepare", prepared); pure(h, flow, "lookup", prepared)
    public(get(h, "/v1/activity?limit=1000"), source()["code"])


@suite.case("atomic_approval_lost_response_and_historical_read_only_recovery", "guided onboarding16 verification2")
def _():
    h, parent, flow = fixture("recovery")
    prepared = owner(h, flow, "prepare"); iid = prepared["owner"]["review"]["intent_id"]
    before = intent(h, iid)["record"]
    conn = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=10)
    try:
        conn.request("POST", path(flow, "approve"), body=compact(payload(flow, prepared)), headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        check(response.status == 200, f"committed owner approval header HTTP {response.status}")
        # Discard response body; public lookup must recover the one consent.
    finally:
        conn.close()
    approved = owner(h, flow, "lookup")
    check(approved["owner"]["state"] == "approved" and approved["owner"]["review"] == prepared["owner"]["review"] and
          approved["owner"]["review_id"] == prepared["owner"]["review_id"], "lost response lost or changed exact approval")
    record = intent(h, iid)["record"]
    check(record["approved"] is True and record["approved_at"] != "-" and record["created_at"] == before["created_at"] and
          record["expires_at"] == before["expires_at"] and record["provider"] == before["provider"], "approval is not the same durable ordinary intention")
    check(approved["request"]["owner_offer_id"] == "-" and not approved["request"]["selection_approved"] and not approved["request"]["commit_approved"] and
          get(h, "/v2/networks") == [], "approval supplied original possession/admission/final consent")
    pure(h, flow, "approve", approved, prepared); pure(h, flow, "lookup", approved)
    h.restart(kill=True)
    check(get(h, PROJECT + "/" + parent["flow_id"])["state"] == "invalidated", "restart fixture retained attached parent")
    approved = pure(h, flow, "approve", approved, prepared)
    advance_to(h, parse_time(prepared["owner"]["review"]["expires_at"]) + timedelta(seconds=1))
    # The review expired and parent detached, but retained approved consent is historical.
    approved = owner(h, flow, "lookup")
    check(approved["owner"]["state"] == "approved" and approved["owner"]["review"] == prepared["owner"]["review"], "expired approved consent was discarded")
    pure(h, flow, "approve", approved, prepared); pure(h, flow, "prepare", approved); pure(h, flow, "lookup", approved)
    wrong = {**payload(flow, prepared), "owner_review_id": "review_" + "f" * 64}
    owner(h, flow, "approve", prepared, status=409, error="review_changed", body=wrong)
    check(intent(h, iid)["record"]["approved_at"] == record["approved_at"], "historical retry recorded a second approval")


@suite.case("exact_binding_parent_cancel_expiry_and_incompatible_profile_refusals", "guided onboarding16 verification2")
def _():
    h, parent, flow = fixture("refuse")
    prepared = owner(h, flow, "prepare"); before = settled(h)
    for patch in ({"join_review_id": "review_" + "1" * 64}, {"owner_review_id": "review_" + "2" * 64},
                  {"context": {**payload(flow)["context"], "native_session_id": "another-conversation"}},
                  {"context": {**payload(flow)["context"], "project_root": str(suite.work / "another-root")}}):
        owner(h, flow, "approve", prepared, status=409, error="review_changed", body={**payload(flow, prepared), **patch})
    check(without(records(h), "dec_clock") == without(before, "dec_clock") and intent(h, prepared["owner"]["review"]["intent_id"])["record"]["approved"] is False,
          "changed binding recorded approval or side effects")
    h.ok("session", "detach", parent["review"]["session_id"])
    invalidated = owner(h, flow, "lookup"); check(invalidated["owner"]["state"] == "invalidated", "detached parent did not invalidate unapproved review")
    owner(h, flow, "approve", prepared, status=409, error="review_changed")
    expired, _, f2 = fixture("expired"); p2 = owner(expired, f2, "prepare")
    advance_to(expired, parse_time(p2["owner"]["review"]["expires_at"]))
    check(owner(expired, f2, "lookup")["owner"]["state"] == "expired", "exact deadline remained actionable")
    owner(expired, f2, "approve", p2, status=409, error="review_expired")
    cancelled, _, f3 = fixture("cancelled"); p3 = owner(cancelled, f3, "prepare")
    status, stopped = cancelled.api("POST", "/v2/link/requests/" + f3["outcome"]["request_id"] + "/cancel", {})
    check(status == 200 and stopped["state"] == "cancelled", "ordinary public cancellation fixture")
    check(owner(cancelled, f3, "lookup")["owner"]["state"] == "cancelled", "cancelled review remained actionable")
    actual, refused = cancelled.api("POST", path(f3, "approve"), payload(f3, p3))
    check(actual == 409, "cancelled request accepted owner approval"); public(refused)
    unsupported, p4, f4 = fixture("profile")
    status, ordinary = unsupported.api("POST", "/v2/link/requests", {"mode": "new", "network_id": f4["outcome"]["network_id"],
        "person_public_key": source()["person"], "migration_proposal_id": "-", "contact_invitation": source()["code"], "helpers": []})
    check(status == 200 and ordinary["request_id"] == f4["outcome"]["request_id"], "ordinary exact code retrieval fixture")
    request = get(unsupported, "/v2/link/requests/" + ordinary["request_id"])
    status, preview = unsupported.api("POST", "/v2/link/approvals", {
        "code": ordinary["display_code"], "network_id": request["network_id"], "person_public_key": request["person_public_key"],
        "provider_id": request["person_public_key"], "signature_format": "sshsig", "scopes": 1,
        "not_after": rfc3339(parse_time(request["created_at"]) + timedelta(days=7)), "expected_host_public_key": request["host_public_key"],
        "expected_device_public_key": request["device_public_key"], "approve": False})
    check(status == 200 and preview["review"]["scopes"] == 1, "public incompatible unapproved-profile fixture")
    before = settled(unsupported)
    owner(unsupported, f4, "prepare", status=409, error="owner_review_unavailable")
    check(without(records(unsupported), "dec_clock") == without(before, "dec_clock"), "guided preparation overwrote incompatible ordinary proposal")


@suite.case("schema_only_abort_rolls_back_exact_ordinary_approval", "guided onboarding16 verification3")
def _():
    h, _, flow = fixture("rollback"); prepared = owner(h, flow, "prepare")
    iid = prepared["owner"]["review"]["intent_id"]
    check(re.fullmatch(r"dint_[0-9a-f]{32}", iid), "unsafe trigger fixture intent")
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute("CREATE TRIGGER conformance_owner_abort BEFORE UPDATE OF record ON dec_intents "
                   "WHEN OLD.intent_id='" + iid + "' AND json_extract(OLD.record,'$.approved')=0 "
                   "AND json_extract(NEW.record,'$.approved')=1 BEGIN SELECT RAISE(ABORT,'conformance'); END")
    try:
        before, files, home = settled(h), private_files(h.state), private_files(h.home)
        actual, denied = h.api("POST", path(flow, "approve"), payload(flow, prepared))
        check(actual >= 400, "injected ordinary approved-intent failure was swallowed"); public(denied)
        check(records(h) == before and private_files(h.state) == files and private_files(h.home) == home,
              "failed approval leaked approval/clock/template/signature/frame/event or private-file writes")
        recovered = owner(h, flow, "lookup")
        check(recovered["owner"] == prepared["owner"] and intent(h, iid)["record"]["approved"] is False,
              "ABORT left an approved mirror or unrecoverable ordinary proposal")
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute("DROP TRIGGER conformance_owner_abort")
    approved = owner(h, flow, "approve", prepared)
    check(approved["owner"]["state"] == "approved" and approved["owner"]["review"]["intent_id"] == iid,
          "exact retry after rollback did not approve original intention")
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        count = db.execute("SELECT count(*) FROM dec_intents WHERE kind='owner'").fetchone()[0]
    check(count == 1, "rollback/retry created duplicate ordinary owner intentions")


@suite.case("strict_private_api_cli_methods_and_credential_boundaries", "guided onboarding16 verification2")
def _():
    h, parent, flow = fixture("boundary"); prepared = owner(h, flow, "prepare")
    for action in ("prepare", "lookup", "approve"):
        body = payload(flow, prepared if action == "approve" else None)
        encoded = compact(body); maximum = encoded + b" " * (65536 - len(encoded))
        if action != "approve":
            actual, response = raw_post(h, path(flow, action), maximum)
            check(actual == 200 and response["owner"] == prepared["owner"], f"{action} exact64KiB API boundary")
            result = h.cli("onboarding", "join", "owner", action, "--stdin", input=json.dumps({"flow_id": flow["flow_id"], **body}), timeout=10)
            check(result.ok and result.json["owner"] == prepared["owner"], f"literal private CLI {action} parity"); public(result.stdout)
        context_json = compact(body["context"])
        duplicate = b'{"context":' + context_json + b',"context":' + context_json + encoded[1 + len(b'"context":') + len(context_json):]
        malformed = [encoded + b"{}", b"null", b"[]", b"{", maximum + b" ", duplicate,
                     encoded.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
                     compact({**body, "context": None}), compact({**body, "join_review_id": "review_bad"}),
                     compact({**body, "context": {**body["context"], "unknown": "private-marker"}})]
        for field in ("path", "invitation", "scopes", "provider_id", "not_after", "private_key", "signatures"):
            malformed.append(compact({**body, field: "private-marker"}))
        if action != "approve":
            malformed.append(compact({**body, "owner_review_id": prepared["owner"]["review_id"]}))
        else:
            malformed.extend([compact(without(body, "owner_review_id")), compact({**body, "owner_review_id": None})])
        before = settled(h)
        for index, raw in enumerate(malformed):
            actual, denied = raw_post(h, path(flow, action), raw)
            check(actual == 400 and denied.get("code") == "invalid", f"{action} malformed body variant{index}: HTTP {actual}"); public(denied, "private-marker")
            # CLI has exactly the API shape plus flow_id. Preserve malformed
            # JSON/duplicates instead of round-tripping through a normalizer.
            cli_raw = b'{"flow_id":' + compact(flow["flow_id"]) + b',' + raw[1:] if raw.startswith(b"{") else raw
            result = h.cli("onboarding", "join", "owner", action, "--stdin", input=cli_raw.decode(), timeout=10)
            check(not result.ok, f"CLI {action} accepted malformed/duplicate/trailing/oversized input variant{index}")
            public(result.stdout + result.stderr, "private-marker")
        check(records(h) == before, f"malformed {action} changed consent/private state")
        for method in ("GET", "PUT", "DELETE"):
            actual, denied = h.api(method, path(flow, action))
            check(actual == 405, f"owner {action} accepted alternate method {method}: HTTP {actual}"); public(denied)
        result = h.cli("onboarding", "join", "owner", action, input=json.dumps({"flow_id": flow["flow_id"], **body}), timeout=10)
        check(not result.ok, f"CLI {action} consumed stdin without --stdin"); public(result.stdout + result.stderr)
    # Exact CLI byte ceiling includes its extra flow_id field.
    cli_body = compact({"flow_id": flow["flow_id"], **payload(flow)})
    result = h.cli("onboarding", "join", "owner", "prepare", "--stdin", input=(cli_body + b" " * (65536 - len(cli_body))).decode(), timeout=10)
    check(result.ok and result.json["owner"] == prepared["owner"], "private CLI exact64KiB ceiling")
    other_flow = {**flow, "flow_id": "flow_" + "0" * 32}
    for action in ("prepare", "lookup", "approve"):
        owner(h, other_flow, action, prepared, status=404, error="not_found")
    p2 = project(h, "nonrequested")
    unrequested = join(h, p2, source()["code"], source()["person"], publish=False)
    for action in ("prepare", "lookup", "approve"):
        owner(h, unrequested, action, prepared, status=409, error="state_conflict")
    credential = h.ok("adapter", "create", "--session", parent["review"]["session_id"], "--expires-at", rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, parent["review"]["agent"], parent["review"]["session_id"], credential)
    actual, _ = adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id, "session_id": adapter.session_id, "instance_id": adapter.instance})
    check(actual == 200, "real scoped credential boundary fixture")
    peer = host("peer")
    for local, remote in ((h, peer), (peer, h)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    bootstrap = host("bootstrap")
    cert, key = suite.work / "owner-cert.pem", suite.work / "owner-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=owner-boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    for action in ("prepare", "lookup", "approve"):
        endpoint, body = path(flow, action), payload(flow, prepared if action == "approve" else None)
        actual, denied = adapter.call("POST", endpoint, body)
        check(actual == 404, f"scoped adapter exposed owner {action}: HTTP {actual}"); public(denied)
        result = subprocess.run([str(suite.probe_bin), "--state", str(peer.state), "--address", h.peer_address, "--alpn", "peerspan-peer/1",
                                 "--method", "POST", "--path", endpoint, "--body-stdin"], input=compact(body), capture_output=True, timeout=10)
        check(result.returncode == 0 and json.loads(result.stdout)["status"] == 404, f"authenticated peer exposed owner {action}")
        data = compact(body)
        with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname="peerspan") as stream:
                stream.sendall((f"POST {endpoint} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, f"bootstrap exposed owner {action}: HTTP {response.status}")
    # Approval still needs its explicit private CLI action and exact digest.
    result = h.cli("onboarding", "join", "owner", "approve", "--stdin", input=json.dumps({"flow_id": flow["flow_id"], **payload(flow, prepared)}), timeout=10)
    check(result.ok and result.json["owner"]["state"] == "approved", "private CLI exact approval failed"); validate(h, flow, result.json)
    public(result.stdout, source()["code"], adapter.token)
    missing = suite.host("no-daemon", start=False); before = private_files(missing.root)
    for action in ("prepare", "lookup", "approve"):
        result = missing.cli("onboarding", "join", "owner", action, "--stdin", input=json.dumps({"flow_id": flow["flow_id"], **payload(flow, prepared if action == "approve" else None)}), timeout=10)
        check(not result.ok and private_files(missing.root) == before, "owner CLI initialized state or started a daemon")
        public(result.stdout + result.stderr, source()["code"])
    public(get(h, "/v1/activity?limit=1000"), source()["code"], adapter.token)


def sshsig(key, message):
    signed = subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", "peerspan-person-v1"],
                            input=message, check=True, capture_output=True, timeout=5).stdout.decode()
    return "".join(line for line in signed.splitlines() if not line.startswith("-----"))


def sign_ready(h, rid, iid, key):
    """Existing advanced typed API; no key/signature enters a guided endpoint."""
    def ready():
        status, value = h.api("GET", "/v2/link/requests/" + rid + "/approval")
        check(status == 200, f"ordinary approved signing lookup HTTP {status}")
        if any(r["role"] == "authority" for r in value["signing_requests"]):
            return value
        h.cli("link", "resume", rid, timeout=10)
        return None
    value = wait_for(ready, timeout=10, interval=0.2, message="existing original authority signing slot")
    for _ in range(4):
        ready_slots = value["signing_requests"]
        metadata = [(r["object_type"], r["role"], r["format"], r["intent_id"] == iid) for r in ready_slots]
        check(all(r["intent_id"] == iid and r["object_type"] == "owner_offer_packet" and
                  ((r["role"] == "authority" and r["format"] == "sshsig" and r["public_key"] == source()["person"]) or
                   (r["role"] == "host" and r["format"] == "ed25519" and r["public_key"] == h.public_key)) for r in ready_slots),
              f"ordinary signature slot changed original/local-host binding; type/role/format/intent-match={metadata}")
        # Ordinary wrappers may also list its locally owned host slot. Only
        # external authority is signed here; explicit ordinary resume handles
        # the host's own key under its existing approval.
        requests = [r for r in ready_slots if r["role"] == "authority"]
        if not requests:
            return value
        for request in requests:
            template = json.loads(base64.b64decode(request["template_base64"], validate=True))
            check(template["request_id"] == rid and template["person_public_key"] == source()["person"] and
                  template["writer_host_public_key"] == h.public_key and request["object_id"] == packet_id(template) and
                  base64.b64decode(request["message_base64"], validate=True) == packet_message(template),
                  "ordinary external slot is not its exact typed owner packet/message")
        signatures = [{"slot_id": r["slot_id"], "role": r["role"], "signature": sshsig(key, base64.b64decode(r["message_base64"], validate=True))} for r in requests]
        status, value = h.api("POST", "/v2/link/requests/" + rid + "/signed", {"intent_id": iid, "signatures": signatures})
        check(status == 200, f"existing exact original signature submission HTTP {status}")
    check(not any(r["role"] == "authority" for r in value["signing_requests"]), "ordinary original signing did not finish bounded authority batch")
    return value


@suite.case("same_intent_advanced_signing_admin_finalization_commit_and_stable_history", "guided onboarding16 verification4")
def _():
    issuer, h = progress_transport_host("live-issuer"), progress_transport_host("live-joiner")
    network = create_network(issuer, "real owner consent", "issuer")
    parent = project(h, "live-owner"); person = source()["person"]
    status, issued = issuer.api("POST", f"/v2/networks/{network['id']}/invitations", {"member": "new original", "expected_person_public_key": person,
                                      "expires_at": rfc3339(issuer.now() + timedelta(hours=1))})
    check(status == 201, "live real invitation fixture")
    code = issued["invitation"]; flow = join(h, parent, code, person); rid = flow["outcome"]["request_id"]
    # Publish a distinct real request while the host still lacks this network.
    # After first adoption it is no longer eligible for a fresh original offer.
    other_person = ssh_public_base64(ssh_key(suite.work, "other-live-original"))
    status, second_invitation = issuer.api("POST", f"/v2/networks/{network['id']}/invitations", {
        "member": "another new original", "expected_person_public_key": other_person,
        "expires_at": rfc3339(issuer.now() + timedelta(hours=1))})
    check(status == 201, "separate pre-adoption invitation fixture")
    other_flow = join(h, project(h, "other-live"), second_invitation["invitation"], other_person)
    prepared = owner(h, flow, "prepare"); approved = owner(h, flow, "approve", prepared)
    iid = approved["owner"]["review"]["intent_id"]; original = approved["owner"]["review"]
    first_record = intent(h, iid)["record"]; first_review = first_record["review_base64"]
    check(approved["owner"]["state"] == "approved" and approved["request"]["owner_offer_id"] == "-" and get(h, "/v2/networks") == [],
          "guided approval fabricated original possession/admission")
    status, ordinary = h.api("POST", "/v2/link/requests", {"mode": "new", "network_id": network["id"], "person_public_key": person,
                            "migration_proposal_id": "-", "contact_invitation": code, "helpers": []})
    check(status == 200 and ordinary["request_id"] == rid, "advanced pairing retrieval changed guided request")
    reply = ordinary["display_code"]
    sign_ready(h, rid, iid, source()["key"])
    view = pull_until(h, rid, "owner_offer_id", timeout=15)
    if view["state"] == "needs_selection":
        select(h, view)
    view = link_view(h, rid)
    check(view["owner_offer_id"] == original["proposed_owner_offer_id"] and view["state"] == "needs_administrator" and
          view["selection_approved"] and not view["commit_approved"], "original signature did not complete the exact possession offer or separate admin/commit")
    after_signature = owner(h, flow, "lookup")
    check(after_signature["owner"]["review"] == original and after_signature["owner"]["next_action"] == "follow_join_progress", "signature changed guided review/history")
    issuer.ok_incomplete("link", "admit", "--network", network["id"], "--owner-offer", view["owner_offer_id"], "--selection", view["selection_id"],
                         "--person", person, "--expect-host-key", view["host_public_key"], "--expect-device-key", view["device_public_key"],
                         "--code-stdin", "--approve", input=reply + "\n")
    view = pull_until(h, rid, "administrator_offer_id", timeout=20)
    finalize(h, view, source()["key"])
    view = pull_until(h, rid, "owner_finalization_id", timeout=20)
    later_record = intent(h, iid)["record"]
    check(later_record["approved"] is True and later_record["approved_at"] == first_record["approved_at"] and
          later_record["review_base64"] != first_review, "real finalization did not exercise the same intent's changed ordinary review")
    after_finalization = owner(h, flow, "lookup")
    check(after_finalization["owner"]["review"] == original and after_finalization["owner"]["review_id"] == approved["owner"]["review_id"] and
          after_finalization["request"]["commit_approved"] is False, "finalization changed first owner review or supplied requester commit")
    commit(h, view); wait_linked(h, issuer, rid, timeout=20)
    issuer.stop()
    applied = owner(h, flow, "lookup")
    check(applied["request"]["state"] == "linked" and applied["owner"]["state"] == "approved" and
          applied["owner"]["review"] == original, "local application discarded original review/history")
    owner(h, other_flow, "prepare", status=409, error="owner_review_unavailable")
    pure(h, flow, "lookup", applied); pure(h, flow, "prepare", applied); pure(h, flow, "approve", applied, prepared)
    h.restart(kill=True)
    historical = owner(h, flow, "lookup")
    check(historical["owner"] == applied["owner"] and historical["request"]["state"] == "linked", "restart changed historical approval or local application")
    pure(h, flow, "lookup", historical); pure(h, flow, "approve", historical, prepared)
    current, _ = pending(h, rid)
    check(current["owner_intent_id"] == iid and historical["request"]["request_id"] == rid, "later stages replaced original request/intention")
    public(get(h, "/v1/activity?limit=1000"), code, reply)


suite.finish()
