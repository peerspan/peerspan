#!/usr/bin/env python3
"""Exact public-key/publication consent, guided session contract section12.

Independent real hosts and public APIs/CLI; no production imports, original
person-key setup by this flow, fabricated authority or protocol rows. Independent
OpenSSL signatures exercise existing legacy/malformed wire forms only. SQLite
reads observe atomicity and privacy; authorized schema-only ABORT triggers and
stopped-host migration fixtures are the only DB mutations. Empty advertised
hints/offline inviter isolate durable publication/replay from transport workers;
no delivery, possession, admission, access or real-model receipt is claimed.
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, b64url_json, check,
                     create_network, parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for)

suite = Suite("join_onboarding", __doc__)
BASE = "/v1/onboarding/join-flows"
PROJECT = "/v1/onboarding/project-flows"
TABLE = "onboarding_join_flows"
EFFECTS = {"create_identity": False, "create_link_request": True, "publish_request": True,
           "select_owner": False, "grant_membership": False, "grant_agent_access": False,
           "approve_machine": False, "share_files": False, "share_conversation": False, "capability_calls": False}
PREVIEW_EFFECTS = {"verify_contact_signature": True, **{key: False for key in EFFECTS if key != "publish_request"}}
TOP = {"version", "host_id", "flow_id", "review_id", "state", "review", "outcome", "next_action"}
REVIEW = {"version", "kind", "flow_id", "host_id", "context", "agent", "invitation_review_id", "invitation",
          "person_public_key", "expires_at", "effects"}
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


def public(value, *secrets):
    body = json.dumps(value, ensure_ascii=False, default=str)
    for marker in ("psi2-", "psl2-", "return_secret", "payload_base64", "request_packet_base64", "token_", *secrets):
        check(not marker or marker not in body, "public join view/error/activity/table leaked private input or signed bytes")


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


def source():
    if not shared:
        h = host("issuer")
        network = create_network(h, 'Exact "é東京" network', "owner")
        # Explicit original keys belong to the independent caller fixture, not
        # the recipient's identity directory. Only public keys enter this flow.
        key = ssh_key(suite.work, "selected-original")
        person = ssh_public_base64(key)
        status, issued = h.api("POST", f"/v2/networks/{network['id']}/invitations", {
            "member": 'Exact "é東京" member', "expected_person_public_key": person,
            "expires_at": rfc3339(h.now() + timedelta(hours=1))})
        check(status == 201, f"real signed invitation HTTP {status}")
        h.stop()
        shared.update(source=h, network=network, code=issued["invitation"], key=key, person=person, signer=WireSigner())
    return shared


def fixture(name):
    state = source(); h = host(name); parent = project(h, name)
    return h, parent, state["code"], state["person"]


def proposal(parent, code, person, replace=None):
    body = {"context": context(parent), "invitation": code, "person_public_key": person}
    if replace:
        body["replace_flow_id"] = replace
    return body


def validate(h, parent, flow, person):
    check(isinstance(flow, dict) and set(flow) == TOP and flow["version"] == 1 and flow["host_id"] == h.id, "exact public join view")
    review = flow["review"]
    check(set(review) == REVIEW and review["version"] == 1 and review["kind"] == "create_join_request", "exact join review shape")
    check(re.fullmatch(r"flow_[0-9a-f]{32}", flow["flow_id"]) and review["flow_id"] == flow["flow_id"]
          and review["host_id"] == h.id and review["context"] == context(parent), "exact host/project flow binding")
    check(review["agent"] == parent["review"]["agent"] and review["person_public_key"] == person, "changed reviewed metadata/original public key")
    nested = review["invitation"]
    check(review["invitation_review_id"] == digest("peerspan-invitation-preview-v1", nested), "section11 nested digest")
    check(nested["effects"] == PREVIEW_EFFECTS and review["effects"] == EFFECTS, "review effects granted unintended authority")
    check(all(type(value) is bool for value in review["effects"].values()), "non-boolean effect")
    check(flow["review_id"] == digest("peerspan-join-review-v1", review), "canonical recursive UTF-8 join digest")
    check(parse_time(review["expires_at"]) <= parse_time(nested["invitation"]["expires_at"]), "review outlived introduction")
    actions = {"review": "approve_join_request", "declined": "none", "requested": "await_participant_reviews",
               "expired": "review_replacement", "invalidated": "review_replacement", "replaced": "review_replacement"}
    check(flow["state"] in actions and flow["next_action"] == actions[flow["state"]], "state/next action")
    if flow["outcome"] is not None:
        check(set(flow["outcome"]) == {"request_id", "network_id", "context_id", "person_public_key"}, "sanitized immutable public outcome")
        check(flow["outcome"]["network_id"] == nested["network"]["id"] and
              flow["outcome"]["context_id"] == nested["network"]["context_id"] and
              flow["outcome"]["person_public_key"] == person and re.fullmatch(r"link_[0-9a-f]{64}", flow["outcome"]["request_id"]), "wrong ordinary request outcome")
    else:
        check(flow["state"] != "requested", "requested view lacks its outcome")
    public(flow)


def prepare(h, parent, code, person, *, status=201, error=None, body=None, replace=None):
    actual, value = h.api("POST", BASE, body if body is not None else proposal(parent, code, person, replace))
    check(actual == status, f"join prepare HTTP {actual}, want {status}")
    if error:
        check(value.get("code") == error, f"prepare HTTP {actual} code {value.get('code')}, want {error}")
    if status in (200, 201):
        validate(h, parent, value, person)
    public(value, code)
    return value


def decision(flow, code, choice="approve"):
    body = {"context": flow["review"]["context"], "review_id": flow["review_id"], "decision": choice}
    if choice == "approve":
        body["invitation"] = code
    return body


def decide(h, flow, code, choice="approve", *, status=200, error=None, body=None):
    actual, value = h.api("POST", BASE + "/" + flow["flow_id"] + "/decision", body if body is not None else decision(flow, code, choice))
    check(actual == status, f"join decision HTTP {actual}, want {status}")
    if error:
        check(value.get("code") == error, f"decision HTTP {actual} code {value.get('code')}, want {error}")
    if status == 200:
        check(value["review"] == flow["review"] and value["review_id"] == flow["review_id"], "decision changed immutable consent terms")
    public(value, code)
    return value


def observe(h, parent, expected):
    before = records(h)
    status, value = h.api("POST", BASE + "/lookup", {"context": context(parent)})
    check(status == 200 and value == {"version": 1, "host_id": h.id, "context": context(parent), "flow": expected}, "exact retained lookup")
    if expected:
        check(get(h, BASE + "/" + expected["flow_id"]) == expected, "lookup/inspect disagree")
    check(records(h) == before, "read-only join lookup/inspect mutated logical state")
    public(value)


def request_fingerprint(h, request_id):
    # Public storage19.4: scheduling acknowledgments may evolve independently;
    # immutable request/device/nonce/packet plus every encrypted frame must not.
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT deadline,record,secret,terminal_read_cap FROM dec_pending WHERE request_id=?", (request_id,)).fetchone()
        check(row is not None, "ordinary request disappeared")
        record = json.loads(row[1])
        immutable = {key: record[key] for key in ("mode", "migration_proposal_id", "expected_network_id", "expected_context_id",
                     "expected_person_public_key", "device_public_key", "host_public_key", "request_nonce", "request_packet_base64", "carrier_endpoints")}
        frames = tuple(db.execute("SELECT * FROM dec_frames WHERE request_id=? ORDER BY role,writer_key,frame_id", (request_id,)))
        ids = tuple(db.execute("SELECT request_id FROM dec_pending ORDER BY request_id"))
        return row[0], immutable, frames, ids


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


class WireSigner:
    """Independent ordinary wire signatures; no admitted identity is invented."""
    def __init__(self):
        self.key = suite.work / "join-fixture-ed25519.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.key)], check=True, capture_output=True, timeout=5)
        self.key.chmod(0o600)
        der = subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"], check=True, capture_output=True, timeout=5).stdout
        self.public = base64.b64encode(der[-32:]).decode()

    def invitation(self, original, *, change=None):
        envelope = b64url_json(original, "psi2-")
        payload = json.loads(base64.b64decode(envelope["payload_base64"]))
        # Legacy has no automatic return; an explicit advanced CLI can still
        # publish. No contact/helper means no background network scheduling.
        payload.pop("return_secret_base64", None); payload["contacts"] = []; payload["helpers"] = []
        if change:
            change(payload)
        envelope["inviter_host_public_key"] = self.public
        envelope["payload_base64"] = base64.b64encode(compact(payload)).decode()
        message = "\n".join(["peerspan-decentralized-contact-invitation-v1", envelope["context_id"], self.public,
                              hashlib.sha256(base64.b64decode(envelope["payload_base64"])).hexdigest()]).encode()
        path = suite.work / "join-signing-message"; path.write_bytes(message); path.chmod(0o600)
        signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(path)],
                                   check=True, capture_output=True, timeout=5).stdout
        envelope["signature"] = base64.b64encode(signature).decode()
        return "psi2-" + base64.urlsafe_b64encode(compact(envelope)).decode().rstrip("=")


@suite.case("exact_public_review_prepare_resume_lookup_are_pure", "guided onboarding12 verification1")
def _():
    h, parent, code, person = fixture("exact")
    check(h.id != source()["source"].id, "inviter/recipient are not distinct real hosts")
    observe(h, parent, None)
    status, preview = h.api("POST", "/v1/onboarding/invitation-preview", {"context": context(parent), "invitation": code})
    check(status == 200, "real signed introduction failed section11 verification")
    before, files, home = records(h), private_files(h.state), private_files(h.home)
    started = h.now(); flow = prepare(h, parent, code, person)
    check(flow["state"] == "review" and flow["outcome"] is None, "prepare published a request")
    check(flow["review"]["invitation"] == preview["review"] and flow["review"]["invitation_review_id"] == preview["review_id"], "nested preview changed exact public terms")
    deadline = parse_time(flow["review"]["expires_at"])
    check(started.replace(microsecond=0) + timedelta(minutes=15) <= deadline <= h.now().replace(microsecond=0) + timedelta(minutes=15), "fixed first-prepare15minute deadline")
    check(without(records(h), TABLE) == without(before, TABLE), "prepare created protocol/key/registry/network/activity effects")
    check(private_files(h.state) == files and private_files(h.home) == home, "prepare wrote private identity/files")
    before = records(h)
    check(prepare(h, parent, code, person, status=200) == flow, "identical prepare extended or regenerated review")
    observe(h, parent, flow)
    check(records(h) == before, "prepare retry mutated persisted state")
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        values = [value for row in db.execute(f"SELECT * FROM {TABLE}") for value in row]
    public(values, code)
    check(hashlib.sha256(code.encode()).hexdigest() in str(values), "only a digest binds the code in the public flow table")
    public(get(h, "/v1/activity?limit=1000"), code)


@suite.case("approval_lost_response_restart_cancel_and_ordinary_cli_reuse", "guided onboarding12 verification2")
def _():
    h, parent, code, person = fixture("publish")
    home = private_files(h.home)
    flow = prepare(h, parent, code, person)
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=10)
    try:
        connection.request("POST", BASE + "/" + flow["flow_id"] + "/decision", body=compact(decision(flow, code)), headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        check(response.status == 200, f"committed approval header HTTP {response.status}")
        # Discard the entire outcome body: recover from public inspection.
    finally:
        connection.close()
    requested = get(h, BASE + "/" + flow["flow_id"])
    validate(h, parent, requested, person); check(requested["state"] == "requested", "lost outcome not recoverable")
    rid = requested["outcome"]["request_id"]
    view = get(h, "/v2/link/requests/" + rid)
    check(view["role"] == "requester" and view["mode"] == "new" and view["network_id"] == source()["network"]["id"] and
          view["person_public_key"] == person and view["migration_proposal_id"] == "-" and not view["selection_approved"] and not view["commit_approved"], "publication changed ordinary request intent or approved participant work")
    check(get(h, "/v2/networks") == [], "publication granted membership")
    check(private_files(h.home) == home, "publication created/imported an original person identity")
    frozen = request_fingerprint(h, rid)
    check(decide(h, flow, code) == requested, "approval retry changed outcome")
    h.restart(kill=True)
    # Restart invalidates parent attachment; recorded consent still replays.
    check(decide(h, flow, code) == requested, "restart recreated or invalidated recorded publication")
    advance_to(h, parse_time(flow["review"]["expires_at"]) + timedelta(seconds=1))
    check(decide(h, flow, code) == requested, "expired review regenerated its approved request")
    check(request_fingerprint(h, rid) == frozen, "retry/restart changed request/device/nonce/frames/deadline")
    status, cancelled = h.api("POST", "/v2/link/requests/" + rid + "/cancel", {})
    check(status == 200 and cancelled["state"] == "cancelled", "public request cancellation fixture")
    frozen = request_fingerprint(h, rid); check(decide(h, flow, code) == requested, "old approval changed retained publication after cancellation")
    check(request_fingerprint(h, rid) == frozen, "old approval recreated a cancelled request")
    reuse, p2, original, selected = fixture("reuse")
    helper = {"address": "127.0.0.1:9", "public_key": source()["signer"].public}
    legacy = source()["signer"].invitation(original, change=lambda p: p.update(helpers=[helper]))
    existing = reuse.cli("join", "--invite-stdin", "--person-key", source()["key"], input=legacy + "\n", timeout=20)
    # Runtime contract: join publishes a flat pending LINK_VIEW and exits
    # nonzero until linking actually completes. Publication is not admission.
    check(not existing.ok and existing.json and existing.json.get("request_id") and existing.json.get("state") == "pending",
          f"ordinary advanced CLI exit {existing.code}, JSON fields {sorted(existing.json) if isinstance(existing.json, dict) else []}, code {existing.json.get('code') if isinstance(existing.json, dict) else None}")
    rid2 = existing.json["request_id"]
    listed = get(reuse, "/v2/link/requests")
    check(len(listed) == 1 and listed[0]["request_id"] == rid2 and not listed[0]["selection_approved"] and not listed[0]["commit_approved"],
          "ordinary pending CLI did not publish exactly one unapproved request")
    frozen = request_fingerprint(reuse, rid2)
    reviewed = prepare(reuse, p2, legacy, selected); outcome = decide(reuse, reviewed, legacy)
    check(outcome["outcome"]["request_id"] == rid2 and request_fingerprint(reuse, rid2) == frozen, "guided approval failed exact existing-request reuse")
    # Public storage19.4 also permits ordinary participant endpoints. Match all
    # signed helpers exactly; the fingerprint above retains every endpoint.
    stored_helpers = [endpoint for endpoint in frozen[1]["carrier_endpoints"] if endpoint["kind"] == "helper"]
    check(reviewed["review"]["invitation"]["helpers"] == [helper] and
          stored_helpers == [{"kind": "helper", **helper}], "signed helper was lost or substituted in publication")


@suite.case("decline_conflicts_pins_expiry_parent_and_explicit_replacement", "guided onboarding12 verification3")
def _():
    h, parent, code, person = fixture("refuse")
    other = ssh_public_base64(ssh_key(suite.work, "other-original"))
    prepare(h, parent, code, other, status=400, error="invalid")
    flow = prepare(h, parent, code, person)
    decide(h, flow, code, status=409, error="review_changed", body={**decision(flow, code), "review_id": "review_" + "1" * 64})
    changed = decision(flow, code); changed["context"] = {**changed["context"], "native_session_id": "different-private-conversation"}
    decide(h, flow, code, status=409, error="review_changed", body=changed)
    different_code = source()["signer"].invitation(code)
    decide(h, flow, code, status=409, error="review_changed", body={**decision(flow, code), "invitation": different_code})
    prepare(h, parent, code, person, replace=flow["flow_id"], status=409, error="flow_conflict")
    declined = decide(h, flow, code, "decline"); check(declined["state"] == "declined", "decline published")
    check(decide(h, flow, code, "decline") == declined, "decline retry changed recorded decision")
    decide(h, flow, code, status=409, error="flow_conflict")
    legacy = source()["signer"].invitation(code)
    prepare(h, parent, legacy, person, status=409, error="flow_conflict")
    replacement = prepare(h, parent, legacy, person, replace=flow["flow_id"])
    check(replacement["flow_id"] != flow["flow_id"], "explicit replacement reused old flow identity")
    decide(h, flow, code, status=409, error="flow_conflict")
    advance_to(h, parse_time(replacement["review"]["expires_at"]))
    decide(h, replacement, legacy, status=409, error="review_expired")
    next_flow = prepare(h, parent, legacy, person, replace=replacement["flow_id"])
    h.ok("session", "detach", parent["review"]["session_id"])
    decide(h, next_flow, legacy, status=409, error="review_changed")
    newer = project(h, "refuse-replaced", replace=parent["flow_id"], old=parent)
    decide(h, next_flow, legacy, status=409, error="review_changed")
    observe(h, newer, None)
    # Each malformed introduction gets a fresh attached proposal binding.
    now = datetime.now(timezone.utc)
    invalid_signature = b64url_json(code, "psi2-")
    invalid_signature["signature"] = base64.b64encode(bytes(64)).decode()
    invalid_signature = "psi2-" + base64.urlsafe_b64encode(compact(invalid_signature)).decode().rstrip("=")
    variants = [(invalid_signature, 400, "invalid"),
                (source()["signer"].invitation(code, change=lambda p: p.update(issued_at=rfc3339(now - timedelta(hours=2)), expires_at=rfc3339(now - timedelta(hours=1)))), 409, "expired"),
                (source()["signer"].invitation(code, change=lambda p: p.update(issued_at=rfc3339(now + timedelta(hours=1)), expires_at=rfc3339(now + timedelta(hours=2)))), 403, "not_yet_valid")]
    # This host's future clock was needed only for fixed review expiry. A new
    # host avoids rolling guarded DEC time backwards for wire window checks.
    invalid = host("wire-refuse")
    for index, (bad, status, error) in enumerate(variants):
        p = project(invalid, "wire-" + str(index)); before = records(invalid)
        prepare(invalid, p, bad, person, status=status, error=error)
        check(records(invalid) == before, "invalid introduction wrote a proposal/protocol record")
    check(get(h, "/v2/link/requests") == [], "refusal paths created a request")


@suite.case("atomic_outcome_failure_and_protocol_quota_roll_back_all_request_effects", "guided onboarding12 verification4")
def _():
    h, parent, code, person = fixture("rollback")
    legacy = source()["signer"].invitation(code)
    flow = prepare(h, parent, legacy, person)
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute(f"CREATE TRIGGER conformance_join_abort BEFORE UPDATE ON {TABLE} BEGIN SELECT RAISE(ABORT,'conformance'); END")
    before, home = records(h), private_files(h.home)
    actual, denied = h.api("POST", BASE + "/" + flow["flow_id"] + "/decision", decision(flow, legacy))
    check(actual >= 400, "injected outcome update failure was swallowed"); public(denied, legacy)
    check(records(h) == before and private_files(h.home) == home, "failed outcome update leaked request/device/frame/contact or consent writes")
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute("DROP TRIGGER conformance_join_abort")
    check(get(h, BASE + "/" + flow["flow_id"]) == flow, "failed transaction decided the review")
    requested = decide(h, flow, legacy); check(requested["state"] == "requested", "retry after rollback did not publish once")
    check(len(get(h, "/v2/link/requests")) == 1, "rollback retry created duplicate requests")
    quota, p2, original, selected = fixture("quota")
    for index in range(8):
        key = ssh_public_base64(ssh_key(suite.work, "quota-original-" + str(index)))
        status, _ = quota.api("POST", "/v2/link/requests", {"mode": "new", "network_id": "-", "person_public_key": key,
                            "migration_proposal_id": "-", "contact_invitation": "-", "helpers": []})
        check(status == 201, f"public request quota fixture {index}: HTTP {status}")
    pending = prepare(quota, p2, original, selected); before = records(quota)
    decide(quota, pending, original, status=409, error="quota_exceeded")
    check(records(quota) == before and get(quota, BASE + "/" + pending["flow_id"]) == pending, "quota failure left a partial request or decided consent")


@suite.case("strict_private_cli_json_bounds_context_and_owner_only_routes", "guided onboarding12 verification5")
def _():
    h, parent, code, person = fixture("boundary")
    body = proposal(parent, code, person); encoded = compact(body)
    # Exact stdin/body bound allows insignificant trailing whitespace.
    maximum = encoded + b" " * (65536 - len(encoded))
    result = h.cli("onboarding", "join", "prepare", "--stdin", input=maximum.decode(), timeout=10)
    check(result.ok, "CLI refused exact64KiB private JSON boundary")
    flow = result.json; validate(h, parent, flow, person)
    check(prepare(h, parent, code, person, status=200) == flow, "CLI/API exact proposal parity")
    for verb, payload, expected in [("lookup", {"context": context(parent)}, {"version": 1, "host_id": h.id, "context": context(parent), "flow": flow}),
                                    ("decide", {"flow_id": flow["flow_id"], **decision(flow, code, "decline")}, None)]:
        result = h.cli("onboarding", "join", verb, "--stdin", input=json.dumps(payload), timeout=10)
        check(result.ok, f"private CLI {verb} failed"); public(result.stdout, code)
        if expected:
            check(result.json == expected, "CLI lookup parity")
    result = h.cli("onboarding", "join", "inspect", flow["flow_id"], timeout=10)
    check(result.ok and result.json["state"] == "declined", "CLI inspect parity"); public(result.stdout, code)
    invalid = [encoded + b"{}", b"null", b"[]", b"{", maximum + b" ",
               compact({**body, "extra": "private-marker"}), compact({**body, "person_public_key": "-"}),
               compact({**body, "invitation": " " + code}), compact({**body, "invitation": "psi2-" + "A" * 32764}),
               b'{"context":' + compact(context(parent)) + b',"context":' + compact(context(parent)) + b',"invitation":' + compact(code) + b',"person_public_key":' + compact(person) + b'}',
               encoded.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"')]
    before = records(h)
    for raw in invalid:
        actual, value = raw_post(h, BASE, raw)
        check(actual == 400 and value.get("code") == "invalid", f"strict body HTTP {actual}"); public(value, code)
        result = h.cli("onboarding", "join", "prepare", "--stdin", input=raw.decode(), timeout=10)
        check(not result.ok, "CLI accepted malformed/duplicate/trailing/oversized private JSON")
        public(result.stdout + result.stderr, code, "private-marker")
    for args in [("prepare",), ("prepare", code), ("lookup",), ("decide",)]:
        result = h.cli("onboarding", "join", *args, input=json.dumps(body), timeout=10)
        check(not result.ok, "CLI consumed implicit stdin or code argument"); public(result.stdout + result.stderr, code)
    check(records(h) == before, "malformed CLI/API calls mutated state")
    for changed, status, error in [({**context(parent), "project_flow_id": "flow_" + "1" * 32}, 404, "not_found"),
                                   ({**context(parent), "project_review_id": "review_" + "1" * 64}, 409, "review_changed")]:
        prepare(h, parent, code, person, body={**body, "context": changed}, status=status, error=error)
    for choice, patch in [("approve", {"invitation": None}), ("decline", {"invitation": code})]:
        actual, value = h.api("POST", BASE + "/" + flow["flow_id"] + "/decision", {**decision(flow, code, choice), **patch})
        check(actual == 400 and value.get("code") == "invalid", "decision's exact code presence not enforced"); public(value, code)
    for method, path in [("GET", BASE), ("PUT", BASE), ("GET", BASE + "/lookup")]:
        actual, value = h.api(method, path); check(actual in (404, 405), "wrong owner method accepted"); public(value)
    # Real registered peer, one scoped credential, and a quiescent bootstrap
    # source keep routing evidence independent of mailbox/rate budget traffic.
    peer = host("peer")
    for local, remote in ((h, peer), (peer, h)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    status, agent = h.api("POST", "/v1/agents", {"name": "join-boundary-fixture", "owner": "fixture"})
    check(status == 201, "public scoped-boundary agent fixture")
    attached = h.ok("session", "attach", "--agent", agent["id"], "--integration", "fixture")
    credential = h.ok("adapter", "create", "--session", attached["id"], "--expires-at", rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, agent, attached["id"], credential)
    status, _ = adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id, "session_id": adapter.session_id, "instance_id": adapter.instance})
    check(status == 200, "scoped boundary private connection")
    bootstrap = host("bootstrap")
    cert, key = suite.work / "route-cert.pem", suite.work / "route-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=join-boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    for method, path, payload in [("POST", BASE, body), ("POST", BASE + "/lookup", {"context": context(parent)}),
                                  ("GET", BASE + "/" + flow["flow_id"], None),
                                  ("POST", BASE + "/" + flow["flow_id"] + "/decision", decision(flow, code))]:
        actual, value = adapter.call(method, path, payload)
        check(actual == 404, f"scoped join owner route HTTP {actual}"); public(value, code)
        args = [str(suite.probe_bin), "--state", str(peer.state), "--address", h.peer_address, "--alpn", "peerspan-peer/1", "--method", method, "--path", path]
        if payload is not None:
            args.append("--body-stdin")
        result = subprocess.run(args, input=compact(payload) if payload is not None else b"", capture_output=True, timeout=10)
        check(result.returncode == 0 and json.loads(result.stdout)["status"] == 404, "authenticated peer exposed private join route")
        data = compact(payload) if payload is not None else b""
        with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname="peerspan") as stream:
                stream.sendall((f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, f"bootstrap join owner route HTTP {response.status}")
    public(get(h, "/v1/activity?limit=1000"), code)
    missing = suite.host("no-daemon", start=False); before = private_files(missing.root)
    result = missing.cli("onboarding", "join", "prepare", "--stdin", input=json.dumps(body), timeout=10)
    check(not result.ok and private_files(missing.root) == before, "CLI started a daemon or initialized missing state")
    public(result.stdout + result.stderr, code)


def clone_state(source_host, name):
    clone = suite.host(name, start=False)
    shutil.copytree(source_host.state, clone.state, dirs_exist_ok=True)
    for name in ("admin.sock", "adapter.sock"):
        (clone.state / name).unlink(missing_ok=True)
    return clone


def refuse_start(h):
    before = records(h)
    with h.log.open("ab") as log:
        process = suite.spawn([str(suite.host_bin), "--state", str(h.state), "run"], stdout=log, stderr=log, env=h.env)
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=5); code = None
    check(code not in (None, 0), "reserved/corrupt/future join schema opened")
    check(records(h) == before, "refused migration changed schema/version/logical state")


@suite.case("schema27_additive_reserved_names_corruption_future28_and_rollback", "guided onboarding12 verification6")
def _():
    h, parent, code, person = fixture("migration")
    flow = prepare(h, parent, code, person); decide(h, flow, code, "decline")
    h.ok("session", "detach", parent["review"]["session_id"])
    identity, activity = get(h, "/v1/host"), get(h, "/v1/activity?limit=1000")
    h.stop(); baseline = records(h)
    legacy = clone_state(h, "legacy26")
    with closing(sqlite3.connect(db_path(legacy))) as db, db:
        db.execute(f"DROP TABLE {TABLE}"); db.execute("PRAGMA user_version = 26")
    old = records(legacy); legacy.start()
    check(get(legacy, "/v1/host") == identity and get(legacy, "/v1/activity?limit=1000") == activity, "migration changed identity/activity")
    check(get(legacy, PROJECT + "/" + parent["flow_id"])["state"] == "invalidated", "migration resurrected historical attachment")
    legacy.stop(); migrated = records(legacy)
    check(migrated["$version"] == (27,) and migrated[TABLE] == (), "26→27 did not add exactly empty join table")
    check(without(migrated, "$schema", "$version", TABLE) == without(old, "$schema", "$version"), "additive migration changed prior authority/registry/history")
    check(migrated["$schema"] == baseline["$schema"], "additive migration changed table definitions")
    for kind, ddl in [("table", f"CREATE TABLE {TABLE} (marker TEXT)"), ("view", f"CREATE VIEW {TABLE} AS SELECT 'reserved' AS marker"),
                      ("index", f"CREATE INDEX {TABLE} ON sessions(id)"),
                      ("trigger", f"CREATE TRIGGER {TABLE} AFTER INSERT ON sessions BEGIN SELECT 1; END")]:
        collision = clone_state(h, "collision-" + kind)
        with closing(sqlite3.connect(db_path(collision))) as db, db:
            db.execute(f"DROP TABLE {TABLE}"); db.execute("PRAGMA user_version = 26"); db.execute(ddl)
        refuse_start(collision)
    for name, ddl in [("missing", f"DROP TABLE {TABLE}"), ("extra", f"ALTER TABLE {TABLE} ADD COLUMN unexpected TEXT"),
                      ("constraints", f"ALTER TABLE {TABLE} RENAME TO old_join; CREATE TABLE {TABLE} AS SELECT * FROM old_join; DROP TABLE old_join")]:
        corrupt = clone_state(h, "corrupt-" + name)
        with closing(sqlite3.connect(db_path(corrupt))) as db, db:
            db.executescript(ddl)
        refuse_start(corrupt)
    future = clone_state(h, "future28")
    with closing(sqlite3.connect(db_path(future))) as db, db:
        db.execute("PRAGMA user_version = 28")
    refuse_start(future)


def identity_inventory(h, parent, *, agent=None, data=None, fallback=False):
    argv = [str(suite.host_bin), "--state", str(h.state), "onboarding", "join", "identities", "--stdin"]
    environment = {**h.env, "SSH_AUTH_SOCK": str(agent or h.root / "absent-agent.sock")}
    if fallback:
        environment.pop("XDG_CONFIG_HOME", None)
    # Existing SSH-agent transport can wait10s before reporting unavailable.
    # Leave room for both owner observations; this is a fixture outer deadline.
    result = subprocess.run(argv, input=compact({"context": context(parent)}) if data is None else data,
                            env=environment, capture_output=True, timeout=20)
    for marker in (b"BEGIN OPENSSH PRIVATE KEY", b"PRIVATE_IDENTITY_COMMENT", b"token_", b"person_ed25519", b"agent.sock"):
        check(marker not in result.stdout + result.stderr, "identity inventory exposed a private key/comment/source path")
    value = None
    if result.stdout.strip():
        try:
            value = json.loads(result.stdout)
        except ValueError:
            check(False, "identity inventory stdout is not controlled JSON")
    if result.returncode == 0:
        check(isinstance(value, dict) and set(value) == {"version", "host_id", "context", "identities"}
              and value["version"] == 1 and value["host_id"] == h.id and value["context"] == context(parent), "exact inventory envelope/binding")
        keys = []
        for item in value["identities"]:
            check(set(item) == {"public_key", "sources"} and len(base64.b64decode(item["public_key"], validate=True)) == 32,
                  "identity inventory returned private/unknown or invalid public fields")
            check(item["sources"] in (["generated"], ["ssh_agent"], ["generated", "ssh_agent"]), "identity provenance order/content")
            keys.append(item["public_key"])
        check(len(keys) <= 64 and keys == sorted(set(keys)), "inventory order/dedup/bound")
    return result.returncode, value


def identity_agent(h):
    path = h.root / "agent.sock"
    with (h.root / "agent.log").open("ab") as log:
        suite.spawn(["ssh-agent", "-D", "-a", str(path)], stdout=log, stderr=log)
    wait_for(path.exists, timeout=5, message="private real SSH agent")
    return path


def add_identity(h, agent, path):
    added = subprocess.run(["ssh-add", str(path)], env={**h.env, "SSH_AUTH_SOCK": str(agent)}, capture_output=True, timeout=5)
    check(added.returncode == 0, "real ssh-add fixture failed")


def generated_identity(h):
    directory = Path(h.env["XDG_CONFIG_HOME"]) / "peerspan"
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    key = directory / "person_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "PRIVATE_IDENTITY_COMMENT generated", "-f", str(key)],
                   check=True, capture_output=True, timeout=5)
    public_key = ssh_public_base64(key)
    key.with_suffix(".pub").unlink()
    return key, public_key


@suite.case("local_identity_inventory_exact_generated_agent_dedup_and_read_only", "guided onboarding13 verification1")
def _():
    h, parent, _, _ = fixture("identities")
    normal, generated = generated_identity(h)
    agent = identity_agent(h); add_identity(h, agent, normal)
    expected = {generated: ["generated", "ssh_agent"]}
    for index in range(2):
        key = ssh_key(suite.work, "agent-original-" + str(index))
        # Comments remain agent-local and must not reach the inventory response.
        subprocess.run(["ssh-keygen", "-q", "-c", "-P", "", "-C", "PRIVATE_IDENTITY_COMMENT token_COMMENT_" + str(index), "-f", str(key)],
                       check=True, capture_output=True, timeout=5)
        add_identity(h, agent, key); expected[ssh_public_base64(key)] = ["ssh_agent"]
    rsa = suite.work / "unsupported-agent-rsa"
    subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "1024", "-N", "", "-C", "PRIVATE_IDENTITY_COMMENT rsa", "-f", str(rsa)],
                   check=True, capture_output=True, timeout=5)
    add_identity(h, agent, rsa)
    before, state, home = records(h), private_files(h.state), private_files(h.home)
    code, value = identity_inventory(h, parent, agent=agent)
    check(code == 0 and value["identities"] == [{"public_key": key, "sources": expected[key]} for key in sorted(expected)], "real generated/agent public inventory differs")
    code, value = identity_inventory(h, parent, agent=agent, fallback=True)
    check(code == 0 and len(value["identities"]) == 3, "HOME fallback changed normal original identity source")
    code, value = identity_inventory(h, parent)
    check(code == 0 and value["identities"] == [{"public_key": generated, "sources": ["generated"]}], "missing SSH agent fabricated keys or hid generated key")
    # A real listening but nonanswering agent must contribute no keys, bounded.
    silent = h.root / "silent-agent.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stalled:
        stalled.bind(str(silent)); stalled.listen(1)
        code, value = identity_inventory(h, parent, agent=silent)
        check(code == 0 and value["identities"] == [{"public_key": generated, "sources": ["generated"]}], "nonanswering agent changed available identities")
    silent.unlink()
    check(records(h) == before and private_files(h.state) == state and private_files(h.home) == home,
          "inventory changed daemon/identity state, private key, permissions or recreated public sidecar")


@suite.case("local_identity_inventory_private_failures_bounds_context_and_no_initialization", "guided onboarding13 verification1")
def _():
    h, parent, _, _ = fixture("identity-refuse")
    code, value = identity_inventory(h, parent)
    check(code == 0 and value["identities"] == [], "empty sources silently created/selected an original key")
    normal, _ = generated_identity(h)
    original, mode = normal.read_bytes(), normal.stat().st_mode & 0o777
    agent = identity_agent(h)
    other = ssh_key(suite.work, "available-agent-original"); add_identity(h, agent, other)
    for fault in ("insecure", "malformed", "oversized", "symlink", "directory"):
        normal.unlink()
        if fault == "symlink":
            normal.symlink_to(other)
        elif fault == "directory":
            normal.mkdir(mode=0o700)
        else:
            normal.write_bytes(original if fault == "insecure" else b"PRIVATE_IDENTITY_COMMENT invalid" if fault == "malformed" else b"x" * 65537)
            normal.chmod(0o644 if fault == "insecure" else mode)
        before, home = records(h), private_files(h.home)
        exit_code, response = identity_inventory(h, parent, agent=agent)
        check(exit_code != 0, "invalid/insecure generated source was masked by an available agent key")
        check(records(h) == before and private_files(h.home) == home, "source refusal rewrote or repaired private identity files")
        if normal.is_dir():
            normal.rmdir()
        else:
            normal.unlink()
        normal.write_bytes(original); normal.chmod(mode)
    body = compact({"context": context(parent)})
    before, home = records(h), private_files(h.home)
    maximum = body + b" " * (65536 - len(body))
    check(identity_inventory(h, parent, data=maximum)[0] == 0, "identity inventory refused exact64KiB JSON boundary")
    malformed = [b"null", b"[]", b"{}", body + b"{}", maximum + b" ", compact({"context": None}),
                 compact({"context": context(parent), "extra": "PRIVATE_IDENTITY_COMMENT"}),
                 b'{"context":' + compact(context(parent)) + b',"context":' + compact(context(parent)) + b'}',
                 body.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"')]
    for data in malformed:
        check(identity_inventory(h, parent, data=data)[0] != 0, "identity inventory accepted malformed/duplicate/trailing/oversized JSON")
    for change in ({"project_flow_id": "flow_" + "1" * 32}, {"project_review_id": "review_" + "1" * 64}, {"native_session_id": "other-private-native"}):
        check(identity_inventory(h, parent, data=compact({"context": {**context(parent), **change}}))[0] != 0, "inventory accepted wrong parent/context")
    check(records(h) == before and private_files(h.home) == home, "JSON/context refusals mutated identity or daemon state")
    #65 actual supported agent keys exceed the complete-result bound. Generated
    # is a further distinct identity, and no result may truncate to a first64.
    for index in range(64):
        key = ssh_key(suite.work, "bounded-agent-" + str(index)); add_identity(h, agent, key)
    before, home = records(h), private_files(h.home)
    check(identity_inventory(h, parent, agent=agent)[0] != 0, "over64 identity inventory silently truncated or selected keys")
    check(records(h) == before and private_files(h.home) == home, "oversized inventory changed local state")
    h.ok("session", "detach", parent["review"]["session_id"])
    check(identity_inventory(h, parent)[0] != 0, "detached parent inventoried local original identities")
    h.stop(); before, home = private_files(h.state), private_files(h.home)
    check(identity_inventory(h, parent)[0] != 0, "missing daemon identity inventory succeeded")
    check(private_files(h.state) == before and private_files(h.home) == home, "inventory initialized missing daemon/identity state")


def create_original(h, parent, *, data=None, agent=None, fallback=False):
    body = {"context": context(parent), "decision": "create_new_identity"}
    environment = {**h.env, "SSH_AUTH_SOCK": str(agent or h.root / "absent-agent.sock")}
    if fallback:
        environment.pop("XDG_CONFIG_HOME", None)
    result = subprocess.run([str(suite.host_bin), "--state", str(h.state), "onboarding", "join", "create-identity", "--stdin"],
                            input=compact(body) if data is None else data, env=environment, cwd=h.root, capture_output=True, timeout=20)
    for marker in (b"BEGIN OPENSSH PRIVATE KEY", b"PRIVATE_CREATION_MARKER", b"token_", b"psi2-",
                   str(Path(environment.get("XDG_CONFIG_HOME", str(h.home / ".config"))) / "peerspan" / "person_ed25519").encode()):
        check(marker not in result.stdout + result.stderr, "creation output leaked private input/key/path/provider data")
    value = None
    if result.stdout.strip():
        try:
            value = json.loads(result.stdout)
        except ValueError:
            check(False, "creation stdout is not controlled JSON")
    if result.returncode == 0:
        check(isinstance(value, dict) and set(value) == {"version", "host_id", "context", "identity"} and value["version"] == 1
              and value["host_id"] == h.id and value["context"] == context(parent), "exact public creation envelope/binding")
        check(set(value["identity"]) == {"public_key", "sources"} and value["identity"]["sources"] == ["generated"]
              and len(base64.b64decode(value["identity"]["public_key"], validate=True)) == 32, "exact saved public original/provenance")
    return result.returncode, value


def saved_original(path):
    import stat
    metadata = path.lstat()
    check(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and metadata.st_mode & 0o777 == 0o600,
          "saved original is not one owned regular0600 file")
    check(path.parent.lstat().st_mode & 0o777 == 0o700 and path.parent.lstat().st_uid == os.getuid(), "normal identity directory is not owned private0700")
    # Creation intentionally has no .pub sidecar. Ask ordinary OpenSSH to read
    # the saved unencrypted private file; this writes/signs nothing.
    derived = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(path)], check=True, capture_output=True, timeout=5).stdout.split()
    check(len(derived) >= 2 and derived[0] == b"ssh-ed25519", "saved original is not ordinary unencrypted Ed25519")
    blob = base64.b64decode(derived[1], validate=True)
    check(len(blob) == 51 and blob[:15] == b"\x00\x00\x00\x0bssh-ed25519" and blob[15:19] == b"\x00\x00\x00\x20", "ordinary public-key derivation shape")
    public_key = base64.b64encode(blob[-32:]).decode()
    check(not path.with_suffix(".pub").exists(), "creation wrote a public sidecar")
    # Ordinary unencrypted discovery must read it without agent/signing/key setup.
    body = path.read_bytes()
    check(body.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----") and b"psi2-" not in body, "saved original format/private contents")
    return public_key, metadata.st_ino, hashlib.sha256(body).hexdigest()


@suite.case("new_original_fresh_private_durable_creation_inventory_and_home_fallback", "guided onboarding14 verification1")
def _():
    for index, fallback in enumerate((False, True)):
        h, parent, _, _ = fixture("create-" + str(index))
        config = h.home / ".config" if fallback else h.home / "missing config" / "nested"
        h.extra_env["XDG_CONFIG_HOME"] = str(config)
        check(not config.exists(), "fresh local configuration fixture unexpectedly exists")
        before, state = records(h), private_files(h.state)
        encoded = compact({"context": context(parent), "decision": "create_new_identity"})
        maximum = encoded + b" " * (65536 - len(encoded))
        code, value = create_original(h, parent, fallback=fallback, data=maximum if not fallback else None)
        check(code == 0, "explicit fresh original creation failed")
        normal = config / "peerspan" / "person_ed25519"
        selected, inode, hashed = saved_original(normal)
        check(value["identity"]["public_key"] == selected, "reply does not name the durably saved original")
        expected = {"peerspan", "peerspan/person_ed25519"}
        check(set(private_files(config)) == expected, "clean creation left a temporary/private duplicate store")
        for directory in (config, normal.parent, *([config.parent] if not fallback else [])):
            check(directory.stat().st_mode & 0o777 == 0o700, "new configuration directory has broad permissions")
        status, inventory = identity_inventory(h, parent, fallback=fallback)
        check(status == 0 and inventory["identities"] == [{"public_key": selected, "sources": ["generated"]}], "normal discovery did not recover the saved original")
        check(create_original(h, parent, fallback=fallback)[0] != 0 and saved_original(normal) == (selected, inode, hashed), "repeat replaced/adopted the existing original")
        check(records(h) == before and private_files(h.state) == state, "local creation wrote daemon/protocol/authority/adapter state or sent original key bytes")


@suite.case("new_original_strict_consent_context_existing_sources_and_filesystem_refusals", "guided onboarding14 verification2")
def _():
    h, parent, _, _ = fixture("creation-refuse")
    body = compact({"context": context(parent), "decision": "create_new_identity"})
    malformed = [b"null", b"[]", b"{}", body + b"{}", body + b" " * (65537 - len(body)),
                 compact({"context": context(parent), "decision": "approve"}),
                 compact({"context": None, "decision": "create_new_identity"}),
                 compact({"context": context(parent), "decision": "create_new_identity", "label": "PRIVATE_CREATION_MARKER"}),
                 compact({"context": context(parent), "decision": "create_new_identity", "invitation": "psi2-PRIVATE_CREATION_MARKER"}),
                 body.replace(b'"decision":', b'"decision":"create_new_identity","decision":'),
                 body.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"')]
    before, home = records(h), private_files(h.home)
    for data in malformed:
        check(create_original(h, parent, data=data)[0] != 0, "malformed/duplicate/extra/oversized creation consent accepted")
    for change in ({"project_flow_id": "flow_" + "1" * 32}, {"project_review_id": "review_" + "1" * 64}, {"native_session_id": "other-private-native"}):
        check(create_original(h, parent, data=compact({"context": {**context(parent), **change}, "decision": "create_new_identity"}))[0] != 0, "creation accepted wrong exact parent/context")
    check(records(h) == before and private_files(h.home) == home, "input/context refusal initialized an original")
    key = ssh_key(suite.work, "creation-existing-original")
    original = key.read_bytes()
    for fault in ("malformed", "insecure-file", "dangling", "symlink-directory", "symlink-ancestor", "insecure-directory", "insecure-ancestor", "relative", "traversal"):
        config = h.home / ("config-" + fault); h.extra_env["XDG_CONFIG_HOME"] = str(config)
        if fault == "relative":
            h.extra_env["XDG_CONFIG_HOME"] = "relative-config"
        elif fault == "traversal":
            h.extra_env["XDG_CONFIG_HOME"] = str(h.home / "unused" / ".." / "traversed")
        elif fault in ("malformed", "insecure-file", "dangling"):
            directory = config / "peerspan"; directory.mkdir(parents=True, mode=0o700)
            normal = directory / "person_ed25519"
            if fault == "dangling":
                normal.symlink_to(h.home / "never-create-target")
            else:
                normal.write_bytes(b"PRIVATE_CREATION_MARKER malformed" if fault == "malformed" else original)
                normal.chmod(0o644 if fault == "insecure-file" else 0o600)
        elif fault in ("symlink-directory", "symlink-ancestor"):
            target = h.home / ("target-" + fault); target.mkdir(mode=0o700)
            if fault == "symlink-directory":
                config.mkdir(mode=0o700); (config / "peerspan").symlink_to(target, target_is_directory=True)
            else:
                config.symlink_to(target, target_is_directory=True)
                h.extra_env["XDG_CONFIG_HOME"] = str(config / "nested")
        else:
            directory = config / "peerspan"; directory.mkdir(parents=True, mode=0o700)
            (directory if fault == "insecure-directory" else config).chmod(0o755 if fault == "insecure-directory" else 0o777)
        old_files, old_records, old_root = private_files(h.home), records(h), private_files(h.root)
        check(create_original(h, parent)[0] != 0, "creation repaired/followed/replaced an insecure or existing identity path")
        check(private_files(h.home) == old_files and private_files(h.root) == old_root and records(h) == old_records,
              "filesystem refusal changed existing bytes/modes/symlinks/targets or daemon state")
    config = h.home / "agent-present"; h.extra_env["XDG_CONFIG_HOME"] = str(config)
    agent = identity_agent(h); add_identity(h, agent, key)
    before, home = records(h), private_files(h.home)
    check(create_original(h, parent, agent=agent)[0] != 0, "available agent original silently created another person")
    check(records(h) == before and private_files(h.home) == home, "nonzero inventory refusal wrote a new identity")
    h.ok("session", "detach", parent["review"]["session_id"])
    check(create_original(h, parent)[0] != 0, "detached parent created an original")
    h.stop(); before, home = private_files(h.state), private_files(h.home)
    check(create_original(h, parent)[0] != 0, "missing daemon creation succeeded")
    check(private_files(h.state) == before and private_files(h.home) == home, "creation initialized daemon/state after refusal")


@suite.case("new_original_concurrent_publish_temporary_ignored_and_parent_loss_preserves_key", "guided onboarding14 verification3")
def _():
    h, parent, _, _ = fixture("concurrent-create")
    config = h.home / ".config"; private = config / "peerspan"; private.mkdir(parents=True, mode=0o700)
    # A private abandoned file is not the active original. Its name is our own
    # fixture name; no undocumented implementation temp prefix is assumed.
    abandoned = private / "conformance-unpublished-temporary"; abandoned.write_bytes(b"partial private fixture"); abandoned.chmod(0o600)
    temporary = (abandoned.stat().st_ino, hashlib.sha256(abandoned.read_bytes()).hexdigest())
    check(identity_inventory(h, parent)[1]["identities"] == [], "inventory adopted a temporary partial original")
    before, state = records(h), private_files(h.state)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: create_original(h, parent), range(2)))
    check(sum(status == 0 for status, _ in results) == 1, "stable concurrent creation did not publish exactly one complete original")
    normal = private / "person_ed25519"; saved = saved_original(normal)
    successful = next(value for status, value in results if status == 0)
    check(successful["identity"]["public_key"] == saved[0], "concurrent result did not identify the winning original")
    check((abandoned.stat().st_ino, hashlib.sha256(abandoned.read_bytes()).hexdigest()) == temporary, "creation changed/adopted an abandoned private temporary file")
    check(set(path.name for path in private.iterdir()) == {normal.name, abandoned.name}, "clean concurrent persistence left an additional active/temporary secret")
    check(create_original(h, parent)[0] != 0 and saved_original(normal) == saved, "repeat overwrote or removed the winner")
    check(identity_inventory(h, parent)[1]["identities"] == [{"public_key": saved[0], "sources": ["generated"]}], "read-only recovery lost the winner")
    check(records(h) == before and private_files(h.state) == state, "concurrent local writes changed protocol/host state")
    h.ok("session", "detach", parent["review"]["session_id"])
    check(create_original(h, parent)[0] != 0 and saved_original(normal) == saved, "post-persistence parent loss erased or replaced the approved original")
    # This proves the observed durable-key invariant after parent loss. The
    # narrower link/fsync/postcheck crash interval remains source/fault evidence.


suite.finish()
