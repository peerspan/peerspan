#!/usr/bin/env python3
"""Exact durable administrator consent: guided contract section21.

Independent genuine two-host/two-person original/selection evidence and existing
ordinary root intents; no production imports, protocol/authority row invention,
key/seed replacement or alternate signing API. A schema-only ABORT trigger is the
only SQLite mutation. Public ordinary unapproved admission is used ONLY for a
negative incompatible-provider fixture, never to set up positive guided consent.
After approval, ordinary root/host signing may progress independently; snapshots
follow explicit observed stages and independently settled transport. Read-only
history asserts global ordinary consent, never frontend signature attribution.
Unreachable missing/pruned/corrupt proof, smaller after-check races and isolated
15-minute expiry beyond an earlier ten-minute stage bound remain source/fault
limits. No native/model/installed/physical acceptance is inferred. Existing
admission6/signing6/owner6/join14/native252 stay unchanged; earlier historical
signing-purity intermittence remains recorded rather than erased by later passes.
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

suite = Suite("admission_consent", __doc__)
BASE = "/v1/onboarding/admission-consent"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
TOP = {"version", "host_id", "context", "observed_at", "request", "admission"}
REVIEW = set("version kind host_id context agent network request_id request_packet_id owner_offer_id selection_id intent_id root_state_id root_public_key person_lease_id host_lease_id member person_public_key host_public_key device_public_key scopes not_after request_created_at request_expires_at created_at expires_at effects".split())
EFFECTS = {"approve_administrator_intent": True, "authorize_network_root_signature": True,
           "authorize_host_packet_signature": True, "publish_administrator_offer_after_signatures": True,
           "grant_membership": False, "grant_agent_access": False, "authorize_original_finalization": False,
           "commit_request": False, "share_files": False, "share_conversation": False, "capability_calls": False}
main_fixture = {}

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

def project(h, name, *, replace=None, old=None, agent_name=None):
    body = {"project_root": old["review"]["project_root"] if old else str(suite.work / ("private " + name)),
            "native_session_id": old["review"]["native_session_id"] if old else "private-conversation-" + name,
            "integration": "claude-code", "agent": {"kind": "new", "name": agent_name or 'Agent "東京" ' + name, "owner": "Owner é"}}
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

def progress_transport_host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    config = h.root / "transport.json"
    config.write_bytes(compact({"format": 1, "advertise_bootstrap": [f"127.0.0.1:{h.bootstrap_port}"], "advertise_quic": [h.peer_address],
                               "rendezvous": [], "relays": [], "publish_contacts": False})); config.chmod(0o600)
    h.extra_args = ["--transport-config", config]
    return h.start()

def pending(h, rid):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT record,secret FROM dec_pending WHERE request_id=?", (rid,)).fetchone()
    check(row is not None, "ordinary request vanished")
    return json.loads(row[0]), row[1]

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

def public(value, *secrets):
    text = json.dumps(value, ensure_ascii=False, default=str)
    for index, marker in enumerate((*PREFIXES, 'payload_base64', 'template_base64', 'message_base64',
                   'secret_base64', 'signing_requests', 'return_secret', 'admin.sock',
                   'adapter.sock', '"signature"', '"seed"', *secrets)):
        check(not marker or marker not in text, f"consent exposed private input/signing/provider material (rule {index})")

def snapshot(h):
    return records(h), private_files(h.state), private_files(h.home)

def packet_message(packet):
    # Wire9.2: semantic packet message excludes every signature.
    fields = ["peerspan-decentralized-packet-v1", packet["context_id"], packet["request_id"], packet["role"],
              packet["writer_host_public_key"], packet["signer_public_key"], packet["person_public_key"],
              packet["issuer_id"], packet["authority_signature_format"],
              hashlib.sha256(base64.b64decode(packet["payload_base64"], validate=True)).hexdigest()]
    return "\n".join(fields).encode()

def packet_id(packet):
    return "dpk_" + hashlib.sha256(packet_message(packet)).hexdigest()

def verify_original(f):
    record, _ = pending(f["a"], f["rid"])
    packet = json.loads(base64.b64decode(record["owner_packet_base64"], validate=True))
    selection = json.loads(base64.b64decode(record["selection_packet_base64"], validate=True))
    view = link_view(f["a"], f["rid"])
    check(packet_id(packet) == view["owner_offer_id"] and packet_id(selection) == view["selection_id"] and
          packet["signer_public_key"] == f["person"] and packet["person_public_key"] == f["person"] and
          packet["issuer_id"] == "-" and packet["authority_signature_format"] == "sshsig",
          "retained prefix lacks exact original-possession packet/selection")
    allowed = suite.work / "allowed-signers"
    key = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(f["key"])], check=True,
                         capture_output=True, timeout=5).stdout
    allowed.write_bytes(b"fixture " + key); allowed.chmod(0o600)
    signature = suite.work / "original.sshsig"; text = packet["authority_signature"]
    signature.write_text("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(text[i:i + 70] for i in range(0, len(text), 70)) +
                         "\n-----END SSH SIGNATURE-----\n"); signature.chmod(0o600)
    verified = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "fixture", "-n",
        "peerspan-person-v1", "-s", str(signature)], input=packet_message(packet), capture_output=True, timeout=5)
    check(verified.returncode == 0, "independent verification of actual original SSHSIG failed")

def pair(name, *, scopes=7, short=False, before_owner=None, ssh_root=False):
    a, b = progress_transport_host(name + "a"), progress_transport_host(name + "b")
    net = create_network(a, 'Admission "é東京" ' + name, "inviter")
    if ssh_root:
        root_key = ssh_key(suite.work, name + "-ssh-root")
        rotated = a.cli("network", "rotate-root", net["id"], "--to-ssh", "--root-key", root_key,
                        input="yes\n", tty=True, timeout=25)
        check(rotated.ok, "genuine public SSH-root rotation fixture")
        net = get(a, "/v2/networks/" + net["id"])
    parent, remote_parent = project(a, name + "a"), project(b, name + "b")
    key = ssh_key(suite.work, name + "-original"); person = ssh_public_base64(key)
    member = 'Original "é東京" ' + name
    status, issued = a.api("POST", "/v2/networks/" + net["id"] + "/invitations", {
        "member": member, "expected_person_public_key": person,
        "expires_at": rfc3339(a.now() + timedelta(hours=1))})
    check(status == 201, "real automatic-return invitation fixture")
    code = issued["invitation"]
    status, request = b.api("POST", "/v2/link/requests", {"mode": "new", "network_id": net["id"],
        "person_public_key": person, "migration_proposal_id": "-", "contact_invitation": code, "helpers": []})
    check(status == 201, "public ordinary original request fixture")
    rid, reply = request["request_id"], request["display_code"]
    f = dict(a=a, b=b, parent=parent, remote_parent=remote_parent, network=net, key=key,
             person=person, member=member, code=code, reply=reply, rid=rid)
    def returned():
        values = get(a, "/v2/link/requests")
        return next((v for v in values if v["request_id"] == rid), None)
    incoming = wait_for(returned, timeout=15, interval=.1, message="automatic returned request, no manual import")
    check(incoming["role"] == "approver" and incoming["owner_offer_id"] == "-", "return fixture skipped original proof")
    if before_owner:
        before_owner(f)
    argv = ["link", "approve", "--network", net["id"], "--person-key", key,
            "--code-stdin", "--approve", "--scopes", str(scopes)]
    if short:
        argv += ["--not-after", rfc3339(parse_time(request["created_at"]) + timedelta(days=1))]
    b.ok_incomplete(*argv, input=reply + "\n", timeout=20)
    view = pull_until(b, rid, "owner_offer_id", timeout=15)
    if view["state"] == "needs_selection":
        select(b, view)
    selected = pull_until(b, rid, "selection_id", timeout=10)
    def arrived():
        v = link_view(a, rid)
        if v["owner_offer_id"] == selected["owner_offer_id"] and v["selection_id"] == selected["selection_id"]:
            return v
        # Explicit advanced test driver: invitation return already retained the
        # request. Ordinary resume fetches its later packets during SETUP only.
        # Inspection below never drives or prepares the protocol.
        a.cli("link", "resume", rid, timeout=15)
        v = link_view(a, rid)
        return v if v["owner_offer_id"] == selected["owner_offer_id"] and v["selection_id"] == selected["selection_id"] else None
    observed = wait_for(arrived, timeout=15, interval=.1, message="ordinary setup owner/selection retention")
    check(observed["state"] == "needs_administrator", "incoming selected prefix advanced without administrator consent")
    check(get(b, "/v2/networks") == [], "selected original prefix prematurely adopted a network")
    b.stop(); settled(a)
    verify_original(f)
    return f

def intent(h, iid):
    check(re.fullmatch(r"dint_[0-9a-f]{32}", iid), "malformed retained ordinary intent reference")
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?", (iid,)).fetchone()
    check(row is not None, "guided consent references no ordinary intent")
    return {"network_id": row[0], "context_id": row[1], "kind": row[2], "record": json.loads(row[3]), "secret": row[4]}


def payload(f, prepared=None, parent=None):
    result = {"context": context(parent or f["parent"]), "request_id": f["rid"]}
    if prepared is not None:
        result["admission_review_id"] = prepared["admission"]["review_id"]
    return result


def validate(f, value, *, parent=None, requests=(), required=True):
    a = f["a"]; parent = parent or f["parent"]
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1,
          "exact consent wrapper/version")
    check(value["host_id"] == a.id and value["context"] == context(parent), "consent changed exact local host/context")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]) and
          abs((parse_time(value["observed_at"]) - a.now()).total_seconds()) < 5, "canonical guarded observation time")
    # Background work is allowed after consent. Bracket the call with genuine
    # ordinary public views instead of attributing a concurrent stage to a read.
    check(any(value["request"] == v for v in requests), "response request is not its bracketed ordinary LINK_VIEW")
    request = value["request"]
    check(request["request_id"] == f["rid"] and request["role"] == "approver", "consent changed incoming retained request/role")
    admission = value["admission"]
    if admission is None:
        check(not required, "missing prepared administrator consent")
        public(value, f["code"], f["reply"]); return
    check(set(admission) == {"review_id", "review", "state", "next_action"}, "exact admission object shape")
    review = admission["review"]
    check(set(review) == REVIEW and type(review["version"]) is int and review["version"] == 1 and
          review["kind"] == "approve_new_original_admission", "exact new-original administrator review shape")
    check(review["host_id"] == a.id and review["context"] == context(parent) and review["agent"] == parent["review"]["agent"],
          "review changed attached public context/agent")
    check(review["network"] == {k: f["network"][k] for k in ("id", "name", "context_id", "genesis_root_public_key")},
          "review changed signed adopted network descriptor")
    for key in ("request_id", "request_packet_id", "owner_offer_id", "selection_id", "person_public_key", "host_public_key", "device_public_key"):
        check(review[key] == request[key], "review changed selected original/request identity: " + key)
    check(review["member"] == f["member"] and review["person_public_key"] == f["person"] and
          review["host_public_key"] == f["b"].public_key and type(review["scopes"]) is int and review["scopes"] == 7,
          "review changed member/original/profile")
    check(review["request_created_at"] == request["created_at"] and review["request_expires_at"] == request["expires_at"] and
          parse_time(review["not_after"]) == parse_time(request["created_at"]) + timedelta(days=7),
          "review changed signed request bounds or fixed machine lifetime")
    stored = intent(a, review["intent_id"])
    record = stored["record"]
    ordinary = json.loads(base64.b64decode(record["review_base64"], validate=True))
    check(stored["kind"] == "administrator" and stored["network_id"] == f["network"]["id"] and
          stored["context_id"] == f["network"]["context_id"] and stored["secret"] is None,
          "consent created wrong ordinary intent or another secret store")
    check(record["provider"] == {"kind": "root", "signer_public_key": review["root_public_key"],
          "signature_format": "ed25519", "lease_id": "-"} and record["root_state_id"] == review["root_state_id"],
          "consent selected unsupported/root-key fallback provider")
    for key in ("root_state_id", "person_lease_id", "host_lease_id", "owner_offer_id", "selection_id", "scopes", "not_after"):
        check(review[key] == ordinary[key], "public consent changed exact ordinary draft: " + key)
    check(all(re.fullmatch(r"ds_[0-9a-f]{64}", review[k]) for k in ("root_state_id", "person_lease_id", "host_lease_id")),
          "malformed exact root/P/H draft IDs")
    check(review["created_at"] == record["created_at"] and parse_time(review["expires_at"]) ==
          min(parse_time(request["expires_at"]), parse_time(record["created_at"]) + timedelta(minutes=15)),
          "review renewed immutable creation/deadline")
    for key in ("request_created_at", "request_expires_at", "created_at", "expires_at", "not_after"):
        check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", review[key]), "noncanonical public consent date")
    check(review["effects"] == EFFECTS and all(type(v) is bool for v in review["effects"].values()), "consent widened admission/F/commit/access effects")
    check(admission["review_id"] == digest("peerspan-onboarding-original-admission-review-v1", review), "recursive UTF-8 canonical administrator review digest")
    actions = {"review": "approve_administrator_intent", "approved": "follow_link_progress", "cancelled": "inspect_link_progress",
               "expired": "inspect_link_progress", "invalidated": "inspect_link_progress"}
    check(admission["state"] in actions and admission["next_action"] == actions[admission["state"]], "consent state claimed wrong next action")
    check((admission["state"] == "approved") == (record["approved"] is True), "public approval differs from durable ordinary consent")
    public(value, f["code"], f["reply"], str(f["key"]))


def op(f, action, prepared=None, *, parent=None, status=200, code=None, override=None):
    a = f["a"]; before = link_view(a, f["rid"]) if status == 200 else None
    actual, value = a.api("POST", BASE + "/" + action, override if override is not None else payload(f, prepared if action == "approve" else None, parent))
    check(actual == status, f"admission {action} HTTP {actual}, want {status}")
    if code:
        check(isinstance(value, dict) and value.get("code") == code,
              f"{action} code {value.get('code') if isinstance(value, dict) else None}, want {code}")
    if actual == 200:
        validate(f, value, parent=parent, requests=(before, link_view(a, f["rid"])), required=action != "lookup")
    public(value, f["code"], f["reply"])
    return value


def pure(f, action, prepared=None, *, parent=None, status=200, code=None, override=None):
    a = f["a"]; settled(a); before = snapshot(a)
    value = op(f, action, prepared, parent=parent, status=status, code=code, override=override)
    after = snapshot(a)
    tables = sorted(k for k in set(before[0]) | set(after[0]) if before[0].get(k) != after[0].get(k))
    state_paths = sorted(k for k in set(before[1]) | set(after[1]) if before[1].get(k) != after[1].get(k))
    home_paths = sorted(k for k in set(before[2]) | set(after[2]) if before[2].get(k) != after[2].get(k))
    check(after == before, f"{action} changed logical records/files: tables={tables}, state_paths={state_paths}, home_paths={home_paths}")
    return value


def main():
    if not main_fixture:
        main_fixture["initializing"] = True
        try:
            fixture = pair("main")
        except Exception:
            main_fixture["failed"] = True; raise
        main_fixture.clear(); main_fixture.update(fixture)
    check(not main_fixture.get("failed"), "earlier shared genuine prefix setup failed")
    return main_fixture


def prepared_main():
    f = main()
    if "prepared" not in f:
        f["prepared"] = op(f, "prepare")
    return f, f["prepared"]


def raw_post(a, action, raw):
    conn = UnixHTTPConnection(str(a.state / "admin.sock"), timeout=10)
    try:
        try:
            conn.request("POST", BASE + "/" + action, body=raw, headers={"Content-Type": "application/json"})
        except BrokenPipeError:
            pass  # Still require the exact early HTTP refusal; never retry.
        response = conn.getresponse(); data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        conn.close()


@suite.case("null_lookup_exact_unapproved_root_drafts_and_pure_fixed_prepare", "guided21 verification1")
def _():
    f = main(); a = f["a"]
    check(pure(f, "lookup")["admission"] is None, "lookup prepared consent")
    private_parent = project(a, "private-agent", agent_name="token_PRIVATE_SHORT")
    pure(f, "prepare", parent=private_parent, status=409, code="admission_review_unavailable")
    check(pure(f, "lookup")["admission"] is None, "failed private-metadata preparation left an intent/reference")
    before = settled(a); files, home = private_files(a.state), private_files(a.home)
    old_pending, old_secret = pending(a, f["rid"])
    value = op(f, "prepare"); f["prepared"] = value
    admission = value["admission"]; review = admission["review"]; current = intent(a, review["intent_id"])["record"]
    check(admission["state"] == "review" and current["approved"] is False and current["approved_at"] == "-" and
          current["signatures"] == [] and current["completed"] is False,
          "prepare approved/signed/published the ordinary root intent")
    after = records(a)
    check(without(after, "dec_intents", "dec_pending", "dec_clock") == without(before, "dec_intents", "dec_pending", "dec_clock") and
          len(after["dec_intents"]) == len(before["dec_intents"]) + 1, "prepare created a journal/schema/event/authority mutation")
    now_pending, now_secret = pending(a, f["rid"])
    check(now_pending["administrator_intent_id"] == review["intent_id"] and
          without(now_pending, "administrator_intent_id") == without(old_pending, "administrator_intent_id") and now_secret == old_secret,
          "prepare changed protocol evidence outside one ordinary intent reference")
    check(private_files(a.state) == files and private_files(a.home) == home, "prepare changed key/private files")
    net = get(a, "/v2/networks/" + f["network"]["id"])
    check(review["root_state_id"] == net["root_state_id"] and review["root_public_key"] == net["root_public_key"], "prepare did not freeze current owned root")
    for action in ("prepare", "lookup", "prepare"):
        retry = pure(f, action)
        check(retry["admission"] == admission, "retained prepare/lookup renewed or changed fixed consent")


@suite.case("atomic_lost_response_approved_restart_expiry_detached_global_history", "guided21 verification2")
def _():
    f = pair("hist"); a = f["a"]; prepared = op(f, "prepare")
    fixed = prepared["admission"]; iid = fixed["review"]["intent_id"]; initial = intent(a, iid)["record"]
    conn = UnixHTTPConnection(str(a.state / "admin.sock"), timeout=10)
    try:
        conn.request("POST", BASE + "/approve", body=compact(payload(f, prepared)), headers={"Content-Type": "application/json"})
        response = conn.getresponse(); check(response.status == 200, "lost-response approval did not commit")
        # Intentionally discard body after committed success headers.
    finally:
        conn.close()
    approved = op(f, "lookup")
    check(approved["admission"]["state"] == "approved" and without(approved["admission"], "state", "next_action") ==
          without(fixed, "state", "next_action"), "response loss changed exact consent")
    record = intent(a, iid)["record"]
    check(record["approved"] is True and record["approved_at"] != "-" and record["created_at"] == initial["created_at"] and
          record["provider"] == initial["provider"], "approval is not the same durable root intent")
    # External ordinary driver observes allowed root/host signatures, never
    # attributes them to lookup/prepare or another frontend.
    pull_until(a, f["rid"], "administrator_offer_id", timeout=15)
    for action in ("lookup", "prepare", "approve"):
        result = pure(f, action, prepared)
        check(result["admission"] == approved["admission"], "approved retry changed fixed global consent")
    other = project(a, "global")
    global_view = pure(f, "lookup", parent=other)
    check(global_view["admission"]["state"] == "approved" and
          without(global_view["admission"]["review"], "context", "agent") == without(fixed["review"], "context", "agent") and
          global_view["admission"]["review_id"] != fixed["review_id"], "another valid context fabricated frontend attribution")
    a.restart(kill=True)
    check(get(a, PROJECT + "/" + f["parent"]["flow_id"])["state"] == "invalidated", "restart did not detach parent fixture")
    advance_to(a, parse_time(fixed["review"]["expires_at"]) + timedelta(seconds=1))
    # Explicit ordinary driver settles expiry independently before the snapshots.
    a.cli("link", "resume", f["rid"], timeout=15)
    for action in ("lookup", "prepare", "approve"):
        result = pure(f, action, prepared)
        check(result["admission"] == approved["admission"], "detached/elapsed history discarded approved consent")
    wrong = {**payload(f, prepared), "admission_review_id": "review_" + "0" * 64}
    before = settled(a); op(f, "approve", prepared, status=409, code="review_changed", override=wrong)
    check(records(a) == before and intent(a, iid)["record"]["approved_at"] == record["approved_at"], "wrong historical digest wrote approval")
    a.stop()


@suite.case("binding_cancel_clock_profile_and_authentic_unsupported_provider_refuse_pure", "guided21 verification3")
def _():
    f = pair("neg"); a = f["a"]
    pure(f, "approve", status=409, code="admission_review_unavailable", override={
        **payload(f), "admission_review_id": "review_" + "0" * 64})
    prepared = op(f, "prepare")
    for patch in ({"admission_review_id": "review_" + "1" * 64},
                  {"context": {**context(f["parent"]), "native_session_id": "different-conversation"}},
                  {"context": {**context(f["parent"]), "project_root": str(suite.work / "different root")}}):
        pure(f, "approve", prepared, status=409, code="review_changed", override={**payload(f, prepared), **patch})
    pure(f, "lookup", status=404, code="not_found", override={**payload(f), "request_id": "link_" + "0" * 64})
    pure(f, "prepare", status=404, code="not_found", override={**payload(f), "context": {
        **context(f["parent"]), "project_flow_id": "flow_" + "0" * 32}})
    a.clock.set(-120)
    pure(f, "approve", prepared, status=409, code="admission_review_unavailable")
    a.clock.set(0)
    check(pure(f, "lookup")["admission"] == prepared["admission"], "stale guarded refusal changed fixed pending review")
    a.ok("session", "detach", f["parent"]["review"]["session_id"])
    check(pure(f, "lookup")["admission"]["state"] == "invalidated", "detached pending context remained actionable")
    pure(f, "approve", prepared, status=409, code="review_changed")
    # Restore one valid explicit context before the independent time stimulus;
    # do not combine parent failure with expiry-code expectations.
    parent = project(a, "neg-restored", replace=f["parent"]["flow_id"], old=f["parent"])
    f["parent"] = parent
    prepared = op(f, "prepare")
    check(prepared["admission"]["state"] == "review", "replacement context did not preserve compatible unapproved intent")
    # Stage expires before the independent 15-minute review window. Exercise
    # actual public stage/request expiry without claiming isolation of the later
    # review deadline in an otherwise inactive ordinary ceremony.
    past_stage = parse_time(prepared["observed_at"]) + timedelta(minutes=11)
    check(past_stage < parse_time(prepared["admission"]["review"]["expires_at"]), "fixture lost independent stage bound")
    advance_to(a, past_stage)
    check(pure(f, "lookup")["admission"]["state"] == "expired", "stage expiry did not outrank detached state")
    pure(f, "approve", prepared, status=409, code="review_expired")
    advance_to(a, parse_time(prepared["request"]["expires_at"]) + timedelta(seconds=1))
    check(pure(f, "lookup")["admission"]["state"] == "expired", "request expiry did not invalidate consent")
    a.stop()
    cancelled = pair("cancel"); p = op(cancelled, "prepare")
    check(cancelled["a"].api("POST", "/v2/link/requests/" + cancelled["rid"] + "/cancel", {})[0] == 200, "public cancellation fixture")
    check(pure(cancelled, "lookup")["admission"]["state"] == "cancelled", "cancelled review remained actionable")
    pure(cancelled, "approve", p, status=409, code="admission_review_unavailable"); cancelled["a"].stop()
    for name, options in (("profile", {"scopes": 1}), ("short", {"short": True})):
        bad = pair(name, **options)
        pure(bad, "prepare", status=409, code="admission_review_unavailable")
        bad["a"].stop()
    unsupported = pair("ssh", ssh_root=True); a = unsupported["a"]
    pure(unsupported, "prepare", status=409, code="admission_review_unavailable")
    v = link_view(a, unsupported["rid"])
    status, ordinary = a.api("POST", "/v2/link/admissions", {
        "code": "-", "request_id": unsupported["rid"], "network_id": unsupported["network"]["id"],
        "person_public_key": unsupported["person"], "provider_id": "network_root", "signature_format": "sshsig",
        "owner_offer_id": v["owner_offer_id"], "selection_id": v["selection_id"],
        "expected_host_public_key": v["host_public_key"], "expected_device_public_key": v["device_public_key"], "approve": False})
    check(status == 200, f"explicit negative-only ordinary SSH-root preview HTTP {status}")
    rec, _ = pending(a, unsupported["rid"]); iid = rec["administrator_intent_id"]
    retained = intent(a, iid)["record"]
    check(retained["provider"]["kind"] == "root" and retained["provider"]["signature_format"] == "sshsig" and
          retained["approved"] is False and retained["signatures"] == [], "negative fixture did not retain unsupported unapproved provider")
    pure(unsupported, "prepare", status=409, code="admission_review_unavailable")
    check(intent(a, iid)["record"] == retained, "guided preparation replaced/approved unsupported ordinary provider")
    a.stop()


@suite.case("strict_private_cli_json_bounds_context_methods_and_scoped_router_isolation", "guided21 verification4")
def _():
    f = pair("bound"); a = f["a"]; prepared = op(f, "prepare")
    for action in ("lookup", "prepare", "approve"):
        data = payload(f, prepared if action == "approve" else None); raw = compact(data)
        maximum = raw + b" " * (65536 - len(raw))
        if action != "approve":
            actual, value = raw_post(a, action, maximum)
            check(actual == 200 and value["admission"] == prepared["admission"], f"{action} exact64KiB API")
            validate(f, value, requests=(link_view(a, f["rid"]),))
            result = a.cli("onboarding", "admission", action, "--stdin", input=maximum.decode(), timeout=10)
            check(result.ok and result.json["admission"] == prepared["admission"], f"{action} exact64KiB CLI parity")
            validate(f, result.json, requests=(link_view(a, f["rid"]),))
            public(result.stdout, f["code"], f["reply"])
        else:
            wrong = {**data, "admission_review_id": "review_" + "0" * 64}; wrong = compact(wrong)
            actual, denied = raw_post(a, action, wrong + b" " * (65536 - len(wrong)))
            check(actual == 409 and denied.get("code") == "review_changed", "approve exact64KiB failed lexical validation instead of exact digest")
        ctx = compact(data["context"])
        duplicate = b'{"context":' + ctx + b',"context":' + ctx + b',"request_id":' + compact(f["rid"]) + (
            b',"admission_review_id":' + compact(prepared["admission"]["review_id"]) if action == "approve" else b'') + b'}'
        malformed = [b"null", b"[]", b"{", raw + b"{}", maximum + b" ", duplicate,
                     raw.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
                     compact({**data, "request_id": None}), compact({**data, "request_id": "link_bad"}),
                     compact({**data, "context": None}), compact({**data, "context": {**data["context"], "extra": "PRIVATE_INPUT"}})]
        for key in ("provider", "signature_format", "scopes", "not_after", "approve", "invitation", "key_file", "packet", "template"):
            malformed.append(compact({**data, key: "PRIVATE_INPUT"}))
        if action == "approve":
            malformed += [compact(without(data, "admission_review_id")), compact({**data, "admission_review_id": None}),
                          compact({**data, "admission_review_id": "review_bad"})]
        else:
            malformed.append(compact({**data, "admission_review_id": prepared["admission"]["review_id"]}))
        before = snapshot(a)
        for index, invalid in enumerate(malformed):
            actual, denied = raw_post(a, action, invalid)
            check(actual == 400 and denied.get("code") == "invalid", f"{action} malformed API variant{index}: HTTP {actual}")
            public(denied, "PRIVATE_INPUT")
            result = a.cli("onboarding", "admission", action, "--stdin", input=invalid.decode(), timeout=10)
            check(not result.ok, f"{action} CLI accepted malformed/duplicate/trailing/oversized input variant{index}")
            public(result.stdout + result.stderr, "PRIVATE_INPUT", str(a.state))
        check(snapshot(a) == before, f"malformed {action} changed logical records/private files")
        for method in ("GET", "PUT", "DELETE"):
            actual, denied = a.api(method, BASE + "/" + action)
            check(actual == 405, f"{action} method {method}: HTTP {actual}"); public(denied)
        for args in (("onboarding", "admission", action), ("onboarding", "admission", action, f["rid"], "--stdin")):
            result = a.cli(*args, input=raw.decode(), timeout=10)
            check(not result.ok, "CLI accepted implicit stdin/positional request"); public(result.stdout + result.stderr, f["rid"])
    missing = suite.host("nd", start=False); before = private_files(missing.root)
    for action in ("lookup", "prepare", "approve"):
        result = missing.cli("onboarding", "admission", action, "--stdin",
            input=compact(payload(f, prepared if action == "approve" else None)).decode(), timeout=10)
        check(not result.ok and private_files(missing.root) == before, "CLI started daemon or initialized state")
        public(result.stdout + result.stderr, str(missing.root))
    credential = a.ok("adapter", "create", "--session", f["parent"]["review"]["session_id"], "--expires-at", rfc3339(a.now() + timedelta(hours=1)))
    adapter = Adapter(a, f["parent"]["review"]["agent"], f["parent"]["review"]["session_id"], credential)
    check(adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id, "session_id": adapter.session_id,
          "instance_id": adapter.instance})[0] == 200, "real scoped adapter fixture")
    peer, bootstrap = host("peer"), host("boot")
    for local, remote in ((a, peer), (peer, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    cert, key = suite.work / "consent-cert.pem", suite.work / "consent-tls-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    for action in ("lookup", "prepare", "approve"):
        endpoint = BASE + "/" + action; data = payload(f, prepared if action == "approve" else None)
        actual, denied = adapter.call("POST", endpoint, data)
        check(actual == 404, f"scoped adapter exposed {action}: HTTP {actual}"); public(denied, adapter.token)
        result = subprocess.run([str(suite.probe_bin), "--state", str(peer.state), "--address", a.peer_address, "--alpn", "peerspan-peer/1",
            "--method", "POST", "--path", endpoint, "--body-stdin"], input=compact(data), capture_output=True, timeout=10)
        check(result.returncode == 0 and json.loads(result.stdout)["status"] == 404, f"authenticated peer exposed {action}")
        raw = compact(data)
        with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as connection:
            with tls.wrap_socket(connection, server_hostname="peerspan") as stream:
                stream.sendall((f"POST {endpoint} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n").encode() + raw)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, f"bootstrap exposed {action}: HTTP {response.status}")
    peer.stop(); bootstrap.stop()
    # Valid explicit private CLI approval is last; subsequent background signing
    # is allowed and is excluded from malformed/read-only purity comparisons.
    maximum = compact(payload(f, prepared)); maximum += b" " * (65536 - len(maximum))
    before_request = link_view(a, f["rid"])
    result = a.cli("onboarding", "admission", "approve", "--stdin", input=maximum.decode(), timeout=10)
    check(result.ok and result.json["admission"]["state"] == "approved", "private CLI exact64KiB approval parity")
    validate(f, result.json, requests=(before_request, link_view(a, f["rid"])))
    public(result.stdout, f["code"], f["reply"], adapter.token)
    a.stop()


@suite.case("schema_only_abort_rolls_back_exact_ordinary_approval_then_retry", "guided21 verification5")
def _():
    f, prepared = prepared_main(); a = f["a"]; iid = prepared["admission"]["review"]["intent_id"]
    before_schema = records(a)["$schema"]
    with closing(sqlite3.connect(db_path(a))) as db, db:
        db.execute(f"CREATE TRIGGER consent_abort BEFORE UPDATE OF record ON dec_intents WHEN OLD.intent_id='{iid}' "
                   "BEGIN SELECT RAISE(ABORT, 'PRIVATE_ABORT_INJECTION'); END")
    try:
        before = snapshot(a)
        actual, denied = a.api("POST", BASE + "/approve", payload(f, prepared))
        check(not 200 <= actual < 300, f"injected approval unexpectedly succeeded: HTTP {actual}")
        public(denied, "PRIVATE_ABORT_INJECTION", f["code"], f["reply"])
        check(snapshot(a) == before and intent(a, iid)["record"]["approved"] is False and
              intent(a, iid)["record"]["approved_at"] == "-", "ABORT left partial approval/clock/reference/schema/private writes")
    finally:
        with closing(sqlite3.connect(db_path(a))) as db, db:
            db.execute("DROP TRIGGER consent_abort")
    check(records(a)["$schema"] == before_schema, "fault injection left storage schema behind")
    approved = op(f, "approve", prepared)
    check(approved["admission"]["state"] == "approved" and approved["admission"]["review"] == prepared["admission"]["review"] and
          intent(a, iid)["record"]["approved"] is True, "exact retry did not atomically approve same ordinary intent")


@suite.case("same_intent_root_publication_original_F_commit_and_pure_fixed_history", "guided21 verification6")
def _():
    f, prepared = prepared_main(); a, b, rid = f["a"], f["b"], f["rid"]
    # Explicit idempotent approval also makes this case independently runnable.
    approved = op(f, "approve", prepared)
    iid = approved["admission"]["review"]["intent_id"]; first = intent(a, iid)["record"]
    check(approved["admission"]["state"] == "approved", "missing explicit administrator consent")
    view = pull_until(a, rid, "administrator_offer_id", timeout=15)
    check(view["owner_finalization_id"] == "-" and not view["commit_approved"], "root consent supplied original F or requester commit")
    b.start()
    view = pull_until(b, rid, "administrator_offer_id", timeout=20)
    finalize(b, view, f["key"])
    view = pull_until(b, rid, "owner_finalization_id", timeout=20)
    check(view["state"] == "needs_commit" and not view["commit_approved"] and get(b, "/v2/networks") == [],
          "administrator consent/finalization granted membership or requester commit")
    commit(b, view); wait_linked(b, a, rid, timeout=20)
    b.stop(); settled(a)
    for action in ("lookup", "prepare", "approve"):
        result = pure(f, action, prepared)
        check(result["admission"] == approved["admission"] and result["request"]["state"] == "linked",
              "explicit F/commit altered original root/P/H consent history")
    current = intent(a, iid)["record"]
    check(current["approved"] is True and current["approved_at"] == first["approved_at"] and
          current["created_at"] == first["created_at"] and current["provider"] == first["provider"] and
          pending(a, rid)[0]["administrator_intent_id"] == iid, "later stages replaced same approved ordinary intent")
    wrong = {**payload(f, prepared), "admission_review_id": "review_" + "0" * 64}
    pure(f, "approve", prepared, status=409, code="review_changed", override=wrong)
    # An unknown retained-request reference cannot create a new history/intent.
    for action in ("lookup", "prepare", "approve"):
        pure(f, action, prepared, status=404, code="not_found", override={
            **payload(f, prepared if action == "approve" else None), "request_id": "link_" + "0" * 64})
    public(get(a, "/v1/activity?limit=1000"), f["code"], f["reply"])


suite.finish()
