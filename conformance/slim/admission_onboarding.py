#!/usr/bin/env python3
"""Read-only incoming admission inspection, guided contract section20.

Independent real hosts and original people; public automatic invitation return,
actual original SSHSIG/selection, and ordinary advanced completion. No production
imports, /admissions preview setup, protocol/authority row fabrication or DB
mutation. Whole-DB purity follows independently settled transport with the remote
stopped; mutable SQLite WAL/SHM bookkeeping is excluded, durable DB content is
compared logically. Unknown/missing owner, requester-side, unsupported terms,
cancellation, clock/stage/request expiry and later stages use genuine evidence.
Unreachable no-selection/admitted-provider/renewal/migration and missing/pruned/
corrupt-proof retention intervals remain source/fault limits without bounded
public fixtures. No physical/installed/native/model acceptance is inferred.
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

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check,
                     commit, create_network, finalize, link_view, parse_time,
                     pull_until, rfc3339, select, ssh_key, ssh_public_base64,
                     wait_for, wait_linked)

suite = Suite("admission_onboarding", __doc__)
BASE = "/v1/onboarding/admission-inspection"
PROJECT = "/v1/onboarding/project-flows"
EFFECTS = {"verify_request_signature": True, "verify_original_owner_signature": True,
           "verify_requester_selection": True, "prepare_administrator_intent": False,
           "approve_administrator_intent": False, "sign_admission": False,
           "grant_membership": False, "grant_agent_access": False, "commit_request": False,
           "share_files": False, "share_conversation": False, "capability_calls": False}
TOP = {"version", "host_id", "context", "observed_at", "request", "review_id", "review", "next_action"}
REVIEW = {"version", "kind", "host_id", "context", "agent", "network", "root_state_id",
          "request_id", "request_packet_id", "owner_offer_id", "selection_id", "member",
          "person_public_key", "host_public_key", "device_public_key", "scopes", "not_after",
          "created_at", "expires_at", "effects"}
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


PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
LINK_KEYS = set('request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next'.split())


def public(value, *secrets):
    text = json.dumps(value, ensure_ascii=False, default=str)
    for index, marker in enumerate((*PREFIXES, 'payload_base64', 'template_base64', 'message_base64',
                   'secret_base64', 'signing_requests', 'return_secret', 'admin.sock',
                   'adapter.sock', '"signature"', '"seed"', *secrets)):
        check(not marker or marker not in text, f"inspection exposed private input/signing/provider material (rule {index})")


def body(parent, rid):
    return {"context": context(parent), "request_id": rid}


def inspect(h, parent, rid, *, status=200, code=None, override=None):
    actual, value = h.api("POST", BASE, body(parent, rid) if override is None else override)
    check(actual == status, f"inspection HTTP {actual}, want {status}")
    if code:
        check(isinstance(value, dict) and value.get("code") == code,
              f"inspection code {value.get('code') if isinstance(value, dict) else None}, want {code}")
    public(value)
    return value


def snapshot(h):
    return records(h), private_files(h.state), private_files(h.home)


def pure(h, parent, rid, *, status=200, code=None):
    settled(h); before = snapshot(h)
    value = inspect(h, parent, rid, status=status, code=code)
    check(snapshot(h) == before, "inspection changed logical tables/schema, durable files, key files or events")
    return value


def raw_post(h, data):
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=10)
    try:
        try:
            connection.request("POST", BASE, body=data, headers={"Content-Type": "application/json"})
        except BrokenPipeError:
            pass  # A legal early refusal can close before a large body finishes.
        response = connection.getresponse(); payload = response.read()
        return response.status, json.loads(payload) if payload else None
    finally:
        connection.close()


def validate(f, value, parent=None):
    a, b, rid = f["a"], f["b"], f["rid"]
    parent = parent or f["parent"]
    check(set(value) == TOP and type(value["version"]) is int and value["version"] == 1,
          "exact inspection wrapper/version")
    check(value["host_id"] == a.id and value["context"] == context(parent) and
          value["next_action"] == "review_administrator_consent", "inspection changed host/context/next consent")
    request = value["request"]
    check(set(request) == LINK_KEYS and request == link_view(a, rid) and request["role"] == "approver" and
          request["state"] == "needs_administrator", "inspection is not the exact ordinary incoming LINK_VIEW")
    review = value["review"]
    check(set(review) == REVIEW and type(review["version"]) is int and review["version"] == 1 and
          review["kind"] == "inspect_new_original_admission", "exact public admission review shape")
    check(review["host_id"] == a.id and review["context"] == context(parent) and
          review["agent"] == parent["review"]["agent"], "review changed attached agent/context")
    check(review["network"] == {key: f["network"][key] for key in ("id", "name", "context_id", "genesis_root_public_key")} and
          review["root_state_id"] == get(a, "/v2/networks/" + f["network"]["id"])["root_state_id"],
          "review changed verified network descriptor/root projection")
    for key in ("request_id", "request_packet_id", "owner_offer_id", "selection_id", "person_public_key",
                "host_public_key", "device_public_key", "created_at", "expires_at"):
        check(review[key] == request[key], "review changed signed request/owner/selection binding: " + key)
    check(review["person_public_key"] == f["person"] and review["host_public_key"] == b.public_key and
          review["member"] == f["member"] and type(review["scopes"]) is int and review["scopes"] == 7,
          "review changed original possession identity/member/profile")
    check(parse_time(review["not_after"]) == parse_time(request["created_at"]) + timedelta(days=7),
          "review extended the fixed signed-request seven-day target lifetime")
    for key in ("observed_at",):
        check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value[key]) and
              abs((parse_time(value[key]) - a.now()).total_seconds()) < 5, "canonical guarded observation time")
    for key in ("created_at", "expires_at", "not_after"):
        check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", review[key]), "noncanonical public date")
    check(review["effects"] == EFFECTS and all(type(v) is bool for v in review["effects"].values()),
          "inspection claimed consent/signing/admission/access/work effects")
    check(value["review_id"] == digest("peerspan-admission-inspection-v1", review), "recursive UTF-8 canonical review digest")
    public(value, f["code"], f["reply"], str(f["key"]))


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


def pair(name, *, scopes=7, short=False, before_owner=None):
    a, b = progress_transport_host(name + "a"), progress_transport_host(name + "b")
    net = create_network(a, 'Admission "é東京" ' + name, "inviter")
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


def current():
    if not shared:
        shared["initializing"] = True
        def pending_refusals(f):
            inspect(f["a"], f["parent"], f["rid"], status=409, code="admission_inspection_unavailable")
            inspect(f["b"], f["remote_parent"], f["rid"], status=409, code="admission_inspection_unavailable")
        try:
            fixture = pair("main", before_owner=pending_refusals)
        except Exception:
            shared["setup_failed"] = True
            raise
        shared.clear(); shared.update(fixture)
    check(not shared.get("setup_failed"), "shared genuine prefix setup failed in earlier case")
    return shared


@suite.case("genuine_returned_original_selection_exact_review_and_pure_retry", "guided20 verification1,3")
def _():
    f = current(); a, parent, rid = f["a"], f["parent"], f["rid"]
    first = pure(a, parent, rid); validate(f, first)
    second = pure(a, parent, rid); validate(f, second)
    check(first["review"] == second["review"] and first["review_id"] == second["review_id"], "pure retry changed exact verified review")
    # Inspection creates no administrator intent or authority. Whole logical
    # snapshots above include ordinary intents, approvals, clock and all tables.
    rec, _ = pending(a, rid)
    check(not rec.get("administrator_intent_id") or rec["administrator_intent_id"] == "-", "inspection prepared administrator consent")



@suite.case("strict_private_cli_api_context_methods_and_credentials", "guided20 verification2")
def _():
    f = current(); a, parent, rid = f["a"], f["parent"], f["rid"]
    payload = body(parent, rid); encoded = compact(payload)
    maximum = encoded + b" " * (65536 - len(encoded))
    before = snapshot(a)
    actual, value = raw_post(a, maximum)
    check(actual == 200, f"exact64KiB API input HTTP {actual}"); validate(f, value)
    result = a.cli("onboarding", "admission", "inspect", "--stdin", input=maximum.decode(), timeout=10)
    check(result.ok, "exact64KiB private CLI input refused"); validate(f, result.json)
    ctx = compact(payload["context"])
    malformed = [b"null", b"[]", b"{", encoded + b"{}", maximum + b" ",
                 b'{"context":' + ctx + b',"context":' + ctx + b',"request_id":' + compact(rid) + b'}',
                 encoded.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"')]
    for replacement in (None, 1, [], "link_bad", "link_" + "A" * 64):
        malformed.append(compact({**payload, "request_id": replacement}))
    malformed += [compact(without(payload, "context")), compact({**payload, "context": None}),
                  compact({**payload, "context": {**payload["context"], "extra": "PRIVATE_INPUT"}})]
    for key in ("invitation", "provider", "person_key", "scopes", "not_after", "approve", "packet", "template"):
        malformed.append(compact({**payload, key: "PRIVATE_INPUT"}))
    for i, raw in enumerate(malformed):
        actual, denied = raw_post(a, raw)
        check(actual == 400 and denied.get("code") == "invalid", f"malformed API variant{i}: HTTP {actual}")
        public(denied, "PRIVATE_INPUT", f["code"], f["reply"])
        result = a.cli("onboarding", "admission", "inspect", "--stdin", input=raw.decode(), timeout=10)
        check(not result.ok, f"CLI accepted malformed/duplicate/trailing/oversized input variant{i}")
        public(result.stdout + result.stderr, "PRIVATE_INPUT", f["code"], f["reply"], str(a.state))
    check(snapshot(a) == before, "strict input handling changed logical records or private files")
    for method in ("GET", "PUT", "DELETE"):
        actual, denied = a.api(method, BASE)
        check(actual == 405, f"alternate method {method}: HTTP {actual}"); public(denied)
    inspect(a, parent, "link_" + "0" * 64, status=404, code="not_found")
    for key, value in (("project_root", str(suite.work / "another private root")),
                       ("native_session_id", "different-conversation"), ("project_review_id", "review_" + "0" * 64)):
        inspect(a, parent, rid, status=409, code="review_changed", override={
            **payload, "context": {**payload["context"], key: value}})
    inspect(a, parent, rid, status=404, code="not_found", override={
        **payload, "context": {**payload["context"], "project_flow_id": "flow_" + "0" * 32}})
    for args in (("onboarding", "admission", "inspect"), ("onboarding", "admission", "inspect", rid, "--stdin")):
        result = a.cli(*args, input=encoded.decode(), timeout=10)
        check(not result.ok, "CLI accepted missing --stdin or positional request reference"); public(result.stdout + result.stderr, rid)
    missing = suite.host("nd", start=False); absent = private_files(missing.root)
    result = missing.cli("onboarding", "admission", "inspect", "--stdin", input=encoded.decode(), timeout=10)
    check(not result.ok and private_files(missing.root) == absent, "CLI started daemon or initialized missing state")
    public(result.stdout + result.stderr, str(missing.root), f["code"], f["reply"])
    credential = a.ok("adapter", "create", "--session", parent["review"]["session_id"],
                      "--expires-at", rfc3339(a.now() + timedelta(hours=1)))
    adapter = Adapter(a, parent["review"]["agent"], parent["review"]["session_id"], credential)
    actual, _ = adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id,
        "session_id": adapter.session_id, "instance_id": adapter.instance})
    check(actual == 200, "real scoped credential fixture")
    actual, denied = adapter.call("POST", BASE, payload)
    check(actual == 404, f"scoped adapter exposed inspection: HTTP {actual}"); public(denied, adapter.token)
    peer = host("peer")
    for local, remote in ((a, peer), (peer, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    result = subprocess.run([str(suite.probe_bin), "--state", str(peer.state), "--address", a.peer_address,
        "--alpn", "peerspan-peer/1", "--method", "POST", "--path", BASE, "--body-stdin"],
        input=encoded, capture_output=True, timeout=10)
    check(result.returncode == 0 and json.loads(result.stdout)["status"] == 404, "authenticated peer exposed inspection")
    bootstrap = host("boot")
    cert, key = suite.work / "cert.pem", suite.work / "tls-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=boundary", "-days", "1",
        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
        with tls.wrap_socket(raw, server_hostname="peerspan") as stream:
            stream.sendall((f"POST {BASE} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n").encode() + encoded)
            response = http.client.HTTPResponse(stream); response.begin(); response.read()
            check(response.status == 404, f"bootstrap exposed inspection: HTTP {response.status}")
    peer.stop(); bootstrap.stop()
    public(get(a, "/v1/activity?limit=1000"), f["code"], f["reply"], adapter.token)


@suite.case("unsupported_profile_lifetime_and_cancelled_genuine_prefix_refuse_pure", "guided20 verification3")
def _():
    for name, options in (("profile", {"scopes": 1}), ("short", {"short": True}), ("cancel", {})):
        f = pair(name, **options); a, rid = f["a"], f["rid"]
        # Different terms are signed through the ordinary explicit CLI, not
        # rewritten retained owner packets or invented authority records.
        if not options:
            actual, denied = a.api("POST", "/v2/link/requests/" + rid + "/cancel", {})
            check(actual == 200, f"public cancellation HTTP {actual}")
        pure(a, f["parent"], rid, status=409, code="admission_inspection_unavailable")
        a.stop()


@suite.case("guarded_stale_future_stage_and_request_expiry_refuse_pure", "guided20 verification3,6")
def _():
    f = pair("clock"); a, parent, rid = f["a"], f["parent"], f["rid"]
    original = pure(a, parent, rid); validate(f, original)
    a.clock.set(-120)
    pure(a, parent, rid, status=409, code="admission_inspection_unavailable")
    a.clock.set(0)
    restored = pure(a, parent, rid)
    check(restored["review"] == original["review"] and restored["review_id"] == original["review_id"],
          "stale observation advanced clock or changed retained evidence")
    # Every real stage precedes fixture completion. Eleven minutes after this
    # observation is beyond the ten-minute stage bound and before one-hour expiry.
    stage_expired = parse_time(original["observed_at"]) + timedelta(minutes=11)
    check(stage_expired < parse_time(original["request"]["expires_at"]), "fixture exhausted request window")
    advance_to(a, stage_expired)
    pure(a, parent, rid, status=409, code="admission_inspection_unavailable")
    advance_to(a, parse_time(original["request"]["expires_at"]) + timedelta(seconds=1))
    pure(a, parent, rid, status=409, code="admission_inspection_unavailable")
    a.stop()


@suite.case("restart_replacement_and_private_decorated_agent_metadata_refuse_pure", "guided20 verification6,privacy")
def _():
    f = current(); a, parent, rid = f["a"], f["parent"], f["rid"]
    original = pure(a, parent, rid)
    a.restart(kill=True)
    pure(a, parent, rid, status=409, code="review_changed")
    replacement = project(a, "replacement", replace=parent["flow_id"], old=parent)
    fresh = pure(a, replacement, rid); validate(f, fresh, replacement)
    check(without(fresh["review"], "context", "agent") == without(original["review"], "context", "agent") and
          fresh["review_id"] != original["review_id"], "new attached context changed graph evidence or reused old review authority")
    pure(a, parent, rid, status=409, code="review_changed")
    f["parent"] = replacement
    for index, prefix in enumerate(PREFIXES):
        for decorated in (False, True):
            marker = f"S{index}PRIVATE"
            # Bidi controls split the prefix; short secrets rule out accidental
            # success merely because a rendered value was clipped.
            name = (prefix[0] + "\u202e" + prefix[1:] if decorated else prefix) + marker
            private_parent = project(a, f"p{index}{int(decorated)}", agent_name=name)
            value = pure(a, private_parent, rid, status=409, code="admission_inspection_unavailable")
            public(value, marker, name)
    validate(f, pure(a, replacement, rid))


@suite.case("same_request_explicit_admission_finalization_commit_then_read_only_refusal", "guided20 verification5")
def _():
    f = current(); a, b, rid = f["a"], f["b"], f["rid"]
    parent = f["parent"]; inspected = pure(a, parent, rid); validate(f, inspected)
    rec, _ = pending(a, rid)
    check(not rec.get("administrator_intent_id") or rec["administrator_intent_id"] == "-", "read created an administrator intent")
    b.start()
    view = link_view(b, rid)
    check(get(b, "/v2/networks") == [] and not view["commit_approved"], "inspection granted admission or requester commit")
    a.ok_incomplete("link", "admit", "--network", f["network"]["id"], "--owner-offer", view["owner_offer_id"],
        "--selection", view["selection_id"], "--person", f["person"], "--expect-host-key", view["host_public_key"],
        "--expect-device-key", view["device_public_key"], "--code-stdin", "--approve", input=f["reply"] + "\n", timeout=20)
    view = pull_until(b, rid, "administrator_offer_id", timeout=20)
    inspect(a, parent, rid, status=409, code="admission_inspection_unavailable")
    finalize(b, view, f["key"])
    view = pull_until(b, rid, "owner_finalization_id", timeout=20)
    check(view["state"] == "needs_commit" and not view["commit_approved"], "advanced finalization supplied requester commit")
    commit(b, view); wait_linked(b, a, rid, timeout=20)
    b.stop(); settled(a)
    pure(a, parent, rid, status=409, code="admission_inspection_unavailable")
    linked = link_view(a, rid)
    check(linked["state"] == "linked" and linked["request_id"] == inspected["request"]["request_id"] and
          linked["owner_offer_id"] == inspected["review"]["owner_offer_id"] and
          linked["selection_id"] == inspected["review"]["selection_id"], "advanced ceremony replaced inspected exact request prefix")
    public(get(a, "/v1/activity?limit=1000"), f["code"], f["reply"])


suite.finish()
