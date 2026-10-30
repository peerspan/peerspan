#!/usr/bin/env python3
"""Explicit incoming proof progress: guided contract section22.

Genuine automatic invitation return and remotely signed original/selection;
NEVER ordinary resume/admission preview/import on the administrator to fill its
prefix. Transparent byte relays forward real pinned host TLS and can disconnect
or stall it; they invent no identities, authority or protocol records. Schema-
only ABORT plus protected pre-retention barriers exercise atomicity/context/
cancellation/deadline. No production imports, private authority mutation,
endpoint injection, new helper, key replacement or fabricated signed packet.
The ordinary same-host remote path automatically selects its single offer;
owner-only/ambiguous carrier intervals, retained incoming renewal setup, corrupt crypto and narrow concurrent
root/proof races remain explicit source/fault limits without a bounded genuine
fixture. One explicit GET attempt's exact method/envelope implementation and
microscopic queued-before-commit interval remain source evidence; black-box
relays verify cached no-IO and bounded offline behavior. No native/model/
installed/physical acceptance is inferred. All old suites remain untouched,
including prior signing historical-purity intermittence evidence.
"""
import base64
import hashlib
import http.client
import json
import math
import re
import select as socket_select
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, commit,
                     create_network, finalize, link_view, parse_time,
                     pull_until, rfc3339, select, ssh_key, ssh_public_base64,
                     wait_for)

suite = Suite("incoming_progress", __doc__)
BASE = "/v1/onboarding/incoming-progress"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
TOP = {"version", "host_id", "context", "observed_at", "request", "next_action"}
LINK_KEYS = set("request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next".split())
main_fixture = {}

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()

def digest(domain, value):
    body = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return "review_" + hashlib.sha256(domain.encode() + b"\n" + body).hexdigest()

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
        check(not marker or marker not in text, f"inspection exposed private input/signing/provider material (rule {index})")

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

class Relay:
    """Transparent pinned TLS bytes; fault modes affect transport only."""
    def __init__(self, target):
        self.target = target; self.mode = "pass"; self.connections = 0; self.received = 0
        self.lock = threading.Lock(); self.stop = threading.Event(); self.sockets = set()
        outer = self
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with outer.lock:
                    outer.connections += 1; mode = outer.mode; outer.sockets.add(self.request)
                upstream = None
                try:
                    if mode == "drop":
                        return
                    if mode == "stall":
                        outer.stop.wait(5); return
                    upstream = socket.create_connection(outer.target, timeout=1)
                    with outer.lock:
                        outer.sockets.add(upstream)
                    while not outer.stop.is_set():
                        ready, _, _ = socket_select.select([self.request, upstream], [], [], .1)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            if source is self.request:
                                with outer.lock:
                                    outer.received += len(data)
                            (upstream if source is self.request else self.request).sendall(data)
                except OSError:
                    pass
                finally:
                    with outer.lock:
                        outer.sockets.discard(self.request)
                        if upstream:
                            outer.sockets.discard(upstream)
                    if upstream:
                        upstream.close()
        self.server = Server(("127.0.0.1", 0), Handler)
        while self.server.server_address[1] == target[1]:
            # The real host has reserved its port logically but has not yet
            # started; avoid a relay ever binding its own upstream address.
            self.server.server_close()
            self.server = Server(("127.0.0.1", 0), Handler)
        self.address = "127.0.0.1:" + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        import atexit
        atexit.register(self.close)

    def counts(self):
        with self.lock:
            return self.connections, self.received

    def close(self):
        if self.stop.is_set():
            return
        self.stop.set()
        with self.lock:
            sockets = list(self.sockets)
        for item in sockets:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=1)


def host(name, *, barrier=False):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    h.relay = Relay(("127.0.0.1", h.bootstrap_port))
    config = h.root / "transport.json"
    config.write_bytes(compact({"format": 1, "advertise_bootstrap": [h.relay.address], "advertise_quic": [h.peer_address],
                               "rendezvous": [], "relays": [], "publish_contacts": False})); config.chmod(0o600)
    h.extra_args = ["--transport-config", config]
    if barrier:
        h.barrier = h.root / "barriers"; h.barrier.mkdir(mode=0o700)
        h.extra_env = {"PEERSPAN_DEC_TEST_MODE": "1", "PEERSPAN_DEC_TEST_BARRIER_DIR": str(h.barrier)}
    return h.start()


def pair(name, *, barrier=False):
    a, b = host(name + "a", barrier=barrier), host(name + "b")
    net = create_network(a, 'Incoming "é東京" ' + name, "inviter")
    parent, remote_parent = project(a, name + "a"), project(b, name + "b")
    key = ssh_key(suite.work, name + "-original"); person = ssh_public_base64(key); member = 'Original "é東京" ' + name
    status, issued = a.api("POST", "/v2/networks/" + net["id"] + "/invitations", {
        "member": member, "expected_person_public_key": person, "expires_at": rfc3339(a.now() + timedelta(hours=1))})
    check(status == 201, "genuine automatic invitation fixture")
    status, request = b.api("POST", "/v2/link/requests", {"mode": "new", "network_id": net["id"], "person_public_key": person,
        "migration_proposal_id": "-", "contact_invitation": issued["invitation"], "helpers": []})
    check(status == 201, "genuine remote original request fixture")
    rid = request["request_id"]
    def returned():
        return next((v for v in get(a, "/v2/link/requests") if v["request_id"] == rid), None)
    incoming = wait_for(returned, timeout=15, interval=.1, message="automatic request return without administrator import/resume")
    check(incoming["role"] == "approver" and incoming["owner_offer_id"] == incoming["selection_id"] == "-", "automatic prefix fixture already advanced")
    return dict(a=a, b=b, parent=parent, remote_parent=remote_parent, key=key, person=person,
                member=member, network=net, rid=rid, code=issued["invitation"], reply=request["display_code"])


def sign_remote(f, *, scopes=7, short=False):
    b = f["b"]; request = link_view(b, f["rid"])
    args = ["link", "approve", "--network", f["network"]["id"], "--person-key", f["key"], "--scopes", str(scopes), "--approve", "--code-stdin"]
    if short:
        args += ["--not-after", rfc3339(parse_time(request["created_at"]) + timedelta(days=1))]
    b.ok_incomplete(*args, input=f["reply"] + "\n", timeout=20)
    remote = pull_until(b, f["rid"], "owner_offer_id", timeout=10)
    if remote["state"] == "needs_selection":
        select(b, remote)
    remote = pull_until(b, f["rid"], "selection_id", timeout=10)
    def published():
        rec, _ = pending(b, f["rid"])
        roles = {frame["role"] for frame in rec["outbound_frames"] if any(
            ack["address"] == f["a"].relay.address and ack["public_key"] == f["a"].public_key for ack in frame["acknowledged_by"])}
        if {"owner", "selection"} <= roles:
            return True
        # Only the REMOTE requester/owner drives its existing publication.
        b.cli("link", "resume", f["rid"], timeout=15)
        return None
    wait_for(published, timeout=15, interval=.1, message="genuine remote owner/selection published to retained inviter carrier")
    f["remote"] = remote
    b.stop(); settled(f["a"])
    before = link_view(f["a"], f["rid"])
    check(before["owner_offer_id"] == before["selection_id"] == "-", "administrator acquired proof before explicit progress action")


def payload(f, parent=None):
    return {"context": context(parent or f["parent"]), "request_id": f["rid"]}


def validate(f, value):
    a = f["a"]
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1,
          "exact incoming-progress wrapper/version")
    check(value["host_id"] == a.id and value["context"] == context(f["parent"]), "progress changed exact local host/context")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]) and
          abs((parse_time(value["observed_at"]) - a.now()).total_seconds()) < 5, "canonical guarded progress observation")
    view = value["request"]
    check(set(view) == LINK_KEYS and view == link_view(a, f["rid"]) and view["role"] == "approver" and
          view["request_id"] == f["rid"], "progress returned another/private/nonordinary request")
    check(not view["selection_approved"] and not view["commit_approved"], "receiving proofs fabricated local consent")
    expected = "wait_for_original_owner" if view["owner_offer_id"] == "-" else (
        "wait_for_requester_selection" if view["selection_id"] == "-" else "review_administrator_consent")
    check(value["next_action"] == expected, "progress claims ready authority or wrong waiting stage")
    for key in ("network_id", "context_id", "person_public_key", "host_public_key", "device_public_key", "request_packet_id", "created_at", "expires_at"):
        check(view[key] == f["initial"][key], "progress changed immutable incoming request: " + key)
    public(value, f["code"], f["reply"], str(f["key"]))


def progress(f, *, status=200, code=None, override=None):
    actual, value = f["a"].api("POST", BASE, payload(f) if override is None else override, timeout=8)
    check(actual == status, f"incoming progress on {f['a'].name} HTTP {actual}, want {status}")
    if code:
        check(isinstance(value, dict) and value.get("code") == code,
              f"incoming progress code {value.get('code') if isinstance(value, dict) else None}, want {code}")
    if actual == 200:
        validate(f, value)
    public(value, f["code"], f["reply"])
    return value


def prepared_pair(name, **kwargs):
    f = pair(name, **kwargs); f["initial"] = link_view(f["a"], f["rid"])
    return f


def current():
    if not main_fixture:
        main_fixture["initializing"] = True
        try:
            f = prepared_pair("main"); sign_remote(f)
        except Exception:
            main_fixture["failed"] = True; raise
        main_fixture.clear(); main_fixture.update(f)
    check(not main_fixture.get("failed"), "earlier genuine main prefix setup failed")
    return main_fixture


def modes(f, mode):
    f["a"].relay.mode = f["b"].relay.mode = mode


def counts(f):
    return f["a"].relay.counts(), f["b"].relay.counts()


def pure(f, *, status=200, code=None, override=None):
    settled(f["a"]); quiet_counts(f); before = snapshot(f["a"]); network = counts(f)
    value = progress(f, status=status, code=code, override=override)
    check(snapshot(f["a"]) == before, "cached/refused progress changed logical tables/schema/private files")
    check(counts(f) == network, "cached/refused progress attempted carrier IO")
    return value


def unchanged_authority(f, before, old_pending, old_secret):
    after = records(f["a"]); rec, secret = pending(f["a"], f["rid"])
    check(without(after, "dec_pending", "dec_frames") == without(before, "dec_pending", "dec_frames"),
          "proof progress changed intents/clock/authority/contacts/events/registry/schema")
    protected = ("format", "roles", "mode", "migration_proposal_id", "expected_network_id", "expected_context_id", "expected_person_public_key",
                 "contact_invitation_base64", "descriptor_base64", "host_public_key", "device_public_key", "request_nonce", "request_packet_base64",
                 "administrator_packet_base64", "owner_finalization_packet_base64", "commit_packet_base64", "outcome_packet_base64",
                 "selection_approved", "commit_approved", "owner_intent_id", "administrator_intent_id", "selection_intent_id", "commit_intent_id",
                 "terminal", "carrier_endpoints", "outbound_frames")
    check(all(rec[k] == old_pending[k] for k in protected) and secret == old_secret, "progress changed consent/authority/endpoints/private operation pins")
    check(rec["administrator_intent_id"] == rec["owner_intent_id"] == rec["selection_intent_id"] == rec["commit_intent_id"] == "-",
          "progress created an ordinary intent")
    check([r for r in after["dec_pending"] if r[0] != f["rid"]] == [r for r in before["dec_pending"] if r[0] != f["rid"]],
          "progress changed another pending request")
    check(set(before["dec_frames"]) <= set(after["dec_frames"]), "progress removed or rewrote retained frames")
    for row in set(after["dec_frames"]) - set(before["dec_frames"]):
        check(row[0] == f["rid"] and row[1] not in ("administrator", "owner_finalization", "commit", "outcome"),
              "progress retained cross-request or later-stage frames")


def raw_post(a, raw):
    conn = UnixHTTPConnection(str(a.state / "admin.sock"), timeout=8)
    try:
        try:
            conn.request("POST", BASE, body=raw, headers={"Content-Type": "application/json"})
        except BrokenPipeError:
            pass
        response = conn.getresponse(); data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        conn.close()

def quiet_counts(f):
    previous = counts(f)
    def quiet():
        nonlocal previous
        now = counts(f); same = now == previous; previous = now
        return now if same else None
    time.sleep(.15)
    return wait_for(quiet, timeout=2, interval=.15, message="transparent carrier relay quiescence")


@suite.case("action_alone_fetches_exact_original_selection_then_cached_no_io", "guided22 verification1")
def _():
    f = current(); a = f["a"]
    before = records(a); old, secret = pending(a, f["rid"]); files, home = private_files(a.state), private_files(a.home)
    network = quiet_counts(f)
    result = progress(f)
    check(result["next_action"] == "review_administrator_consent" and result["request"]["owner_offer_id"] == f["remote"]["owner_offer_id"] and
          result["request"]["selection_id"] == f["remote"]["selection_id"], "action failed to fetch exact remotely selected original prefix")
    for old_count, new_count in zip(network, quiet_counts(f)):
        check(0 <= new_count[0] - old_count[0] <= 1, "one progress call automatically retried a pinned carrier connection")
    unchanged_authority(f, before, old, secret); verify_original(f)
    check(private_files(a.state) == files and private_files(a.home) == home, "progress created private/key files or a secret journal")
    actual, inspection = a.api("POST", "/v1/onboarding/admission-inspection", payload(f))
    check(actual == 200 and inspection["review"]["owner_offer_id"] == f["remote"]["owner_offer_id"] and
          inspection["review"]["selection_id"] == f["remote"]["selection_id"] and
          inspection["review_id"] == digest("peerspan-admission-inspection-v1", inspection["review"]),
          "fetched prefix is not independently usable by exact read-only inspection")
    actual, lookup = a.api("POST", "/v1/onboarding/admission-consent/lookup", payload(f))
    check(actual == 200 and lookup["admission"] is None, "progress prepared/approved administrator consent")
    public(inspection, f["code"], f["reply"]); public(lookup)
    modes(f, "drop"); quiet_counts(f)
    cached = pure(f)
    check(cached["request"] == result["request"] and cached["next_action"] == result["next_action"], "cached proof retry changed exact stage")


@suite.case("request_only_waiting_repeat_preserves_stage_and_bounded_valid_endpoint", "guided22 verification2")
def _():
    f = prepared_pair("wait"); a = f["a"]; f["b"].stop()
    # The inviter's real mailbox is valid; the other retained endpoint stalls.
    # Concurrent bounded fetch must still accept the valid completed response.
    f["b"].relay.mode = "stall"
    began = time.monotonic(); first = progress(f)
    check(time.monotonic() - began < 5 and first["next_action"] == "wait_for_original_owner", "request-only valid carrier did not yield bounded honest waiting")
    rec, _ = pending(a, f["rid"]); check(rec["owner_packet_base64"] == rec["selection_packet_base64"] == "-", "waiting fabricated an owner/selection")
    a.clock.set(-120)
    pure(f, status=409, code="incoming_progress_unavailable")
    a.clock.set(60)
    settled(a); before = snapshot(a)
    second = progress(f)
    check(second["next_action"] == first["next_action"] and second["request"] == first["request"] and snapshot(a) == before,
          "identical partial evidence renewed stage life, poll cache, consent or authority")
    advance_to(a, parse_time(first["request"]["created_at"]) + timedelta(minutes=11))
    quiet_counts(f)
    pure(f, status=409, code="incoming_progress_unavailable")
    advance_to(a, parse_time(first["request"]["expires_at"]) + timedelta(seconds=1))
    pure(f, status=409, code="incoming_progress_unavailable")
    a.stop()


@suite.case("strict_cli_api_bounds_context_methods_and_private_router_isolation", "guided22 verification3")
def _():
    f = current(); a = f["a"]
    if link_view(a, f["rid"])["selection_id"] == "-":
        progress(f)
    modes(f, "drop"); quiet_counts(f)
    data = payload(f); raw = compact(data); maximum = raw + b" " * (65536 - len(raw))
    before = snapshot(a); network = counts(f)
    actual, value = raw_post(a, maximum)
    check(actual == 200, f"exact64KiB API HTTP {actual}"); validate(f, value)
    result = a.cli("onboarding", "admission", "progress", "--stdin", input=maximum.decode(), timeout=8)
    check(result.ok, "exact64KiB private progress CLI failed"); validate(f, result.json)
    ctx = compact(data["context"])
    malformed = [b"null", b"[]", b"{", raw + b"{}", maximum + b" ",
        b'{"context":' + ctx + b',"context":' + ctx + b',"request_id":' + compact(f["rid"]) + b'}',
        raw.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
        compact({**data, "context": None}), compact({**data, "request_id": None}), compact({**data, "request_id": "link_bad"}),
        compact({**data, "context": {**data["context"], "extra": "PRIVATE_INPUT"}})]
    for key in ("code", "invitation", "file", "key", "endpoints", "helpers", "provider", "deadline", "approve", "packet"):
        malformed.append(compact({**data, key: "PRIVATE_INPUT"}))
    for index, invalid in enumerate(malformed):
        actual, denied = raw_post(a, invalid)
        check(actual == 400 and denied.get("code") == "invalid", f"malformed API variant{index}: HTTP {actual}"); public(denied, "PRIVATE_INPUT")
        result = a.cli("onboarding", "admission", "progress", "--stdin", input=invalid.decode(), timeout=8)
        check(not result.ok, f"CLI accepted malformed/duplicate/trailing/oversized input variant{index}")
        public(result.stdout + result.stderr, "PRIVATE_INPUT", str(a.state))
    check(snapshot(a) == before and counts(f) == network, "cached/invalid private CLI/API initialized state, performed IO or wrote records")
    for method in ("GET", "PUT", "DELETE"):
        actual, denied = a.api(method, BASE)
        check(actual == 405, f"alternate method {method}: HTTP {actual}"); public(denied)
    for patch in ({"request_id": "link_" + "0" * 64},
                  {"context": {**data["context"], "project_flow_id": "flow_" + "0" * 32}}):
        pure(f, status=404, code="not_found", override={**data, **patch})
    for patch in ({"native_session_id": "different-conversation"}, {"project_root": str(suite.work / "different root")},
                  {"project_review_id": "review_" + "0" * 64}):
        pure(f, status=409, code="review_changed", override={**data, "context": {**data["context"], **patch}})
    private_parent = project(a, "private-agent", agent_name="token_PRIVATE_SHORT")
    pure(f, status=409, code="incoming_progress_unavailable", override=payload(f, private_parent))
    for args in (("onboarding", "admission", "progress"), ("onboarding", "admission", "progress", f["rid"], "--stdin")):
        result = a.cli(*args, input=raw.decode(), timeout=8)
        check(not result.ok, "progress consumed implicit stdin/positional request"); public(result.stdout + result.stderr, f["rid"])
    missing = suite.host("nd", start=False); empty = private_files(missing.root)
    result = missing.cli("onboarding", "admission", "progress", "--stdin", input=raw.decode(), timeout=8)
    check(not result.ok and private_files(missing.root) == empty, "progress started daemon or initialized missing state")
    public(result.stdout + result.stderr, str(missing.root))
    credential = a.ok("adapter", "create", "--session", f["parent"]["review"]["session_id"], "--expires-at", rfc3339(a.now() + timedelta(hours=1)))
    adapter = Adapter(a, f["parent"]["review"]["agent"], f["parent"]["review"]["session_id"], credential)
    check(adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id, "session_id": adapter.session_id,
          "instance_id": adapter.instance})[0] == 200, "real scoped credential fixture")
    actual, denied = adapter.call("POST", BASE, data)
    check(actual == 404, f"scoped adapter exposed progress: HTTP {actual}"); public(denied, adapter.token)
    peer, bootstrap = host("peer"), host("boot")
    for local, remote in ((a, peer), (peer, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    result = subprocess.run([str(suite.probe_bin), "--state", str(peer.state), "--address", a.peer_address, "--alpn", "peerspan-peer/1",
        "--method", "POST", "--path", BASE, "--body-stdin"], input=raw, capture_output=True, timeout=8)
    check(result.returncode == 0 and json.loads(result.stdout)["status"] == 404, "authenticated peer exposed progress")
    cert, key = suite.work / "cert.pem", suite.work / "tls-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=boundary", "-days", "1",
        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as connection:
        with tls.wrap_socket(connection, server_hostname="peerspan") as stream:
            stream.sendall((f"POST {BASE} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n").encode() + raw)
            response = http.client.HTTPResponse(stream); response.begin(); response.read()
            check(response.status == 404, f"bootstrap exposed progress: HTTP {response.status}")
    peer.stop(); bootstrap.stop()
    req = prepared_pair("req"); req["a"].stop(); req["a"].relay.mode = "drop"
    settled(req["b"]); rec_before = snapshot(req["b"])
    actual, denied = req["b"].api("POST", BASE, {"context": context(req["remote_parent"]), "request_id": req["rid"]})
    check(actual == 409 and denied.get("code") == "incoming_progress_unavailable", "requester role entered incoming proof action")
    check(snapshot(req["b"]) == rec_before, "requester refusal changed protocol/authority state"); public(denied)
    req["b"].stop()


@suite.case("unsupported_signed_terms_rollback_and_offline_budget_no_false_progress", "guided22 verification4")
def _():
    for name, options in (("profile", {"scopes": 1}), ("short", {"short": True})):
        f = prepared_pair(name); sign_remote(f, **options)
        before = snapshot(f["a"])
        progress(f, status=409, code="incoming_progress_unavailable")
        check(snapshot(f["a"]) == before, "failed signed-term verification partially retained frames, proofs or stage")
        rec, _ = pending(f["a"], f["rid"])
        check(rec["owner_packet_base64"] == rec["selection_packet_base64"] == "-", "unsupported owner/selection became cached authority")
        f["a"].stop()
    f = prepared_pair("offline"); f["b"].stop(); modes(f, "stall")
    settled(f["a"]); before = snapshot(f["a"]); began = time.monotonic()
    progress(f, status=409, code="incoming_progress_unavailable")
    check(time.monotonic() - began < 5, "offline concurrent transport pass exceeded its bounded owner-local request")
    check(snapshot(f["a"]) == before, "offline attempt retained partial work or created authority")
    f["a"].stop()


def arm(f):
    directory = f["a"].barrier; name = "dec.incoming_progress.before_retain"
    for suffix in ("arm", "entered", "continue"):
        (directory / (name + "." + suffix)).unlink(missing_ok=True)
    target = directory / (name + ".arm"); target.write_text(f["rid"] + "\n"); target.chmod(0o600)
    return directory / (name + ".entered"), directory / (name + ".continue"), target


def barrier_attempt(f, mode):
    entered, release, armed = arm(f); a = f["a"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(a.api, "POST", BASE, payload(f), timeout=10)
        try:
            wait_for(lambda: entered.exists(), timeout=4, interval=.02, message="actual fetched-proof pre-retention barrier")
            check(entered.read_text().strip() == f["rid"], "barrier captured another operation")
            if mode == "context":
                change = pool.submit(project, a, "replaced", replace=f["parent"]["flow_id"], old=f["parent"])
                change.result(timeout=1)  # A writer must finish while progress remains paused.
                expected = "review_changed"
            elif mode == "cancel":
                change = pool.submit(a.api, "POST", "/v2/link/requests/" + f["rid"] + "/cancel", {})
                check(change.result(timeout=1)[0] == 200, "concurrent cancellation blocked or failed while progress held no DB lock")
                expected = "review_changed"
            else:
                # Registered barrier is reached before this elapsed-time stimulus.
                # Four seconds beyond entry must exceed the whole action's4s
                # monotonic retention deadline without relying on fake UTC.
                time.sleep(4.15)
                expected = "incoming_progress_unavailable"
            before = snapshot(a)
            release.write_text("continue\n"); release.chmod(0o600)
            actual, denied = future.result(timeout=5)
            check(actual == 409 and denied.get("code") == expected, f"{mode} in-flight guard HTTP {actual}, code {denied.get('code') if isinstance(denied, dict) else None}")
            public(denied, f["code"], f["reply"])
            check(snapshot(a) == before, f"{mode} guard retained fetched frames/proofs or wrote after its last check")
            rec, _ = pending(a, f["rid"])
            check(rec["owner_packet_base64"] == rec["selection_packet_base64"] == "-", f"{mode} guard left partial owner/selection")
        finally:
            if not release.exists():
                release.write_text("continue\n"); release.chmod(0o600)
            armed.unlink(missing_ok=True)
            # Context-managed executor drains both actual HTTP/mutation calls.
            # No old future or fault stays detached after this case.


@suite.case("pre_retention_context_cancel_deadline_and_schema_abort_are_atomic", "guided22 verification5")
def _():
    deadline = None
    for mode in ("context", "cancel", "deadline"):
        f = prepared_pair("race" + mode, barrier=True); sign_remote(f)
        barrier_attempt(f, mode)
        if mode == "deadline":
            deadline = f
        else:
            pure(f, status=409, code="review_changed" if mode == "context" else "incoming_progress_unavailable")
            f["a"].stop()
    f = deadline; a = f["a"]; rid = f["rid"]
    with closing(sqlite3.connect(db_path(a))) as db, db:
        db.execute(f"CREATE TRIGGER progress_abort BEFORE UPDATE OF record ON dec_pending WHEN OLD.request_id='{rid}' "
                   "BEGIN SELECT RAISE(ABORT, 'PRIVATE_PROGRESS_ABORT'); END")
    try:
        before = snapshot(a)
        actual, denied = a.api("POST", BASE, payload(f), timeout=8)
        check(not 200 <= actual < 300, "schema-only fault did not abort pending retention")
        public(denied, "PRIVATE_PROGRESS_ABORT", f["code"], f["reply"])
        check(snapshot(a) == before, "aborted pending update left earlier fetched-frame inserts or other partial state")
    finally:
        with closing(sqlite3.connect(db_path(a))) as db, db:
            db.execute("DROP TRIGGER progress_abort")
    check(progress(f)["next_action"] == "review_administrator_consent", "exact post-ABORT retry did not recover genuine fetched prefix")
    verify_original(f); a.stop()


@suite.case("fetched_prefix_exact_consent_root_offer_F_commit_then_no_progress_resurrection", "guided22 verification6")
def _():
    f = current(); a, b, rid = f["a"], f["b"], f["rid"]
    if link_view(a, rid)["selection_id"] == "-":
        modes(f, "pass"); progress(f)
    actual, prepared = a.api("POST", "/v1/onboarding/admission-consent/prepare", payload(f))
    check(actual == 200 and prepared["admission"]["state"] == "review", "explicit exact root consent preparation failed")
    modes(f, "drop"); quiet_counts(f)
    pure(f, status=409, code="incoming_progress_unavailable")
    modes(f, "pass")
    actual, approved = a.api("POST", "/v1/onboarding/admission-consent/approve", {
        **payload(f), "admission_review_id": prepared["admission"]["review_id"]})
    check(actual == 200 and approved["admission"]["state"] == "approved", "explicit root approval failed")
    # Only observe the administrator's allowed ordinary background publication;
    # never call broad ordinary resume/preview/import from this suite on it.
    wait_for(lambda: link_view(a, rid)["administrator_offer_id"] != "-", timeout=15, interval=.1, message="approved root/host offer publication")
    b.start()
    view = pull_until(b, rid, "administrator_offer_id", timeout=20)
    finalize(b, view, f["key"])
    view = pull_until(b, rid, "owner_finalization_id", timeout=20)
    check(view["state"] == "needs_commit" and not view["commit_approved"] and get(b, "/v2/networks") == [],
          "proof progress or root consent supplied original F/requester commit/adoption")
    commit(b, view)
    # Existing helper drives BOTH peers with resume. Keep the administrator
    # observer explicit instead: only requester resume is a permitted driver.
    def linked():
        remote, local = link_view(b, rid), link_view(a, rid)
        if remote["state"] == local["state"] == "linked":
            return True
        b.cli("link", "resume", rid, timeout=15)
        return None
    wait_for(linked, timeout=25, interval=.2, message="same fetched request applied on requester and administrator")
    b.stop(); modes(f, "drop"); quiet_counts(f); settled(a)
    pure(f, status=409, code="incoming_progress_unavailable")
    before = snapshot(a)
    actual, historical = a.api("POST", "/v1/onboarding/admission-consent/lookup", payload(f))
    check(actual == 200 and historical["admission"] == approved["admission"] and historical["request"]["state"] == "linked" and
          snapshot(a) == before, "incoming progress recreated work or changed ordinary administrator history")
    public(historical, f["code"], f["reply"])


suite.finish()
