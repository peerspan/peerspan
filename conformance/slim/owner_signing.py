#!/usr/bin/env python3
"""Bounded local original owner-offer signing, guided contract section18.

Independent real hosts, public commands/APIs and genuine SSH agents. A private
owner-socket proxy forwards authentic operations and mutates captured responses
only; an agent proxy forwards genuine protocol messages and counts key use.
No protocol/authority DB fabrication, production imports or new API. Database
reads verify retained proof and pure history. Observable signature/submission
counts do not claim to count internal generated-key signing calls. Missing/
pruned/corrupt evidence and the narrow final-read/POST interval remain source/
fault limits. Fresh signing past the15min approved-review window is not forced:
an unoffered stage already expires after10min, and resume cannot extend it.
The client-window distinction remains source coverage; real expired historical
replay is checked. A lost response can mean committed signature; no automatic retry
or cancellation of dispatched key use is claimed. No native/model/installed
or two-physical-machine acceptance is inferred. Existing suites stay unchanged.
"""
import base64
import copy
import hashlib
import http.server
import json
import math
import os
import re
import shutil
import socket
import socketserver
import sqlite3
import stat
import subprocess
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Clock, Result, Suite, UnixHTTPConnection, check, commit,
                     create_network, finalize, link_view, parse_time, pull_until,
                     rfc3339, select, ssh_key, ssh_public_base64, wait_for, wait_linked)

suite = Suite("owner_signing", __doc__)
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
    transport.chmod(0o600); h.extra_args = ["--transport-config", transport, "--person-key-file", h.root / "absent-daemon-person-key"]
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


def progress_transport_host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    config = h.root / "transport.json"
    config.write_bytes(compact({"format": 1, "advertise_bootstrap": [f"127.0.0.1:{h.bootstrap_port}"], "advertise_quic": [h.peer_address],
                               "rendezvous": [], "relays": [], "publish_contacts": False})); config.chmod(0o600)
    h.extra_args = ["--transport-config", config, "--person-key-file", h.root / "absent-daemon-person-key"]
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


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class HostProxy:
    """HTTP boundary faults on authentic responses, never protocol-row edits."""
    def __init__(self, h, name):
        self.host = h; self.state = suite.work / name
        self.state.mkdir(mode=0o700)
        self.calls = []; self.mutate = lambda method, endpoint, body, status, value: (status, value)
        self.drop_signed = False
        outer = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def handle_request(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                body = json.loads(raw) if raw else None
                outer.calls.append((self.command, self.path, copy.deepcopy(body)))
                conn = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=10)
                try:
                    conn.request(self.command, self.path, body=raw if raw else None,
                                 headers={"Content-Type": "application/json"} if raw else {})
                    response = conn.getresponse(); data = response.read(); status = response.status
                finally:
                    conn.close()
                value = json.loads(data) if data else None
                status, value = outer.mutate(self.command, self.path, body, status, copy.deepcopy(value))
                if self.path.endswith("/signed") and outer.drop_signed:
                    outer.drop_signed = False
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                data = compact(value) if value is not None else b""
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.send_header("Connection", "close")
                self.end_headers(); self.wfile.write(data)
            do_GET = handle_request
            do_POST = handle_request
        self.server = UnixServer(str(self.state / "admin.sock"), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self):
        self.thread.start(); return self

    def __exit__(self, *_args):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    @property
    def submissions(self):
        return [body for method, endpoint, body in self.calls if method == "POST" and endpoint.endswith("/signed")]


def read_exact(stream, size):
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise EOFError("closed agent frame")
        value.extend(chunk)
    return bytes(value)


def ssh_string(value, offset=0):
    size = int.from_bytes(value[offset:offset + 4], "big")
    return value[offset + 4:offset + 4 + size], offset + 4 + size


class AgentProxy:
    """Counts messages while forwarding to a real ssh-agent with genuine keys."""
    def __init__(self, name, keys):
        self.actual = suite.work / (name + "a.sock"); self.path = suite.work / (name + "p.sock")
        log = (suite.work / (name + "-agent.log")).open("ab")
        self.process = suite.spawn(["ssh-agent", "-D", "-a", str(self.actual)], stdout=log, stderr=log)
        log.close(); wait_for(lambda: self.actual.exists(), timeout=5, message="real SSH agent socket")
        for key in keys:
            result = subprocess.run(["ssh-add", str(key)], env={**os.environ, "SSH_AUTH_SOCK": str(self.actual)}, capture_output=True, timeout=5)
            check(result.returncode == 0, "real ssh-add fixture failed")
        self.messages = []; self.errors = []; self.before = lambda _kind: None
        outer = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as remote:
                        remote.settimeout(15); remote.connect(str(outer.actual))
                        while True:
                            prefix = read_exact(self.request, 4); size = int.from_bytes(prefix, "big")
                            check(0 < size <= 1_048_576, "bounded real agent request")
                            message = read_exact(self.request, size)
                            outer.messages.append(message); outer.before(message[0])
                            remote.sendall(prefix + message)
                            prefix = read_exact(remote, 4); answer = read_exact(remote, int.from_bytes(prefix, "big"))
                            self.request.sendall(prefix + answer)
                except (EOFError, ConnectionError, OSError):
                    return
                except Exception as error:
                    outer.errors.append(type(error).__name__)
        self.server = UnixServer(str(self.path), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self):
        self.thread.start(); return self

    def __exit__(self, *_args):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        check(not self.errors, f"real agent boundary fixture failed: {self.errors}")

    @property
    def signatures(self):
        return [message for message in self.messages if message[0] == 13]


def generated_path(h):
    return h.home / ".config" / "peerspan" / "person_ed25519"


def install_key(h, key=None):
    target = generated_path(h)
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True); target.parent.chmod(0o700)
    target.write_bytes((key or source()["key"]).read_bytes()); target.chmod(0o600)
    return target


def signed_body(flow, approved):
    return {"flow_id": flow["flow_id"], **payload(flow, approved), "decision": "sign_original_owner_offer"}


def command(h, flow, approved, *, proxy=None, agent=None, data=None, env=None, stdin=True):
    body = compact(signed_body(flow, approved)) if data is None else data
    environment = {**h.env, "SSH_AUTH_SOCK": str(agent.path if agent else h.root / "absent-agent.sock"), **(env or {})}
    argv = [str(suite.host_bin), "--state", str(proxy.state if proxy else h.state), "onboarding", "join", "owner", "sign"]
    if stdin:
        argv.append("--stdin")
    result = subprocess.run(argv, input=body, env=environment, cwd=h.root, capture_output=True, timeout=20)
    # Never dump raw stdout/stderr, templates, signatures, key/agent diagnostics.
    for marker in (b"BEGIN OPENSSH PRIVATE KEY", b"PRIVATE_SIGNING_MARKER", b"PRIVATE_AGENT_COMMENT", b"token_", b"psi2-", b"psl2-",
                   str(generated_path(h)).encode(), str(environment["SSH_AUTH_SOCK"]).encode(),
                   str((proxy.state if proxy else h.state) / "admin.sock").encode(),
                   str(environment.get("XDG_CONFIG_HOME", h.home / ".config")).encode()):
        check(marker not in result.stdout + result.stderr, "bounded signing output leaked private key/code/path/provider material")
    answer = Result(argv, result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
    if answer.ok:
        check(isinstance(answer.json, dict) and set(answer.json) == TOP | {"original_signature"} and
              answer.json["original_signature"] == {"state": "recorded"}, "exact sanitized original-signature result")
        validate(h, flow, without(answer.json, "original_signature"))
        check(answer.json["owner"]["review"] == approved["owner"]["review"] and answer.json["owner"]["review_id"] == approved["owner"]["review_id"],
              "signing result changed fixed original review/digest")
    public(answer.stdout, source()["code"])
    return answer


def approved_fixture(name):
    h, parent, flow = fixture(name); prepared = owner(h, flow, "prepare")
    approved = owner(h, flow, "approve", prepared)
    return h, parent, flow, approved


def verify_offer(h, flow, approved):
    rid = flow["outcome"]["request_id"]
    # Explicit advanced test driver, separate from the command under test.
    view = pull_until(h, rid, "owner_offer_id", timeout=15)
    record, _ = pending(h, rid)
    packet = json.loads(base64.b64decode(record["owner_packet_base64"], validate=True))
    check(packet_id(packet) == approved["owner"]["review"]["proposed_owner_offer_id"] == view["owner_offer_id"] and
          packet["signer_public_key"] == source()["person"] and packet["authority_signature_format"] == "sshsig" and
          packet["authority_signature"] != "-", "real ordinary offer lacks exact original possession proof")
    signatures = intent(h, approved["owner"]["review"]["intent_id"])["record"]["signatures"]
    authority = [s for s in signatures if s["role"] == "authority"]
    check(len(authority) == 1 and authority[0]["slot_id"] == 1 and authority[0]["signature"] == packet["authority_signature"], "not exactly one retained slot1 original authority signature")
    allowed = suite.work / "allowed-signers"
    public_key = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(source()["key"])], capture_output=True, check=True, timeout=5).stdout
    allowed.write_bytes(b"fixture " + public_key); allowed.chmod(0o600)
    sig = suite.work / "authority.sshsig"
    text = packet["authority_signature"]
    sig.write_text("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(text[i:i + 70] for i in range(0, len(text), 70)) + "\n-----END SSH SIGNATURE-----\n"); sig.chmod(0o600)
    verified = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "fixture", "-n", "peerspan-person-v1", "-s", str(sig)],
                              input=packet_message(packet), capture_output=True, timeout=5)
    check(verified.returncode == 0, "independent SSHSIG verification of real owner packet failed")
    return view


def check_submission(proxy, approved):
    check(len(proxy.submissions) == 1, f"signing submitted {len(proxy.submissions)} batches, want one")
    batch = proxy.submissions[0]
    check(set(batch) == {"intent_id", "signatures"} and batch["intent_id"] == approved["owner"]["review"]["intent_id"] and len(batch["signatures"]) == 1,
          "signature submission widened the original batch/intention")
    entry = batch["signatures"][0]
    check(set(entry) == {"slot_id", "role", "signature"} and entry["slot_id"] == 1 and entry["role"] == "authority", "CLI signed a host/later/unrelated role")


def pure_retry(h, flow, approved, proxy, agent=None, *, logical=True):
    before = settled(h) if logical else None
    files, home = private_files(h.state), private_files(h.home)
    at = len(proxy.calls); submitted = len(proxy.submissions); signatures = len(agent.signatures) if agent else 0
    result = command(h, flow, approved, proxy=proxy, agent=agent)
    check(result.ok, "exact completed-offer retry failed historical retrieval")
    calls = proxy.calls[at:]
    check(not any(endpoint.endswith(("/approval", "/signed", "/resume")) for _, endpoint, _ in calls) and len(proxy.submissions) == submitted,
          "complete-offer retry performed ordinary signing lookup/submission/polling")
    check(agent is None or len(agent.signatures) == signatures, "completed-offer retry signed again")
    check((not logical or records(h) == before) and private_files(h.state) == files and private_files(h.home) == home,
          "complete-offer retry changed logical records/private files")
    return result


@suite.case("generated_original_one_typed_signature_real_proof_and_pure_replay", "guided onboarding18 verification1")
def _():
    h, _, flow, approved = approved_fixture("generated"); key = install_key(h)
    files, home = private_files(h.state), private_files(h.home)
    with AgentProxy("g", [source()["key"]]) as agent, HostProxy(h, "gp") as proxy:
        first = command(h, flow, approved, proxy=proxy, agent=agent)
        check_submission(proxy, approved)
        check(agent.messages == [], "matching generated key contacted SSH agent")
        view = verify_offer(h, flow, approved)
        check(view["administrator_offer_id"] == "-" and view["owner_finalization_id"] == "-" and not view["commit_approved"] and
              get(h, "/v2/networks") == [], "original possession became administrator/final-commit/admission consent")
        check(private_files(h.state) == files and private_files(h.home) == home and key.is_file(), "signing changed/created original or private files")
        # A single post-submission lookup may report outcome unknown; no polling
        # is allowed inside this command. The external driver observed proof.
        check(sum(endpoint.endswith("/approval") for _, endpoint, _ in proxy.calls) == 1, "fresh command polled ordinary signing views")
        if not first.ok:
            check(not first.json or first.json.get("original_signature") is None, "uncertain result claimed signature success")
        key.unlink()
        pure_retry(h, flow, approved, proxy, agent)
        check(agent.messages == [], "completed offer replay listed or used an agent key")
        public(get(h, "/v1/activity?limit=1000"), source()["code"])


@suite.case("exact_real_agent_selection_and_unsafe_generated_source_refusal_without_fallback", "guided onboarding18 verification2")
def _():
    wrong = ssh_key(suite.work, "PRIVATE_AGENT_COMMENT-wrong")
    h, _, flow, approved = approved_fixture("agent"); install_key(h, wrong)
    with AgentProxy("a", [wrong, source()["key"]]) as agent, HostProxy(h, "ap") as proxy:
        home = private_files(h.home); command(h, flow, approved, proxy=proxy, agent=agent)
        check(len(agent.signatures) == 1, "exact original agent path did not sign once")
        check(all(message[0] in (11, 13) for message in agent.messages), "signing mutated SSH-agent identities")
        blob, _ = ssh_string(agent.signatures[0], 1)
        algorithm, at = ssh_string(blob); raw_key, _ = ssh_string(blob, at)
        check(algorithm == b"ssh-ed25519" and base64.b64encode(raw_key).decode() == source()["person"], "agent signed with another listed identity")
        check_submission(proxy, approved); verify_offer(h, flow, approved)
        check(private_files(h.home) == home, "agent fallback replaced a valid different generated key")
    refused, _, f2, a2 = approved_fixture("unsafe")
    target = install_key(refused); original = target.read_bytes()
    with AgentProxy("u", [source()["key"]]) as agent, HostProxy(refused, "up") as proxy:
        for fault in ("insecure", "malformed", "oversized", "symlink", "directory", "fifo", "private-directory", "ancestor-writable",
                      "parent-symlink", "relative", "traversal", "redundant-slash", "dot-component"):
            target.unlink(); environment = {}
            if fault == "symlink":
                target.symlink_to(source()["key"])
            elif fault == "directory":
                target.mkdir(mode=0o700)
            elif fault == "fifo":
                os.mkfifo(target, 0o600)
            else:
                target.write_bytes(b"PRIVATE_SIGNING_MARKER invalid" if fault == "malformed" else b"x" * 65537 if fault == "oversized" else original)
                target.chmod(0o644 if fault == "insecure" else 0o600)
            if fault == "private-directory":
                target.parent.chmod(0o755)
            if fault == "ancestor-writable":
                target.parent.parent.chmod(0o777)
            if fault == "parent-symlink":
                target.parent.rename(target.parent.with_name("held-private"))
                target.parent.symlink_to(target.parent.with_name("held-private"), target_is_directory=True)
            if fault == "relative":
                environment["XDG_CONFIG_HOME"] = ".config"
            if fault == "traversal":
                environment["XDG_CONFIG_HOME"] = str(refused.home / "child" / ".." / ".config")
            if fault == "redundant-slash":
                environment["XDG_CONFIG_HOME"] = str(refused.home) + "/.config//"
            if fault == "dot-component":
                environment["XDG_CONFIG_HOME"] = str(refused.home) + "/./.config"
            before, home = settled(refused), private_files(refused.home)
            count = len(agent.messages); submitted = len(proxy.submissions)
            result = command(refused, f2, a2, proxy=proxy, agent=agent, env=environment)
            check(not result.ok, f"unsafe generated source {fault} was silently bypassed")
            check(len(agent.messages) == count and len(proxy.submissions) == submitted, f"source refusal {fault} fell back to agent/submission")
            check(records(refused) == before and private_files(refused.home) == home, f"source refusal {fault} repaired/mutated keys or daemon")
            if fault == "parent-symlink":
                target.parent.unlink(); target.parent.with_name("held-private").rename(target.parent)
            target.parent.chmod(0o700)
            target.parent.parent.chmod(0o700)
            if target.is_dir() and not target.is_symlink():
                target.rmdir()
            else:
                target.unlink()
            target.write_bytes(original); target.chmod(0o600)
        target.unlink()
        with AgentProxy("w", [wrong]) as wrong_agent:
            before, home = settled(refused), private_files(refused.home)
            check(not command(refused, f2, a2, proxy=proxy, agent=wrong_agent).ok and not wrong_agent.signatures, "missing exact agent key chose another original")
            check(records(refused) == before and private_files(refused.home) == home and not proxy.submissions, "missing key created/submitted state")


@suite.case("strict_private_cli_decision_bounds_binding_and_pre_key_eligibility", "guided onboarding18 verification3")
def _():
    h, parent, flow = fixture("strict"); prepared = owner(h, flow, "prepare")
    with AgentProxy("s", [source()["key"]]) as agent, HostProxy(h, "sp") as proxy:
        check(not command(h, flow, prepared, proxy=proxy, agent=agent).ok and not agent.messages and not proxy.submissions,
              "unapproved consent reached key/agent/signature IO")
        approved = owner(h, flow, "approve", prepared)
        body = signed_body(flow, approved); raw = compact(body); maximum = raw + b" " * (65536 - len(raw))
        invalid = [b"null", b"[]", b"{}", raw + b"{}", maximum + b" ", compact({**body, "decision": None}),
                   compact({**body, "decision": "approve"}), compact({**body, "flow_id": "flow_bad"}), compact({**body, "context": None}),
                   raw.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
                   b'{"flow_id":' + compact(flow["flow_id"]) + b',' + raw[1:]]
        for field in ("code", "path", "key", "provider_id", "scopes", "not_after", "template_base64", "message_base64", "signatures"):
            invalid.append(compact({**body, field: "PRIVATE_SIGNING_MARKER"}))
        before, home = settled(h), private_files(h.home)
        for index, data in enumerate(invalid):
            check(not command(h, flow, approved, proxy=proxy, agent=agent, data=data).ok, f"malformed private signing JSON variant{index} accepted")
        for patch in ({"owner_review_id": "review_" + "1" * 64}, {"join_review_id": "review_" + "2" * 64},
                      {"context": {**body["context"], "native_session_id": "other-private-native"}}):
            check(not command(h, flow, approved, proxy=proxy, agent=agent, data=compact({**body, **patch})).ok, "wrong owner/join/context pin reached signing")
        check(not command(h, flow, approved, proxy=proxy, agent=agent, stdin=False).ok, "signing consumed implicit private stdin")
        check(not agent.messages and not proxy.submissions and records(h) == before and private_files(h.home) == home, "invalid/binding inputs used a key or mutated state")
        # The exact byte ceiling reaches the real signer and one submission.
        install_key(h); command(h, flow, approved, proxy=proxy, data=maximum)
        check_submission(proxy, approved); verify_offer(h, flow, approved)
        generated_path(h).unlink(); pure_retry(h, flow, approved, proxy, agent)
    cancelled, _, f2, a2 = approved_fixture("cancel")
    check(cancelled.api("POST", "/v2/link/requests/" + f2["outcome"]["request_id"] + "/cancel", {})[0] == 200, "real cancellation fixture")
    with AgentProxy("c", [source()["key"]]) as agent, HostProxy(cancelled, "cp") as proxy:
        check(not command(cancelled, f2, a2, proxy=proxy, agent=agent).ok and not agent.messages and not proxy.submissions, "cancelled request reached key use")
    detached, p3, f3, a3 = approved_fixture("detach")
    detached.ok("session", "detach", p3["review"]["session_id"])
    with AgentProxy("d", [source()["key"]]) as agent, HostProxy(detached, "dp") as proxy:
        check(not command(detached, f3, a3, proxy=proxy, agent=agent).ok and not agent.messages and not proxy.submissions, "detached parent reached fresh key use")
    missing = suite.host("missing", start=False); before = private_files(missing.root)
    check(not command(missing, flow, approved).ok and private_files(missing.root) == before, "signing initialized state or started missing daemon")
    check(h.api("POST", path(flow, "sign"), signed_body(flow, approved))[0] == 404, "CLI slice added an owner-sign HTTP route")


def alter_packet(view, change):
    for slot in view["signing_requests"]:
        packet = json.loads(base64.b64decode(slot["template_base64"]))
        change(packet)
        slot["template_base64"] = base64.b64encode(compact(packet)).decode()
        slot["object_id"] = packet_id(packet)
        slot["message_base64"] = base64.b64encode(packet_message(packet)).decode()


def alter_payload(view, patch):
    def change(packet):
        body = json.loads(base64.b64decode(packet["payload_base64"]))
        body.update(patch); packet["payload_base64"] = base64.b64encode(compact(body)).decode()
    alter_packet(view, change)


def alter_descriptor(view):
    packet = json.loads(base64.b64decode(view["signing_requests"][0]["template_base64"]))
    body = json.loads(base64.b64decode(packet["payload_base64"]))
    descriptor = copy.deepcopy(body["descriptor"]); descriptor["name"] += " changed"
    alter_payload(view, {"descriptor": descriptor})


@suite.case("authentic_response_faults_refuse_wrong_review_provider_packet_slots_and_messages", "guided onboarding18 verification4")
def _():
    h, _, flow, approved = approved_fixture("faults"); rid = flow["outcome"]["request_id"]
    status, original = h.api("GET", "/v2/link/requests/" + rid + "/approval")
    check(status == 200 and any(s["role"] == "authority" for s in original["signing_requests"]), "authentic approved ready-slot fixture")
    with AgentProxy("f", [source()["key"]]) as agent, HostProxy(h, "fp") as proxy:
        before, home = settled(h), private_files(h.home)
        owner_faults = [
            ("extra", lambda v: v.update(signing_requests="PRIVATE_SIGNING_MARKER")),
            ("digest", lambda v: v["owner"].update(review_id="review_" + "f" * 64)),
            ("host", lambda v: v.update(host_id="host_" + "f" * 64)),
            ("effects", lambda v: v["owner"]["review"]["effects"].update(commit_request=True)),
            ("request", lambda v: v["request"].update(device_public_key=source()["person"])),
        ]
        for label, change in owner_faults:
            def mutate(method, endpoint, body, status, value):
                if endpoint.endswith("/owner/lookup"):
                    change(value)
                return status, value
            proxy.mutate = mutate
            check(not command(h, flow, approved, proxy=proxy, agent=agent).ok, f"owner response fault {label} signed")
        packet_faults = [
            ("intent", lambda v: [s.update(intent_id="dint_" + "1" * 32) for s in v["signing_requests"]]),
            ("slot2", lambda v: [s.update(slot_id=2) for s in v["signing_requests"]]),
            ("role", lambda v: v["signing_requests"][0].update(role="issuer")),
            ("laterF", lambda v: [s.update(object_type="owner_finalization_packet") for s in v["signing_requests"]]),
            ("format", lambda v: v["signing_requests"][0].update(format="ed25519")),
            ("key", lambda v: v["signing_requests"][0].update(public_key=h.public_key)),
            ("message", lambda v: v["signing_requests"][0].update(message_base64=base64.b64encode(b"PRIVATE_SIGNING_MARKER arbitrary").decode())),
            ("duplicates", lambda v: v["signing_requests"].append(copy.deepcopy(v["signing_requests"][0]))),
            ("no original slot or proof", lambda v: v.update(signing_requests=[])),
            ("provider", lambda v: v["review"]["provider"].update(kind="network_root")),
            ("root", lambda v: v["review"].update(root_state_id="drs_" + "1" * 64)),
            ("profile", lambda v: v["review"].update(scopes=15)),
            ("stage", lambda v: v["review"].update(stage="owner_finalization")),
            ("packet member", lambda v: alter_payload(v, {"member": "different reviewed member"})),
            ("packet descriptor", alter_descriptor),
            ("packet scopes", lambda v: alter_payload(v, {"scopes": 1})),
            ("packet lifetime", lambda v: alter_payload(v, {"not_after": rfc3339(h.now() + timedelta(days=8))})),
            ("packet root", lambda v: alter_payload(v, {"root_state_id": "drs_" + "2" * 64})),
            ("packet host", lambda v: alter_packet(v, lambda p: p.update(writer_host_public_key=source()["person"]))),
        ]
        for label, change in packet_faults:
            fault = copy.deepcopy(original); change(fault)
            proxy.mutate = lambda method, endpoint, body, status, value: (status, copy.deepcopy(fault) if endpoint.endswith("/approval") else value)
            check(not command(h, flow, approved, proxy=proxy, agent=agent).ok, f"typed ordinary response fault {label} reached signing")
        check(not agent.signatures and not proxy.submissions, "malformed authentic-response faults signed or submitted original bytes")
        check(records(h) == before and private_files(h.home) == home, "response faults changed durable protocol/key state")
        check(intent(h, approved["owner"]["review"]["intent_id"])["record"]["approved"] is True, "response faults changed durable approval")


@suite.case("pre_key_pre_submission_guards_and_lost_submission_response_recover_once", "guided onboarding18 verification5")
def _():
    for index, mode in enumerate(("parent-before-key", "cancel-during-key", "expiry-during-key")):
        h, parent, flow, approved = approved_fixture("guard" + str(index))
        with AgentProxy("r" + str(index), [source()["key"]]) as agent, HostProxy(h, "rp" + str(index)) as proxy:
            fired = []
            def change(kind):
                expected = 11 if mode == "parent-before-key" else 13
                if kind != expected or fired:
                    return
                fired.append(kind)
                if mode == "parent-before-key":
                    check(h.api("POST", "/v1/sessions/" + parent["review"]["session_id"] + "/detach", {})[0] == 200, "public key-selection parent-change fixture")
                elif mode == "cancel-during-key":
                    check(h.api("POST", "/v2/link/requests/" + flow["outcome"]["request_id"] + "/cancel", {})[0] == 200, "public during-sign request cancellation fixture")
                else:
                    advance_to(h, parse_time(approved["request"]["expires_at"]) + timedelta(seconds=1))
            agent.before = change
            check(not command(h, flow, approved, proxy=proxy, agent=agent).ok and fired, f"guard {mode} did not observe the controlled boundary")
            check(len(agent.signatures) == (0 if mode == "parent-before-key" else 1) and not proxy.submissions,
                  f"guard {mode} signed before recheck or submitted after changed eligibility")
    h, _, flow, approved = approved_fixture("lost")
    with AgentProxy("l", [source()["key"]]) as agent, HostProxy(h, "lp") as proxy:
        proxy.drop_signed = True
        result = command(h, flow, approved, proxy=proxy, agent=agent)
        check(not result.ok, "dropped committed submission response claimed a known result")
        check_submission(proxy, approved); check(len(agent.signatures) == 1, "uncertain submission retried original signing")
        verify_offer(h, flow, approved)
        before = len(agent.messages); pure_retry(h, flow, approved, proxy, agent)
        check(len(agent.messages) == before and len(agent.signatures) == 1, "unknown-outcome exact replay relisted/resigned the original")


@suite.case("same_intent_real_administrator_finalization_commit_and_pure_history_without_keys", "guided onboarding18 verification6")
def _():
    issuer, h = progress_transport_host("live-issuer"), progress_transport_host("live-joiner")
    network = create_network(issuer, "bounded original ceremony", "issuer"); parent = project(h, "live-owner")
    status, issued = issuer.api("POST", f"/v2/networks/{network['id']}/invitations", {"member": "new original", "expected_person_public_key": source()["person"],
                                      "expires_at": rfc3339(issuer.now() + timedelta(hours=1))})
    check(status == 201, "live invitation fixture")
    flow = join(h, parent, issued["invitation"], source()["person"]); prepared = owner(h, flow, "prepare"); approved = owner(h, flow, "approve", prepared)
    key = install_key(h); rid = flow["outcome"]["request_id"]; iid = approved["owner"]["review"]["intent_id"]
    status, ordinary = h.api("POST", "/v2/link/requests", {"mode": "new", "network_id": network["id"], "person_public_key": source()["person"],
                            "migration_proposal_id": "-", "contact_invitation": issued["invitation"], "helpers": []})
    check(status == 200 and ordinary["request_id"] == rid, "ordinary pairing retrieval did not reuse exact guided request")
    reply = ordinary["display_code"]
    with HostProxy(h, "vp") as proxy:
        command(h, flow, approved, proxy=proxy); check_submission(proxy, approved)
        view = verify_offer(h, flow, approved); key.unlink()
        pure_retry(h, flow, approved, proxy, logical=False)
        if view["state"] == "needs_selection":
            select(h, view)
        view = link_view(h, rid)
        # Bring the independent administrator to the same legitimate decision
        # time so its finite ordinary parents are verified coherently.
        issuer.clock.set(h.clock.offset)
        issuer.ok_incomplete("link", "admit", "--network", network["id"], "--owner-offer", view["owner_offer_id"], "--selection", view["selection_id"],
                             "--person", source()["person"], "--expect-host-key", view["host_public_key"], "--expect-device-key", view["device_public_key"],
                             "--code-stdin", "--approve", input=reply + "\n")
        view = pull_until(h, rid, "administrator_offer_id", timeout=20); finalize(h, view, source()["key"])
        view = pull_until(h, rid, "owner_finalization_id", timeout=20)
        pure_retry(h, flow, approved, proxy, logical=False)
        commit(h, view); wait_linked(h, issuer, rid, timeout=20); issuer.stop()
        check(pending(h, rid)[0]["owner_intent_id"] == iid, "advanced F/commit changed the original intention")
        pure_retry(h, flow, approved, proxy)
        h.restart(kill=True)
        advance_to(h, parse_time(approved["request"]["expires_at"]) + timedelta(seconds=1))
        pure_retry(h, flow, approved, proxy)
        check(len(proxy.submissions) == 1, "historical retry signed later F work or recreated original approval")


suite.finish()
