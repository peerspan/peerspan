#!/usr/bin/env python3
"""Exact nonsigning project agent-access consent, guided contract section31.

Independent contract-only source: actual two-host/two-person admission, signed
public baseline policies, ordinary provider selection and attached projects.
Both bootstrap TLS paths and every enabled QUIC path are transparently counted.
Real invitation/request deadlines, ordinary create/cancel maintenance, empty
outboxes/journals and synchronous directory observations precede purity bounds.
Only schema-only SQLite ABORT triggers and a restored offline corruption of an
already genuine NONSIGNING receipt are negative storage faults. No authority,
action, key, seed, queue or protocol row is invented or edited. Setup's ordinary
policy signing is explicit; no guided prepare/approve signs or publishes.

Source limits: this one-machine-per-person fixture does not establish genuine
same-person displaced unsettled withdrawals, incomplete/forked/root histories,
independent root/member/lease changes, broken owned-device seed, u64/edit-counter
exhaustion, a deterministic first-link ordinary-action collision, or aggregate
receipt/intent/output quotas. Absent-policy behavior is observed only if genuine
ordinary setup leaves that stream absent; no fake empty authority is substituted.
No claim about signer file-open syscalls, subsecond races, native/model/physical
readiness or installed bundles. All 25 previous suite sources remain unchanged.
"""
import atexit
import base64
import copy
import hashlib
import http.client
import json
import math
import re
import select
import shutil
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.parse
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, create_network,
                     join_new_person, parse_time, rfc3339, ssh_key, ssh_public_base64,
                     wait_for)
from counted_peer import CountedUDP, exchange_current_contacts, peer_address

suite = Suite("access_consent", __doc__)
BASE = "/v1/onboarding/access-consent"
INSPECT = "/v1/onboarding/access-inspection"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ("psi2-", "psl2-", "peerspan-invite-v1.", "peerspan-member-invite-v1.",
            "peerspan-person-invite-v1.", "token_", "instance_")
TOP = set("version host_id context observed_at access".split())
REVIEW = set("version kind access_id host_id context inspection_review_id inspection replaces_access_id grant action_id intent_id provider statement created_at expires_at effects".split())
RECORD = set("format operation_id approved approved_at review_base64 provider root_state_id person_public_key host_public_key device_public_key scopes not_after created_at expires_at templates signatures completed terminal result_base64".split())
EFFECTS = {"approve_policy_intent": True, "authorize_policy_signature": True,
           "authorize_policy_publication": True, "grant_agent_access_after_signatures": True,
           "grant_membership": False, "delegate_tasks": False, "share_files": False,
           "share_conversation": False, "capability_calls": False, "allow_disconnected": False}
state = {}

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()

def get(h, path):
    status, value = h.api("GET", path, timeout=8)
    check(status == 200, f"public fixture observation HTTP {status}")
    return value

class Relay:
    """Count every connection and received byte without terminating pinned TLS."""
    def __init__(self, target):
        self.target = target
        self.connections = self.received = 0
        self.lock, self.done = threading.Lock(), threading.Event()
        self.sockets = set()
        outer = self

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                upstream = None
                with outer.lock:
                    outer.connections += 1
                    outer.sockets.add(self.request)
                try:
                    upstream = socket.create_connection(outer.target, timeout=2)
                    with outer.lock:
                        outer.sockets.add(upstream)
                    while not outer.done.is_set():
                        ready, _, _ = select.select([self.request, upstream], [], [], .1)
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
                        outer.sockets.discard(upstream)
                    if upstream:
                        upstream.close()

        self.server = Server(("127.0.0.1", 0), Handler)
        while self.server.server_address[1] == target[1]:
            self.server.server_close()
            self.server = Server(("127.0.0.1", 0), Handler)
        self.address = "127.0.0.1:" + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        atexit.register(self.close)

    def counts(self):
        with self.lock:
            return self.connections, self.received

    def close(self):
        if self.done.is_set():
            return
        self.done.set()
        with self.lock:
            active = list(self.sockets)
        for item in active:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)

def host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    h.relay = Relay(("127.0.0.1", h.bootstrap_port))
    h.counted_peer = CountedUDP(("127.0.0.1", h.peer_port))
    config = h.root / "transport.json"
    config.write_bytes(compact({"format": 1, "advertise_bootstrap": [h.relay.address],
                               "advertise_quic": [h.counted_peer.address], "rendezvous": [], "relays": [],
                               "publish_contacts": False}))
    config.chmod(0o600)
    h.extra_args = ["--transport-config", config, "--person-key-file", h.root / "absent-person-key"]
    h.extra_env = {"SSH_AUTH_SOCK": str(h.root / "absent-agent.sock")}
    return h.start()

def project(h, name, *, old=None, agent=None):
    body = {"project_root": old["review"]["project_root"] if old else str(suite.work / ("project " + name)),
            "native_session_id": old["review"]["native_session_id"] if old else "native-" + name,
            "integration": "claude-code", "agent": agent or {
                "kind": "new", "name": 'Agent "東京" ' + name, "owner": "Owner é"}}
    if old:
        body["replace_flow_id"] = old["flow_id"]
    status, flow = h.api("POST", PROJECT, body, timeout=8)
    check(status == 201, f"ordinary project preparation HTTP {status}")
    status, flow = h.api("POST", PROJECT + "/" + flow["flow_id"] + "/decision", {
        **{key: body[key] for key in ("project_root", "native_session_id", "integration")},
        "review_id": flow["review_id"], "decision": "approve"}, timeout=8)
    check(status == 200 and flow["state"] == "attached", "ordinary project attachment failed")
    return flow

def context(parent):
    return {"project_flow_id": parent["flow_id"], "project_review_id": parent["review_id"],
            **{key: parent["review"][key] for key in ("project_root", "native_session_id", "integration")}}

def statement_id(envelope):
    message = "\n".join(("peerspan-decentralized-statement-v1", envelope["kind"], envelope["context_id"],
                          hashlib.sha256(base64.b64decode(envelope["payload_base64"], validate=True)).hexdigest()))
    return "ds_" + hashlib.sha256(message.encode()).hexdigest()

def current_policy(h, net, person):
    status, current = h.api("GET", f"/v2/networks/{net}/policy/{urllib.parse.quote(person, safe='')}")
    if status == 404:
        return None
    check(status == 200, "ordinary current-policy observation failed")
    envelope = json.loads(base64.b64decode(current["statement_base64"], validate=True))
    signed = json.loads(base64.b64decode(envelope["payload_base64"], validate=True))
    body = json.loads(base64.b64decode(signed["body_base64"], validate=True))
    check(current["statement_id"] == statement_id(envelope), "ordinary policy statement ID mismatch")
    return current, envelope, signed, body

def db_path(h):
    paths = []
    for path in h.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                paths.append(path)
    check(len(paths) == 1, "expected exactly one ordinary host database")
    return paths[0]

def records(h):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True, timeout=5)) as db, db:
        db.execute("BEGIN")
        value = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                 "$version": db.execute("PRAGMA user_version").fetchone()}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            value[name] = tuple(sorted(db.execute('SELECT * FROM "' + name.replace('"', '""') + '"'), key=repr))
        return value

def files(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))] if root.exists() else []:
        # Logical DB rows include every table. SQLite WAL/SHM are read-lock and
        # checkpoint bookkeeping, including files our read connection creates.
        if any(str(path).endswith(s) and Path(str(path)[:-len(s)]).suffix == ".db" for s in ("-wal", "-shm")):
            continue
        result[str(path.relative_to(root))] = (path.lstat().st_mode,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and path.suffix != ".db" else None)
    return result

def snapshot(h):
    return records(h), files(h.state), files(h.home)

def traffic(f):
    return (f["a"].relay.counts(), f["b"].relay.counts(),
            f["a"].counted_peer.counts(), f["b"].counted_peer.counts())

def retired_transport(f):
    for local in (f["a"], f["b"]):
        with closing(sqlite3.connect(f"file:{db_path(local)}?mode=ro", uri=True)) as db:
            if db.execute("SELECT count(*) FROM dec_pending WHERE secret IS NOT NULL OR terminal_read_cap IS NOT NULL").fetchone()[0]:
                return False
            if db.execute("SELECT count(*) FROM dec_frames").fetchone()[0]:
                return False
            if db.execute("SELECT count(*) FROM dec_outbox").fetchone()[0]:
                return False
        if list(local.state.glob("*-journal")):
            return False
    return True

def unsigned_maintenance(h):
    key = ssh_key(suite.work, "access-maintenance-" + h.name)
    status, spare = h.api("POST", "/v2/link/requests", {
        "mode": "new", "network_id": "-", "person_public_key": ssh_public_base64(key),
        "migration_proposal_id": "-", "contact_invitation": "-", "helpers": []})
    check(status == 201 and not spare["selection_approved"] and not spare["commit_approved"],
          "ordinary unsigned retirement maintenance created consent")
    status, cancelled = h.api("POST", "/v2/link/requests/" + spare["request_id"] + "/cancel", {})
    check(status == 200 and cancelled["state"] == "cancelled", "ordinary maintenance cancellation failed")

def quiet(f, h, *, require_retirement=False):
    previous = snapshot(h), traffic(f)
    stable_since = time.monotonic()
    def settled():
        nonlocal previous, stable_since
        current = snapshot(h), traffic(f)
        if current != previous:
            stable_since = time.monotonic()
        previous = current
        return time.monotonic() - stable_since >= .3 and (not require_retirement or retired_transport(f))
    wait_for(settled, timeout=5, interval=.1, message="genuine whole-state and both-carrier quiescence")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def public(value, *secrets):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    for n, marker in enumerate((*PREFIXES, "payload_base64", "template_base64", "message_base64",
                                "signing_requests", "return_secret", '"signature"', '"seed"',
                                "admin.sock", "adapter.sock", *secrets)):
        check(not marker or marker not in text, f"access consent exposed private material rule{n}")


def key_body(parent, network, person):
    return {"context": context(parent), "network_id": network, "person_public_key": person}


def inspection(h, parent, network, person):
    status, value = h.api("POST", INSPECT, key_body(parent, network, person), timeout=8)
    check(status == 200 and value.get("next_action") == "review_agent_access", "genuine exact current inspection prerequisite")
    check(value["review_id"] == "review_" + hashlib.sha256(
        b"peerspan-project-access-inspection-v1\n" + canonical(value["review"])).hexdigest(), "inspection digest prerequisite")
    return value


def intent(h, iid):
    check(re.fullmatch(r"dint_[0-9a-f]{32}", iid), "noncanonical durable intent ID")
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?", (iid,)).fetchone()
    check(row is not None, "receipt references no retained ordinary intent")
    return {"network_id": row[0], "context_id": row[1], "kind": row[2], "record": json.loads(row[3]), "secret": row[4]}


def unsigned(h, value):
    review = value["access"]["review"]
    action = intent(h, review["intent_id"])
    record = action["record"]
    check(action["kind"] == "action" and action["secret"] is None and len(record["templates"]) == 1,
          "access is not a separate ordinary single-template policy action")
    slot = record["templates"][0]
    check(set(slot) == {"slot_id", "object_type", "template_base64"} and slot["slot_id"] == 1
          and slot["object_type"] == "policy", "ordinary immutable typed policy slot")
    envelope = json.loads(base64.b64decode(slot["template_base64"], validate=True))
    raw = base64.b64decode(envelope["payload_base64"], validate=True)
    return action, envelope, raw, json.loads(raw)


def validate(h, parent, value, *, expected=None):
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1,
          "closed exact access-consent result")
    check(value["host_id"] == h.id and value["context"] == context(parent), "exact outer host/project context")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"])
          and abs((parse_time(value["observed_at"]) - h.now()).total_seconds()) < 5, "canonical actual observation time")
    access = value["access"]
    if access is None:
        public(value)
        return
    check(set(access) == {"access_id", "review_id", "review", "state", "next_action"}, "closed consent observation")
    review = access["review"]
    check(set(review) == REVIEW and type(review["version"]) is int and review["version"] == 1
          and review["kind"] == "approve_project_agent_access", "closed full immutable access review")
    check(review["access_id"] == access["access_id"] and review["host_id"] == h.id and review["context"] == context(parent),
          "receipt/context identity duplication")
    frozen = review["inspection"]
    check(review["inspection_review_id"] == "review_" + hashlib.sha256(
        b"peerspan-project-access-inspection-v1\n" + canonical(frozen)).hexdigest(), "frozen complete inspection digest")
    check(frozen["host_id"] == h.id and frozen["context"] == context(parent)
          and frozen["agent"] == parent["review"]["agent"], "full frozen agent and inspection binding")
    principal = "person:person_" + hashlib.sha256(base64.b64decode(frozen["participant"]["person_public_key"], validate=True)).hexdigest()
    check(review["grant"] == {"policy_scope": "owner_agent_name", "agent_id": frozen["agent"]["id"],
          "agent_name": frozen["agent"]["name"], "principal": principal,
          "actions": ["message.append", "task.submit"], "max_message_bytes": 65536,
          "max_artifact_bytes": 0, "allow_disconnected": False}, "exact narrow owner-wide agent NAME profile")
    check(review["replaces_access_id"] == "-" or re.fullmatch(r"dint_[0-9a-f]{32}", review["replaces_access_id"]),
          "immutable replacement lineage is not a local intent ID")
    check(re.fullmatch(r"act_[0-9a-f]{64}", review["action_id"]), "ordinary policy action ID")
    receipt = intent(h, access["access_id"])
    record = receipt["record"]
    action, envelope, raw, payload = unsigned(h, value)
    action_record = action["record"]
    network = frozen["network"]
    check(receipt["kind"] == "access_review" and receipt["secret"] is None and set(record) == RECORD
          and receipt["network_id"] == action["network_id"] == network["id"]
          and receipt["context_id"] == action["context_id"] == network["context_id"], "existing-schema typed nonsigning receipt")
    check(type(record["format"]) is int and record["format"] == 1 and type(record["approved"]) is bool
          and record["templates"] == [] and record["signatures"] == []
          and record["completed"] is True and record["terminal"] == "-" and record["result_base64"] == "-",
          "receipt acquired a signing, publication, secret or terminal role")
    check(base64.b64decode(record["review_base64"], validate=True) == canonical(review), "canonical full durable public receipt")
    key = key_body(parent, network["id"], frozen["participant"]["person_public_key"])
    check(record["operation_id"] == "arev_" + hashlib.sha256(
        b"peerspan-project-access-key-v1\n" + canonical(key)).hexdigest(), "exact local recovery operation key")
    for field in ("provider", "root_state_id", "person_public_key", "host_public_key", "device_public_key",
                  "scopes", "not_after", "created_at"):
        check(record[field] == action_record[field], "receipt/action duplicated field differs: " + field)
    provider = review["provider"]
    check(set(provider) == {"kind", "person_public_key", "host_public_key", "device_public_key", "lease_id", "root_state_id", "scopes", "not_after"}
          and provider["kind"] in ("original_person", "device")
          and provider["person_public_key"] == frozen["owner"]["person_public_key"]
          and provider["host_public_key"] == h.public_key and provider["root_state_id"] == frozen["root_state_id"],
          "frozen public owner provider changed or fell back to root")
    check(action_record["provider"] == {"kind": "original" if provider["kind"] == "original_person" else "device",
          "signer_public_key": provider["person_public_key"] if provider["kind"] == "original_person" else provider["device_public_key"],
          "signature_format": "sshsig" if provider["kind"] == "original_person" else "ed25519",
          "lease_id": "-" if provider["kind"] == "original_person" else provider["lease_id"]}, "fixed concrete provider/signature format")
    check(record["root_state_id"] == frozen["root_state_id"] and record["person_public_key"] == provider["person_public_key"]
          and record["host_public_key"] == h.public_key and record["device_public_key"] == provider["device_public_key"]
          and record["expires_at"] == review["expires_at"], "receipt public identity/time pins differ")
    check(envelope["kind"] == "policy" and envelope["context_id"] == network["context_id"]
          and statement_id(envelope) == review["statement"]["id"], "ordinary policy statement binding")
    concrete = provider["lease_id"] if provider["kind"] == "device" else provider["person_public_key"]
    check(review["action_id"] == "act_" + hashlib.sha256("\n".join(("peerspan-decentralized-action-intent-v1",
          network["context_id"], "policy", review["statement"]["id"], concrete)).encode()).hexdigest(), "ordinary concrete-provider action ID digest")
    check(action_record["signatures"] == [] and action_record["completed"] is False
          and action_record["terminal"] == "-" and action_record["result_base64"] == "-", "consent's ordinary policy action was signed or applied")
    check(set(review["statement"]) == {"id", "payload_sha256", "payload"}
          and review["statement"]["payload_sha256"] == hashlib.sha256(raw).hexdigest(), "exact original unsigned payload digest")
    body = json.loads(base64.b64decode(payload["body_base64"], validate=True))
    check(review["statement"]["payload"] == {**{k: v for k, v in payload.items() if k != "body_base64"}, "body": body},
          "public payload normalized, dropped or invented unsigned fields")
    check(set(payload) == set("root_state_id operation_id sequence predecessors resolves issuer parents issued_at not_before not_after body_base64".split())
          and payload["operation_id"] == "-" and payload["root_state_id"] == frozen["root_state_id"], "complete ordinary policy payload shape")
    check(review["created_at"] == action_record["created_at"] and parse_time(review["expires_at"]) == min(
        parse_time(payload["issued_at"]) + timedelta(seconds=300), parse_time(payload["not_after"])), "immutable ordinary issued-time consent expiry")
    check(review["effects"] == EFFECTS and all(type(x) is bool for x in review["effects"].values()), "consent effects widened signing/application or sharing")
    check(access["review_id"] == "review_" + hashlib.sha256(
        b"peerspan-project-access-consent-v1\n" + canonical(review)).hexdigest(), "canonical review digest omits frozen exact terms")
    next_actions = {"review": "approve_policy_intent", "approved": "follow_policy_action",
                    "expired": "inspect_agent_access", "invalidated": "inspect_agent_access"}
    check(access["state"] in next_actions and access["next_action"] == next_actions[access["state"]], "incorrect consent state/action")
    check((access["state"] == "approved") == (record["approved"] is True), "guided approval inferred from ordinary action")
    if record["approved"]:
        check(record["approved_at"] == action_record["approved_at"] and action_record["approved"] is True, "atomic identical approval timestamp")
    else:
        check(record["approved_at"] == "-", "unapproved receipt retained approval time")
    check(len(compact(value)) <= 1024 * 1024, "public consent response exceeded1MiB")
    if expected:
        check(review == expected["access"]["review"] and access["review_id"] == expected["access"]["review_id"], "fixed historical review changed")
    public(value)


def op(h, parent, network, person, action, prepared=None, *, inspected=None, replace=None, override=None, status=200, code=None):
    data = key_body(parent, network, person)
    if action == "prepare":
        data["inspection_review_id"] = inspected["review_id"] if inspected else prepared["access"]["review"]["inspection_review_id"]
        if replace is not None:
            data["replace_access_id"] = replace
    elif action == "approve":
        data.update(access_id=prepared["access"]["access_id"], access_review_id=prepared["access"]["review_id"])
    actual, value = h.api("POST", BASE + "/" + action, override if override is not None else data, timeout=8)
    check(actual == status, f"access {action} HTTP {actual}, want {status}")
    if actual == 200:
        validate(h, parent, value)
    else:
        check(isinstance(value, dict) and value.get("code") == code and "access" not in value
              and "review" not in value, f"access {action} did not return closed {code}")
        public(value)
    return value


def directory(f):
    for local, remote in ((f["a"], f["b"]), (f["b"], f["a"])):
        check(get(local, "/v2/networks/" + f["net"])["authority"]["state"] == "usable", "startup authority prerequisite")
        status, view = local.api("POST", "/v1/directory/refresh?network=" + f["net"], {}, timeout=12)
        check(status == 200 and view.get("network_id") == f["net"] and isinstance(view.get("agents"), list), "bounded actual startup directory result")
        known = [entry for entry in view["hosts"] if entry["host_id"] == remote.id]
        check(len(known) == 1 and known[0]["state"] == "ok", "current genuine peer startup query has not completed")


def stable(f):
    for local in (f["a"], f["b"]):
        quiet(f, local, require_retirement=True)


def whole(f):
    return snapshot(f["a"]), snapshot(f["b"])


def pure(f, h, parent, person, action, prepared=None, **options):
    stable(f)
    before, counters = whole(f), traffic(f)
    value = op(h, parent, f["net"], person, action, prepared, **options)
    check(whole(f) == before, f"pure {action} changed whole schema/DB/state/home on either participant")
    check(traffic(f) == counters, f"pure {action} used original TCP or an enabled UDP carrier")
    return value


def select_provider(h, network, person, provider):
    status, value = h.api("POST", f"/v2/networks/{network}/provider", {
        "provider_id": provider, "person_public_key": person, "host_public_key": h.public_key, "approve": True}, timeout=8)
    check(status == 200 and value["provider"]["person_public_key"] == person, "genuine exact ordinary provider selection")
    return value["provider"]


def retire(f):
    targets = [parse_time(x) for x in (*f["invitation_bounds"], f["request_deadline"])]
    target = max(*targets, f["a"].now(), f["b"].now()) + timedelta(seconds=1)
    for local in (f["a"], f["b"]):
        people = get(local, f"/v2/networks/{f['net']}/persons")["persons"]
        check(all(target < parse_time(person["not_after"]) for person in people), "real retirement exceeds current person lease")
        local.clock.set(local.clock.offset + math.ceil((target - local.now()).total_seconds()))
        unsigned_maintenance(local)
    stable(f)


def world():
    if state:
        check("net" in state, "shared genuine fixture setup did not complete")
        return state
    state["building"] = True
    a, b = host("alice"), host("bob")
    net = create_network(a, "Consent 東京", "alice")
    key = ssh_key(b.root, "bob")
    rid = join_new_person(a, b, "bob", key, net["id"])
    for local, remote in ((a, b), (b, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", peer_address(remote))
    exchange_current_contacts(suite, a, b, net["id"])
    bounds = []
    for local in (a, b):
        with closing(sqlite3.connect(f"file:{db_path(local)}?mode=ro", uri=True)) as db:
            bounds.extend(row[0] for row in db.execute("SELECT deadline FROM dec_pending WHERE request_id LIKE 'di_%'"))
    check(bounds, "actual contact invitation deadlines missing")
    state.update(a=a, b=b, net=net["id"], alice=net["person_public_key"], bob=ssh_public_base64(key), key=key,
                 request_deadline=get(b, "/v2/link/requests/" + rid)["expires_at"], invitation_bounds=bounds)
    retire(state)
    state.update(pa=project(a, "alice"), pb=project(b, "bob"))
    state["device"] = get(b, "/v2/networks/" + state["net"])["provider"]
    check(state["device"]["kind"] == "device", "joined host did not retain genuine selected owned device")
    directory(state)
    stable(state)
    state["schema"] = records(b)["$schema"]
    return state


def prepare(f, h, parent, person):
    return op(h, parent, f["net"], person, "prepare", inspected=inspection(h, parent, f["net"], person))


def main_prepared():
    f = world()
    if "prepared" not in f:
        baseline(f)
        f["prepared"] = prepare(f, f["b"], f["pb"], f["alice"])
    return f, f["prepared"]


def baseline(f):
    h, net = f["b"], f["net"]
    name = f["pb"]["review"]["agent"]["name"]
    allowed = h.ok("allow", "alice", "--network", net, "--agent", name, "--files", "12345", "--delegate")
    h.ok("allow", "everyone", "--network", net, "--agent", name)
    h.ok("allow", "everyone", "--network", net, "--agent", "unrelated-default", "--no-tasks")
    h.ok("trust", h.id, "--network", net)
    current, _, signed, body = current_policy(h, net, f["bob"])
    status, plan = h.api("POST", f"/v2/networks/{net}/policy-edits/plan", {"provider_id": "auto"})
    check(status == 200, "genuine read-only next policy/edit plan")
    narrow = [rule for rule in body["rules"] if rule["agent"] == name and rule["actions"] == ["message.append", "task.submit"]]
    check(len(narrow) == 1 and narrow[0]["principals"] == ["network"], "same-settings append prerequisite")
    narrow[0]["max_artifact_bytes"] = 0
    now = rfc3339(h.now())
    body.update(version=plan["version"] + 1, issued_at=now,
        capability_rules=[{"host": h.id, "capability": "fixture-operation", "principals": [allowed["principal"]],
                           "max_input_bytes": 1234, "allow_disconnected": True, "max_calls_per_hour": 17}],
        edits=sorted([entry for entry in body["edits"] if entry["host"] != h.id] + [{"host": h.id, "seq": plan["seq"]}], key=lambda entry: entry["host"]))
    signed.update(sequence=plan["version"] + 1, predecessors=[current["statement_id"]], resolves=[], issued_at=now,
                  not_before=now, body_base64=base64.b64encode(compact(body)).decode())
    status, action = h.api("POST", f"/v2/networks/{net}/actions", {
        "kind": "policy", "provider_id": "auto", "signature_format": "auto",
        "payload_base64": base64.b64encode(compact(signed)).decode(), "approve": True}, timeout=8)
    check(status == 200 and action["committed"] is True and action["signing_requests"] == [], "genuine signed raw baseline setup")
    f["baseline"] = current_policy(h, net, f["bob"])
    directory(f)
    stable(f)


def assert_only(before, after, tables):
    check(before[1:] == after[1:], "consent changed state/home file paths, modes or bytes")
    check({k: v for k, v in before[0].items() if k not in tables} ==
          {k: v for k, v in after[0].items() if k not in tables}, "consent changed unrelated table/schema/version rows")


def assert_new_pair(before, after, prepared):
    assert_only(before, after, {"dec_intents"})
    expected = {prepared["access"]["access_id"], prepared["access"]["review"]["intent_id"]}
    old, new = {row[0]: row for row in before[0]["dec_intents"]}, {row[0]: row for row in after[0]["dec_intents"]}
    check(set(new) - set(old) == expected and all(new[key] == value for key, value in old.items()),
          "preparation did not add exactly two rows while preserving all old kinds/bytes")


def assert_approved_pair(h, prepared, before, after):
    assert_only(before, after, {"dec_intents", "dec_clock"})
    ids = {prepared["access"]["access_id"], prepared["access"]["review"]["intent_id"]}
    old, new = {row[0]: row for row in before[0]["dec_intents"]}, {row[0]: row for row in after[0]["dec_intents"]}
    check(set(old) == set(new), "approval inserted/deleted an intent")
    approved_at = []
    for iid in old:
        if iid not in ids:
            check(old[iid] == new[iid], "approval changed another existing intent kind/record")
            continue
        check(old[iid][:4] == new[iid][:4] and old[iid][5:] == new[iid][5:], "approval changed identity, type or secret")
        original, actual = json.loads(old[iid][4]), json.loads(new[iid][4])
        check(actual["approved"] is True and actual["approved_at"] != "-" and
              {k: v for k, v in original.items() if k not in ("approved", "approved_at")} ==
              {k: v for k, v in actual.items() if k not in ("approved", "approved_at")},
              "approval changed exact unsigned template/signatures/review/provider/payload")
        approved_at.append(actual["approved_at"])
    check(len(approved_at) == 2 and approved_at[0] == approved_at[1]
          and abs((parse_time(approved_at[0]) - h.now()).total_seconds()) < 5, "both approvals did not share actual decision time")


def raw(h, action, data):
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=8)
    try:
        try:
            connection.request("POST", BASE + "/" + action, body=data, headers={"Content-Type": "application/json"})
        except BrokenPipeError:
            pass
        response = connection.getresponse()
        result = response.read()
        return response.status, json.loads(result) if result else None
    finally:
        connection.close()


@suite.case("exact_two_person_narrow_owner_name_payload_unsigned_pair_and_cli", "guided31 verification1")
def _():
    f = world()
    h, parent, net = f["b"], f["pb"], f["net"]
    versions = get(f["a"], f"/v2/networks/{net}/access-versions")["policies"]
    if not any(item["person_public_key"] == f["alice"] for item in versions):
        absent_parent = project(f["a"], "absent-policy")
        absent_inspection = inspection(f["a"], absent_parent, net, f["bob"])
        check(absent_inspection["review"]["policy"] is None, "genuinely empty stream inspection is not null")
        absent = op(f["a"], absent_parent, net, f["bob"], "prepare", inspected=absent_inspection)
        body = absent["access"]["review"]["statement"]["payload"]["body"]
        check(body["format"] == 2 and body["capability_rules"] == [] and body["trusted_hosts"] == []
              and len(body["rules"]) == 1 and body["rules"][0]["principals"] == [absent["access"]["review"]["grant"]["principal"]],
              "genuine absent policy did not start with only the exact first profile")
    else:
        print("LIMIT absent_policy: genuine creator setup retained a policy stream; no fake empty baseline substituted", flush=True)
    baseline(f)
    inspected = inspection(h, parent, net, f["alice"])
    status, plan = h.api("POST", f"/v2/networks/{net}/policy-edits/plan", {"provider_id": "auto"})
    check(status == 200, "actual next edit/version planning prerequisite")
    maximum = next(item for item in get(h, f"/v2/networks/{net}/access-versions")["policies"] if item["person_public_key"] == f["bob"])
    stable(f)
    before, remote, counters = snapshot(h), snapshot(f["a"]), traffic(f)
    prepared = op(h, parent, net, f["alice"], "prepare", inspected=inspected)
    assert_new_pair(before, snapshot(h), prepared)
    check(snapshot(f["a"]) == remote and traffic(f) == counters, "preparation granted/published remotely or used a carrier")
    access, review = prepared["access"], prepared["access"]["review"]
    check(access["state"] == "review" and review["inspection"] == inspected["review"] and review["replaces_access_id"] == "-",
          "first exact inspection receipt/lineage/state")
    action, _, _, payload = unsigned(h, prepared)
    original = inspected["review"]["policy"]["body"]
    body = review["statement"]["payload"]["body"]
    check(review["provider"] == f["device"], "review changed actual selected provider public terms")
    check(payload["sequence"] == body["version"] == maximum["version"] + 1 == plan["version"] + 1
          and payload["predecessors"] == maximum["head_ids"] and payload["resolves"] == [], "retained maximum/head-based new generation")
    check(payload["issued_at"] == payload["not_before"] == body["issued_at"] == review["created_at"]
          and payload["not_after"] == body["valid_until"], "frozen ordinary times/body wrapper")
    check(payload["issuer"] == {"kind": "device", "person_public_key": f["bob"]}, "actual selected device issuer")
    parents = {entry["role"]: entry["id"] for entry in payload["parents"]}
    owner = inspected["review"]["owner"]
    check(parents == {"issuer_person": owner["person_lease_id"], "issuer_device": owner["host"]["device_lease_id"]}, "exact ordinary scope1 provider parents")
    expected_end = min(parse_time(payload["issued_at"]) + timedelta(days=1), parse_time(review["provider"]["not_after"]),
                       parse_time(inspected["review"]["participant"]["not_after"]))
    check(parse_time(payload["not_after"]) == expected_end, "policy lifetime is not fixed24h/provider/person minimum")
    expected = copy.deepcopy(original)
    expected.update(version=maximum["version"] + 1, issued_at=payload["issued_at"], valid_until=payload["not_after"],
        edits=sorted([entry for entry in original["edits"] if entry["host"] != h.id] + [{"host": h.id, "seq": plan["seq"]}], key=lambda entry: entry["host"]))
    narrow = [rule for rule in expected["rules"] if rule["agent"] == review["grant"]["agent_name"]
              and rule["actions"] == ["message.append", "task.submit"] and rule.get("max_artifact_bytes", 0) == 0]
    check(len(narrow) == 1 and narrow[0]["max_artifact_bytes"] == 0 and review["grant"]["principal"] not in narrow[0]["principals"],
          "raw explicit-default same-settings baseline prerequisite")
    narrow[0]["principals"].append(review["grant"]["principal"])
    check(body == expected and body["capability_rules"] and body["trusted_hosts"], "complete signed raw baseline/order/defaults/unrelated terms were not preserved")
    check(action["record"]["approved"] is False and action["record"]["approved_at"] == "-"
          and action["record"]["signatures"] == [] and action["record"]["completed"] is False
          and action["record"]["terminal"] == "-" and action["record"]["result_base64"] == "-", "preparation signed, approved or applied ordinary policy")
    f["prepared"] = prepared
    for command in ("lookup", "prepare"):
        data = key_body(parent, net, f["alice"])
        if command == "prepare":
            data["inspection_review_id"] = inspected["review_id"]
        before, counters = whole(f), traffic(f)
        result = h.cli("onboarding", "access", command, "--stdin", input=compact(data).decode(), timeout=8)
        check(result.ok and result.json["access"] == access, "exact private stdin API/CLI parity or idempotence")
        validate(h, parent, result.json, expected=prepared)
        check(whole(f) == before and traffic(f) == counters, "lookup/repeated prepare CLI changed state/files/carriers")
        public(result.stderr)


@suite.case("exact_binding_null_recovery_lineage_and_advanced_approval_not_consent", "guided31 verification2")
def _():
    f, main = main_prepared()
    h, net = f["b"], f["net"]
    parent = project(h, "binding")
    check(pure(f, h, parent, f["alice"], "lookup")["access"] is None, "lookup-null created a receipt")
    inspected = inspection(h, parent, net, f["alice"])
    prepared = op(h, parent, net, f["alice"], "prepare", inspected=inspected)
    # This different actual agent has no same-name rule: append one exact profile.
    action, _, _, payload = unsigned(h, prepared)
    rules = prepared["access"]["review"]["statement"]["payload"]["body"]["rules"]
    grant = prepared["access"]["review"]["grant"]
    check(rules[-1] == {"agent": grant["agent_name"], "principals": [grant["principal"]],
          **{k: grant[k] for k in ("actions", "max_message_bytes", "max_artifact_bytes", "allow_disconnected")}}, "new exact narrow rule append")
    data = key_body(parent, net, f["alice"])
    for key, value, status, code in (("project_flow_id", "flow_" + "f" * 32, 404, "not_found"),
        ("project_review_id", "review_" + "0" * 64, 409, "review_changed"),
        ("project_root", str(suite.work / "different-root"), 409, "review_changed"),
        ("native_session_id", "different-native", 409, "review_changed")):
        pure(f, h, parent, f["alice"], "lookup", override={**data, "context": {**data["context"], key: value}}, status=status, code=code)
    pure(f, h, parent, f["alice"], "lookup", override={**data, "network_id": "net_" + "f" * 64}, status=404, code="not_found")
    pure(f, h, parent, f["alice"], "approve", prepared, override={**data,
         "access_id": "dint_" + "f" * 32, "access_review_id": prepared["access"]["review_id"]}, status=404, code="not_found")
    pure(f, h, parent, f["alice"], "approve", prepared, override={**data,
         "access_id": prepared["access"]["access_id"], "access_review_id": "review_" + "0" * 64}, status=409, code="review_changed")
    pure(f, h, parent, f["bob"], "approve", prepared, status=409, code="review_changed")
    pure(f, h, parent, f["alice"], "prepare", prepared, replace=prepared["access"]["access_id"], status=409, code="review_changed")
    select_provider(h, net, f["bob"], f["bob"])
    invalid = pure(f, h, parent, f["alice"], "lookup")
    check(invalid["access"]["state"] == "invalidated", "genuine provider change left old work live")
    check(pure(f, h, parent, f["alice"], "prepare", prepared)["access"] == invalid["access"], "invalidated exact history was refreshed")
    successor = op(h, parent, net, f["alice"], "prepare", inspected=inspection(h, parent, net, f["alice"]), replace=prepared["access"]["access_id"])
    check(successor["access"]["access_id"] != prepared["access"]["access_id"] and
          successor["access"]["review"]["intent_id"] != prepared["access"]["review"]["intent_id"] and
          successor["access"]["review"]["replaces_access_id"] == prepared["access"]["access_id"], "replacement did not create exact new lineage/action")
    check(pure(f, h, parent, f["alice"], "prepare", successor, replace=prepared["access"]["access_id"])["access"] == successor["access"], "exact replacement retry appended another receipt")
    pure(f, h, parent, f["alice"], "approve", prepared, status=409, code="review_changed")
    pure(f, h, parent, f["alice"], "prepare", successor, replace=successor["access"]["access_id"], status=409, code="review_changed")
    select_provider(h, net, f["bob"], f["device"]["lease_id"])
    check(pure(f, h, f["pb"], f["alice"], "lookup")["access"] == main["access"], "restored actual provider changed untouched exact pending consent")
    # Ordinary advanced approval of an unavailable external original cannot sign.
    select_provider(f["a"], net, f["alice"], f["alice"])
    check(get(f["a"], f"/v2/networks/{net}")["provider_state"]["state"] == "unavailable", "external original is unexpectedly available")
    other = project(f["a"], "advanced")
    ordinary = prepare(f, f["a"], other, f["bob"])
    _, _, encoded, _ = unsigned(f["a"], ordinary)
    status, result = f["a"].api("POST", f"/v2/networks/{net}/actions", {"kind": "policy", "provider_id": "auto",
        "signature_format": "auto", "payload_base64": base64.b64encode(encoded).decode(), "approve": True}, timeout=8)
    check(status == 200 and result["action_id"] == ordinary["access"]["review"]["action_id"]
          and result["committed"] is False and result["signing_requests"], "genuine advanced-only original action approval prerequisite")
    check(intent(f["a"], ordinary["access"]["review"]["intent_id"])["record"]["signatures"] == [], "advanced fixture unexpectedly signed")
    observed = pure(f, f["a"], other, f["bob"], "lookup")
    check(observed["access"]["state"] == "invalidated" and
          intent(f["a"], ordinary["access"]["access_id"])["record"]["approved"] is False, "advanced action approval became human consent")
    pure(f, f["a"], other, f["bob"], "approve", ordinary, status=409, code="review_changed")
    pure(f, f["a"], other, f["bob"], "prepare", ordinary, replace=ordinary["access"]["access_id"], status=409, code="review_changed")
    check(pure(f, f["a"], other, f["bob"], "prepare", ordinary)["access"] == observed["access"],
          "advanced-approved ordinary action lost pure invalidated history")
    f["advanced"] = other, ordinary


@suite.case("late_prepare_approve_faults_atomic_exact_receipt_action_clock_and_no_signing", "guided31 verification3")
def _():
    f, prepared = main_prepared()
    h, net, parent = f["b"], f["net"], f["pb"]
    fault_parent = project(h, "fault")
    inspected = inspection(h, fault_parent, net, f["alice"])
    stable(f)
    original_schema = records(h)["$schema"]
    count = len(records(h)["dec_intents"])
    # Abort only after both genuine attempted inserts have reached the table,
    # independent of which of the receipt/action the implementation inserts first.
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute(f"CREATE TRIGGER access_prepare_abort AFTER INSERT ON dec_intents "
                   f"WHEN (SELECT count(*) FROM dec_intents) >= {count + 2} "
                   "BEGIN SELECT RAISE(ABORT,'PRIVATE_ACCESS_ABORT'); END")
    try:
        before, counters = whole(f), traffic(f)
        status, denied = h.api("POST", BASE + "/prepare", {**key_body(fault_parent, net, f["alice"]),
            "inspection_review_id": inspected["review_id"]}, timeout=8)
        check(not 200 <= status < 300, "late INSERT fault unexpectedly succeeded")
        public(denied, "PRIVATE_ACCESS_ABORT")
        check(whole(f) == before and traffic(f) == counters, "late preparation fault left one row, clock, files or IO")
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute("DROP TRIGGER access_prepare_abort")
    check(records(h)["$schema"] == original_schema, "preparation fault left DDL")
    retried = op(h, fault_parent, net, f["alice"], "prepare", inspected=inspected)
    check(retried["access"]["state"] == "review", "exact preparation retry did not retain genuine pair")
    receipt_id, action_id = prepared["access"]["access_id"], prepared["access"]["review"]["intent_id"]
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute(f"CREATE TRIGGER access_approve_abort AFTER UPDATE OF record ON dec_intents "
                   f"WHEN NEW.intent_id IN ('{receipt_id}','{action_id}') AND "
                   f"(SELECT count(*) FROM dec_intents WHERE intent_id IN ('{receipt_id}','{action_id}') "
                   "AND json_extract(record,'$.approved')=1)=2 "
                   "BEGIN SELECT RAISE(ABORT,'PRIVATE_ACCESS_ABORT'); END")
    try:
        before, counters = whole(f), traffic(f)
        status, denied = h.api("POST", BASE + "/approve", {**key_body(parent, net, f["alice"]),
            "access_id": receipt_id, "access_review_id": prepared["access"]["review_id"]}, timeout=8)
        check(not 200 <= status < 300, "late UPDATE fault unexpectedly succeeded")
        public(denied, "PRIVATE_ACCESS_ABORT")
        check(whole(f) == before and traffic(f) == counters, "late approval fault left partial receipt/action/clock/files/IO")
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute("DROP TRIGGER access_approve_abort")
    check(records(h)["$schema"] == original_schema, "approval fault left DDL")
    stable(f)
    before, remote, counters = snapshot(h), snapshot(f["a"]), traffic(f)
    approved = op(h, parent, net, f["alice"], "approve", prepared)
    check(approved["access"]["state"] == "approved", "exact genuine policy consent was not approved")
    validate(h, parent, approved, expected=prepared)
    assert_approved_pair(h, prepared, before, snapshot(h))
    check(snapshot(f["a"]) == remote and traffic(f) == counters, "consent published, signed or used remote carrier")
    for command in ("lookup", "prepare", "approve"):
        check(pure(f, h, parent, f["alice"], command, prepared)["access"] == approved["access"], "approved replay changed exact receipt/action/time")
    f["approved"] = approved
    # Original slots remain legitimate public authority with no matching file
    # or agent. Consent itself cannot require a possession/signature probe.
    a = f["a"]
    select_provider(a, net, f["alice"], f["alice"])
    check(get(a, f"/v2/networks/{net}")["provider_state"]["state"] == "unavailable", "missing external original prerequisite")
    external_parent = project(a, "absent-original")
    external = prepare(f, a, external_parent, f["bob"])
    stable(f)
    before, remote, counters = snapshot(a), snapshot(h), traffic(f)
    request = {**key_body(external_parent, net, f["bob"]), "access_id": external["access"]["access_id"],
               "access_review_id": external["access"]["review_id"]}
    result = a.cli("onboarding", "access", "approve", "--stdin", input=compact(request).decode(), timeout=8)
    check(result.ok and result.json["access"]["state"] == "approved", "private CLI consent probed absent original signer")
    validate(a, external_parent, result.json, expected=external)
    assert_approved_pair(a, external, before, snapshot(a))
    check(snapshot(h) == remote and traffic(f) == counters, "original consent produced a signature/publication/remote request")
    public(result.stderr, str(a.root / "absent-person-key"))
    f["external"] = external_parent, external, result.json


@suite.case("genuine_changed_policy_provider_clock_and_expiry_refuse_without_refresh", "guided31 verification4")
def _():
    f, _ = main_prepared()
    h, net = f["b"], f["net"]
    parent = project(h, "stale")
    stale = prepare(f, h, parent, f["alice"])
    original = intent(h, stale["access"]["review"]["intent_id"])
    h.ok("allow", "alice", "--network", net, "--agent", "ordinary-change")
    directory(f)
    pure(f, h, parent, f["alice"], "approve", stale, status=409, code="review_changed")
    invalid = pure(f, h, parent, f["alice"], "lookup")
    check(invalid["access"]["state"] == "invalidated" and intent(h, stale["access"]["review"]["intent_id"]) == original,
          "genuine new head signed, rewrote or refreshed stale action")
    current = inspection(h, parent, net, f["alice"])
    check(current["review_id"] != stale["access"]["review"]["inspection_review_id"], "actual policy change did not change current inspection")
    pure(f, h, parent, f["alice"], "prepare", stale, inspected=current, status=409, code="review_changed")
    replacement = op(h, parent, net, f["alice"], "prepare", inspected=current, replace=stale["access"]["access_id"])
    check(replacement["access"]["review"]["replaces_access_id"] == stale["access"]["access_id"] and
          replacement["access"]["review"]["statement"] != stale["access"]["review"]["statement"], "changed head replacement silently reused old draft")
    offset = h.clock.offset
    h.clock.set(offset - 120)
    pure(f, h, parent, f["alice"], "approve", replacement, status=409, code="access_review_unavailable")
    h.clock.set(offset)
    check(pure(f, h, parent, f["alice"], "lookup")["access"] == replacement["access"], "rollback refusal mutated fixed consent")
    deadline = parse_time(replacement["access"]["review"]["expires_at"]) + timedelta(seconds=1)
    for local in (f["a"], f["b"]):
        local.clock.set(local.clock.offset + math.ceil((deadline - local.now()).total_seconds()))
    directory(f)
    elapsed = pure(f, h, parent, f["alice"], "lookup")
    check(elapsed["access"]["state"] == "expired", "fixed actual issued-time300s bound refreshed on lookup")
    check(pure(f, h, parent, f["alice"], "prepare", replacement)["access"] == elapsed["access"], "expired exact preparation refreshed payload/time")
    pure(f, h, parent, f["alice"], "approve", replacement, status=409, code="review_expired")
    successor = op(h, parent, net, f["alice"], "prepare", inspected=inspection(h, parent, net, f["alice"]),
                   replace=replacement["access"]["access_id"])
    check(successor["access"]["access_id"] != replacement["access"]["access_id"] and
          successor["access"]["review"]["replaces_access_id"] == replacement["access"]["access_id"] and
          successor["access"]["review"]["created_at"] != replacement["access"]["review"]["created_at"], "explicit expired replacement did not preserve old lineage/time")
    pure(f, h, parent, f["alice"], "approve", replacement, status=409, code="review_changed")
    f["pending"] = parent, successor
    print("LIMIT genuine_complex_guards: fork/incomplete/unsettled sibling, independent root/member/lease change, broken device seed and u64/edit overflow not constructed", flush=True)


@suite.case("approved_unapproved_detached_replaced_elapsed_restart_history_strict_all_carrier_purity", "guided31 verification5")
def _():
    f, prepared = main_prepared()
    h, net = f["b"], f["net"]
    approved = f.get("approved") or op(h, f["pb"], net, f["alice"], "approve", prepared)
    original_record = intent(h, prepared["access"]["access_id"])
    action_record = intent(h, prepared["access"]["review"]["intent_id"])
    if "pending" not in f:
        parent = project(h, "unapproved-history")
        f["pending"] = parent, prepare(f, h, parent, f["alice"])
    pending_parent, pending = f["pending"]
    h.ok("session", "detach", pending_parent["review"]["session_id"])
    unapproved = pure(f, h, pending_parent, f["alice"], "lookup")
    check(unapproved["access"]["state"] == "invalidated", "detached unapproved exact receipt stayed live")
    pure(f, h, pending_parent, f["alice"], "approve", pending, status=409, code="review_changed")
    h.ok("session", "detach", f["pb"]["review"]["session_id"])
    replacement_parent = project(h, "history-replacement", old=f["pb"])
    check(replacement_parent["flow_id"] != f["pb"]["flow_id"], "genuine project replacement did not change original parent")
    directory(f)
    stable(f)
    for command in ("lookup", "prepare", "approve"):
        check(pure(f, h, f["pb"], f["alice"], command, prepared)["access"] == approved["access"], "detached/replaced/elapsed approved history changed")
    h.restart(kill=True)
    # Observe actual ordinary startup/detach and a completed synchronous current
    # directory result before the unchanged strict baseline, never sleep a guess.
    check(get(h, PROJECT + "/" + replacement_parent["flow_id"])["state"] == "invalidated", "restart did not observe ordinary attachment invalidation")
    directory(f)
    stable(f)
    before, counters = whole(f), traffic(f)
    for command in ("lookup", "prepare", "approve"):
        value = op(h, f["pb"], net, f["alice"], command, prepared)
        check(value["access"] == approved["access"], "restart lost exact approved history")
        data = key_body(f["pb"], net, f["alice"])
        if command == "prepare":
            data["inspection_review_id"] = prepared["access"]["review"]["inspection_review_id"]
        elif command == "approve":
            data.update(access_id=prepared["access"]["access_id"], access_review_id=prepared["access"]["review_id"])
        result = h.cli("onboarding", "access", command, "--stdin", input=compact(data).decode(), timeout=8)
        check(result.ok and result.json["access"] == approved["access"], "restarted exact private CLI history parity")
        validate(h, f["pb"], result.json, expected=prepared)
        public(result.stderr)
    pending_after = op(h, pending_parent, net, f["alice"], "lookup")
    check(pending_after["access"]["review"] == pending["access"]["review"] and pending_after["access"]["state"] == "invalidated",
          "restarted unapproved history refreshed or inferred consent")
    check(whole(f) == before, "historical API/CLI changed aggregate schemas/DB/state/home on either host")
    check(traffic(f) == counters, "historical API/CLI used either original TCP or any enabled UDP path")
    check(intent(h, prepared["access"]["access_id"]) == original_record and
          intent(h, prepared["access"]["review"]["intent_id"]) == action_record, "historical replay changed exact approved_at/template/signature/action bytes")
    if "external" in f:
        parent, external, external_approved = f["external"]
        check(get(f["a"], f"/v2/networks/{net}")["provider_state"]["state"] == "unavailable", "history fixture unexpectedly acquired original signer")
        for command in ("lookup", "prepare", "approve"):
            check(pure(f, f["a"], parent, f["bob"], command, external)["access"] == external_approved["access"],
                  "absent signer or elapsed window changed approved original consent")


@suite.case("strict_private_input_cli_routers_schema_nonsigning_kind_and_corruption_fail_closed", "guided31 verification6")
def _():
    f, prepared = main_prepared()
    h, parent, net = f["b"], f["pb"], f["net"]
    if "approved" not in f:
        f["approved"] = op(h, parent, net, f["alice"], "approve", prepared)
    approved = f["approved"]
    stable(f)
    before, counters = whole(f), traffic(f)
    for command in ("lookup", "prepare", "approve"):
        data = key_body(parent, net, f["alice"])
        if command == "prepare":
            data["inspection_review_id"] = prepared["access"]["review"]["inspection_review_id"]
        elif command == "approve":
            data.update(access_id=prepared["access"]["access_id"], access_review_id=prepared["access"]["review_id"])
        encoded = compact(data)
        maximum = b" " * (65536 - len(encoded)) + encoded
        status, value = raw(h, command, maximum)
        check(status == 200 and value["access"] == approved["access"], "exact64KiB valid historical API body")
        result = h.cli("onboarding", "access", command, "--stdin", input=maximum.decode(), timeout=8)
        check(result.ok and result.json["access"] == approved["access"], "exact64KiB private CLI parity")
        malformed = [b"null", b"[]", b"{", b"\xff", encoded + b"{}", maximum + b" ",
            encoded.replace(b'"context":', b'"context":null,"context":', 1),
            encoded.replace(b'"integration":', b'"integration":"claude-code","integration":', 1)]
        for key in data:
            malformed += [compact({k: v for k, v in data.items() if k != key}),
                          compact({**data, key: None}), compact({**data, key: 12})]
        for key in data["context"]:
            malformed += [compact({**data, "context": {k: v for k, v in data["context"].items() if k != key}}),
                          compact({**data, "context": {**data["context"], key: None}}),
                          compact({**data, "context": {**data["context"], key: 12}})]
        malformed += [compact({**data, "person_public_key": "bad"}),
                      compact({**data, "person_public_key": base64.b64encode(b"\xff" * 32).decode()}),
                      compact({**data, "context": {**data["context"], "extra": "PRIVATE_INPUT"}})]
        for key in ("provider_id", "signature_format", "approve", "scope", "key_file", "invitation", "template", "payload_base64"):
            malformed.append(compact({**data, key: "PRIVATE_INPUT"}))
        if command == "prepare":
            malformed += [compact({**data, "replace_access_id": None}), compact({**data, "replace_access_id": "dint_bad"})]
        for n, invalid in enumerate(malformed):
            status, denied = raw(h, command, invalid)
            check(status == 400 and isinstance(denied, dict) and denied.get("code") == "invalid", f"closed {command} variant{n}: HTTP {status}")
            public(denied, "PRIVATE_INPUT", data["context"]["project_root"], data["context"]["native_session_id"])
            result = h.cli("onboarding", "access", command, "--stdin", input=invalid.decode(errors="replace"), timeout=8)
            check(not result.ok, f"private CLI accepted closed {command} variant{n}")
            public(result.stdout + result.stderr, "PRIVATE_INPUT", data["context"]["project_root"], data["context"]["native_session_id"], str(h.state))
        for args in ((), ("--approve", "--stdin"), ("--person-key", "PRIVATE_INPUT", "--stdin"), (encoded.decode(),)):
            result = h.cli("onboarding", "access", command, *args, input=encoded.decode(), timeout=8)
            check(not result.ok, "CLI accepted implicit stdin, argv payload or signer override")
            public(result.stdout + result.stderr, "PRIVATE_INPUT", data["context"]["project_root"], data["context"]["native_session_id"])
        for argv in (("onboarding", "--state", str(h.state), "access", command),
                     ("onboarding", "access", "--state", str(h.state), command),
                     ("onboarding", "access", command, "--state", str(h.state))):
            result = subprocess.run([str(suite.host_bin), *argv, encoded.decode()], capture_output=True, env=h.env, cwd=h.root, timeout=8)
            check(result.returncode != 0, "interleaved global flags accepted private argv payload")
            public((result.stdout + result.stderr).decode(errors="replace"), encoded.decode(), data["context"]["project_root"], data["context"]["native_session_id"])
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            status, denied = h.api(method, BASE + "/" + command, data, timeout=8)
            check(status == 405, f"unsupported {command} method HTTP {status}")
            public(denied)
    check(whole(f) == before and traffic(f) == counters, "invalid input/method/CLI changed whole DB/files or any carrier")
    # A valid adapter credential and genuine mutually authenticated peer cannot
    # reach owner-local receipt preparation or approval.
    attached = project(h, "router")
    credential = h.ok("adapter", "create", "--session", attached["review"]["session_id"], "--expires-at", rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, attached["review"]["agent"], attached["review"]["session_id"], credential)
    check(adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id,
        "session_id": adapter.session_id, "instance_id": adapter.instance})[0] == 200, "genuine bounded scoped adapter setup")
    cert, key = suite.work / "consent-boundary-cert.pem", suite.work / "consent-boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    for command in ("lookup", "prepare", "approve"):
        data = key_body(parent, net, f["alice"])
        if command == "prepare":
            data["inspection_review_id"] = prepared["access"]["review"]["inspection_review_id"]
        elif command == "approve":
            data.update(access_id=prepared["access"]["access_id"], access_review_id=prepared["access"]["review_id"])
        endpoint = BASE + "/" + command
        status, denied = adapter.call("POST", endpoint, data)
        check(status == 404, "scoped adapter exposed owner-local access consent")
        public(denied, adapter.token, adapter.instance)
        result = subprocess.run([str(suite.probe_bin), "--state", str(f["a"].state), "--address", peer_address(h),
            "--alpn", "peerspan-peer/1", "--path", endpoint, "--method", "POST", "--body-stdin"],
            input=compact(data), capture_output=True, timeout=15)
        check(result.returncode == 0 and json.loads(result.stdout).get("status") == 404, "authenticated normal peer exposed access consent")
        public(result.stderr.decode(errors="replace"))
        encoded = compact(data)
        address, port = h.relay.address.split(":")
        with socket.create_connection((address, int(port)), timeout=5) as connection:
            with tls.wrap_socket(connection, server_hostname="peerspan") as stream:
                stream.sendall((f"POST {endpoint} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n").encode() + encoded)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, "bootstrap router exposed access consent")
    # Receipt IDs cannot be used as a provider or as the ordinary action's
    # signing-intent reference, even though both are real retained local IDs.
    stable(f)
    before, counters = whole(f), traffic(f)
    status, denied = h.api("POST", f"/v2/networks/{net}/provider", {"provider_id": prepared["access"]["access_id"],
        "person_public_key": f["bob"], "host_public_key": h.public_key, "approve": False}, timeout=8)
    check(status == 400, "nonsigning receipt became an owner provider")
    public(denied)
    status, denied = h.api("POST", f"/v2/networks/{net}/actions/{prepared['access']['review']['action_id']}/signed", {
        "intent_id": prepared["access"]["access_id"], "signatures": [{"slot_id": 1, "role": "issuer", "signature": base64.b64encode(bytes(64)).decode()}]}, timeout=8)
    check(not 200 <= status < 300, "nonsigning receipt reached ordinary action signature submission")
    public(denied)
    check(whole(f) == before and traffic(f) == counters, "nonsigning-route refusal mutated metadata, clock, signature or carrier")
    check(records(h)["$schema"] == f["schema"] and records(h)["$version"] == (27,), "new access metadata changed schema27 SQL/version")
    absent = suite.host("absent", start=False)
    shutil.rmtree(absent.state)
    before = files(absent.root)
    for command in ("lookup", "prepare", "approve"):
        data = key_body(parent, net, f["alice"])
        if command == "prepare":
            data["inspection_review_id"] = prepared["access"]["review"]["inspection_review_id"]
        elif command == "approve":
            data.update(access_id=prepared["access"]["access_id"], access_review_id=prepared["access"]["review_id"])
        result = absent.cli("onboarding", "access", command, "--stdin", input=compact(data).decode(), timeout=8)
        check(not result.ok and files(absent.root) == before and not absent.state.exists(), "private CLI initialized missing daemon state")
        public(result.stdout + result.stderr, data["context"]["project_root"], data["context"]["native_session_id"], str(absent.state))
    # Offline corruption is limited to one nonsigning duplicated host field;
    # restore the genuine original Record bytes in finally, never fabricate a
    # valid receipt, action/template, signature, provider, seed or authority.
    iid = prepared["access"]["access_id"]
    database = db_path(h)
    h.stop(kill=True)
    with closing(sqlite3.connect(database)) as db, db:
        original = db.execute("SELECT record FROM dec_intents WHERE intent_id=?", (iid,)).fetchone()[0]
        corrupt = json.loads(original); corrupt["host_public_key"] = f["a"].public_key
        db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (compact(corrupt).decode(), iid))
    try:
        h.start()
        directory(f)
        pure(f, h, parent, f["alice"], "lookup", status=409, code="access_review_unavailable")
        pure(f, h, parent, f["alice"], "approve", prepared, status=409, code="access_review_unavailable")
    finally:
        h.stop(kill=True)
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (original, iid))
    # A canonical absent ordinary-action reference is corrupt retained metadata,
    # unlike a caller's unknown access ID. Edit only this genuine receipt and
    # restore its exact original bytes; never manufacture the referenced action.
    missing_action_intent = "dint_" + "f" * 32
    with closing(sqlite3.connect(database)) as db, db:
        check(db.execute("SELECT record FROM dec_intents WHERE intent_id=?", (iid,)).fetchone()[0] == original,
              "earlier receipt fault was not restored byte-for-byte")
        check(db.execute("SELECT 1 FROM dec_intents WHERE intent_id=?", (missing_action_intent,)).fetchone() is None,
              "broken-reference fixture does not name an actually absent intent")
        corrupt = json.loads(original)
        corrupt_review = json.loads(base64.b64decode(corrupt["review_base64"], validate=True))
        corrupt_review["intent_id"] = missing_action_intent
        corrupt["review_base64"] = base64.b64encode(canonical(corrupt_review)).decode()
        db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (compact(corrupt).decode(), iid))
    try:
        h.start()
        directory(f)
        pure(f, h, parent, f["alice"], "lookup", status=409, code="access_review_unavailable")
        pure(f, h, parent, f["alice"], "approve", prepared, status=409, code="access_review_unavailable")
    finally:
        h.stop(kill=True)
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (original, iid))
    print("LIMIT unexecuted_bounds: aggregate256/16MiB receipts,4096 intents,64 unsigned actions,1MiB valid output and deterministic first-action collision not constructed", flush=True)
    print("LIMIT unsafe_projection: no genuine section30 digest for an unsafe/oversized public review; strict private-input refusal is exercised instead", flush=True)


suite.finish()
