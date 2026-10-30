#!/usr/bin/env python3
"""Exact signed project-policy local application, guided section33.

Independent contract-only six-case real-binary suite. A genuine two-person,
two-host public ceremony supplies selected device/original policy authority,
project consent and actual issuer signatures. All original TCP and every
advertised/configured UDP path are counted. Real invitation/request expiry,
ordinary unsigned create/cancel maintenance, actual empty queues/journals and
observed ordinary directory results precede strict whole-state/carrier proofs.
Those observations are not a global transport fence; any failure remains real.
Prior PR79 UDP/contact failure causes remain unclassified.

Only schema-only late ABORT and restored negative offline faults of genuine
result/signature/proof/admission records mutate SQLite. No authority/provider/
seed/template/queue or valid protocol state is fabricated. Existing27 suites,
helpers, harness and native sources remain byte-exact.

Source/manual limits: complex fork/incomplete/sibling-unsettled ancestry,
independent root/member/lease mutation, quota/u64/edit exhaustion, full90s
server timeout/cancellation and deterministically held overlapping transactions
and genuine oversized/unsafe retained projections are not constructed.
Concurrent actual calls and a lost real response exercise
idempotence, not a forced internal commit boundary. Directory enforcement is
ordinary authorization evidence, not observed model delivery/readiness. No
installed/physical/model/full-state-upgrade acceptance is inferred.
"""
import atexit
import base64
import copy
import hashlib
import http.client
import http.server
import json
import math
import os
import re
import select
import shutil
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, join_new_person,
                     parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for)
from counted_peer import CountedUDP, exchange_current_contacts, peer_address

suite = Suite("access_application", __doc__)
BASE = "/v1/onboarding/access-consent"
INSPECT = "/v1/onboarding/access-inspection"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ("psi2-", "psl2-", "peerspan-invite-v1.", "peerspan-member-invite-v1.",
            "peerspan-person-invite-v1.", "token_", "instance_")
TOP = set("version host_id context observed_at access application".split())
APPLICATION = set("state action_id intent_id statement_id proof_id peer_delivery connection_readiness".split())
PHASES = {"pure_application", "pure_apply", "input_refusal", "missing_daemon", "signature_setup",
          "application_rollback", "history", "record_corruption", "concurrent_recovery", "lost_recovery"}
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
                                "signing_requests", "statement_base64", '"catalog"', "result_base64", "return_secret", '"signature"', '"seed"',
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
    return {"network_id": row[0], "context_id": row[1], "kind": row[2], "record": json.loads(row[3]),
            "record_text": row[3], "secret": row[4]}



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



def purity_file_categories(actual, expected):
    """Project only already captured entry counts, never names/modes/hashes."""
    changed = [name for name in set(expected) | set(actual) if expected.get(name) != actual.get(name)]
    result = {"before_count": len(expected), "after_count": len(actual), "changed_count": len(changed),
              "added_count": len(set(actual) - set(expected)), "removed_count": len(set(expected) - set(actual)),
              "file_count": 0, "directory_count": 0, "socket_count": 0, "other_count": 0}
    for name in changed:
        mode = (actual.get(name) or expected[name])[0] & 0o170000
        category = {0o100000: "file_count", 0o040000: "directory_count", 0o140000: "socket_count"}.get(mode, "other_count")
        result[category] += 1
    return result



def purity_snapshot_diagnostic(actual, expected, phase, participant):
    """Failure only: return the original captured snapshot without extra IO."""
    try:
        if actual != expected:
            phases = PHASES
            changed = [name for name in sorted(set(expected[0]) | set(actual[0]))
                       if expected[0].get(name) != actual[0].get(name)]
            summary = {"phase": phase if phase in phases else "unknown", "category": "snapshot",
                       "participant": participant if participant in {"alice", "bob"} else "unknown",
                       "changed_table_count": len(changed), "changed_tables": []}
            for name in changed[:128]:
                summary["changed_tables"].append({"name": name if name in {"$schema", "$version"}
                    or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) else "unknown",
                    "before_count": len(expected[0].get(name, ())), "after_count": len(actual[0].get(name, ()))})
            summary["state_entries"] = purity_file_categories(actual[1], expected[1])
            summary["home_entries"] = purity_file_categories(actual[2], expected[2])
            print("access_purity_failure_public=" + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # Diagnostics cannot replace the original complete verdict.
    return actual



def purity_whole_diagnostic(actual, expected, phase):
    """Both existing participant captures; preserve their original comparison."""
    try:
        if actual != expected:
            for index, participant in enumerate(("alice", "bob")):
                purity_snapshot_diagnostic(actual[index], expected[index], phase, participant)
    except Exception:
        pass
    return actual



def purity_missing_files_diagnostic(actual, expected):
    """The original absent-daemon file capture, without exposing its root."""
    try:
        if actual != expected:
            print("access_purity_failure_public=" + json.dumps({"phase": "missing_daemon", "category": "files",
                "participant": "absent", "root_entries": purity_file_categories(actual, expected)}, sort_keys=True), flush=True)
    except Exception:
        pass
    return actual



def purity_traffic_diagnostic(actual, expected, phase):
    """Every captured TCP/UDP counter delta, with no reset or carrier filter."""
    try:
        if actual != expected:
            phases = PHASES
            summary = {"phase": phase if phase in phases else "unknown", "category": "carriers", "carriers": []}
            for index, participant, kind in ((0, "alice", "tcp"), (1, "bob", "tcp"), (2, "alice", "udp"), (3, "bob", "udp")):
                fields = ("connections", "received_bytes") if kind == "tcp" else (
                    "received_datagrams", "received_bytes", "returned_datagrams", "returned_bytes")
                summary["carriers"].append({"participant": participant, "kind": kind,
                    "deltas": {field: actual[index][column] - expected[index][column] for column, field in enumerate(fields)}})
            print("access_purity_failure_public=" + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass
    return actual



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



def assert_only(before, after, tables):
    check(before[1:] == after[1:], "consent changed state/home file paths, modes or bytes")
    check({k: v for k, v in before[0].items() if k not in tables} ==
          {k: v for k, v in after[0].items() if k not in tables}, "consent changed unrelated table/schema/version rows")



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



def ssh_string(value):
    return struct.pack(">I", len(value)) + value



def host(name, *, owner=False):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    h.owner_key = ssh_key(h.root, "owner") if owner else h.root / "absent-owner"
    h.relay = Relay(("127.0.0.1", h.bootstrap_port))
    h.counted_peer = CountedUDP(("127.0.0.1", h.peer_port))
    config = h.root / "transport.json"
    config.write_bytes(compact({"format": 1, "advertise_bootstrap": [h.relay.address],
        "advertise_quic": [h.counted_peer.address], "rendezvous": [], "relays": [], "publish_contacts": False}))
    config.chmod(0o600)
    h.extra_args = ["--transport-config", config, "--person-key-file", h.owner_key]
    h.extra_env = {"SSH_AUTH_SOCK": str(h.root / "absent-agent")}
    return h.start()



def world():
    if state:
        check("pa" in state, "shared genuine fixture setup did not complete")
        return state
    state["building"] = True
    a, b = host("a", owner=True), host("b")
    net = a.ok("network", "create", "Application 東京", "--as", "alice", "--person-key-file", a.owner_key)
    check(net["mode"] == "decentralized" and net["person_public_key"] == ssh_public_base64(a.owner_key), "exact original network creation prerequisite")
    key = ssh_key(b.root, "bob")
    rid = join_new_person(a, b, "bob", key, net["id"])
    for local, remote in ((a, b), (b, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", peer_address(remote))
    exchange_current_contacts(suite, a, b, net["id"])
    bounds = []
    for local in (a, b):
        with closing(sqlite3.connect(f"file:{db_path(local)}?mode=ro", uri=True)) as db:
            bounds.extend(row[0] for row in db.execute("SELECT deadline FROM dec_pending WHERE request_id LIKE 'di_%'"))
    check(bounds, "actual invitation retirement deadlines missing")
    state.update(a=a, b=b, net=net["id"], alice=net["person_public_key"], bob=ssh_public_base64(key), key=key,
                 invitation_bounds=bounds, request_deadline=get(b, "/v2/link/requests/" + rid)["expires_at"])
    retire(state)
    creator = next(member for member in get(a, "/v2/networks/" + state["net"] + "/members")["members"] if member["host_public_key"] == a.public_key)
    check(creator["device_lease_id"] != "-", "genuine creator owned-device lease is absent")
    creator_provider = select_provider(a, state["net"], state["alice"], creator["device_lease_id"])
    check(creator_provider["kind"] == "device", "ordinary creator-device selection prerequisite")
    for local in (a, b):
        local.ok("allow", "everyone", "--network", state["net"], "--agent", "setup-only")
    state.update(pa=project(a, "a"), pb=project(b, "b"),
                 alice_device=creator_provider,
                 bob_device=get(b, "/v2/networks/" + state["net"])["provider"])
    check(state["bob_device"]["kind"] == "device", "joined owner lacks genuine selected scope1 device")
    directory(state); stable(state)
    state["schema"] = records(b)["$schema"]
    return state



def selected_person(f, h):
    return f["alice"] if h is f["b"] else f["bob"]



def consent(f, h, name, *, approve=True, parent=None):
    parent = parent or project(h, name)
    person = selected_person(f, h)
    inspected = inspection(h, parent, f["net"], person)
    status, prepared = h.api("POST", BASE + "/prepare", {**key_body(parent, f["net"], person),
        "inspection_review_id": inspected["review_id"]}, timeout=8)
    check(status == 200 and set(prepared) == TOP - {"application"} and prepared["access"]["state"] == "review", "genuine section31 unsigned consent prerequisite")
    access, review = prepared["access"], prepared["access"]["review"]
    check(review["inspection"] == inspected["review"] and access["review_id"] == "review_" + hashlib.sha256(
        b"peerspan-project-access-consent-v1\n" + canonical(review)).hexdigest(), "exact complete approved-review prerequisite")
    if approve:
        status, approved = h.api("POST", BASE + "/approve", {**key_body(parent, f["net"], person),
            "access_id": access["access_id"], "access_review_id": access["review_id"]}, timeout=8)
        check(status == 200 and set(approved) == TOP - {"application"} and approved["access"]["state"] == "approved"
              and approved["access"]["review"] == review, "genuine exact guided and ordinary approval prerequisite")
        prepared = approved
    return parent, prepared



def policy_message(h, prepared):
    _, envelope, _, _ = unsigned(h, prepared)
    check(len(envelope["signatures"]) == 1, "ordinary policy template is not exactly one issuer slot")
    declared = envelope["signatures"][0]
    check(declared["role"] == "issuer" and declared["signature"] == "-", "policy unsigned typed role changed")
    return "\n".join(("peerspan-decentralized-signature-v1", statement_id(envelope), "issuer", declared["public_key"])).encode(), declared



def verify_policy_signature(h, prepared):
    message, declared = policy_message(h, prepared)
    record = intent(h, prepared["access"]["review"]["intent_id"])["record"]
    check(record["signatures"] and len(record["signatures"]) == 1 and record["completed"] is True, "missing exact completed issuer signature")
    signature = record["signatures"][0]
    check(set(signature) == {"slot_id", "role", "signature"} and signature["slot_id"] == 1 and signature["role"] == "issuer", "wrong policy slot/role")
    stem = suite.work / "verify-policy"
    if declared["format"] == "ed25519":
        key = base64.b64decode(declared["public_key"], validate=True)
        stem.with_suffix(".der").write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
        stem.with_suffix(".sig").write_bytes(base64.b64decode(signature["signature"], validate=True))
        stem.with_suffix(".msg").write_bytes(message)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(stem.with_suffix(".der")),
            "-rawin", "-in", str(stem.with_suffix(".msg")), "-sigfile", str(stem.with_suffix(".sig"))], capture_output=True, timeout=5)
    else:
        check(declared["format"] == "sshsig", "wrong original fixed signature format")
        blob = ssh_string(b"ssh-ed25519") + ssh_string(base64.b64decode(declared["public_key"], validate=True))
        stem.with_suffix(".allowed").write_text("fixture ssh-ed25519 " + base64.b64encode(blob).decode() + "\n")
        text = signature["signature"]
        stem.with_suffix(".sig").write_text("-----BEGIN SSH SIGNATURE-----\n" + "\n".join(text[n:n + 70] for n in range(0, len(text), 70)) + "\n-----END SSH SIGNATURE-----\n")
        result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(stem.with_suffix(".allowed")), "-I", "fixture",
            "-n", "peerspan-person-v1", "-s", str(stem.with_suffix(".sig"))], input=message, capture_output=True, timeout=5)
    check(result.returncode == 0, "external crypto verification over actual frozen policy message failed")
    return signature



def assert_signature_write(h, prepared, before, after):
    assert_only(before, after, {"dec_intents", "dec_clock"})
    old, new = {row[0]: row for row in before[0]["dec_intents"]}, {row[0]: row for row in after[0]["dec_intents"]}
    iid = prepared["access"]["review"]["intent_id"]
    check(set(old) == set(new), "signing inserted/deleted an intent or receipt")
    for key in old:
        if key != iid:
            check(old[key] == new[key], "signing changed receipt or unrelated intent bytes")
            continue
        check(old[key][:4] == new[key][:4] and old[key][5:] == new[key][5:], "signing changed action identity/kind/secret")
        original, current = json.loads(old[key][4]), json.loads(new[key][4])
        check(original["signatures"] == [] and original["completed"] is False and current["completed"] is True
              and len(current["signatures"]) == 1 and {k: v for k, v in original.items() if k not in {"signatures", "completed"}}
              == {k: v for k, v in current.items() if k not in {"signatures", "completed"}},
              "signature write changed approval/time/template/review/provider/payload")
    verify_policy_signature(h, prepared)


def application_input(f, h, parent, prepared, *, apply=False):
    data = {**key_body(parent, f["net"], selected_person(f, h)),
            "access_id": prepared["access"]["access_id"],
            "access_review_id": prepared["access"]["review_id"]}
    if apply:
        data["decision"] = "apply_project_agent_access"
    return data


def proof_id(kind, body):
    return "dp_" + hashlib.sha256(("peerspan-decentralized-proof-v1\n" + kind + "\n" +
                                   hashlib.sha256(body).hexdigest()).encode()).hexdigest()


def applied_evidence(h, prepared):
    """Verify actual retained action/result/proof/admission, never mint evidence."""
    action, template, raw_payload, payload = unsigned(h, prepared)
    record = action["record"]; review = prepared["access"]["review"]
    check(record["terminal"] == "applied" and record["completed"] is True and len(record["signatures"]) == 1,
          "ordinary applied action lacks its completed exact issuer signature")
    verify_policy_signature(h, prepared)
    result = json.loads(base64.b64decode(record["result_base64"], validate=True))
    check(set(result) == set("action_id review signing_requests statement_base64 proof_id catalog committed delivery".split())
          and result["action_id"] == review["action_id"] and result["committed"] is True
          and result["signing_requests"] == [], "ordinary durable result is not exactly the applied reviewed action")
    raw_statement = base64.b64decode(result["statement_base64"], validate=True)
    envelope = json.loads(raw_statement)
    signature = record["signatures"][0]
    expected = copy.deepcopy(template); expected["signatures"][0]["signature"] = signature["signature"]
    check(envelope == expected and base64.b64decode(envelope["payload_base64"], validate=True) == raw_payload
          and statement_id(envelope) == review["statement"]["id"]
          and result["proof_id"] == proof_id("policy", raw_statement),
          "application substituted signed payload/slot/key/format or exact envelope proof ID")
    catalog = result["catalog"]
    check(isinstance(catalog, dict) and catalog["context_id"] == action["context_id"]
          and any(item == {"id": result["proof_id"], "kind": "policy", "body_base64": result["statement_base64"]}
                  for item in catalog["objects"]), "ordinary result omits its exact signed policy proof")
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        stored = db.execute("SELECT kind,body FROM dec_objects WHERE network_id=? AND context_id=? AND proof_id=?",
                            (action["network_id"], action["context_id"], result["proof_id"])).fetchone()
        admitted = db.execute("SELECT record FROM dec_admissions WHERE network_id=? AND context_id=? AND statement_id=?",
                              (action["network_id"], action["context_id"], review["statement"]["id"])).fetchone()
    check(stored == ("policy", raw_statement) and admitted is not None,
          "application lacks exact ordinary local proof/admission evidence")
    admission = json.loads(admitted[0])
    check(admission["kind"] == "policy" and admission["proof_id"] == result["proof_id"]
          and admission["basis"]["kind"] == "current", "applied policy has no verified current ordinary admission basis")
    ordinary = get(h, f"/v2/networks/{action['network_id']}/actions/{review['action_id']}")
    check(ordinary == result, "completed ordinary GET changed the retained exact action result")
    return result


def application_view(h, parent, prepared, value):
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1
          and value["host_id"] == h.id and value["context"] == context(parent)
          and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]),
          "closed exact canonical application observation")
    access = value["access"]; review = prepared["access"]["review"]
    check(type(access) is dict and set(access) == {"access_id", "review_id", "review", "state", "next_action"}
          and access["access_id"] == prepared["access"]["access_id"]
          and access["review_id"] == prepared["access"]["review_id"] and access["review"] == review,
          "application changed the complete immutable receipt/review/digest")
    receipt = intent(h, access["access_id"])
    action, _, _, _ = unsigned(h, prepared); record = action["record"]
    check(receipt["kind"] == "access_review" and receipt["secret"] is None
          and receipt["record"]["templates"] == receipt["record"]["signatures"] == []
          and receipt["record"]["completed"] is True and receipt["record"]["terminal"] == "-"
          and receipt["record"]["result_base64"] == "-"
          and base64.b64decode(receipt["record"]["review_base64"], validate=True) == canonical(review),
          "nonsigning human receipt became an application/signing record")
    if not receipt["record"]["approved"]:
        check(value["application"] is None and access["state"] != "approved",
              "unapproved or advanced-only ordinary work inferred guided application consent")
    else:
        check(record["approved"] is True and record["approved_at"] == receipt["record"]["approved_at"]
              and access["state"] == "approved", "application lost matching exact dual approvals")
        applied = record["terminal"] == "applied"
        signed = len(record["signatures"]) == 1
        check(type(record["signatures"]) is list and len(record["signatures"]) in {0, 1}
              and type(record["completed"]) is bool and record["completed"] == signed,
              "application observation changed exact sole typed-slot completion")
        marker = value["application"]
        check(type(marker) is dict and set(marker) == APPLICATION
              and marker["state"] == ("locally_applied" if applied else "signed" if signed else "unsigned")
              and marker["action_id"] == review["action_id"] and marker["intent_id"] == review["intent_id"]
              and marker["statement_id"] == review["statement"]["id"]
              and marker["peer_delivery"] == marker["connection_readiness"] == "not_verified",
              "application marker changed identity/state or claimed delivery/readiness")
        check((signed and type(marker["proof_id"]) is str and re.fullmatch(r"dp_[0-9a-f]{64}", marker["proof_id"]))
              or (not signed and marker["proof_id"] == "-"), "unsigned/signed exact proof marker")
        if applied:
            check(marker["proof_id"] == applied_evidence(h, prepared)["proof_id"], "marker differs from exact admitted proof")
    check(len(compact(value)) <= 1048576, "application response exceeds closed1MiB bound")
    public(value, str(h.root))


def operation(f, h, parent, prepared, action="application", *, status=200, code=None, override=None):
    data = application_input(f, h, parent, prepared, apply=action == "apply") if override is None else override
    actual, value = h.api("POST", BASE + "/" + action, data, timeout=95 if action == "apply" else 8)
    check(actual == status, f"access {action} HTTP{actual}, want{status}")
    if actual == 200:
        application_view(h, parent, prepared, value)
    else:
        check(type(value) is dict and value.get("code") == code and not ({"access", "review", "application"} & set(value)),
              f"access {action} did not return closed {code}")
        public(value)
    return value


def strict_unchanged(f, before, counters, phase):
    check(purity_whole_diagnostic(whole(f), before, phase) == before, "application changed whole schemas/DB/state/home")
    check(purity_traffic_diagnostic(traffic(f), counters, phase) == counters, "application used original TCP or an enabled UDP path")


def pure(f, h, parent, prepared, action="application", **options):
    stable(f); before, counters = whole(f), traffic(f)
    value = operation(f, h, parent, prepared, action, **options)
    strict_unchanged(f, before, counters, "pure_" + action)
    return value


def signed(f, h, name, *, parent=None, prepared=None):
    if prepared is None:
        parent, prepared = consent(f, h, name, parent=parent)
    check(parent is not None, "signature setup lacks its exact attached project")
    stable(f); before, remote, counters = snapshot(h), snapshot(f["a"] if h is f["b"] else f["b"]), traffic(f)
    data = {**application_input(f, h, parent, prepared), "decision": "sign_project_agent_access"}
    status, value = h.api("POST", BASE + "/sign", data, timeout=95)
    check(status == 200 and value["access"] == prepared["access"] and value["signing"]["state"] == "signed",
          "genuine exact section32 stored issuer signature prerequisite")
    assert_signature_write(h, prepared, before, snapshot(h))
    other = f["a"] if h is f["b"] else f["b"]
    check(purity_snapshot_diagnostic(snapshot(other), remote, "signature_setup", "alice" if other is f["a"] else "bob") == remote,
          "signature setup mutated the remote participant")
    check(purity_traffic_diagnostic(traffic(f), counters, "signature_setup") == counters,
          "signature storage published before explicit application")
    return parent, prepared


def action_events(h):
    return [event for event in get(h, "/v1/activity?limit=1000") if event["kind"] == "network.action_applied"]


def assert_application(h, prepared, before_action, before_receipt, previous_events):
    review = prepared["access"]["review"]
    action = intent(h, review["intent_id"])
    check(intent(h, prepared["access"]["access_id"]) == before_receipt, "application changed human receipt/approval/review bytes")
    check({k: v for k, v in action["record"].items() if k not in {"terminal", "result_base64"}} ==
          {k: v for k, v in before_action["record"].items() if k not in {"terminal", "result_base64"}},
          "application refreshed signature/provider/payload/approval/template/time")
    result = applied_evidence(h, prepared)
    check(len(action_events(h)) == previous_events + 1, "application emitted missing/duplicate ordinary action event")
    current = current_policy(h, action["network_id"], action["record"]["person_public_key"])
    check(current is not None and current[0]["statement_id"] == review["statement"]["id"]
          and current[0]["statement_base64"] == result["statement_base64"]
          and current[3] == review["statement"]["payload"]["body"], "ordinary current policy did not enforce exact reviewed body")
    own_edit = next(edit for edit in current[3]["edits"] if edit["host"] == h.id)
    edits = get(h, f"/v2/networks/{action['network_id']}/policy-edits")["edits"]
    check(any(edit["seq"] == own_edit["seq"] and edit["state"] == "settled"
              and edit["signed_version"] == current[3]["version"] for edit in edits), "ordinary exact local edit did not settle")
    return result


def peer_agents(f, source, target):
    result = subprocess.run([str(suite.probe_bin), "--state", str(source.state), "--address", peer_address(target),
        "--alpn", "peerspan-peer/1", "--path", f"/peer/v1/networks/{f['net']}/agents", "--method", "GET"],
        capture_output=True, timeout=15)
    check(result.returncode == 0, "genuine authenticated ordinary evaluator transport failed")
    response = json.loads(result.stdout)
    check(response["status"] == 200 and isinstance(response["body"], list), "ordinary peer permission projection failed")
    return response["body"]


def fault_startup_observed(f):
    """Observe actual bounded startup work, including truthful corrupt-state errors."""
    for local, remote in ((f["a"], f["b"]), (f["b"], f["a"])):
        status, value = local.api("POST", "/v1/directory/refresh?network=" + f["net"], {}, timeout=12)
        check(status == 200 and isinstance(value, dict) and value.get("network_id") == f["net"],
              "negative-state startup observation changed selected network")
        known = [host for host in value["hosts"] if host["host_id"] == remote.id]
        check(len(known) == 1 and known[0]["state"] in {"ok", "error", "unsupported"},
              "negative-state startup work has no completed truthful observation")


@suite.case("exact_dual_approval_signature_local_proof_edit_event_and_ordinary_enforcement", "guided33 verification1")
def _():
    f = world(); h = f["b"]
    parent, prepared = consent(f, h, "main", approve=False, parent=f["pb"])
    check(pure(f, h, parent, prepared)["application"] is None, "unapproved receipt acquired application state")
    pure(f, h, parent, prepared, "apply", status=409, code="review_changed")
    parent, prepared = consent(f, h, "main", parent=parent)
    check(pure(f, h, parent, prepared)["application"]["state"] == "unsigned", "approved unsigned observation signed/applied")
    pure(f, h, parent, prepared, "apply", status=409, code="access_application_unavailable")
    name = prepared["access"]["review"]["grant"]["agent_name"]
    check(not any(entry["name"] == name for entry in peer_agents(f, f["a"], h)), "exact agent already authorized before reviewed application")
    parent, signed_review = signed(f, h, "main", parent=parent, prepared=prepared)
    check(signed_review == prepared, "signature preparation replaced exact human receipt")
    marker = pure(f, h, parent, prepared)["application"]
    check(marker["state"] == "signed", "genuine stored signature missing from pure application marker")
    old_action = intent(h, prepared["access"]["review"]["intent_id"])
    old_receipt = intent(h, prepared["access"]["access_id"])
    old_events = len(action_events(h)); old_files = snapshot(h)[1:]
    membership = get(h, f"/v2/networks/{f['net']}/members")["members"]
    applied = operation(f, h, parent, prepared, "apply")
    check(applied["application"] == {**marker, "state": "locally_applied"}, "explicit apply changed exact signed identity/proof")
    result = assert_application(h, prepared, old_action, old_receipt, old_events)
    check(snapshot(h)[1:] == old_files and records(h)["$schema"] == f["schema"] and records(h)["$version"] == (27,),
          "application created schema/key/private file state")
    check(get(h, f"/v2/networks/{f['net']}/members")["members"] == membership, "agent policy application changed network membership")
    entries = [entry for entry in peer_agents(f, f["a"], h) if entry["name"] == name]
    check(len(entries) == 1 and entries[0]["agent_id"] == parent["review"]["agent"]["id"], "ordinary evaluator omitted/substituted reviewed target agent")
    policies = [auth for auth in entries[0]["authorizations"] if auth["kind"] == "policy"]
    check(len(policies) == 1 and policies[0]["actions"] == ["message.append", "task.submit"]
          and policies[0]["max_message_bytes"] == 65536 and policies[0]["max_artifact_bytes"] == 0
          and all("task.delegate" not in auth["actions"] for auth in entries[0]["authorizations"]),
          "ordinary local evaluator widened the exact narrow reviewed access profile")
    stable(f)
    for command in ("application", "apply"):
        value = pure(f, h, parent, prepared, command)
        check(value["application"] == applied["application"], "applied API exact retry changed marker")
        before, counters = whole(f), traffic(f)
        cli = h.cli("onboarding", "access", command, "--stdin",
            input=compact(application_input(f, h, parent, prepared, apply=command == "apply")).decode(), timeout=95 if command == "apply" else 8)
        check(cli.ok and cli.json["application"] == applied["application"] and cli.json["access"] == applied["access"], "private CLI applied-state parity")
        application_view(h, parent, prepared, cli.json); public(cli.stderr)
        strict_unchanged(f, before, counters, "pure_" + command)
    check(len(action_events(h)) == old_events + 1, "exact replay emitted another event")
    f["applied"] = parent, prepared, applied
    f["main_proof"] = result["proof_id"]


@suite.case("missing_guided_or_signature_changed_exact_pins_real_provider_head_clock_and_expiry_refuse", "guided33 verification2")
def _():
    f = world(); h = f["b"]
    parent, unsigned_review = consent(f, h, "unsigned-history")
    pure(f, h, parent, unsigned_review, "apply", status=409, code="access_application_unavailable")
    f["unsigned"] = parent, unsigned_review
    a = f["a"]; select_provider(a, f["net"], f["alice"], f["alice"])
    advanced_parent, advanced = consent(f, a, "advanced", approve=False)
    _, _, payload, _ = unsigned(a, advanced)
    held = a.root / "advanced-original-held-away"; a.owner_key.rename(held)
    try:
        status, ordinary = a.api("POST", f"/v2/networks/{f['net']}/actions", {"kind": "policy", "provider_id": f["alice"],
            "signature_format": "sshsig", "payload_base64": base64.b64encode(payload).decode(), "approve": True}, timeout=8)
    finally:
        held.rename(a.owner_key)
    check(status == 200 and ordinary["action_id"] == advanced["access"]["review"]["action_id"]
          and ordinary["committed"] is False and ordinary["signing_requests"], "genuine advanced-only exact original approval prerequisite")
    observed = pure(f, a, advanced_parent, advanced)
    check(observed["access"]["state"] == "invalidated" and observed["application"] is None
          and intent(a, advanced["access"]["access_id"])["record"]["approved"] is False, "ordinary approval supplied guided human consent")
    pure(f, a, advanced_parent, advanced, "apply", status=409, code="review_changed")
    select_provider(a, f["net"], f["alice"], f["alice_device"]["lease_id"])
    parent, prepared = signed(f, h, "pins")
    data = application_input(f, h, parent, prepared, apply=True)
    for override, status, code in (({**data, "access_review_id": "review_" + "0" * 64}, 409, "review_changed"),
        ({**data, "person_public_key": f["bob"]}, 409, "review_changed"),
        ({**data, "context": {**data["context"], "project_review_id": "review_" + "0" * 64}}, 409, "review_changed"),
        ({**data, "context": {**data["context"], "project_root": str(suite.work / "wrong-project")}}, 409, "review_changed"),
        ({**data, "context": {**data["context"], "project_flow_id": "flow_" + "f" * 32}}, 404, "not_found"),
        ({**data, "network_id": "net_" + "f" * 64}, 404, "not_found")):
        pure(f, h, parent, prepared, "apply", override=override, status=status, code=code)
    offset = h.clock.offset
    h.clock.set(offset - 120)
    try:
        for command in ("application", "apply"):
            pure(f, h, parent, prepared, command, status=409, code="access_application_unavailable")
    finally:
        h.clock.set(offset)
    select_provider(h, f["net"], f["bob"], f["bob"])
    pure(f, h, parent, prepared, "apply", status=409, code="review_changed")
    check(pure(f, h, parent, prepared)["application"]["state"] == "signed", "provider change rewrote historical signed observation")
    select_provider(h, f["net"], f["bob"], f["bob_device"]["lease_id"])
    h.ok("allow", "alice", "--network", f["net"], "--agent", "genuine-head-change")
    directory(f)
    pure(f, h, parent, prepared, "apply", status=409, code="review_changed")
    inspected = inspection(h, parent, f["net"], f["alice"])
    status, successor = h.api("POST", BASE + "/prepare", {**key_body(parent, f["net"], f["alice"]),
        "inspection_review_id": inspected["review_id"], "replace_access_id": prepared["access"]["access_id"]}, timeout=8)
    check(status == 200 and successor["access"]["access_id"] != prepared["access"]["access_id"]
          and successor["access"]["review"]["replaces_access_id"] == prepared["access"]["access_id"],
          "genuine changed-head exact receipt replacement prerequisite")
    pure(f, h, parent, prepared, "apply", status=409, code="review_changed")
    h.ok("session", "detach", parent["review"]["session_id"])
    pure(f, h, parent, prepared, "apply", status=409, code="review_changed")
    check(pure(f, h, parent, prepared)["application"]["state"] == "signed", "detached signed history performed fresh validation")
    parent, elapsed = signed(f, h, "expired")
    target = parse_time(elapsed["access"]["review"]["expires_at"]) + timedelta(seconds=1)
    for local in (f["a"], f["b"]):
        local.clock.set(local.clock.offset + math.ceil((target - local.now()).total_seconds()))
    directory(f)
    pure(f, h, parent, elapsed, "apply", status=409, code="review_expired")
    check(pure(f, h, parent, elapsed)["application"]["state"] == "signed", "elapsed observation refreshed/applied signed work")
    f["elapsed"] = parent, elapsed
    print("LIMIT live_guards: complex root/member/lease fork/incomplete/sibling-unsettled paths and quota/u64/edit overflow lack genuine compact fixtures", flush=True)


@suite.case("late_ordinary_action_result_SQL_abort_rolls_back_all_publication_and_retains_signature", "guided33 verification3")
def _():
    f = world(); h = f["b"]; parent, prepared = signed(f, h, "rollback")
    iid = prepared["access"]["review"]["intent_id"]; schema = records(h)["$schema"]
    signature = verify_policy_signature(h, prepared)
    check(re.fullmatch(r"dint_[0-9a-f]{32}", iid), "unsafe genuine action selector")
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute("CREATE TRIGGER application_result_abort AFTER UPDATE OF record ON dec_intents "
            f"WHEN NEW.intent_id='{iid}' AND json_extract(NEW.record,'$.terminal')='applied' "
            "AND json_extract(NEW.record,'$.result_base64')!='-' BEGIN SELECT RAISE(ABORT,'PRIVATE_APPLICATION_ABORT'); END")
    try:
        for local in (f["a"], f["b"]):
            local.clock.set(local.clock.offset + 2)
        stable(f); before, counters = whole(f), traffic(f)
        status, denied = h.api("POST", BASE + "/apply", application_input(f, h, parent, prepared, apply=True), timeout=95)
        check(not 200 <= status < 300 and type(denied) is dict and "code" in denied
              and not ({"access", "review", "application"} & set(denied)), "late storage ABORT did not return controlled non2xx")
        public(denied, "PRIVATE_APPLICATION_ABORT")
        strict_unchanged(f, before, counters, "application_rollback")
        action = intent(h, iid)["record"]
        check(action["terminal"] == "-" and action["result_base64"] == "-" and action["signatures"] == [signature],
              "late ABORT changed authentic signature or left an application result")
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute("DROP TRIGGER application_result_abort")
    check(records(h)["$schema"] == schema, "schema-only fault left DDL")
    check(pure(f, h, parent, prepared)["application"]["state"] == "signed", "rollback observation applied or resigned")
    f["rollback"] = parent, prepared


class LostResponse:
    """Forward exactly one genuine private apply, then discard its real response."""
    def __init__(self, h):
        self.state = suite.work / "lost"; self.state.mkdir(mode=0o700)
        self.calls = 0; self.result = None; self.failed = False
        outer = self
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_POST(self):
                try:
                    outer.calls += 1
                    data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                    check(self.path == BASE + "/apply", "lost-response fixture changed actual route")
                    outer.result = h.api("POST", self.path, data, timeout=95)
                    self.connection.shutdown(socket.SHUT_RDWR)
                except Exception:
                    outer.failed = True
        self.server = Server(str(self.state / "admin.sock"), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
    def __enter__(self):
        self.thread.start(); return self
    def __exit__(self, *_args):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=1)


@suite.case("concurrent_real_apply_and_lost_response_recover_one_action_proof_edit_event", "guided33 verification4")
def _():
    f = world(); h = f["b"]; check("rollback" in f, "genuine signed rollback prerequisite missing")
    parent, prepared = f["rollback"]
    old_action = intent(h, prepared["access"]["review"]["intent_id"]); old_receipt = intent(h, prepared["access"]["access_id"])
    events = len(action_events(h)); gate = threading.Barrier(3); results = []; failures = []
    def invoke():
        try:
            gate.wait(timeout=5)
            results.append(h.api("POST", BASE + "/apply", application_input(f, h, parent, prepared, apply=True), timeout=95))
        except Exception:
            failures.append(True)
    threads = [threading.Thread(target=invoke, daemon=True) for _ in range(2)]
    for thread in threads: thread.start()
    gate.wait(timeout=5)
    for thread in threads: thread.join(timeout=96)
    check(not failures and all(not thread.is_alive() for thread in threads) and len(results) == 2
          and all(status == 200 for status, _ in results), "concurrent genuine explicit application failed")
    for _, value in results: application_view(h, parent, prepared, value)
    check(results[0][1]["application"] == results[1][1]["application"], "overlap changed exact applied identity")
    assert_application(h, prepared, old_action, old_receipt, events)
    stable(f)
    check(pure(f, h, parent, prepared)["application"] == results[0][1]["application"], "concurrent pure recovery changed marker")
    a = f["a"]; select_provider(a, f["net"], f["alice"], f["alice"])
    parent, prepared = signed(f, a, "original-lost")
    original = intent(a, prepared["access"]["review"]["intent_id"]); receipt = intent(a, prepared["access"]["access_id"])
    events = len(action_events(a)); backup = a.root / "original-held-away"
    a.owner_key.rename(backup)
    check(not a.owner_key.exists() and not Path(a.extra_env["SSH_AUTH_SOCK"]).exists(), "original signing sources are not genuinely absent")
    with LostResponse(a) as proxy:
        result = subprocess.run([str(suite.host_bin), "--state", str(proxy.state), "onboarding", "access", "apply", "--stdin"],
            input=compact(application_input(f, a, parent, prepared, apply=True)), capture_output=True, env=a.env, timeout=95)
        check(result.returncode != 0 and proxy.calls == 1 and not proxy.failed and proxy.result is not None
              and proxy.result[0] == 200, "real committed lost response was retried or not actually discarded")
        public((result.stdout + result.stderr).decode(errors="replace"), str(proxy.state))
    # Unknown outcome is resolved through the pure observation before any replay.
    stable(f); recovered = pure(f, a, parent, prepared)
    check(recovered["application"]["state"] == "locally_applied" and recovered["application"] == proxy.result[1]["application"],
          "pure lost-response observation did not recover the one committed application")
    assert_application(a, prepared, original, receipt, events)
    f["original_applied"] = parent, prepared, recovered
    print("LIMIT budgets_overlap: full90s server timeout/cancellation and a forced transaction-overlap boundary are not constructed; two actual concurrent calls and one actual lost response are observed", flush=True)


@suite.case("applied_unsigned_signed_history_after_expiry_head_provider_detach_replacement_restart_and_corruption", "guided33 verification5")
def _():
    f = world()
    check(all(name in f for name in ("applied", "original_applied", "unsigned", "elapsed")), "earlier genuine history prerequisites did not complete")
    h = f["b"]; parent, prepared, applied = f["applied"]
    # A real newer head makes the old applied grant historical rather than current.
    h.ok("allow", "alice", "--network", f["net"], "--agent", "current-different-policy")
    check(current_policy(h, f["net"], f["bob"])[0]["statement_id"] != prepared["access"]["review"]["statement"]["id"],
          "actual newer policy-head prerequisite missing")
    for local, name in ((f["b"], "applied"), (f["a"], "original_applied")):
        old_parent, _, _ = f[name]
        local.ok("session", "detach", old_parent["review"]["session_id"])
        project(local, "replacement-" + local.name, old=old_parent)
    select_provider(f["a"], f["net"], f["alice"], f["alice_device"]["lease_id"])
    select_provider(h, f["net"], f["bob"], f["bob"])
    target = max(parse_time(f[name][1]["access"]["review"]["expires_at"])
                 for name in ("applied", "original_applied", "unsigned", "elapsed")) + timedelta(seconds=1)
    for local in (f["a"], f["b"]):
        local.clock.set(local.clock.offset + max(0, math.ceil((target - local.now()).total_seconds())))
        check(not local.owner_key.exists() and not Path(local.extra_env["SSH_AUTH_SOCK"]).exists(), "original source is not genuinely absent")
        local.restart(kill=True)
    directory(f); stable(f)
    before, counters = whole(f), traffic(f)
    for name, local in (("applied", f["b"]), ("original_applied", f["a"])):
        parent, prepared, applied = f[name]
        for command in ("application", "apply"):
            value = operation(f, local, parent, prepared, command)
            check(value["application"] == applied["application"] and value["access"] == applied["access"], "historical applied API changed exact consent/evidence marker")
            result = local.cli("onboarding", "access", command, "--stdin",
                input=compact(application_input(f, local, parent, prepared, apply=command == "apply")).decode(), timeout=95 if command == "apply" else 8)
            check(result.ok and result.json["application"] == applied["application"] and result.json["access"] == applied["access"],
                  "historical private CLI lost exact retained application")
            application_view(local, parent, prepared, result.json); public(result.stderr)
    for name, expected in (("unsigned", "unsigned"), ("elapsed", "signed")):
        parent, prepared = f[name]
        check(operation(f, h, parent, prepared)["application"]["state"] == expected, "historical unsigned/signed observation performed fresh work")
    strict_unchanged(f, before, counters, "history")
    # Only old, already genuine application evidence is negatively faulted.
    parent, prepared, _ = f["applied"]; iid = prepared["access"]["review"]["intent_id"]
    sid = prepared["access"]["review"]["statement"]["id"]; pid = f["main_proof"]
    database = db_path(h)
    for fault in ("result", "signature", "proof", "admission"):
        h.stop(kill=True)
        with closing(sqlite3.connect(database)) as db, db:
            original = db.execute("SELECT record FROM dec_intents WHERE intent_id=?", (iid,)).fetchone()[0]
            proof = db.execute("SELECT * FROM dec_objects WHERE network_id=? AND proof_id=?", (f["net"], pid)).fetchone()
            admission = db.execute("SELECT * FROM dec_admissions WHERE network_id=? AND statement_id=?", (f["net"], sid)).fetchone()
            check(proof is not None and admission is not None, "negative evidence was not genuinely retained")
            if fault in {"result", "signature"}:
                corrupt = json.loads(original)
                if fault == "result":
                    corrupt["result_base64"] = base64.b64encode(b"{}").decode()
                else:
                    raw_signature = base64.b64decode(corrupt["signatures"][0]["signature"], validate=True)
                    corrupt["signatures"][0]["signature"] = base64.b64encode(raw_signature[:-1] + bytes([raw_signature[-1] ^ 1])).decode()
                db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (compact(corrupt).decode(), iid))
            elif fault == "proof":
                db.execute("DELETE FROM dec_objects WHERE network_id=? AND proof_id=?", (f["net"], pid))
            else:
                db.execute("DELETE FROM dec_admissions WHERE network_id=? AND statement_id=?", (f["net"], sid))
        try:
            h.start(); fault_startup_observed(f); stable(f)
            for command in ("application", "apply"):
                pure(f, h, parent, prepared, command, status=409, code="access_application_unavailable")
        finally:
            h.stop(kill=True)
            with closing(sqlite3.connect(database)) as db, db:
                if fault in {"result", "signature"}:
                    db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (original, iid))
                elif fault == "proof":
                    db.execute("INSERT INTO dec_objects VALUES (?,?,?,?,?)", proof)
                else:
                    db.execute("INSERT INTO dec_admissions VALUES (?,?,?,?)", admission)
    h.start(); directory(f); stable(f)
    check(pure(f, h, parent, prepared)["application"] == f["applied"][2]["application"], "exact restored evidence did not recover unchanged application")


@suite.case("closed_private_input_64KiB_argv_no_daemon_router_and_retained_result_reference", "guided33 verification6")
def _():
    f = world(); h = f["b"]
    check("applied" in f, "genuine applied privacy prerequisite missing")
    parent, prepared, applied = f["applied"]
    stable(f); before, counters = whole(f), traffic(f)
    for command in ("application", "apply"):
        data = application_input(f, h, parent, prepared, apply=command == "apply")
        encoded = compact(data); maximum = b" " * (65536 - len(encoded)) + encoded
        status, value = raw(h, command, maximum)
        check(status == 200 and value["application"] == applied["application"], "exact64KiB applied API recovery failed")
        result = h.cli("onboarding", "access", command, "--stdin", input=maximum.decode(), timeout=95 if command == "apply" else 8)
        check(result.ok and result.json["application"] == applied["application"], "exact64KiB private CLI parity")
        malformed = [b"null", b"[]", b"{", b"\xff", encoded + b"{}", maximum + b" ",
            encoded.replace(b'"context":', b'"context":null,"context":', 1),
            encoded.replace(b'"integration":', b'"integration":"claude-code","integration":', 1)]
        for key in data:
            malformed += [compact({k: v for k, v in data.items() if k != key}), compact({**data, key: None}), compact({**data, key: 12})]
        for key in data["context"]:
            malformed += [compact({**data, "context": {k: v for k, v in data["context"].items() if k != key}}),
                          compact({**data, "context": {**data["context"], key: None}})]
        for extra in ("provider_id", "person_key_file", "signature_format", "signature", "template", "payload_base64", "approve"):
            malformed.append(compact({**data, extra: "PRIVATE_APPLICATION_INPUT"}))
        malformed += [compact({**data, "access_id": "dint_bad"}), compact({**data, "access_review_id": "review_bad"}),
            compact({**data, "network_id": "net_bad"}), compact({**data, "person_public_key": base64.b64encode(b"\xff" * 31).decode()}),
            compact({**data, "context": {**data["context"], "extra": "PRIVATE_APPLICATION_INPUT"}}),
            compact({**data, "decision": "sign_project_agent_access" if command == "apply" else "apply_project_agent_access"})]
        for n, invalid in enumerate(malformed):
            status, denied = raw(h, command, invalid)
            check(status == 400 and type(denied) is dict and denied.get("code") == "invalid", f"closed {command} variant{n}: HTTP{status}")
            public(denied, "PRIVATE_APPLICATION_INPUT", data["context"]["project_root"], data["context"]["native_session_id"])
            result = h.cli("onboarding", "access", command, "--stdin", input=invalid.decode(errors="replace"), timeout=8)
            check(not result.ok, f"private CLI accepted malformed {command} variant{n}")
            public(result.stdout + result.stderr, "PRIVATE_APPLICATION_INPUT", str(h.state), data["context"]["project_root"], data["context"]["native_session_id"])
        for args in ((), (encoded.decode(),), ("--person-key", "PRIVATE_APPLICATION_INPUT", "--stdin"),
                     ("--provider", "PRIVATE_APPLICATION_INPUT", "--stdin"), ("--approve", "--stdin")):
            result = h.cli("onboarding", "access", command, *args, input=encoded.decode(), timeout=8)
            check(not result.ok, "CLI accepted implicit stdin/private argv/provider override")
            public(result.stdout + result.stderr, "PRIVATE_APPLICATION_INPUT", data["context"]["project_root"], data["context"]["native_session_id"])
        for argv in (("onboarding", "--state", str(h.state), "access", command),
                     ("onboarding", "access", "--state", str(h.state), command), ("onboarding", "access", command, "--state", str(h.state))):
            result = subprocess.run([str(suite.host_bin), *argv, encoded.decode()], capture_output=True, env=h.env, cwd=h.root, timeout=8)
            check(result.returncode != 0, "interleaved global flags accepted private argv")
            public((result.stdout + result.stderr).decode(errors="replace"), encoded.decode(), data["context"]["project_root"], data["context"]["native_session_id"])
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            status, denied = h.api(method, BASE + "/" + command, data, timeout=8)
            check(status == 405, "owner application route accepted unsupported method")
            public(denied)
        absent = {**data, "access_id": "dint_" + "f" * 32}
        status, denied = h.api("POST", BASE + "/" + command, absent, timeout=8)
        check(status == 404 and denied.get("code") == "not_found", "unknown requested access ID confused with corrupt retained reference")
        public(denied)
    strict_unchanged(f, before, counters, "input_refusal")
    attached = project(h, "router")
    credential = h.ok("adapter", "create", "--session", attached["review"]["session_id"], "--expires-at", rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, attached["review"]["agent"], attached["review"]["session_id"], credential)
    check(adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id, "session_id": adapter.session_id,
          "instance_id": adapter.instance})[0] == 200, "real scoped adapter authentication prerequisite")
    cert, key = suite.work / "boundary-cert.pem", suite.work / "boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=boundary", "-days", "1",
        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    for command in ("application", "apply"):
        data = application_input(f, h, parent, prepared, apply=command == "apply"); endpoint = BASE + "/" + command
        status, denied = adapter.call("POST", endpoint, data)
        check(status == 404, "scoped adapter exposed owner policy application")
        public(denied, adapter.token, adapter.instance)
        result = subprocess.run([str(suite.probe_bin), "--state", str(f["a"].state), "--address", peer_address(h), "--alpn", "peerspan-peer/1",
            "--path", endpoint, "--method", "POST", "--body-stdin"], input=compact(data), capture_output=True, timeout=15)
        check(result.returncode == 0 and json.loads(result.stdout).get("status") == 404, "authenticated peer exposed owner application")
        public(result.stderr.decode(errors="replace"))
        address, port = h.relay.address.split(":"); encoded = compact(data)
        with socket.create_connection((address, int(port)), timeout=5) as connection:
            with tls.wrap_socket(connection, server_hostname="peerspan") as stream:
                stream.sendall((f"POST {endpoint} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n").encode() + encoded)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, "bootstrap router exposed owner policy application")
    missing = suite.host("missing", start=False); shutil.rmtree(missing.state); before_files = files(missing.root)
    for command in ("application", "apply"):
        result = missing.cli("onboarding", "access", command, "--stdin",
            input=compact(application_input(f, h, parent, prepared, apply=command == "apply")).decode(), timeout=8)
        check(not result.ok and purity_missing_files_diagnostic(files(missing.root), before_files) == before_files and not missing.state.exists(),
              "private CLI initialized absent daemon/state")
        public(result.stdout + result.stderr, str(missing.state), context(parent)["project_root"], context(parent)["native_session_id"])
    # Corrupt only the cached genuine result's proof reference, never authority.
    database = db_path(h); iid = prepared["access"]["review"]["intent_id"]; h.stop(kill=True)
    with closing(sqlite3.connect(database)) as db, db:
        original = db.execute("SELECT record FROM dec_intents WHERE intent_id=?", (iid,)).fetchone()[0]
        corrupt = json.loads(original); result = json.loads(base64.b64decode(corrupt["result_base64"], validate=True))
        absent_proof = "dp_" + "f" * 64
        check(db.execute("SELECT 1 FROM dec_objects WHERE proof_id=?", (absent_proof,)).fetchone() is None, "negative result reference is not absent")
        result["proof_id"] = absent_proof; corrupt["result_base64"] = base64.b64encode(compact(result)).decode()
        db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (compact(corrupt).decode(), iid))
    try:
        h.start(); fault_startup_observed(f); stable(f)
        for command in ("application", "apply"):
            pure(f, h, parent, prepared, command, status=409, code="access_application_unavailable")
    finally:
        h.stop(kill=True)
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (original, iid))
    check(records(h)["$schema"] == f["schema"] and records(h)["$version"] == (27,), "application continuation changed schema27")
    print("LIMIT cryptographic_capacity_acceptance: full catalog-closure corruption matrices, fork/quota/overflow, accepted message/task, native/model/installed/physical and full-state-upgrade boundaries are source/manual", flush=True)


suite.finish()
