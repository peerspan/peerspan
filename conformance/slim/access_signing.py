#!/usr/bin/env python3
"""Bounded project policy signature storage, guided session section32.

Independent contract-only source. One genuine two-person/two-host public
admission, exact project/consent actions, real original files and a real
multi-identity ssh-agent. A transparent local agent proxy counts/holds genuine
messages and injects only negative response faults. No authority/key/seed/
protocol/template row is invented or edited. Schema-only ABORT triggers and
restored offline faults of already genuine receipt/signature records are the
only SQLite mutations. Real invitation/request expiry, ordinary maintenance,
empty outboxes/journals and completed directory setup precede strict snapshots.
Both original bootstrap TCP and every enabled QUIC path remain counted.

Source/manual limits: no genuine complex root/member/lease fork, incomplete
ancestry, same-person unsettled sibling withdrawal, quota/overflow exhaustion,
broken selected-device seed or valid oversized/unsafe projection is constructed.
The full90s monotonic agent timeout, lost-response/commit boundary and overlapping
explicit calls remain unexecuted; controlled real-agent IO barriers cover fresh
pin changes without adding a clock/retry loop. Foreign-owned file and file-open
syscall counts are not isolated. No physical/native/model or
installed acceptance is inferred. All26 old suites/helpers/harness stay exact.
"""
import atexit
import base64
import copy
import hashlib
import http.client
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

suite = Suite("access_signing", __doc__)
BASE = "/v1/onboarding/access-consent"
INSPECT = "/v1/onboarding/access-inspection"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ("psi2-", "psl2-", "peerspan-invite-v1.", "peerspan-member-invite-v1.",
            "peerspan-person-invite-v1.", "token_", "instance_")
TOP = set("version host_id context observed_at access signing".split())
SIGNING = set("state action_id intent_id statement_id signature_count required_signatures policy_application peer_delivery connection_readiness".split())
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
            phases = {"prepare_pair", "prepare_cli", "prepare_fault", "approve_fault", "device_approval",
                      "original_approval", "restart_history", "input_refusal", "nonsigning_route",
                      "pure_lookup", "pure_prepare", "pure_approve", "pure_signing", "pure_sign",
                      "device_signature", "original_file", "original_agent", "lookup_race", "signature_race",
                      "signature_fault", "clock_fault", "record_corruption"}
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
            phases = {"prepare_pair", "prepare_cli", "prepare_fault", "approve_fault", "device_approval",
                      "original_approval", "restart_history", "input_refusal", "nonsigning_route",
                      "pure_lookup", "pure_prepare", "pure_approve", "pure_signing", "pure_sign",
                      "device_signature", "original_file", "original_agent", "lookup_race", "signature_race",
                      "signature_fault", "clock_fault", "record_corruption"}
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


def ssh_read_string(value, offset=0):
    size = struct.unpack(">I", value[offset:offset + 4])[0]
    end = offset + 4 + size
    check(end <= len(value), "bounded SSH-agent fixture packet")
    return value[offset + 4:end], end


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def agent_packet(stream):
    size = struct.unpack(">I", read_exact(stream, 4))[0]
    if not 0 < size <= 1024 * 1024:
        raise ValueError("agent fixture packet bound")
    return read_exact(stream, size)


def sshsig_preimage(message):
    return b"SSHSIG" + ssh_string(b"peerspan-person-v1") + ssh_string(b"") + ssh_string(b"sha512") + ssh_string(hashlib.sha512(message).digest())


class AgentProxy:
    """Forward the real agent; controlled holds/faults never create valid rows."""
    def __init__(self, path, upstream, wrong_key):
        self.path, self.upstream, self.wrong_key = path, upstream, wrong_key
        self.lock, self.seen, self.release = threading.Lock(), threading.Event(), threading.Event()
        self.mode, self.expected_message = "pass", b""
        self.requests = []
        outer = self

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream_socket:
                        upstream_socket.settimeout(5)
                        upstream_socket.connect(str(outer.upstream))
                        while True:
                            packet = agent_packet(self.request)
                            kind, key, message, flags = packet[0], b"", b"", 0
                            if kind == 13:  # SSH2_AGENTC_SIGN_REQUEST
                                key, offset = ssh_read_string(packet, 1)
                                message, offset = ssh_read_string(packet, offset)
                                flags = struct.unpack(">I", packet[offset:offset + 4])[0]
                            with outer.lock:
                                mode = outer.mode
                                outer.requests.append((kind, key, message, flags))
                            if mode == "reject_all":
                                self.request.sendall(ssh_string(b"\x05"))
                                continue
                            forwarded = packet
                            if kind == 13 and mode in {"wrong_key", "wrong_role", "wrong_message"}:
                                if mode == "wrong_key":
                                    key = outer.wrong_key
                                elif mode == "wrong_role":
                                    message = sshsig_preimage(outer.expected_message.replace(b"\nissuer\n", b"\nhost\n"))
                                else:
                                    message = message[:-1] + bytes([message[-1] ^ 1])
                                forwarded = bytes([kind]) + ssh_string(key) + ssh_string(message) + struct.pack(">I", flags)
                            upstream_socket.sendall(ssh_string(forwarded))
                            reply = agent_packet(upstream_socket)
                            if (kind == 11 and mode == "hold_lookup") or (kind == 13 and mode == "hold_signature"):
                                outer.seen.set()
                                if not outer.release.wait(timeout=10):
                                    return
                            if kind == 13 and mode in {"wrong_format", "wrong_signature"} and reply[0] == 14:
                                signature, _ = ssh_read_string(reply, 1)
                                algorithm, offset = ssh_read_string(signature)
                                signature, _ = ssh_read_string(signature, offset)
                                if mode == "wrong_format":
                                    algorithm = b"ssh-rsa"
                                else:
                                    signature = signature[:-1] + bytes([signature[-1] ^ 1])
                                reply = b"\x0e" + ssh_string(ssh_string(algorithm) + ssh_string(signature))
                            self.request.sendall(ssh_string(reply))
                except (OSError, EOFError, ValueError):
                    pass

        self.server = Server(str(path), Handler)
        path.chmod(0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        atexit.register(self.close)

    def configure(self, mode, message=b""):
        with self.lock:
            self.mode, self.expected_message = mode, message
        self.seen.clear(); self.release.clear()

    def captured(self):
        with self.lock:
            return tuple(self.requests)

    def counts(self):
        captured = self.captured()
        return len(captured), sum(entry[0] == 11 for entry in captured), sum(entry[0] == 13 for entry in captured)

    def close(self):
        self.release.set()
        self.server.shutdown(); self.server.server_close()
        self.thread.join(timeout=1)
        self.path.unlink(missing_ok=True)


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
    net = a.ok("network", "create", "Signing 東京", "--as", "alice", "--person-key-file", a.owner_key)
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


def configure_agent(f):
    if "agent" in f:
        return f["agent"]
    h = f["a"]
    upstream, exposed = h.root / "real-agent", h.root / "agent"
    check(len(str(exposed).encode()) < 104, "short TMPDIR required for genuine Unix agent endpoint")
    suite.spawn(["ssh-agent", "-D", "-a", str(upstream)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for(upstream.exists, timeout=3, interval=.05, message="real ssh-agent socket")
    for key in (f["key"], h.owner_key):
        result = subprocess.run(["ssh-add", str(key)], env={**h.env, "SSH_AUTH_SOCK": str(upstream)}, capture_output=True, timeout=5)
        check(result.returncode == 0, "real multi-identity agent key loading")
    listed = subprocess.run(["ssh-add", "-L"], env={**h.env, "SSH_AUTH_SOCK": str(upstream)}, capture_output=True, timeout=5)
    check(listed.returncode == 0 and len(listed.stdout.splitlines()) == 2
          and ssh_public_base64(f["key"]) != ssh_public_base64(h.owner_key), "actual agent does not hold two distinct real identities")
    wrong_key = base64.b64decode(Path(str(f["key"]) + ".pub").read_text().split()[1])
    proxy = AgentProxy(exposed, upstream, wrong_key)
    h.extra_env["SSH_AUTH_SOCK"] = str(exposed)
    h.restart(kill=True)
    directory(f); stable(f)
    f["agent"] = proxy
    return proxy


def selected_person(f, h):
    return f["alice"] if h is f["b"] else f["bob"]


def consent(f, h, name, *, approve=True, parent=None):
    parent = parent or project(h, name)
    person = selected_person(f, h)
    inspected = inspection(h, parent, f["net"], person)
    status, prepared = h.api("POST", BASE + "/prepare", {**key_body(parent, f["net"], person),
        "inspection_review_id": inspected["review_id"]}, timeout=8)
    check(status == 200 and set(prepared) == TOP - {"signing"} and prepared["access"]["state"] == "review", "genuine section31 unsigned consent prerequisite")
    access, review = prepared["access"], prepared["access"]["review"]
    check(review["inspection"] == inspected["review"] and access["review_id"] == "review_" + hashlib.sha256(
        b"peerspan-project-access-consent-v1\n" + canonical(review)).hexdigest(), "exact complete approved-review prerequisite")
    if approve:
        status, approved = h.api("POST", BASE + "/approve", {**key_body(parent, f["net"], person),
            "access_id": access["access_id"], "access_review_id": access["review_id"]}, timeout=8)
        check(status == 200 and set(approved) == TOP - {"signing"} and approved["access"]["state"] == "approved"
              and approved["access"]["review"] == review, "genuine exact guided and ordinary approval prerequisite")
        prepared = approved
    return parent, prepared


def signing_input(f, h, parent, prepared, *, sign=False):
    data = {**key_body(parent, f["net"], selected_person(f, h)), "access_id": prepared["access"]["access_id"],
            "access_review_id": prepared["access"]["review_id"]}
    if sign:
        data["decision"] = "sign_project_agent_access"
    return data


def signing_view(h, parent, prepared, value):
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1
          and value["host_id"] == h.id and value["context"] == context(parent), "closed exact section32 outer view")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]), "canonical signing observation time")
    access, review = value["access"], value["access"]["review"]
    check(set(access) == {"access_id", "review_id", "review", "state", "next_action"}
          and review == prepared["access"]["review"] and access["access_id"] == prepared["access"]["access_id"]
          and access["review_id"] == prepared["access"]["review_id"], "signing changed complete receipt/review/digest")
    receipt = intent(h, access["access_id"])
    action, envelope, raw_payload, payload = unsigned(h, value)
    record = action["record"]
    check(receipt["kind"] == "access_review" and receipt["secret"] is None and receipt["record"]["templates"] == []
          and receipt["record"]["signatures"] == [] and receipt["record"]["completed"] is True
          and receipt["record"]["result_base64"] == "-" and receipt["record"]["terminal"] == "-", "receipt became a signing/publication record")
    check(base64.b64decode(receipt["record"]["review_base64"], validate=True) == canonical(review), "stored exact nonsigning receipt changed")
    check(record["terminal"] == "-" and record["result_base64"] == "-" and type(record["signatures"]) is list and len(record["signatures"]) in {0, 1}
          and type(record["completed"]) is bool and record["completed"] == (len(record["signatures"]) == 1), "ordinary typed slot/completed mismatch")
    check(statement_id(envelope) == review["statement"]["id"] and hashlib.sha256(raw_payload).hexdigest() == review["statement"]["payload_sha256"]
          and {**{k: v for k, v in payload.items() if k != "body_base64"}, "body": json.loads(base64.b64decode(payload["body_base64"], validate=True))}
          == review["statement"]["payload"], "actual unsigned policy template or payload changed")
    provider = review["provider"]
    declared = envelope["signatures"]
    expected_key = provider["device_public_key"] if provider["kind"] == "device" else provider["person_public_key"]
    expected_format = "ed25519" if provider["kind"] == "device" else "sshsig"
    check(provider["kind"] in {"device", "original_person"} and len(declared) == 1 and declared[0] == {
        "role": "issuer", "public_key": expected_key, "format": expected_format, "signature": "-"}
        and record["provider"]["signer_public_key"] == expected_key and record["provider"]["signature_format"] == expected_format,
          "ordinary policy slot changed selected owner key/format/role or fell back to root")
    dual = receipt["record"]["approved"] is True and record["approved"] is True
    if not dual:
        check(value["signing"] is None, "unapproved/advanced-only action inferred guided signing consent")
    else:
        check(receipt["record"]["approved_at"] == record["approved_at"], "dual approvals differ")
        signed = len(record["signatures"]) == 1
        expected = {"state": "signed" if signed else "unsigned", "action_id": review["action_id"], "intent_id": review["intent_id"],
            "statement_id": review["statement"]["id"], "signature_count": 1 if signed else 0, "required_signatures": 1,
            "policy_application": "not_verified", "peer_delivery": "not_verified", "connection_readiness": "not_verified"}
        check(type(value["signing"]) is dict and set(value["signing"]) == SIGNING and value["signing"] == expected,
              "signature marker widened application/delivery/access/readiness or changed exact slot counts")
        check(type(value["signing"]["signature_count"]) is int and type(value["signing"]["required_signatures"]) is int,
              "signature counts accepted booleans or another public type")
    check(len(compact(value)) <= 1024 * 1024, "signing response exceeded public1MiB limit")
    public(value)


def operation(f, h, parent, prepared, action, *, status=200, code=None, override=None, timeout=None):
    data = signing_input(f, h, parent, prepared, sign=action == "sign") if override is None else override
    actual, value = h.api("POST", BASE + "/" + action, data, timeout=timeout or (95 if action == "sign" else 8))
    check(actual == status, f"access {action} HTTP {actual}, want {status}")
    if actual == 200:
        signing_view(h, parent, prepared, value)
    else:
        check(isinstance(value, dict) and value.get("code") == code and not ({"access", "review", "signing"} & set(value)),
              f"access {action} did not return closed {code}")
        public(value)
    return value


def strict_unchanged(f, before, counters, phase):
    check(purity_whole_diagnostic(whole(f), before, phase) == before, "signing changed whole schema/DB/state/home outside its exact boundary")
    check(purity_traffic_diagnostic(traffic(f), counters, phase) == counters, "signing used original TCP or an enabled UDP path")


def pure_operation(f, h, parent, prepared, action="signing", **options):
    stable(f)
    before, counters = whole(f), traffic(f)
    agent_counts = f["agent"].counts() if "agent" in f else None
    value = operation(f, h, parent, prepared, action, **options)
    strict_unchanged(f, before, counters, "pure_" + action)
    check(agent_counts == (f["agent"].counts() if "agent" in f else None), "read/refusal/replay probed or signed with an external agent")
    return value


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


def sign_exact(f, h, parent, prepared, *, cli=False, phase="device_signature"):
    stable(f)
    before, remote, counters = snapshot(h), snapshot(f["a"] if h is f["b"] else f["b"]), traffic(f)
    if cli:
        result = h.cli("onboarding", "access", "sign", "--stdin", input=compact(signing_input(f, h, parent, prepared, sign=True)).decode(), timeout=95)
        check(result.ok, "exact explicit private CLI policy signing failed")
        value = result.json; signing_view(h, parent, prepared, value); public(result.stderr)
    else:
        value = operation(f, h, parent, prepared, "sign")
    check(value["signing"]["state"] == "signed", "explicit signing did not retain the exact issuer slot")
    assert_signature_write(h, prepared, before, snapshot(h))
    other = f["a"] if h is f["b"] else f["b"]
    check(purity_snapshot_diagnostic(snapshot(other), remote, phase, "alice" if other is f["a"] else "bob") == remote,
          "local policy signing changed the other participant")
    check(purity_traffic_diagnostic(traffic(f), counters, phase) == counters, "signature storage published or used a peer carrier")
    return value


@suite.case("dual_consent_null_unsigned_exact_device_signature_only_and_cli", "guided32 verification1")
def _():
    f = world(); h = f["b"]
    parent, prepared = consent(f, h, "device", approve=False, parent=f["pb"])
    check(pure_operation(f, h, parent, prepared)["signing"] is None, "unapproved consent has a signing marker")
    pure_operation(f, h, parent, prepared, "sign", status=409, code="access_signing_unavailable")
    parent, prepared = consent(f, h, "device", parent=parent)
    check(prepared["access"]["review"]["provider"] == f["bob_device"], "device consent changed actual selected scope1 provider")
    unsigned_view = pure_operation(f, h, parent, prepared)
    check(unsigned_view["signing"]["state"] == "unsigned" and unsigned_view["signing"]["signature_count"] == 0, "approved unsigned observation")
    policy_before = current_policy(h, f["net"], f["bob"])
    people = get(h, f"/v2/networks/{f['net']}/persons")["persons"]
    check({person["person_public_key"] for person in people} == {f["alice"], f["bob"]}, "genuine distinct membership prerequisite")
    agent_name = prepared["access"]["review"]["grant"]["agent_name"]
    check(all(rule["agent"] != agent_name for rule in policy_before[3]["rules"]), "fixture already applied reviewed agent-name rule")
    signed = sign_exact(f, h, parent, prepared)
    check(current_policy(h, f["net"], f["bob"]) == policy_before, "policy signature storage applied a grant")
    for command in ("signing", "sign"):
        check(pure_operation(f, h, parent, prepared, command)["signing"] == signed["signing"], "exact signed replay changed marker")
        stable(f); before, counters = whole(f), traffic(f)
        result = h.cli("onboarding", "access", command, "--stdin", input=compact(signing_input(f, h, parent, prepared, sign=command == "sign")).decode(), timeout=95 if command == "sign" else 8)
        check(result.ok and result.json["signing"] == signed["signing"] and result.json["access"] == signed["access"], "private CLI exact signature observation/replay parity")
        signing_view(h, parent, prepared, result.json); public(result.stderr)
        strict_unchanged(f, before, counters, "pure_" + command)
    status, old_view = h.api("POST", BASE + "/lookup", key_body(parent, f["net"], f["alice"]), timeout=8)
    check(status == 200 and set(old_view) == TOP - {"signing"} and old_view["access"] == signed["access"], "section31 old operation shape/history changed")
    f["device_signed"] = parent, prepared, signed


@suite.case("safe_configured_original_file_and_exact_real_multi_identity_agent", "guided32 verification2")
def _():
    f = world(); h = f["a"]
    select_provider(h, f["net"], f["alice"], f["alice"])
    info = h.owner_key.stat(); original, mode = h.owner_key.read_bytes(), info.st_mode & 0o777
    check(info.st_uid == os.geteuid() and mode & 0o077 == 0 and len(original) <= 16384, "genuine safe process-owned configured owner file")
    parent, prepared = consent(f, h, "file")
    check(prepared["access"]["review"]["provider"]["kind"] == "original_person", "selected original prerequisite")
    signed = sign_exact(f, h, parent, prepared, cli=True, phase="original_file")
    check(h.owner_key.read_bytes() == original and h.owner_key.stat().st_mode & 0o777 == mode, "original signing changed configured private owner-file bytes/mode")
    f["file_signed"] = parent, prepared, signed
    safe_target = h.root / "matching-owner.saved"; safe_target.write_bytes(original); safe_target.chmod(0o600)
    for variant in ("missing", "broad", "wrong", "malformed", "symlink", "fifo", "oversized", "encrypted"):
        h.owner_key.unlink(missing_ok=True)
        if variant == "symlink":
            h.owner_key.symlink_to(safe_target)
        elif variant == "fifo":
            os.mkfifo(h.owner_key, 0o600)
        elif variant != "missing":
            content = f["key"].read_bytes() if variant == "wrong" else b"PRIVATE_BAD_OWNER" if variant == "malformed" else b"x" * 16385 if variant == "oversized" else original
            h.owner_key.write_bytes(content); h.owner_key.chmod(0o644 if variant == "broad" else 0o600)
            if variant == "encrypted":
                result = subprocess.run(["ssh-keygen", "-p", "-P", "", "-N", "PRIVATE_FIXTURE_PASSWORD", "-f", str(h.owner_key)], capture_output=True, timeout=5)
                check(result.returncode == 0, "genuine same-key encrypted OpenSSH fixture")
        try:
            bad_parent, bad = consent(f, h, "file-" + variant)
            stable(f); before, counters = whole(f), traffic(f)
            operation(f, h, bad_parent, bad, "sign", status=409, code="access_signing_unavailable", timeout=5)
            strict_unchanged(f, before, counters, "original_file")
        finally:
            h.owner_key.unlink(missing_ok=True)
            h.owner_key.write_bytes(original); h.owner_key.chmod(mode)
    agent = configure_agent(f)
    parent, prepared = consent(f, h, "agent")
    offset = len(agent.captured())
    signed = sign_exact(f, h, parent, prepared, phase="original_agent")
    message, declared = policy_message(h, prepared)
    requests = agent.captured()[offset:]
    signatures = [entry for entry in requests if entry[0] == 13]
    exact_key = ssh_string(b"ssh-ed25519") + ssh_string(base64.b64decode(f["alice"], validate=True))
    check(any(entry[0] == 11 for entry in requests) and len(signatures) == 1 and signatures[0][1] == exact_key
          and signatures[0][2] == sshsig_preimage(message) and signatures[0][3] == 0
          and declared["public_key"] == f["alice"], "agent selected another identity/message/format or made an extra possession signature")
    f["agent_signed"] = parent, prepared, signed
    backup = h.root / "owner-held-away"
    h.owner_key.rename(backup); f["owner_backup"] = backup
    removed = subprocess.run(["ssh-add", "-d", str(Path(str(h.owner_key) + ".pub"))],
        env={**h.env, "SSH_AUTH_SOCK": str(agent.upstream)}, capture_output=True, timeout=5)
    check(removed.returncode == 0, "genuine removal of only the exact original agent identity")
    try:
        parent, missing = consent(f, h, "wrong-agent-only")
        offset = len(agent.captured()); stable(f); before, counters = whole(f), traffic(f)
        operation(f, h, parent, missing, "sign", status=409, code="access_signing_unavailable")
        strict_unchanged(f, before, counters, "original_agent")
        requests = agent.captured()[offset:]
        check(any(entry[0] == 11 for entry in requests) and not any(entry[0] == 13 for entry in requests),
              "sole unrelated agent identity was selected or signed as fallback")
    finally:
        restored = subprocess.run(["ssh-add", str(backup)], env={**h.env, "SSH_AUTH_SOCK": str(agent.upstream)}, capture_output=True, timeout=5)
        check(restored.returncode == 0, "restore genuine original identity in real multi-identity agent")


def raced_sign(f, mode):
    h, agent = f["a"], f["agent"]
    parent, prepared = consent(f, h, mode)
    message, _ = policy_message(h, prepared)
    offset = len(agent.captured()); agent.configure(mode, message)
    result = {}
    def request():
        try:
            result["response"] = h.api("POST", BASE + "/sign", signing_input(f, h, parent, prepared, sign=True), timeout=95)
        except Exception:
            result["failed"] = True
    worker = threading.Thread(target=request, daemon=True); worker.start()
    try:
        check(agent.seen.wait(timeout=5), "real external-agent IO barrier was not reached")
        if mode == "hold_lookup":
            status, changed = h.api("POST", f"/v2/networks/{f['net']}/provider", {"provider_id": f["alice_device"]["lease_id"],
                "person_public_key": f["alice"], "host_public_key": h.public_key, "approve": True}, timeout=3)
            check(status == 200 and changed["provider"]["kind"] == "device", "ordinary selection blocked by held external-agent IO")
        else:
            detached = h.cli("session", "detach", parent["review"]["session_id"], timeout=3)
            check(detached.ok, "ordinary detach blocked by held external-agent IO")
        before, counters = whole(f), traffic(f)
        agent.release.set(); worker.join(timeout=5)
        check(not worker.is_alive() and not result.get("failed") and "response" in result, "bounded external-agent race did not finish")
        status, denied = result["response"]
        check(status == 409 and isinstance(denied, dict) and denied.get("code") == "review_changed", "late external signature accepted changed exact pins")
        public(denied)
        strict_unchanged(f, before, counters, "lookup_race" if mode == "hold_lookup" else "signature_race")
        count = sum(entry[0] == 13 for entry in agent.captured()[offset:])
        check(count == (0 if mode == "hold_lookup" else 1), "pre-sign or after-IO guard crossed its actual SSH signature boundary")
        check(intent(h, prepared["access"]["review"]["intent_id"])["record"]["signatures"] == [], "raced signature survived changed terms")
    finally:
        agent.release.set(); worker.join(timeout=5); agent.configure("pass")
        if mode == "hold_lookup":
            select_provider(h, f["net"], f["alice"], f["alice"])


@suite.case("exact_approval_binding_live_pins_real_agent_io_races_and_fixed_expiry", "guided32 verification3")
def _():
    f = world(); h = f["a"]; agent = configure_agent(f)
    select_provider(h, f["net"], f["alice"], f["alice"])
    if "owner_backup" not in f:
        backup = h.root / "owner-held-away"; h.owner_key.rename(backup); f["owner_backup"] = backup
    agent.configure("reject_all")
    parent, unapproved = consent(f, h, "advanced", approve=False)
    _, _, raw_payload, _ = unsigned(h, unapproved)
    status, advanced = h.api("POST", f"/v2/networks/{f['net']}/actions", {"kind": "policy", "provider_id": f["alice"],
        "signature_format": "sshsig", "payload_base64": base64.b64encode(raw_payload).decode(), "approve": True}, timeout=8)
    check(status == 200 and advanced["committed"] is False and advanced["signing_requests"], "genuine advanced-only unavailable original prerequisite")
    advanced_view = pure_operation(f, h, parent, unapproved)
    check(advanced_view["signing"] is None and advanced_view["access"]["state"] == "invalidated", "advanced ordinary approval supplied guided consent")
    pure_operation(f, h, parent, unapproved, "sign", status=409, code="access_signing_unavailable")
    agent.configure("pass")
    parent, prepared = consent(f, h, "binding")
    data = signing_input(f, h, parent, prepared, sign=True)
    for patch, status, code in (({"access_review_id": "review_" + "0" * 64}, 409, "review_changed"),
        ({"person_public_key": f["alice"]}, 409, "review_changed"), ({"access_id": "dint_" + "f" * 32}, 404, "not_found"),
        ({"network_id": "net_" + "f" * 64}, 404, "not_found"),
        ({"context": {**data["context"], "native_session_id": "PRIVATE_OTHER_NATIVE"}}, 409, "review_changed"),
        ({"context": {**data["context"], "project_flow_id": "flow_" + "f" * 32}}, 404, "not_found")):
        pure_operation(f, h, parent, prepared, "sign", override={**data, **patch}, status=status, code=code)
    h.ok("session", "detach", parent["review"]["session_id"])
    check(pure_operation(f, h, parent, prepared)["signing"]["state"] == "unsigned", "detached unsigned observation inferred liveness")
    pure_operation(f, h, parent, prepared, "sign", status=409, code="review_changed")
    latest_parent, superseded = consent(f, h, "latest")
    select_provider(h, f["net"], f["alice"], f["alice_device"]["lease_id"])
    current = inspection(h, latest_parent, f["net"], f["bob"])
    status, successor = h.api("POST", BASE + "/prepare", {**key_body(latest_parent, f["net"], f["bob"]),
        "inspection_review_id": current["review_id"], "replace_access_id": superseded["access"]["access_id"]}, timeout=8)
    check(status == 200 and successor["access"]["review"]["replaces_access_id"] == superseded["access"]["access_id"], "genuine latest-receipt replacement prerequisite")
    check(pure_operation(f, h, latest_parent, superseded)["signing"]["state"] == "unsigned", "superseded read hid retained exact unsigned action")
    pure_operation(f, h, latest_parent, superseded, "sign", status=409, code="review_changed")
    select_provider(h, f["net"], f["alice"], f["alice"])
    raced_sign(f, "hold_lookup"); raced_sign(f, "hold_signature")
    parent, stale = consent(f, h, "head")
    h.ok("allow", "everyone", "--network", f["net"], "--agent", "changed-head", "--person-key", f["owner_backup"])
    directory(f); stable(f)
    check(pure_operation(f, h, parent, stale)["signing"]["state"] == "unsigned", "head change hid retained unsigned state")
    pure_operation(f, h, parent, stale, "sign", status=409, code="review_changed")
    b = f["b"]; parent, elapsed = consent(f, b, "elapsed")
    offset = b.clock.offset
    try:
        b.clock.set(offset - 120)
        pure_operation(f, b, parent, elapsed, "sign", status=409, code="access_signing_unavailable")
        pure_operation(f, b, parent, elapsed, status=409, code="access_signing_unavailable")
    finally:
        b.clock.set(offset)
    deadline = parse_time(elapsed["access"]["review"]["expires_at"]) + timedelta(seconds=1)
    for local in (f["a"], f["b"]):
        local.clock.set(local.clock.offset + math.ceil((deadline - local.now()).total_seconds()))
    directory(f); stable(f)
    check(pure_operation(f, b, parent, elapsed)["signing"]["state"] == "unsigned", "elapsed read refreshed/hid unsigned history")
    pure_operation(f, b, parent, elapsed, "sign", status=409, code="review_expired")
    f["elapsed"] = parent, elapsed


@suite.case("late_signature_clock_sql_faults_and_real_wrong_agent_results_rollback", "guided32 verification4")
def _():
    f = world(); h = f["a"]; agent = configure_agent(f)
    select_provider(h, f["net"], f["alice"], f["alice"])
    if h.owner_key.exists():
        backup = h.root / "owner-held-away"; h.owner_key.rename(backup); f["owner_backup"] = backup
    for fault in ("wrong_role", "wrong_key", "wrong_message", "wrong_format", "wrong_signature"):
        parent, prepared = consent(f, h, fault)
        message, _ = policy_message(h, prepared)
        agent.configure(fault, message); offset = len(agent.captured())
        try:
            stable(f); before, counters = whole(f), traffic(f)
            operation(f, h, parent, prepared, "sign", status=409, code="access_signing_unavailable")
            strict_unchanged(f, before, counters, "signature_fault")
            check(sum(entry[0] == 13 for entry in agent.captured()[offset:]) == 1, "negative signer fault did not cross one genuine exact signature request")
        finally:
            agent.configure("pass")
    b = f["b"]
    select_provider(b, f["net"], f["bob"], f["bob_device"]["lease_id"])
    for fault in ("signature", "clock"):
        parent, prepared = consent(f, b, "sql-" + fault)
        iid = prepared["access"]["review"]["intent_id"]
        original_schema = records(b)["$schema"]
        names = []
        with closing(sqlite3.connect(db_path(b))) as db, db:
            if fault == "signature":
                names = ["signing_signature_abort"]
                db.execute(f"CREATE TRIGGER {names[0]} AFTER UPDATE OF record ON dec_intents "
                    f"WHEN NEW.intent_id='{iid}' AND json_array_length(json_extract(NEW.record,'$.signatures'))=1 "
                    "BEGIN SELECT RAISE(ABORT,'PRIVATE_SIGNING_ABORT'); END")
            else:
                for operation_name in ("INSERT", "UPDATE"):
                    name = "signing_clock_" + operation_name.lower() + "_abort"; names.append(name)
                    db.execute(f"CREATE TRIGGER {name} AFTER {operation_name} ON dec_clock "
                        f"WHEN NEW.network_id='{f['net']}' BEGIN SELECT RAISE(ABORT,'PRIVATE_SIGNING_ABORT'); END")
        try:
            if fault == "clock":
                for local in (f["a"], f["b"]):
                    local.clock.set(local.clock.offset + 2)
            stable(f); before, counters = whole(f), traffic(f)
            status, denied = b.api("POST", BASE + "/sign", signing_input(f, b, parent, prepared, sign=True), timeout=95)
            check(not 200 <= status < 300 and isinstance(denied, dict) and "code" in denied
                  and not ({"access", "review", "signing"} & set(denied)), "injected late SQLite fault did not return controlled non2xx")
            public(denied, "PRIVATE_SIGNING_ABORT")
            strict_unchanged(f, before, counters, "signature_fault" if fault == "signature" else "clock_fault")
            check(intent(b, iid)["record"]["signatures"] == [] and intent(b, iid)["record"]["completed"] is False,
                  "late SQLite fault retained signature/completed or partial clock")
        finally:
            with closing(sqlite3.connect(db_path(b))) as db, db:
                for name in names:
                    db.execute("DROP TRIGGER " + name)
        check(records(b)["$schema"] == original_schema, "schema-only signing fault left DDL")
    print("LIMIT complex_signing: no genuine fork/member/lease/incomplete/unsettled sibling, broken device seed, quota/u64/edit overflow; full90s timeout, overlap and lost-response boundary unexecuted", flush=True)


@suite.case("signed_expired_changed_replaced_detached_restart_absent_signer_history_pure", "guided32 verification5")
def _():
    f = world()
    check(all(name in f for name in ("device_signed", "file_signed", "agent_signed", "agent")), "earlier genuine signature fixtures did not complete")
    h, agent = f["a"], f["agent"]
    parent, prepared, signed = f["agent_signed"]
    current = inspection(h, parent, f["net"], f["bob"])
    check(current["review_id"] != prepared["access"]["review"]["inspection_review_id"], "genuine intervening policy-head prerequisite missing")
    status, successor = h.api("POST", BASE + "/prepare", {**key_body(parent, f["net"], f["bob"]),
        "inspection_review_id": current["review_id"], "replace_access_id": prepared["access"]["access_id"]}, timeout=8)
    check(status == 200 and successor["access"]["review"]["replaces_access_id"] == prepared["access"]["access_id"], "genuine exact consent replacement prerequisite")
    h.ok("session", "detach", parent["review"]["session_id"])
    project(h, "replacement", old=parent)
    select_provider(f["b"], f["net"], f["bob"], f["bob"])
    agent.configure("reject_all")
    check(not h.owner_key.exists(), "historical original file is not genuinely absent")
    for local in (f["a"], f["b"]):
        local.restart(kill=True)
    directory(f); stable(f)
    retained = {}
    for name, local in (("device_signed", f["b"]), ("file_signed", f["a"]), ("agent_signed", f["a"])):
        parent, prepared, signed = f[name]
        check(local.now() > parse_time(prepared["access"]["review"]["expires_at"]), "history fixture did not cross actual immutable review expiry")
        retained[name] = intent(local, prepared["access"]["access_id"]), intent(local, prepared["access"]["review"]["intent_id"])
        verify_policy_signature(local, prepared)
    before, counters, agent_counts = whole(f), traffic(f), agent.counts()
    for name, local in (("device_signed", f["b"]), ("file_signed", f["a"]), ("agent_signed", f["a"])):
        parent, prepared, signed = f[name]
        for command in ("signing", "sign"):
            value = operation(f, local, parent, prepared, command)
            check(value["access"] == signed["access"] and value["signing"] == signed["signing"], "historical API lost exact signed consent/slot")
            result = local.cli("onboarding", "access", command, "--stdin", input=compact(signing_input(f, local, parent, prepared, sign=command == "sign")).decode(), timeout=95 if command == "sign" else 8)
            check(result.ok and result.json["access"] == signed["access"] and result.json["signing"] == signed["signing"], "historical private CLI changed exact signed marker")
            signing_view(local, parent, prepared, result.json); public(result.stderr)
        check((intent(local, prepared["access"]["access_id"]), intent(local, prepared["access"]["review"]["intent_id"])) == retained[name],
              "historical observation changed receipt/signature/template/approval bytes")
    strict_unchanged(f, before, counters, "restart_history")
    check(agent.counts() == agent_counts, "signed history looked up or signed with absent/broken external signer")


@suite.case("closed_private_input_cli_router_no_daemon_and_real_record_corruption", "guided32 verification6")
def _():
    f = world(); h = f["b"]
    check("device_signed" in f, "genuine completed device signature prerequisite missing")
    parent, prepared, signed = f["device_signed"]
    stable(f); before, counters = whole(f), traffic(f)
    for command in ("signing", "sign"):
        data = signing_input(f, h, parent, prepared, sign=command == "sign")
        encoded = compact(data); maximum = b" " * (65536 - len(encoded)) + encoded
        status, value = raw(h, command, maximum)
        check(status == 200 and value["signing"] == signed["signing"], "exact64KiB signed API history")
        result = h.cli("onboarding", "access", command, "--stdin", input=maximum.decode(), timeout=95 if command == "sign" else 8)
        check(result.ok and result.json["signing"] == signed["signing"], "exact64KiB private CLI parity")
        malformed = [b"null", b"[]", b"{", b"\xff", encoded + b"{}", maximum + b" ",
            encoded.replace(b'"context":', b'"context":null,"context":', 1),
            encoded.replace(b'"integration":', b'"integration":"claude-code","integration":', 1)]
        for key in data:
            malformed += [compact({k: v for k, v in data.items() if k != key}), compact({**data, key: None}), compact({**data, key: 12})]
        for key in data["context"]:
            malformed += [compact({**data, "context": {**data["context"], key: None}})]
        for extra in ("provider_id", "person_key_file", "signature_format", "signature", "template", "payload_base64", "approve"):
            malformed.append(compact({**data, extra: "PRIVATE_INPUT"}))
        malformed += [compact({**data, "access_id": "dint_bad"}), compact({**data, "access_review_id": "review_bad"}),
            compact({**data, "person_public_key": base64.b64encode(b"\xff" * 32).decode()}),
            compact({**data, "context": {**data["context"], "extra": "PRIVATE_INPUT"}})]
        malformed.append(compact({**data, "decision": "approve" if command == "sign" else "sign_project_agent_access"}))
        for n, invalid in enumerate(malformed):
            status, denied = raw(h, command, invalid)
            check(status == 400 and isinstance(denied, dict) and denied.get("code") == "invalid", f"closed {command} variant{n}: HTTP{status}")
            public(denied, "PRIVATE_INPUT", data["context"]["project_root"], data["context"]["native_session_id"])
            result = h.cli("onboarding", "access", command, "--stdin", input=invalid.decode(errors="replace"), timeout=8)
            check(not result.ok, f"CLI accepted malformed {command} variant{n}")
            public(result.stdout + result.stderr, "PRIVATE_INPUT", data["context"]["project_root"], data["context"]["native_session_id"], str(h.state))
        for args in ((), (encoded.decode(),), ("--person-key", "PRIVATE_INPUT", "--stdin"), ("--provider", "PRIVATE_INPUT", "--stdin"), ("--approve", "--stdin")):
            result = h.cli("onboarding", "access", command, *args, input=encoded.decode(), timeout=8)
            check(not result.ok, "CLI accepted implicit stdin/private argv/override")
            public(result.stdout + result.stderr, "PRIVATE_INPUT", data["context"]["project_root"], data["context"]["native_session_id"])
        for argv in (("onboarding", "--state", str(h.state), "access", command), ("onboarding", "access", "--state", str(h.state), command),
                     ("onboarding", "access", command, "--state", str(h.state))):
            result = subprocess.run([str(suite.host_bin), *argv, encoded.decode()], capture_output=True, env=h.env, cwd=h.root, timeout=8)
            check(result.returncode != 0, "interleaved global flags accepted private argv")
            public((result.stdout + result.stderr).decode(errors="replace"), encoded.decode(), data["context"]["project_root"], data["context"]["native_session_id"])
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            status, denied = h.api(method, BASE + "/" + command, data, timeout=8)
            check(status == 405, "unsupported signing method accepted")
            public(denied)
    strict_unchanged(f, before, counters, "input_refusal")
    attached = project(h, "router")
    credential = h.ok("adapter", "create", "--session", attached["review"]["session_id"], "--expires-at", rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, attached["review"]["agent"], attached["review"]["session_id"], credential)
    check(adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id, "session_id": adapter.session_id,
        "instance_id": adapter.instance})[0] == 200, "real adapter authentication prerequisite")
    cert, key = suite.work / "boundary-cert.pem", suite.work / "boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=boundary", "-days", "1",
        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    for command in ("signing", "sign"):
        data = signing_input(f, h, parent, prepared, sign=command == "sign"); endpoint = BASE + "/" + command
        status, denied = adapter.call("POST", endpoint, data)
        check(status == 404, "scoped adapter exposed owner signing")
        public(denied, adapter.token, adapter.instance)
        result = subprocess.run([str(suite.probe_bin), "--state", str(f["a"].state), "--address", peer_address(h), "--alpn", "peerspan-peer/1",
            "--path", endpoint, "--method", "POST", "--body-stdin"], input=compact(data), capture_output=True, timeout=15)
        check(result.returncode == 0 and json.loads(result.stdout).get("status") == 404, "authenticated normal peer exposed owner signing")
        public(result.stderr.decode(errors="replace"))
        address, port = h.relay.address.split(":"); encoded = compact(data)
        with socket.create_connection((address, int(port)), timeout=5) as connection:
            with tls.wrap_socket(connection, server_hostname="peerspan") as stream:
                stream.sendall((f"POST {endpoint} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n").encode() + encoded)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, "bootstrap exposed owner signing")
    missing = suite.host("missing", start=False); shutil.rmtree(missing.state)
    original_files = files(missing.root)
    for command in ("signing", "sign"):
        result = missing.cli("onboarding", "access", command, "--stdin", input=compact(signing_input(f, h, parent, prepared, sign=command == "sign")).decode(), timeout=8)
        check(not result.ok and purity_missing_files_diagnostic(files(missing.root), original_files) == original_files and not missing.state.exists(), "CLI initialized absent daemon")
        public(result.stdout + result.stderr, str(missing.state), context(parent)["project_root"], context(parent)["native_session_id"])
    database = db_path(h); action_id = prepared["access"]["review"]["intent_id"]; receipt_id = prepared["access"]["access_id"]
    for fault in ("role", "slot", "signature", "completed", "reference", "receipt"):
        h.stop(kill=True)
        target = receipt_id if fault in {"reference", "receipt"} else action_id
        with closing(sqlite3.connect(database)) as db, db:
            original = db.execute("SELECT record FROM dec_intents WHERE intent_id=?", (target,)).fetchone()[0]
            corrupt = json.loads(original)
            if fault == "reference":
                absent_id = "dint_" + "f" * 32
                check(db.execute("SELECT 1 FROM dec_intents WHERE intent_id=?", (absent_id,)).fetchone() is None, "negative reference is not absent")
                review = json.loads(base64.b64decode(corrupt["review_base64"], validate=True)); review["intent_id"] = absent_id
                corrupt["review_base64"] = base64.b64encode(canonical(review)).decode()
            elif fault == "receipt":
                corrupt["host_public_key"] = f["a"].public_key
            elif fault == "completed":
                corrupt["completed"] = False
            elif fault in {"role", "slot"}:
                corrupt["signatures"][0]["role" if fault == "role" else "slot_id"] = "host" if fault == "role" else 2
            else:
                raw_signature = base64.b64decode(corrupt["signatures"][0]["signature"], validate=True)
                corrupt["signatures"][0]["signature"] = base64.b64encode(raw_signature[:-1] + bytes([raw_signature[-1] ^ 1])).decode()
            db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (compact(corrupt).decode(), target))
        try:
            h.start(); directory(f); stable(f)
            pure_operation(f, h, parent, prepared, status=409, code="access_signing_unavailable")
            pure_operation(f, h, parent, prepared, "sign", status=409, code="access_signing_unavailable")
        finally:
            h.stop(kill=True)
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("UPDATE dec_intents SET record=? WHERE intent_id=?", (original, target))
    check(records(h)["$schema"] == f["schema"] and records(h)["$version"] == (27,), "signature continuation changed schema27")
    print("LIMIT output_bounds: no genuine oversized/unsafe frozen section31 receipt or aggregate capacity boundary; no authority/template/seed fabricated", flush=True)


suite.finish()
