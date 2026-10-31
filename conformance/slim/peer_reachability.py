#!/usr/bin/env python3
"""Section38 selected-machine reachability; independent public conformance.

One genuine bootstrap-only two-person/two-host DEC ceremony precedes strict
no-route purity, then ordinary current counted direct hints enable positive
pinned exchanges. No protocol/authority row edits, worker suppression, key
removal or invented crypto. All365 native and29 old slim/helper files stay exact.
Only new-suite copies of independent public fixture helpers are used.

Both bootstrap TCP relays and every enabled peer UDP path are counted. Expected
explicit peer traffic is separated from strict complete DB/state/home purity;
nonselected paths stay idle. Actual consumed UDP barrier gates a dispatched
exchange outside any database transaction. No diagnostic prints private values.
Limits: no hosted helper/relay, encrypted application-GET counts/reused-connection retry attribution, real pinned
403/404/500 custom server, partial/malformed/oversized encrypted response fixture,
concurrent root/policy mutation or actual peer/model/incoming delivery acceptance.
A real authenticated200 grants no permission or combined readiness assertion.
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
import subprocess
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, create_network,
                     join_new_person, parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for)
from counted_peer import exchange_current_contacts, peer_address

suite = Suite("peer_reachability", __doc__)
BASE = "/v1/onboarding/reachability"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ("psi2-", "psl2-", "peerspan-invite-v1.", "peerspan-member-invite-v1.",
            "peerspan-person-invite-v1.", "token_", "instance_")
TOP = set("version host_id context observed_at review_id review next_action".split())
REVIEW = set("version kind host_id context agent network root_state_id owner participant policy effects".split())
MEMBER = set("host_public_key member person_public_key host_lease_id binding_lease_id device_lease_id not_after".split())
PERSON = set("person_public_key member person_lease_id not_after".split())
CONTENT = {"rules", "capability_rules", "trusted_hosts"}
EFFECTS = {"inspect_current_membership": True, "inspect_current_policy": True,
           "prepare_access": False, "approve_access": False, "sign_policy": False,
           "publish_policy": False, "grant_agent_access": False, "share_files": False,
           "share_conversation": False, "capability_calls": False}
state = {}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def get(h, path):
    status, value = h.api("GET", path, timeout=8)
    check(status == 200, f"public fixture observation HTTP {status}")
    return value


def public(value, *secrets):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    for n, marker in enumerate((*PREFIXES, "payload_base64", "template_base64", "message_base64",
                                "signing_requests", "return_secret", '"signature"', '"seed"',
                                "admin.sock", "adapter.sock", *secrets)):
        check(not marker or marker not in text, f"inspection leaked private material rule{n}")


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


def payload(parent, net, person):
    return {"context": context(parent), "network_id": net, "person_public_key": person}


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


def validate(h, parent, net, person, value, bounds):
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1,
          "closed access-inspection wrapper/version")
    check(value["host_id"] == h.id and value["context"] == context(parent)
          and value["next_action"] == "review_agent_access", "exact inspection wrapper binding/action")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]) is not None
          and bounds[0] - timedelta(seconds=1) <= parse_time(value["observed_at"]) <= bounds[1] + timedelta(seconds=1),
          "canonical current inspection time")
    review = value["review"]
    check(type(review) is dict and set(review) == REVIEW and type(review["version"]) is int
          and review["version"] == 1 and review["kind"] == "inspect_project_agent_access", "closed access review")
    check(review["host_id"] == h.id and review["context"] == context(parent)
          and review["agent"] == parent["review"]["agent"], "project and original complete agent binding")
    network = get(h, f"/v2/networks/{net}")
    check(review["network"] == {key: network[key] for key in ("id", "name", "context_id")}
          and review["root_state_id"] == network["root_state_id"], "exact current network/root binding")
    people = get(h, f"/v2/networks/{net}/persons")["persons"]
    machines = get(h, f"/v2/networks/{net}/members")["members"]
    check(all(set(p) == PERSON for p in people) and all(set(m) == MEMBER for m in machines), "ordinary member/person shapes")
    own = next(p for p in people if p["person_public_key"] == network["person_public_key"])
    selected = next(p for p in people if p["person_public_key"] == person)
    mine = next(m for m in machines if m["host_public_key"] == h.public_key)
    check(review["owner"] == {**{k: own[k] for k in ("person_public_key", "member", "person_lease_id")}, "host": mine},
          "local own-person binding differs from verified ordinary membership")
    check(review["participant"] == {**selected, "hosts": sorted(
        [m for m in machines if m["person_public_key"] == person], key=lambda m: m["host_public_key"])},
          "selected person, complete sorted machines or finite P/H/B references differ")
    observed = parse_time(value["observed_at"])
    for finite in (selected["not_after"], mine["not_after"], *[m["not_after"] for m in review["participant"]["hosts"]]):
        check(parse_time(finite) > observed, "inspection returned expired membership")
    ordinary = current_policy(h, net, own["person_public_key"])
    policy = review["policy"]
    if ordinary is None:
        check(policy is None, "genuinely absent policy was not null")
    else:
        current, _, signed, body = ordinary
        check(type(policy) is dict and set(policy) == {"statement_id", "proof_id", "body", "enforced_content", "valid_until"},
              "closed policy projection")
        check(policy["statement_id"] == current["statement_id"] and policy["body"] == body,
              "inspection rewrote or truncated verified signed PolicyBody")
        enforced = policy["enforced_content"]
        check(set(enforced) == CONTENT and enforced["capability_rules"] == body["capability_rules"]
              and enforced["trusted_hosts"] == body["trusted_hosts"], "settled capability/trust content differs")
        # max_artifact_bytes is optional and defaults to zero in ordinary
        # Content. Compare its documented value, while body above retains the
        # exact signed JSON field presence. This is no authorization evaluator.
        check([{**rule, "max_artifact_bytes": rule.get("max_artifact_bytes", 0)} for rule in enforced["rules"]] ==
              [{**rule, "max_artifact_bytes": rule.get("max_artifact_bytes", 0)} for rule in body["rules"]],
              "settled rules lost actions, principals, byte bounds or default values")
        # Every fixture policy ends within 24h and its genuine P/H/B/device
        # parents last seven days. Its own signed end is the ancestry minimum.
        check(observed < parse_time(policy["valid_until"]) and policy["valid_until"] == signed["not_after"],
              "exact policy effective ancestry bound")
    check(review["effects"] == EFFECTS, "membership/policy observation inferred consent, operation access, sharing or readiness")
    digest = hashlib.sha256(b"peerspan-project-access-inspection-v1\n" +
        json.dumps(review, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    check(value["review_id"] == "review_" + digest, "canonical digest does not bind every review term")
    check(len(compact(value)) <= 2 * 1024 * 1024, "inspection exceeded public output bound")
    public(value)


def db_path(h):
    paths = []
    for path in h.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                paths.append(path)
    check(len(paths) == 1, "expected exactly one ordinary host database")
    return paths[0]


def records(h):
    result = {}
    for path in sorted(h.state.glob("*.db")):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)) as db, db:
            db.execute("BEGIN")
            value = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                     "$version": db.execute("PRAGMA user_version").fetchone()}
            for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                value[name] = tuple(sorted(db.execute('SELECT * FROM "' + name.replace('"', '""') + '"'), key=repr))
            result[path.name] = value
    check(result, "no actual databases in reachability snapshot")
    return result


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
    h.readiness_maintenance_pass = getattr(h, "readiness_maintenance_pass", 0) + 1
    key = ssh_key(suite.work, "readiness-maintenance-" + h.name + "-" + str(h.readiness_maintenance_pass))
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


def advance(f, target):
    for local in (f["a"], f["b"]):
        members = get(local, "/v2/networks/" + f["net"] + "/members")["members"]
        people = get(local, "/v2/networks/" + f["net"] + "/persons")["persons"]
        check(all(target < parse_time(row["not_after"]) for row in [*members, *people]), "genuine fixture clock exceeds verified membership")
        for person in (f["alice"], f["bob"]):
            policy = current_policy(local, f["net"], person)
            if policy:
                check(target < parse_time(policy[2]["not_after"]), "fixture retirement exceeds current retained policy bound")
        local.clock.set(local.clock.offset + math.ceil((target - local.now()).total_seconds()))


def current_contacts(f, window_seconds):
    for local in (f["a"], f["b"]):
        net = get(local, "/v2/networks/" + f["net"])
        check(net["authority"]["state"] == "usable", "pure readiness fixture lacks current authority")
        for remote in (f["a"], f["b"]):
            with closing(sqlite3.connect(f"file:{db_path(local)}?mode=ro", uri=True)) as db:
                row = db.execute("SELECT sequence,record FROM dec_contacts WHERE network_id=? AND context_id=? AND host_key=?",
                    (f["net"], net["context_id"], remote.public_key)).fetchone()
            check(row is not None, "pure fixture lacks retained bound current signed contact")
            sequence = int.from_bytes(row[0], "big") if type(row[0]) is bytes else row[0]
            record = json.loads(row[1])
            check(record["format"] == 1 and record["conflicted"] is False and record["contacts_base64"], "current contact is conflicted or absent")
            for raw_contact in record["contacts_base64"]:
                contact = json.loads(base64.b64decode(raw_contact, validate=True))
                hints = base64.b64decode(contact["payload_base64"], validate=True)
                check(contact["host_public_key"] == remote.public_key and contact["context_id"] == net["context_id"]
                      and contact["sequence"] == sequence and parse_time(contact["expires_at"]) > local.now() + timedelta(seconds=window_seconds)
                      and json.loads(hints) == {"bootstrap_addresses": [remote.relay.address], "quic_addresses": [peer_address(remote)], "relays": []},
                      "current retained signed contact expired or enables an uncounted carrier")
                message = "\n".join(("peerspan-decentralized-contact-v1", contact["context_id"], contact["host_public_key"],
                    str(contact["sequence"]), contact["issued_at"], contact["expires_at"], hashlib.sha256(hints).hexdigest()))
                check(hashlib.sha256(message.encode()).hexdigest() in record["message_hashes"], "actual signed contact guard mismatch")


def sync_directory(f):
    for local, remote in ((f["a"], f["b"]), (f["b"], f["a"])):
        status, synced = local.api("POST", "/v2/networks/" + f["net"] + "/sync", {}, timeout=35)
        check(status == 200 and remote.public_key in synced["attempted"] and synced["unavailable"] == [],
              "genuine explicit ordinary sync has unavailable or missing participant")
        status, view = local.api("POST", "/v1/directory/refresh?network=" + f["net"], {}, timeout=12)
        check(status == 200 and any(row["host_id"] == remote.id and row["state"] == "ok" for row in view["hosts"]),
              "genuine authenticated startup directory query not completed")


class CountedBarrierUDP:
    """Opaque QUIC relay, with an actual consumed-datagram dispatch barrier."""
    def __init__(self, target):
        self.target = target
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.address = "127.0.0.1:" + str(self.socket.getsockname()[1])
        self.lock, self.done = threading.Lock(), threading.Event()
        self.routes, self.pending = {}, []
        self.received_datagrams = self.received_bytes = 0
        self.returned_datagrams = self.returned_bytes = 0
        self.armed = False
        self.dispatch = threading.Event()
        self.generation = 0
        self.thread = threading.Thread(target=self._forward, daemon=True)
        self.thread.start()
        atexit.register(self.close)

    def _send(self, data, client):
        if client not in self.routes:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.bind(("127.0.0.1", 0))
            upstream.connect(self.target)
            self.routes[client] = upstream
        try:
            self.routes[client].send(data)
        except OSError:
            pass

    def _forward(self):
        try:
            while not self.done.is_set():
                with self.lock:
                    queued = [] if self.armed else self.pending[:]
                    if not self.armed:
                        self.pending.clear()
                for data, client in queued:
                    self._send(data, client)
                upstreams = {upstream: client for client, upstream in self.routes.items()}
                ready, _, _ = select.select([self.socket, *upstreams], [], [], .02)
                for source in ready:
                    if source is self.socket:
                        data, client = self.socket.recvfrom(65536)
                        with self.lock:
                            self.received_datagrams += 1
                            self.received_bytes += len(data)
                            if self.armed:
                                self.pending.append((data, client))
                                self.generation += 1
                                self.dispatch.set()
                                continue
                        self._send(data, client)
                    else:
                        try:
                            data = source.recv(65536)
                        except OSError:
                            continue
                        with self.lock:
                            self.returned_datagrams += 1
                            self.returned_bytes += len(data)
                        self.socket.sendto(data, upstreams[source])
        except OSError:
            pass

    def arm(self):
        with self.lock:
            check(not self.pending and not self.armed, "counted QUIC barrier already active")
            self.dispatch.clear()
            self.armed = True
            return self.generation

    def held(self, generation):
        with self.lock:
            return self.armed and self.generation > generation and bool(self.pending)

    def release(self):
        with self.lock:
            self.armed = False

    def counts(self):
        with self.lock:
            return self.received_datagrams, self.received_bytes, self.returned_datagrams, self.returned_bytes

    def close(self):
        if self.done.is_set():
            return
        self.done.set()
        self.thread.join(timeout=1)
        self.socket.close()
        for upstream in self.routes.values():
            upstream.close()


def transport_config(h):
    path = h.root / "transport.json"
    path.write_bytes(compact({"format": 1, "advertise_bootstrap": [h.relay.address],
        "advertise_quic": [h.counted_peer.address] if h.direct else [],
        "rendezvous": [], "relays": [], "publish_contacts": False}))
    path.chmod(0o600)
    return path


def host(name):
    """Public bootstrap-only run first; enable the ordinary peer listener later."""
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    h.relay = Relay(("127.0.0.1", h.bootstrap_port))
    h.counted_peer = CountedBarrierUDP(("127.0.0.1", h.peer_port))
    h.direct = False
    h.extra_args = ["--transport-config", transport_config(h), "--person-key-file", h.root / "absent-person-key"]
    h.extra_env = {"SSH_AUTH_SOCK": str(h.root / "absent-agent.sock")}
    normal = h.start
    def start():
        h.started_at = time.monotonic()
        if h.direct:
            return normal()
        check(h.process is None, "bootstrap-only fixture is already running")
        with h.log.open("ab") as log:
            h.process = subprocess.Popen([str(suite.host_bin), "--state", str(h.state), "run",
                "--bootstrap-listen", "127.0.0.1:" + str(h.bootstrap_port), *map(str, h.extra_args)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=h.env, start_new_session=True)
        wait_for(lambda: (h.state / "admin.sock").exists() and h._ping(), timeout=30, message="bootstrap-only owner socket")
        info = get(h, "/v1/host")
        h.id, h.public_key = info["id"], info["public_key"]
        return h
    h.start = start
    return h.start()


def whole(f):
    return snapshot(f["a"]), snapshot(f["b"])


def strict_state(f, before, phase):
    after = whole(f)
    if after != before:
        try:
            summary = {"phase": phase, "participants": []}
            for role, old, new in zip(("target", "project"), before, after):
                tables = []
                for database in set(old[0]) | set(new[0]):
                    for table in set(old[0].get(database, {})) | set(new[0].get(database, {})):
                        if old[0].get(database, {}).get(table) != new[0].get(database, {}).get(table):
                            tables.append(table if re.fullmatch(r"[a-z][a-z0-9_]{0,63}|\$schema|\$version", table) else "unknown")
                summary["participants"].append({"role": role, "changed_tables": sorted(tables),
                    "state_changed_count": sum(old[1].get(k) != new[1].get(k) for k in set(old[1]) | set(new[1])),
                    "home_changed_count": sum(old[2].get(k) != new[2].get(k) for k in set(old[2]) | set(new[2]))})
            print("reachability_purity_public=" + json.dumps(summary, sort_keys=True), flush=True)
        except Exception:
            pass
    check(after == before, "reachability changed complete logical schemas/DB/authority/clock/consent/private state or home")


def no_io(f, before, phase):
    after = traffic(f)
    if after != before:
        print("reachability_carriers_public=" + json.dumps({"phase": phase,
            "deltas": [[x-y for x, y in zip(a, b)] for a, b in zip(after, before)]}), flush=True)
    check(after == before, "guarded/no-route reachability used a counted TCP or UDP carrier")


def selected_io(f, before):
    after = traffic(f)
    check(after[:2] == before[:2] and after[3] == before[3], "reachability used a bootstrap or nonselected peer carrier")
    check(after[2][0] > before[2][0] and after[2][1] > before[2][1], "explicit selected pinned peer exchange was not dispatched")


def request(f, parent=None, *, person=None, peer=None):
    return {**payload(parent or f["pb"], f["net"], person or f["alice"]), "peer_host_id": peer or f["a"].id}


def verify(f, parent, body, value, bounds):
    h = f["b"]
    check(type(value) is dict and set(value) == set("version host_id context observed_at inspection reachability".split()),
          "closed reachability wrapper")
    check(type(value["version"]) is int and value["version"] == 1 and value["host_id"] == h.id
          and value["context"] == body["context"], "exact local host/project binding")
    inspected = value["inspection"]
    check(type(inspected) is dict and set(inspected) == {"review_id", "review"}, "closed complete inspection envelope")
    validate(h, parent, body["network_id"], body["person_public_key"], {"version": 1, "host_id": h.id,
        "context": body["context"], "observed_at": value["observed_at"], **inspected, "next_action": "review_agent_access"}, bounds)
    result = value["reachability"]
    check(type(result) is dict and set(result) == set("direction peer_host_id peer_host_public_key result http_status incoming_delivery model_receipt connection_readiness".split()),
          "closed public reachability result")
    remote = [row for row in inspected["review"]["participant"]["hosts"]
              if "host_" + hashlib.sha256(base64.b64decode(row["host_public_key"], validate=True)).hexdigest() == body["peer_host_id"]
              and row["host_public_key"] != h.public_key]
    check(len(remote) == 1 and result["peer_host_id"] == body["peer_host_id"]
          and result["peer_host_public_key"] == remote[0]["host_public_key"], "exact selected remote public key/derived ID")
    check(result["direction"] == "project_host_to_participant_host"
          and all(result[k] == "not_verified" for k in ("incoming_delivery", "model_receipt", "connection_readiness")),
          "outbound reachability became permission, incoming delivery, model receipt or overall readiness")
    check((result["result"] == "authenticated_response" and type(result["http_status"]) is int and 200 <= result["http_status"] <= 599)
          or (result["result"] == "not_verified" and result["http_status"] is None), "invalid authenticated/negative HTTP evidence")
    check(len(compact(value)) <= 2 * 1024 * 1024, "reachability output bound")
    public(value, *f["secrets"], f["a"].relay.address, f["b"].relay.address, peer_address(f["a"]), peer_address(f["b"]))
    return value


def observe(f, *, parent=None, body=None, status=200, code=None, outcome=None):
    parent = parent or f["pb"]
    body = body or request(f, parent)
    began = f["b"].now()
    actual, value = f["b"].api("POST", BASE, body, timeout=13)
    ended = f["b"].now()
    check(actual == status, f"explicit reachability HTTP {actual}, want {status}")
    if status == 200:
        verify(f, parent, body, value, (began, ended))
        if outcome:
            if value["reachability"]["result"] != outcome:
                try:
                    allowed = {"authenticated_response", "not_verified"}
                    process = f["a"].process
                    poll = process.poll() if process is not None else "absent"
                    process_status = "running" if poll is None else "absent" if poll == "absent" else (
                        "exited_zero" if poll == 0 else "exited_nonzero" if type(poll) is int else "unknown")
                    observed_status = value["reachability"]["http_status"]
                    print("reachability_outcome_public=" + json.dumps({
                        "expected": outcome if outcome in allowed else "unknown",
                        "actual": value["reachability"]["result"] if value["reachability"]["result"] in allowed else "unknown",
                        "http_status": observed_status if observed_status is None or type(observed_status) is int and 200 <= observed_status <= 599 else "unknown",
                        "target_process_running": process is not None and poll is None,
                        "target_process_status": process_status,
                        "target_udp_thread_alive": f["a"].counted_peer.thread.is_alive(),
                        "project_udp_thread_alive": f["b"].counted_peer.thread.is_alive(),
                        "carriers": traffic(f)}, sort_keys=True), flush=True)
                except Exception:
                    pass
            check(value["reachability"]["result"] == outcome, "unexpected explicit transport observation")
    else:
        check(type(value) is dict and (code is None or value.get("code") == code)
              and "inspection" not in value and "reachability" not in value, "refusal became empty successful evidence or wrong fixed code")
        public(value, body["context"]["project_root"], body["context"]["native_session_id"], *f["secrets"])
    return value


def raw(h, data):
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=13)
    try:
        try:
            connection.request("POST", BASE, body=data, headers={"Content-Type": "application/json"})
        except BrokenPipeError:
            pass
        response = connection.getresponse()
        value = response.read()
        return response.status, json.loads(value) if value else None
    finally:
        connection.close()


def restart_project(f):
    old = f["pb"]
    f["pb"] = project(f["b"], "current", old=old, agent={"kind": "existing", "id": old["review"]["agent"]["id"]})


def bootstrap_retry_times(f, diagnostic=None):
    """All genuine retained outboxes, without editing/filtering retry state."""
    retry_times = []
    if diagnostic is not None:
        diagnostic["participants"] = []
    for role, local in (("target", f["a"]), ("project", f["b"])):
        observed = {"role": role, "pending_secrets": "unknown", "pending_readcaps": "unknown",
                    "frames": "unknown", "journals": "unknown", "retry_seconds_remaining": []}
        if diagnostic is not None:
            diagnostic["participants"].append(observed)
        with closing(sqlite3.connect(f"file:{db_path(local)}?mode=ro", uri=True)) as db:
            # Same rows/query as before; project the two constituent counts too.
            pending = db.execute("SELECT count(*),sum(secret IS NOT NULL),sum(terminal_read_cap IS NOT NULL) "
                "FROM dec_pending WHERE secret IS NOT NULL OR terminal_read_cap IS NOT NULL").fetchone()
            observed["pending_secrets"], observed["pending_readcaps"] = int(pending[1] or 0), int(pending[2] or 0)
            if pending[0]:
                return None
            frames = db.execute("SELECT count(*) FROM dec_frames").fetchone()[0]
            observed["frames"] = frames
            if frames:
                return None
            for (record,) in db.execute("SELECT record FROM dec_outbox"):
                value = json.loads(record)
                check(type(value) is dict and type(value.get("next_attempt_at")) is str,
                      "ordinary outbox lacks a documented retry timestamp")
                deadline = parse_time(value["next_attempt_at"])
                retry_times.append(deadline)
                observed["retry_seconds_remaining"].append({
                    "target_clock": round((deadline - f["a"].now()).total_seconds(), 3),
                    "project_clock": round((deadline - f["b"].now()).total_seconds(), 3)})
        journals = list(local.state.glob("*-journal"))
        observed["journals"] = len(journals)
        if journals:
            return None
    if any(local.now() + timedelta(seconds=2) >= deadline for local in (f["a"], f["b"]) for deadline in retry_times):
        return None
    return {"retry_times": retry_times}


def bootstrap_quiet(f, h):
    previous = snapshot(h), traffic(f)
    started = stable_since = time.monotonic()
    samples = []
    def settled():
        nonlocal previous, stable_since
        current = snapshot(h), traffic(f)
        if current != previous:
            stable_since = time.monotonic()
        old = previous
        previous = current
        diagnostic = {}
        window = bootstrap_retry_times(f, diagnostic)
        try:
            logical = {name: 0 for name in ("$schema", "$version", "dec_outbox", "dec_pending", "dec_frames",
                "dec_contacts", "dec_decision_clock", "dec_clock", "decision_clock", "other")}
            for database in set(old[0][0]) | set(current[0][0]):
                for table in set(old[0][0].get(database, {})) | set(current[0][0].get(database, {})):
                    if old[0][0].get(database, {}).get(table) != current[0][0].get(database, {}).get(table):
                        logical[table if table in logical else "other"] += 1
            diagnostic.update({"elapsed_ms": int((time.monotonic() - started) * 1000),
                "since_stable_ms": int((time.monotonic() - stable_since) * 1000),
                "logical_table_changes": logical,
                "state_file_changes": sum(old[0][1].get(k) != current[0][1].get(k) for k in set(old[0][1]) | set(current[0][1])),
                "home_file_changes": sum(old[0][2].get(k) != current[0][2].get(k) for k in set(old[0][2]) | set(current[0][2])),
                "carrier_deltas": [[x-y for x, y in zip(a, b)] for a, b in zip(current[1], old[1])],
                "retry_window_available": window is not None})
            samples.append(diagnostic)
            del samples[:-8]
        except Exception:
            pass
        return window if time.monotonic() - stable_since >= .3 and window is not None else None
    try:
        return wait_for(settled, timeout=5, interval=.1, message="genuine whole-state no-route quiescence before all retained retry times")
    except Exception:
        try:
            print("reachability_bootstrap_quiet_public=" + json.dumps({"participant": "target" if h is f["a"] else "project",
                "samples": samples}, sort_keys=True), flush=True)
        except Exception:
            pass
        raise


def before_retries(f, window):
    check(all(local.now() < deadline for local in (f["a"], f["b"]) for deadline in window["retry_times"]),
          "no-route capture crossed an actual retained outbox retry time")


def world():
    if state:
        check("pb" in state and "ready" in state, "shared genuine bootstrap/direct prerequisite did not finish")
        return state
    state["building"] = True
    a, b = host("a"), host("b")
    net = create_network(a, "Reachability 東京", "alice")
    key = ssh_key(b.root, "bob")
    rid = join_new_person(a, b, "bob", key, net["id"])
    bounds = []
    for local in (a, b):
        with closing(sqlite3.connect(f"file:{db_path(local)}?mode=ro", uri=True)) as db:
            bounds.extend(row[0] for row in db.execute("SELECT deadline FROM dec_pending WHERE request_id LIKE 'di_%'"))
    state.update(a=a, b=b, net=net["id"], alice=net["person_public_key"], bob=ssh_public_base64(key),
        request_id=rid, request_deadline=get(b, "/v2/link/requests/" + rid)["expires_at"], invitation_bounds=bounds,
        pb=project(b, "bootstrap"), secrets=[])
    target = max(*[parse_time(x) for x in [*bounds, state["request_deadline"]]], a.now(), b.now()) + timedelta(seconds=1)
    advance(state, target)
    for local in (a, b):
        unsigned_maintenance(local)
        local.restart()
    restart_project(state)
    for local in (a, b):
        retry_window = bootstrap_quiet(state, local)
    before, counts = whole(state), traffic(state)
    before_retries(state, retry_window)
    observe(state, outcome="not_verified")
    began = b.now()
    result = b.cli("onboarding", "reachability", "--stdin", input=compact(request(state)).decode(), timeout=16)
    check(result.ok, "bootstrap-only no-route private CLI failed")
    verify(state, state["pb"], request(state), result.json, (began, b.now()))
    check(result.json["reachability"]["result"] == "not_verified", "bootstrap-only request invented a usable peer route")
    strict_state(state, before, "no_current_route"); no_io(state, counts, "no_current_route")
    before_retries(state, retry_window)
    state["no_route_pure"] = True
    for local in (a, b):
        local.direct = True
        transport_config(local)
        local.restart()
    for local, remote in ((a, b), (b, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", peer_address(remote))
    short = exchange_current_contacts(suite, a, b, state["net"])
    advance(state, max(*[parse_time(x) for x in short], a.now(), b.now()) + timedelta(seconds=1))
    for local in (a, b):
        unsigned_maintenance(local)
        local.restart()
    sync_directory(state)
    current_contacts(state, 55)
    restart_project(state)
    state["pa"] = project(a, "target")
    for local in (a, b):
        quiet(state, local, require_retirement=True)
    state["fresh_window"] = min(a.started_at, b.started_at)
    state["ready"] = True
    return state


def directory(f):
    result = subprocess.run([str(suite.probe_bin), "--state", str(f["b"].state), "--address", peer_address(f["a"]),
        "--alpn", "peerspan-peer/1", "--path", "/peer/v1/networks/" + f["net"] + "/agents", "--method", "GET"],
        input=b"", capture_output=True, timeout=15)
    try:
        value = json.loads(result.stdout)
    except ValueError:
        value = None
    status = value.get("status") if type(value) is dict else None
    body = value.get("body") if type(value) is dict else None
    check(result.returncode == 0 and status == 200 and type(body) is list,
          f"ordinary directory prerequisite HTTP {status if type(status) is int else 'unknown'}, body {'array' if type(body) is list else 'unknown'}")
    return body


def within_window(f):
    check(time.monotonic() - f["fresh_window"] < 60, "fixture crossed first ordinary anti-entropy boundary")


@suite.case("exact_pinned_api_cli_public_shape_empty_directory_without_adapter", "guided38 verification1,5 no-route prerequisite")
def _():
    f = world()
    check(f["no_route_pure"], "genuine bootstrap-only negative purity prerequisite missing")
    check(directory(f) == [], "membership/metadata-only target unexpectedly advertised an agent")
    before = traffic(f)
    first = observe(f, outcome="authenticated_response")
    check(first["reachability"]["http_status"] == 200, "genuine authenticated receiver did not return200")
    selected_io(f, before)
    h = f["b"]; began = h.now()
    result = h.cli("onboarding", "reachability", "--stdin", input=compact(request(f)).decode(), timeout=16)
    check(result.ok, "exact private reachability CLI failed")
    verify(f, f["pb"], request(f), result.json, (began, h.now()))
    check(result.json["reachability"]["result"] == "authenticated_response" and result.json["reachability"]["http_status"] == 200,
          "private CLI changed authenticated response evidence")
    check(result.json["inspection"] == first["inspection"], "stable complete inspection/digest changed across API/CLI")
    public(result.stderr, request(f)["context"]["project_root"], request(f)["context"]["native_session_id"], str(h.state))
    check(get(h, "/v1/sessions/" + f["pb"]["review"]["session_id"])["agent_id"] == f["pb"]["review"]["agent"]["id"],
          "reachability changed exact metadata-only session")
    within_window(f)


@suite.case("changed_receiver_grants_remain_distinct_from_reachability_and_wrong_pin_refuses", "guided38 verification2")
def _():
    f = world(); a, b = f["a"], f["b"]
    agent = f["pa"]["review"]["agent"]
    issued = a.ok("grant", "create", "--peer", b.id, "--agent", agent["id"],
        "--expires-at", rfc3339(a.now() + timedelta(hours=1)), "--max-message-bytes", "12345", "--allow-disconnected")
    entries = directory(f)
    check(any(row["agent_id"] == agent["id"] and any(auth.get("grant_id") == issued["id"] for auth in row["authorizations"])
              for row in entries), "ordinary target grant was not advertised")
    permitted = observe(f, outcome="authenticated_response")
    a.ok("grant", "revoke", issued["id"])
    check(directory(f) == [], "ordinary receiver withdrawal remained advertised")
    withdrawn = observe(f, outcome="authenticated_response")
    check(permitted["reachability"] == withdrawn["reachability"] and withdrawn["reachability"]["http_status"] == 200,
          "receiver permissions changed the meaning of outbound transport evidence")
    # Public manual hints have ordinary precedence, but never override the key.
    b.ok("peer", "add", "--id", a.id, "--public-key", a.public_key, "--address", peer_address(b))
    # A fresh ordinary process prevents an already authenticated cached QUIC
    # connection from making this purported wrong-server stimulus irrelevant.
    b.restart()
    restart_project(f)
    try:
        denied = observe(f, outcome="not_verified")
        check(denied["reachability"]["http_status"] is None, "wrong real server key was authenticated as the selected target")
    finally:
        b.ok("peer", "add", "--id", a.id, "--public-key", a.public_key, "--address", peer_address(a))
        b.restart()
        restart_project(f)
    observe(f, outcome="authenticated_response")
    within_window(f)


@suite.case("exact_current_target_context_and_replaced_parent_refuse_before_all_peer_io", "guided38 verification3")
def _():
    f = world(); h = f["b"]; original = f["pb"]
    unused = ssh_key(suite.work, "unused-person")
    body = request(f)
    refusals = [({**body, "peer_host_id": "host_" + "0" * 64}, 409, "reachability_unavailable"),
        ({**body, "peer_host_id": h.id}, 409, "reachability_unavailable"),
        ({**body, "person_public_key": f["bob"], "peer_host_id": h.id}, 409, "reachability_unavailable"),
        ({**body, "person_public_key": ssh_public_base64(unused)}, 409, "access_inspection_unavailable"),
        ({**body, "network_id": "net_" + "0" * 64}, 404, "not_found"),
        ({**body, "context": {**body["context"], "project_flow_id": "flow_" + "0" * 32}}, 404, "not_found")]
    for field, value in (("project_root", str(suite.work / "different-project")), ("native_session_id", "different-conversation"),
                         ("project_review_id", "review_" + "0" * 64)):
        refusals.append(({**body, "context": {**body["context"], field: value}}, 409, "review_changed"))
    for local in (f["a"], h):
        quiet(f, local, require_retirement=True)
    before, counters = whole(f), traffic(f)
    for invalid, status, code in refusals:
        observe(f, body=invalid, status=status, code=code)
    strict_state(f, before, "preflight_guards"); no_io(f, counters, "preflight_guards")
    check(h.api("POST", "/v1/sessions/" + original["review"]["session_id"] + "/detach", {})[0] == 200,
          "ordinary detached-parent prerequisite")
    before, counters = whole(f), traffic(f)
    observe(f, parent=original, status=409, code="review_changed")
    strict_state(f, before, "detached_parent"); no_io(f, counters, "detached_parent")
    restart_project(f)
    before, counters = whole(f), traffic(f)
    observe(f, parent=original, status=409, code="review_changed")
    strict_state(f, before, "replaced_parent"); no_io(f, counters, "replaced_parent")
    observe(f, outcome="authenticated_response")
    within_window(f)


@suite.case("actual_dispatched_counted_exchange_rechecks_detached_parent_without_lock_or_rebind", "guided38 verification4")
def _():
    f = world(); h, target = f["b"], f["a"]
    for local in (target, h):
        quiet(f, local, require_retirement=True)
    old = f["pb"]; body = request(f); counts = traffic(f)
    generation = target.counted_peer.arm()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(h.api, "POST", BASE, body, 13)
        try:
            check(target.counted_peer.dispatch.wait(3) and target.counted_peer.held(generation),
                  "reachability did not dispatch real counted datagrams into the registered barrier")
            check(not pending.done(), "counted held exchange unexpectedly completed")
            # This ordinary writer must finish while network IO is still held.
            check(h.api("POST", "/v1/sessions/" + old["review"]["session_id"] + "/detach", {}, timeout=2)[0] == 200,
                  "in-flight reachability retained a database lock or blocked ordinary detachment")
            check(target.counted_peer.held(generation), "actual dispatched barrier was not held through context change")
        finally:
            target.counted_peer.release()
        status, denied = pending.result(timeout=13)
    check(status == 409 and type(denied) is dict and denied.get("code") in ("reachability_unavailable", "review_changed")
          and "reachability" not in denied and "inspection" not in denied,
          f"late old reachability result survived authoritative detachment HTTP {status}")
    public(denied, body["context"]["project_root"], body["context"]["native_session_id"])
    selected_io(f, counts)
    restart_project(f)
    # New explicit context works; no old result is rebound into it.
    observe(f, outcome="authenticated_response")
    within_window(f)


@suite.case("repeated_success_failed_route_and_no_route_preserve_complete_both_state_and_exact_carriers", "guided38 verification5")
def _():
    f = world(); h, target = f["b"], f["a"]
    check(f["no_route_pure"], "genuine no-current-route capture was omitted")
    for local in (target, h):
        quiet(f, local, require_retirement=True)
    before, counters = whole(f), traffic(f)
    for _ in range(2):
        observe(f, outcome="authenticated_response")
    began = h.now()
    result = h.cli("onboarding", "reachability", "--stdin", input=compact(request(f)).decode(), timeout=16)
    check(result.ok, "repeated private reachability read failed")
    verify(f, f["pb"], request(f), result.json, (began, h.now()))
    check(result.json["reachability"]["result"] == "authenticated_response", "repeat lost current pinned transport")
    strict_state(f, before, "repeated_success"); selected_io(f, counters)
    # A stopped target leaves only the same exact counted direct route. It is
    # transport failure, without route discovery/contact-learning fallback.
    target.stop()
    for local in (target, h):
        quiet(f, local, require_retirement=True)
    before, counters = whole(f), traffic(f)
    negative = observe(f, outcome="not_verified")
    check(negative["reachability"]["http_status"] is None, "dead selected route invented an HTTP response")
    strict_state(f, before, "failed_selected_route"); selected_io(f, counters)
    target.start()
    for local in (target, h):
        quiet(f, local, require_retirement=True)
    observe(f, outcome="authenticated_response")
    within_window(f)


@suite.case("closed_private_cli_api_missing_daemon_owner_routers_and_actual_expired_authority", "guided38 verification6,3 expired authority")
def _():
    f = world(); h = f["b"]; body = request(f); encoded = compact(body)
    maximum = encoded + b" " * (65536 - len(encoded))
    check(raw(h, maximum)[0] == 200, "exact64KiB reachability input refused")
    invalid = [b"null", b"[]", b"{", b"\xff", encoded + b"{}", maximum + b" ",
        encoded.replace(b'"context":', b'"context":null,"context":', 1),
        encoded.replace(b'"peer_host_id":', b'"peer_host_id":"host_' + b"0" * 64 + b'","peer_host_id":', 1)]
    for field in body:
        invalid.extend([compact({k: v for k, v in body.items() if k != field}), compact({**body, field: None})])
    for field in body["context"]:
        invalid.append(compact({**body, "context": {**body["context"], field: None}}))
    for extra in ({"address": "PRIVATE_INPUT"}, {"url": "PRIVATE_INPUT"}, {"public_key": "PRIVATE_INPUT"}, {"approve": "PRIVATE_INPUT"}):
        invalid.append(compact({**body, **extra}))
    invalid.extend([compact({**body, "peer_host_id": "host_1"}), compact({**body, "network_id": "net_1"}),
        compact({**body, "person_public_key": "bad"}), compact({**body, "context": {**body["context"], "extra": "PRIVATE_INPUT"}})])
    for local in (f["a"], h):
        quiet(f, local, require_retirement=True)
    before, counters = whole(f), traffic(f)
    for number, data in enumerate(invalid):
        status, denied = raw(h, data)
        check(status == 400 and type(denied) is dict and denied.get("code") == "invalid", f"malformed reachability input{number} HTTP {status}")
        public(denied, "PRIVATE_INPUT", body["context"]["project_root"], body["context"]["native_session_id"])
        result = h.cli("onboarding", "reachability", "--stdin", input=data.decode(errors="replace"), timeout=16)
        check(not result.ok, f"private reachability CLI accepted malformed input{number}")
        public(result.stdout + result.stderr, "PRIVATE_INPUT", body["context"]["project_root"], body["context"]["native_session_id"], str(h.state))
    for command in (("onboarding", "reachability"), ("onboarding", "reachability", "--stdin", "--approve"),
                    ("onboarding", "reachability", encoded.decode()),
                    ("onboarding", "--state", str(h.state), "reachability", encoded.decode()),
                    ("onboarding", "reachability", "--state", str(h.state), encoded.decode())):
        result = h.cli(*command, input=encoded.decode(), timeout=16)
        check(not result.ok, "reachability accepted positional input, missing stdin or mutation flag")
        public(result.stdout + result.stderr, encoded.decode(), body["context"]["project_root"], body["context"]["native_session_id"])
    for method in ("GET", "PUT", "PATCH", "DELETE"):
        status, denied = h.api(method, BASE, body, timeout=13)
        check(status in (404, 405), f"unsupported reachability method HTTP {status}"); public(denied)
    strict_state(f, before, "closed_input"); no_io(f, counters, "closed_input")
    within_window(f)
    status, agent = h.api("POST", "/v1/agents", {"name": "boundary", "owner": "owner"})
    check(status == 201, "real scoped adapter agent prerequisite")
    session = h.ok("session", "attach", "--agent", agent["id"], "--integration", "fixture")
    credential = h.ok("adapter", "create", "--session", session["id"], "--expires-at", rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, agent, session["id"], credential); f["secrets"].extend([adapter.token, adapter.instance])
    status, connected = adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id,
        "session_id": adapter.session_id, "instance_id": adapter.instance, "protocol_version": "fixture-reachability-v1"}, timeout=8)
    check(status == 200, "ordinary scoped adapter handshake prerequisite")
    status, denied = adapter.call("POST", BASE, body, timeout=13)
    check(status == 404, "credential-scoped adapter exposed reachability administration"); public(denied, *f["secrets"])
    peer = subprocess.run([str(suite.probe_bin), "--state", str(f["a"].state), "--address", peer_address(h),
        "--alpn", "peerspan-peer/1", "--path", BASE, "--method", "POST", "--body-stdin"],
        input=encoded, capture_output=True, timeout=15)
    try:
        view = json.loads(peer.stdout)
    except ValueError:
        view = None
    check(peer.returncode == 0 and type(view) is dict and view.get("status") == 404, "authenticated peer exposed reachability administration")
    public(peer.stderr.decode(errors="replace"), *f["secrets"])
    isolated = suite.host("route")
    check(isolated.api("POST", BASE, {}, timeout=13)[0] == 400, "private malformed reachability route prerequisite")
    cert, key = suite.work / "route-cert.pem", suite.work / "route-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=reachability", "-days", "1",
        "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    with socket.create_connection(("127.0.0.1", isolated.bootstrap_port), timeout=5) as sock:
        with tls.wrap_socket(sock, server_hostname="peerspan") as stream:
            stream.sendall((f"POST {BASE} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}").encode())
            response = http.client.HTTPResponse(stream); response.begin(); response.read()
            check(response.status == 404, f"bootstrap reachability boundary HTTP {response.status}, want404")
    absent = suite.host("missing", start=False); shutil.rmtree(absent.state)
    old = files(absent.root)
    result = absent.cli("onboarding", "reachability", "--stdin", input=encoded.decode(), timeout=16)
    check(not result.ok and not absent.state.exists() and files(absent.root) == old, "missing-daemon reachability created state or files")
    public(result.stdout + result.stderr, body["context"]["project_root"], body["context"]["native_session_id"], str(absent.state))
    # Last: genuinely expire current authority, never restore a persisted clock.
    end = max(parse_time(row["not_after"]) for row in get(h, "/v2/networks/" + f["net"] + "/persons")["persons"])
    target = end + timedelta(seconds=1)
    for local in (f["a"], h):
        local.clock.set(local.clock.offset + math.ceil((target - local.now()).total_seconds()))
    counts = traffic(f)
    observe(f, status=409, code="access_inspection_unavailable")
    no_io(f, counts, "expired_authority")


suite.finish()
