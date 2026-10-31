#!/usr/bin/env python3
"""Section36 current project readiness, independent public-contract conformance.

Genuine two people/two hosts, ordinary DEC admission, current policy/grants and
real adapter handshakes. No authority/protocol row mutation, worker suppression,
key deletion or invented readiness. Copied only independently authored public
fixture helpers. Both bootstrap TCP relays and every enabled peer UDP path are
counted. All349 native sources and28 prior slim suites/harnesses stay unchanged.

Purity setup observes actual request/invitation retirement, signed current
counted contacts, ordinary sync/directory completion and a genuine fresh-start
window before normal60s anti-entropy. Every schema/table/state/home comparison
and all TCP/UDP counters remains strict; setup quiescence is no global fence.
No classification of earlier unclassified transport/contact failures follows.

Limits: two hosts provide one remote machine per person, no remote same-person
self-path, multi-machine order tie, concurrent pending withdrawal/group/fork/
missing-ancestry/immutable-agent/provider-limit or >2MiB valid output fixture. Genuine normal
policy/block/grant changes are exercised; no alternate evaluator is implemented.
Adapter ready is only a deterministic public handshake, not real model receipt,
peer reachability, actual conversation readiness or installed/physical evidence.
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
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, create_network,
                     join_new_person, parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for)
from counted_peer import CountedUDP, exchange_current_contacts, peer_address, peer_request

suite = Suite("readiness", __doc__)
BASE = "/v1/onboarding/readiness"
INSPECT = "/v1/onboarding/access-inspection"
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
CONNECTION = set("adapter_id session_id state recoverable lease_expires_at last_seen_at channel channel_verified_at protocol_version".split())
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


def validate(h, parent, net, person, value):
    check(type(value) is dict and set(value) == TOP and type(value["version"]) is int and value["version"] == 1,
          "closed access-inspection wrapper/version")
    check(value["host_id"] == h.id and value["context"] == context(parent)
          and value["next_action"] == "review_agent_access", "exact inspection wrapper binding/action")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]) is not None
          and abs((parse_time(value["observed_at"]) - h.now()).total_seconds()) < 5,
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
    check(result, "no actual databases in readiness snapshot")
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


def raw(h, data):
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=8)
    try:
        try:
            connection.request("POST", BASE, body=data, headers={"Content-Type": "application/json"})
        except BrokenPipeError:
            pass
        response = connection.getresponse()
        data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


def world():
    if state:
        check("pb" in state, "shared genuine readiness prerequisite did not finish")
        return state
    state["building"] = True
    a, b = host("a"), host("b")
    net = create_network(a, "Readiness 東京", "alice")
    key = ssh_key(b.root, "bob")
    rid = join_new_person(a, b, "bob", key, net["id"])
    for local, remote in ((a, b), (b, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", peer_address(remote))
    bounds = exchange_current_contacts(suite, a, b, net["id"])
    for local in (a, b):
        with closing(sqlite3.connect(f"file:{db_path(local)}?mode=ro", uri=True)) as db:
            bounds.extend(row[0] for row in db.execute("SELECT deadline FROM dec_pending WHERE request_id LIKE 'di_%'"))
    check(bounds, "genuine invitation expiry prerequisite absent")
    state.update(a=a, b=b, net=net["id"], alice=net["person_public_key"], bob=ssh_public_base64(key), key=key,
                 request_deadline=get(b, "/v2/link/requests/" + rid)["expires_at"], invitation_bounds=bounds,
                 pa=project(a, "a"), pb=project(b, "b"), credentials={}, secrets=[], request_id=rid)
    return state


def whole(f):
    return snapshot(f["a"]), snapshot(f["b"])


def strict(actual, expected, counters, before_counters, phase):
    """Failure-only fixed category diagnostics; retain complete original verdicts."""
    if actual != expected or counters != before_counters:
        try:
            summary = {"phase": phase, "participants": [], "carriers": []}
            for index, role in enumerate(("issuer", "receiver")):
                old, new = expected[index], actual[index]
                changes = []
                for database in sorted(set(old[0]) | set(new[0])):
                    for table in sorted(set(old[0].get(database, {})) | set(new[0].get(database, {}))):
                        left, right = old[0].get(database, {}).get(table, ()), new[0].get(database, {}).get(table, ())
                        if left != right:
                            changes.append({"table": table if table in {"$schema", "$version"} or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", table) else "unknown",
                                            "before_count": len(left), "after_count": len(right)})
                summary["participants"].append({"role": role, "logical_changes": changes,
                    "state_changed_count": sum(old[1].get(k) != new[1].get(k) for k in set(old[1]) | set(new[1])),
                    "home_changed_count": sum(old[2].get(k) != new[2].get(k) for k in set(old[2]) | set(new[2]))})
            for n, role, kind in ((0, "issuer", "tcp"), (1, "receiver", "tcp"), (2, "issuer", "udp"), (3, "receiver", "udp")):
                summary["carriers"].append({"role": role, "kind": kind,
                    "deltas": [x - y for x, y in zip(counters[n], before_counters[n])]})
            print("readiness_purity_public=" + json.dumps(summary, sort_keys=True), flush=True)
        except Exception:
            pass
    check(actual == expected, "readiness changed complete logical schemas/DB/clock/private state or home files")
    check(counters == before_counters, "readiness used one of the counted bootstrap TCP or peer UDP carriers")


def verify(f, parent, value, person=None):
    h = f["b"]
    person = person or f["alice"]
    check(type(value) is dict and set(value) == set("version host_id context observed_at inspection readiness".split()),
          "closed readiness outer shape")
    check(type(value["version"]) is int and value["version"] == 1 and value["host_id"] == h.id
          and value["context"] == context(parent), "readiness version/host/private project binding")
    observed = value["observed_at"]
    check(type(observed) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", observed)
          and abs((parse_time(observed) - h.now()).total_seconds()) < 5, "readiness actual canonical observation time")
    inspected = value["inspection"]
    check(type(inspected) is dict and set(inspected) == {"review_id", "review"}, "closed current inspection envelope")
    validate(h, parent, f["net"], person, {"version": 1, "host_id": h.id, "context": context(parent), "observed_at": observed,
        **inspected, "next_action": "review_agent_access"})
    readiness = value["readiness"]
    check(type(readiness) is dict and set(readiness) == set("direction session_id adapter_connections peers peer_reachability model_receipt connection_readiness".split()),
          "closed complete readiness projection")
    check(readiness["direction"] == "participant_hosts_to_project_agent" and readiness["session_id"] == parent["review"]["session_id"],
          "readiness borrowed another project/direction/session")
    check(all(readiness[k] == "not_verified" for k in ("peer_reachability", "model_receipt", "connection_readiness")),
          "membership/permission/channel inferred peer/model/overall readiness")
    expected = sorted(("host_" + hashlib.sha256(base64.b64decode(row["host_public_key"], validate=True)).hexdigest(), row["host_public_key"])
                      for row in inspected["review"]["participant"]["hosts"] if row["host_public_key"] != h.public_key)
    peers = readiness["peers"]
    check(type(peers) is list and all(type(peer) is dict and set(peer) == {"host_id", "host_public_key", "authorizations"} for peer in peers),
          "closed participant-machine projection")
    check([(peer["host_id"], peer["host_public_key"]) for peer in peers] == expected, "current remote host inclusion/ID derivation/order")
    for peer in peers:
        check(type(peer["authorizations"]) is list, "honest empty authorizations must be an array")
        for auth in peer["authorizations"]:
            check(type(auth) is dict and auth.get("kind") in {"self", "policy", "grant"}
                  and type(auth.get("actions")) is list and auth["actions"]
                  and set(auth["actions"]) <= {"message.append", "task.submit", "task.delegate"}
                  and type(auth.get("max_message_bytes")) is int and 1 <= auth["max_message_bytes"] <= 65536
                  and type(auth.get("max_artifact_bytes")) is int and 0 <= auth["max_artifact_bytes"] <= 1073741824,
                  "receiver authorization omitted/widened typed actions/bounds")
            if auth["kind"] != "self":
                check("from_agent" in auth and (auth["from_agent"] is None or re.fullmatch(r"agent_[0-9a-f]{32}", auth["from_agent"])),
                      "receiver requester-agent restriction was omitted or merged")
    connections = readiness["adapter_connections"]
    check(type(connections) is list and all(type(item) is dict and set(item) == CONNECTION for item in connections), "full closed adapter connections")
    expected_ids = f["credentials"].get(parent["review"]["session_id"], [])
    check([item["adapter_id"] for item in connections] == sorted(expected_ids), "credential validity/session filtering/order differs")
    for connection in connections:
        check(connection["session_id"] == parent["review"]["session_id"], "agent-wide channel borrowed from another session")
        check(connection == get(h, "/v1/adapters/" + connection["adapter_id"] + "/connection"), "readiness changed ordinary public connection evidence")
    check(len(compact(value)) <= 2 * 1024 * 1024, "readiness public output exceeded2MiB")
    public(value, *f["secrets"], *(local.relay.address for local in (f["a"], f["b"])),
           *(peer_address(local) for local in (f["a"], f["b"])))
    return value


def observe(f, parent=None, *, person=None, body=None, status=200, code=None):
    h, parent = f["b"], parent or f["pb"]
    actual, value = h.api("POST", BASE, body if body is not None else payload(parent, f["net"], person or f["alice"]), timeout=8)
    check(actual == status, f"readiness observation HTTP {actual}, want {status}")
    if actual == 200:
        return verify(f, parent, value, person)
    check(type(value) is dict and value.get("code") == code and "readiness" not in value and "inspection" not in value,
          "readiness refusal did not preserve exact closed inherited error")
    public(value, *f["secrets"], parent["review"]["project_root"], parent["review"]["native_session_id"])
    return value


def auths(f, view=None, *, compare_peer=True):
    view = observe(f) if view is None else view
    peers = view["readiness"]["peers"]
    check(len(peers) == 1 and peers[0]["host_id"] == f["a"].id, "two-person fixture omitted exact remote machine")
    actual = peers[0]["authorizations"]
    if compare_peer:
        ordinary = peer_request(suite, f["a"], f["b"], "GET", "/peer/v1/networks/" + f["net"] + "/agents")
        check(type(ordinary) is list, "ordinary authenticated receiver projection is not an array")
        selected = [entry for entry in ordinary if entry["agent_id"] == f["pb"]["review"]["agent"]["id"]]
        check(len(selected) == (1 if actual else 0), "ordinary receiver and readiness disagree on agent presence")
        check((selected[0]["authorizations"] if selected else []) == actual, "readiness rewrote/reordered/unioned ordinary authorizations")
    return actual


def connection_adapter(f, parent, *, seconds=3600):
    h = f["b"]
    credential = h.ok("adapter", "create", "--session", parent["review"]["session_id"],
                      "--expires-at", rfc3339(h.now() + timedelta(seconds=seconds)))
    agent = get(h, "/v1/agents/" + parent["review"]["agent"]["id"])
    adapter = Adapter(h, agent, parent["review"]["session_id"], credential)
    f["secrets"].extend([adapter.token, adapter.instance])
    f["credentials"][adapter.session_id] = [adapter.adapter_id]
    return adapter


def connect(adapter):
    status, view = adapter.call("POST", "/adapter/v1/connect", {"adapter_id": adapter.adapter_id,
        "session_id": adapter.session_id, "instance_id": adapter.instance, "protocol_version": "fixture-readiness-v1"}, timeout=8)
    check(status == 200, "ordinary manual adapter connect failed")
    return view


def sync_directory(f):
    for local, remote in ((f["a"], f["b"]), (f["b"], f["a"])):
        status, synced = local.api("POST", "/v2/networks/" + f["net"] + "/sync", {}, timeout=35)
        check(status == 200 and remote.public_key in synced["attempted"] and synced["unavailable"] == [],
              "genuine explicit ordinary sync has unavailable or missing participant")
        status, view = local.api("POST", "/v1/directory/refresh?network=" + f["net"], {}, timeout=12)
        check(status == 200 and any(row["host_id"] == remote.id and row["state"] == "ok" for row in view["hosts"]),
              "genuine authenticated startup directory query not completed")


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


def pure_start(f):
    original = max(*[parse_time(x) for x in [*f["invitation_bounds"], f["request_deadline"]]], f["a"].now(), f["b"].now()) + timedelta(seconds=1)
    advance(f, original)
    for local in (f["a"], f["b"]):
        unsigned_maintenance(local)
    short = exchange_current_contacts(suite, f["a"], f["b"], f["net"])
    target = max(*[parse_time(x) for x in short], f["a"].now(), f["b"].now()) + timedelta(seconds=1)
    advance(f, target)
    for local in (f["a"], f["b"]):
        unsigned_maintenance(local)
    started = time.monotonic()
    for local in (f["a"], f["b"]):
        local.restart()
    sync_directory(f)
    remaining = 60 - (time.monotonic() - started)
    check(remaining > 0, "readiness setup exhausted first ordinary periodic-sync window")
    current_contacts(f, remaining)
    for local in (f["a"], f["b"]):
        quiet(f, local, require_retirement=True)
    check(time.monotonic() - started < 60, "readiness startup did not settle before first periodic sync")
    return started


@suite.case("exact_current_inspection_remote_machine_shape_cli_and_metadata_only_session", "guided36 verification1")
def _():
    f = world()
    first = observe(f)
    check(first["readiness"]["adapter_connections"] == [], "metadata attachment fabricated a credential or connected process")
    check(auths(f, first) == [], "new project membership alone invented access authorization")
    status, inspected = f["b"].api("POST", INSPECT, payload(f["pb"], f["net"], f["alice"]), timeout=8)
    check(status == 200 and first["inspection"] == {k: inspected[k] for k in ("review_id", "review")}, "readiness changed complete current section30 inspection/digest")
    result = f["b"].cli("onboarding", "readiness", "--stdin", input=compact(payload(f["pb"], f["net"], f["alice"])).decode(), timeout=8)
    check(result.ok and type(result.json) is dict, "private readiness CLI failed")
    second = verify(f, f["pb"], result.json)
    check({k: v for k, v in second.items() if k != "observed_at"} == {k: v for k, v in first.items() if k != "observed_at"},
          "readiness API/CLI complete projection parity")
    self_view = observe(f, person=f["bob"])
    check(self_view["readiness"]["peers"] == [], "selected local host was advertised as a remote caller")
    public(result.stderr, *f["secrets"])


@suite.case("ordinary_current_grants_origin_bounds_policy_withdrawal_block_and_applied_history", "guided36 verification2")
def _():
    f = world(); h, source = f["b"], f["a"]
    agent = f["pb"]["review"]["agent"]
    status, origin = source.api("POST", "/v1/agents", {"name": "requester-origin", "owner": "alice"})
    check(status == 201, "ordinary requester-agent prerequisite")
    expiry = rfc3339(h.now() + timedelta(hours=6))
    message = h.ok("grant", "create", "--peer", source.id, "--agent", agent["id"], "--expires-at", expiry,
                   "--max-message-bytes", "12345", "--from-agent", origin["id"], "--allow-disconnected")
    task = h.ok("grant", "create", "--peer", source.id, "--agent", agent["id"], "--expires-at", expiry,
                "--action", "task.submit", "--max-message-bytes", "5678", "--max-artifact-bytes", "16384", "--allow-disconnected")
    expected = [{"kind": "grant", "grant_id": value["id"], "actions": [value["action"]],
        "max_message_bytes": value["max_message_bytes"], "max_artifact_bytes": value["max_artifact_bytes"],
        "expires_at": value["expires_at"], "from_agent": value["requester_agent_id"]}
        for value in sorted((message, task), key=lambda row: row["id"])]
    check(auths(f) == expected, "grant actions/bounds/order/origin were omitted or unioned")
    h.ok("grant", "revoke", message["id"])
    check(auths(f) == [entry for entry in expected if entry["grant_id"] == task["id"]], "revoked origin-restricted grant remained advertised")
    h.ok("access", "allow", "--network", f["net"], "--agent", agent["name"],
         "--principal", "agent:" + source.id + "/" + origin["id"], "--action", "message.append", "--action", "task.submit",
         "--max-message-bytes", "3210", "--max-artifact-bytes", "4096")
    entries = auths(f)
    policy = [entry for entry in entries if entry["kind"] == "policy"]
    check(len(policy) == 1 and policy[0]["actions"] == ["message.append", "task.submit"]
          and policy[0]["max_message_bytes"] == 3210 and policy[0]["max_artifact_bytes"] == 4096
          and policy[0]["from_agent"] == origin["id"], "current policy lost exact requester-agent restriction or bounds")
    h.ok("access", "deny", "--network", f["net"], "--agent", agent["name"])
    check(auths(f) == [entry for entry in expected if entry["grant_id"] == task["id"]], "withdrawal replaced current receiver evaluation with old policy")
    h.ok("grant", "revoke", task["id"]); check(auths(f) == [], "revoked explicit grant remained advertised")
    # Retain a genuine applied guided action, then prove current withdrawal/block
    # evaluation wins over its unchanged historical local application marker.
    inspected = observe(f)["inspection"]
    key = payload(f["pb"], f["net"], f["alice"])
    status, prepared = h.api("POST", "/v1/onboarding/access-consent/prepare", {**key, "inspection_review_id": inspected["review_id"]}, timeout=8)
    check(status == 200 and prepared["access"]["state"] == "review", "genuine exact nonsigning policy consent prerequisite")
    refs = {**key, "access_id": prepared["access"]["access_id"], "access_review_id": prepared["access"]["review_id"]}
    status, approved = h.api("POST", "/v1/onboarding/access-consent/approve", refs, timeout=8)
    check(status == 200 and approved["access"]["state"] == "approved", "genuine exact policy approval prerequisite")
    status, signed = h.api("POST", "/v1/onboarding/access-consent/sign", {**refs, "decision": "sign_project_agent_access"}, timeout=95)
    check(status == 200 and signed["signing"]["state"] == "signed", "genuine selected owned-device policy signature prerequisite")
    status, applied = h.api("POST", "/v1/onboarding/access-consent/apply", {**refs, "decision": "apply_project_agent_access"}, timeout=95)
    check(status == 200 and applied["application"]["state"] == "locally_applied", "genuine exact policy application prerequisite")
    entries = auths(f)
    check(len(entries) == 1 and entries[0]["kind"] == "policy" and entries[0]["from_agent"] is None
          and entries[0]["actions"] == ["message.append", "task.submit"] and entries[0]["max_artifact_bytes"] == 0,
          "ordinary current narrow policy projection after actual application")
    h.ok("access", "block", "--host", source.id); check(auths(f) == [], "blocked current caller retained policy authorization")
    h.ok("access", "unblock", "--host", source.id)
    check(auths(f) == entries, "unblocking did not restore actual current policy evaluation")
    h.ok("access", "deny", "--network", f["net"], "--agent", agent["name"])
    check(auths(f) == [], "historical applied consent substituted for withdrawn current permission")
    status, historical = h.api("POST", "/v1/onboarding/access-consent/application", refs, timeout=8)
    check(status == 200 and historical["application"] == applied["application"], "ordinary withdrawal rewrote exact recorded application history")
    f["historical"] = refs


@suite.case("exact_project_session_registered_unverified_verified_other_session_expiry_and_revocation", "guided36 verification3,5 aggregate privacy")
def _():
    f = world(); h, parent = f["b"], f["pb"]
    agent = get(h, "/v1/agents/" + parent["review"]["agent"]["id"])
    other = h.ok("session", "attach", "--agent", agent["id"], "--integration", "fixture-other")
    credential = h.ok("adapter", "create", "--session", other["id"], "--expires-at", rfc3339(h.now() + timedelta(hours=2)))
    wrong = Adapter(h, agent, other["id"], credential); f["secrets"].extend([wrong.token, wrong.instance])
    connect(wrong); wrong.ready()
    check(get(h, "/v1/adapters/" + wrong.adapter_id + "/connection")["channel"] == "verified", "other-session verified-channel prerequisite")
    check(observe(f)["readiness"]["adapter_connections"] == [], "another same-agent session supplied this project's channel")
    h.ok("adapter", "revoke", wrong.adapter_id)
    h.api("POST", "/v1/sessions/" + other["id"] + "/detach", {})
    current = connection_adapter(f, parent, seconds=65)
    view = observe(f)["readiness"]["adapter_connections"][0]
    check(view["state"] == "registered" and view["channel"] is None, "unconnected credential claimed a live channel")
    connect(current)
    view = observe(f)["readiness"]["adapter_connections"][0]
    check(view["state"] == "ready" and view["channel"] == "unverified" and view["channel_verified_at"] is None,
          "live lease inferred channel/model verification")
    current.ready()
    view = observe(f)["readiness"]["adapter_connections"][0]
    check(view["state"] == "ready" and view["channel"] == "verified" and view["channel_verified_at"], "actual ready handshake missing from exact session evidence")
    unsafe = "token_SHORT_PROTOCOL_SECRET"; f["secrets"].append(unsafe)
    status, _ = current.call("POST", "/adapter/v1/connect", {"adapter_id": current.adapter_id, "session_id": current.session_id,
        "instance_id": current.instance, "protocol_version": unsafe}, timeout=8)
    check(status == 200, "ordinary bounded public protocol metadata prerequisite refused")
    observe(f, status=409, code="readiness_unavailable")
    connect(current); observe(f)
    expiry = get(h, "/v1/adapters/" + current.adapter_id)["expires_at"]
    target = max(parse_time(expiry), f["a"].now(), f["b"].now()) + timedelta(seconds=1)
    advance(f, target); f["credentials"][current.session_id] = []
    check(observe(f)["readiness"]["adapter_connections"] == [], "expired credential remained current readiness evidence")
    # Q uses a distinct root/native project context; it cannot replace S by name.
    q = project(h, "revoked", agent={"kind": "existing", "id": agent["id"]})
    revoked = connection_adapter(f, q)
    check(observe(f, q)["readiness"]["adapter_connections"][0]["state"] == "registered", "new distinct exact-session credential prerequisite")
    h.ok("adapter", "revoke", revoked.adapter_id); f["credentials"][revoked.session_id] = []
    check(observe(f, q)["readiness"]["adapter_connections"] == [], "revoked exact-session credential remained current")
    check(observe(f)["readiness"]["adapter_connections"] == [], "distinct project session revived old project credential")


@suite.case("complete_database_private_files_all_carriers_repeat_refusal_and_detached_restart_purity", "guided36 verification4")
def _():
    f = world(); f["fresh_window"] = pure_start(f)
    old = f["pb"]
    before, counters = whole(f), traffic(f)
    observe(f, old, status=409, code="review_changed")
    observe(f, old, status=409, code="review_changed")
    strict(whole(f), before, traffic(f), counters, "detached_restart")
    f["pb"] = project(f["b"], "resumed", old=old, agent={"kind": "existing", "id": old["review"]["agent"]["id"]})
    for local in (f["a"], f["b"]):
        quiet(f, local, require_retirement=True)
    before, counters = whole(f), traffic(f)
    first = observe(f)
    for _ in range(3):
        check(observe(f)["inspection"] == first["inspection"], "unchanged current terms changed inspection digest")
    encoded = compact(payload(f["pb"], f["net"], f["alice"])).decode()
    for _ in range(2):
        result = f["b"].cli("onboarding", "readiness", "--stdin", input=encoded, timeout=8)
        check(result.ok, "quiescent readiness CLI read failed"); verify(f, f["pb"], result.json)
    observe(f, body={**payload(f["pb"], f["net"], f["alice"]), "context": {
        **context(f["pb"]), "native_session_id": "different-conversation"}}, status=409, code="review_changed")
    strict(whole(f), before, traffic(f), counters, "repeat_and_refusal")
    check(time.monotonic() - f["fresh_window"] < 60, "pure interval crossed first ordinary periodic-sync boundary")


@suite.case("strict_private_stdin_methods_missing_daemon_and_owner_only_peer_bootstrap_adapter_routers", "guided36 verification6")
def _():
    f = world(); h = f["b"]
    body = payload(f["pb"], f["net"], f["alice"]); encoded = compact(body)
    maximum = b" " * (65536 - len(encoded)) + encoded
    check(raw(h, maximum)[0] == 200, "exact64KiB readiness input refused")
    invalid = [b"null", b"[]", b"{", b"\xff", encoded + b"{}", maximum + b" ",
        encoded.replace(b'"context":', b'"context":null,"context":', 1),
        encoded.replace(b'"integration":', b'"integration":"claude-code","integration":', 1)]
    for key in body:
        invalid.extend([compact({k: v for k, v in body.items() if k != key}), compact({**body, key: None})])
    for key in context(f["pb"]):
        invalid.append(compact({**body, "context": {**body["context"], key: None}}))
    invalid.extend([compact({**body, "approve": "PRIVATE_INPUT"}), compact({**body, "network_id": "net_1"}),
                    compact({**body, "person_public_key": "bad"}), compact({**body, "agent_id": "agent_" + "0" * 32}),
                    compact({**body, "context": {**body["context"], "extra": "PRIVATE_INPUT"}})])
    for local in (f["a"], f["b"]):
        quiet(f, local, require_retirement=True)
    before, counters = whole(f), traffic(f)
    for number, data in enumerate(invalid):
        status, denied = raw(h, data)
        check(status == 400 and isinstance(denied, dict) and denied.get("code") == "invalid", f"malformed readiness input{number} HTTP {status}")
        public(denied, "PRIVATE_INPUT", body["context"]["project_root"], body["context"]["native_session_id"], *f["secrets"])
        result = h.cli("onboarding", "readiness", "--stdin", input=data.decode(errors="replace"), timeout=8)
        check(not result.ok, f"private CLI accepted malformed readiness input{number}")
        public(result.stdout + result.stderr, "PRIVATE_INPUT", body["context"]["project_root"], body["context"]["native_session_id"], str(h.state), *f["secrets"])
    for command in (("onboarding", "readiness"), ("onboarding", "readiness", "--stdin", "--approve"),
                    ("onboarding", "readiness", encoded.decode()),
                    ("onboarding", "--state", str(h.state), "readiness", encoded.decode()),
                    ("onboarding", "readiness", "--state", str(h.state), encoded.decode())):
        result = h.cli(*command, input=encoded.decode(), timeout=8)
        check(not result.ok, "readiness CLI accepted positional input, missing stdin or approval")
        public(result.stdout + result.stderr, body["context"]["project_root"], body["context"]["native_session_id"], encoded.decode(), *f["secrets"])
    for method in ("GET", "PUT", "PATCH", "DELETE"):
        status, denied = h.api(method, BASE, body, timeout=8)
        check(status in (404, 405), f"unsupported readiness method HTTP {status}"); public(denied)
    strict(whole(f), before, traffic(f), counters, "closed_input")
    check(time.monotonic() - f["fresh_window"] < 60, "standalone input corpus crossed first periodic-sync boundary")
    # Register a separate real scoped caller, manually bind it without a renewer.
    status, agent = h.api("POST", "/v1/agents", {"name": "boundary", "owner": "owner"})
    check(status == 201, "scoped boundary agent prerequisite")
    session = h.ok("session", "attach", "--agent", agent["id"], "--integration", "fixture")
    credential = h.ok("adapter", "create", "--session", session["id"], "--expires-at", rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, agent, session["id"], credential); f["secrets"].extend([adapter.token, adapter.instance]); connect(adapter)
    status, denied = adapter.call("POST", BASE, body, timeout=8)
    check(status == 404, "credential-scoped adapter exposed readiness administration"); public(denied, *f["secrets"])
    result = subprocess.run([str(suite.probe_bin), "--state", str(f["a"].state), "--address", peer_address(h),
        "--alpn", "peerspan-peer/1", "--path", BASE, "--method", "POST", "--body-stdin"], input=encoded, capture_output=True, timeout=15)
    check(result.returncode == 0 and json.loads(result.stdout).get("status") == 404, "authenticated peer exposed readiness administration")
    public(result.stderr.decode(errors="replace"), *f["secrets"])
    # Isolate source-rate buckets. A malformed body proves routing absence even
    # though this quiescent bootstrap-only host owns no selected network.
    isolated = suite.host("route")
    check(isolated.api("POST", BASE, {}, timeout=8)[0] == 400, "new private readiness route prerequisite")
    cert, key = suite.work / "route-cert.pem", suite.work / "route-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=readiness", "-days", "1",
        "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    with socket.create_connection(("127.0.0.1", isolated.bootstrap_port), timeout=5) as sock:
        with tls.wrap_socket(sock, server_hostname="peerspan") as stream:
            stream.sendall((f"POST {BASE} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}").encode())
            response = http.client.HTTPResponse(stream); response.begin(); response.read()
            check(response.status == 404, f"bootstrap readiness boundary HTTP {response.status}, want404")
    absent = suite.host("missing", start=False); shutil.rmtree(absent.state)
    before_missing = files(absent.root)
    result = absent.cli("onboarding", "readiness", "--stdin", input=encoded.decode(), timeout=8)
    check(not result.ok and not absent.state.exists() and files(absent.root) == before_missing, "missing-daemon readiness created state/files")
    public(result.stdout + result.stderr, body["context"]["project_root"], body["context"]["native_session_id"], str(absent.state))


@suite.case("exact_changed_detached_replaced_unknown_expired_and_unsafe_current_terms_fail_closed", "guided36 verification5")
def _():
    f = world(); h, parent = f["b"], f["pb"]
    body = payload(parent, f["net"], f["alice"])
    for field, value in (("project_root", str(suite.work / "different-project")), ("native_session_id", "different-conversation"),
                         ("project_review_id", "review_" + "0" * 64)):
        observe(f, body={**body, "context": {**body["context"], field: value}}, status=409, code="review_changed")
    observe(f, body={**body, "context": {**body["context"], "project_flow_id": "flow_" + "0" * 32}}, status=404, code="not_found")
    observe(f, body={**body, "network_id": "net_" + "0" * 64}, status=404, code="not_found")
    unused = ssh_key(suite.work, "unused-person")
    observe(f, body={**body, "person_public_key": ssh_public_base64(unused)}, status=409, code="access_inspection_unavailable")
    check(h.api("POST", "/v1/sessions/" + parent["review"]["session_id"] + "/detach", {})[0] == 200, "ordinary explicit project detach prerequisite")
    observe(f, parent, status=409, code="review_changed")
    fresh = project(h, "replacement", old=parent, agent={"kind": "existing", "id": parent["review"]["agent"]["id"]})
    observe(f, parent, status=409, code="review_changed"); observe(f, fresh)
    for number, name in enumerate([prefix + "SHORT_INPUT" for prefix in PREFIXES] + ["to\u202eken_SHORT_INPUT"]):
        unsafe = project(h, "unsafe-" + str(number), agent={"kind": "new", "name": name, "owner": "public owner"})
        denied = observe(f, unsafe, status=409, code="access_inspection_unavailable")
        public(denied, name, "SHORT_INPUT")
    # Actual current finite authority expiry, without changing retained grants,
    # provider/keys or protocol rows. No restoration of persisted clock guards.
    observe(f, fresh)
    end = max(parse_time(row["not_after"]) for row in get(h, "/v2/networks/" + f["net"] + "/persons")["persons"])
    target = end + timedelta(seconds=1)
    for local in (f["a"], f["b"]):
        local.clock.set(local.clock.offset + math.ceil((target - local.now()).total_seconds()))
    observe(f, fresh, status=409, code="access_inspection_unavailable")


suite.finish()
