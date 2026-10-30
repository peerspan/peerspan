#!/usr/bin/env python3
"""Project-bound access inspection, guided-session-contract section30.

Independent contract-only suite: real temporary hosts, ordinary seven-stage
admission, attached projects and public policy actions. SQLite is read only for
whole-state comparisons; no authority, policy, intent or storage row is edited.
Both configured bootstrap carriers are transparent counting TLS relays; QUIC
advertisement is empty. No implementation imports or copied policy evaluator.

Source/manual limits: if ordinary join already retains a local-person policy,
the absent-policy assertion is explicitly reported as unexecuted. This compact
two-person fixture cannot create a genuine
same-person concurrent displaced withdrawal, policy/root fork, incomplete proof
ancestry, legacy/migration fence, changed immutable agent metadata, or a >2MiB
valid projection through ordinary operations. Those refusals remain unexecuted;
we never substitute manufactured storage/catalog authority. Multiple retained
proof selection is checked against the real public catalog, without claiming
that this fixture necessarily creates two proofs of one statement. One machine
per person checks sorting and exact inclusion, not a multi-machine tie. Original
signer file-open syscalls, microsecond expiry crossings, physical/model/native
readiness and installed-bundle behavior remain separate gates. Startup's ordinary
session detach is settled before restart purity measurement, never omitted from
the aggregate snapshot. All pre-existing suites remain byte-for-byte unchanged.
"""
import atexit
import base64
import hashlib
import http.client
import json
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

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, create_network,
                     join_new_person, parse_time, rfc3339, ssh_key, ssh_public_base64,
                     wait_for)


suite = Suite("access_onboarding", __doc__)
BASE = "/v1/onboarding/access-inspection"
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


def host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + ".clock")))
    h.relay = Relay(("127.0.0.1", h.bootstrap_port))
    config = h.root / "transport.json"
    config.write_bytes(compact({"format": 1, "advertise_bootstrap": [h.relay.address],
                               "advertise_quic": [], "rendezvous": [], "relays": [],
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


def world():
    if not state:
        state["building"] = True
        a, b = host("alice"), host("bob")
        net = create_network(a, "Access 東京", "alice")
        key = ssh_key(b.root, "bob")
        join_new_person(a, b, "bob", key, net["id"])
        state.update(a=a, b=b, net=net["id"], key=key, alice=net["person_public_key"],
                     bob=ssh_public_base64(key), pa=project(a, "alice"), pb=project(b, "bob"))
    check("pa" in state, "ordinary two-person fixture did not finish")
    return state


def statement_id(envelope):
    message = "\n".join(("peerspan-decentralized-statement-v1", envelope["kind"], envelope["context_id"],
                          hashlib.sha256(base64.b64decode(envelope["payload_base64"], validate=True)).hexdigest()))
    return "ds_" + hashlib.sha256(message.encode()).hexdigest()


def catalog(h, net):
    result = {}
    for item in get(h, f"/v2/networks/{net}/catalog")["catalog"]["objects"]:
        if item["kind"] == "activation":
            continue
        raw = base64.b64decode(item["body_base64"], validate=True)
        envelope = json.loads(raw)
        sid = statement_id(envelope)
        proof = "dp_" + hashlib.sha256(("peerspan-decentralized-proof-v1\n" + item["kind"] + "\n" +
                                          hashlib.sha256(raw).hexdigest()).encode()).hexdigest()
        check(proof == item["id"] and envelope["kind"] == item["kind"], "public catalog ID/kind mismatch")
        result.setdefault(sid, []).append((proof, envelope, json.loads(base64.b64decode(envelope["payload_base64"]))))
    return result


def verify_statement(envelope):
    sid = statement_id(envelope)
    for signature in envelope["signatures"]:
        message = "\n".join(("peerspan-decentralized-signature-v1", sid,
                              signature["role"], signature["public_key"])).encode()
        stem = suite.work / "verify-public"
        key = base64.b64decode(signature["public_key"], validate=True)
        check(len(key) == 32, "noncanonical statement signing key")
        if signature["format"] == "ed25519":
            stem.with_suffix(".der").write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
            stem.with_suffix(".sig").write_bytes(base64.b64decode(signature["signature"], validate=True))
            stem.with_suffix(".msg").write_bytes(message)
            result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                "-inkey", str(stem.with_suffix(".der")), "-rawin", "-in", str(stem.with_suffix(".msg")),
                "-sigfile", str(stem.with_suffix(".sig"))], capture_output=True, timeout=5)
        else:
            check(signature["format"] == "sshsig", "unexpected statement signature format")
            blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + key
            stem.with_suffix(".allowed").write_text("inspector ssh-ed25519 " + base64.b64encode(blob).decode() + "\n")
            sig = signature["signature"]
            stem.with_suffix(".sig").write_text("-----BEGIN SSH SIGNATURE-----\n" +
                "\n".join(sig[i:i + 70] for i in range(0, len(sig), 70)) + "\n-----END SSH SIGNATURE-----\n")
            result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(stem.with_suffix(".allowed")),
                "-I", "inspector", "-n", "peerspan-person-v1", "-s", str(stem.with_suffix(".sig"))],
                input=message, capture_output=True, timeout=5)
        check(result.returncode == 0, "independent public statement signature verification failed")


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


def inspect(h, parent, net, person, *, body=None, status=200, code=None):
    actual, value = h.api("POST", BASE, payload(parent, net, person) if body is None else body, timeout=8)
    check(actual == status, f"access inspection HTTP {actual}, want {status}")
    if status == 200:
        validate(h, parent, net, person, value)
    else:
        check(isinstance(value, dict) and value.get("code") == code, f"access refusal did not return {code}")
        check("review" not in value and "review_id" not in value, "refusal exposed partial active-looking terms")
        public(value)
    return value


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


def rich_policy(f):
    a, net = f["a"], f["net"]
    allowed = a.ok("allow", "bob", "--network", net, "--agent", f["pa"]["review"]["agent"]["name"],
                   "--files", "12345", "--delegate")
    a.ok("allow", "everyone", "--network", net, "--agent", "default-artifact-rule", "--no-tasks")
    a.ok("trust", a.id, "--network", net)
    current, _, signed, body = current_policy(a, net, f["alice"])
    status, plan = a.api("POST", f"/v2/networks/{net}/policy-edits/plan", {"provider_id": "auto"})
    check(status == 200, "ordinary policy-edit planning failed")
    now = rfc3339(a.now())
    defaults = [rule for rule in body["rules"] if rule["agent"] == "default-artifact-rule"]
    check(len(defaults) == 1, "ordinary explicit-default policy rule fixture")
    defaults[0]["max_artifact_bytes"] = 0
    body.update(version=body["version"] + 1, issued_at=now, capability_rules=[{
        "host": a.id, "capability": "fixture-operation", "principals": [allowed["principal"]],
        "max_input_bytes": 1234, "allow_disconnected": True, "max_calls_per_hour": 17}],
        edits=sorted([e for e in body["edits"] if e["host"] != a.id] + [{"host": a.id, "seq": plan["seq"]}],
                     key=lambda e: e["host"]))
    signed.update(sequence=signed["sequence"] + 1, predecessors=[current["statement_id"]], resolves=[],
                  issued_at=now, not_before=now, body_base64=base64.b64encode(compact(body)).decode())
    status, action = a.api("POST", f"/v2/networks/{net}/actions", {
        "kind": "policy", "provider_id": "auto", "signature_format": "auto",
        "payload_base64": base64.b64encode(compact(signed)).decode(), "approve": True})
    check(status == 200 and action["committed"] is True and not action["signing_requests"],
          "ordinary locally signed complete policy action failed")


def records(h):
    paths = []
    for path in h.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                paths.append(path)
    check(len(paths) == 1, "expected exactly one ordinary host database")
    with closing(sqlite3.connect(f"file:{paths[0]}?mode=ro", uri=True, timeout=5)) as db, db:
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


def access_purity_diagnostic(actual, expected, phase):
    """GU.impl30d: project only already captured counts on original failure."""
    try:
        if actual != expected:
            phases = {"repeat_refusal", "post_startup_refusal", "post_restart_valid"}
            summary = {"phase": phase if phase in phases else "unknown", "changed_tables": [],
                       "state_entries": "unknown", "home_entries": "unknown"}
            for name in sorted(set(expected[0]) | set(actual[0])):
                before, after = expected[0].get(name, ()), actual[0].get(name, ())
                if before != after:
                    summary["changed_tables"].append({
                        "name": name if name in ("$schema", "$version") or re.fullmatch(r"[a-z_]+", name) else "unknown",
                        "before_count": len(before), "after_count": len(after)})
            for index, category in ((1, "state_entries"), (2, "home_entries")):
                before, after = expected[index], actual[index]
                summary[category] = {"before_count": len(before), "after_count": len(after),
                    "changed_count": sum(before.get(key) != after.get(key) for key in set(before) | set(after))}
            print("access_purity_failure_public=" + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # A diagnostic cannot replace the unchanged original verdict.
    return actual


def traffic(f):
    return f["a"].relay.counts(), f["b"].relay.counts()


def quiet(f, h):
    previous = snapshot(h), traffic(f)
    stable_since = time.monotonic()
    def settled():
        nonlocal previous, stable_since
        current = snapshot(h), traffic(f)
        if current != previous:
            stable_since = time.monotonic()
        previous = current
        return time.monotonic() - stable_since >= .3
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


@suite.case("exact_two_person_project_policy_digest_and_cli", "guided30 verification1")
def _():
    f = world()
    rich_policy(f)
    value = inspect(f["a"], f["pa"], f["net"], f["bob"])
    review = value["review"]
    retained = catalog(f["a"], f["net"])
    ids = [(review["owner"]["person_lease_id"], "person_lease"),
           (review["participant"]["person_lease_id"], "person_lease")]
    for member in [review["owner"]["host"], *review["participant"]["hosts"]]:
        ids += [(member[field], kind) for field, kind in (
            ("host_lease_id", "host_lease"), ("binding_lease_id", "binding_lease"), ("device_lease_id", "device_lease"))]
    for sid, kind in ids:
        check(sid in retained, "current P/H/B/device reference absent from genuine catalog")
        _, envelope, signed = retained[sid][0]
        check(envelope["kind"] == kind and signed["root_state_id"] == review["root_state_id"], "current verified parent kind/root")
        verify_statement(envelope)
    policy = review["policy"]
    check(policy["proof_id"] == min(p[0] for p in retained[policy["statement_id"]]), "first sorted retained policy proof")
    verify_statement(retained[policy["statement_id"]][0][1])
    check(policy["body"]["rules"] and policy["body"]["capability_rules"] and policy["body"]["trusted_hosts"],
          "fixture did not exercise complete message/task/capability/trust policy content")
    check(any(rule["agent"] == "default-artifact-rule" and "max_artifact_bytes" in rule
              and rule["max_artifact_bytes"] == 0 for rule in policy["body"]["rules"]),
          "exact signed policy JSON lost the explicitly present default artifact bound")
    result = f["a"].cli("onboarding", "access", "inspect", "--stdin", input=compact(payload(f["pa"], f["net"], f["bob"])).decode(), timeout=8)
    check(result.ok, "explicit stdin access CLI failed")
    validate(f["a"], f["pa"], f["net"], f["bob"], result.json)
    check({k: v for k, v in result.json.items() if k != "observed_at"} ==
          {k: v for k, v in value.items() if k != "observed_at"}, "API/CLI exact public parity")
    public(result.stderr)


@suite.case("exact_context_refusals_detach_and_replacement", "guided30 verification2")
def _():
    f = world()
    h, net, person = f["a"], f["net"], f["bob"]
    parent = project(h, "binding")
    correct = payload(parent, net, person)
    unknown_person = ssh_public_base64(ssh_key(suite.work, "unknown-person"))
    quiet(f, h)
    before = snapshot(h)
    for key, replacement, status, code in (
        ("project_flow_id", "flow_" + "f" * 32, 404, "not_found"),
        ("project_review_id", "review_" + "0" * 64, 409, "review_changed"),
        ("project_root", str(suite.work / "wrong-root"), 409, "review_changed"),
        ("native_session_id", "wrong-native", 409, "review_changed"),
        ("integration", "other", 400, "invalid")):
        inspect(h, parent, net, person, body={**correct, "context": {**correct["context"], key: replacement}}, status=status, code=code)
    inspect(h, parent, net, person, body={**correct, "network_id": "net_" + "f" * 64}, status=404, code="not_found")
    inspect(h, parent, net, person, body={**correct, "person_public_key": unknown_person},
            status=409, code="access_inspection_unavailable")
    check(snapshot(h) == before, "binding/selection refusals created project, identity, request or other durable state")
    h.ok("session", "detach", parent["review"]["session_id"])
    before = snapshot(h)
    inspect(h, parent, net, person, status=409, code="review_changed")
    check(snapshot(h) == before, "detached parent read repaired an attachment")
    newer = project(h, "replacement", old=parent)
    before = snapshot(h)
    inspect(h, parent, net, person, status=409, code="review_changed")
    replacement = inspect(h, newer, net, person)
    check(replacement["review"]["agent"] == newer["review"]["agent"] and newer["review"]["agent"] != parent["review"]["agent"],
          "replacement failed to bind the new explicit agent")
    check(snapshot(h) == before, "replaced/exact project reads changed durable state")


@suite.case("real_absent_policy_and_genuine_policy_changes", "guided30 verification3")
def _():
    f = world()
    h, net = f["b"], f["net"]
    no_policy = current_policy(h, net, f["bob"]) is None
    absent = inspect(h, f["pb"], net, f["alice"])
    if no_policy:
        check(absent["review"]["policy"] is None, "real absent policy must be null")
    else:
        print("LIMIT absent_policy: ordinary join retained a policy; no public empty-stream fixture established", flush=True)
    h.ok("allow", "alice", "--network", net, "--files", "4096", "--delegate", "--person-key", f["key"])
    active = inspect(h, f["pb"], net, f["alice"])
    again = inspect(h, f["pb"], net, f["alice"])
    check(active["review_id"] != absent["review_id"] and active["review_id"] == again["review_id"],
          "real policy appearance must change digest; unchanged reads must retain it")
    signed_before = active["review"]["policy"]["body"]
    h.ok("deny", "alice", "--network", net, "--person-key", f["key"])
    withdrawn = inspect(h, f["pb"], net, f["alice"])
    check(withdrawn["review_id"] != active["review_id"] and withdrawn["review"]["policy"]["body"] != signed_before,
          "new genuine withdrawal policy did not change inspection digest/body")
    check(withdrawn["review"]["policy"]["body"]["rules"] == [] and signed_before["rules"], "ordinary deny fixture did not withdraw the rule")
    # This is a settled withdrawal, not the source-only displaced-withdrawal
    # condition documented above. Do not claim its body/content difference.


@suite.case("missing_original_signer_clock_rollback_expiry_and_revocation", "guided30 verification4")
def _():
    f = world()
    h, net, person = f["b"], f["net"], f["bob"]
    status, selected = h.api("POST", f"/v2/networks/{net}/provider", {
        "provider_id": person, "person_public_key": person, "host_public_key": h.public_key, "approve": True})
    check(status == 200 and selected["provider"]["kind"] == "original_person", "ordinary original provider selection")
    moved = Path(str(f["key"]) + ".unavailable")
    f["key"].rename(moved)
    try:
        check(get(h, f"/v2/networks/{net}")["provider_state"]["state"] == "unavailable", "missing original signer fixture remains available")
        inspect(h, f["pb"], net, f["alice"])
    finally:
        moved.rename(f["key"])
    h.clock.set(600)
    h.ok("allow", "alice", "--network", net, "--person-key", f["key"])
    h.clock.set(0)
    inspect(h, f["pb"], net, f["alice"], status=409, code="access_inspection_unavailable")
    h.clock.set(600)
    inspect(h, f["pb"], net, f["alice"])
    h.clock.set(2 * 86400)
    inspect(h, f["pb"], net, f["alice"], status=409, code="access_inspection_unavailable")
    h.clock.set(8 * 86400)
    inspect(h, f["pb"], net, f["alice"], status=409, code="access_inspection_unavailable")
    h.clock.set(600)
    # A real host revocation leaves the person's lease current. Its now-empty
    # machine list is valid public evidence and must not imply reachability.
    f["a"].ok("network", "revoke", "--network", net, "--host", h.id, "--approve")
    value = inspect(f["a"], f["pa"], net, person)
    check(value["review"]["participant"]["hosts"] == [], "revoked host remained current in selected person's machines")
    f["peer_revoked"] = True


@suite.case("whole_state_both_carriers_repeat_refusal_and_restart_purity", "guided30 verification5")
def _():
    f = world()
    h, net, person = f["a"], f["net"], f["alice"]
    for peer in (f["a"], f["b"]):
        peer.clock.set(1800)  # retire authentic invitation/return windows
    quiet(f, h)
    before, counters = snapshot(h), traffic(f)
    first = inspect(h, f["pa"], net, person)
    for _ in range(3):
        check(inspect(h, f["pa"], net, person)["review_id"] == first["review_id"], "unchanged terms changed digest")
    inspect(h, f["pa"], net, person, body={**payload(f["pa"], net, person), "context": {
        **context(f["pa"]), "native_session_id": "wrong-private-native"}}, status=409, code="review_changed")
    check(access_purity_diagnostic(snapshot(h), before, "repeat_refusal") == before, "repeat/refusal changed aggregate schema/DB rows, state or home files")
    check(traffic(f) == counters, "repeat/refusal attempted IO on either configured carrier")
    h.restart(kill=True)
    quiet(f, h)
    before, counters = snapshot(h), traffic(f)
    inspect(h, f["pa"], net, person, status=409, code="review_changed")
    inspect(h, f["pa"], net, person, status=409, code="review_changed")
    check(access_purity_diagnostic(snapshot(h), before, "post_startup_refusal") == before and traffic(f) == counters, "post-startup historical refusals changed records/files/carriers")
    f["pa"] = project(h, "restart", old=f["pa"])
    quiet(f, h)
    before, counters = snapshot(h), traffic(f)
    inspect(h, f["pa"], net, person)
    result = h.cli("onboarding", "access", "inspect", "--stdin", input=compact(payload(f["pa"], net, person)).decode(), timeout=8)
    check(result.ok, "fresh attached project CLI after restart failed")
    validate(h, f["pa"], net, person, result.json)
    check(access_purity_diagnostic(snapshot(h), before, "post_restart_valid") == before and traffic(f) == counters, "post-restart valid API/CLI wrote rows/files or used a carrier")


@suite.case("closed_stdin_privacy_methods_unavailable_and_route_isolation", "guided30 verification6")
def _():
    f = world()
    h, net, person = f["a"], f["net"], f["alice"]
    body = payload(f["pa"], net, person)
    encoded = compact(body)
    maximum = b" " * (65536 - len(encoded)) + encoded
    check(raw(h, maximum)[0] == 200, "exact 65536-byte valid body was rejected")
    invalid = [b"null", b"[]", b"{", b"\xff", encoded + b"{}", maximum + b" ",
               encoded.replace(b'"context":', b'"context":null,"context":', 1),
               encoded.replace(b'"integration":', b'"integration":"claude-code","integration":', 1)]
    for key in body:
        invalid += [compact({k: v for k, v in body.items() if k != key}), compact({**body, key: None}), compact({**body, key: 12})]
    for key in context(f["pa"]):
        invalid += [compact({**body, "context": {**body["context"], key: None}})]
    for extra in ("agent", "provider", "person_key", "approve", "invitation", "review_id"):
        invalid.append(compact({**body, extra: "PRIVATE_INPUT"}))
    invalid.append(compact({**body, "context": {**body["context"], "extra": "PRIVATE_INPUT"}}))
    for key in ("", "bad", base64.b64encode(b"a" * 31).decode(), base64.b64encode(b"a" * 32).decode().rstrip("="), " " + person):
        invalid.append(compact({**body, "person_public_key": key}))
    for net_id in ("", "alice", "net_1", "net_" + "A" * 64):
        invalid.append(compact({**body, "network_id": net_id}))
    quiet(f, h)
    before = snapshot(h)
    for index, data in enumerate(invalid):
        status, denied = raw(h, data)
        check(status == 400 and isinstance(denied, dict) and denied.get("code") == "invalid", f"closed API variant{index} HTTP {status}")
        public(denied, "PRIVATE_INPUT", body["context"]["project_root"], body["context"]["native_session_id"])
        result = h.cli("onboarding", "access", "inspect", "--stdin", input=data.decode(errors="replace"), timeout=8)
        check(not result.ok, f"CLI accepted invalid/duplicate/trailing/oversized variant{index}")
        public(result.stdout + result.stderr, "PRIVATE_INPUT", body["context"]["project_root"], body["context"]["native_session_id"], str(h.state))
    for args in ((), ("--approve", "--stdin"), ("--person-key", "PRIVATE_INPUT", "--stdin"),
                 ("--network", net, "--stdin"), (encoded.decode(),)):
        result = h.cli("onboarding", "access", "inspect", *args, input=encoded.decode(), timeout=8)
        check(not result.ok, "CLI accepted positional payload, signer override or missing --stdin")
        public(result.stdout + result.stderr, "PRIVATE_INPUT", body["context"]["project_root"], body["context"]["native_session_id"])
    for command in (("onboarding", "--state", str(h.state), "access", "inspect"),
                    ("onboarding", "access", "--state", str(h.state), "inspect"),
                    ("onboarding", "access", "inspect", "--state", str(h.state))):
        rejected = subprocess.run([str(suite.host_bin), *command, encoded.decode()],
                                  capture_output=True, env=h.env, cwd=h.root, timeout=8)
        check(rejected.returncode != 0, "global-flag CLI accepted a positional private payload")
        public((rejected.stdout + rejected.stderr).decode(errors="replace"),
               body["context"]["project_root"], body["context"]["native_session_id"], encoded.decode())
    for method in ("GET", "PUT", "PATCH", "DELETE"):
        status, denied = h.api(method, BASE, body, timeout=8)
        check(status in (404, 405), f"unsupported inspection method HTTP {status}")
        public(denied)
    check(snapshot(h) == before, "invalid input/CLI/methods changed aggregate DB/state/home")
    # Use a genuine current peer on a fresh network after the main fixture's
    # revocation. This also verifies explicit network choice with two networks.
    isolation = create_network(h, "route-isolation", "alice")
    join_new_person(h, f["b"], "bob", f["key"], isolation["id"])
    adapter = h.agent("inspection-boundary", ready=False)
    try:
        status, denied = adapter.call("POST", BASE, body)
        check(status == 404, "scoped adapter exposed owner access inspection")
        public(denied, adapter.token, adapter.instance)
    finally:
        adapter.stop()
    result = subprocess.run([str(suite.probe_bin), "--state", str(f["b"].state), "--address", h.peer_address,
        "--alpn", "peerspan-peer/1", "--path", BASE, "--method", "POST", "--body-stdin"],
        input=encoded, capture_output=True, timeout=15)
    check(json.loads(result.stdout).get("status") == 404, "authenticated peer exposed owner access inspection")
    public(result.stderr.decode(errors="replace"))
    cert, key = suite.work / "boundary-cert.pem", suite.work / "boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=boundary", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key))
    tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    with socket.create_connection(("127.0.0.1", h.bootstrap_port), timeout=5) as connection:
        with tls.wrap_socket(connection, server_hostname="peerspan") as stream:
            stream.sendall((f"POST {BASE} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\n"
                            f"Content-Length: {len(encoded)}\r\n\r\n").encode() + encoded)
            response = http.client.HTTPResponse(stream)
            response.begin()
            response.read()
            check(response.status == 404, "bootstrap exposed owner access inspection")
    for number, name in enumerate([p + "PRIVATE_INPUT" for p in PREFIXES] + ["to\u200bken_PRIVATE_INPUT", "to\u202eken_PRIVATE_INPUT"]):
        parent = project(h, "unsafe-" + str(number), agent={"kind": "new", "name": name, "owner": "public owner"})
        denied = inspect(h, parent, net, person, status=409, code="access_inspection_unavailable")
        public(denied, name, "PRIVATE_INPUT")
    absent = suite.host("missing", start=False)
    shutil.rmtree(absent.state)
    before_missing = files(absent.root)
    result = absent.cli("onboarding", "access", "inspect", "--stdin", input=encoded.decode(), timeout=8)
    check(not result.ok and files(absent.root) == before_missing and not absent.state.exists(), "missing-daemon CLI created state")
    public(result.stdout + result.stderr, body["context"]["project_root"], body["context"]["native_session_id"], str(absent.state))
    h.stop()
    before_stopped = files(h.state), files(h.home)
    result = h.cli("onboarding", "access", "inspect", "--stdin", input=encoded.decode(), timeout=8)
    check(not result.ok and (files(h.state), files(h.home)) == before_stopped, "stopped-daemon CLI changed files")
    public(result.stdout + result.stderr, body["context"]["project_root"], body["context"]["native_session_id"], str(h.state))


suite.finish()
