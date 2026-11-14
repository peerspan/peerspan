"""Shared fixtures of the PF-2 read suites (peerfs_read.py, peerfs_read_lapse.py).

Written independently from docs/peerfs-read-contract.md (cited "read N"), its PF-06
amendment (a first object alone over 16 MiB is 503), docs/peerfs-local-contract.md
sections 3-4, the PF-2 paragraph of docs/host-service-contract.md and the public
vectors docs/vectors/peerfs-read-policy.json. CI has no PeerFS binary, so an in-suite
fake provider on `<directory>/peerfs.sock` serves `GET /v1/host-bridge`, `GET
/v1/branches`, `GET /v1/branches/{name}/log` and `POST /v1/objects/fetch` (with and
without `within`) in the PeerFS batch encoding (uleb128 count; per object the 33-byte
ID, a kind byte and uleb128-length bytes). Its object graph is abstract: IDs are
random, so the suites check bytes and order against the fake, not BLAKE3 identities.
alice's host serves (S); bob's host reads (R) through `peerspan-peer-probe`.

A suite calls `bind(suite, clock)` once, then `start_hosts(...)` in its setup case.
"""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import urllib.parse
from datetime import timedelta

from harness import check, create_network, join_new_person, rfc3339, ssh_key
from runtime_common import policy_statement, policy_version, run_side_by_side, sshsig

MIB = 1 << 20
LIMIT = 16 * MIB
REPO = Path(__file__).resolve().parents[2]
VECTORS = json.loads((REPO / "docs/vectors/peerfs-read-policy.json").read_text())
RULE_KEYS = ["host", "space", "branch", "principals", "actions", "allow_disconnected"]
state = {}
suite = clock = None


def bind(the_suite, the_clock):
    global suite, clock
    suite, clock = the_suite, the_clock


def start_hosts(networks, lapsing=None):
    """alice and bob; alice creates NETWORKS ({key: (name, bob joins)}); bob's grants in LAPSING end after 4 days
    and 1 hour, outside the root's renewal threshold until the clock jumps (spec 7.1)."""
    a, b = suite.host("alice"), suite.host("bob")
    state.update(a=a, b=b, roots=suite.work / "roots", alice_public={})
    state["roots"].mkdir(mode=0o700)
    state["alice_key"] = a.home / ".config/peerspan/person_ed25519"
    state["bob_key"] = ssh_key(b.root, "bob")
    joins = []
    for key, (name, joined) in networks.items():
        net = state[key] = create_network(a, name, "alice")
        state["alice_public"][net["id"]] = a.api("GET", f"/v2/networks/{net['id']}")[1]["person_public_key"]
        if joined:
            extra = {"not_after": rfc3339(clock.now().replace(microsecond=0) + timedelta(days=4, hours=1))} \
                if key == lapsing else {}
            joins.append((join_new_person, (a, b, "bob", state["bob_key"], net["id"]), extra))
    run_side_by_side(*joins)
    state["alice_pid"] = a.ok("person", "show", "--person-key", state["alice_key"])["person_id"]
    state["bob_pid"] = b.ok("person", "show", "--person-key", state["bob_key"])["person_id"]
    state["bob_p"] = f"person:{state['bob_pid']}"


def simple_graph(name):
    g = Graph()
    g.branches["main"] = g.commit(g.add(TREE, b"t", [g.blob()]), [], name)
    return g


def sp(name):
    return state["spaces"][name]["id"]


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


# The PeerFS batch encoding and an abstract object graph.

def uleb(number):
    out = bytearray()
    while True:
        byte, number = number & 127, number >> 7
        out.append(byte | (128 if number else 0))
        if not number:
            return bytes(out)


def read_uleb(data, i):
    number = shift = 0
    while True:
        byte = data[i]
        i += 1
        number |= (byte & 127) << shift
        shift += 7
        if byte < 128:
            return number, i


def encode(objects):
    return uleb(len(objects)) + b"".join(bytes.fromhex(i) + bytes([k]) + uleb(len(d)) + d for i, k, d in objects)


def decode(data):
    count, i = read_uleb(data, 0)
    out = []
    for _ in range(count):
        oid, kind = data[i:i + 33].hex(), data[i + 33]
        length, i = read_uleb(data, i + 34)
        out.append((oid, kind, data[i:i + length]))
        i += length
    check(i == len(data), f"batch has {len(data) - i} trailing bytes")
    return out


def encoded_size(length):
    return 33 + 1 + len(uleb(length)) + length


BLOB, FILE, TREE, COMMIT = 1, 2, 3, 4


class Graph:
    """Objects (id -> kind, bytes), strong links followed by reach, and weak `predecessor` links never followed."""

    def __init__(self):
        self.objects, self.links, self.branches, self.commits = {}, {}, {}, {}

    def add(self, kind, data, links=()):
        oid = "01" + os.urandom(32).hex()
        self.objects[oid], self.links[oid] = (kind, data), list(links)
        return oid

    def blob(self, size=24):
        return self.add(BLOB, os.urandom(size) if size <= 4096 else bytes([size % 251]) * size)

    def commit(self, tree, parents=(), message="change", predecessor=None):
        data = compact({"tree": tree, "parents": list(parents), "predecessor": predecessor, "m": message}).encode()
        oid = self.add(COMMIT, data, [tree, *parents])
        self.commits[oid] = (tree, list(parents), message, predecessor)
        return oid

    def reach(self, branch):
        seen, todo = set(), [self.branches[branch]]
        while todo:
            oid = todo.pop()
            if oid not in seen:
                seen.add(oid)
                todo.extend(self.links[oid])
        return seen

    def log(self, branch):
        out, todo, seen = [], [self.branches[branch]], set()
        while todo:
            oid = todo.pop(0)
            if oid in seen:
                continue
            seen.add(oid)
            tree, parents, message, predecessor = self.commits[oid]
            entry = {"id": oid, "tree": tree, "parents": parents, "change": os.urandom(16).hex(), "host": "fake",
                     "agent": "suite", "time_ms": 1794600000000 + len(seen), "message": message,
                     "signed_by": base64.b64encode(b"\1" * 32).decode()}
            if predecessor:
                entry["predecessor"] = predecessor
            out.append(entry)
            todo.extend(parents)
        return out

    def entry(self, oid):
        return (oid, *self.objects[oid])


def http_reply(status, body, content_type="application/json"):
    return (b"HTTP/1.1 %d X\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % (status, content_type.encode(), len(body)) + body)


def not_found():
    return http_reply(404, b'{"code":"not_found","error":"not found"}')


class Provider:
    """A fake PeerFS provider for one binding. OLD refuses `within` as an older provider does; STALL holds
    answers of that route kind ("fetch" or "branches") until `release` is set."""

    def __init__(self, registration, graph, old=False):
        self.registration, self.graph, self.old = registration, graph, old
        self.path = Path(registration["directory"]) / "peerfs.sock"
        self.requests, self.stall, self.release, self.held = [], None, threading.Event(), 0
        self.lock, self.done = threading.Lock(), threading.Event()
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        self.path.chmod(0o600)
        self.listener.listen(16)
        self.listener.settimeout(.05)
        threading.Thread(target=self._serve, daemon=True).start()

    def identity(self):
        r = self.registration
        return {"format": 1, "protocol": "peerfs-host-v1", **{k: r[k] for k in (
            "space_id", "binding_id", "network_id", "context_id", "host_id", "public_key", "directory")}}

    def _serve(self):
        while not self.done.is_set():
            try:
                connection, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._answer, args=(connection,), daemon=True).start()

    def _answer(self, connection):
        with connection:
            connection.settimeout(40)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = connection.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                head, body = data.split(b"\r\n\r\n", 1)
                lines = head.decode().split("\r\n")
                length = next((int(l.split(":", 1)[1]) for l in lines if l.lower().startswith("content-length:")), 0)
                while len(body) < length:
                    body += connection.recv(65536)
                method, target = lines[0].split(" ")[:2]
                with self.lock:
                    self.requests.append((method, target, body))
                connection.sendall(self._route(method, target, body))
            except OSError:
                pass

    def _hold(self, kind):
        if self.stall == kind:
            with self.lock:
                self.held += 1
            self.release.wait(35)

    def _route(self, method, target, body):
        g = self.graph
        path, _, query = target.partition("?")
        parts = [urllib.parse.unquote(p) for p in path.split("/")]
        if method == "GET" and path == "/v1/host-bridge":
            return http_reply(200, compact(self.identity()).encode())
        if method == "GET" and path == "/v1/branches":
            self._hold("branches")
            return http_reply(200, compact([{"name": n, "head": h} for n, h in sorted(g.branches.items())]).encode())
        if method == "GET" and len(parts) == 5 and parts[1:3] == ["v1", "branches"] and parts[4] == "log":
            self._hold("branches")
            if parts[3] not in g.branches:
                return not_found()
            limit = dict(urllib.parse.parse_qsl(query)).get("limit")
            log = g.log(parts[3])
            return http_reply(200, compact(log[:int(limit)] if limit else log).encode())
        if method == "POST" and path == "/v1/objects/fetch":
            request = json.loads(body)
            if self.old and "within" in request:
                return http_reply(400, b'{"code":"invalid","error":"Failed to deserialize the JSON body into the '
                                       b'target type: within: unknown field `within`, expected `ids`"}')
            self._hold("fetch")
            ids = request["ids"]
            if "within" in request:
                if request["within"] not in g.branches or not set(ids) <= g.reach(request["within"]):
                    return not_found()
            batch = encode([g.entry(i) for i in ids if i in g.objects])
            return http_reply(200, batch, "application/octet-stream")
        return not_found()

    def fetches(self):
        return [json.loads(b) for m, t, b in self.requests if t == "/v1/objects/fetch"]

    def stop(self):
        self.done.set()
        self.listener.close()
        if self.path.exists():
            self.path.unlink()


# Hosts, bindings and policies.

def binding(net, graph=None, activate=True, old=False):
    """Prepare (and activate) a binding on alice for NET, served by a fake provider over GRAPH."""
    a = state["a"]
    state["counter"] = state.get("counter", 0) + 1
    directory = state["roots"] / f"s{state['counter']}"
    directory.mkdir(mode=0o700)
    terms = {"space_id": "space_" + os.urandom(16).hex(), "network_id": net["id"], "context_id": net["context_id"],
             "directory": str(directory)}
    status, registration = a.api("POST", "/v1/fs/spaces", terms)
    check(status == 201, f"fixture: prepare: {status} {registration}")
    provider = Provider(registration, graph or Graph())
    provider.old = old
    if activate:
        status, value = a.api("POST", f"/v1/fs/spaces/{terms['space_id']}/activate",
                              {"binding_id": registration["binding_id"]})
        check(status == 200 and value["registration"]["state"] == "registered", f"fixture: activate: {status} {value}")
    return {"id": terms["space_id"], "registration": registration, "provider": provider, "graph": provider.graph,
            "directory": directory}


def rule(space, branch, principals, allow_disconnected=False, host=None):
    return {"host": host or state["a"].id, "space": space, "branch": branch, "principals": sorted(principals),
            "actions": ["fs.read"], "allow_disconnected": allow_disconnected}


def body_text(body, fs_raw):
    """BODY (keys in order, without fs_rules) as compact JSON with FS_RAW spliced in after peerbox_rules, or where
    it would be (read 2)."""
    items = [(k, compact(v)) for k, v in body.items() if k != "fs_rules"]
    if fs_raw is not None:
        anchor = max(i for i, (k, _) in enumerate(items) if k in ("capability_rules", "runtime_rules", "peerbox_rules"))
        items.insert(anchor + 1, ("fs_rules", fs_raw))
    return "{" + ",".join(compact(k) + ":" + v for k, v in items) + "}"


def sign(rules=None, fs_raw=None, net=None):
    """Sign alice's next policy in NET with its fs_rules replaced by RULES, or the exact text FS_RAW, or omitted.
    Returns (status, response, body bytes)."""
    a, key = state["a"], state["alice_key"]
    net = net or state["net1"]
    person = state["alice_public"][net["id"]]
    statement_id, _, payload, body = policy_statement(a, person, net["id"])
    now = a.now().replace(microsecond=0)
    until = now + timedelta(hours=23)
    body.update(version=body["version"] + 1, issued_at=rfc3339(now), valid_until=rfc3339(until))
    status, plan = a.api("POST", f"/v2/networks/{net['id']}/policy-edits/plan", {"provider_id": person})
    check(status == 200, f"policy-edits/plan: {status} {plan}")
    edits = [e for e in body.get("edits", []) if e["host"] != a.id] + [{"host": a.id, "seq": plan["seq"]}]
    body["edits"] = sorted(edits, key=lambda e: e["host"])
    if rules is not None:
        fs_raw = compact(sorted(rules, key=lambda r: (r["host"], r["space"], r["branch"].encode()))) if rules else None
    text = body_text(body, fs_raw).encode()
    payload.update(sequence=payload["sequence"] + 1, predecessors=[statement_id], resolves=[],
                   issuer={"kind": "person", "person_public_key": person},
                   parents=[p for p in payload["parents"] if p["role"] == "issuer_person"],
                   issued_at=rfc3339(now), not_before=rfc3339(now), not_after=rfc3339(until),
                   body_base64=base64.b64encode(text).decode())
    status, response = a.api("POST", f"/v2/networks/{net['id']}/actions", {
        "kind": "policy", "provider_id": person, "signature_format": "sshsig",
        "payload_base64": base64.b64encode(compact(payload).encode()).decode(), "approve": True})
    while status == 200 and response.get("signing_requests"):
        signatures = [{"slot_id": r["slot_id"], "role": r["role"],
                       "signature": sshsig(key, base64.b64decode(r["message_base64"]))}
                      for r in response["signing_requests"]]
        status, response = a.api("POST", f"/v2/networks/{net['id']}/actions/{response['action_id']}/signed",
                                 {"intent_id": response["signing_requests"][0]["intent_id"], "signatures": signatures})
    return status, response, text


def signed(rules, net=None):
    status, response, _ = sign(rules, net=net)
    check(status == 200 and response.get("committed"), f"fixture: sign fs_rules: {status} {response}")
    return version(net)


def version(net=None):
    net = net or state["net1"]
    return policy_version(state["a"], state["alice_public"][net["id"]], net["id"])


def raw_body(net=None):
    """The exact bytes of alice's current policy body in NET."""
    net = net or state["net1"]
    status, current = state["a"].api(
        "GET", f"/v2/networks/{net['id']}/policy/{urllib.parse.quote(state['alice_public'][net['id']], safe='')}")
    check(status == 200, f"current policy: {status}")
    envelope = json.loads(base64.b64decode(current["statement_base64"]))
    return base64.b64decode(json.loads(base64.b64decode(envelope["payload_base64"]))["body_base64"])


def fs_rules(net=None):
    return json.loads(raw_body(net)).get("fs_rules")


def cite(net=None, ver=None):
    return {"person_id": state["alice_pid"], "version": ver if ver is not None else version(net)}


# Peer requests (read 5).

def probe(method, path, body=None, raw=None, sender=None, receiver=None, timeout=45):
    sender, receiver = sender or state["b"], receiver or state["a"]
    args = [str(suite.probe_bin), "--address", receiver.peer_address, "--alpn", "peerspan-peer/1", "--path", path,
            "--method", method, "--state", str(sender.state), "--raw-body"]
    data = raw if raw is not None else None if body is None else compact(body).encode()
    if data is not None:
        args.append("--body-stdin")
    p = subprocess.run(args, input=data or b"", capture_output=True, timeout=timeout)
    check(p.returncode == 0, f"probe {method} {path}: exit {p.returncode} {p.stderr.decode(errors='replace')[-300:]}")
    answer = json.loads(p.stdout)
    return answer["status"], base64.b64decode(answer.get("body_base64") or ""), answer


def as_json(data):
    try:
        return json.loads(data)
    except ValueError:
        return data


def branches(network, sender=None):
    status, data, _ = probe("GET", f"/peer/v1/fs/branches?network={network}", sender=sender)
    return status, as_json(data)


def fs_path(space, branch, op):
    return f"/peer/v1/fs/spaces/{space}/branches/{urllib.parse.quote(branch, safe='')}/{op}"


def head(space, branch, policy=None, **kw):
    status, data, _ = probe("POST", fs_path(space, branch, "head"), {"policy": policy or cite()}, **kw)
    return status, as_json(data)


def objects(space, branch, ids, policy=None, **kw):
    body = {"policy": policy or cite(), "ids": ids}
    status, data, answer = probe("POST", fs_path(space, branch, "objects"), body, **kw)
    return status, data, answer


NOT_FOUND = []


def refused(status, data, want, what):
    check(status == want, f"{what}: HTTP {status} {as_json(data) if isinstance(data, bytes) else data}, want {want}")
    if want == 404:
        NOT_FOUND.append(data if isinstance(data, bytes) else compact(data).encode())


def fetched(space, branch, ids, what):
    status, data, answer = objects(space, branch, ids)
    check(status == 200, f"{what}: HTTP {status} {as_json(data)}")
    length = {k.lower(): v for k, v in (answer.get("headers") or {}).items()}.get("content-length")
    check(length is None or int(length) == len(data), f"{what}: Content-Length {length} for {len(data)} bytes")
    return decode(data)


def listing(*pairs):
    """The expected discovery entries for (space, branch) PAIRS, sorted by (space, branch)."""
    return [{"host": state["a"].id, "space": s, "branch": b, "policy": cite()}
            for s, b in sorted(pairs, key=lambda p: (p[0], p[1].encode()))]


def provider_calls():
    return {name: len(sp["provider"].requests) for name, sp in state["spaces"].items()}


def share(space, branch, *principals, net=None, extra=(), tty=False, answer=None):
    a = state["a"]
    args = ["fs", "share", space, branch, *sum((["--with", p] for p in principals), []), "--network",
            (net or state["net1"])["id"], "--person-key", str(state["alice_key"]), *extra]
    if tty:
        return a.cli(*args, tty=True, input=answer, timeout=60)
    return a.cli("--json", *args, "--yes", timeout=90)


def shares_listed(net=None):
    result = state["a"].cli("fs", "shares", "--network", (net or state["net1"])["id"], "--json")
    check(result.ok, f"fs shares: exit {result.code} {result.stderr.strip()[-200:]}")
    found = []

    def walk(value):
        if isinstance(value, dict):
            if "branch" in value and ("space" in value or "space_id" in value):
                found.append(value)
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
    walk(result.json)
    return {(e.get("space") or e.get("space_id"), e["branch"]): e for e in found}


