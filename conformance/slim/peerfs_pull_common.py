"""Shared fixtures of the PF-3 pull suites (peerfs_pull.py, peerfs_pull_agents.py).

Written independently from docs/peerfs-pull-contract.md (cited "pull N"; with its amendment that a fetch stopped
part way hands over the objects already held), decisions PF-07 to PF-11, the PF-3 paragraphs of
docs/host-service-contract.md, and PeerFS's README for what a pull does of its source. CI has no PeerFS binary:

- S (alice) serves its shared spaces through peerfs_read_common's fake provider, here `Source`, which can also
  serve a tampered object in place of the true one.
- L (bob) is a `Destination`: besides `GET /v1/host-bridge` it answers `POST /v1/pull {from, branch}` as the README
  describes a pull: `GET /v1/space`, `GET /v1/branches`, then `POST /v1/objects/fetch` rounds on the `from` socket,
  requiring every requested object in each answer, in order; each object is checked against the true graph
  (identity and kind); each commit's (abstract) signature is checked and its author key asked of bob's
  `host-keys/check` for L's binding; blobs are kept as they are checked, trees and commits only once the whole
  history is present, and the tracking reference `<host from /v1/space>/<branch>` is written last; it answers
  `{remote, branch, head, objects, bytes}`, the shape a genuine PeerFS binary gives (the README names none). Everything
  it saw of the proxy (paths and statuses, bodies, the socket's and directory's mode and owner) is recorded.

Refusals map as PeerFS's: a missing, mismatched or wrong-kind object or a failing source is 502 `remote`; a
signature that does not verify or an unrecognized author key is 403 `forbidden`.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time

from harness import UnixHTTPConnection, check, ssh_key, ssh_public_base64, wait_for
import peerfs_read_common as common
from peerfs_read_common import (BLOB, COMMIT, FILE, TREE, Graph, Provider, binding, compact, decode, encode,
                                http_reply, rule, state)

MIB = 1 << 20
ANSWER = {"peer", "space", "branch", "into", "tracking", "head", "objects", "bytes"}


class Source(Provider):
    """S's fake provider; TAMPER maps an object ID to the (kind, bytes) served instead of the true ones."""

    def __init__(self, registration, graph, old=False):
        super().__init__(registration, graph, old)
        self.tamper = {}

    def _route(self, method, target, body):
        reply = super()._route(method, target, body)
        if self.tamper and target == "/v1/objects/fetch" and reply.startswith(b"HTTP/1.1 200"):
            data = reply.split(b"\r\n\r\n", 1)[1]
            reply = http_reply(200, encode([(o, *self.tamper.get(o, (k, d))) for o, k, d in decode(data)]),
                               "application/octet-stream")
        return reply

    def asked(self):
        """Every object ID S's host asked this provider for."""
        return [i for f in self.fetches() for i in f["ids"]]


def truth(oid):
    for g in state["graphs"]:
        if oid in g.objects:
            return (*g.objects[oid], g.links[oid])
    return None


def sig_of(body):
    return hashlib.sha256(compact({k: body[k] for k in ("tree", "parents", "m", "host", "key")}).encode()).hexdigest()


def signed_commit(g, tree, parents, message, author=None, bad=False):
    """A commit naming its author host and key, with an abstract signature (BAD: one that does not verify)."""
    host, key = author or (state["a"].id, state["a"].public_key)
    body = {"tree": tree, "parents": list(parents), "m": message, "host": host, "key": key}
    body["sig"] = sig_of(body)[::-1] if bad else sig_of(body)
    oid = g.add(COMMIT, compact(body).encode(), [tree, *parents])
    g.commits[oid] = (tree, list(parents), message, None)
    return oid


def stranger():
    """A self-consistent host identity no context admitted: a genuine Ed25519 key, its ID the key's hash."""
    key = ssh_public_base64(ssh_key(state["roots"].parent, "stranger"))
    return "host_" + hashlib.sha256(base64.b64decode(key)).hexdigest(), key


def history(g, name, commits=2, blobs=(24, 30), last=(), author=None, bad=False, parent=None):
    """Branch NAME: COMMITS commits, each with a tree of one file of fresh blobs of sizes BLOBS (and, for the last,
    blobs LAST directly under its tree). Returns the head."""
    for n in range(commits):
        end = n == commits - 1
        file = g.add(FILE, os.urandom(20), [g.blob(s) for s in blobs])
        tree = g.add(TREE, os.urandom(40), [file, *([g.blob(s) for s in last] if end else [])])
        parent = signed_commit(g, tree, [parent] if parent else [], f"{name} {n}", author, bad and end)
    g.branches[name] = parent
    return parent


class Destination(Provider):
    """L's fake provider (see the module docstring). PROBE makes the next pull try the proxy's other paths;
    FOREIGN makes it connect once from another account (a callable given the socket path)."""

    def __init__(self, registration, graph, old=False):
        super().__init__(registration, graph, old)
        self.store, self.remotes, self.pulls = set(), {}, []
        self.store_lock = threading.Lock()
        self.probe, self.foreign, self.host = False, None, None
        self.recognized = {}

    def _route(self, method, target, body):
        if method == "POST" and target == "/v1/pull":
            return self._pull(body)
        return super()._route(method, target, body)

    def _fail(self, record, status, code, why):
        record["outcome"] = why
        record["ended"] = time.monotonic()
        return http_reply(status, compact({"code": code, "error": why}).encode())

    def _pull(self, body):
        record = {"request": json.loads(body), "calls": [], "asked": [], "batches": [], "fetched": 0, "bytes": 0, "probes": {},
                  "outcome": None, "key_checks": []}
        self.pulls.append(record)
        path, branch = record["request"].get("from"), record["request"].get("branch")
        try:
            sock, folder = os.lstat(path), os.lstat(os.path.dirname(path))
            record.update(socket=path, directory=os.path.dirname(path), is_socket=stat.S_ISSOCK(sock.st_mode),
                          mode=stat.S_IMODE(sock.st_mode), uid=sock.st_uid, dir_mode=stat.S_IMODE(folder.st_mode),
                          dir_uid=folder.st_uid)
        except (OSError, TypeError) as error:
            return self._fail(record, 502, "remote", f"no source socket: {error}")

        def call(method, target, payload=None):
            connection = UnixHTTPConnection(path, timeout=150)
            try:
                data = None if payload is None else (payload if isinstance(payload, bytes) else compact(payload).encode())
                connection.request(method, target, body=data,
                                   headers={"Content-Type": "application/json"} if data is not None else {})
                response = connection.getresponse()
                result = response.status, response.read()
            except (OSError, http.client.HTTPException) as error:
                result = 0, str(error).encode()
            finally:
                connection.close()
            record["calls"].append((method, target, result[0]))
            return result

        status, data = call("GET", "/v1/space")
        if status != 200:
            return self._fail(record, 502, "remote", f"space: {status}")
        record["space"] = space = json.loads(data)
        status, data = call("GET", "/v1/branches")
        if status != 200:
            return self._fail(record, 502, "remote", f"branches: {status}")
        record["branches"] = json.loads(data)
        heads = [b.get("head") for b in record["branches"] if isinstance(b, dict) and b.get("name") == branch]
        if not heads:
            return self._fail(record, 404, "not_found", "no such branch at the source")
        head = heads[0]
        if self.probe:
            self.probe = False
            self._probe(record, call, head, branch)
        if self.foreign:
            foreign, self.foreign = self.foreign, None
            record["foreign"] = foreign(path)
        pending, frontier = {}, [head]
        while frontier:
            want = []
            for oid in frontier:
                if oid not in self.store and oid not in pending and oid not in want:
                    want.append(oid)
            frontier = []
            for start in range(0, len(want), 256):
                ids = want[start:start + 256]
                record["asked"].append(ids)
                status, data = call("POST", "/v1/objects/fetch", {"ids": ids})
                if status != 200:
                    return self._fail(record, 502, "remote", f"fetch: {status}")
                try:
                    got = decode(data)
                except Exception:  # noqa: BLE001 - a malformed batch is the source's failure
                    return self._fail(record, 502, "remote", "malformed batch")
                record["fetched"] += len(got)
                record["bytes"] += len(data)
                record["batches"].append([o for o, _, _ in got])
                for n, oid in enumerate(ids):
                    if n >= len(got) or got[n][0] != oid:
                        return self._fail(record, 502, "remote", "missing object")
                    kind, content = got[n][1], got[n][2]
                    true = truth(oid)
                    if true is None or true[1] != content:
                        return self._fail(record, 502, "remote", "identity")
                    if true[0] != kind:
                        return self._fail(record, 502, "remote", "kind")
                    if kind == COMMIT:
                        problem = self._verify(record, content)
                        if problem:
                            return self._fail(record, 403, "forbidden", problem)
                    if kind == BLOB:
                        with self.store_lock:
                            self.store.add(oid)
                    else:
                        pending[oid] = True
                    frontier.extend(true[2])
        with self.store_lock:
            self.store.update(pending)
            self.remotes[f"{space.get('host')}/{branch}"] = head
        record["outcome"], record["ended"] = "ok", time.monotonic()
        # The answer of a genuine PeerFS pull (observed from the binary; the README does not give its shape).
        return http_reply(200, compact({"remote": space.get("host"), "branch": branch, "head": head,
                                        "objects": record["fetched"], "bytes": record["bytes"]}).encode())

    def _verify(self, record, content):
        body = json.loads(content)
        if body.get("sig") != sig_of(body):
            return "signature"
        pair = (body["host"], body["key"])
        if pair not in self.recognized:
            r = self.registration
            status, value = self.host.api("POST", f"/v1/fs/spaces/{r['space_id']}/host-keys/check",
                                          {"binding_id": r["binding_id"], "host_id": pair[0], "public_key": pair[1]})
            record["key_checks"].append((pair, status, value))
            self.recognized[pair] = status == 200 and isinstance(value, dict) and value.get("recognized") is True
        return None if self.recognized[pair] else "unrecognized author"

    def _probe(self, record, call, head, branch):
        """Paths beyond the three, and fetches outside {ids} with 1 to 256 distinct IDs."""
        others = [("GET", "/v1/host-bridge", None), ("GET", "/v1/remotes", None), ("POST", "/v1/space", {}),
                  ("GET", f"/v1/branches/{branch}/log", None), ("POST", "/v1/branches", {"name": "x", "from": branch}),
                  ("POST", "/v1/objects/have", {"ids": [head]}), ("POST", "/v1/pull", {"from": "/x", "branch": "y"}),
                  ("GET", "/v1/objects/fetch", None), ("GET", "/v1/space/x", None), ("GET", "/", None)]
        for method, target, payload in others:
            record["probes"][f"{method} {target}"] = (call(method, target, payload)[0], 404)
        many = ["01" + os.urandom(32).hex() for _ in range(257)]
        for label, payload in (("two of one ID", {"ids": [head, head]}), ("no IDs", {"ids": []}),
                               ("within", {"ids": [head], "within": branch}), ("257 IDs", {"ids": many}),
                               ("not JSON", b"{\"ids\":")):
            record["probes"][f"fetch {label}"] = (call("POST", "/v1/objects/fetch", payload)[0], 400)


FOREIGN_SCRIPT = r"""
import ctypes, os, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
# Keep capabilities across the effective-UID change (SECBIT_NO_SETUID_FIXUP), so path permissions are not what
# refuses: only the proxy's own SO_PEERCRED check can.
if libc.prctl(28, 1 << 2, 0, 0, 0) != 0:
    print("setup prctl", ctypes.get_errno()); sys.exit()
os.setegid(65534); os.seteuid(65534)
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print("connect", e.errno); sys.exit()
try:
    s.sendall(b"GET /v1/space HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
except OSError as e:
    print("io", e.errno); sys.exit()
print("answer", data[:40].decode(errors="replace").replace("\r\n", " "))
"""


def foreign_connect(path):
    p = subprocess.run([sys.executable, "-I", "-c", FOREIGN_SCRIPT, path], capture_output=True, timeout=15)
    return p.stdout.decode(errors="replace").strip() or p.stderr.decode(errors="replace")[-200:]


# Hosts, spaces and pulls.

def destination(net, activate=True):
    """A binding on bob served by a Destination."""
    d = binding(net, host=state["b"], cls=Destination, activate=activate)
    d["provider"].host = state["b"]
    return d


def source(net, graph):
    s = binding(net, graph, cls=Source)
    state["graphs"].append(graph)
    return s


def proxies():
    """The pull directories now in bob's state directory (host-service PF-3: `pull-<16 hex>`)."""
    return sorted(p.name for p in state["b"].state.glob("pull-*"))


def pull(branch, into, space, network=None, max_bytes=None, adapter=None, timeout=180, **extra):
    body = {"peer": state["a"].id, "space": space, "branch": branch, "into": into, **extra}
    if network:
        body["network"] = network
    if max_bytes is not None:
        body["max_bytes"] = max_bytes
    if adapter is not None:
        return adapter.call("POST", "/adapter/v1/fs/pulls", body, timeout=timeout)
    return state["b"].api("POST", "/v1/fs/pulls", body, timeout=timeout)


def tracking(space, branch):
    return f"{state['a'].id}:{space}/{branch}"


def pulled(status, value, branch, into, space, head, what):
    """Check a pull's answer (pull 2 step 5) and that the reference was written at HEAD."""
    provider = destinations()[into]["provider"]
    seen = f"(L saw {[(m, t) for m, t, _ in provider.requests[-4:]]}, " \
           f"last pull {provider.pulls[-1]['outcome'] if provider.pulls else None})"
    check(status == 200, f"{what}: HTTP {status} {value} {seen}")
    check(isinstance(value, dict) and set(value) == ANSWER, f"{what}: answer fields {value}")
    want = {"peer": state["a"].id, "space": space, "branch": branch, "into": into,
            "tracking": tracking(space, branch), "head": head}
    check({k: value[k] for k in want} == want, f"{what}: answer {value}, want {want}")
    ref = destinations()[into]["provider"].remotes.get(tracking(space, branch))
    check(ref == head, f"{what}: tracking reference {ref}, want {head}")
    return value


def destinations():
    return {d["id"]: d for d in state["dest"].values()}


def refused(status, value, want, code, what):
    check(status == want and isinstance(value, dict) and value.get("code") == code,
          f"{what}: HTTP {status} {value}, want {want} {code}")


def gone(directory, what):
    wait_for(lambda: not Path(directory).exists(), timeout=5, interval=.1, message=f"{what}: the proxy removed")


def fs_pulled(subject):
    status, body = state["b"].api("GET", "/v1/activity?limit=1000")
    check(status == 200, f"activity: {status} {body}")
    entries = body if isinstance(body, list) else next(v for v in body.values() if isinstance(v, list))
    return [e for e in entries if e.get("kind") == "fs.pulled" and e.get("subject_id") == subject]


def share_all(branches, extra=()):
    """Sign alice's policy with one fs.read rule for bob per (space, branch) in BRANCHES, plus EXTRA rules."""
    return common.signed([rule(s, b, [state["bob_p"]]) for s, b in branches] + list(extra))


def stalled(provider):
    """Hold the provider's fetches until the returned release is called."""
    provider.release.clear()
    provider.held, provider.stall = 0, "fetch"

    def release():
        provider.stall = None
        provider.release.set()
    return release


def in_thread(function, *args, **kw):
    out = {}

    def run():
        try:
            out["value"] = function(*args, **kw)
        except Exception as error:  # noqa: BLE001 - reported by the case
            out["error"] = error
    t = threading.Thread(target=run, daemon=True)
    t.start()
    out["thread"] = t
    return out


def start(networks=None):
    """Hosts (alice serves, bob pulls), bob joined to alice's net1."""
    common.start_hosts(networks or {"net1": ("files", True)})
    state.update(graphs=[], dest={})
    roots = state["roots"]
    roots.chmod(0o700)
