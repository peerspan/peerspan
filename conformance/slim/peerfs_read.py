#!/usr/bin/env python3
"""PF-2: policy vectors, share/unshare, discovery, head and objects, rules, provider states and router isolation.

Written independently from docs/peerfs-read-contract.md section 8 with its PF-06 amendment; the fixtures, fake
provider and their sources are in peerfs_read_common.py. The two-network listing, lapsed membership and renewal
cases need the test clock and a second join and are in peerfs_read_lapse.py.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

from harness import Suite, check, free_port, wait_for
from runtime_common import learn
import peerfs_read_common as common
from peerfs_read_common import (FILE, LIMIT, MIB, NOT_FOUND, RULE_KEYS, TREE, VECTORS, Graph, Provider, as_json,
                                binding, branches, cite, compact, encode, encoded_size, fetched, fs_path, fs_rules,
                                head, listing, need, objects, probe, provider_calls, raw_body, refused, rule, share,
                                shares_listed, sign, signed, simple_graph, sp, state, version)

os.umask(0o077)
suite = Suite("peerfs_read", __doc__)
common.bind(suite, None)


def main_graph():
    """main: seven commits; the head's predecessor is a snapshot reaching its own tree; dev forks at c3 with its own
    blob; an orphan; 300 small blobs and the large objects under the head's tree."""
    g = Graph()
    commits, parent = [], None
    shared = g.blob()
    for n in range(7):
        tree = g.add(TREE, os.urandom(40), [g.add(FILE, os.urandom(20), [g.blob(), shared])])
        parent = g.commit(tree, [parent] if parent else [], f"c{n + 1}")
        commits.append(parent)
    snap_blob = g.blob()
    snap_tree = g.add(TREE, os.urandom(40), [snap_blob])
    snapshot = g.commit(snap_tree, [commits[-1]], "snapshot")
    small = [g.blob(8) for _ in range(300)]
    first = 8 * MIB
    large = [g.blob(first), g.blob(LIMIT - 1 - encoded_size(first) - 34 - 4)]
    large.append(g.blob(len(g.objects[large[1]][1]) + 1))
    huge = g.blob(17 * MIB)
    top = g.add(TREE, os.urandom(40), [*small, *large, huge])
    head = g.commit(top, [commits[-1]], "c8", predecessor=snapshot)
    dev_blob = g.blob()
    dev = g.commit(g.add(TREE, os.urandom(40), [dev_blob]), [commits[2]], "dev")
    g.branches = {"main": head, "dev": dev}
    orphan = g.blob()
    state["obj"] = dict(head=head, commits=commits, snapshot=snapshot, snap_tree=snap_tree, snap_blob=snap_blob,
                        small=small, large=large, huge=huge, dev_blob=dev_blob, orphan=orphan, top=top)
    check(len(encode([g.entry(i) for i in large[:2]])) == LIMIT, "fixture: large pair is not exactly 16 MiB")
    return g


@suite.case("setup", "decentralized-spec 6, 8; PF-1 sections 3-4 (prepare, activate)")
def _():
    common.start_hosts({"net1": ("files", True), "net3": ("files-alone", False)})
    a, net1 = state["a"], state["net1"]
    spaces = {"one": binding(net1, main_graph()), "two": binding(net1, simple_graph("two"))}
    for name in ("stopped", "changed", "old", "released"):
        spaces[name] = binding(net1, simple_graph(name), old=(name == "old"))
    spaces["prepared"] = binding(net1, activate=False)
    r = spaces["released"]["registration"]
    status, _ = a.api("POST", f"/v1/fs/spaces/{r['space_id']}/release", {"binding_id": r["binding_id"]})
    check(status == 200, f"fixture: release: {status}")
    state["spaces"] = spaces


@suite.case("policy_vectors", "read 2: public vectors; exact keys and order; each refused shape invalid")
def _():
    need("spaces")
    for vector in VECTORS["positive"]:
        check(hashlib.sha256(vector["body"].encode()).hexdigest() == vector["body_sha256_hex"],
              f"vector {vector['name']}: body digest")
    positive = next(v for v in VECTORS["positive"] if v["name"] == "with_fs_rules")["body"]

    def spliced(text):
        start = text.index('"fs_rules":') + len('"fs_rules":')
        return text[start:text.index(',"trusted_hosts"')]
    before = version()
    status, response, text = sign(fs_raw=spliced(positive))
    check(status == 200 and response.get("committed"), f"the positive vector's fs_rules: {status} {response}")
    check(raw_body() == text, "the admitted body is not byte-identical to the signed one")
    check(('"fs_rules":' + spliced(positive)).encode() in raw_body(), "stored fs_rules differ from the vector's")
    learn(state["b"], state["alice_public"][state["net1"]["id"]], before + 1, state["net1"]["id"])
    current, accepted = version(), []
    for vector in VECTORS["negative"]:
        status, response, _ = sign(fs_raw=spliced(vector["body"]))
        if not (status == 400 and isinstance(response, dict) and response.get("code") == "invalid"):
            accepted.append(f"{vector['name']} ({status} {str(response)[:80]})")
    check(not accepted, f"refused shapes not answered 400 invalid: {accepted}")
    check(version() == current, "a refused policy changed the current version")
    status, response, text = sign([])
    check(status == 200 and response.get("committed") and b"fs_rules" not in raw_body(),
          f"a policy without filesystem rules omits fs_rules: {status} {response}")


@suite.case("share_review_and_shares", "read 7; host-service PF-2: review fields, unregistered refused, shares")
def _():
    a = state["a"]
    one, g = sp("one"), state["spaces"]["one"]["graph"]
    status, empty = branches(state["net1"]["id"])
    check(status == 200 and empty == {"network": state["net1"]["id"], "branches": []},
          f"a peer without a rule: {status} {empty}")
    status, view = a.api("GET", f"/v1/fs/spaces/{one}/branches/main")
    reg = state["spaces"]["one"]["registration"]
    check(status == 200 and view == {"space_id": one, "binding_id": reg["binding_id"],
                                     "network_id": state["net1"]["id"],
                                     "branch": "main", "head": g.branches["main"], "commits": 8},
          f"owner-local branch read: {status} {view}")
    before = version()
    review = share(one, "main", state["bob_p"], tty=True, answer="n\n")
    text = review.stdout + review.stderr
    missing = [w for w in (one, "main", g.branches["main"], "8", state["bob_pid"], "history") if w not in text]
    check(not missing, f"the review does not name {missing}: {text[-600:]!r}")
    check(version() == before, "declining the review signed a policy")
    for name in ("prepared", "released"):
        refusal = share(sp(name), "main", state["bob_p"])
        check(not refusal.ok and version() == before, f"fs share of a {name} binding: exit {refusal.code}")
    result = share(one, "main", state["bob_p"])
    check(result.ok, f"fs share: exit {result.code} {result.stderr.strip()[-300:]}")
    check(version() == before + 1, "fs share did not sign the next version")
    body = json.loads(raw_body())
    keys = list(body)
    anchor = max(keys.index(k) for k in ("capability_rules", "runtime_rules", "peerbox_rules") if k in keys)
    check(keys.index("fs_rules") == anchor + 1, f"fs_rules is not where peerbox_rules would be: {keys}")
    check([list(r) for r in body["fs_rules"]] == [RULE_KEYS]
          and body["fs_rules"][0] == rule(one, "main", [state["bob_p"]]),
          f"signed rule {body['fs_rules']}")
    listed = shares_listed()
    check(set(listed) == {(one, "main")} and state["bob_p"] in compact(listed[(one, "main")])
          and compact(listed[(one, "main")]).count(str(before + 1)) >= 1, f"fs shares after share: {listed}")
    state["base_rules"] = body["fs_rules"]


def full_rules(*, one_main=True):
    bob = [state["bob_p"]]
    rules = [rule(sp(n), "main", bob) for n in ("two", "stopped", "changed", "old", "prepared", "released")]
    rules += [rule(sp("one"), "dev", bob), rule(sp("one"), "ghost", bob),
              rule(sp("two"), "theirs", ["person:person_" + "f" * 64])]
    if one_main:
        rules.append(rule(sp("one"), "main", bob))
    return rules


@suite.case("discovery", "read 5 Discovery: exact rules, registered only, no provider contact, unshared network, 400")
def _():
    need("base_rules")
    signed(full_rules())
    calls = provider_calls()
    status, value = branches(state["net1"]["id"])
    want = listing(*[(sp(n), "main") for n in ("one", "two", "stopped", "changed", "old")],
                   (sp("one"), "dev"), (sp("one"), "ghost"))
    check(status == 200 and value == {"network": state["net1"]["id"], "branches": want},
          f"net1 listing: {status} {value}, want {want}")
    check(provider_calls() == calls, "discovery contacted a provider")
    status, value = branches(state["net3"]["id"])
    check(status == 200 and value == {"network": state["net3"]["id"], "branches": []},
          f"a network bob does not share: {status} {value}")
    for path in ("/peer/v1/fs/branches", "/peer/v1/fs/branches?network=net_xyz",
                 "/peer/v1/fs/branches?network=" + state["net1"]["id"].upper().replace("NET_", "net_"),
                 "/peer/v1/fs/branches?network="):
        status, data, _ = probe("GET", path)
        check(status == 400, f"GET {path}: HTTP {status}, want 400")


@suite.case("head_and_objects", "read 5: head, ordered batch with within, unreached/snapshot/other-space/malformed")
def _():
    need("base_rules")
    one, o, g = sp("one"), state["obj"], state["spaces"]["one"]["graph"]
    provider = state["spaces"]["one"]["provider"]
    status, value = head(one, "main")
    want = {"host": state["a"].id, "space": one, "branch": "main", "head": g.branches["main"]}
    check(status == 200 and value == want,
          f"head: {status} {value}")
    status, value = head(one, "dev")
    check(status == 200 and value["head"] == g.branches["dev"], f"dev head: {status} {value}")
    ids = [o["head"], o["top"], o["commits"][0], o["small"][5], o["commits"][3]]
    got = fetched(one, "main", ids, "a reached batch")
    check(got == [g.entry(i) for i in ids], "the batch is not the requested objects in request order")
    check(provider.fetches()[-1] == {"ids": ids, "within": "main"}, f"provider asked {provider.fetches()[-1:]}")
    got = fetched(one, "dev", [g.branches["dev"], o["dev_blob"], o["commits"][2]], "dev batch")
    check([e[0] for e in got] == [g.branches["dev"], o["dev_blob"], o["commits"][2]], "dev batch order")
    other = state["spaces"]["two"]["graph"]
    for label, bad in (("an unreached object", o["orphan"]), ("a snapshot", o["snapshot"]),
                       ("a snapshot's tree", o["snap_tree"]), ("a snapshot-only blob", o["snap_blob"]),
                       ("another branch's object", o["dev_blob"]),
                       ("another space's object", other.branches["main"]),
                       ("an unknown object", "01" + "ab" * 32)):
        status, data, _ = objects(one, "main", [o["head"], bad])
        refused(status, data, 404, label)
    bad_ids = ["01" + "AB" * 32, "02" + "ab" * 32, "01" + "ab" * 31, "01" + "ab" * 33, "", 7]
    for bad in bad_ids:
        status, data, _ = objects(one, "main", [o["head"], bad])
        refused(status, data, 400, f"a malformed ID {bad!r}")
    for label, body in (("no ids", {"policy": cite(), "ids": []}),
                        ("a repeated ID", {"policy": cite(), "ids": [o["head"]] * 2}),
                        ("no policy", {"ids": [o["head"]]}),
                        ("an extra field", {"policy": cite(), "ids": [o["head"]], "x": 1}),
                        ("a policy with an extra field", {"policy": {**cite(), "x": 1}, "ids": [o["head"]]}),
                        ("257 IDs", {"policy": cite(), "ids": o["small"][:257]})):
        status, data, _ = probe("POST", fs_path(one, "main", "objects"), body)
        refused(status, data, 400, label)
    status, data, _ = probe("POST", fs_path(one, "main", "head"), raw=b'{"policy":')
    refused(status, data, 400, "a truncated head body")
    got = fetched(one, "main", o["small"][:256], "256 IDs")
    check([e[0] for e in got] == o["small"][:256], "256-ID batch")
    refused(*head(one, "ghost"), 404, "an absent branch")
    status, data, _ = objects(one, "ghost", [o["head"]])
    refused(status, data, 404, "objects of an absent branch")
    refused(*head("space_" + "0" * 32, "main"), 404, "a space S does not hold")
    refused(*head(one, "main", policy=cite(ver=version() - 1)), 404, "an earlier policy version")
    refused(*head(one, "main", policy={"person_id": state["bob_pid"], "version": version()}), 404, "bob's own policy")


@suite.case("size_bound", "read 5 Objects batches, PF-06: 16 MiB exactly, one over left for later, first over 503")
def _():
    need("base_rules")
    one, o, g = sp("one"), state["obj"], state["spaces"]["one"]["graph"]
    large = o["large"]
    got = fetched(one, "main", large[:2], "exactly 16 MiB")
    check(got == [g.entry(i) for i in large[:2]], "both objects of an exactly 16 MiB answer")
    got = fetched(one, "main", [large[0], large[2], o["small"][0]], "one byte over")
    check(got == [g.entry(large[0])], f"one over 16 MiB: got {[e[0][:10] for e in got]}, want only the first")
    got = fetched(one, "main", [large[0], o["huge"]], "a later object over 16 MiB")
    check([e[0] for e in got] == [large[0]], "a later oversized object was not left for the next request")
    status, data, _ = objects(one, "main", [o["huge"], large[0]])
    refused(status, data, 503, "a first object alone over 16 MiB (PF-06)")


@suite.case("concurrency_limit", "read 5 Bounds: at most 4 concurrent objects requests per reader host, then 429")
def _():
    need("base_rules")
    one, o = sp("one"), state["obj"]
    provider = state["spaces"]["one"]["provider"]
    provider.release.clear()
    provider.held, provider.stall = 0, "fetch"
    results = []
    threads = [threading.Thread(target=lambda: results.append(objects(one, "main", [o["head"]]))) for _ in range(4)]
    try:
        for t in threads:
            t.start()
        wait_for(lambda: provider.held >= 4, timeout=15, message="four held objects requests")
        status, data, _ = objects(one, "main", [o["head"]])
        check(status == 429, f"a fifth concurrent objects request: HTTP {status} {as_json(data)}")
        status, value = head(one, "main")
        check(status == 200, f"head while four objects requests are held: HTTP {status}")
    finally:
        provider.stall = None
        provider.release.set()
        for t in threads:
            t.join(40)
    check(sorted(r[0] for r in results) == [200] * 4, f"the four held requests: {[r[0] for r in results]}")
    fetched(one, "main", [o["head"]], "after the slots free")


@suite.case("authority_rules", "read 3 step 2: another host's, space's or branch's rule; fs.read absent; 404 "
                               "before the provider")
def _():
    need("base_rules")
    one, o = sp("one"), state["obj"]
    others = full_rules(one_main=False) + [rule(one, "main", [state["bob_p"]], host="host_" + "a" * 64)]
    signed(others)
    state["a"].ok("allow", "bob", "--person-key", str(state["alice_key"]), "--network", state["net1"]["id"])
    calls = provider_calls()["one"]
    refused(*head(one, "main"), 404, "only another host's rule names (one, main)")
    status, data, _ = objects(one, "main", [o["head"]])
    refused(status, data, 404, "objects with no rule for this host")
    status, data, _ = objects(sp("two"), "main", [o["head"]])
    refused(status, data, 404, "another space's rule (and its objects)")
    check(provider_calls()["one"] == calls, "a request without a rule contacted the provider")
    status, value = head(one, "dev")
    check(status == 200, f"another branch's rule still reads that branch: HTTP {status}")
    status, value = branches(state["net1"]["id"])
    check((one, "main") not in {(e["space"], e["branch"]) for e in value["branches"]}, "listed without a rule")
    check(len(set(NOT_FOUND)) == 1, f"404 answers differ: {sorted(set(NOT_FOUND))[:3]}")
    signed(full_rules())


@suite.case("withdrawal_and_unrelated_edit", "read 3, 7: unshare refuses the next batch, bytes stay; an unrelated "
                                             "edit keeps fs_rules")
def _():
    need("base_rules")
    one, o, g = sp("one"), state["obj"], state["spaces"]["one"]["graph"]
    rules = fs_rules()
    state["a"].ok("deny", "bob", "--person-key", str(state["alice_key"]), "--network", state["net1"]["id"])
    check(fs_rules() == rules, "an edit that does not touch filesystem rules changed them")
    kept = fetched(one, "main", [o["head"]], "before withdrawal")
    result = state["a"].cli("--json", "fs", "unshare", one, "main", "--network", state["net1"]["id"], "--yes",
                            "--person-key", str(state["alice_key"]), timeout=90)
    check(result.ok, f"fs unshare: exit {result.code} {result.stderr.strip()[-300:]}")
    status, data, _ = objects(one, "main", [o["head"]])
    refused(status, data, 404, "the next batch after withdrawal")
    refused(*head(one, "main"), 404, "head after withdrawal")
    check(kept == [g.entry(o["head"])], "bytes fetched before the withdrawal")
    check((one, "main") not in shares_listed() and (one, "dev") in shares_listed(), "fs shares after unshare")
    signed(full_rules())


def _ppid(entry):
    try:
        return int((entry / "stat").read_text().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return -1


def tls_request(context, port, method, path, body=None):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="peerspan") as stream:
            payload = b"" if body is None else compact(body).encode()
            stream.sendall(f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: "
                           f"application/json\r\nContent-Length: {len(payload)}\r\n\r\n".encode() + payload)
            response = http.client.HTTPResponse(stream)
            response.begin()
            return response.status, response.read()


@suite.case("provider_states", "read 3 step 1, 4, 6: released, prepared, changed directory, stopped, too old, "
                               "slow; nothing started")
def _():
    need("base_rules")
    spaces = state["spaces"]
    for name in ("released", "prepared"):
        refused(*head(sp(name), "main"), 503, f"a {name} binding")
    changed = spaces["changed"]
    check(head(sp("changed"), "main")[0] == 200, "control: the changed space reads before the change")
    changed["directory"].chmod(0o750)
    try:
        refused(*head(sp("changed"), "main"), 503, "a changed directory")
    finally:
        changed["directory"].chmod(0o700)
    stopped = spaces["stopped"]
    stopped["provider"].stop()
    pid = state["a"].process.pid
    children = lambda: {e.name for e in Path("/proc").iterdir() if e.name.isdigit() and _ppid(e) == pid}
    before = children()
    refused(*head(sp("stopped"), "main"), 503, "a stopped provider")
    status, data, _ = objects(sp("stopped"), "main", [stopped["graph"].branches["main"]])
    refused(status, data, 503, "objects from a stopped provider")
    check(not stopped["provider"].path.exists() and children() <= before, "the host started a provider")
    old = spaces["old"]
    check(head(sp("old"), "main")[0] == 200, "control: an older provider still answers head")
    status, data, _ = objects(sp("old"), "main", [old["graph"].branches["main"]])
    refused(status, data, 503, "a provider older than within")
    check(any("within" in f for f in old["provider"].fetches()), "the host did not ask the older provider with within")
    slow = Provider(stopped["registration"], stopped["graph"])
    slow.stall = "branches"
    try:
        began = time.monotonic()
        refused(*head(sp("stopped"), "main"), 503, "a provider slower than the 5-second head bound")
        check(time.monotonic() - began < 8, f"head took {time.monotonic() - began:.1f}s, past its 5-second bound")
    finally:
        slow.release.set()
        slow.stop()


@suite.case("interfaces", "read 5, 8: the three routes absent (404) on the owner-local and adapter routers")
def _():
    need("base_rules")
    a, one = state["a"], sp("one")
    routes = [("GET", f"/peer/v1/fs/branches?network={state['net1']['id']}", None),
              ("POST", fs_path(one, "main", "head"), {"policy": cite()}),
              ("POST", fs_path(one, "main", "objects"), {"policy": cite(), "ids": [state["obj"]["head"]]})]
    for method, path, body in routes:
        check(a.api(method, path, body)[0] == 404, f"owner-local router serves {path}")
    adapter = a.agent("boundary")
    try:
        for method, path, body in routes:
            check(adapter.call(method, path, body)[0] == 404, f"adapter router serves {path}")
    finally:
        adapter.stop()
    cert, key = suite.work / "tls-cert", suite.work / "tls-key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=pf-read", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=10)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    context.load_cert_chain(str(cert), str(key))
    context.set_alpn_protocols(["peerspan-bootstrap/1"])
    helper_state = suite.work / "helper"
    helper_state.mkdir(mode=0o700)
    port = free_port(socket.SOCK_STREAM)
    log = (suite.work / "helper.log").open("wb")
    process = suite.spawn([str(suite.host_bin.parent / "peerspan-helper"), "--state", str(helper_state), "serve",
                           "--listen", f"127.0.0.1:{port}"], stdout=log, stderr=log)
    log.close()
    deadline = time.monotonic() + 5
    while True:
        try:
            tls_request(context, port, "GET", "/")
            break
        except (OSError, ssl.SSLError):
            check(time.monotonic() < deadline and process.poll() is None, "helper fixture did not become ready")
            time.sleep(.05)
    state["tls"] = (context, port, routes)


@suite.case("pairing_helper_not_served", "read 8 Interfaces: pairing and helper answer the three routes exactly as "
            "an unserved path of the same shape, with and without a query string")
def _():
    (context, port, routes), = need("tls")
    shapes = [*routes, ("GET", "/peer/v1/fs/branches", None)]
    differ = []
    for name, at in (("pairing", state["a"].bootstrap_port), ("helper", port)):
        for method, path, body in shapes:
            unserved = path.replace("/peer/v1/fs/", "/peer/v1/unserved-fs/")
            got = tls_request(context, at, method, path, body)
            want = tls_request(context, at, method, unserved, body)
            if got != want:
                differ.append(f"{name} {method} {path.split('?')[0][-40:]}: {got}, unserved {want}")
    check(not differ, f"routes answered unlike an unserved path: {differ}")


suite.finish()
