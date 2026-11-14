#!/usr/bin/env python3
"""PF-3: the owner's cross-host pull: pull, proxy, refusals, verification failures, bounds and resumption.

Written independently from docs/peerfs-pull-contract.md section 7 (cited "pull N"), PF-07 to PF-11 and the PF-3
paragraph of docs/host-service-contract.md; fakes and fixtures in peerfs_pull_common.py over
peerfs_read_common.py. alice's host is S, bob's host is B and his space L the destination. The agents' pulls are
in peerfs_pull_agents.py.
"""
import os
import re
import signal
import subprocess
import time

from harness import Skip, Suite, check, create_network, wait_for
import peerfs_read_common as common
from peerfs_read_common import Graph, encoded_size, need, sp, state
from peerfs_pull_common import (MIB, destination, fs_pulled, foreign_connect, gone, history, in_thread, proxies,
                                pull, pulled, refused, share_all, source, stalled, start, stranger, tracking)

os.umask(0o077)
suite = Suite("peerfs_pull", __doc__)
common.bind(suite, None)
BRANCHES = ["main", "probe", "move", "reset", "big", "huge", "corrupt", "kind", "badsig", "stranger", "stop",
            "cancel", "conc", "withdraw"]


def cli_pull(branch, into, space, *extra, timeout=180):
    return state["b"].cli("--json", "fs", "pull", "--peer", state["a"].id, "--space", space, "--branch", branch,
                          "--into", into, *extra, timeout=timeout)


def L():
    return state["dest"]["L"]


def fake():
    return L()["provider"]


def src():
    return state["spaces"]["one"]["provider"]


def g1():
    return state["spaces"]["one"]["graph"]


def no_ref(branch, what, space=None):
    ref = fake().remotes.get(tracking(space or sp("one"), branch))
    check(ref is None, f"{what}: a tracking reference was written ({ref})")


def held(release):
    wait_for(lambda: src().held >= 1, timeout=20, interval=.05, message="a held objects request at S's provider")


@suite.case("setup", "decentralized-spec 6, 8; PF-1 sections 3-4; read 2 (fs_rules)")
def _():
    start()
    net1, b = state["net1"], state["b"]
    g, g2 = Graph(), Graph()
    for name in BRANCHES:
        if name == "big":
            history(g, name, last=(7 * MIB,) * 6)
        elif name == "huge":
            history(g, name, commits=1, last=(17 * MIB,))
        elif name == "stranger":
            history(g, name, author=stranger())
        else:
            history(g, name, bad=(name == "badsig"))
    history(g, "nope")
    history(g, "twin")
    history(g2, "twin")
    state["spaces"] = {"one": source(net1, g), "two": source(net1, g2)}
    other = create_network(b, "bob-own", "bob")
    state["dest"] = {"L": destination(net1), "other": destination(other), "changed": destination(net1),
                     "down": destination(net1), "prepared": destination(net1, activate=False),
                     "released": destination(net1)}
    r = state["dest"]["released"]["registration"]
    status, value = b.api("POST", f"/v1/fs/spaces/{r['space_id']}/release", {"binding_id": r["binding_id"]})
    check(status == 200, f"fixture: release: {status} {value}")
    state["rules"] = [(sp("one"), n) for n in BRANCHES + ["twin"]] + [(sp("two"), "twin")]
    share_all(state["rules"])
    state["ready"] = True


@suite.case("pull_and_again", "pull 2, 7 Pull: the reference at the selected head, every reached object and no "
                               "others, the answer, fs.pulled; a second pull fetches nothing new")
def _():
    need("ready")
    one, into, g = sp("one"), L()["id"], g1()
    head = g.branches["main"]
    asked = len(src().fetches())
    result = cli_pull("main", into, one)
    check(result.ok, f"fs pull: exit {result.code} {result.stderr.strip()[-300:]} {[(m, t) for m, t, _ in fake().requests[-4:]]}")
    value = pulled(200, result.json, "main", into, one, head, "fs pull --json")
    record = fake().pulls[-1]
    reached = g.reach("main")
    check(fake().store == reached, f"L holds {len(fake().store)} objects, the head reaches {len(reached)}")
    check(value["objects"] == record["fetched"] == len(reached), f"objects {value['objects']}, served "
                                                                   f"{record['fetched']}, reached {len(reached)}")
    fetches = src().fetches()[asked:]
    size = sum(encoded_size(len(g.objects[o][1])) for o in reached)
    check(size <= value["bytes"] <= size + 3 * len(fetches), f"bytes {value['bytes']}, the objects encode to {size}")
    check(all(f.get("within") == "main" for f in fetches), f"S asked its provider outside within: {fetches[:2]}")
    a = state["a"]
    check(record["space"] == {"path": f"peerspan:{a.id}/{one}", "host": f"{a.id}:{one}", "objects": 0,
                              "key": a.public_key}, f"GET /v1/space answered {record['space']}")
    check(record["branches"] == [{"name": "main", "head": head}], f"GET /v1/branches answered {record['branches']}")
    check(any(p == (a.id, a.public_key) and s == 200 and v.get("recognized") is True
              for p, s, v in record["key_checks"]), f"S's own key was not recognized: {record['key_checks']}")
    gone(record["directory"], "after a pull")
    check(fs_pulled(f"{into}/{tracking(one, 'main')}"), "no fs.pulled activity for the owner's pull")
    status, value = pull("main", into, one)
    pulled(status, value, "main", into, one, head, "a second pull")
    check(value["objects"] == 0 and value["bytes"] == 0 and len(src().fetches()) == asked + len(fetches),
          f"a second pull fetched again: {value}")


@suite.case("proxy_paths_and_privacy", "pull 2.3, 7 Proxy: only the three calls; 0600 socket in a 0700 directory "
                                       "of the state directory, B's account; removed after success")
def _():
    need("ready")
    one, into = sp("one"), L()["id"]
    fake().probe = True
    if os.geteuid() == 0:
        fake().foreign = foreign_connect
    status, value = pull("probe", into, one)
    pulled(status, value, "probe", into, one, g1().branches["probe"], "the probed pull")
    record = state["probed"] = fake().pulls[-1]
    wrong = {k: v for k, v in record["probes"].items() if v[0] != v[1]}
    check(len(record["probes"]) == 15 and not wrong, f"the proxy answered (got, want) {wrong}")
    folder = record["directory"]
    check(os.path.dirname(folder) == str(state["b"].state) and re.fullmatch(r"pull-[0-9a-f]{16}",
                                                                              os.path.basename(folder)),
          f"the proxy directory {folder} is not pull-<16 hex> in bob's state directory")
    check(record["is_socket"] and record["mode"] == 0o600 and record["dir_mode"] == 0o700,
          f"socket {oct(record['mode'])}, directory {oct(record['dir_mode'])}")
    check(record["uid"] == record["dir_uid"] == os.geteuid(), "the proxy is not owned by the daemon's account")
    gone(folder, "after the probed pull")


@suite.case("proxy_other_account", "pull 2: the proxy accepts only connections whose SO_PEERCRED is B's account")
def _():
    record, = need("probed")
    if os.geteuid() != 0:
        raise Skip("connecting as another account needs root here (setuid with capabilities kept); not run")
    seen = record.get("foreign", "")
    if seen.startswith("setup") or seen == "connect 13":
        raise Skip(f"could not connect as another account past the directory's permissions ({seen})")
    check(not re.search(r"HTTP/1\.[01] 2\d\d", seen), f"a connection from uid 65534 was served: {seen}")


@suite.case("bound_then_resume", "pull 4, 7 Bounds: the byte bound is 507 with no reference; a rerun with a larger "
                                 "--max-bytes completes without the blobs held; several S answers in one batch")
def _():
    need("ready")
    one, into, g = sp("one"), L()["id"], g1()
    big = [o for o in g.reach("big") if len(g.objects[o][1]) == 7 * MIB]
    status, value = pull("big", into, one, max_bytes=10 * MIB)
    refused(status, value, 507, "too_large", "a pull past its 10 MiB bound")
    no_ref("big", "a bounded pull")
    gone(fake().pulls[-1]["directory"], "after a failed pull")
    kept = [o for o in big if o in fake().store]
    check(kept and len(kept) < len(big), f"L kept {len(kept)} of the {len(big)} large blobs of the stopped pull")
    asked = len(src().fetches())
    result = cli_pull("big", into, one, "--max-bytes", str(200 * MIB))
    check(result.ok, f"the rerun: exit {result.code} {result.stderr.strip()[-300:]}")
    value = pulled(200, result.json, "big", into, one, g.branches["big"], "the rerun")
    again = [i for f in src().fetches()[asked:] for i in f["ids"]]
    check(not set(kept) & set(again), "the rerun fetched blobs L already held")
    full = sum(encoded_size(len(g.objects[o][1])) for o in g.reach("big"))
    check(value["bytes"] < full - len(kept) * 7 * MIB + MIB, f"the rerun fetched {value['bytes']} of {full} bytes")
    record = fake().pulls[-1]
    rest = [n for n, ids in enumerate(record["asked"]) if set(ids) & set(big)]
    check(rest and all(record["batches"][n] == record["asked"][n] for n in rest), "a fetch was not answered whole")
    across = [f for f in src().fetches()[asked:] if set(f["ids"]) & set(big)]
    check(len(across) >= 2, f"the large blobs came in {len(across)} S answers; the fixture needs several")


@suite.case("head_selected_once", "pull 2.2, 7 Pull: a move during the pull does not change its target; a later "
                                  "pull brings the new head")
def _():
    need("ready")
    one, into, g = sp("one"), L()["id"], g1()
    old = g.branches["move"]
    release = stalled(src())
    try:
        out = in_thread(pull, "move", into, one)
        held(release)
        new = history(g, "move", commits=1, parent=old)
    finally:
        release()
    out["thread"].join(120)
    pulled(*out["value"], "move", into, one, old, "a pull while the branch moved")
    check(fake().pulls[-1]["branches"] == [{"name": "move", "head": old}], "GET /v1/branches did not give the target")
    status, value = pull("move", into, one)
    pulled(status, value, "move", into, one, new, "the next pull")
    check(value["objects"] == 5, f"the next pull fetched {value['objects']} objects, want the 5 new ones")


@suite.case("two_spaces_at_once", "pull 2.3, 7 Pull: one branch name in two shared spaces, pulled at once, arrives "
                                  "as two references")
def _():
    need("ready")
    into = L()["id"]
    runs = {name: in_thread(pull, "twin", into, sp(name)) for name in ("one", "two")}
    for name, out in runs.items():
        out["thread"].join(120)
        check("value" in out, f"pull of {name}/twin raised {out.get('error')}")
        pulled(*out["value"], "twin", into, sp(name), state["spaces"][name]["graph"].branches["twin"],
               f"{name}/twin at once")
    check(tracking(sp("one"), "twin") != tracking(sp("two"), "twin"), "the two references share a name")


@suite.case("refusals", "pull 2.1, 3, 6, 7 Refusals: unshared, no space, malformed, another network, prepared, "
                        "released, changed directory, provider down; nothing written")
def _():
    need("ready")
    one, net1, dest = sp("one"), state["net1"]["id"], state["dest"]
    calls = {k: len(d["provider"].pulls) for k, d in dest.items()}
    refs = {k: dict(d["provider"].remotes) for k, d in dest.items()}
    asked = len(src().fetches())
    cases = [("an unshared branch", ("nope", dest["L"]["id"], one), {}, 404, "not_found"),
             ("no such local space", ("main", "space_" + "0" * 32, one), {}, 404, "not_found"),
             ("a malformed destination", ("main", "space_X", one), {}, 400, "invalid"),
             ("a malformed branch", ("a/b", dest["L"]["id"], one), {}, 400, "invalid"),
             ("another network", ("main", dest["other"]["id"], one), {"network": net1}, 409, "conflict"),
             ("a prepared destination", ("main", dest["prepared"]["id"], one), {}, 409, "conflict"),
             ("a released destination", ("main", dest["released"]["id"], one), {}, 409, "conflict"),
             ("the destination provider down", ("main", dest["down"]["id"], one), {}, 503, "unavailable")]
    dest["down"]["provider"].stop()
    problems = []
    for label, args, kw, want, code in cases:
        status, value = pull(*args, **kw)
        if not (status == want and isinstance(value, dict) and value.get("code") == code):
            problems.append(f"{label}: {status} {value}")
    status, value = pull("main", dest["other"]["id"], one)
    if status not in (404, 409):
        problems.append(f"another network without --network: {status} {value}")
    changed = dest["changed"]
    changed["directory"].chmod(0o750)
    try:
        status, value = pull("main", changed["id"], one)
        if not (status == 409 and value.get("code") == "conflict"):
            problems.append(f"a changed destination directory: {status} {value}")
    finally:
        changed["directory"].chmod(0o700)
    check(not problems, "; ".join(problems))
    after = {k: len(d["provider"].pulls) for k, d in dest.items()}
    check(after == calls, f"a refused pull reached a destination provider: {calls} -> {after}")
    check(len(src().fetches()) == asked and not proxies(), "a refused pull fetched objects or left a proxy")
    check({k: dict(d["provider"].remotes) for k, d in dest.items()} == refs, "a refused pull wrote a reference")


@suite.case("concurrent_same_branch", "pull 2.1, 4: a second pull of the same (L, S, space, branch) is 409 within "
                                      "seconds while the first runs; a later pull succeeds")
def _():
    need("ready")
    one, into, g = sp("one"), L()["id"], g1()
    release = stalled(src())
    try:
        first = in_thread(pull, "conc", into, one)
        held(release)
        began = time.monotonic()
        status, value = pull("conc", into, one, timeout=20)
        took = time.monotonic() - began
        refused(status, value, 409, "conflict", "a concurrent pull of the same branch")
        check(took < 5, f"the 409 took {took:.1f}s")
    finally:
        release()
    first["thread"].join(120)
    pulled(*first["value"], "conc", into, one, g.branches["conc"], "the first pull")
    status, value = pull("conc", into, one, timeout=60)
    pulled(status, value, "conc", into, one, g.branches["conc"], "a later pull")


@suite.case("verification_failures", "pull 3, 7: a corrupted object, a wrong kind, a bad signature and an "
                                     "unrecognized author each fail 502 with no reference")
def _():
    need("ready")
    one, into, g = sp("one"), L()["id"], g1()

    def blob_of(branch):
        return next(o for o in g.reach(branch) if g.objects[o][0] == 1)

    def tree_of(branch):
        return g.commits[g.branches[branch]][0]
    corrupt, tree = blob_of("corrupt"), tree_of("kind")
    data = g.objects[corrupt][1]
    src().tamper = {corrupt: (1, bytes([data[0] ^ 1]) + data[1:]), tree: (1, g.objects[tree][1])}
    problems = []
    try:
        for branch, why in (("corrupt", "identity"), ("kind", "kind"), ("badsig", "signature"),
                            ("stranger", "unrecognized author")):
            status, value = pull(branch, into, one)
            outcome = fake().pulls[-1]["outcome"]
            if outcome != why:
                problems.append(f"{branch}: the fake failed on {outcome!r}, the fixture meant {why!r}")
            if not (status == 502 and isinstance(value, dict) and value.get("code") == "remote"):
                problems.append(f"{branch}: HTTP {status} {value}, want 502 remote")
            if fake().remotes.get(tracking(one, branch)):
                problems.append(f"{branch}: a tracking reference was written")
    finally:
        src().tamper = {}
    check(not problems, "; ".join(problems))
    checks = fake().pulls[-1]["key_checks"]
    check(any(s == 200 and v.get("recognized") is False for _, s, v in checks),
          f"the stranger's key was not asked of host-keys/check as unrecognized: {checks}")


@suite.case("object_over_answer", "pull 4, 7, PF-06: an object larger than one answer fails the pull 503")
def _():
    need("ready")
    one, into = sp("one"), L()["id"]
    status, value = pull("huge", into, one)
    refused(status, value, 503, "unavailable", "a 17 MiB object")
    no_ref("huge", "an object over 16 MiB")
    gone(fake().pulls[-1]["directory"], "after the 503")


@suite.case("withdrawal_mid_pull", "pull 4, 7: a share withdrawn during the pull fails it there with 404")
def _():
    need("ready")
    one, into = sp("one"), L()["id"]
    release = stalled(src())
    try:
        out = in_thread(pull, "withdraw", into, one)
        held(release)
        share_all([r for r in state["rules"] if r != (one, "withdraw")])
    finally:
        release()
    out["thread"].join(120)
    refused(*out["value"], 404, "not_found", "a pull whose share was withdrawn")
    no_ref("withdraw", "a withdrawn share")


@suite.case("reset_mid_pull", "pull 4: a target the branch no longer reaches fails 404; a rerun pulls the new head")
def _():
    need("ready")
    one, into, g = sp("one"), L()["id"], g1()
    release = stalled(src())
    try:
        out = in_thread(pull, "reset", into, one)
        held(release)
        new = history(g, "reset-new", commits=1)
        g.branches["reset"] = g.branches.pop("reset-new")
    finally:
        release()
    out["thread"].join(120)
    refused(*out["value"], 404, "not_found", "a pull whose target was reset away")
    no_ref("reset", "a reset branch")
    status, value = pull("reset", into, one)
    pulled(status, value, "reset", into, one, new, "the rerun after the reset")


@suite.case("source_stops", "pull 4, 7: S stopping mid-pull fails it 503 with no reference; a rerun completes")
def _():
    need("ready")
    one, into, g, a = sp("one"), L()["id"], g1(), state["a"]
    release = stalled(src())
    try:
        out = in_thread(pull, "stop", into, one)
        held(release)
        a.stop(kill=True)
    finally:
        release()
    out["thread"].join(120)
    a.start()
    refused(*out["value"], 503, "unavailable", "a pull whose source stopped")
    no_ref("stop", "a stopped source")
    gone(fake().pulls[-1]["directory"], "after the source stopped")
    status, value = pull("stop", into, one)
    pulled(status, value, "stop", into, one, g.branches["stop"], "the rerun")


@suite.case("cancellation", "pull 4: killing fs pull ends the pull: proxy removed, no reference, never complete; "
                            "the next pull of the branch is not 409")
def _():
    need("ready")
    one, into, g, b = sp("one"), L()["id"], g1(), state["b"]
    release = stalled(src())
    try:
        before = len(fake().pulls)
        process = subprocess.Popen(
            [str(suite.host_bin), "--state", str(b.state), "--json", "fs", "pull", "--peer", state["a"].id,
             "--space", one, "--branch", "cancel", "--into", into], env=b.env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        held(release)
        check(len(proxies()) == 1, f"proxy directories while pulling: {proxies()}")
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=10)
        wait_for(lambda: not proxies(), timeout=10, interval=.1, message="the proxy removed after the kill")
    finally:
        release()
    record = fake().pulls[before]
    wait_for(lambda: record["outcome"] is not None, timeout=20, interval=.1, message="the destination's pull to end")
    check(record["outcome"] != "ok", "the destination's pull completed after the kill")
    no_ref("cancel", "a cancelled pull")
    status, value = pull("cancel", into, one, timeout=60)
    pulled(status, value, "cancel", into, one, g.branches["cancel"], "a pull after the cancelled one")


suite.finish()
